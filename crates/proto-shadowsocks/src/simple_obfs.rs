//! SIP003 `simple-obfs` / `obfs-local`, as a stream wrapper instead of a
//! subprocess.
//!
//! The plugin is a carrier, not a protocol: it neither encrypts nor
//! authenticates anything, it only makes the first bytes of a Shadowsocks
//! connection look like an HTTP request or a TLS ClientHello. So it is
//! implemented here as an [`AsyncRead`]/[`AsyncWrite`] shim under the
//! Shadowsocks codec, and the core never launches `obfs-local`.
//!
//! Wire format taken from the reference implementation
//! (`shadowsocks/simple-obfs`, `src/obfs_http.c` and `src/obfs_tls.c`,
//! layouts in `src/obfs_tls.h`) and cross-checked against an independent client
//! (`MetaCubeX/mihomo`, `transport/simple-obfs/{http,tls}.go`). Both agree byte
//! for byte, and the constants below are annotated with where they come from.
//!
//! Notably **only the first message in each direction is disguised**: after it,
//! `http` relays verbatim and `tls` wraps every write in one
//! `application_data` record.

use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::{BufMut, BytesMut};
use foxcore_api::SimpleObfsConfig;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `deobfs_app_data` in the reference refuses a record longer than this, so a
/// writer that exceeds it produces a stream its own server will not read.
const MAX_RECORD: usize = 16_384;

/// `0x17 0x03 0x03` — `tls_data_header` in `obfs_tls.c`.
const APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03];

/// `sizeof(struct tls_server_hello)` = 96, `struct tls_change_cipher_spec` = 6,
/// `struct tls_encrypted_handshake` = 5. The first server message is those
/// three back to back, and the payload follows inside the third.
const SERVER_HELLO_LEN: usize = 96;
const CHANGE_CIPHER_SPEC_LEN: usize = 6;
const ENCRYPTED_HANDSHAKE_LEN: usize = 5;
const TLS_FIRST_RESPONSE_LEN: usize =
    SERVER_HELLO_LEN + CHANGE_CIPHER_SPEC_LEN + ENCRYPTED_HANDSHAKE_LEN;

/// A response header that never ends is a server that is not this plugin.
const MAX_HTTP_RESPONSE_HEADER: usize = 8 * 1024;

const READ_CHUNK: usize = 4 * 1024;

/// Fixed tail of the fake ClientHello: cipher suites, compression, and the
/// extensions that follow the session ticket and SNI. Copied from
/// `tls_client_hello_template` and `tls_ext_others_template`.
const CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

const OTHER_EXTENSIONS: [u8; 66] = [
    // ec_point_formats
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, //
    // supported_groups
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, //
    // signature_algorithms
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02,
    0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x02, 0x03, //
    // encrypt_then_mac
    0x00, 0x16, 0x00, 0x00, //
    // extended_master_secret
    0x00, 0x17, 0x00, 0x00,
];

/// Everything in the ClientHello except the payload and the host: the 138-byte
/// header, the 4-byte session ticket header, the 9-byte SNI header and the 66
/// bytes above. `212 + len(data) + len(host)` is the record length mihomo
/// writes, and 217 - 5 = 212.
const CLIENT_HELLO_OVERHEAD: usize = 217;

#[derive(Debug)]
enum ReadState {
    /// `http`: strip up to and including the first CRLFCRLF, then relay.
    HttpHeader,
    /// `tls`: the fixed 107-byte first response.
    TlsFirstResponse,
    /// `tls`: `0x17 0x03 0x03` plus a 16-bit length.
    TlsRecordHeader,
    Payload {
        remaining: usize,
    },
    Relay,
}

pub struct SimpleObfsStream<S> {
    inner: S,
    mode: Mode,
    read_state: ReadState,
    /// Bytes read from the carrier and not yet handed upstream. It holds at
    /// most one partial header plus whatever arrived with it.
    inbox: BytesMut,
    /// Framed bytes not yet accepted by the carrier.
    outbox: BytesMut,
    first_request: bool,
    eof: bool,
}

enum Mode {
    Http {
        host: String,
        uri: String,
        method: String,
        port: u16,
    },
    Tls {
        host: String,
    },
}

impl<S> SimpleObfsStream<S> {
    pub fn new(inner: S, config: &SimpleObfsConfig, port: u16) -> Self {
        let (mode, read_state) = match config {
            SimpleObfsConfig::Http { host, uri, method } => (
                Mode::Http {
                    host: host.clone(),
                    uri: uri.clone(),
                    method: method.clone(),
                    port,
                },
                ReadState::HttpHeader,
            ),
            SimpleObfsConfig::Tls { host } => (
                Mode::Tls { host: host.clone() },
                ReadState::TlsFirstResponse,
            ),
        };
        Self {
            inner,
            mode,
            read_state,
            inbox: BytesMut::new(),
            outbox: BytesMut::new(),
            first_request: true,
            eof: false,
        }
    }

    /// The largest plaintext run one call may frame.
    fn write_limit(&self) -> usize {
        match self.mode {
            // The single HTTP request carries whatever the first write was;
            // afterwards the stream is verbatim, so nothing needs splitting.
            Mode::Http { .. } if !self.first_request => usize::MAX,
            _ => MAX_RECORD,
        }
    }

    fn frame(&mut self, payload: &[u8]) {
        match (&self.mode, self.first_request) {
            (Mode::Http { .. }, false) => self.outbox.extend_from_slice(payload),
            (
                Mode::Http {
                    host,
                    uri,
                    method,
                    port,
                },
                true,
            ) => {
                let mut rng = rand::rng();
                let mut key = [0_u8; 16];
                rng.fill_bytes(&mut key);
                // `curl/7.%d.%d` with the same ranges the reference draws from.
                let request = format!(
                    "{method} {uri} HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     User-Agent: curl/7.{}.{}\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Key: {}\r\n\
                     Content-Length: {}\r\n\
                     \r\n",
                    rng.random_range(0..51),
                    rng.random_range(0..2),
                    STANDARD.encode(key),
                    payload.len(),
                    host = http_host(host, *port),
                );
                self.outbox.extend_from_slice(request.as_bytes());
                self.outbox.extend_from_slice(payload);
                self.first_request = false;
            }
            (Mode::Tls { host }, true) => {
                client_hello(&mut self.outbox, host, payload);
                self.first_request = false;
            }
            (Mode::Tls { .. }, false) => {
                self.outbox.extend_from_slice(&APPLICATION_DATA);
                self.outbox.put_u16(payload.len() as u16);
                self.outbox.extend_from_slice(payload);
            }
        }
    }
}

fn http_host(host: &str, port: u16) -> String {
    // The reference omits the port only for 80, and the server trims whatever
    // port it is given before matching, so this is cosmetic for the server and
    // load-bearing for a middlebox.
    if port == 80 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// Build the fake ClientHello with `payload` inside the session ticket
/// extension. Mirrors `obfs_tls_request` field by field.
fn client_hello(out: &mut BytesMut, host: &str, payload: &[u8]) {
    let host = host.as_bytes();
    let total = CLIENT_HELLO_OVERHEAD + payload.len() + host.len();
    let mut rng = rand::rng();
    let mut random = [0_u8; 28];
    let mut session_id = [0_u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut session_id);

    // Record header: handshake, TLS 1.0, length.
    out.put_u8(0x16);
    out.extend_from_slice(&[0x03, 0x01]);
    out.put_u16((total - 5) as u16);

    // Handshake header: ClientHello, 24-bit length, TLS 1.2.
    out.put_u8(0x01);
    out.put_u8(0x00);
    out.put_u16((total - 9) as u16);
    out.extend_from_slice(&[0x03, 0x03]);

    // Random: unix time then 28 random bytes, as TLS 1.2 used to specify.
    out.put_u32(unix_time());
    out.extend_from_slice(&random);
    out.put_u8(32);
    out.extend_from_slice(&session_id);

    out.put_u16(CIPHER_SUITES.len() as u16);
    out.extend_from_slice(&CIPHER_SUITES);
    // One compression method: null.
    out.extend_from_slice(&[0x01, 0x00]);

    out.put_u16((total - 138) as u16);

    // session_ticket carries the payload.
    out.extend_from_slice(&[0x00, 0x23]);
    out.put_u16(payload.len() as u16);
    out.extend_from_slice(payload);

    // server_name.
    out.extend_from_slice(&[0x00, 0x00]);
    out.put_u16((host.len() + 5) as u16);
    out.put_u16((host.len() + 3) as u16);
    out.put_u8(0x00);
    out.put_u16(host.len() as u16);
    out.extend_from_slice(host);

    out.extend_from_slice(&OTHER_EXTENSIONS);
}

fn unix_time() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as u32)
        .unwrap_or_default()
}

impl<S> SimpleObfsStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_drain(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outbox.is_empty() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(context, &self.outbox))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            let _ = self.outbox.split_to(written);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for SimpleObfsStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = min(buffer.len(), this.write_limit());
        this.frame(&buffer[..take]);
        // The framed bytes are owned now, so a carrier that is not ready yet
        // only defers them; the next call drains before framing anything else.
        match this.poll_drain(context) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

impl<S> SimpleObfsStream<S>
where
    S: AsyncRead + Unpin,
{
    /// Pull one chunk from the carrier into `inbox`. `Ok(false)` is EOF.
    fn poll_fill(&mut self, context: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut scratch = [0_u8; READ_CHUNK];
        let mut read = ReadBuf::new(&mut scratch);
        ready!(Pin::new(&mut self.inner).poll_read(context, &mut read))?;
        let filled = read.filled();
        if filled.is_empty() {
            self.eof = true;
            return Poll::Ready(Ok(false));
        }
        self.inbox.extend_from_slice(filled);
        Poll::Ready(Ok(true))
    }

    /// Try to advance past a header using only what is already buffered.
    /// `Ok(false)` means the buffer is short and more bytes are needed.
    fn parse_header(&mut self) -> io::Result<bool> {
        match self.read_state {
            ReadState::HttpHeader => {
                let Some(end) = find_crlf_crlf(&self.inbox) else {
                    if self.inbox.len() > MAX_HTTP_RESPONSE_HEADER {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "simple-obfs http response header is not terminated",
                        ));
                    }
                    return Ok(false);
                };
                let _ = self.inbox.split_to(end);
                self.read_state = ReadState::Relay;
                Ok(true)
            }
            ReadState::TlsFirstResponse => {
                if self.inbox.len() < TLS_FIRST_RESPONSE_LEN {
                    return Ok(false);
                }
                let header = self.inbox.split_to(TLS_FIRST_RESPONSE_LEN);
                // The reference client checks the ServerHello content type and
                // then trusts the fixed layout; the encrypted-handshake record
                // is always `0x16 0x03 0x03` from the same template, so it is
                // checked too rather than skipped blindly.
                let handshake = &header[SERVER_HELLO_LEN + CHANGE_CIPHER_SPEC_LEN..];
                if header[0] != 0x16 || handshake[..3] != [0x16, 0x03, 0x03] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "simple-obfs tls response is not a ServerHello",
                    ));
                }
                let length = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
                self.read_state = ReadState::Payload { remaining: length };
                Ok(true)
            }
            ReadState::TlsRecordHeader => {
                if self.inbox.len() < 5 {
                    return Ok(false);
                }
                let header = self.inbox.split_to(5);
                if header[..3] != APPLICATION_DATA {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "simple-obfs tls record is not application data",
                    ));
                }
                let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                if length > MAX_RECORD {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "simple-obfs tls record is over 16384 bytes",
                    ));
                }
                self.read_state = ReadState::Payload { remaining: length };
                Ok(true)
            }
            ReadState::Payload { .. } | ReadState::Relay => Ok(true),
        }
    }
}

fn find_crlf_crlf(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

impl<S> AsyncRead for SimpleObfsStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.parse_header()? {
                if !this.eof && ready!(this.poll_fill(context))? {
                    continue;
                }
                // A record boundary is where a stream is allowed to end. A
                // header that was started and never finished is a truncated
                // carrier, and saying "clean close" there would hand the codec
                // above a short read it cannot tell from a real one.
                return Poll::Ready(
                    if matches!(this.read_state, ReadState::TlsRecordHeader)
                        && this.inbox.is_empty()
                    {
                        Ok(())
                    } else {
                        Err(io::ErrorKind::UnexpectedEof.into())
                    },
                );
            }
            match this.read_state {
                ReadState::Payload { remaining: 0 } => {
                    this.read_state = ReadState::TlsRecordHeader;
                }
                ReadState::Payload { ref mut remaining } => {
                    if this.inbox.is_empty() {
                        if this.eof || !ready!(this.poll_fill(context))? {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        continue;
                    }
                    let take = min(min(*remaining, this.inbox.len()), buffer.remaining());
                    if take == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    buffer.put_slice(&this.inbox.split_to(take));
                    *remaining -= take;
                    return Poll::Ready(Ok(()));
                }
                ReadState::Relay => {
                    if !this.inbox.is_empty() {
                        let take = min(this.inbox.len(), buffer.remaining());
                        if take == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        buffer.put_slice(&this.inbox.split_to(take));
                        return Poll::Ready(Ok(()));
                    }
                    if this.eof {
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(context, buffer);
                }
                _ => unreachable!("parse_header leaves only payload or relay states"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn http() -> SimpleObfsConfig {
        SimpleObfsConfig::Http {
            host: "www.bing.com".to_owned(),
            uri: "/".to_owned(),
            method: "GET".to_owned(),
        }
    }

    fn tls() -> SimpleObfsConfig {
        SimpleObfsConfig::Tls {
            host: "www.bing.com".to_owned(),
        }
    }

    /// Everything the client writes, with the carrier accepting one byte per
    /// call so partial writes are exercised.
    async fn written(config: &SimpleObfsConfig, port: u16, chunks: &[&[u8]]) -> Vec<u8> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut stream = SimpleObfsStream::new(client, config, port);
        for chunk in chunks {
            stream.write_all(chunk).await.unwrap();
        }
        stream.flush().await.unwrap();
        drop(stream);
        let mut collected = Vec::new();
        let mut server = server;
        server.read_to_end(&mut collected).await.unwrap();
        collected
    }

    #[tokio::test]
    async fn http_request_matches_the_reference_template() {
        let wire = written(&http(), 8388, &[b"salt-and-payload", b" more"]).await;
        let text = String::from_utf8(wire).unwrap();
        let (header, body) = text.split_once("\r\n\r\n").unwrap();
        let lines: Vec<_> = header.split("\r\n").collect();
        assert_eq!(lines[0], "GET / HTTP/1.1");
        assert_eq!(lines[1], "Host: www.bing.com:8388");
        assert!(lines[2].starts_with("User-Agent: curl/7."));
        assert_eq!(lines[3], "Upgrade: websocket");
        assert_eq!(lines[4], "Connection: Upgrade");
        assert!(lines[5].starts_with("Sec-WebSocket-Key: "));
        assert_eq!(lines[6], "Content-Length: 16");
        // Only the first write is disguised; the rest is verbatim.
        assert_eq!(body, "salt-and-payload more");
    }

    #[tokio::test]
    async fn http_host_header_drops_the_default_port() {
        let wire = written(&http(), 80, &[b"x"]).await;
        let text = String::from_utf8(wire).unwrap();
        assert!(text.contains("\r\nHost: www.bing.com\r\n"), "{text}");
    }

    #[tokio::test]
    async fn client_hello_is_byte_exact() {
        let payload = b"first-shadowsocks-write";
        let wire = written(&tls(), 443, &[payload]).await;
        let host = b"www.bing.com";
        let total = CLIENT_HELLO_OVERHEAD + payload.len() + host.len();
        assert_eq!(wire.len(), total);

        assert_eq!(&wire[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]) as usize, total - 5);
        assert_eq!(wire[5], 0x01);
        assert_eq!(wire[6], 0x00);
        assert_eq!(u16::from_be_bytes([wire[7], wire[8]]) as usize, total - 9);
        assert_eq!(&wire[9..11], &[0x03, 0x03]);
        // 4 byte time + 28 random + session id length + 32 session id.
        assert_eq!(wire[43], 32);
        assert_eq!(u16::from_be_bytes([wire[76], wire[77]]), 56);
        assert_eq!(&wire[78..134], &CIPHER_SUITES);
        assert_eq!(&wire[134..136], &[0x01, 0x00]);
        assert_eq!(
            u16::from_be_bytes([wire[136], wire[137]]) as usize,
            total - 138
        );
        // session_ticket extension with the payload verbatim.
        assert_eq!(&wire[138..140], &[0x00, 0x23]);
        assert_eq!(
            u16::from_be_bytes([wire[140], wire[141]]) as usize,
            payload.len()
        );
        assert_eq!(&wire[142..142 + payload.len()], payload);
        // server_name extension.
        let sni = 142 + payload.len();
        assert_eq!(&wire[sni..sni + 2], &[0x00, 0x00]);
        assert_eq!(
            u16::from_be_bytes([wire[sni + 2], wire[sni + 3]]) as usize,
            host.len() + 5
        );
        assert_eq!(
            u16::from_be_bytes([wire[sni + 4], wire[sni + 5]]) as usize,
            host.len() + 3
        );
        assert_eq!(wire[sni + 6], 0x00);
        assert_eq!(
            u16::from_be_bytes([wire[sni + 7], wire[sni + 8]]) as usize,
            host.len()
        );
        assert_eq!(&wire[sni + 9..sni + 9 + host.len()], host);
        assert_eq!(&wire[sni + 9 + host.len()..], &OTHER_EXTENSIONS);
    }

    #[tokio::test]
    async fn tls_writes_after_the_hello_are_application_data_records() {
        let wire = written(&tls(), 443, &[b"hello-payload", b"second", b"third"]).await;
        let tail = &wire[CLIENT_HELLO_OVERHEAD + 13 + 12..];
        assert_eq!(&tail[..3], &APPLICATION_DATA);
        assert_eq!(u16::from_be_bytes([tail[3], tail[4]]), 6);
        assert_eq!(&tail[5..11], b"second");
        assert_eq!(&tail[11..14], &APPLICATION_DATA);
        assert_eq!(u16::from_be_bytes([tail[14], tail[15]]), 5);
        assert_eq!(&tail[16..21], b"third");
    }

    #[tokio::test]
    async fn tls_splits_a_write_that_does_not_fit_one_record() {
        let payload = vec![7_u8; MAX_RECORD + 100];
        let wire = written(&tls(), 443, &[b"hello", &payload]).await;
        let tail = &wire[CLIENT_HELLO_OVERHEAD + 5 + 12..];
        assert_eq!(
            u16::from_be_bytes([tail[3], tail[4]]) as usize,
            MAX_RECORD,
            "the first record must stop at the limit the server enforces"
        );
        let second = &tail[5 + MAX_RECORD..];
        assert_eq!(&second[..3], &APPLICATION_DATA);
        assert_eq!(u16::from_be_bytes([second[3], second[4]]) as usize, 100);
    }

    /// Feed a client-side reader the bytes a reference server would send.
    async fn deobfuscate(config: &SimpleObfsConfig, wire: &[u8]) -> io::Result<Vec<u8>> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(wire).await.unwrap();
        server.shutdown().await.unwrap();
        drop(server);
        let mut stream = SimpleObfsStream::new(client, config, 443);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await?;
        Ok(out)
    }

    /// The same, delivered one byte per read. The reference is written against
    /// a whole buffer and would not survive this; a stream implementation has
    /// to, because a header split across two segments is ordinary TCP.
    async fn deobfuscate_by_the_byte(config: &SimpleObfsConfig, wire: &[u8]) -> Vec<u8> {
        let (client, mut server) = tokio::io::duplex(1);
        let wire = wire.to_vec();
        let feeder = tokio::spawn(async move {
            for byte in wire {
                server.write_all(&[byte]).await.unwrap();
            }
            server.shutdown().await.unwrap();
        });
        let mut stream = SimpleObfsStream::new(client, config, 443);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        feeder.await.unwrap();
        out
    }

    #[tokio::test]
    async fn a_tls_response_split_across_every_byte_still_reassembles() {
        let mut wire = server_first_response(b"first");
        wire.extend_from_slice(&APPLICATION_DATA);
        wire.extend_from_slice(&6_u16.to_be_bytes());
        wire.extend_from_slice(b"second");
        wire.extend_from_slice(&APPLICATION_DATA);
        wire.extend_from_slice(&5_u16.to_be_bytes());
        wire.extend_from_slice(b"third");
        assert_eq!(
            deobfuscate_by_the_byte(&tls(), &wire).await,
            b"firstsecondthird"
        );
    }

    #[tokio::test]
    async fn an_http_response_split_across_every_byte_still_reassembles() {
        let wire = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\npayload";
        assert_eq!(deobfuscate_by_the_byte(&http(), wire).await, b"payload");
    }

    fn server_first_response(payload: &[u8]) -> Vec<u8> {
        let mut wire = vec![0_u8; TLS_FIRST_RESPONSE_LEN];
        wire[0] = 0x16;
        wire[1] = 0x03;
        wire[2] = 0x01;
        wire[3..5].copy_from_slice(&91_u16.to_be_bytes());
        wire[SERVER_HELLO_LEN] = 0x14;
        let handshake = SERVER_HELLO_LEN + CHANGE_CIPHER_SPEC_LEN;
        wire[handshake] = 0x16;
        wire[handshake + 1] = 0x03;
        wire[handshake + 2] = 0x03;
        wire[handshake + 3..handshake + 5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);
        wire
    }

    #[tokio::test]
    async fn tls_response_yields_the_hidden_payload_then_records() {
        let mut wire = server_first_response(b"first");
        wire.extend_from_slice(&APPLICATION_DATA);
        wire.extend_from_slice(&6_u16.to_be_bytes());
        wire.extend_from_slice(b"second");
        assert_eq!(deobfuscate(&tls(), &wire).await.unwrap(), b"firstsecond");
    }

    #[tokio::test]
    async fn tls_response_with_a_foreign_record_type_is_refused() {
        let mut wire = server_first_response(b"first");
        wire.extend_from_slice(&[0x16, 0x03, 0x03]);
        wire.extend_from_slice(&1_u16.to_be_bytes());
        wire.push(0);
        let error = deobfuscate(&tls(), &wire).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn tls_response_that_is_not_a_server_hello_is_refused() {
        let mut wire = server_first_response(b"first");
        wire[0] = 0x17;
        let error = deobfuscate(&tls(), &wire).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_tls_response_is_not_reported_as_a_clean_close() {
        let wire = server_first_response(b"first");
        let error = deobfuscate(&tls(), &wire[..TLS_FIRST_RESPONSE_LEN - 1])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn http_response_headers_are_stripped_once() {
        let wire =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\npayload\r\n\r\nmore";
        assert_eq!(
            deobfuscate(&http(), wire).await.unwrap(),
            b"payload\r\n\r\nmore"
        );
    }

    #[tokio::test]
    async fn http_response_without_a_header_terminator_is_refused() {
        let wire = vec![b'x'; MAX_HTTP_RESPONSE_HEADER + 1];
        let error = deobfuscate(&http(), &wire).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
        ));
    }
}
