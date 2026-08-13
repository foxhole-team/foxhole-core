//! Hysteria2 client outbound over QUIC — mirrors `thjty` `inbound/hysteria2.rs`.
//!
//! Flow (modern Hysteria2, what the server's `handle_auth_stream` expects):
//!   1. QUIC connect, ALPN `h3`, using the shared strict/pinned TLS policy.
//!   2. Open an H3 control uni-stream and send SETTINGS (kept open for the connection lifetime).
//!   3. Open a bidi stream and send an H3 `POST /auth` HEADERS frame (QPACK via the server's own
//!      `qpack` crate) carrying `hysteria-auth` / `hysteria-cc-rx`; read the `:status 233` reply.
//!   4. Each proxied TCP flow is a fresh bidi stream: `varint(0x401) | addr | padding`, then relay.
//!
//! Congestion is the Brutal controller ([`crate::brutal`]), targeted at `up_mbps` bytes/sec.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Poll, ready};
use std::time::Duration;

use foxcore_api::{Destination, Hysteria2Config, Hysteria2ObfsConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::rustls_client_config;
use qpack::{HeaderField, decode_stateless, encode_stateless};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, Join};

use crate::brutal::BrutalConfig;
use crate::hop::{HopPlan, PortHopRuntime};
use crate::obfs::SalamanderRuntime;
use crate::{codec as h2, varint};

const H3_CONTROL_STREAM: u64 = 0x00;
const H3_SETTINGS_FRAME: u64 = 0x04;
const H3_HEADERS_FRAME: u64 = 0x01;
const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const H3_SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
const MAX_RESPONSE_HEADERS_LEN: usize = 16 * 1024;
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
// Leave room for Salamander's eight-byte salt inside a conventional 1500-byte
// path MTU. IPv6 has the larger fixed network header.
const SALAMANDER_MAX_QUIC_PAYLOAD_IPV4: u16 = 1_464;
const SALAMANDER_MAX_QUIC_PAYLOAD_IPV6: u16 = 1_444;
/// Upper bound on any padding / skipped-frame length we will read off the QUIC stream. The value
/// is a server-supplied varint (up to 2^62); without a cap a malicious or corrupt server could
/// pin a reader in `skip` indefinitely. 64 KiB is far above any legitimate Hysteria2 padding.
const MAX_SKIP_LEN: usize = 64 * 1024;

/// An authenticated Hysteria2 QUIC connection. Cheap to clone (shares the connection); every
/// proxied flow opens its own stream.
pub struct Hysteria2Conn {
    conn: Connection,
    // Kept alive so the connection (and its H3 control stream) is not torn down.
    _endpoint: Endpoint,
    _control: SendStream,
    /// Whether the server advertised `hysteria-udp: true`.
    pub udp_enabled: bool,
}

impl Hysteria2Conn {
    /// Connect and authenticate one resolved candidate. The session resolves
    /// again and tries every candidate on each reconnect.
    pub async fn connect(
        cfg: &Hysteria2Config,
        server_addr: SocketAddr,
        dialer: &ProtectedDialer,
    ) -> io::Result<Arc<Self>> {
        // Build the UDP socket ourselves so its fd can be handed to `VpnService.protect()` before
        // QUIC sends anything — an unprotected first datagram would route back into our own TUN.
        let socket = dialer.bind_udp_std(server_addr.is_ipv6())?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        let runtime: Arc<dyn quinn::Runtime> = match &cfg.obfs {
            Some(Hysteria2ObfsConfig::Salamander { password }) => {
                let max_payload = if server_addr.is_ipv6() {
                    SALAMANDER_MAX_QUIC_PAYLOAD_IPV6
                } else {
                    SALAMANDER_MAX_QUIC_PAYLOAD_IPV4
                };
                endpoint_config
                    .max_udp_payload_size(max_payload)
                    .map_err(|error| other(format!("Salamander endpoint config: {error}")))?;
                Arc::new(SalamanderRuntime::new(password.expose()))
            }
            None => Arc::new(quinn::TokioRuntime),
        };
        // Port hopping wraps whatever socket the runtime above produced:
        // obfuscation rewrites the datagram body, hopping rewrites its address.
        let runtime = match hop_plan(cfg)? {
            Some(plan) => {
                Arc::new(PortHopRuntime::new(runtime, plan, server_addr)) as Arc<dyn quinn::Runtime>
            }
            None => runtime,
        };
        let mut endpoint = Endpoint::new(endpoint_config, None, socket, runtime)?;
        endpoint.set_default_client_config(build_client_config(cfg)?);

        let sni = cfg.tls.server_name.as_deref().unwrap_or(&cfg.server);
        let connecting = endpoint
            .connect(server_addr, sni)
            .map_err(|e| other(format!("quic connect config: {e}")))?;
        let conn = tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Hysteria2 QUIC handshake timed out",
                )
            })?
            .map_err(|e| other(format!("quic handshake: {e}")))?;

        // H3 control stream + SETTINGS (stateless QPACK: advertise no dynamic table).
        let mut control = conn.open_uni().await.map_err(quic_io)?;
        control.write_all(&control_settings_frame()).await?;

        let udp_enabled = authenticate(&conn, cfg).await?;

        Ok(Arc::new(Self {
            conn,
            _endpoint: endpoint,
            _control: control,
            udp_enabled,
        }))
    }

    /// The underlying QUIC connection, for the datagram-based UDP relay
    /// ([`crate::hysteria2_udp`]).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Open a proxied TCP flow to `target`. The returned duplex is `recv`+`send` joined, ready
    /// for the relay.
    ///
    /// The request goes out here; the server's response header is taken off the
    /// stream on first use, not before returning. Waiting for it here cost a
    /// full round trip before the caller could send its first byte, on every
    /// connection — the reference client does not pay it, and the same defect
    /// was fixed on the VLESS path in `e9d7918` for a stronger reason still: a
    /// server that emits its header only once the destination has spoken
    /// deadlocks against a client that will not hand over the stream until the
    /// header arrives.
    ///
    /// What must not be lost with the round trip is the refusal. See
    /// [`LazyTcpResponse`] for how a rejected flow surfaces, and why a write can
    /// still leave before the answer is known.
    pub async fn open_tcp(
        &self,
        target: &Destination,
    ) -> io::Result<LazyTcpResponse<Join<RecvStream, SendStream>>> {
        let (mut send, recv) = self.conn.open_bi().await.map_err(quic_io)?;
        let mut req = Vec::with_capacity(32);
        h2::encode_tcp_request(target, &[], &mut req).map_err(|e| other(e.to_string()))?;
        send.write_all(&req).await?;
        Ok(LazyTcpResponse::new(tokio::io::join(recv, send)))
    }
}

/// Bytes taken off the stream in one go while the response header is still
/// incomplete.
///
/// Sized against the header rather than against a payload: status, message and
/// padding can legitimately reach a few tens of kilobytes together
/// ([`h2::MAX_RESPONSE_PADDING_LEN`]), and a probe much smaller than that would
/// turn one server's padding into dozens of reads. Anything read past the header
/// is payload and is handed to the caller, so a large probe costs nothing.
const RESPONSE_PROBE: usize = 4096;

/// Where a flow is with respect to the server's response header.
enum Stage {
    /// The header has not fully arrived. Nothing has been delivered to the
    /// caller yet.
    Reading,
    /// The header is gone; everything from here is payload.
    Ready,
    /// The server refused, and said this. Latched: every later read *and* write
    /// fails with it, so a refused flow can never look like a quiet one.
    Refused(String),
}

/// A Hysteria2 TCP flow whose response header is consumed on first use.
///
/// The refusal contract, stated plainly because the lazy shape is what makes it
/// worth stating:
///
/// * The **first read** either delivers payload or fails. A server that refused
///   is reported at that read with its own message, and a server that hung up
///   before finishing its header is an `UnexpectedEof` rather than a clean empty
///   stream — a truncated refusal must not read as a zero-length success.
/// * A **write** cannot wait for the answer without reintroducing the round trip
///   this type exists to remove, so it does not. What it does do is take the
///   header if it has already arrived, which is the ordinary case for a refusal:
///   the server refuses immediately, so the second write and every write after
///   it fails. Once refused, nothing on this stream ever succeeds again.
pub struct LazyTcpResponse<S> {
    inner: S,
    /// Bytes read while looking for the end of the header. After the header is
    /// taken this holds the payload that arrived with it, and drains to empty.
    buffered: Vec<u8>,
    stage: Stage,
}

impl<S> LazyTcpResponse<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            buffered: Vec::new(),
            stage: Stage::Reading,
        }
    }
}

impl<S: AsyncRead + Unpin> LazyTcpResponse<S> {
    /// Read once and try again to take the header off the front.
    ///
    /// `Ready(Ok(()))` means progress was made, not that the header is complete;
    /// the caller re-reads [`Self::stage`] to find out.
    fn poll_take_header(&mut self, context: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        let mut chunk = [0_u8; RESPONSE_PROBE];
        let mut probe = tokio::io::ReadBuf::new(&mut chunk);
        ready!(std::pin::Pin::new(&mut self.inner).poll_read(context, &mut probe))?;
        let filled = probe.filled();
        if filled.is_empty() {
            // Not a clean end of stream: the server owed a header and stopped.
            // Reporting success here would turn a refusal the caller never saw
            // into an empty response body.
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "hysteria2 tcp response header truncated",
            )));
        }
        self.buffered.extend_from_slice(filled);

        let mut consumed = 0;
        match h2::decode_tcp_response(&self.buffered, &mut consumed) {
            Ok(response) => {
                self.buffered.drain(..consumed);
                self.stage = if response.ok {
                    Stage::Ready
                } else {
                    Stage::Refused(response.message)
                };
            }
            // More bytes will settle it.
            Err(crate::CodecError::Truncated) => {}
            // A length no server could mean. Refusing here is what keeps the
            // buffering above bounded.
            Err(error) => {
                return Poll::Ready(Err(other(format!(
                    "hysteria2 tcp response header: {error}"
                ))));
            }
        }
        Poll::Ready(Ok(()))
    }

    /// The error a refused flow owes its caller, if the refusal is already known
    /// or can be learned without waiting.
    fn refusal(&mut self, context: &mut std::task::Context<'_>) -> Option<io::Error> {
        loop {
            match &self.stage {
                Stage::Refused(message) => {
                    return Some(other(format!("hysteria2 tcp rejected: {message}")));
                }
                Stage::Ready => return None,
                // Never parks: `Pending` means the server has not answered yet,
                // and the caller's write is not waiting on that.
                Stage::Reading => match self.poll_take_header(context) {
                    Poll::Pending => return None,
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Some(error),
                },
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LazyTcpResponse<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &this.stage {
                Stage::Refused(message) => {
                    return Poll::Ready(Err(other(format!("hysteria2 tcp rejected: {message}"))));
                }
                Stage::Ready => {
                    if !this.buffered.is_empty() {
                        let take = this.buffered.len().min(buf.remaining());
                        buf.put_slice(&this.buffered[..take]);
                        this.buffered.drain(..take);
                        return Poll::Ready(Ok(()));
                    }
                    return std::pin::Pin::new(&mut this.inner).poll_read(context, buf);
                }
                Stage::Reading => ready!(this.poll_take_header(context))?,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for LazyTcpResponse<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.refusal(context) {
            return Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.inner).poll_write(context, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.refusal(context) {
            return Poll::Ready(Err(error));
        }
        std::pin::Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Deliberately not gated on the refusal: shutting down a flow the server
        // already refused is the right thing to do, and failing it would leave
        // the caller with a stream it cannot close cleanly.
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

/// Build the H3 control stream prefix: stream type + a SETTINGS frame declaring no QPACK
/// dynamic table (`0x1=0`, `0x7=0`), which is all a stateless-QPACK client needs.
fn control_settings_frame() -> Vec<u8> {
    let mut settings = Vec::new();
    varint::encode(H3_SETTING_QPACK_MAX_TABLE_CAPACITY, &mut settings);
    varint::encode(0, &mut settings);
    varint::encode(H3_SETTING_QPACK_BLOCKED_STREAMS, &mut settings);
    varint::encode(0, &mut settings);

    let mut out = Vec::new();
    varint::encode(H3_CONTROL_STREAM, &mut out);
    varint::encode(H3_SETTINGS_FRAME, &mut out);
    varint::encode(settings.len() as u64, &mut out);
    out.extend_from_slice(&settings);
    out
}

/// Send the H3 `POST /auth` request and parse the response. Returns whether UDP is enabled.
async fn authenticate(conn: &Connection, cfg: &Hysteria2Config) -> io::Result<bool> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(quic_io)?;

    let down_bps = u64::from(cfg.down_mbps) * 125_000;
    let headers = vec![
        HeaderField::new(b":method".to_vec(), b"POST".to_vec()),
        HeaderField::new(b":scheme".to_vec(), b"https".to_vec()),
        HeaderField::new(
            b":authority".to_vec(),
            h2::AuthRequest::AUTHORITY.as_bytes().to_vec(),
        ),
        HeaderField::new(b":path".to_vec(), h2::AuthRequest::PATH.as_bytes().to_vec()),
        HeaderField::new(
            b"hysteria-auth".to_vec(),
            cfg.password.expose().as_bytes().to_vec(),
        ),
        HeaderField::new(
            b"hysteria-cc-rx".to_vec(),
            down_bps.to_string().into_bytes(),
        ),
        HeaderField::new(b"hysteria-padding".to_vec(), Vec::new()),
    ];
    let mut block = Vec::new();
    encode_stateless(&mut block, headers).map_err(|e| other(format!("qpack encode: {e:?}")))?;

    let mut frame = Vec::with_capacity(block.len() + 8);
    varint::encode(H3_HEADERS_FRAME, &mut frame);
    varint::encode(block.len() as u64, &mut frame);
    frame.extend_from_slice(&block);
    send.write_all(&frame).await?;

    // Read frames until the response HEADERS; skip anything else.
    loop {
        let frame_type = read_varint(&mut recv).await?;
        let len = read_varint(&mut recv).await? as usize;
        if frame_type == H3_HEADERS_FRAME {
            if len == 0 || len > MAX_RESPONSE_HEADERS_LEN {
                return Err(other("hysteria2 auth response headers length invalid"));
            }
            let mut buf = vec![0u8; len];
            recv.read_exact(&mut buf).await.map_err(quic_read)?;
            return parse_auth_response(&buf);
        }
        if len > MAX_SKIP_LEN {
            return Err(other(format!(
                "hysteria2 auth response frame too long ({len})"
            )));
        }
        skip(&mut recv, len).await?;
    }
}

fn parse_auth_response(block: &[u8]) -> io::Result<bool> {
    let mut cursor: &[u8] = block;
    let decoded = decode_stateless(&mut cursor, MAX_RESPONSE_HEADERS_LEN as u64)
        .map_err(|e| other(format!("qpack decode: {e:?}")))?;

    let mut ok = false;
    let mut udp = false;
    for f in &decoded.fields {
        let name = f.name.as_ref();
        let value = f.value.as_ref();
        if name == b":status" {
            ok = value == h2::AUTH_OK_STATUS.as_bytes();
        } else if name.eq_ignore_ascii_case(b"hysteria-udp") {
            udp = value.eq_ignore_ascii_case(b"true");
        }
    }
    if !ok {
        return Err(other("hysteria2 auth rejected (status != 233)"));
    }
    Ok(udp)
}

fn build_client_config(cfg: &Hysteria2Config) -> io::Result<quinn::ClientConfig> {
    let mut tls_config = cfg.tls.clone();
    if tls_config.alpn.is_empty() {
        tls_config.alpn.push("h3".into());
    }
    let tls = Arc::unwrap_or_clone(rustls_client_config(&tls_config)?);

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| other(format!("quic tls: {e}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic_tls));

    let mut transport = quinn::TransportConfig::default();
    let target_bps = u64::from(cfg.up_mbps) * 125_000;
    if target_bps > 0 {
        transport.congestion_controller_factory(Arc::new(BrutalConfig::new(target_bps)));
    }
    let idle_timeout = Duration::from_secs(30)
        .try_into()
        .map_err(|_| other("hysteria2 idle timeout is outside QUIC limits"))?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// Read a QUIC varint from an async stream.
async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(r.read_u8().await?);
    }
    Ok(value)
}

async fn skip(recv: &mut RecvStream, mut len: usize) -> io::Result<()> {
    let mut buf = [0u8; 512];
    while len > 0 {
        let n = len.min(buf.len());
        recv.read_exact(&mut buf[..n]).await.map_err(quic_read)?;
        len -= n;
    }
    Ok(())
}

fn quic_io(e: quinn::ConnectionError) -> io::Error {
    other(format!("quic: {e}"))
}

fn quic_read(e: quinn::ReadExactError) -> io::Error {
    other(format!("quic read: {e}"))
}

fn other(m: impl Into<String>) -> io::Error {
    io::Error::other(m.into())
}

/// Expand the configured ranges into the port set the socket hops over.
///
/// The connection's own port is included: the reference treats the address it
/// dialled as one more member of the set, and leaving it out would make the very
/// first hop move away from the only port known to answer.
fn hop_plan(cfg: &Hysteria2Config) -> io::Result<Option<HopPlan>> {
    if cfg.server_ports.is_empty() {
        return Ok(None);
    }
    let mut ports = vec![cfg.port];
    for range in &cfg.server_ports {
        ports.extend(range.ports());
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(Some(HopPlan {
        ports: ports.into(),
        interval: Duration::from_millis(cfg.hop_interval_ms),
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// What the scripted peer does on the next read.
    enum Step {
        /// Hand over exactly these bytes.
        Chunk(Vec<u8>),
        /// End of stream.
        Eof,
        /// Say nothing, forever. No waker is registered, which is deliberate:
        /// any test that parks on this hangs, and a hang is the honest signal
        /// that the code under test waited when it was not supposed to.
        Silent,
    }

    /// A peer that answers reads from a script and records what was written.
    ///
    /// The scripting matters more than it looks: a server is free to deliver the
    /// response header one byte at a time, and an adapter that assumed a whole
    /// header per read would pass a single-chunk test and still stall on the
    /// wire.
    struct Scripted {
        steps: VecDeque<Step>,
        written: Vec<u8>,
    }

    impl Scripted {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: steps.into(),
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.steps.front() {
                Some(Step::Silent) | None => Poll::Pending,
                Some(Step::Eof) => Poll::Ready(Ok(())),
                Some(Step::Chunk(_)) => {
                    let Some(Step::Chunk(chunk)) = self.steps.pop_front() else {
                        unreachable!("front was just matched as a chunk")
                    };
                    buf.put_slice(&chunk);
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// `status | msg | padding`, the way the server writes it.
    fn response(status: u64, message: &str, padding: usize) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode(status, &mut out);
        varint::encode(message.len() as u64, &mut out);
        out.extend_from_slice(message.as_bytes());
        varint::encode(padding as u64, &mut out);
        out.extend(std::iter::repeat_n(0x00, padding));
        out
    }

    async fn read_payload<S>(stream: &mut LazyTcpResponse<S>, want: usize) -> io::Result<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut out = Vec::new();
        let mut chunk = [0_u8; 64];
        while out.len() < want {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..read]);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn the_caller_may_write_before_the_server_has_answered() {
        // The whole point of the change: the peer says nothing at all, and the
        // request still leaves. Under the eager reader this test could not be
        // written — `open_tcp` would not have returned yet.
        let mut stream = LazyTcpResponse::new(Scripted::new(vec![Step::Silent]));
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        assert_eq!(&stream.inner.written, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn payload_arriving_with_the_header_is_delivered() {
        let mut wire = response(0, "", 0);
        wire.extend_from_slice(b"hello");
        let mut stream = LazyTcpResponse::new(Scripted::new(vec![Step::Chunk(wire), Step::Eof]));
        assert_eq!(read_payload(&mut stream, 5).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn a_header_split_one_byte_per_read_is_still_taken() {
        let mut steps: Vec<Step> = response(0, "ok", 3)
            .into_iter()
            .map(|byte| Step::Chunk(vec![byte]))
            .collect();
        steps.push(Step::Chunk(b"payload".to_vec()));
        steps.push(Step::Eof);
        let mut stream = LazyTcpResponse::new(Scripted::new(steps));
        assert_eq!(read_payload(&mut stream, 7).await.unwrap(), b"payload");
    }

    #[tokio::test]
    async fn a_refusal_fails_the_first_read_and_stays_failed() {
        let mut stream = LazyTcpResponse::new(Scripted::new(vec![
            Step::Chunk(response(1, "no such host", 0)),
            Step::Chunk(b"payload that must never be delivered".to_vec()),
        ]));

        let error = read_payload(&mut stream, 1).await.unwrap_err();
        assert!(
            error.to_string().contains("no such host"),
            "the server's own reason must reach the caller: {error}"
        );
        // Latched, not one-shot: a caller that retried would otherwise be handed
        // the bytes the refusal said it may not have.
        let again = read_payload(&mut stream, 1).await.unwrap_err();
        assert!(again.to_string().contains("no such host"));
    }

    #[tokio::test]
    async fn a_refusal_that_has_already_arrived_fails_the_write() {
        // The ordinary shape of a refusal: the server answers immediately, so
        // the write that follows finds the answer waiting and fails instead of
        // pushing bytes into a flow that was never opened.
        let mut stream =
            LazyTcpResponse::new(Scripted::new(vec![Step::Chunk(response(1, "refused", 0))]));
        let error = stream.write_all(b"payload").await.unwrap_err();
        assert!(error.to_string().contains("refused"), "{error}");
        assert!(
            stream.inner.written.is_empty(),
            "a refused flow must not have carried the caller's bytes"
        );
    }

    #[tokio::test]
    async fn eof_before_the_header_is_an_error_not_an_empty_stream() {
        // A truncated header must not read as a clean end of stream: that would
        // turn a server that refused into a zero-length success.
        let mut stream =
            LazyTcpResponse::new(Scripted::new(vec![Step::Chunk(vec![0x00]), Step::Eof]));
        let error = read_payload(&mut stream, 1).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn padding_the_server_promises_but_never_sends_is_bounded() {
        // A length no legitimate server means. It has to be refused rather than
        // waited for, or the reader buffers against a peer that will never
        // finish its header.
        let mut header = Vec::new();
        varint::encode(0, &mut header);
        varint::encode(0, &mut header);
        varint::encode(1 << 40, &mut header);
        let mut stream = LazyTcpResponse::new(Scripted::new(vec![Step::Chunk(header)]));
        let error = read_payload(&mut stream, 1).await.unwrap_err();
        assert!(
            error.to_string().contains("exceeds protocol limit"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_message_longer_than_the_protocol_allows_is_refused() {
        let mut header = Vec::new();
        varint::encode(0, &mut header);
        varint::encode(h2::MAX_ADDRESS_LEN + 1, &mut header);
        let mut stream = LazyTcpResponse::new(Scripted::new(vec![Step::Chunk(header)]));
        let error = read_payload(&mut stream, 1).await.unwrap_err();
        assert!(
            error.to_string().contains("exceeds protocol limit"),
            "{error}"
        );
    }
}
