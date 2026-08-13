#![forbid(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use foxcore_api::{Destination, TrojanConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{
    BoxDatagramSession, BoxStream, Datagram, ServerFirstStream, datagram_channel, establish_stream,
};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::sync::CancellationToken;

const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const CRLF: &[u8; 2] = b"\r\n";

#[derive(Clone)]
pub struct TrojanOutbound {
    config: Arc<TrojanConfig>,
    dialer: ProtectedDialer,
}

impl TrojanOutbound {
    pub async fn new(config: TrojanConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        if !config.tls.enabled {
            return Err(invalid("Trojan requires TLS"));
        }
        dialer
            .resolve_server_addresses(&config.server, config.port, config.server_ip)
            .await?;
        Ok(Self {
            config: Arc::new(config),
            dialer,
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        self.connect(COMMAND_CONNECT, destination).await
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        let stream = self.connect(COMMAND_UDP_ASSOCIATE, destination).await?;
        let (session, mut channels) = datagram_channel(64);
        let default_destination = destination.clone();
        let cancel = channels.cancel.clone();
        tokio::spawn(async move {
            relay_datagrams(
                stream,
                default_destination,
                &mut channels.uplink,
                channels.downlink,
                cancel,
            )
            .await;
        });
        Ok(session)
    }

    async fn connect(&self, command: u8, destination: &Destination) -> io::Result<BoxStream> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let stream = establish_stream(
            tcp,
            &self.config.tls,
            &self.config.transport,
            &self.config.server,
            self.config.port,
        )
        .await?;
        let prefix = request_header(self.config.password.expose(), command, destination)?;
        Ok(client_stream(stream, prefix))
    }
}

/// Compose the client stream: the request header in front of the first write,
/// wrapped so a read flushes it when the destination speaks first.
///
/// Trojan has no server greeting of its own — the proxy is transparent once the
/// header is accepted — so the header travelling with the first payload write is
/// what keeps the opening record the size of a real request. Against SSH, SMTP,
/// IMAP or any other protocol whose server sends the banner, that alone
/// deadlocks: the caller reads and never writes, and the header never leaves.
fn client_stream(stream: BoxStream, prefix: Bytes) -> BoxStream {
    Box::new(ServerFirstStream::new(PrefixedStream::new(stream, prefix)))
}

fn request_header(password: &str, command: u8, destination: &Destination) -> io::Result<Bytes> {
    let digest = Sha224::digest(password.as_bytes());
    let mut header = BytesMut::with_capacity(96);
    for byte in digest {
        header.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    header.extend_from_slice(CRLF);
    header.extend_from_slice(&[command]);
    encode_address(destination, &mut header)?;
    header.extend_from_slice(CRLF);
    Ok(header.freeze())
}

fn encode_address(destination: &Destination, output: &mut BytesMut) -> io::Result<()> {
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            output.extend_from_slice(&[ATYP_IPV4]);
            output.extend_from_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            output.extend_from_slice(&[ATYP_IPV6]);
            output.extend_from_slice(&address.octets());
        }
        None => {
            let domain = destination.host.as_bytes();
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(invalid("Trojan domain length must be in 1..=255"));
            }
            output.extend_from_slice(&[ATYP_DOMAIN, domain.len() as u8]);
            output.extend_from_slice(domain);
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

async fn decode_address<R>(reader: &mut R) -> io::Result<Destination>
where
    R: AsyncRead + Unpin,
{
    let host = match reader.read_u8().await? {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid("empty Trojan UDP domain"));
            }
            let mut domain = vec![0_u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| invalid("non-UTF-8 Trojan UDP domain"))?
        }
        other => return Err(invalid(format!("unsupported Trojan address type {other}"))),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

async fn relay_datagrams(
    stream: BoxStream,
    default_destination: Destination,
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            outgoing = uplink.recv() => {
                let Some(outgoing) = outgoing else { break };
                if outgoing.payload.is_empty() || outgoing.payload.len() > u16::MAX as usize {
                    continue;
                }
                let destination = if outgoing.destination.host.is_empty() {
                    &default_destination
                } else {
                    &outgoing.destination
                };
                let mut frame = BytesMut::with_capacity(32 + outgoing.payload.len());
                if encode_address(destination, &mut frame).is_err() {
                    continue;
                }
                frame.extend_from_slice(&(outgoing.payload.len() as u16).to_be_bytes());
                frame.extend_from_slice(CRLF);
                frame.extend_from_slice(&outgoing.payload);
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
            decoded = read_udp_frame(&mut reader) => {
                let Ok(datagram) = decoded else { break };
                if downlink.send(datagram).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn read_udp_frame<R>(reader: &mut R) -> io::Result<Datagram>
where
    R: AsyncRead + Unpin,
{
    let destination = decode_address(reader).await?;
    let length = reader.read_u16().await? as usize;
    let mut delimiter = [0_u8; 2];
    reader.read_exact(&mut delimiter).await?;
    if delimiter != *CRLF {
        return Err(invalid("invalid Trojan UDP delimiter"));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(Datagram::new(destination, Bytes::from(payload)))
}

struct PrefixedStream {
    inner: BoxStream,
    prefix: Bytes,
    written: usize,
}

impl PrefixedStream {
    fn new(inner: BoxStream, prefix: Bytes) -> Self {
        Self {
            inner,
            prefix,
            written: 0,
        }
    }

    fn poll_prefix(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.prefix.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(context, &self.prefix[self.written..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write Trojan request header",
                )));
            }
            self.written += written;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_prefix(context))?;
        // A zero-length write means "put the header out and carry nothing" —
        // that is how `ServerFirstStream` unblocks a server-first destination.
        // Passing it down would ask the carrier for write readiness this call
        // does not need, which on a full socket buffer parks the very read the
        // priming exists to release.
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_prefix(context))?;
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_prefix(context))?;
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_header_matches_trojan_spec() {
        let header = request_header(
            "password",
            COMMAND_CONNECT,
            &Destination::new("example.com", 443),
        )
        .unwrap();
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], COMMAND_CONNECT);
        assert_eq!(header[59], ATYP_DOMAIN);
        assert!(header.ends_with(CRLF));
        assert_eq!(
            &header[..56],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    /// A destination that speaks first — SSH, SMTP, IMAP, FTP, MySQL — never
    /// gives the caller a byte to piggyback the Trojan header on. Before this,
    /// the composed stream sent the header only from `poll_write`, so a caller
    /// that read first waited for a banner the server could not send because it
    /// had not yet been told where to connect. Nothing timed out and nothing
    /// errored; the flow simply stopped.
    #[tokio::test]
    async fn a_client_that_reads_first_still_sends_the_request_header() {
        let (carrier, mut server) = tokio::io::duplex(64 * 1024);
        let prefix = request_header(
            "password",
            COMMAND_CONNECT,
            &Destination::new("smtp.example", 25),
        )
        .unwrap();
        let expected = prefix.clone();
        let mut client = client_stream(Box::new(carrier), prefix);

        let peer = tokio::spawn(async move {
            let mut header = vec![0_u8; expected.len()];
            server.read_exact(&mut header).await.unwrap();
            assert_eq!(
                header,
                &expected[..],
                "the header must reach the server before any application byte"
            );
            server
                .write_all(b"220 smtp.example ESMTP\r\n")
                .await
                .unwrap();
            server
        });

        let mut banner = [0_u8; 24];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut banner),
        )
        .await
        .expect("a server-first destination must not deadlock")
        .unwrap();
        assert_eq!(&banner, b"220 smtp.example ESMTP\r\n");
        peer.await.unwrap();
    }

    /// The header still rides with the first payload when there is one, so a
    /// client-first flow keeps the opening record indistinguishable in size
    /// from an ordinary request.
    #[tokio::test]
    async fn a_client_that_writes_first_sends_header_and_payload_together() {
        let (carrier, mut server) = tokio::io::duplex(64 * 1024);
        let prefix = request_header(
            "password",
            COMMAND_CONNECT,
            &Destination::new("example.com", 443),
        )
        .unwrap();
        let mut expected = prefix.to_vec();
        let mut client = client_stream(Box::new(carrier), prefix);
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        client.flush().await.unwrap();
        expected.extend_from_slice(b"GET / HTTP/1.1\r\n");

        let mut opening = vec![0_u8; expected.len()];
        server.read_exact(&mut opening).await.unwrap();
        assert_eq!(opening, expected);
    }

    #[test]
    fn encodes_ipv4_and_ipv6_addresses() {
        let mut ipv4 = BytesMut::new();
        encode_address(&Destination::new("1.2.3.4", 53), &mut ipv4).unwrap();
        assert_eq!(&ipv4[..5], &[ATYP_IPV4, 1, 2, 3, 4]);

        let mut ipv6 = BytesMut::new();
        encode_address(&Destination::new("2001:db8::1", 443), &mut ipv6).unwrap();
        assert_eq!(ipv6[0], ATYP_IPV6);
        assert_eq!(&ipv6[ipv6.len() - 2..], &443_u16.to_be_bytes());
    }
}
