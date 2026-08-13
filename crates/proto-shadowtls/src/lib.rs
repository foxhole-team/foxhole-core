//! Clean-room strict ShadowTLS v3 client transport.
//!
//! ShadowTLS itself carries a TCP byte stream, not a destination. FoxCore
//! therefore exposes the production composition ShadowTLS → Shadowsocks
//! explicitly. UDP uses UoT v2 over that inner Shadowsocks stream.
//! The protocol implementation is derived only from the public v3 protocol
//! document without copying another implementation.
//!
//! Protocol source:
//! <https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md>

#![forbid(unsafe_code)]

#[cfg(feature = "fuzzing")]
pub mod fuzz_internals;
mod handshake;
mod transport;
mod uot;
mod wire;

use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use foxcore_api::{Destination, ShadowTlsConfig, ShadowTlsInnerConfig, TlsVersion};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream, ServerFirstStream};
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;

#[derive(Clone)]
pub struct ShadowTlsOutbound {
    config: Arc<ShadowTlsConfig>,
    inner_server: Arc<ServerConfig>,
    context: SharedContext,
    dialer: ProtectedDialer,
    udp_over_tcp: bool,
}

impl ShadowTlsOutbound {
    pub async fn new(config: ShadowTlsConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        validate_runtime_config(&config)?;
        let server_address = dialer
            .resolve_server(&config.server, config.port, config.server_ip)
            .await?;
        let (method, password, udp_over_tcp) = match &config.inner {
            ShadowTlsInnerConfig::Shadowsocks {
                method,
                password,
                udp_over_tcp,
            } => (method, password, *udp_over_tcp),
        };
        let method = CipherKind::from_str(method)
            .map_err(|error| invalid(format!("unsupported inner Shadowsocks method: {error}")))?;
        let inner_server = ServerConfig::new(
            ServerAddr::SocketAddr(server_address),
            password.expose(),
            method,
        )
        .map_err(|error| invalid(format!("invalid inner Shadowsocks configuration: {error}")))?;
        Ok(Self {
            config: Arc::new(config),
            inner_server: Arc::new(inner_server),
            context: Context::new_shared(ServerType::Local),
            dialer,
            udp_over_tcp,
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let transport = self.connect_transport().await?;
        Ok(self.inner_stream(transport, destination))
    }

    /// Layer the inner Shadowsocks codec over an established ShadowTLS carrier.
    ///
    /// The inner stream sends its salt and target address on the first *write*,
    /// which deadlocks every destination whose server speaks first: the caller
    /// waits for a banner and the Shadowsocks server waits to be told where to
    /// connect. [`ServerFirstStream`] turns the caller's first read into the
    /// zero-length write that emits the header and nothing else, so a
    /// client-first flow still opens with header and payload in one piece.
    fn inner_stream<S>(&self, transport: S, destination: &Destination) -> BoxStream
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        Box::new(ServerFirstStream::new(ProxyClientStream::from_stream(
            self.context.clone(),
            transport,
            &self.inner_server,
            to_address(destination),
        )))
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        if !self.udp_over_tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP-over-TCP is disabled for this ShadowTLS profile",
            ));
        }
        let transport = self.connect_transport().await?;
        let stream = self.inner_stream(transport, &uot::magic_destination());
        uot::open(stream, destination.clone()).await
    }

    async fn connect_transport(&self) -> io::Result<BoxStream> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        handshake::connect(tcp, &self.config).await
    }
}

fn validate_runtime_config(config: &ShadowTlsConfig) -> io::Result<()> {
    if config.password.is_empty() {
        return Err(invalid("ShadowTLS password must not be empty"));
    }
    if !config.tls.enabled
        || config.tls.min_version == Some(TlsVersion::Tls12)
        || config.tls.max_version == Some(TlsVersion::Tls12)
    {
        return Err(invalid("ShadowTLS v3 strict mode requires TLS 1.3"));
    }
    if !config.tls.alpn.is_empty() && config.tls.alpn != ["http/1.1"] {
        return Err(invalid(
            "ShadowTLS muddled fallback requires empty or HTTP/1.1 ALPN",
        ));
    }
    if !(1..=120_000).contains(&config.handshake_timeout_ms) {
        return Err(invalid(
            "ShadowTLS handshake_timeout_ms must be in 1..=120000",
        ));
    }
    Ok(())
}

fn to_address(destination: &Destination) -> Address {
    match destination.ip() {
        Some(ip) => Address::SocketAddress(SocketAddr::new(ip, destination.port)),
        None => Address::DomainNameAddress(destination.host.clone(), destination.port),
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_is_preserved_for_the_inner_protocol() {
        assert_eq!(
            to_address(&Destination::new("example.com", 443)),
            Address::DomainNameAddress("example.com".to_owned(), 443)
        );
    }

    fn profile() -> ShadowTlsConfig {
        ShadowTlsConfig {
            server: "127.0.0.1".into(),
            port: 443,
            server_ip: None,
            password: foxcore_api::SecretString::new("hunter2"),
            inner: ShadowTlsInnerConfig::Shadowsocks {
                method: "chacha20-ietf-poly1305".into(),
                password: foxcore_api::SecretString::new("inner"),
                udp_over_tcp: true,
            },
            tls: foxcore_api::TlsConfig {
                enabled: true,
                min_version: Some(TlsVersion::Tls13),
                max_version: Some(TlsVersion::Tls13),
                ..foxcore_api::TlsConfig::default()
            },
            handshake_timeout_ms: 15_000,
        }
    }

    /// ShadowTLS carries a plain byte stream, so everything a destination needs
    /// to be reachable is written by the *inner* Shadowsocks codec — on the
    /// first application write. A caller that reads first (SSH, SMTP, IMAP,
    /// FTP, MySQL) therefore hung with the carrier up and zero bytes inside it.
    ///
    /// The outer v3 handshake is not re-proved here; it has its own tests. This
    /// drives the exact composition `connect_stream` returns over a carrier the
    /// test owns, so the assertion is about what the inner server receives.
    #[tokio::test]
    async fn a_caller_that_reads_first_still_sends_the_inner_request_header() {
        use shadowsocks::relay::tcprelay::crypto_io::{CryptoRead, CryptoStream, StreamType};
        use tokio::io::{AsyncReadExt, ReadBuf};

        let outbound = ShadowTlsOutbound::new(profile(), ProtectedDialer::host())
            .await
            .unwrap();
        let (carrier, inner_server) = tokio::io::duplex(64 * 1024);

        let context = outbound.context.clone();
        let inner = outbound.inner_server.clone();
        let accept = tokio::spawn(async move {
            let mut crypto = CryptoStream::from_stream(
                &context,
                inner_server,
                StreamType::Server,
                inner.method(),
                inner.key(),
            );
            let mut buffer = vec![0_u8; 512];
            let mut read = ReadBuf::new(&mut buffer);
            std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut crypto).poll_read_decrypted(cx, &context, &mut read)
            })
            .await
            .unwrap();
            read.filled().to_vec()
        });

        let mut stream = outbound.inner_stream(carrier, &Destination::new("example.com", 443));
        let reader = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), accept)
            .await
            .expect("a server-first destination must not deadlock")
            .unwrap();
        reader.abort();

        let mut expected = bytes::BytesMut::new();
        Address::DomainNameAddress("example.com".to_owned(), 443).write_to_buf(&mut expected);
        assert_eq!(received, &expected[..]);
    }
}
