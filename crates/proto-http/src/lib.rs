//! HTTP CONNECT outbound client for FoxCore (RFC 9110 §9.3.6).
//!
//! A CONNECT tunnel is TCP and nothing else. UDP therefore fails closed with an
//! explicit error rather than quietly degrading a datagram flow onto a stream.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod leftover;

#[cfg(feature = "fuzzing")]
pub mod fuzz_internals;

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use foxcore_api::{Destination, SecretString};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream, wrap_tls};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use codec::{MAX_HEADER_BYTES, encode_connect, parse_response};
pub use error::HttpProxyError;
use leftover::LeftoverStream;

/// Read chunk for the response head. Small on purpose: the head is tiny and the
/// first payload bytes usually arrive in the same segment.
const HEAD_READ_CHUNK: usize = 1024;
/// Matches the TLS/WebSocket handshake budget in `foxcore-transport`.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 15_000;

// `Eq` is deliberately absent: `TlsConfig` only implements `PartialEq`.
/// The typed profile lives in `foxcore-api`; see the note in `proto-socks`.
pub use foxcore_api::HttpProxyConfig;

#[derive(Debug, Clone)]
pub struct HttpProxyOutbound {
    config: Arc<HttpProxyConfig>,
    dialer: ProtectedDialer,
}

impl HttpProxyOutbound {
    pub async fn new(config: HttpProxyConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        if config.username.is_some() != config.password.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP proxy requires both username and password, or neither",
            ));
        }
        if config
            .password
            .as_ref()
            .is_some_and(foxcore_api::SecretString::is_empty)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP proxy password must not be empty",
            ));
        }
        if config.handshake_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP proxy handshake_timeout_ms must be greater than zero",
            ));
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
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let stream = wrap_tls(tcp, &self.config.tls, &self.config.server).await?;
        Ok(connect(
            stream,
            destination,
            self.credentials(),
            &self.config.headers,
            Duration::from_millis(self.config.handshake_timeout_ms),
        )
        .await?)
    }

    /// Always an error: see the module docs. Reporting `Unsupported` here is
    /// what keeps a UDP flow from being silently rewritten onto TCP.
    pub async fn connect_datagram(
        &self,
        _destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        Err(HttpProxyError::UdpUnsupported.into())
    }

    fn credentials(&self) -> Option<(&str, &str)> {
        match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => Some((username.as_str(), password.expose())),
            _ => None,
        }
    }
}

/// Perform the CONNECT exchange on an already-established byte stream.
async fn connect<S>(
    stream: S,
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    headers: &BTreeMap<String, SecretString>,
    timeout: Duration,
) -> Result<BoxStream, HttpProxyError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    tokio::time::timeout(
        timeout,
        connect_unbounded(stream, destination, credentials, headers),
    )
    .await
    .map_err(|_| {
        HttpProxyError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "HTTP CONNECT handshake timed out",
        ))
    })?
}

async fn connect_unbounded<S>(
    mut stream: S,
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    headers: &BTreeMap<String, SecretString>,
) -> Result<BoxStream, HttpProxyError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut request = encode_connect(destination, credentials, headers)?;
    let written = stream.write_all(&request).await;
    // The request buffer holds `Proxy-Authorization`; clear it either way.
    request.fill(0);
    written?;
    stream.flush().await?;

    let mut buffer = BytesMut::with_capacity(HEAD_READ_CHUNK);
    let response = loop {
        if let Some(response) = parse_response(&buffer)? {
            break response;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(HttpProxyError::HeadersTooLarge(MAX_HEADER_BYTES));
        }
        if stream.read_buf(&mut buffer).await? == 0 {
            // Headers that stop without CRLFCRLF are not a tunnel.
            return Err(HttpProxyError::Malformed(
                "the proxy closed the connection before the response head ended",
            ));
        }
    };

    if !(200..300).contains(&response.status) {
        return Err(HttpProxyError::Status(response.status));
    }

    // Whatever arrived in the same buffer after the blank line is already
    // tunnel payload. Dropping it here would silently corrupt the very first
    // bytes the peer sent.
    let leftover = Bytes::copy_from_slice(&buffer[response.header_len..]);
    Ok(Box::new(LeftoverStream::new(stream, leftover)))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use foxcore_api::SecretString;

    use tokio::net::TcpListener;

    use super::*;

    /// `BoxStream` and `BoxDatagramSession` are trait objects without `Debug`,
    /// so `Result::unwrap_err` cannot be used on the outbound results.
    trait ExpectError {
        fn expect_error(self) -> io::Error;
    }

    impl<T> ExpectError for io::Result<T> {
        fn expect_error(self) -> io::Error {
            match self {
                Ok(_) => panic!("expected the call to fail"),
                Err(error) => error,
            }
        }
    }

    /// In-process proxy: reads the CONNECT head, answers with `script`, then
    /// echoes uppercased bytes.
    async fn spawn_proxy(
        script: &'static [u8],
        expected_request: Option<&'static [u8]>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = BytesMut::new();
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                if stream.read_buf(&mut head).await.unwrap() == 0 {
                    break;
                }
            }
            if let Some(expected) = expected_request {
                assert_eq!(head.as_ref(), expected);
            }
            stream.write_all(script).await.unwrap();

            let mut payload = [0_u8; 5];
            if stream.read_exact(&mut payload).await.is_ok() {
                payload.make_ascii_uppercase();
                let _ = stream.write_all(&payload).await;
            }
        });
        (address, handle)
    }

    fn config(address: SocketAddr) -> HttpProxyConfig {
        HttpProxyConfig {
            server: address.ip().to_string(),
            port: address.port(),
            ..HttpProxyConfig::default()
        }
    }

    #[tokio::test]
    async fn a_2xx_response_opens_the_tunnel() {
        let (address, proxy) = spawn_proxy(
            b"HTTP/1.1 200 Connection established\r\n\r\n",
            Some(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
        )
        .await;
        let outbound = HttpProxyOutbound::new(config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0_u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"HELLO");
        drop(stream);
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn payload_glued_to_the_response_head_is_not_lost() {
        // The proxy packs the first tunnel bytes into the same segment as the
        // blank line — the classic way to lose a server greeting.
        let (address, proxy) =
            spawn_proxy(b"HTTP/1.1 200 OK\r\nProxy-Agent: t\r\n\r\nEARLY", None).await;
        let outbound = HttpProxyOutbound::new(config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        let mut early = [0_u8; 5];
        stream.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"EARLY");

        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0_u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"HELLO");
        drop(stream);
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_authorization_is_sent_when_credentials_are_configured() {
        let (address, proxy) = spawn_proxy(
            b"HTTP/1.1 200 OK\r\n\r\n",
            Some(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic Zm94OmhvbGU=\r\n\r\n",
            ),
        )
        .await;
        let outbound = HttpProxyOutbound::new(
            HttpProxyConfig {
                username: Some("fox".into()),
                password: Some(SecretString::new("hole")),
                ..config(address)
            },
            ProtectedDialer::host(),
        )
        .await
        .unwrap();
        outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn a_407_is_a_typed_authentication_failure() {
        let (address, proxy) = spawn_proxy(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n",
            None,
        )
        .await;
        let outbound = HttpProxyOutbound::new(config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HttpProxyError>())
            .expect("the HTTP status must stay typed");
        assert_eq!(typed.status(), Some(407));
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn a_502_never_returns_a_stream() {
        let (address, proxy) = spawn_proxy(b"HTTP/1.1 502 Bad Gateway\r\n\r\n", None).await;
        let outbound = HttpProxyOutbound::new(config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn headers_that_stop_without_a_blank_line_are_not_a_tunnel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = BytesMut::new();
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                if stream.read_buf(&mut head).await.unwrap() == 0 {
                    return;
                }
            }
            // No CRLFCRLF, then EOF.
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nX-Truncated: 1\r\n")
                .await;
        });
        let outbound = HttpProxyOutbound::new(config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn a_proxy_that_accepts_and_then_stalls_hits_the_handshake_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Never answers, never closes.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let error = connect(
            stream,
            &Destination::new("example.com", 443),
            None,
            &BTreeMap::new(),
            Duration::from_millis(150),
        )
        .await
        .err()
        .map(io::Error::from)
        .expect("a stalled proxy must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        proxy.abort();
    }

    #[tokio::test]
    async fn an_unbounded_header_flood_is_cut_off() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = BytesMut::new();
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                if stream.read_buf(&mut head).await.unwrap() == 0 {
                    return;
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n").await;
            // Never sends the blank line.
            let filler = vec![b'x'; 4096];
            for _ in 0..64 {
                if stream.write_all(&filler).await.is_err() {
                    return;
                }
            }
        });
        let outbound = HttpProxyOutbound::new(config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            outbound.connect_stream(&Destination::new("example.com", 443)),
        )
        .await
        .expect("the bounded reader must stop on its own")
        .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        proxy.abort();
    }

    #[tokio::test]
    async fn udp_fails_closed_rather_than_degrading_to_tcp() {
        let outbound = HttpProxyOutbound::new(
            HttpProxyConfig {
                server: "127.0.0.1".into(),
                port: 3128,
                ..HttpProxyConfig::default()
            },
            ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let error = outbound
            .connect_datagram(&Destination::new("dns.example", 53))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn neither_the_password_nor_custom_headers_appear_in_debug_output() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Token".to_owned(), SecretString::new("cdn-token-value"));
        let config = HttpProxyConfig {
            server: "proxy.example".into(),
            port: 3128,
            username: Some("fox".into()),
            password: Some(SecretString::new("super-secret")),
            headers,
            ..HttpProxyConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("cdn-token-value"));
        // The header *name* is not a secret and stays visible for diagnostics.
        assert!(rendered.contains("X-Token"));
        assert!(rendered.contains("REDACTED"));
    }
}
