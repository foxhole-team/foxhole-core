//! SOCKS5 outbound client for FoxCore (RFC 1928 + RFC 1929).
//!
//! `CONNECT` carries TCP flows and `UDP ASSOCIATE` carries datagram flows, so a
//! SOCKS5 profile is never quietly TCP-only. Hostnames are always put on the
//! wire as `ATYP=DOMAINNAME`, which keeps DNS on the proxy side.

#![forbid(unsafe_code)]

mod codec;
mod error;
mod udp;

#[cfg(feature = "fuzzing")]
pub mod fuzz_internals;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use foxcore_api::Destination;
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use codec::{
    CMD_CONNECT, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD, encode_auth, encode_greeting,
    encode_request, read_auth_status, read_method_selection, read_reply,
};
pub use error::{SocksError, SocksReply};

/// Matches the TLS/WebSocket handshake budget in `foxcore-transport`.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 15_000;

/// The typed profile lives in `foxcore-api`: it is the single dictionary the
/// core speaks, and a second definition here would let the two drift.
pub use foxcore_api::SocksConfig;

#[derive(Debug, Clone)]
pub struct SocksOutbound {
    config: Arc<SocksConfig>,
    dialer: ProtectedDialer,
}

impl SocksOutbound {
    pub async fn new(config: SocksConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        // Half-configured credentials are a configuration bug, and connecting
        // anonymously "because the password is missing" is exactly the silent
        // downgrade the core forbids.
        if config.username.is_some() != config.password.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 requires both username and password, or neither",
            ));
        }
        if config
            .password
            .as_ref()
            .is_some_and(foxcore_api::SecretString::is_empty)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 password must not be empty",
            ));
        }
        if config.handshake_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 handshake_timeout_ms must be greater than zero",
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
        let mut stream = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        self.run_handshake(&mut stream, CMD_CONNECT, destination)
            .await?;
        Ok(Box::new(stream))
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        udp::associate(self, destination).await
    }

    pub(crate) async fn run_handshake<S>(
        &self,
        stream: &mut S,
        command: u8,
        destination: &Destination,
    ) -> Result<Destination, SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(
            Duration::from_millis(self.config.handshake_timeout_ms),
            handshake(stream, self.credentials(), command, destination),
        )
        .await
        .map_err(|_| {
            SocksError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS5 handshake timed out",
            ))
        })?
    }

    fn credentials(&self) -> Option<(&str, &str)> {
        match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => Some((username.as_str(), password.expose())),
            _ => None,
        }
    }
}

/// Run the full client handshake and return the server's `BND.ADDR`/`BND.PORT`.
async fn handshake<S>(
    stream: &mut S,
    credentials: Option<(&str, &str)>,
    command: u8,
    destination: &Destination,
) -> Result<Destination, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let offered = if credentials.is_some() {
        METHOD_USERNAME_PASSWORD
    } else {
        METHOD_NO_AUTH
    };
    stream
        .write_all(&encode_greeting(credentials.is_some()))
        .await?;
    stream.flush().await?;
    read_method_selection(stream, offered).await?;

    if let Some((username, password)) = credentials {
        let mut request = encode_auth(username, password)?;
        let result = stream.write_all(&request).await;
        // The password lives in this buffer; clear it before the allocation is
        // released so it cannot outlive the handshake.
        request.fill(0);
        result?;
        stream.flush().await?;
        read_auth_status(stream).await?;
    }

    stream
        .write_all(&encode_request(command, destination)?)
        .await?;
    stream.flush().await?;
    read_reply(stream).await
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use foxcore_api::SecretString;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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

    /// Minimal in-process SOCKS5 server: reads one client handshake, replies
    /// with `script`, then echoes uppercased bytes.
    pub(crate) async fn spawn_server(
        script: Vec<u8>,
        expect_request: Option<Vec<u8>>,
        authenticated: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05);
            if authenticated {
                assert_eq!(greeting, [0x05, 0x01, 0x02]);
                stream.write_all(&[0x05, 0x02]).await.unwrap();
                let mut version_and_length = [0_u8; 2];
                stream.read_exact(&mut version_and_length).await.unwrap();
                assert_eq!(version_and_length[0], 0x01);
                let mut username = vec![0_u8; version_and_length[1] as usize];
                stream.read_exact(&mut username).await.unwrap();
                let password_length = stream.read_u8().await.unwrap() as usize;
                let mut password = vec![0_u8; password_length];
                stream.read_exact(&mut password).await.unwrap();
                assert_eq!(username, b"fox");
                assert_eq!(password, b"hole");
                stream.write_all(&[0x01, 0x00]).await.unwrap();
            } else {
                assert_eq!(greeting, [0x05, 0x01, 0x00]);
                stream.write_all(&[0x05, 0x00]).await.unwrap();
            }

            if let Some(expected) = expect_request {
                let mut request = vec![0_u8; expected.len()];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request, expected);
            }
            stream.write_all(&script).await.unwrap();

            let mut payload = [0_u8; 5];
            if stream.read_exact(&mut payload).await.is_ok() {
                payload.make_ascii_uppercase();
                let _ = stream.write_all(&payload).await;
            }
        });
        (address, handle)
    }

    fn outbound_config(address: SocketAddr) -> SocksConfig {
        SocksConfig {
            server: address.ip().to_string(),
            port: address.port(),
            ..SocksConfig::default()
        }
    }

    #[tokio::test]
    async fn connect_puts_the_hostname_on_the_wire_and_tunnels_bytes() {
        let expected = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb".to_vec();
        let reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38];
        let (address, server) = spawn_server(reply, Some(expected), false).await;

        let outbound = SocksOutbound::new(outbound_config(address), ProtectedDialer::host())
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
        server.await.unwrap();
    }

    #[tokio::test]
    async fn username_password_authentication_runs_before_the_request() {
        let expected = b"\x05\x01\x00\x01\x01\x02\x03\x04\x00\x50".to_vec();
        let reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let (address, server) = spawn_server(reply, Some(expected), true).await;

        let config = SocksConfig {
            username: Some("fox".into()),
            password: Some(SecretString::new("hole")),
            ..outbound_config(address)
        };
        let outbound = SocksOutbound::new(config, ProtectedDialer::host())
            .await
            .unwrap();
        outbound
            .connect_stream(&Destination::new("1.2.3.4", 80))
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_refusal_reaches_the_caller_with_its_reply_code() {
        let reply = vec![0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let (address, server) = spawn_server(reply, None, false).await;

        let outbound = SocksOutbound::new(outbound_config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<SocksError>())
            .expect("the SOCKS refusal must stay typed");
        assert!(matches!(
            typed,
            SocksError::Refused(SocksReply::ConnectionNotAllowed)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_truncated_reply_fails_instead_of_returning_a_half_open_tunnel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0_u8; 18];
            stream.read_exact(&mut request).await.unwrap();
            // Half of the ten-byte IPv4 reply, then the socket dies.
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127])
                .await
                .unwrap();
        });
        let outbound = SocksOutbound::new(outbound_config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_server_that_answers_with_socks4_is_rejected() {
        let (address, server) =
            spawn_server(vec![0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0], None, false).await;
        let outbound = SocksOutbound::new(outbound_config(address), ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_server_picking_an_unoffered_auth_method_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            // The client only offered username/password, so GSSAPI is a
            // downgrade attempt.
            stream.write_all(&[0x05, 0x01]).await.unwrap();
        });

        let config = SocksConfig {
            username: Some("fox".into()),
            password: Some(SecretString::new("hole")),
            ..outbound_config(address)
        };
        let outbound = SocksOutbound::new(config, ProtectedDialer::host())
            .await
            .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_proxy_that_accepts_and_then_stalls_hits_the_handshake_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Never answers the greeting, never closes.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(stream);
        });
        let outbound = SocksOutbound::new(
            SocksConfig {
                handshake_timeout_ms: 150,
                ..outbound_config(address)
            },
            ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let error = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        server.abort();
    }

    #[tokio::test]
    async fn half_configured_credentials_are_refused_at_construction() {
        let config = SocksConfig {
            server: "127.0.0.1".into(),
            port: 1080,
            username: Some("fox".into()),
            ..SocksConfig::default()
        };
        let error = SocksOutbound::new(config, ProtectedDialer::host())
            .await
            .expect_error();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn the_password_never_appears_in_debug_output() {
        let config = SocksConfig {
            server: "proxy.example".into(),
            port: 1080,
            server_ip: None,
            username: Some("fox".into()),
            password: Some(SecretString::new("super-secret")),
            ..SocksConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[tokio::test]
    async fn a_dead_proxy_surfaces_a_transport_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let outbound = SocksOutbound::new(outbound_config(address), ProtectedDialer::host()).await;
        if let Ok(outbound) = outbound {
            assert!(
                outbound
                    .connect_stream(&Destination::new("example.com", 443))
                    .await
                    .is_err()
            );
        }
        // Nothing must have been left listening on the dropped port.
        assert!(TcpStream::connect(address).await.is_err());
    }
}
