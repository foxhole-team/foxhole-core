#![forbid(unsafe_code)]

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use foxcore_api::{Destination, I2pConfig};
use foxcore_transport::{BoxDatagramSession, BoxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS_VERSION: u8 = 5;
const SOCKS_NO_AUTH: u8 = 0;
const SOCKS_USERNAME_PASSWORD: u8 = 2;
const SOCKS_AUTH_VERSION: u8 = 1;
const SOCKS_AUTH_SUCCESS: u8 = 0;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_DOMAIN: u8 = 3;

/// TCP-only adapter for the SOCKS5 listener owned by a separate i2pd process.
///
/// The proxy endpoint must be loopback and every destination must end in .i2p.
/// These checks are repeated here even when configuration validation already ran,
/// so a routing mistake cannot turn the adapter into a general-purpose proxy.
#[derive(Debug, Clone)]
pub struct I2pOutbound {
    config: I2pConfig,
}

impl I2pOutbound {
    pub fn new(config: I2pConfig) -> io::Result<Self> {
        validate_proxy_endpoint(config.socks_address)?;
        validate_credentials(&config)?;
        Ok(Self { config })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let host = normalized_i2p_host(&destination.host)?;
        let mut stream = tokio::time::timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            TcpStream::connect(self.config.socks_address),
        )
        .await
        .map_err(|_| timed_out("I2P SOCKS5 connect timed out"))??;
        stream.set_nodelay(true)?;

        tokio::time::timeout(
            Duration::from_millis(self.config.handshake_timeout_ms),
            socks5_connect(&mut stream, &host, destination.port, &self.config),
        )
        .await
        .map_err(|_| timed_out("I2P SOCKS5 handshake timed out"))??;

        Ok(Box::new(stream))
    }

    pub async fn connect_datagram(
        &self,
        _destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "I2P external adapter is TCP-only",
        ))
    }
}

async fn socks5_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    config: &I2pConfig,
) -> io::Result<()> {
    let method = if config.username.is_some() {
        SOCKS_USERNAME_PASSWORD
    } else {
        SOCKS_NO_AUTH
    };
    stream.write_all(&[SOCKS_VERSION, 1, method]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [SOCKS_VERSION, method] {
        return Err(invalid(
            "I2P SOCKS5 proxy rejected the required authentication method",
        ));
    }
    if method == SOCKS_USERNAME_PASSWORD {
        socks5_authenticate(stream, config).await?;
    }

    let host_length = u8::try_from(host.len())
        .map_err(|_| invalid("I2P destination exceeds SOCKS5 domain limit"))?;
    let mut request = Vec::with_capacity(7 + host.len());
    request.extend_from_slice(&[SOCKS_VERSION, SOCKS_CONNECT, 0, SOCKS_DOMAIN, host_length]);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != SOCKS_VERSION || response[2] != 0 {
        return Err(invalid("invalid I2P SOCKS5 response header"));
    }
    if response[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "I2P SOCKS5 proxy rejected destination",
        ));
    }

    match response[3] {
        1 => discard_exact(stream, 4 + 2).await,
        3 => {
            let length = stream.read_u8().await? as usize;
            discard_exact(stream, length + 2).await
        }
        4 => discard_exact(stream, 16 + 2).await,
        _ => Err(invalid("invalid I2P SOCKS5 bound-address type")),
    }
}

async fn socks5_authenticate(stream: &mut TcpStream, config: &I2pConfig) -> io::Result<()> {
    let (username, password) = match (&config.username, &config.password) {
        (Some(username), Some(password)) => (username.as_bytes(), password.expose().as_bytes()),
        _ => return Err(invalid("I2P SOCKS5 credentials are incomplete")),
    };
    let username_length = u8::try_from(username.len())
        .map_err(|_| invalid("I2P SOCKS5 username exceeds protocol limit"))?;
    let password_length = u8::try_from(password.len())
        .map_err(|_| invalid("I2P SOCKS5 password exceeds protocol limit"))?;
    if username_length == 0 || password_length == 0 {
        return Err(invalid("I2P SOCKS5 credentials must not be empty"));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[SOCKS_AUTH_VERSION, username_length]);
    request.extend_from_slice(username);
    request.push(password_length);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;

    let mut verdict = [0_u8; 2];
    stream.read_exact(&mut verdict).await?;
    if verdict != [SOCKS_AUTH_VERSION, SOCKS_AUTH_SUCCESS] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "I2P SOCKS5 authentication failed",
        ));
    }
    Ok(())
}

async fn discard_exact(stream: &mut TcpStream, length: usize) -> io::Result<()> {
    let mut buffer = [0_u8; 257];
    if length > buffer.len() {
        return Err(invalid("I2P SOCKS5 response address is too large"));
    }
    stream.read_exact(&mut buffer[..length]).await?;
    Ok(())
}

fn validate_proxy_endpoint(endpoint: SocketAddr) -> io::Result<()> {
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err(invalid(
            "I2P SOCKS5 endpoint must be a non-zero loopback socket address",
        ));
    }
    Ok(())
}

fn validate_credentials(config: &I2pConfig) -> io::Result<()> {
    match (&config.username, &config.password) {
        (None, None) => Ok(()),
        (Some(username), Some(password))
            if !username.is_empty()
                && username.len() <= u8::MAX as usize
                && !password.is_empty()
                && password.expose().len() <= u8::MAX as usize =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => Err(invalid("I2P SOCKS5 credentials must contain 1..=255 bytes")),
        _ => Err(invalid(
            "I2P SOCKS5 username and password must be set together",
        )),
    }
}

fn normalized_i2p_host(host: &str) -> io::Result<String> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > u8::MAX as usize || !host.is_ascii() {
        return Err(invalid("invalid I2P destination"));
    }
    let normalized = host.to_ascii_lowercase();
    if !normalized.ends_with(".i2p") || normalized.len() == 4 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "I2P adapter refuses non-.i2p destination",
        ));
    }
    if normalized.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(invalid("invalid I2P destination"));
    }
    Ok(normalized)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn config(address: SocketAddr) -> I2pConfig {
        I2pConfig {
            socks_address: address,
            username: None,
            password: None,
            // Generous because these tests assert protocol behaviour, not
            // latency. At one second the loopback connect lost a coin flip on a
            // busy machine, and the failure read as a broken handshake rather
            // than as a scheduler that was late.
            connect_timeout_ms: 5_000,
            handshake_timeout_ms: 5_000,
        }
    }

    fn authenticated_config(address: SocketAddr) -> I2pConfig {
        I2pConfig {
            username: Some("foxhole".into()),
            password: Some(foxcore_api::SecretString::new("i2p-test-password")),
            ..config(address)
        }
    }

    #[test]
    fn rejects_non_loopback_proxy_endpoint() {
        let error = I2pOutbound::new(config("192.0.2.1:4447".parse().unwrap())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_clearnet_before_connecting_to_proxy() {
        let outbound =
            I2pOutbound::new(config("127.0.0.1:9".parse().unwrap())).expect("valid endpoint");
        let error = outbound
            .connect_stream(&Destination::new("example.com", 80))
            .await
            .err()
            .expect("clearnet must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn performs_socks5_handshake_and_relays_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH])
                .await
                .unwrap();

            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(
                &request[..4],
                &[SOCKS_VERSION, SOCKS_CONNECT, 0, SOCKS_DOMAIN]
            );
            let mut host = vec![0_u8; request[4] as usize];
            stream.read_exact(&mut host).await.unwrap();
            assert_eq!(host, b"service.i2p");
            let port = stream.read_u16().await.unwrap();
            assert_eq!(port, 7656);
            stream
                .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();

            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let outbound = I2pOutbound::new(config(address)).unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("Service.I2P.", 7656))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn performs_authenticated_socks5_handshake_without_no_auth_downgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_USERNAME_PASSWORD]);
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_USERNAME_PASSWORD])
                .await
                .unwrap();

            let mut auth_header = [0_u8; 2];
            stream.read_exact(&mut auth_header).await.unwrap();
            assert_eq!(auth_header, [SOCKS_AUTH_VERSION, 7]);
            let mut username = [0_u8; 7];
            stream.read_exact(&mut username).await.unwrap();
            assert_eq!(&username, b"foxhole");
            let password_length = stream.read_u8().await.unwrap();
            let mut password = vec![0_u8; password_length as usize];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(password, b"i2p-test-password");
            stream
                .write_all(&[SOCKS_AUTH_VERSION, SOCKS_AUTH_SUCCESS])
                .await
                .unwrap();

            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            let mut host = vec![0_u8; request[4] as usize];
            stream.read_exact(&mut host).await.unwrap();
            let _port = stream.read_u16().await.unwrap();
            stream
                .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });

        let outbound = I2pOutbound::new(authenticated_config(address)).unwrap();
        outbound
            .connect_stream(&Destination::new("service.i2p", 7656))
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn refuses_proxy_attempt_to_downgrade_authenticated_i2p_to_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH])
                .await
                .unwrap();
        });

        let outbound = I2pOutbound::new(authenticated_config(address)).unwrap();
        let error = outbound
            .connect_stream(&Destination::new("service.i2p", 80))
            .await
            .err()
            .expect("authentication downgrade must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_malformed_proxy_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[4, SOCKS_NO_AUTH]).await.unwrap();
        });

        let outbound = I2pOutbound::new(config(address)).unwrap();
        let error = outbound
            .connect_stream(&Destination::new("service.i2p", 80))
            .await
            .err()
            .expect("invalid version must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
