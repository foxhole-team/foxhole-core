use std::io;
use std::sync::Arc;
use std::time::Duration;

use foxcore_api::{Destination, TuicConfig, TuicCongestionControl};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::rustls_client_config;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use quinn_proto::congestion::{CubicConfig, NewRenoConfig};
use tokio::io::Join;
use zeroize::Zeroize;

use crate::codec;

const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const AUTH_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INCOMING_UNI_STREAMS: u32 = 256;

/// One authenticated TUIC v5 connection. Every TCP flow gets a fresh QUIC
/// bidirectional stream; UDP associations share the same QUIC connection.
pub struct TuicConnection {
    connection: Connection,
    _endpoint: Endpoint,
}

impl TuicConnection {
    pub async fn connect(config: &TuicConfig, dialer: &ProtectedDialer) -> io::Result<Arc<Self>> {
        let addresses = dialer
            .resolve_server_addresses(&config.server, config.port, config.server_ip)
            .await?;
        let mut last_error = None;
        for address in addresses {
            match Self::connect_address(config, dialer, address).await {
                Ok(connection) => return Ok(connection),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "TUIC server has no address")
        }))
    }

    async fn connect_address(
        config: &TuicConfig,
        dialer: &ProtectedDialer,
        server_address: std::net::SocketAddr,
    ) -> io::Result<Arc<Self>> {
        let socket = dialer.bind_udp_std(server_address.is_ipv6())?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(build_client_config(config)?);

        let sni = config.tls.server_name.as_deref().unwrap_or(&config.server);
        let connecting = endpoint
            .connect(server_address, sni)
            .map_err(|error| other(format!("TUIC QUIC connect config: {error}")))?;
        let connection = tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUIC QUIC handshake timed out"))?
            .map_err(|error| other(format!("TUIC QUIC handshake: {error}")))?;

        authenticate(&connection, config).await?;
        spawn_heartbeat(
            connection.clone(),
            Duration::from_millis(config.heartbeat_ms),
        );

        Ok(Arc::new(Self {
            connection,
            _endpoint: endpoint,
        }))
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> io::Result<Join<RecvStream, SendStream>> {
        let (mut send, receive) = self.connection.open_bi().await.map_err(quic_connection)?;
        let mut command = Vec::with_capacity(2 + 1 + destination.host.len() + 2);
        codec::encode_connect(destination, &mut command)
            .map_err(|error| other(error.to_string()))?;
        send.write_all(&command).await.map_err(quic_write)?;
        Ok(tokio::io::join(receive, send))
    }
}

impl Drop for TuicConnection {
    fn drop(&mut self) {
        self.connection
            .close(VarInt::from_u32(0), b"TUIC client closed");
    }
}

async fn authenticate(connection: &Connection, config: &TuicConfig) -> io::Result<()> {
    let uuid = parse_uuid(config.uuid.expose())?;
    let mut token = [0_u8; 32];
    connection
        .export_keying_material(&mut token, &uuid, config.password.expose().as_bytes())
        .map_err(|error| other(format!("TUIC TLS exporter: {error:?}")))?;

    let mut command = Vec::with_capacity(50);
    codec::encode_authenticate(&uuid, &token, &mut command);
    let result = async {
        let mut stream = connection.open_uni().await.map_err(quic_connection)?;
        stream.write_all(&command).await.map_err(quic_write)?;
        stream
            .finish()
            .map_err(|error| other(format!("TUIC authentication finish: {error}")))
    };
    let result = tokio::time::timeout(AUTH_WRITE_TIMEOUT, result)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "TUIC authentication stream timed out",
            )
        })?;
    token.zeroize();
    command.zeroize();
    result
}

fn spawn_heartbeat(connection: Connection, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The authentication command itself is activity; the first heartbeat
        // belongs one full interval later, not immediately at task creation.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = connection.closed() => return,
                _ = ticker.tick() => {
                    if connection.send_datagram(Vec::from(codec::heartbeat()).into()).is_err() {
                        connection.close(VarInt::from_u32(1), b"TUIC heartbeat failed");
                        return;
                    }
                }
            }
        }
    });
}

fn build_client_config(config: &TuicConfig) -> io::Result<quinn::ClientConfig> {
    let tls = Arc::unwrap_or_clone(rustls_client_config(&config.tls)?);
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| other(format!("TUIC QUIC TLS: {error}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    match config.congestion_control {
        TuicCongestionControl::Cubic => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        TuicCongestionControl::NewReno => {
            transport.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
        }
    }
    let idle_timeout = Duration::from_millis(config.idle_timeout_ms)
        .try_into()
        .map_err(|error| other(format!("TUIC idle timeout: {error}")))?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
    transport.max_concurrent_uni_streams(VarInt::from_u32(MAX_INCOMING_UNI_STREAMS));
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    client.transport_config(Arc::new(transport));
    Ok(client)
}

fn parse_uuid(value: &str) -> io::Result<[u8; 16]> {
    let mut output = [0_u8; 16];
    let mut high_nibble = None;
    let mut written = 0_usize;
    for byte in value.bytes().filter(|byte| *byte != b'-') {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(invalid_uuid()),
        };
        if let Some(high) = high_nibble.take() {
            if written >= output.len() {
                return Err(invalid_uuid());
            }
            output[written] = (high << 4) | nibble;
            written += 1;
        } else {
            high_nibble = Some(nibble);
        }
    }
    if written != output.len() || high_nibble.is_some() {
        return Err(invalid_uuid());
    }
    Ok(output)
}

fn invalid_uuid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TUIC uuid must contain exactly 32 hexadecimal digits",
    )
}

fn quic_connection(error: quinn::ConnectionError) -> io::Error {
    other(format!("TUIC QUIC connection: {error}"))
}

fn quic_write(error: quinn::WriteError) -> io::Error {
    other(format!("TUIC QUIC write: {error}"))
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_parser_accepts_canonical_and_compact_forms() {
        let canonical = parse_uuid("2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365").unwrap();
        let compact = parse_uuid("2dd61d9375d84da4ac0e6aece7eac365").unwrap();
        assert_eq!(canonical, compact);
        assert_eq!(&canonical[..4], &[0x2d, 0xd6, 0x1d, 0x93]);
    }

    #[test]
    fn uuid_parser_rejects_bad_lengths_and_non_hex() {
        assert!(parse_uuid("abcd").is_err());
        assert!(parse_uuid("2dd61d9375d84da4ac0e6aece7eac36z").is_err());
        assert!(parse_uuid("2dd61d9375d84da4ac0e6aece7eac36500").is_err());
    }
}
