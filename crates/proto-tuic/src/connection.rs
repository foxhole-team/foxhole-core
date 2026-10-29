use std::io;
use std::sync::Arc;
use std::time::Duration;

use foxcore_api::{Destination, TuicConfig, TuicCongestionControl};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{quic, rustls_client_config};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use quinn_proto::congestion::{CubicConfig, NewRenoConfig};
use tokio::io::Join;
use zeroize::Zeroize;

use crate::codec;

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
        let owned_config = config.clone();
        let owned_dialer = dialer.clone();
        dialer
            .connect_server_candidates(
                &config.server,
                config.port,
                config.server_ip,
                move |address| {
                    let config = owned_config.clone();
                    let dialer = owned_dialer.clone();
                    async move { Self::connect_address(&config, &dialer, address).await }
                },
            )
            .await
    }

    pub(crate) async fn connect_address(
        config: &TuicConfig,
        dialer: &ProtectedDialer,
        server_address: std::net::SocketAddr,
    ) -> io::Result<Arc<Self>> {
        let socket = dialer.bind_udp_std(server_address.is_ipv6())?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        quic_shape::apply_endpoint_shape(&mut endpoint_config);
        let mut endpoint =
            Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))?;
        endpoint.set_default_client_config(build_client_config(config)?);

        let sni = config.tls.server_name.as_deref().unwrap_or(&config.server);
        let connecting = endpoint
            .connect(server_address, sni)
            .map_err(|error| other(format!("TUIC QUIC connect config: {error}")))?;
        let connection = tokio::time::timeout(dialer.handshake_timeout(), connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUIC QUIC handshake timed out"))?
            .map_err(|error| other(format!("TUIC QUIC handshake: {error}")))?;

        let connection = Self {
            connection,
            _endpoint: endpoint,
        };
        authenticate(&connection.connection, config).await?;
        if let Some(diagnostic) = config.heartbeat_clamp() {
            log::warn!("{diagnostic}");
        }
        spawn_heartbeat(
            connection.connection.clone(),
            Duration::from_millis(config.effective_heartbeat_ms()),
        );

        Ok(Arc::new(connection))
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
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The authentication command itself is activity; the first heartbeat
        // belongs one full interval later, not immediately at task creation.
        ticker.tick().await;
        let mut last_sent = connection.stats().udp_tx.datagrams;
        loop {
            tokio::select! {
                _ = connection.closed() => return,
                _ = ticker.tick() => {
                    let sent = connection.stats().udp_tx.datagrams;
                    if sent != last_sent {
                        last_sent = sent;
                        continue;
                    }
                    if connection.send_datagram(Vec::from(codec::heartbeat()).into()).is_err() {
                        connection.close(VarInt::from_u32(1), b"TUIC heartbeat failed");
                        return;
                    }
                    last_sent = connection.stats().udp_tx.datagrams;
                }
            }
        }
    });
}

fn build_client_config(config: &TuicConfig) -> io::Result<quinn::ClientConfig> {
    let mut tls_config = config.tls.clone();
    if tls_config.alpn.is_empty() {
        tls_config.alpn.push(quic::DEFAULT_ALPN.into());
    }
    let tls = Arc::unwrap_or_clone(rustls_client_config(&tls_config)?);
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| other(format!("TUIC QUIC TLS: {error}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic_tls));
    client.initial_dst_cid_provider(Arc::new(quic_shape::initial_destination_connection_id));
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
    transport.datagram_receive_buffer_size(Some(quic::DATAGRAM_RECEIVE_BUFFER_BYTES));
    transport.datagram_send_buffer_size(quic::DATAGRAM_SEND_BUFFER_BYTES);
    quic_shape::apply_flow_control(&mut transport);
    client.transport_config(Arc::new(transport));
    Ok(client)
}

pub(crate) mod quic_shape {
    use foxcore_transport::quic;
    use quinn_proto::{ConnectionId, ConnectionIdGenerator, RandomConnectionIdGenerator};

    pub(crate) fn initial_destination_connection_id() -> ConnectionId {
        RandomConnectionIdGenerator::new(quic::INITIAL_DESTINATION_CONNECTION_ID_BYTES)
            .generate_cid()
    }

    pub(crate) fn apply_flow_control(transport: &mut quinn::TransportConfig) {
        transport.receive_window(quic::RECEIVE_WINDOW_BYTES.into());
        transport.stream_receive_window(quic::STREAM_RECEIVE_WINDOW_BYTES.into());
    }

    pub(crate) fn apply_endpoint_shape(endpoint: &mut quinn::EndpointConfig) {
        endpoint.grease_quic_bit(quic::GREASE_QUIC_BIT);
    }
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
    use foxcore_dialer::SocketCallbacks;
    use rustls_pki_types::PrivatePkcs8KeyDer;

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn a_blackholed_first_address_does_not_hide_a_working_tuic_peer() {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![quic::DEFAULT_ALPN.as_bytes().to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let reachable = endpoint.local_addr().unwrap();
        let black_hole = tokio::net::UdpSocket::bind(("127.0.0.2", reachable.port()))
            .await
            .unwrap();
        let silent = black_hole.local_addr().unwrap();
        let server_endpoint = endpoint.clone();
        let server = tokio::spawn(async move {
            let peer = server_endpoint.accept().await.unwrap().await.unwrap();
            let mut authenticate = peer.accept_uni().await.unwrap();
            let command = authenticate.read_to_end(50).await.unwrap();
            assert_eq!(&command[..2], &[5, 0]);
            assert_eq!(
                &command[2..18],
                &[
                    0x2d, 0xd6, 0x1d, 0x93, 0x75, 0xd8, 0x4d, 0xa4, 0xac, 0x0e, 0x6a, 0xec, 0xe7,
                    0xea, 0xc3, 0x65
                ]
            );
            let mut expected_token = [0_u8; 32];
            peer.export_keying_material(&mut expected_token, &command[2..18], b"synthetic")
                .unwrap();
            assert_eq!(&command[18..], &expected_token);
            peer
        });
        let mut config = black_hole_config(reachable.port());
        config.server = "localhost".into();
        config.tls.insecure = true;
        let callbacks =
            SocketCallbacks::none().with_resolver(move |_, _, _| Ok(vec![silent, reachable]));
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1))
            .with_handshake_timeout(Duration::from_secs(1));
        dialer.set_network_handle(1);

        let connection = tokio::time::timeout(
            dialer.handshake_timeout(),
            TuicConnection::connect(&config, &dialer),
        )
        .await
        .expect("the reachable candidate must authenticate within the shared handshake budget")
        .unwrap();
        let peer = server.await.unwrap();
        drop(connection);
        tokio::time::timeout(Duration::from_millis(500), peer.closed())
            .await
            .expect("discarding the connection must stop its heartbeat task");
    }

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

    fn black_hole_config(port: u16) -> TuicConfig {
        TuicConfig {
            server: "127.0.0.1".into(),
            port,
            server_ip: None,
            uuid: foxcore_api::SecretString::new("2dd61d93-75d8-4da4-ac0e-6aece7eac365"),
            password: foxcore_api::SecretString::new("synthetic"),
            congestion_control: TuicCongestionControl::Cubic,
            udp_relay_mode: foxcore_api::TuicUdpRelayMode::Native,
            tcp: true,
            udp: true,
            zero_rtt_handshake: false,
            heartbeat_ms: 10_000,
            idle_timeout_ms: 30_000,
            tls: foxcore_api::TlsConfig {
                enabled: true,
                ..Default::default()
            },
        }
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn the_quic_handshake_budget_comes_from_the_profile() {
        let black_hole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = black_hole_config(black_hole.local_addr().unwrap().port());
        let dialer = ProtectedDialer::host().with_handshake_timeout(Duration::from_millis(300));

        let started = std::time::Instant::now();
        let Err(error) = TuicConnection::connect(&config, &dialer).await else {
            panic!("a socket that never answers cannot complete a QUIC handshake");
        };
        let elapsed = started.elapsed();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(5),
            "the profile asked for 300ms and got {elapsed:?}"
        );
    }

    #[test]
    fn the_default_handshake_budget_is_the_fifteen_seconds_that_was_hardcoded() {
        assert_eq!(
            ProtectedDialer::host().handshake_timeout(),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn the_heartbeat_the_connection_runs_on_is_the_clamped_one() {
        let mut config = black_hole_config(443);
        config.heartbeat_ms = 120_000;
        config.idle_timeout_ms = 5_000;
        assert_eq!(config.effective_heartbeat_ms(), 2_500);
        assert!(config.heartbeat_clamp().is_some());
    }
}
