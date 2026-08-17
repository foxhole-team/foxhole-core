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

    /// Crate-visible rather than private so the fingerprint measurement in
    /// `quic_fingerprint.rs` can dial one address it owns. `connect` resolves a
    /// name first, and a measurement that had to go through DNS would be
    /// measuring the resolver as well as the QUIC client.
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
        // The profile's budget, not a constant in this file. Its default is the
        // 15 seconds that used to be hardcoded here, so a profile that says
        // nothing behaves exactly as it did.
        let connection = tokio::time::timeout(dialer.handshake_timeout(), connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUIC QUIC handshake timed out"))?
            .map_err(|error| other(format!("TUIC QUIC handshake: {error}")))?;

        authenticate(&connection, config).await?;
        if let Some(diagnostic) = config.heartbeat_clamp() {
            // Recorded rather than silent: the profile asked for a spacing this
            // connection is not using, and `logcat.rs` forwards `warn` and
            // above from every crate, including in a release build.
            log::warn!("{diagnostic}");
        }
        spawn_heartbeat(
            connection.clone(),
            Duration::from_millis(config.effective_heartbeat_ms()),
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
        // Never a catch-up burst. The default `Burst` behaviour counts the
        // ticks a sleeping phone missed and fires all of them the moment it
        // wakes: ten minutes of doze at the default interval is sixty
        // heartbeats back to back, which is a radio wakeup and sixty datagrams
        // to say the same thing once.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The authentication command itself is activity; the first heartbeat
        // belongs one full interval later, not immediately at task creation.
        ticker.tick().await;
        let mut last_sent = connection.stats().udp_tx.datagrams;
        loop {
            tokio::select! {
                _ = connection.closed() => return,
                _ = ticker.tick() => {
                    // A heartbeat exists to hold the NAT mapping open and keep
                    // the peer's idle timer from expiring. Traffic does both,
                    // so a connection that has put a datagram on the wire since
                    // the last check needs no extra one — and on a phone that
                    // datagram is a radio wakeup bought for nothing. Measured
                    // on the socket rather than on the relay, because that is
                    // where the NAT mapping is actually refreshed.
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
    // A profile that names no ALPN used to fall through to the shared TLS
    // default, which is `h2, http/1.1` — two *TCP* protocol identifiers, on a
    // QUIC connection. No browser and no reference TUIC client can produce
    // that hello: `h2` means HTTP/2 over TLS over TCP, and HTTP/3 over QUIC is
    // `h3`. It is a one-line tell that survives every other disguise, and it
    // put `h2` into this outbound's JA4 where `h3` belongs.
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

/// The handshake-shaping knobs, applied the same way hysteria2 applies them.
///
/// Every *value* comes from [`foxcore_transport::quic`], so the two QUIC
/// outbounds cannot drift into two fingerprints. Only this glue is per crate:
/// `foxcore-transport` is a dependency of protocols that have no business
/// linking quinn, so the crate that owns the numbers cannot own the calls.
/// `quic_fingerprint.rs` in both crates measures the result off the wire, which
/// is what would catch a copy that stopped matching.
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

    /// The handshake budget is the profile's, not a constant in this file.
    ///
    /// Dialled at a socket that is bound and never answers, so the QUIC
    /// handshake can only end by expiring. The elapsed bound is the assertion
    /// with teeth: with the old hardcoded 15 seconds this would still return
    /// `TimedOut`, thirty times later.
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

    /// And the default is exactly what was hardcoded, so a profile that says
    /// nothing about it behaves as it always did.
    #[test]
    fn the_default_handshake_budget_is_the_fifteen_seconds_that_was_hardcoded() {
        assert_eq!(
            ProtectedDialer::host().handshake_timeout(),
            Duration::from_secs(15)
        );
    }

    /// The clamp is not merely computed — the connection runs on it.
    #[test]
    fn the_heartbeat_the_connection_runs_on_is_the_clamped_one() {
        let mut config = black_hole_config(443);
        config.heartbeat_ms = 120_000;
        config.idle_timeout_ms = 5_000;
        assert_eq!(config.effective_heartbeat_ms(), 2_500);
        assert!(config.heartbeat_clamp().is_some());
    }
}
