use std::time::Duration;

use foxcore_api::{SecretString, TlsConfig, TuicConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::quic::{
    self, INITIAL_DESTINATION_CONNECTION_ID_BYTES, RECEIVE_WINDOW_BYTES,
    STREAM_RECEIVE_WINDOW_BYTES,
};
use foxcore_transport::quic_initial::{CapturedFlight, InitialCapture, transport_parameter};

fn synthetic_config() -> TuicConfig {
    TuicConfig {
        server: "tuic.example".into(),
        port: 443,
        server_ip: None,
        uuid: SecretString::new("2dd61d93-75d8-4da4-ac0e-6aece7eac365"),
        password: SecretString::new("synthetic"),
        congestion_control: foxcore_api::TuicCongestionControl::Cubic,
        udp_relay_mode: foxcore_api::TuicUdpRelayMode::Native,
        tcp: true,
        udp: true,
        zero_rtt_handshake: false,
        heartbeat_ms: 10_000,
        idle_timeout_ms: 30_000,
        tls: TlsConfig {
            enabled: true,
            ..TlsConfig::default()
        },
    }
}

async fn capture() -> CapturedFlight {
    let config = synthetic_config();
    let listener = InitialCapture::bind().expect("loopback capture socket");
    let address = listener.local_addr().expect("capture address");
    let dialer = ProtectedDialer::host().with_handshake_timeout(Duration::from_secs(3));
    let connect = tokio::spawn(async move {
        let _ = crate::connection::TuicConnection::connect_address(&config, &dialer, address).await;
    });
    let flight =
        tokio::task::spawn_blocking(move || listener.collect_first_flight(Duration::from_secs(5)))
            .await
            .expect("capture thread")
            .expect("a complete ClientHello in the first flight");
    connect.abort();
    flight
}

fn varint(flight: &CapturedFlight, id: u64) -> Option<u64> {
    flight
        .transport_parameters()
        .expect("transport parameters")
        .iter()
        .find(|parameter| parameter.id == id)
        .and_then(|parameter| parameter.as_varint())
}

fn parameter_ids(flight: &CapturedFlight) -> Vec<u64> {
    flight
        .transport_parameters()
        .expect("transport parameters")
        .iter()
        .map(|parameter| parameter.id)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_alpn_is_h3_and_not_the_tcp_default() {
    let flight = capture().await;
    let hello = foxcore_transport::ja::parse(&flight.client_hello);
    assert_eq!(hello.alpn, vec![quic::DEFAULT_ALPN.to_owned()]);
    assert!(
        !hello
            .alpn
            .iter()
            .any(|name| name == "h2" || name == "http/1.1"),
        "a TCP ALPN is back on a QUIC hello: {:?}",
        hello.alpn
    );
}

#[test]
fn the_shared_tls_default_alpn_is_still_the_tcp_pair() {
    let config = foxcore_transport::rustls_client_config(&TlsConfig::default())
        .expect("a default TLS profile builds");
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "if this ever changes, the QUIC ALPN override stops proving anything"
    );
    assert_ne!(
        config.alpn_protocols,
        vec![quic::DEFAULT_ALPN.as_bytes().to_vec()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_initial_destination_connection_id_is_eight_bytes() {
    let flight = capture().await;
    assert_eq!(
        flight.first_packet().destination_connection_id.len(),
        INITIAL_DESTINATION_CONNECTION_ID_BYTES,
        "quinn's untouched default is 20"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_control_carries_the_measured_browser_values() {
    let flight = capture().await;
    assert_eq!(
        varint(&flight, transport_parameter::INITIAL_MAX_DATA),
        Some(u64::from(RECEIVE_WINDOW_BYTES))
    );
    assert_ne!(
        varint(&flight, transport_parameter::INITIAL_MAX_DATA),
        Some(u64::MAX >> 2),
        "quinn's VarInt::MAX default is back on the wire"
    );
    assert_eq!(
        varint(
            &flight,
            transport_parameter::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
        ),
        Some(u64::from(STREAM_RECEIVE_WINDOW_BYTES))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grease_quic_bit_is_not_advertised() {
    let flight = capture().await;
    assert!(!parameter_ids(&flight).contains(&transport_parameter::GREASE_QUIC_BIT));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stream_limits_stay_where_the_protocol_needs_them() {
    let flight = capture().await;
    assert!(
        !parameter_ids(&flight).contains(&transport_parameter::INITIAL_MAX_STREAMS_BIDI),
        "a zero limit is the default, so it is omitted rather than sent"
    );
    assert_eq!(
        varint(&flight, transport_parameter::INITIAL_MAX_STREAMS_UNI),
        Some(256)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_flight_is_two_1200_byte_datagrams() {
    let flight = capture().await;
    assert_eq!(flight.datagram_lens(), vec![1200, 1200]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_quic_ja4_matches_the_published_chrome_prefix() {
    use foxcore_transport::ja;
    let flight = capture().await;
    let hello = ja::parse(&flight.client_hello);
    let (ja4, _raw) = ja::ja4_over(&hello, ja::Transport::Quic);
    let mut fields = ja4.split('_');
    assert_eq!(fields.next(), Some("q13d0312h3"), "JA4_a");
    assert_eq!(fields.next(), Some("55b375c5d22e"), "JA4_b");
}
