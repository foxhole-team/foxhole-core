use std::collections::HashSet;
use std::time::Duration;

use foxcore_api::{Hysteria2Config, SecretString, TlsConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::quic::{
    self, INITIAL_DESTINATION_CONNECTION_ID_BYTES, RECEIVE_WINDOW_BYTES,
    STREAM_RECEIVE_WINDOW_BYTES,
};
use foxcore_transport::quic_initial::{CapturedFlight, InitialCapture, transport_parameter};

fn synthetic_config() -> Hysteria2Config {
    Hysteria2Config {
        server: "hy2.example".into(),
        port: 443,
        server_ip: None,
        password: SecretString::new("synthetic"),
        up_mbps: 0,
        down_mbps: 0,
        obfs: None,
        server_ports: Vec::new(),
        hop_interval_ms: 30_000,
        keepalive_ms: 10_000,
        idle_timeout_ms: 30_000,
        tls: TlsConfig::default(),
    }
}

async fn capture() -> CapturedFlight {
    let config = synthetic_config();
    let listener = InitialCapture::bind().expect("loopback capture socket");
    let address = listener.local_addr().expect("capture address");
    let dialer = ProtectedDialer::host().with_handshake_timeout(Duration::from_secs(3));
    let connect = tokio::spawn(async move {
        let _ = crate::connection::Hysteria2Conn::connect(&config, address, &dialer).await;
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
async fn the_initial_destination_connection_id_is_eight_bytes() {
    let flight = capture().await;
    assert_eq!(
        flight.first_packet().destination_connection_id.len(),
        INITIAL_DESTINATION_CONNECTION_ID_BYTES
    );
}

#[test]
fn quinns_default_connection_id_length_is_the_one_we_are_moving_away_from() {
    use quinn_proto::{ConnectionIdGenerator, RandomConnectionIdGenerator};
    const MAX_CID_SIZE: usize = 20;
    let quinn_default = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
    assert_eq!(quinn_default.len(), 20, "quinn's default DCID length");
    assert_ne!(
        quinn_default.len(),
        INITIAL_DESTINATION_CONNECTION_ID_BYTES,
        "if these ever agree, the shaping below is a no-op and proves nothing"
    );
    assert_eq!(
        super::connection::quic_shape::initial_destination_connection_id().len(),
        INITIAL_DESTINATION_CONNECTION_ID_BYTES
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_alpn_is_h3() {
    let flight = capture().await;
    let hello = foxcore_transport::ja::parse(&flight.client_hello);
    assert_eq!(hello.alpn, vec![quic::DEFAULT_ALPN.to_owned()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_control_carries_the_measured_browser_values() {
    let flight = capture().await;
    assert_eq!(
        varint(&flight, transport_parameter::INITIAL_MAX_DATA),
        Some(u64::from(RECEIVE_WINDOW_BYTES))
    );
    for id in [
        transport_parameter::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        transport_parameter::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        transport_parameter::INITIAL_MAX_STREAM_DATA_UNI,
    ] {
        assert_eq!(
            varint(&flight, id),
            Some(u64::from(STREAM_RECEIVE_WINDOW_BYTES)),
            "stream window {id:#x}"
        );
    }
    assert_ne!(
        varint(&flight, transport_parameter::INITIAL_MAX_DATA),
        Some(u64::MAX >> 2),
        "quinn's VarInt::MAX default is back on the wire"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grease_quic_bit_is_not_advertised() {
    let flight = capture().await;
    assert!(
        !parameter_ids(&flight).contains(&transport_parameter::GREASE_QUIC_BIT),
        "0x2ab2 is still being sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reserved_transport_parameter_is_drawn_per_connection() {
    let mut seen = HashSet::new();
    for _ in 0..3 {
        let flight = capture().await;
        let reserved: Vec<u64> = parameter_ids(&flight)
            .into_iter()
            .filter(|id| transport_parameter::is_reserved(*id))
            .collect();
        assert_eq!(reserved.len(), 1, "exactly one reserved parameter");
        seen.insert(reserved[0]);
    }
    assert!(
        seen.len() > 1,
        "the reserved parameter id repeated across connections: {seen:#x?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_transport_parameter_order_moves_between_connections() {
    let mut orders = HashSet::new();
    for _ in 0..4 {
        orders.insert(parameter_ids(&capture().await));
    }
    assert!(
        orders.len() > 1,
        "every connection wrote the parameters in the same order: {orders:#x?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_parameters_no_quinn_knob_reaches_are_recorded() {
    let flight = capture().await;
    let ids = parameter_ids(&flight);

    assert!(
        ids.contains(&transport_parameter::MIN_ACK_DELAY_DRAFT07),
        "min_ack_delay is no longer unconditional; the fork scope shrank"
    );

    assert!(
        !ids.contains(&transport_parameter::VERSION_INFORMATION),
        "quinn grew version_information support; the fork scope shrank"
    );

    assert_eq!(
        varint(&flight, transport_parameter::MAX_DATAGRAM_FRAME_SIZE),
        Some(u64::from(u16::MAX))
    );

    let first = flight.first_packet();
    assert_eq!(first.crypto.len(), 1, "quinn writes one CRYPTO frame");
    assert_eq!(first.crypto[0].0, 0, "starting at offset zero");
    assert_eq!(first.packet_number, 0, "and packet number zero");
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
    assert_ne!(ja::ja4(&hello).0, ja4);
}
