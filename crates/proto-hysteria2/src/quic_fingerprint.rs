//! What Hysteria2's QUIC client actually puts on the wire.
//!
//! Everything here is read back off a real first flight: the client dials a
//! loopback UDP socket that never answers, and `foxcore_transport::quic_initial`
//! decrypts the Initial packets exactly as an observer on the path would. No
//! server, no credentials, no traffic leaving the machine.
//!
//! The point of measuring rather than asserting on the configuration is that a
//! `TransportConfig` setter is a statement of intent and the datagram is a
//! fact. Two of the fields below are quinn defaults that nobody chose and that
//! nothing else on the internet sends.

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
        // Never succeeds: the capture socket answers nothing. The first flight
        // is sent before any reply could arrive, which is the whole point.
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

// ---------------------------------------------------------------------------
// Fields configuration reaches, and which this crate now sets.
// ---------------------------------------------------------------------------

/// The single largest tell that was on the wire, and the cheapest to remove.
///
/// quinn's default `initial_dst_cid_provider` draws `MAX_CID_SIZE` bytes. RFC
/// 9000 §7.2 permits 8..=20, measured Chromium 151 sends 8, and 20 is simply
/// the largest value the field can hold — so it identified the stack rather
/// than the connection.
#[tokio::test(flavor = "multi_thread")]
async fn the_initial_destination_connection_id_is_eight_bytes() {
    let flight = capture().await;
    assert_eq!(
        flight.first_packet().destination_connection_id.len(),
        INITIAL_DESTINATION_CONNECTION_ID_BYTES
    );
}

/// Negative control for the field above. quinn's untouched default is
/// reproduced here from its own source, so this test fails the day the fix
/// stops being a fix — either because the line was removed and 20 came back, or
/// because quinn changed its default and the comparison stopped meaning
/// anything.
#[test]
fn quinns_default_connection_id_length_is_the_one_we_are_moving_away_from() {
    use quinn_proto::{ConnectionIdGenerator, RandomConnectionIdGenerator};
    // quinn's `MAX_CID_SIZE` is private, so the value is written out here. RFC
    // 9000 §17.2 fixes it at 20 for QUIC v1, so this is a protocol constant
    // rather than a copy of an implementation detail that could drift.
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

/// `h3` is the only ALPN a QUIC connection can honestly offer.
#[tokio::test(flavor = "multi_thread")]
async fn the_alpn_is_h3() {
    let flight = capture().await;
    let hello = foxcore_transport::ja::parse(&flight.client_hello);
    assert_eq!(hello.alpn, vec![quic::DEFAULT_ALPN.to_owned()]);
}

/// Flow control moved off quinn's defaults and onto the values measured from
/// Chromium 151. `initial_max_data` mattered most: quinn's default is
/// `VarInt::MAX`, which reaches the wire as 4611686018427387903 — a number no
/// browser sends and nobody chose.
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
    // The negative control is the value that used to be there: quinn's
    // `VarInt::MAX` default. Reaching the wire again would mean the setter was
    // dropped.
    assert_ne!(
        varint(&flight, transport_parameter::INITIAL_MAX_DATA),
        Some(u64::MAX >> 2),
        "quinn's VarInt::MAX default is back on the wire"
    );
}

/// RFC 9287 `grease_quic_bit` is one more parameter in a set we want to look
/// ordinary, and measured Chromium 151 does not send it.
#[tokio::test(flavor = "multi_thread")]
async fn grease_quic_bit_is_not_advertised() {
    let flight = capture().await;
    assert!(
        !parameter_ids(&flight).contains(&transport_parameter::GREASE_QUIC_BIT),
        "0x2ab2 is still being sent"
    );
}

// ---------------------------------------------------------------------------
// Fields quinn already handles, verified rather than assumed.
// ---------------------------------------------------------------------------

/// quinn issue #2057 reported a constant reserved ("GREASE") transport
/// parameter, which would have been a per-binary constant on every connection.
/// The pin here is that 0.11.16 draws it per connection: the assumption was
/// worth checking and it came back fixed.
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

/// The order the parameters are written in is itself an observable, and a fixed
/// order would be a per-implementation constant. quinn 0.11.16 shuffles it, and
/// so does measured Chromium — so this needs no work, only evidence.
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

// ---------------------------------------------------------------------------
// Fields configuration does *not* reach. Pinned so the fork scope is a test
// rather than a paragraph: if a later quinn makes one of these configurable or
// drops it, this test is what says so.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_parameters_no_quinn_knob_reaches_are_recorded() {
    let flight = capture().await;
    let ids = parameter_ids(&flight);

    // quinn writes `min_ack_delay` unconditionally — `TransportParameters::new`
    // has no branch for it. Measured Chromium 151 does not send it at all.
    assert!(
        ids.contains(&transport_parameter::MIN_ACK_DELAY_DRAFT07),
        "min_ack_delay is no longer unconditional; the fork scope shrank"
    );

    // RFC 9368 version_information. quinn has no field for it; Chromium sends
    // it on every connection.
    assert!(
        !ids.contains(&transport_parameter::VERSION_INFORMATION),
        "quinn grew version_information support; the fork scope shrank"
    );

    // quinn derives max_datagram_frame_size from the receive buffer and clamps
    // it to `u16::MAX`, so 65536 — Chromium's value — is not expressible.
    assert_eq!(
        varint(&flight, transport_parameter::MAX_DATAGRAM_FRAME_SIZE),
        Some(u64::from(u16::MAX))
    );

    // One contiguous CRYPTO frame from offset zero. Chromium splits its hello
    // into a dozen out-of-order pieces interleaved with PING and PADDING.
    let first = flight.first_packet();
    assert_eq!(first.crypto.len(), 1, "quinn writes one CRYPTO frame");
    assert_eq!(first.crypto[0].0, 0, "starting at offset zero");
    assert_eq!(first.packet_number, 0, "and packet number zero");
}

/// The first flight's shape, which is the coarsest thing an observer sees.
/// quinn pads to the RFC 9000 §14.1 minimum of 1200; measured Chromium 151 pads
/// to 1250. Recorded rather than changed — see the report for why raising it is
/// not free on IPv6.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_flight_is_two_1200_byte_datagrams() {
    let flight = capture().await;
    assert_eq!(flight.datagram_lens(), vec![1200, 1200]);
}

/// JA4 over QUIC is JA4 with a `q`. With the ALPN and cipher list where they
/// now are, JA4_a and JA4_b are exactly the values FoxIO publish for Chrome's
/// QUIC fingerprint; JA4_c is not, and cannot be without a rustls fork.
#[tokio::test(flavor = "multi_thread")]
async fn the_quic_ja4_matches_the_published_chrome_prefix() {
    use foxcore_transport::ja;
    let flight = capture().await;
    let hello = ja::parse(&flight.client_hello);
    let (ja4, _raw) = ja::ja4_over(&hello, ja::Transport::Quic);
    let mut fields = ja4.split('_');
    assert_eq!(fields.next(), Some("q13d0312h3"), "JA4_a");
    assert_eq!(fields.next(), Some("55b375c5d22e"), "JA4_b");
    // Negative control: the same hello over TCP must not produce the same
    // string, or the transport character is being ignored.
    assert_ne!(ja::ja4(&hello).0, ja4);
}
