use foxcore_transport::quic_initial::{self, Frame, transport_parameter};

const CHROMIUM_151: &str =
    include_str!("../../../fixtures/quic-initial/chromium-151-first-flight.hex");

fn flight() -> Vec<quic_initial::InitialDatagram> {
    CHROMIUM_151
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let bytes: Vec<u8> = (0..line.len() / 2)
                .map(|index| u8::from_str_radix(&line[index * 2..index * 2 + 2], 16).expect("hex"))
                .collect();
            quic_initial::parse_datagram(&bytes).expect("a Chromium Initial datagram")
        })
        .collect()
}

#[test]
fn chromium_pads_its_initials_to_1250_bytes_not_1200() {
    let flight = flight();
    for datagram in &flight {
        assert_eq!(datagram.len, 1250);
        assert_eq!(
            datagram.packets.len(),
            1,
            "no coalescing in the first flight"
        );
    }
}

#[test]
fn chromium_uses_an_eight_byte_destination_connection_id_and_no_source_id() {
    let flight = flight();
    let first = &flight[0].packets[0];
    assert_eq!(first.version, quic_initial::VERSION_1);
    assert_eq!(
        first.destination_connection_id.len(),
        8,
        "Chromium's initial DCID is 8 bytes"
    );
    assert_eq!(
        first.source_connection_id.len(),
        0,
        "Chromium offers a zero-length source connection ID"
    );
    assert!(first.token.is_empty(), "no token on a first connection");
}

#[test]
fn chromiums_hello_spans_every_datagram_of_the_flight() {
    let flight = flight();
    assert_eq!(flight.len(), 2, "two datagrams in the first flight");
    for datagram in &flight {
        for packet in &datagram.packets {
            assert!(
                packet
                    .frames
                    .iter()
                    .any(|frame| matches!(frame, Frame::Crypto { .. })),
                "every Initial of the flight carries part of the hello"
            );
        }
    }
}

#[test]
fn chromium_does_not_grease_its_quic_hello() {
    let flight = flight();
    let hello = quic_initial::client_hello(&flight).expect("a complete ClientHello");
    let parsed = foxcore_transport::ja::parse(&hello);
    let grease = foxcore_transport::ja::is_grease;

    assert!(
        !parsed.ciphers.iter().copied().any(grease),
        "expected no GREASE cipher over QUIC: {:04x?}",
        parsed.ciphers
    );
    assert!(
        !parsed.extensions.iter().copied().any(grease),
        "expected no GREASE extension over QUIC: {:04x?}",
        parsed.extensions
    );
    assert!(
        !parsed.groups.iter().copied().any(grease),
        "expected no GREASE group over QUIC: {:04x?}",
        parsed.groups
    );
    assert_eq!(
        parsed.ciphers,
        vec![0x1301, 0x1302, 0x1303],
        "the three TLS 1.3 suites, and only those"
    );
}

#[test]
fn the_captured_hello_is_a_chromium_hello() {
    let flight = flight();
    let hello = quic_initial::client_hello(&flight).expect("a complete ClientHello");
    let parsed = foxcore_transport::ja::parse(&hello);

    assert_eq!(parsed.alpn, vec!["h3".to_owned()], "HTTP/3 ALPN");
    assert!(
        parsed
            .extensions
            .contains(&quic_initial::QUIC_TRANSPORT_PARAMETERS_EXTENSION),
        "a QUIC hello carries extension 0x39"
    );
    assert!(parsed.extensions.contains(&0x44cd), "ALPS");
    assert!(parsed.extensions.contains(&0xfe0d), "ECH");
    assert_eq!(parsed.groups.first(), Some(&0x11ec));
}

#[test]
fn the_cipher_hash_is_the_published_chrome_quic_value() {
    use foxcore_transport::ja;
    let flight = flight();
    let hello = quic_initial::client_hello(&flight).expect("ClientHello");
    let parsed = ja::parse(&hello);
    let (ja4, _raw) = ja::ja4_over(&parsed, ja::Transport::Quic);
    let mut fields = ja4.split('_');
    let a = fields.next().expect("JA4_a");
    assert!(a.starts_with('q'), "JA4 over QUIC starts with q: {a}");
    assert_eq!(fields.next(), Some("55b375c5d22e"), "JA4_b");
}

#[test]
fn chromium_scatters_its_client_hello_across_shuffled_crypto_frames() {
    let flight = flight();
    let first = &flight[0].packets[0];
    assert!(
        first.crypto.len() >= 5,
        "expected many CRYPTO frames, got {}",
        first.crypto.len()
    );
    assert!(
        first.crypto.first().map(|(offset, _)| *offset) != Some(0)
            || first.crypto.windows(2).any(|pair| pair[0].0 > pair[1].0),
        "expected the CRYPTO offsets to be out of order: {:?}",
        first.crypto.iter().map(|(o, _)| *o).collect::<Vec<_>>()
    );
    assert!(
        first
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::Ping)),
        "expected PING frames padding out the Initial"
    );
}

#[test]
fn chromium_starts_at_packet_number_one_and_widens_the_encoding() {
    let flight = flight();
    assert_eq!(flight[0].packets[0].packet_number, 1);
    assert_eq!(flight[0].packets[0].packet_number_len, 1);
    assert_eq!(flight[1].packets[0].packet_number, 2);
    assert_eq!(flight[1].packets[0].packet_number_len, 2);
}

#[test]
fn chromium_sends_version_information_which_is_the_parameter_quinn_has_no_field_for() {
    let flight = flight();
    let hello = quic_initial::client_hello(&flight).expect("ClientHello");
    let parameters = quic_initial::transport_parameters(&hello).expect("extension 0x39");
    let ids: Vec<u64> = parameters.iter().map(|p| p.id).collect();
    assert!(
        ids.contains(&transport_parameter::VERSION_INFORMATION),
        "RFC 9368 version_information (0x11) is in Chromium's set: {ids:#x?}"
    );
}

#[test]
fn chromium_draws_a_reserved_transport_parameter_too() {
    let flight = flight();
    let hello = quic_initial::client_hello(&flight).expect("ClientHello");
    let parameters = quic_initial::transport_parameters(&hello).expect("extension 0x39");
    assert!(
        parameters
            .iter()
            .any(|p| transport_parameter::is_reserved(p.id)),
        "Chromium includes a reserved (GREASE) transport parameter"
    );
}

#[test]
fn the_fixture_cannot_have_come_from_this_workspaces_own_client() {
    let flight = flight();
    let first = &flight[0].packets[0];

    assert_eq!(flight[0].len, 1250);

    assert_eq!(first.packet_number, 1);

    assert!(first.crypto.len() >= 5);

    let hello = quic_initial::client_hello(&flight).expect("ClientHello");
    let parsed = foxcore_transport::ja::parse(&hello);
    assert!(parsed.extensions.contains(&0x44cd));
    assert!(parsed.extensions.contains(&0xfe0d));

    let ids: Vec<u64> = quic_initial::transport_parameters(&hello)
        .expect("extension 0x39")
        .iter()
        .map(|p| p.id)
        .collect();
    assert!(ids.contains(&transport_parameter::VERSION_INFORMATION));
    assert!(ids.contains(&0x3128), "a Google-private code point");

    assert!(!ids.contains(&transport_parameter::MIN_ACK_DELAY_DRAFT07));
}

#[test]
fn the_fixture_is_a_real_encrypted_capture() {
    let line = CHROMIUM_151.lines().next().expect("a datagram");
    let mut bytes: Vec<u8> = (0..line.len() / 2)
        .map(|index| u8::from_str_radix(&line[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect();
    assert!(quic_initial::parse_datagram(&bytes).is_ok());
    bytes[7] ^= 0x01;
    assert!(
        quic_initial::parse_datagram(&bytes).is_err(),
        "a fixture that still parses with a mutated DCID would not be encrypted data"
    );
}
