use foxcore_transport::quic_initial::{
    self, Frame, QUIC_TRANSPORT_PARAMETERS_EXTENSION, VERSION_1, transport_parameter,
};

const RFC9001_A2: &str =
    include_str!("../../../fixtures/quic-initial/rfc9001-a2-client-initial.hex");

fn vector() -> Vec<u8> {
    let hex: String = RFC9001_A2.chars().filter(|c| !c.is_whitespace()).collect();
    (0..hex.len() / 2)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn the_rfc_sample_packet_is_a_1200_byte_datagram() {
    let bytes = vector();
    assert_eq!(bytes.len(), 1200);
    let datagram = quic_initial::parse_datagram(&bytes).expect("RFC 9001 A.2 parses");
    assert_eq!(datagram.len, 1200);
    assert_eq!(datagram.packets.len(), 1, "not a coalesced datagram");
}

#[test]
fn the_header_fields_are_the_ones_the_appendix_prints() {
    let bytes = vector();
    let packet = quic_initial::parse_initial(&bytes).expect("A.2 parses");

    assert_eq!(bytes[0], 0xc0, "the sample is protected on the wire");
    assert_eq!(packet.first_byte, 0xc3, "unprotected first byte");
    assert_eq!(packet.version, VERSION_1);
    assert_eq!(
        packet.destination_connection_id,
        b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
    );
    assert!(packet.source_connection_id.is_empty());
    assert!(packet.token.is_empty());
    assert_eq!(packet.packet_number, 2, "the appendix says packet number 2");
    assert_eq!(packet.packet_number_len, 4);
    assert_eq!(packet.packet_len, bytes.len());
}

#[test]
fn the_payload_decrypts_to_one_crypto_frame_and_1162_bytes_of_frames() {
    let bytes = vector();
    let packet = quic_initial::parse_initial(&bytes).expect("A.2 parses");

    assert_eq!(
        packet.frames.first(),
        Some(&Frame::Crypto {
            offset: 0,
            len: 241
        })
    );
    assert_eq!(
        packet.frames.get(1),
        Some(&Frame::Padding { len: 1162 - 245 })
    );
    assert_eq!(packet.frames.len(), 2, "nothing else is in there");
}

#[test]
fn the_crypto_frame_reassembles_into_the_appendix_client_hello() {
    let bytes = vector();
    let datagram = quic_initial::parse_datagram(&bytes).expect("A.2 parses");
    let hello = quic_initial::client_hello(&[datagram]).expect("one complete ClientHello");

    assert_eq!(hello[0], 0x01);
    assert_eq!(hello.len(), 4 + 0xed);

    let parsed = foxcore_transport::ja::parse(&hello);
    assert_eq!(parsed.ciphers, vec![0x1301, 0x1302]);
    assert!(parsed.has_sni, "the appendix hello carries example.com");
    assert_eq!(parsed.alpn, vec!["alpn".to_owned()]);
    assert_eq!(parsed.supported_versions, vec![0x0304]);
    assert!(
        parsed
            .extensions
            .contains(&QUIC_TRANSPORT_PARAMETERS_EXTENSION),
        "extension 0x39 is what makes this a QUIC hello: {:04x?}",
        parsed.extensions
    );
}

#[test]
fn the_transport_parameters_come_back_in_the_order_the_appendix_wrote_them() {
    let bytes = vector();
    let datagram = quic_initial::parse_datagram(&bytes).expect("A.2 parses");
    let hello = quic_initial::client_hello(&[datagram]).expect("ClientHello");
    let parameters = quic_initial::transport_parameters(&hello).expect("extension 0x39");

    let ids: Vec<u64> = parameters.iter().map(|p| p.id).collect();
    assert_eq!(
        ids,
        vec![
            transport_parameter::INITIAL_MAX_DATA,
            transport_parameter::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            transport_parameter::INITIAL_MAX_STREAM_DATA_UNI,
            transport_parameter::INITIAL_MAX_STREAMS_BIDI,
            transport_parameter::MAX_IDLE_TIMEOUT,
            transport_parameter::INITIAL_MAX_STREAMS_UNI,
            transport_parameter::INITIAL_SOURCE_CONNECTION_ID,
            transport_parameter::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        ]
    );

    let by_id = |id: u64| {
        parameters
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.as_varint())
    };
    assert_eq!(by_id(transport_parameter::MAX_IDLE_TIMEOUT), Some(30_000));
    assert_eq!(
        by_id(transport_parameter::INITIAL_MAX_STREAMS_BIDI),
        Some(16)
    );
    assert_eq!(
        by_id(transport_parameter::INITIAL_MAX_DATA),
        Some(u64::MAX >> 2),
        "0408ffffffffffffffff is the largest 8-byte varint"
    );
    assert_eq!(
        parameters
            .iter()
            .find(|p| p.id == transport_parameter::INITIAL_SOURCE_CONNECTION_ID)
            .map(|p| p.value.clone()),
        Some(b"\x83\x94\xc8\xf0\x3e\x51\x57\x08".to_vec()),
        "the client's own connection ID, echoed as a transport parameter"
    );
}

#[test]
fn a_single_flipped_payload_bit_fails_authentication() {
    let mut bytes = vector();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let error = quic_initial::parse_initial(&bytes).expect_err("the tag must not verify");
    assert!(
        error.to_string().contains("AEAD"),
        "expected an authentication failure, got: {error}"
    );
}

#[test]
fn a_flipped_header_bit_fails_authentication_too() {
    let mut bytes = vector();
    bytes[15] ^= 0x08;
    assert!(
        quic_initial::parse_initial(&bytes).is_err(),
        "a mutated header must not authenticate"
    );
}

#[test]
fn perturbing_the_header_protection_sample_breaks_the_parse() {
    let mut bytes = vector();
    bytes[26] ^= 0xff;
    assert!(
        quic_initial::parse_initial(&bytes).is_err(),
        "a mutated header-protection sample must not yield a valid packet"
    );
}

#[test]
fn the_keys_come_from_the_destination_connection_id() {
    let mut bytes = vector();
    bytes[6] ^= 0x01;
    assert!(
        quic_initial::parse_initial(&bytes).is_err(),
        "Initial keys must be derived from the DCID"
    );
}

#[test]
fn a_client_hello_missing_its_tail_is_an_error_not_a_short_hello() {
    let bytes = vector();
    let mut datagram = quic_initial::parse_datagram(&bytes).expect("A.2 parses");
    for packet in &mut datagram.packets {
        for (_, data) in &mut packet.crypto {
            data.truncate(data.len() - 1);
        }
    }
    let error = quic_initial::client_hello(&[datagram]).expect_err("must not return a short hello");
    assert!(
        error.to_string().contains("short of its declared"),
        "got: {error}"
    );
}

#[test]
fn reserved_transport_parameter_ids_are_the_rfc_sequence() {
    assert!(transport_parameter::is_reserved(27));
    assert!(transport_parameter::is_reserved(31 * 5 + 27));
    assert!(transport_parameter::is_reserved(31 * 1000 + 27));
    assert!(!transport_parameter::is_reserved(0x01));
    assert!(!transport_parameter::is_reserved(0x39));
    assert!(!transport_parameter::is_reserved(31 * 5 + 28));
}
