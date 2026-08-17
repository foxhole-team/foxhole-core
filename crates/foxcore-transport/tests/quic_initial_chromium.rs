//! Chromium's own QUIC first flight, measured and pinned.
//!
//! `fixtures/quic-initial/chromium-151-first-flight.hex` is a capture, not a
//! transcription: Brave 151.1.93.136 (Chromium 151) was pointed at a loopback
//! UDP socket with `--origin-to-force-quic-on`, in a throwaway profile, and the
//! datagrams it sent before hearing anything back were written down verbatim.
//! Nothing was published, no live server was involved, and the only name in the
//! hello is the loopback address it was told to connect to.
//!
//! This is the comparison target for the QUIC half of the fingerprint surface,
//! and it is a fixture for the same reason the uTLS-derived tables are: a
//! number nobody can re-derive is a number nobody can check.

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
    // RFC 9000 §14.1 only requires 1200. Chromium's own default max packet
    // length is 1250, and it pads every Initial of the flight to it — so the
    // datagram size alone separates a Chromium QUIC client from most others.
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

/// The ML-KEM key share makes the hello far too big for one packet, so the
/// first flight is two datagrams and every one of them carries CRYPTO. Our own
/// clients reach the same shape for the same reason, which is why datagram
/// count is one of the few things that already matches.
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

/// The finding that changes what the TLS half of this comparison is worth.
///
/// Chromium's *TCP* hello is full of GREASE — a GREASE cipher, two GREASE
/// extensions, a GREASE key-share group — and reproducing it is most of why
/// `proto-reality` carries transcribed uTLS tables. Its **QUIC** hello has none
/// of it: BoringSSL does not turn GREASE on for the QUIC handshake. Whatever
/// else separates a rustls hello from a Chromium one over QUIC, GREASE is not
/// on the list, and JA4_b comes out identical for exactly that reason.
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
    // 0x44cd is ALPS (application settings) and 0xfe0d is ECH; both are
    // BoringSSL extensions rustls does not send, and they are what keeps JA4_c
    // apart even though JA4_a and JA4_b now agree.
    assert!(parsed.extensions.contains(&0x44cd), "ALPS");
    assert!(parsed.extensions.contains(&0xfe0d), "ECH");
    // X25519MLKEM768 first, which is also what this workspace's rustls provider
    // offers since the post-quantum fix.
    assert_eq!(parsed.groups.first(), Some(&0x11ec));
}

/// The published reference point. FoxIO's own README gives Chrome's QUIC JA4 as
/// `q13d0312h3_55b375c5d22e_06cda9e17597`. This capture is a different Chromium
/// build, so JA4_a's extension count differs by one, but JA4_b — the cipher
/// hash — is the published value exactly, which is what makes the capture
/// checkable against something nobody in this repository wrote.
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

/// Chromium's Initial packets do not carry the hello the way any other stack
/// does: it is cut into a dozen pieces, written out of order, and interleaved
/// with PING and PADDING. This is Chromium's chaos protection, and it is the
/// single largest thing on the QUIC surface that configuration cannot reach.
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

/// Two more things configuration cannot reach: Chromium's first Initial carries
/// packet number 1 with a one-byte encoding and the second carries 2 with a
/// two-byte encoding. quinn starts at 0. uQUIC's Chrome spec records the same
/// pattern, which is a second, independent witness for this capture.
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

/// Provenance, as a test rather than a claim in a comment.
///
/// This fixture was challenged on the grounds that its hello carries only the
/// three TLS 1.3 suites and no GREASE, which over **TCP** would indeed mean a
/// rustls hello rather than a Chromium one. Over QUIC it does not: QUIC
/// mandates TLS 1.3, so BoringSSL offers no TLS 1.2 suites, and it does not
/// turn GREASE on for the QUIC handshake at all. FoxIO publish both of Chrome's
/// fingerprints side by side for exactly this reason —
/// `t13d1516h2_8daaf6152771_…` over TCP and `q13d0312h3_55b375c5d22e_…` over
/// QUIC — and this capture's JA4_b is the published QUIC one.
///
/// Rather than rest on that, the checks below are the structural facts that
/// only a browser can produce. Every one of them is something our own stack
/// cannot emit at any setting, so if this file were ever re-captured from our
/// own client by mistake, this test fails instead of the comparison quietly
/// becoming a comparison with ourselves.
#[test]
fn the_fixture_cannot_have_come_from_this_workspaces_own_client() {
    let flight = flight();
    let first = &flight[0].packets[0];

    // 1. quinn pads client Initials to RFC 9000's 1200-byte minimum and has no
    //    setting that reaches 1250 without also raising the path MTU.
    assert_eq!(flight[0].len, 1250);

    // 2. quinn's initial packet number is 0. Chromium's is 1, and it widens the
    //    encoding to two bytes on the second packet.
    assert_eq!(first.packet_number, 1);

    // 3. quinn writes one contiguous CRYPTO frame from offset 0. This carries a
    //    dozen fragments, out of order, interleaved with PING.
    assert!(first.crypto.len() >= 5);

    // 4. rustls sends neither ALPS (0x44cd) nor ECH (0xfe0d); BoringSSL sends
    //    both. A reassembly error could not invent a well-formed extension.
    let hello = quic_initial::client_hello(&flight).expect("ClientHello");
    let parsed = foxcore_transport::ja::parse(&hello);
    assert!(parsed.extensions.contains(&0x44cd));
    assert!(parsed.extensions.contains(&0xfe0d));

    // 5. quinn has no field for RFC 9368 version_information (0x11) and cannot
    //    emit Google's private 0x3128 at all.
    let ids: Vec<u64> = quic_initial::transport_parameters(&hello)
        .expect("extension 0x39")
        .iter()
        .map(|p| p.id)
        .collect();
    assert!(ids.contains(&transport_parameter::VERSION_INFORMATION));
    assert!(ids.contains(&0x3128), "a Google-private code point");

    // 6. And quinn always sends min_ack_delay, which is absent here.
    assert!(!ids.contains(&transport_parameter::MIN_ACK_DELAY_DRAFT07));
}

/// Negative control for the whole fixture: the capture has to be real QUIC that
/// only decrypts with keys derived from its own DCID. Corrupt one byte of the
/// connection ID and every assertion above loses its input.
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
