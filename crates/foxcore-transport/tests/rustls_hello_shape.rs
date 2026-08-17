//! What the generic (rustls) TLS path actually puts on the wire.
//!
//! `proto-reality` writes its own ClientHello from a table transcribed from
//! uTLS, so the REALITY path is a parrot. Every *other* protocol that speaks
//! TLS here — VLESS/VMess/Trojan/Shadowsocks/AnyTLS/Naive/HTTP over TLS — goes
//! through rustls, which decides its own hello shape.
//!
//! Nobody had measured the difference. This file does: it captures the real
//! bytes off a socket and asserts, field by field, what rustls sends. It is a
//! measurement first and a regression guard second — when rustls changes its
//! hello, this test says so and the numbers in the comparison note stop being
//! fiction.
//!
//! Everything is synthetic and nothing leaves the machine: the "server" is a
//! `TcpListener` on 127.0.0.1 that reads one record and hangs up.

use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use foxcore_api::TlsConfig;
use foxcore_transport::rustls_client_config;

/// Fields of a ClientHello, parsed back off the wire.
#[derive(Debug)]
struct Hello {
    record_version: [u8; 2],
    legacy_version: u16,
    session_id_len: usize,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    /// Extension code points, in the order they were sent.
    extensions: Vec<u16>,
    supported_groups: Vec<u16>,
    key_share_groups: Vec<u16>,
    supported_versions: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn: Vec<String>,
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn parse(record: &[u8]) -> Hello {
    assert_eq!(record[0], 0x16, "not a handshake record");
    let record_version = [record[1], record[2]];
    let body = &record[5..];
    assert_eq!(body[0], 0x01, "not a ClientHello");

    let legacy_version = be16(body, 4);
    let session_id_len = body[38] as usize;
    let mut cursor = 39 + session_id_len;

    let cipher_len = be16(body, cursor) as usize;
    let cipher_suites = (0..cipher_len / 2)
        .map(|index| be16(body, cursor + 2 + index * 2))
        .collect();
    cursor += 2 + cipher_len;

    let compression_len = body[cursor] as usize;
    let compression_methods = body[cursor + 1..cursor + 1 + compression_len].to_vec();
    cursor += 1 + compression_len;

    let extensions_len = be16(body, cursor) as usize;
    cursor += 2;
    let end = cursor + extensions_len;

    let mut hello = Hello {
        record_version,
        legacy_version,
        session_id_len,
        cipher_suites,
        compression_methods,
        extensions: Vec::new(),
        supported_groups: Vec::new(),
        key_share_groups: Vec::new(),
        supported_versions: Vec::new(),
        signature_algorithms: Vec::new(),
        alpn: Vec::new(),
    };

    while cursor + 4 <= end {
        let extension_type = be16(body, cursor);
        let length = be16(body, cursor + 2) as usize;
        let start = cursor + 4;
        let body_slice = &body[start..start + length];
        hello.extensions.push(extension_type);
        match extension_type {
            0x000a => {
                let list = be16(body_slice, 0) as usize;
                hello.supported_groups = (0..list / 2)
                    .map(|index| be16(body_slice, 2 + index * 2))
                    .collect();
            }
            0x0033 => {
                let list = be16(body_slice, 0) as usize;
                let mut at = 2;
                while at + 4 <= 2 + list {
                    let group = be16(body_slice, at);
                    let share = be16(body_slice, at + 2) as usize;
                    hello.key_share_groups.push(group);
                    at += 4 + share;
                }
            }
            0x002b => {
                let list = body_slice[0] as usize;
                hello.supported_versions = (0..list / 2)
                    .map(|index| be16(body_slice, 1 + index * 2))
                    .collect();
            }
            0x000d => {
                let list = be16(body_slice, 0) as usize;
                hello.signature_algorithms = (0..list / 2)
                    .map(|index| be16(body_slice, 2 + index * 2))
                    .collect();
            }
            0x0010 => {
                let mut at = 2;
                while at < body_slice.len() {
                    let length = body_slice[at] as usize;
                    hello.alpn.push(
                        String::from_utf8_lossy(&body_slice[at + 1..at + 1 + length]).into_owned(),
                    );
                    at += 1 + length;
                }
            }
            _ => {}
        }
        cursor = start + length;
    }
    hello
}

/// Dial a local listener with the real client config and return the hello.
fn capture(tls: &TlsConfig) -> Hello {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let config = rustls_client_config(tls).expect("client config");

    let client = std::thread::spawn(move || {
        let name = rustls::pki_types::ServerName::try_from("measure.example").unwrap();
        let mut connection =
            rustls::ClientConnection::new(config, name).expect("client connection");
        let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        // One write is all that is needed: the hello is the first flight.
        let _ = connection.write_tls(&mut socket);
    });

    let (mut server, _) = listener.accept().expect("accept");
    let mut buffer = vec![0_u8; 8192];
    let read = server.read(&mut buffer).expect("read");
    buffer.truncate(read);
    drop(server);
    let _ = client.join();
    parse(&buffer)
}

fn default_tls() -> TlsConfig {
    TlsConfig {
        enabled: true,
        server_name: Some("measure.example".to_owned()),
        ..TlsConfig::default()
    }
}

/// The measurement. Every assertion here is a fact about rustls, recorded so
/// the comparison with Chrome is grounded in bytes rather than in reading the
/// rustls source.
#[test]
fn the_generic_path_hello_is_recorded_field_by_field() {
    let hello = capture(&default_tls());

    // Printed so `cargo test -- --nocapture` is a measurement tool, not just a
    // pass/fail.
    println!("rustls ClientHello: {hello:#?}");

    // --- Fields that match Chrome already -----------------------------------
    assert_eq!(
        hello.legacy_version, 0x0303,
        "legacy_version is 0x0303 in every TLS 1.3 hello"
    );
    assert_eq!(
        hello.session_id_len, 32,
        "rustls sends a 32-byte compatibility session id, as Chrome does"
    );
    assert_eq!(hello.compression_methods, vec![0x00]);

    // rustls already writes 0x0301 on the initial record, for the same
    // historical-compatibility reason BoringSSL does. This was *assumed* to be
    // a divergence before it was measured; it is not one.
    assert_eq!(
        hello.record_version,
        [0x03, 0x01],
        "rustls matches Chrome on the initial record version"
    );

    // supported_versions carries the same two versions Chrome offers. Only the
    // GREASE entry is missing.
    assert_eq!(hello.supported_versions, vec![0x0304, 0x0303]);

    // --- Differences configuration CAN reach --------------------------------

    // The post-quantum group now leads, as Chrome's does, and a share is sent
    // for it. The aws-lc-rs default put it last; `crypto_provider` reorders.
    assert_eq!(
        hello.supported_groups.first(),
        Some(&0x11ec),
        "the hybrid must be offered first by default"
    );
    assert_eq!(
        hello.key_share_groups,
        vec![0x11ec, 0x001d],
        "shares for hybrid and x25519, as Chrome sends (minus GREASE)"
    );

    // --- Differences that are architectural ---------------------------------

    // No GREASE anywhere. Chrome puts a GREASE value in cipher_suites,
    // supported_groups, supported_versions and two extension slots. rustls has
    // no API for any of it.
    assert!(
        !hello.cipher_suites.iter().any(|id| is_grease(*id)),
        "rustls does not GREASE its cipher list"
    );
    assert!(
        !hello.extensions.iter().any(|id| is_grease(*id)),
        "rustls does not send GREASE extensions"
    );
    assert!(
        !hello.supported_groups.iter().any(|id| is_grease(*id)),
        "rustls does not GREASE supported_groups"
    );

    // Ten suites against Chrome's sixteen, in a different order, and ending in
    // the renegotiation SCSV (0x00ff) that Chrome does not send at all --
    // Chrome carries `renegotiation_info` as an extension instead.
    assert_eq!(
        hello.cipher_suites,
        vec![
            0x1302, 0x1301, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0x00ff,
        ],
        "the recorded rustls cipher list"
    );
    assert_ne!(
        hello.cipher_suites.first(),
        Some(&0x1301),
        "rustls leads with AES-256; Chrome leads with GREASE then AES-128"
    );

    // The extension *set*. Order is deliberately not asserted here: rustls
    // shuffles it per connection (see the test below), which is the same thing
    // Chrome does since 110. Eleven extensions against Chrome's eighteen.
    let mut sent = hello.extensions.clone();
    sent.sort_unstable();
    assert_eq!(
        sent,
        vec![
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x0023, 0x002b, 0x002d, 0x0033
        ],
        "the recorded rustls extension set (0x0010 is the default ALPN)"
    );

    // Extensions Chrome sends that rustls does not, at all.
    for (code_point, name) in [
        (0x0012_u16, "signed_certificate_timestamp"),
        (0x001b, "compress_certificate"),
        (0x44cd, "application_settings"),
        (0x0015, "padding"),
        (0xfe0d, "encrypted_client_hello (GREASE)"),
        (0xff01, "renegotiation_info"),
    ] {
        assert!(
            !hello.extensions.contains(&code_point),
            "rustls unexpectedly sent {name}; the Chrome gap is smaller than recorded"
        );
    }

    // signature_algorithms includes ed25519 (0x0807), which Chrome never
    // offers, and is in a different order.
    assert!(
        hello.signature_algorithms.contains(&0x0807),
        "rustls offers ed25519; Chrome does not"
    );
    assert_eq!(hello.signature_algorithms.len(), 10);
}

/// rustls permutes its extension order per connection.
///
/// Worth its own test because it was assumed to be a static tell and is not:
/// rustls shuffles, exactly as Chrome has since 110. A fixed order would have
/// been the single loudest thing about this hello, and it is not there. What
/// remains is the extension *set*, which the test above pins.
#[test]
fn rustls_shuffles_its_extension_order() {
    let tls = default_tls();
    let mut orders = std::collections::HashSet::new();
    for _ in 0..12 {
        orders.insert(capture(&tls).extensions);
    }
    assert!(
        orders.len() > 1,
        "rustls emitted one fixed extension order over 12 connections; if upstream \
         stopped permuting, the generic path gained a static fingerprint"
    );
    // Whatever the order, the set never changes.
    let sets: std::collections::HashSet<Vec<u16>> = orders
        .iter()
        .map(|order| {
            let mut sorted = order.clone();
            sorted.sort_unstable();
            sorted
        })
        .collect();
    assert_eq!(sets.len(), 1, "the extension set must not vary");
}

/// `curve_preferences` reaches the wire in the order given, after the hybrid.
///
/// The hybrid is prepended when a list omits it (see the security test below),
/// so what this pins is that the *rest* of the order is the profile's.
#[test]
fn curve_preferences_reach_the_wire_in_order() {
    use foxcore_api::CurveGroup;

    let mut tls = default_tls();
    tls.curve_preferences = vec![CurveGroup::Secp256r1, CurveGroup::X25519];
    let hello = capture(&tls);
    assert_eq!(hello.supported_groups, vec![0x11ec, 0x0017, 0x001d]);

    let mut tls = default_tls();
    tls.curve_preferences = vec![CurveGroup::X25519, CurveGroup::Secp256r1];
    let hello = capture(&tls);
    assert_eq!(hello.supported_groups, vec![0x11ec, 0x001d, 0x0017]);
}

/// ALPN is configurable and reaches the wire verbatim.
#[test]
fn alpn_reaches_the_wire_in_order() {
    let mut tls = default_tls();
    tls.alpn = vec!["h2".into(), "http/1.1".into()];
    let hello = capture(&tls);
    assert_eq!(hello.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
}

fn is_grease(value: u16) -> bool {
    (value >> 8) == (value & 0xff) && (value & 0x0f) == 0x0a
}

/// Kept honest: the parser must reject something that is not a ClientHello,
/// or every assertion above could be passing on a misread buffer.
#[test]
#[should_panic(expected = "not a handshake record")]
fn the_parser_rejects_a_non_handshake_record() {
    parse(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]);
}

// Silence the unused warning for `Arc` when features change the imports above.
const _: Option<Arc<()>> = None;

/// A profile cannot silently negotiate a classical-only key exchange.
///
/// This is the security half of the fingerprint work and the one that would
/// matter even if nobody ever looked at a ClientHello. `curve_preferences`
/// replaces the provider's group list, so naming `["x25519"]` to shape a hello
/// used to drop `X25519MLKEM768` and quietly remove post-quantum protection.
/// Now the hybrid is prepended to any list that omits it.
#[test]
fn a_curve_preference_cannot_silently_drop_the_post_quantum_group() {
    use foxcore_api::CurveGroup;

    // The exact shape that used to downgrade: a classical-only preference set
    // for cosmetic reasons.
    let mut tls = default_tls();
    tls.curve_preferences = vec![CurveGroup::X25519, CurveGroup::Secp256r1];
    let hello = capture(&tls);
    assert_eq!(
        hello.supported_groups,
        vec![0x11ec, 0x001d, 0x0017],
        "the hybrid must be prepended to a preference list that omits it"
    );
    assert!(
        hello.key_share_groups.contains(&0x11ec),
        "and a share must be sent for it"
    );

    // A profile that names the hybrid keeps its own order untouched.
    let mut tls = default_tls();
    tls.curve_preferences = vec![CurveGroup::X25519, CurveGroup::X25519MlKem768];
    let hello = capture(&tls);
    assert_eq!(
        hello.supported_groups,
        vec![0x001d, 0x11ec],
        "an explicit list naming the hybrid is honoured as written"
    );
}

/// Dropping the hybrid stays possible, but only by saying so.
///
/// The escape hatch exists because a server that mishandles a 1216-byte key
/// share is a real thing to have to work around. The point is that it takes a
/// field named after what it does, which shows up in a config review.
#[test]
fn classical_only_is_reachable_but_only_deliberately() {
    use foxcore_api::CurveGroup;

    let mut tls = default_tls();
    tls.curve_preferences = vec![CurveGroup::X25519, CurveGroup::Secp256r1];
    tls.allow_classical_only_key_exchange = true;
    let hello = capture(&tls);
    assert_eq!(
        hello.supported_groups,
        vec![0x001d, 0x0017],
        "an explicit opt-out is honoured exactly as written"
    );
    assert!(
        !hello.supported_groups.contains(&0x11ec),
        "and really does drop the hybrid"
    );
}

/// A profile that names no ALPN still sends one, because a browser does.
#[test]
fn the_default_alpn_is_what_a_browser_sends() {
    let tls = default_tls();
    assert!(tls.alpn.is_empty(), "the profile names no ALPN");
    let hello = capture(&tls);
    assert_eq!(hello.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
}
