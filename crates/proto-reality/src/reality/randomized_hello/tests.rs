//! Properties, because there is no vector.
//!
//! Every other hello in this crate is checked against frozen bytes: a table
//! either reproduces `fingerprints/chrome_133.json` or it does not. That test
//! cannot exist here. The whole claim of `randomized` is that the bytes differ
//! per connection, so a golden vector would either be wrong or would have to
//! freeze the randomness that makes the profile a profile.
//!
//! So what is pinned is the *shape of the space*: which extensions may appear,
//! which must appear, which combinations may not, how far the draw is allowed
//! to move, and — the one that decides whether this ships at all — that every
//! draw carries TLS 1.3 and an `x25519` key share, without which REALITY has
//! nothing to derive its authentication key from.
//!
//! The randomness is injected ([`SeededDraws`]), so every assertion below runs
//! over a fixed, reproducible set of seeds. A failure names a seed and can be
//! replayed.
//!
//! # The negative controls
//!
//! A property test that passes against a broken generator proves nothing, so
//! [`neutralising_the_generator_fails_the_properties`] breaks it four ways —
//! freezes the draw, drops a mandatory extension, drops the TLS 1.3 block, and
//! takes uTLS' P-256-only key-share draw — and asserts that the same checks
//! then fail, and that the same handshake harness then rejects the hello.
//!
//! Everything is synthetic: `example.com`, a client random of repeated bytes,
//! and a REALITY key that belongs to nobody.

use std::collections::BTreeSet;
use std::io;

use aws_lc_rs::{agreement, digest};
use foxcore_transport::ja;

use super::*;
use crate::reality::hello_profile::{
    CHROME_ALPN_PROTOCOLS, EchGreaseParams, GreaseValues, HelloSession, boring_padding, is_grease,
};
use crate::reality::reality_client_connection::{
    RealityClientConfig, RealityClientConnection, RealityHello,
};
use crate::reality::reality_key_exchange::NamedGroup;
use crate::reality::reality_tls13_messages::construct_client_hello;
use crate::reality::testkit_internals as internals;

/// How many draws every property runs over. Large enough that a coin weighted
/// 0.33 lands on both faces thousands of times, small enough to stay a unit
/// test.
const SEEDS: u64 = 3_000;

// ------------------------------------------------------------ the vocabulary

/// Every extension code point a generated hello may carry, and nothing else.
///
/// This is the closed vocabulary, written out rather than derived from the
/// generator: a new variant added to [`Slot`] without a decision about whether
/// it belongs on the wire fails here.
const ALLOWED_EXTENSIONS: [u16; 15] = [
    ext::SERVER_NAME,
    ext::SESSION_TICKET,
    ext::SIGNATURE_ALGORITHMS,
    ext::EC_POINT_FORMATS,
    ext::SUPPORTED_GROUPS,
    ext::ALPN,
    ext::STATUS_REQUEST,
    ext::SIGNED_CERTIFICATE_TIMESTAMP,
    ext::RENEGOTIATION_INFO,
    ext::EXTENDED_MASTER_SECRET,
    ext::KEY_SHARE,
    ext::PSK_KEY_EXCHANGE_MODES,
    ext::SUPPORTED_VERSIONS,
    ext::APPLICATION_SETTINGS_OLD,
    ext::PADDING,
];

/// The eight that are not optional. Five are unconditional in uTLS; the other
/// three come with the TLS 1.3 branch, which this port forces.
const MANDATORY_EXTENSIONS: [u16; 8] = [
    ext::SERVER_NAME,
    ext::SESSION_TICKET,
    ext::SIGNATURE_ALGORITHMS,
    ext::EC_POINT_FORMATS,
    ext::SUPPORTED_GROUPS,
    ext::KEY_SHARE,
    ext::PSK_KEY_EXCHANGE_MODES,
    ext::SUPPORTED_VERSIONS,
];

/// Every signature scheme the draw may reach, base plus optional.
fn signature_algorithm_universe() -> BTreeSet<u16> {
    BASE_SIGNATURE_ALGORITHMS
        .iter()
        .chain(OPTIONAL_SIGNATURE_ALGORITHMS.iter())
        .copied()
        .collect()
}

const X25519_GROUP: u16 = 0x001d;
const SECP256R1_GROUP: u16 = 0x0017;

// -------------------------------------------------------------- the parser

/// A strict walk over the ClientHello.
///
/// Deliberately not [`ja::parse`], which is written to survive whatever a real
/// network hands it. Here every length field has to add up exactly and the
/// message has to end where it says it does — which is the well-formedness
/// half of the claim, and the half a lenient parser would hide.
struct Parsed {
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

fn be16(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .map(|slice| u16::from_be_bytes([slice[0], slice[1]]))
        .ok_or_else(|| format!("truncated at {at}"))
}

fn parse_strict(hello: &[u8]) -> Result<Parsed, String> {
    if hello.first() != Some(&0x01) {
        return Err("handshake type is not ClientHello".to_owned());
    }
    let declared = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    if declared + 4 != hello.len() {
        return Err(format!(
            "handshake length {declared} does not match the {} bytes produced",
            hello.len() - 4
        ));
    }

    let mut at = 4 + 2 + 32; // header, legacy_version, random
    let session_id_len = *hello.get(at).ok_or("truncated at the session id")? as usize;
    at += 1 + session_id_len;

    let cipher_bytes = be16(hello, at)? as usize;
    at += 2;
    if !cipher_bytes.is_multiple_of(2) {
        return Err("odd cipher_suites length".to_owned());
    }
    let mut ciphers = Vec::new();
    for index in 0..cipher_bytes / 2 {
        ciphers.push(be16(hello, at + index * 2)?);
    }
    at += cipher_bytes;

    let compression_len = *hello.get(at).ok_or("truncated at compression")? as usize;
    at += 1 + compression_len;

    let extensions_len = be16(hello, at)? as usize;
    at += 2;
    let end = at + extensions_len;
    if end != hello.len() {
        return Err(format!(
            "extensions block ends at {end}, message ends at {}",
            hello.len()
        ));
    }
    let mut extensions = Vec::new();
    while at < end {
        let extension_type = be16(hello, at)?;
        let body_len = be16(hello, at + 2)? as usize;
        let body_start = at + 4;
        let body_end = body_start + body_len;
        if body_end > end {
            return Err(format!(
                "extension 0x{extension_type:04x} runs past the list"
            ));
        }
        extensions.push((extension_type, hello[body_start..body_end].to_vec()));
        at = body_end;
    }

    Ok(Parsed {
        ciphers,
        extensions,
    })
}

// -------------------------------------------------------------- the checks

/// Every property one hello must satisfy, as a `Result` rather than an assert.
///
/// A `Result` so the negative controls can assert that these *fail* without
/// catching a panic — a check that can only shout is a check that cannot be
/// tested itself.
fn check(hello: &[u8]) -> Result<(), String> {
    let parsed = parse_strict(hello)?;

    let types: Vec<u16> = parsed.extensions.iter().map(|(id, _)| *id).collect();
    for mandatory in MANDATORY_EXTENSIONS {
        if !types.contains(&mandatory) {
            return Err(format!("mandatory extension 0x{mandatory:04x} is missing"));
        }
    }
    for id in &types {
        if !ALLOWED_EXTENSIONS.contains(id) {
            return Err(format!("extension 0x{id:04x} is outside the vocabulary"));
        }
        if is_grease(*id) {
            return Err(format!("GREASE extension 0x{id:04x}: uTLS draws none"));
        }
    }
    let unique: BTreeSet<u16> = types.iter().copied().collect();
    if unique.len() != types.len() {
        return Err("an extension type appears twice".to_owned());
    }

    // ALPS is TLS 1.3-only and draft-vvv-tls-alps-01 allows it only beside an
    // ALPN extension. uTLS gates it on exactly that.
    if types.contains(&ext::APPLICATION_SETTINGS_OLD) && !types.contains(&ext::ALPN) {
        return Err("application_settings without ALPN".to_owned());
    }

    let body = |id: u16| -> Vec<u8> {
        parsed
            .extensions
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(_, body)| body.clone())
            .unwrap_or_default()
    };

    // --- REALITY compatibility. The two that decide whether this can ship.
    let versions = body(ext::SUPPORTED_VERSIONS);
    if versions.first().copied() != Some((versions.len() - 1) as u8) {
        return Err("supported_versions list length is wrong".to_owned());
    }
    let offered: Vec<u16> = versions[1..]
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    if offered.first() != Some(&TLS_1_3) {
        return Err(format!(
            "supported_versions does not lead with 1.3: {offered:04x?}"
        ));
    }

    let shares = body(ext::KEY_SHARE);
    let list_len = u16::from_be_bytes([shares[0], shares[1]]) as usize;
    if list_len + 2 != shares.len() {
        return Err("key_share list length is wrong".to_owned());
    }
    let group = u16::from_be_bytes([shares[2], shares[3]]);
    let share_len = u16::from_be_bytes([shares[4], shares[5]]) as usize;
    if group != X25519_GROUP {
        return Err(format!(
            "key_share is 0x{group:04x}, not x25519; REALITY authenticates against the flat \
             x25519 share and has nothing to read"
        ));
    }
    if share_len != 32 || shares.len() != 6 + 32 {
        return Err("key_share must be exactly one 32-byte x25519 entry".to_owned());
    }

    let groups_body = body(ext::SUPPORTED_GROUPS);
    let groups: Vec<u16> = groups_body[2..]
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    if groups.first() != Some(&X25519_GROUP) {
        return Err(format!(
            "supported_groups does not lead with x25519: {groups:04x?}"
        ));
    }
    if !groups.contains(&SECP256R1_GROUP) {
        return Err("supported_groups is missing secp256r1".to_owned());
    }

    // --- the cipher list, and uTLS' bounds on it.
    if parsed.ciphers.is_empty() || parsed.ciphers.len() > 22 {
        return Err(format!(
            "{} cipher suites is out of range",
            parsed.ciphers.len()
        ));
    }
    if !TLS13_CIPHER_SUITES.contains(&parsed.ciphers[0]) {
        return Err(format!(
            "the first suite is 0x{:04x}; removeRandomCiphers never removes index 0, so a TLS \
             1.3 suite is always there",
            parsed.ciphers[0]
        ));
    }
    let unique: BTreeSet<u16> = parsed.ciphers.iter().copied().collect();
    if unique.len() != parsed.ciphers.len() {
        return Err("a cipher suite appears twice".to_owned());
    }
    let mut seen_obsolete = false;
    for id in &parsed.ciphers {
        if is_grease(*id) {
            return Err(format!("GREASE cipher 0x{id:04x}: uTLS draws none"));
        }
        if RC4_CIPHER_SUITES.contains(id) {
            return Err(format!("RC4 suite 0x{id:04x}: TLS 1.3 forbids it"));
        }
        if TLS13_CIPHER_SUITES.contains(id) {
            continue;
        }
        let Some((_, obsolete)) = LEGACY_CIPHER_SUITES.iter().find(|(known, _)| known == id) else {
            return Err(format!(
                "cipher 0x{id:04x} is outside Go's cipherSuites table"
            ));
        };
        // `sortableCiphers.Less` sorts every non-obsolete suite ahead of every
        // obsolete one. This is what keeps the shuffle browser-shaped rather
        // than uniformly random.
        if *obsolete {
            seen_obsolete = true;
        } else if seen_obsolete {
            return Err(format!(
                "modern suite 0x{id:04x} appears after an obsolete one"
            ));
        }
    }

    // --- signature algorithms.
    let sig_body = body(ext::SIGNATURE_ALGORITHMS);
    let declared = u16::from_be_bytes([sig_body[0], sig_body[1]]) as usize;
    if declared + 2 != sig_body.len() || !declared.is_multiple_of(2) {
        return Err("signature_algorithms length is wrong".to_owned());
    }
    let schemes: Vec<u16> = sig_body[2..]
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let universe = signature_algorithm_universe();
    let present: BTreeSet<u16> = schemes.iter().copied().collect();
    if present.len() != schemes.len() {
        return Err("a signature scheme appears twice".to_owned());
    }
    for scheme in &schemes {
        if !universe.contains(scheme) {
            return Err(format!(
                "signature scheme 0x{scheme:04x} is outside the draw"
            ));
        }
    }
    for base in BASE_SIGNATURE_ALGORITHMS {
        if !present.contains(&base) {
            return Err(format!("base signature scheme 0x{base:04x} is missing"));
        }
    }
    // RFC 8446 §4.2.3: "RSASSA-PSS ... is mandatory in TLS 1.3".
    if !present.contains(&PSS_RSAE_SHA256) {
        return Err("rsa_pss_rsae_sha256 is missing on a TLS 1.3 hello".to_owned());
    }

    // --- padding.
    if let Some(position) = types.iter().position(|id| *id == ext::PADDING) {
        if position + 1 != types.len() {
            return Err("padding is not last".to_owned());
        }
        let unpadded = hello.len() - 4 - body(ext::PADDING).len();
        match boring_padding(unpadded) {
            Some(expected) if expected == body(ext::PADDING).len() => {}
            other => {
                return Err(format!(
                    "padding is {} bytes; BoringSSL's rule gives {other:?} for an unpadded {unpadded}",
                    body(ext::PADDING).len()
                ));
            }
        }
    }

    Ok(())
}

// ------------------------------------------------------------- the fixtures

const SERVER_PRIVATE: [u8; 32] = [0x4a; 32];
const SERVER_NAME: &str = "example.com";

fn server_public_key() -> [u8; 32] {
    let key = agreement::PrivateKey::from_private_key(&agreement::X25519, &SERVER_PRIVATE).unwrap();
    let mut public = [0_u8; 32];
    public.copy_from_slice(key.compute_public_key().unwrap().as_ref());
    public
}

/// The ClientHello handshake message a draw produces, without the REALITY
/// session-id encryption — the shape is all these properties are about.
///
/// Every per-connection value the executor asks for is pinned: the key shares
/// are synthetic bytes of the right length rather than a real
/// [`ClientKeyExchange`], because a freshly generated public key would make the
/// hello differ between two calls with the *same* seed and there would be no
/// way to tell an injected-randomness failure from an ephemeral key.
fn hello_bytes(drawn: &RandomizedHello) -> io::Result<Vec<u8>> {
    drawn.with_profile(|profile| {
        let key_shares: Vec<(NamedGroup, Vec<u8>)> = profile
            .key_share_groups()
            .into_iter()
            .map(|group| {
                // x25519 is 32 bytes, an uncompressed P-256 point is 65.
                let len = if group == NamedGroup::X25519 { 32 } else { 65 };
                (group, vec![0x7b_u8; len])
            })
            .collect();
        let session = HelloSession {
            client_random: &[0x11_u8; 32],
            session_id: &[0x5c_u8; 32],
            server_name: SERVER_NAME,
            alpn_protocols: CHROME_ALPN_PROTOCOLS,
            key_shares: &key_shares,
            grease: GreaseValues::from_seed([0; 5]),
            ech_grease: EchGreaseParams::new([0x5a; 32], &mut SeededDraws::new(1)),
            permutation_seed: 0,
        };
        construct_client_hello(profile, &session)
    })
}

fn draw(seed: u64) -> RandomizedHello {
    RandomizedHello::draw(&mut SeededDraws::new(seed))
}

// -------------------------------------------------------- the property tests

/// The headline claim: every draw is a well-formed ClientHello that REALITY
/// can actually use.
#[test]
fn every_draw_is_well_formed_and_reality_compatible() {
    for seed in 0..SEEDS {
        let bytes = hello_bytes(&draw(seed))
            .unwrap_or_else(|error| panic!("seed {seed} produced no hello: {error}"));
        if let Err(reason) = check(&bytes) {
            panic!("seed {seed}: {reason}");
        }
    }
}

/// The draw is bounded the way uTLS bounds it — and it is a draw at all.
///
/// The first half of this is the interesting one: "bounded" is not a mood, it
/// is that every optional piece appears on *both* faces across the sample and
/// nothing outside the vocabulary ever appears. A generator that always said
/// yes, or always said no, would pass [`check`] and fail here.
#[test]
fn the_draw_is_bounded_and_actually_varies() {
    let optional = [
        ext::ALPN,
        ext::STATUS_REQUEST,
        ext::SIGNED_CERTIFICATE_TIMESTAMP,
        ext::RENEGOTIATION_INFO,
        ext::EXTENDED_MASTER_SECRET,
        ext::APPLICATION_SETTINGS_OLD,
    ];
    let mut present = vec![0_u32; optional.len()];
    let mut absent = vec![0_u32; optional.len()];
    let mut cipher_counts = BTreeSet::new();
    let mut group_counts = BTreeSet::new();
    let mut scheme_counts = BTreeSet::new();
    let mut orders = BTreeSet::new();

    for seed in 0..SEEDS {
        let bytes = hello_bytes(&draw(seed)).expect("hello");
        let parsed = parse_strict(&bytes).expect("well formed");
        let types: Vec<u16> = parsed.extensions.iter().map(|(id, _)| *id).collect();
        for (index, id) in optional.iter().enumerate() {
            if types.contains(id) {
                present[index] += 1;
            } else {
                absent[index] += 1;
            }
        }
        cipher_counts.insert(parsed.ciphers.len());
        orders.insert(types.clone());
        for (id, body) in &parsed.extensions {
            if *id == ext::SUPPORTED_GROUPS {
                group_counts.insert(body.len());
            }
            if *id == ext::SIGNATURE_ALGORITHMS {
                scheme_counts.insert(body.len());
            }
        }
    }

    for (index, id) in optional.iter().enumerate() {
        assert!(
            present[index] > 0 && absent[index] > 0,
            "extension 0x{id:04x} is not actually drawn: present {} absent {}",
            present[index],
            absent[index]
        );
    }

    // uTLS' bounds, stated as numbers. Three TLS 1.3 suites plus nineteen
    // non-RC4 legacy ones is twenty-two before `removeRandomCiphers`, and that
    // function never removes index 0.
    assert!(
        cipher_counts.iter().all(|count| (1..=22).contains(count)),
        "cipher counts out of range: {cipher_counts:?}"
    );
    assert!(
        cipher_counts.len() > 4,
        "removeRandomCiphers is not removing anything: {cipher_counts:?}"
    );
    // `supported_groups`: three groups or four, never anything else.
    assert_eq!(
        group_counts,
        BTreeSet::from([2 + 3 * 2, 2 + 4 * 2]),
        "supported_groups lengths"
    );
    // Signature schemes: seven at minimum (six base plus forced PSS), eleven at
    // most, and only the four documented steps in between.
    assert_eq!(
        scheme_counts,
        BTreeSet::from([2 + 7 * 2, 2 + 8 * 2, 2 + 9 * 2, 2 + 10 * 2, 2 + 11 * 2]),
        "signature_algorithms lengths"
    );
    assert!(
        orders.len() > SEEDS as usize / 2,
        "only {} distinct extension layouts in {SEEDS} draws",
        orders.len()
    );
}

/// The injected source is the only source: the same seed is the same hello.
///
/// Without this the tests above would be measuring the OS RNG, and a failure
/// could not be replayed.
#[test]
fn the_same_seed_draws_the_same_hello() {
    for seed in [0_u64, 1, 42, 9_999] {
        let first = hello_bytes(&draw(seed)).expect("hello");
        let second = hello_bytes(&draw(seed)).expect("hello");
        assert_eq!(first, second, "seed {seed} is not reproducible");
        let other = hello_bytes(&draw(seed + 1)).expect("hello");
        assert_ne!(first, other, "seed {seed} and {} agree", seed + 1);
    }
}

/// A generated hello completes a REALITY handshake against the test server.
///
/// Well-formed is not the same as usable. This drives the real client through
/// the real harness — the one `proto-vless`' integration test dials over a
/// socket — for a sample of pinned draws, and only succeeds if the server can
/// find the `x25519` share, derive the REALITY key, and be believed.
#[test]
fn a_generated_hello_completes_a_reality_handshake() {
    for seed in 0..128_u64 {
        complete_handshake(RealityHello::RandomizedSeeded(seed))
            .unwrap_or_else(|error| panic!("seed {seed} did not complete a handshake: {error}"));
    }
}

/// Drive one connection to a completed handshake in memory.
fn complete_handshake(hello: RealityHello) -> io::Result<()> {
    let mut connection = RealityClientConnection::new(RealityClientConfig {
        public_key: server_public_key(),
        short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        server_name: SERVER_NAME.to_owned(),
        hello,
    })?;

    let mut wire = Vec::new();
    connection.write_tls(&mut wire)?;
    let client_hello = &wire[5..];

    let parsed = internals::parse_client_hello(client_hello, &SERVER_PRIVATE)?;
    let (server_hello, shared_secret) = internals::build_server_hello(&parsed)?;

    let mut transcript = digest::Context::new(parsed.cipher_suite.digest_algorithm());
    transcript.update(client_hello);
    transcript.update(&server_hello);
    let flight = internals::build_encrypted_flight(
        &parsed,
        &shared_secret,
        transcript,
        SERVER_NAME,
        client_hello,
        &server_hello,
    )?;

    let mut from_server =
        internals::record_header(internals::CONTENT_TYPE_HANDSHAKE, server_hello.len());
    from_server.extend_from_slice(&server_hello);
    from_server.extend_from_slice(&flight.bytes);

    let mut cursor: &[u8] = &from_server;
    while !cursor.is_empty() {
        let read = connection.read_tls(&mut cursor)?;
        if read == 0 {
            break;
        }
        connection.process_new_packets()?;
    }

    if connection.is_handshaking() {
        return Err(io::Error::other("handshake did not complete"));
    }
    Ok(())
}

// ---------------------------------------------------------- negative control

/// Break the generator four ways; the properties above must notice all four.
///
/// This is the test that makes the others mean something. Each case takes a
/// real draw and neutralises exactly one thing — the two that uTLS itself can
/// produce and this port excludes, plus a dropped mandatory extension and a
/// frozen draw — and asserts that the checks fail, with the reason quoted so a
/// future edit that weakens a check fails here rather than going quiet.
#[test]
fn neutralising_the_generator_fails_the_properties() {
    // 1. The draw is fixed: one hello for every connection. Every per-hello
    //    check still passes — a constant hello is a perfectly well-formed one —
    //    and that is exactly why "it varies" has to be its own assertion.
    let frozen = hello_bytes(&draw(7)).expect("hello");
    assert!(
        check(&frozen).is_ok(),
        "a frozen draw is still a valid hello, which is the point"
    );
    let frozen_orders: BTreeSet<Vec<u16>> = (0..SEEDS)
        .map(|_| {
            parse_strict(&frozen)
                .expect("well formed")
                .extensions
                .iter()
                .map(|(id, _)| *id)
                .collect()
        })
        .collect();
    assert_eq!(
        frozen_orders.len(),
        1,
        "a frozen draw must collapse the layout set that \
         `the_draw_is_bounded_and_actually_varies` requires to be large"
    );

    // 2. A mandatory extension is dropped.
    let mut dropped = draw(11);
    dropped
        .layout
        .retain(|slot| *slot != Slot::SignatureAlgorithms);
    let bytes = hello_bytes(&dropped).expect("hello");
    let reason = check(&bytes).expect_err("a hello without signature_algorithms must fail");
    assert!(
        reason.contains(&format!("0x{:04x}", ext::SIGNATURE_ALGORITHMS)),
        "{reason}"
    );

    // 3. uTLS' TLS 1.2 branch: no key_share, no supported_versions. This one
    //    cannot even be built — `HelloProfile::validate` refuses a ClientHello
    //    with no key_share extension before any bytes exist — which is the
    //    strongest form the check could take.
    let mut tls12 = draw(13);
    tls12
        .layout
        .retain(|slot| !matches!(slot, Slot::KeyShare | Slot::SupportedVersions));
    let error = hello_bytes(&tls12).expect_err("a TLS 1.2 shape must not produce a hello");
    assert!(error.to_string().contains("key_share"), "{error}");

    // 4. uTLS' `FirstKeyShare_Set_CurveP256`, weighted 0.25 upstream. The hello
    //    is well-formed TLS and a browser could send it; REALITY cannot use it,
    //    because the server reads the flat x25519 share out of the ClientHello
    //    and there is not one. Both the check and the harness must say so.
    let mut p256 = draw(17);
    p256.key_shares = vec![KeyShareSlot::Group(NamedGroup::Secp256r1)];
    p256.supported_groups = vec![
        GroupSlot::Group(NamedGroup::Secp256r1),
        GroupSlot::Group(NamedGroup::Secp384r1),
    ];
    let bytes = hello_bytes(&p256).expect("a P-256 hello is still a hello");
    let reason = check(&bytes).expect_err("a P-256-only key share must fail");
    assert!(reason.contains("x25519"), "{reason}");
    let server_side = internals::parse_client_hello(&bytes, &SERVER_PRIVATE)
        .err()
        .expect("the REALITY server must reject a hello with no x25519 share");
    assert!(
        server_side.to_string().contains("no x25519 key share"),
        "{server_side}"
    );

    // And with all four restored, the generator passes again.
    for seed in [7_u64, 11, 13, 17] {
        check(&hello_bytes(&draw(seed)).expect("hello")).expect("restored");
    }
}

// ------------------------------------------------------- what a detector sees

/// What this costs, measured rather than asserted: **JA4 moves too.**
///
/// The parrots have a stable JA4 and a moving JA3 — JA4 sorts its cipher and
/// extension lists, so Chrome's per-connection permutation and its GREASE drop
/// out, which is exactly how a real browser behaves. A generated hello has a
/// different cipher *set* and a different extension *set* per connection, so
/// sorting does not save it, and the JA4 moves.
///
/// That is the trade in one line: an exact-match blocklist cannot hold this
/// client, and an aggregate-statistics detector gets a signal no browser
/// produces — a single client whose JA4 is never the same twice. The test
/// asserts the fact rather than a preference, so that a future change which
/// stabilises JA4 has to come here and say so.
#[test]
fn a_generated_hello_moves_ja3_and_ja4_together() {
    let mut ja3s = BTreeSet::new();
    let mut ja4s = BTreeSet::new();
    for seed in 0..64_u64 {
        let bytes = hello_bytes(&draw(seed)).expect("hello");
        let hello = ja::parse(&bytes);
        ja3s.insert(ja::ja3_hash(&hello));
        ja4s.insert(ja::ja4(&hello).0);
    }
    assert!(ja3s.len() > 32, "JA3 barely moves: {} values", ja3s.len());
    assert!(
        ja4s.len() > 8,
        "JA4 is nearly stable at {} values; the generator has stopped varying the \
         cipher and extension *sets*, which is the only thing JA4 sorting cannot hide",
        ja4s.len()
    );

    println!(
        "\nrandomized: {} distinct JA3 and {} distinct JA4 over 64 draws",
        ja3s.len(),
        ja4s.len()
    );
    let sample = hello_bytes(&draw(0)).expect("hello");
    let hello = ja::parse(&sample);
    println!(
        "  seed 0  JA3 {}  JA4 {}",
        ja::ja3_hash(&hello),
        ja::ja4(&hello).0
    );
}
