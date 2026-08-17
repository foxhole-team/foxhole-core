//! What a detector sees when this core sends each REALITY parrot.
//!
//! The parrots cannot be pointed at a public JA3/JA4 service: they only
//! complete a handshake against a REALITY server, and a detector needs a
//! completed connection to answer. So the fingerprint is computed here, with
//! the *same* implementation that `foxcore-transport/tests/ja_fingerprint.rs`
//! validates against `tls.browserleaks.com` — that test asserts the
//! computation reproduces a third party's answer byte for byte, which is what
//! makes the numbers below measurements rather than assertions.
//!
//! Run with `--nocapture` to print the table.
//!
//! Everything is synthetic: a public key of repeated bytes and an
//! `example.com` SNI.

use foxcore_transport::ja;

use super::hello_profile::RealityHelloProfile;
use super::reality_client_connection::{RealityClientConfig, RealityClientConnection};

fn hello_bytes(profile: RealityHelloProfile) -> Vec<u8> {
    // A REALITY public key that belongs to nobody. Any valid X25519 point does:
    // the hello's *shape* does not depend on which server it is aimed at.
    let config = RealityClientConfig {
        public_key: [0x2a; 32],
        short_id: [1, 2, 3, 4, 5, 6, 7, 8],
        server_name: "example.com".to_owned(),
        hello: profile.into(),
    };
    let mut connection = RealityClientConnection::new(config).expect("client");
    let mut wire = Vec::new();
    connection.write_tls(&mut wire).expect("hello");
    assert_eq!(wire[0], 0x16, "first record is the handshake");
    wire[5..].to_vec()
}

/// Every parrot's JA3 and JA4, printed and sanity-checked.
///
/// The assertions are structural rather than golden hashes: the hello is
/// GREASEd and (for Chrome) permuted per connection, so a frozen hash would
/// either be wrong or would require freezing the randomness that makes the
/// parrot a parrot. What is pinned is what a detector keys on first.
#[test]
fn every_parrot_reports_the_fingerprint_its_table_implies() {
    println!("\n{:<12} {:<34} JA4", "profile", "JA3");
    for profile in RealityHelloProfile::ALL {
        let bytes = hello_bytes(*profile);
        let hello = ja::parse(&bytes);
        let ja3 = ja::ja3_hash(&hello);
        let (ja4, ja4_raw) = ja::ja4(&hello);
        println!("{:<12} {ja3:<34} {ja4}", format!("{profile:?}"));
        println!("             raw {ja4_raw}");

        // JA4_a is human-readable and is what a cheap detector matches first:
        // TLS version, SNI present, cipher count, extension count, ALPN.
        let a = ja4.split('_').next().expect("JA4_a");
        assert!(
            a.starts_with("t13d"),
            "{profile:?}: TLS 1.3 with an SNI: {a}"
        );
        assert!(a.ends_with("h2"), "{profile:?}: first ALPN is h2: {a}");

        // GREASE must never reach a fingerprint. If it did, every connection
        // would produce a different JA4 and the parrot would defeat itself.
        for value in hello.ciphers.iter().chain(hello.extensions.iter()) {
            if ja::is_grease(*value) {
                assert!(
                    !ja4_raw.contains(&format!("{value:04x}")),
                    "{profile:?}: GREASE {value:#06x} leaked into JA4"
                );
            }
        }
    }
}

/// The capture-derived profiles must reproduce the *browser's* JA4.
///
/// This is the only assertion in the tree that compares a parrot against a
/// measurement of the thing it imitates rather than against another
/// description of it. `chrome_151.json` and `firefox_153.json` each record, in
/// `provenance.measured_ja4`, the JA4 computed from the captured ClientHello of
/// the shipping browser; the number is written in exactly one place and read
/// from there, so a table edit that moves the fingerprint fails here instead of
/// silently producing a client that matches no browser.
///
/// JA4 is the right thing to pin and JA3 is not: JA4 sorts its cipher and
/// extension lists, so Chrome's per-connection permutation and every GREASE
/// value drop out, and what remains is exactly the part a detector can match
/// across connections.
///
/// The older uTLS-derived tables are deliberately not pinned this way. They
/// describe builds nobody here can run, so the honest reference for them stays
/// `scripts/fingerprint-from-utls.py`.
#[test]
fn the_captured_profiles_reproduce_the_browsers_measured_ja4() {
    const CAPTURED: &[(RealityHelloProfile, &str, &str)] = &[
        (
            RealityHelloProfile::Chrome151,
            "chrome_151",
            include_str!("../../../../fingerprints/chrome_151.json"),
        ),
        (
            RealityHelloProfile::Firefox153,
            "firefox_153",
            include_str!("../../../../fingerprints/firefox_153.json"),
        ),
    ];

    for (profile, name, json) in CAPTURED {
        let vector: serde_json::Value =
            serde_json::from_str(json).expect("fingerprint file is not valid JSON");
        let measured = vector["provenance"]["measured_ja4"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} has no provenance.measured_ja4"));

        let (ja4, ja4_raw) = ja::ja4(&ja::parse(&hello_bytes(*profile)));
        assert_eq!(
            ja4, measured,
            "{name} no longer reproduces the browser it was captured from\n  \
             parrot   {ja4}\n  browser  {measured}\n  parrot raw {ja4_raw}"
        );
    }
}

/// JA4 is stable across connections; JA3 is not, for the profiles that permute.
///
/// The sharpest practical result here. JA4 sorts its lists, so Chrome's
/// per-connection extension shuffle does not move it — which is why a JA4
/// blocklist is the thing to worry about and a JA3 one largely is not.
#[test]
fn ja4_is_stable_while_ja3_moves_for_the_permuting_profiles() {
    let mut ja4s = std::collections::HashSet::new();
    let mut ja3s = std::collections::HashSet::new();
    for _ in 0..12 {
        let hello = ja::parse(&hello_bytes(RealityHelloProfile::Chrome133));
        ja4s.insert(ja::ja4(&hello).0);
        ja3s.insert(ja::ja3_hash(&hello));
    }
    assert_eq!(ja4s.len(), 1, "JA4 must not move between connections");
    assert!(
        ja3s.len() > 1,
        "Chrome permutes its extensions, so JA3 must move; if it stopped, the \
         profile lost its shuffle"
    );

    // Firefox neither GREASEs nor permutes, so both are stable.
    let mut ja4s = std::collections::HashSet::new();
    let mut ja3s = std::collections::HashSet::new();
    for _ in 0..8 {
        let hello = ja::parse(&hello_bytes(RealityHelloProfile::Firefox148));
        ja4s.insert(ja::ja4(&hello).0);
        ja3s.insert(ja::ja3_hash(&hello));
    }
    assert_eq!(ja4s.len(), 1, "Firefox JA4 is stable");
    assert_eq!(ja3s.len(), 1, "Firefox JA3 is stable too");
}
