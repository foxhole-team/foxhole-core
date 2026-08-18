use foxcore_transport::ja;

use super::hello_profile::RealityHelloProfile;
use super::reality_client_connection::{RealityClientConfig, RealityClientConnection};

fn hello_bytes(profile: RealityHelloProfile) -> Vec<u8> {
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

        let a = ja4.split('_').next().expect("JA4_a");
        assert!(
            a.starts_with("t13d"),
            "{profile:?}: TLS 1.3 with an SNI: {a}"
        );
        assert!(a.ends_with("h2"), "{profile:?}: first ALPN is h2: {a}");

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
