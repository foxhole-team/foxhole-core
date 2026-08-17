//! Holds the Rust hello tables to the committed fingerprint data.
//!
//! `fingerprints/*.json` is the reviewable transcription of each profile:
//! for most of them uTLS' matching `Hello*` parrot (`u_parrots.go`), and for
//! `chrome_151` and `firefox_153` a first-party capture of the shipping
//! browser, because uTLS carries no table for either build. They are data, not
//! documentation: everything below re-reads them and asserts that the tables
//! in `hello_profile.rs` still say the same thing.
//!
//! The capture-derived vectors are generated from the captured bytes rather
//! than from the Rust tables, so the two sides of every assertion below have
//! independent origins and agreement means something.
//!
//! The point is drift. A parrot fails silently — a wrong code point or a moved
//! extension costs nothing at handshake time and everything at a DPI box — so
//! the table that produces the bytes and the table a reviewer reads have to be
//! checked against each other by something that runs in CI, not by eye.
//!
//! This is the seam a signed fingerprint feed would later arrive through: the
//! JSON is already the shape such a feed would carry, and the built-in tables
//! are the fail-closed default it would have to agree with. Nothing here
//! parses JSON outside `cfg(test)`; the shipped library has no feed and no
//! network dependency for its parrot.

use serde_json::Value;

use super::hello_profile::{
    CipherSuiteSlot, ExtensionSlot, GroupSlot, HelloProfile, KeyShareSlot, RealityHelloProfile,
    VersionSlot, ext,
};
use super::reality_tls13_messages::INITIAL_RECORD_VERSION;

/// Every profile this build writes, paired with its committed vector.
///
/// A profile added to `RealityHelloProfile` without a vector here fails
/// `every_profile_has_a_committed_vector`, so the table below cannot quietly
/// fall behind the enum.
const VECTORS: &[(RealityHelloProfile, &str)] = &[
    (
        RealityHelloProfile::Chrome151,
        include_str!("../../../../fingerprints/chrome_151.json"),
    ),
    (
        RealityHelloProfile::Chrome133,
        include_str!("../../../../fingerprints/chrome_133.json"),
    ),
    (
        RealityHelloProfile::Chrome131,
        include_str!("../../../../fingerprints/chrome_131.json"),
    ),
    (
        RealityHelloProfile::Edge85,
        include_str!("../../../../fingerprints/edge_85.json"),
    ),
    (
        RealityHelloProfile::Safari263,
        include_str!("../../../../fingerprints/safari_26_3.json"),
    ),
    (
        RealityHelloProfile::Ios14,
        include_str!("../../../../fingerprints/ios_14.json"),
    ),
    (
        RealityHelloProfile::Qq111,
        include_str!("../../../../fingerprints/qq_11_1.json"),
    ),
    (
        RealityHelloProfile::Firefox153,
        include_str!("../../../../fingerprints/firefox_153.json"),
    ),
    (
        RealityHelloProfile::Firefox148,
        include_str!("../../../../fingerprints/firefox_148.json"),
    ),
];

fn pairs() -> Vec<(&'static str, &'static HelloProfile)> {
    VECTORS
        .iter()
        .map(|(profile, json)| (*json, profile.table()))
        .collect()
}

fn table(json: &str) -> Value {
    serde_json::from_str(json).expect("fingerprint file is not valid JSON")
}

/// Parse `"0x1301"` and friends. The files spell every code point as a
/// zero-padded hex string so a reviewer reads the same token that appears in
/// the RFC and in uTLS.
fn hex16(value: &Value) -> u16 {
    let text = value.as_str().expect("code point must be a string");
    let digits = text
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("code point {text} is not 0x-prefixed"));
    u16::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("code point {text} is not hex"))
}

fn fingerprint(json: &str) -> Value {
    table(json)["fingerprint"].clone()
}

/// The code point a slot writes, or `None` for the slots whose type is a
/// per-connection GREASE value rather than a constant.
fn slot_code_point(slot: &ExtensionSlot) -> Option<u16> {
    match slot {
        ExtensionSlot::Constant { extension_type, .. } => Some(*extension_type),
        ExtensionSlot::Grease { .. } => None,
        ExtensionSlot::ServerName => Some(ext::SERVER_NAME),
        ExtensionSlot::SupportedGroups(_) => Some(ext::SUPPORTED_GROUPS),
        ExtensionSlot::KeyShare(_) => Some(ext::KEY_SHARE),
        ExtensionSlot::Alpn => Some(ext::ALPN),
        ExtensionSlot::SupportedVersions(_) => Some(ext::SUPPORTED_VERSIONS),
        ExtensionSlot::EchGrease => Some(ext::ENCRYPTED_CLIENT_HELLO),
        ExtensionSlot::Padding => Some(ext::PADDING),
    }
}

/// The vector's own integrity: the stored digest must cover the stored table.
///
/// Without this, a hand edit to the data would quietly re-point every
/// assertion below at whatever the editor happened to write.
fn assert_digest(json: &str) {
    use aws_lc_rs::digest;

    let file = table(json);
    let canonical = canonical_json(&file["fingerprint"]);
    // ASCII-only by construction: the digest has to be reproducible from any
    // language, and Python's `json.dumps` escapes non-ASCII by default while
    // `serde_json` does not. Keeping the table ASCII removes the question.
    assert!(
        canonical.is_ascii(),
        "fingerprint table contains non-ASCII; the digest would depend on an \
         escaping convention"
    );
    let actual = digest::digest(&digest::SHA256, canonical.as_bytes());
    let actual = actual.as_ref().iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    });
    assert_eq!(
        file["fingerprint_sha256"].as_str().expect("digest field"),
        actual,
        "fingerprint_sha256 does not cover the fingerprint object; re-hash the file"
    );
}

/// JSON with sorted keys and no whitespace — the convention the files document
/// in `fingerprint_sha256_covers`.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key"),
                        canonical_json(&map[*key])
                    )
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", body.join(","))
        }
        other => serde_json::to_string(other).expect("scalar"),
    }
}

#[test]
fn the_committed_fingerprints_are_self_consistent() {
    for (json, _) in pairs() {
        assert_digest(json);
    }
}

/// The enum and the vector table must name the same set. Adding a profile
/// without a committed vector would leave it with no drift guard at all.
#[test]
fn every_profile_has_a_committed_vector() {
    assert_eq!(
        VECTORS.len(),
        RealityHelloProfile::ALL.len(),
        "a profile exists with no committed fingerprint vector"
    );
    for profile in RealityHelloProfile::ALL {
        assert!(
            VECTORS.iter().any(|(candidate, _)| candidate == profile),
            "{profile:?} has no vector"
        );
    }
    // And each vector's `name` must be the table's own name, so a
    // copy-and-paste that pairs the wrong file with a profile is caught.
    for (json, profile) in pairs() {
        assert_eq!(
            table(json)["name"].as_str(),
            Some(profile.name),
            "vector paired with the wrong profile"
        );
    }
}

#[test]
fn cipher_suites_match_the_committed_table() {
    for (json, profile) in pairs() {
        let expected = fingerprint(json)["cipher_suites"].clone();
        let expected = expected.as_array().expect("cipher_suites is a list");
        assert_eq!(
            expected.len(),
            profile.cipher_suites.len(),
            "{}: cipher count",
            profile.name
        );
        for (index, (entry, slot)) in expected.iter().zip(profile.cipher_suites).enumerate() {
            let role = entry["role"].as_str().expect("role");
            match slot {
                CipherSuiteSlot::Grease => assert_eq!(
                    role, "grease",
                    "{} cipher {index}: table says GREASE",
                    profile.name
                ),
                CipherSuiteSlot::Negotiable(id) => {
                    assert_eq!(role, "negotiable", "{} cipher {index}", profile.name);
                    assert_eq!(
                        hex16(&entry["value"]),
                        *id,
                        "{} cipher {index}",
                        profile.name
                    );
                }
                CipherSuiteSlot::Decorative(id) => {
                    assert_eq!(role, "decorative", "{} cipher {index}", profile.name);
                    assert_eq!(
                        hex16(&entry["value"]),
                        *id,
                        "{} cipher {index}",
                        profile.name
                    );
                }
            }
        }
    }
}

/// Extension *order* before permutation. The permutation is per connection,
/// but the table order is what a reviewer diffs against uTLS, and the two
/// GREASE slots and padding are pinned regardless.
#[test]
fn extension_order_matches_the_committed_table() {
    for (json, profile) in pairs() {
        let expected = fingerprint(json)["extension_order"].clone();
        let expected = expected.as_array().expect("extension_order is a list");
        assert_eq!(
            expected.len(),
            profile.extensions.len(),
            "{}: extension count",
            profile.name
        );
        for (index, (entry, slot)) in expected.iter().zip(profile.extensions).enumerate() {
            assert_eq!(
                entry["order"].as_u64().expect("order"),
                index as u64 + 1,
                "{}: extension_order is not 1-based dense",
                profile.name
            );
            let declared = entry["type"].as_str().expect("type");
            match slot_code_point(slot) {
                None => assert_eq!(
                    declared, "GREASE",
                    "{} extension {index}: table has a GREASE slot",
                    profile.name
                ),
                Some(code_point) => assert_eq!(
                    hex16(&entry["type"]),
                    code_point,
                    "{} extension {index} ({declared})",
                    profile.name
                ),
            }
        }
    }
}

#[test]
fn groups_shares_versions_and_alpn_match_the_committed_table() {
    for (json, profile) in pairs() {
        let fp = fingerprint(json);
        let name = profile.name;

        let groups = find_groups(profile);
        let expected = fp["supported_groups"].as_array().expect("groups").clone();
        assert_eq!(expected.len(), groups.len(), "{name}: group count");
        for (index, (entry, slot)) in expected.iter().zip(groups).enumerate() {
            match slot {
                GroupSlot::Grease => {
                    assert_eq!(
                        entry["value"].as_str(),
                        Some("GREASE"),
                        "{name} group {index}"
                    )
                }
                GroupSlot::Group(group) => assert_eq!(
                    hex16(&entry["value"]),
                    group.id(),
                    "{name} group {index} ({})",
                    group.name()
                ),
            }
        }

        let shares = find_key_shares(profile);
        let expected = fp["key_shares"].as_array().expect("key_shares").clone();
        assert_eq!(expected.len(), shares.len(), "{name}: key share count");
        for (index, (entry, slot)) in expected.iter().zip(shares).enumerate() {
            match slot {
                KeyShareSlot::Grease => {
                    assert_eq!(
                        entry["value"].as_str(),
                        Some("GREASE"),
                        "{name} share {index}"
                    )
                }
                KeyShareSlot::Group(group) => assert_eq!(
                    hex16(&entry["value"]),
                    group.id(),
                    "{name} share {index} ({})",
                    group.name()
                ),
            }
        }

        let versions = find_versions(profile);
        let expected = fp["supported_versions"]
            .as_array()
            .expect("supported_versions")
            .clone();
        assert_eq!(expected.len(), versions.len(), "{name}: version count");
        for (index, (entry, slot)) in expected.iter().zip(versions).enumerate() {
            match slot {
                VersionSlot::Grease => assert_eq!(
                    entry["value"].as_str(),
                    Some("GREASE"),
                    "{name} version {index}"
                ),
                VersionSlot::Version(version) => {
                    assert_eq!(hex16(&entry["value"]), *version, "{name} version {index}")
                }
            }
        }

        let alpn: Vec<&str> = fp["alpn"]
            .as_array()
            .expect("alpn")
            .iter()
            .map(|entry| entry.as_str().expect("alpn entry"))
            .collect();
        assert_eq!(
            alpn,
            super::hello_profile::CHROME_ALPN_PROTOCOLS,
            "{name}: ALPN"
        );
    }
}

/// The record-layer version is the field the tables did not used to carry at
/// all, and the field the client used to get wrong.
#[test]
fn the_record_layer_version_matches_the_committed_table() {
    for (json, _) in pairs() {
        let fp = fingerprint(json);
        let initial = &fp["record_layer_version"]["initial_client_hello"];
        assert_eq!(
            hex16(initial).to_be_bytes(),
            INITIAL_RECORD_VERSION,
            "committed table and INITIAL_RECORD_VERSION disagree"
        );
        assert_eq!(
            fp["record_layer_version"]["subsequent_records"].as_str(),
            Some("0x0303")
        );
    }
}

fn find_groups(profile: &HelloProfile) -> &'static [GroupSlot] {
    profile
        .extensions
        .iter()
        .find_map(|slot| match slot {
            ExtensionSlot::SupportedGroups(groups) => Some(*groups),
            _ => None,
        })
        .expect("profile has supported_groups")
}

fn find_key_shares(profile: &HelloProfile) -> &'static [KeyShareSlot] {
    profile
        .extensions
        .iter()
        .find_map(|slot| match slot {
            ExtensionSlot::KeyShare(entries) => Some(*entries),
            _ => None,
        })
        .expect("profile has key_share")
}

fn find_versions(profile: &HelloProfile) -> &'static [VersionSlot] {
    profile
        .extensions
        .iter()
        .find_map(|slot| match slot {
            ExtensionSlot::SupportedVersions(versions) => Some(*versions),
            _ => None,
        })
        .expect("profile has supported_versions")
}
