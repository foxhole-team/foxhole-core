use serde_json::Value;

use super::hello_profile::{
    CipherSuiteSlot, ExtensionSlot, GroupSlot, HelloProfile, KeyShareSlot, RealityHelloProfile,
    VersionSlot, ext,
};
use super::reality_tls13_messages::INITIAL_RECORD_VERSION;

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

fn assert_digest(json: &str) {
    use aws_lc_rs::digest;

    let file = table(json);
    let canonical = canonical_json(&file["fingerprint"]);
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
