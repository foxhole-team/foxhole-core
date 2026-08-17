//! The breakage this feature was opened for.
//!
//! `foxcore-link` used to refuse any `encryption=` value other than `none`, so
//! the day a provider switched VLESS Encryption on, every one of its nodes
//! stopped importing — the same shape of failure as the gRPC and `fp` gates
//! before it. These tests hold the import path to the two properties that
//! matter: a variant this build implements must import, and a variant it does
//! not must cost that one node and nothing else.
//!
//! They live in this crate rather than in `foxcore-link`'s own test module
//! because that file is being edited concurrently; `foxcore-link` is a
//! dev-dependency here, so the public import API is reachable without touching
//! it.

use foxcore_api::{OutboundConfig, VlessEncryptionMode, parse_vless_encryption};
use foxcore_link::{LinkError, import_link, import_subscription_partial};

/// Synthetic X25519 server key: 32 bytes of a fixed pattern, base64url.
const X25519_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn vless_link(encryption: Option<&str>) -> String {
    let mut link = String::from(
        "vless://11111111-2222-3333-4444-555555555555@example.invalid:443?type=tcp&security=none",
    );
    if let Some(encryption) = encryption {
        link.push_str("&encryption=");
        link.push_str(encryption);
    }
    link.push_str("#node");
    link
}

fn vless_config(link: &str) -> foxcore_api::VlessConfig {
    match import_link(link).expect("link imports").outbound {
        OutboundConfig::Vless(config) => config,
        other => panic!("expected a VLESS profile, got {other:?}"),
    }
}

#[test]
fn a_profile_with_encryption_imports_and_keeps_the_parameter() {
    for (mode, expected) in [
        ("native", VlessEncryptionMode::Native),
        ("xorpub", VlessEncryptionMode::XorPub),
        ("random", VlessEncryptionMode::Random),
    ] {
        for rtt in ["0rtt", "1rtt"] {
            let spec = format!("mlkem768x25519plus.{mode}.{rtt}.{X25519_KEY}");
            let config = vless_config(&vless_link(Some(&spec)));
            let stored = config
                .encryption
                .as_ref()
                .unwrap_or_else(|| panic!("{spec} was dropped from the profile"));
            assert_eq!(stored.expose(), spec);

            // The stored value has to be the thing the outbound will parse, not
            // a normalisation of it.
            let params = parse_vless_encryption(stored.expose()).expect("stored value re-parses");
            assert_eq!(params.xor_mode, expected);
            assert_eq!(params.zero_rtt, rtt == "0rtt");
        }
    }
}

#[test]
fn padding_parameters_and_relay_chains_survive_the_round_trip() {
    let spec = format!(
        "mlkem768x25519plus.random.0rtt.100-40-40.100-5-5.100-60-60.{X25519_KEY}.{X25519_KEY}"
    );
    let config = vless_config(&vless_link(Some(&spec)));
    let stored = config.encryption.expect("encryption kept");
    assert_eq!(stored.expose(), spec);
    let params = parse_vless_encryption(stored.expose()).unwrap();
    assert_eq!(params.nfs_keys.len(), 2);
    assert_eq!(params.padding.lens.len(), 2);
    assert_eq!(params.padding.gaps.len(), 1);
}

#[test]
fn none_and_absent_both_mean_no_encryption_layer() {
    assert!(vless_config(&vless_link(None)).encryption.is_none());
    assert!(vless_config(&vless_link(Some("none"))).encryption.is_none());
}

/// The regression itself. If this fails, the gate is back.
#[test]
fn a_supported_variant_is_no_longer_refused_outright() {
    let spec = format!("mlkem768x25519plus.native.0rtt.{X25519_KEY}");
    let result = import_link(&vless_link(Some(&spec)));
    assert!(
        result.is_ok(),
        "a profile this build can execute was refused: {:?}",
        result.err()
    );
}

/// Negative control for the test above: the importer has not simply stopped
/// looking at the parameter. A variant this build cannot execute must still be
/// refused, and the message must name it.
#[test]
fn an_unsupported_variant_is_still_refused_and_named() {
    let spec = format!("mlkem768x25519plus.chameleon.1rtt.{X25519_KEY}");
    let error = import_link(&vless_link(Some(&spec))).expect_err("unsupported mode was accepted");
    assert!(
        matches!(error, LinkError::Unsupported(_)),
        "expected an unsupported-option error, got {error:?}"
    );
    assert!(
        error.to_string().contains("chameleon"),
        "the error does not name the variant: {error}"
    );
}

/// And the property the whole exercise is about: one node this build cannot
/// execute must not cost the user the rest of the subscription.
#[test]
fn an_unsupported_variant_costs_one_node_not_the_subscription() {
    let good = vless_link(Some(&format!(
        "mlkem768x25519plus.native.1rtt.{X25519_KEY}"
    )));
    let future = vless_link(Some(&format!("mlkem1024x448plus.native.1rtt.{X25519_KEY}")));
    let plain = vless_link(None);

    let body = format!("{good}\n{future}\n{plain}\n");
    let imported = import_subscription_partial(&body).expect("subscription imports");

    assert_eq!(
        imported.profiles.len(),
        2,
        "the supported nodes did not survive: {:?}",
        imported.rejected
    );
    assert_eq!(imported.rejected.len(), 1, "expected exactly one rejection");
    let rejected = &imported.rejected[0];
    assert_eq!(rejected.index, 2, "the wrong line was rejected");
    assert_eq!(rejected.scheme.as_deref(), Some("vless"));

    // The variant is deliberately *not* named here. `RejectedLine::reason` is a
    // closed category so the report can be persisted or pasted into a bug
    // report without carrying any of the link with it; the detailed message
    // goes to the strict importer's direct caller, which is what
    // `an_unsupported_variant_is_still_refused_and_named` covers.
    assert!(
        !rejected.reason.contains("mlkem1024x448plus"),
        "the persistable rejection reason leaked the link's contents: {rejected:?}"
    );
    assert_eq!(rejected.reason, "unsupported share-link option");
}
