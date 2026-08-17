//! What happens when the downloaded document is bad, which is the case that has
//! to work on someone's phone at three in the morning.
//!
//! The rule is one sentence: an unverified, malformed, stale or missing
//! document falls back to the tables built into this binary — never to "no
//! fingerprint", and never to a half-parsed set. This test states each of the
//! ways a stored document goes wrong and then reads the socket to check that a
//! complete, correct hello still went out.
//!
//! Its own binary: nothing here may install anything, and the registry is
//! process-global.
//!
//! Everything is synthetic: `example.com`, a public key of repeated bytes, and
//! a local listener that answers nothing.

mod fingerprint_table_support;

use fingerprint_table_support as support;
use proto_reality::{
    RealityHelloProfile, install_fingerprint_tables, using_downloaded_fingerprint_tables,
};

#[tokio::test]
async fn every_way_a_document_goes_bad_falls_back_to_the_built_in_tables() {
    let committed = support::committed_document();
    let serialised = committed.to_string();

    // Rewritten after signing: the bytes changed, the declared digest did not.
    // This is the one an attacker with publishing access but no signing key
    // would try, and the one a half-finished edit produces by accident.
    let rewritten = support::with_marked_renegotiation_info(committed.clone(), "0000");

    // Right shape, wrong schema: a feed that changed format under us.
    let mut future_schema = support::rehash(rewritten.clone());
    future_schema["schema"] = serde_json::json!(2);

    // A table that cannot produce a hello at all.
    let mut no_key_share = committed.clone();
    for entry in no_key_share["profiles"].as_array_mut().expect("profiles") {
        let slots = entry["fingerprint"]["extension_order"]
            .as_array_mut()
            .expect("extension_order");
        slots.retain(|slot| slot["type"] != "0x0033");
        for (index, slot) in slots.iter_mut().enumerate() {
            slot["order"] = serde_json::json!(index + 1);
        }
    }
    let no_key_share = support::rehash(no_key_share);

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("absent", Vec::new()),
        ("empty object", b"{}".to_vec()),
        ("not json", b"<html>404</html>".to_vec()),
        (
            "truncated",
            serialised.as_bytes()[..serialised.len() / 2].to_vec(),
        ),
        (
            "rewritten after signing",
            rewritten.to_string().into_bytes(),
        ),
        ("unknown schema", future_schema.to_string().into_bytes()),
        (
            "cannot produce a hello",
            no_key_share.to_string().into_bytes(),
        ),
    ];

    for (label, bytes) in cases {
        let refused = install_fingerprint_tables(&bytes);
        assert!(
            refused.is_err(),
            "{label}: a document that fails a check must not install"
        );
        assert!(
            !using_downloaded_fingerprint_tables(),
            "{label}: nothing may be left installed"
        );

        for profile in RealityHelloProfile::ALL {
            let hello = support::client_hello_on_the_wire(*profile).await;
            support::assert_is_a_complete_client_hello(&format!("{label}/{profile:?}"), &hello);
            assert_eq!(
                support::extension_body(&hello, support::RENEGOTIATION_INFO),
                Some(vec![0x00]),
                "{label}/{profile:?}: the built-in table must be writing the bytes"
            );
        }
    }
}
