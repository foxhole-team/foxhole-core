mod fingerprint_table_support;

use fingerprint_table_support as support;
use proto_reality::{
    RealityHelloProfile, install_fingerprint_tables, using_downloaded_fingerprint_tables,
};

#[tokio::test]
async fn every_way_a_document_goes_bad_falls_back_to_the_built_in_tables() {
    let committed = support::committed_document();
    let serialised = committed.to_string();

    let rewritten = support::with_marked_renegotiation_info(committed.clone(), "0000");

    let mut future_schema = support::rehash(rewritten.clone());
    future_schema["schema"] = serde_json::json!(2);

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
