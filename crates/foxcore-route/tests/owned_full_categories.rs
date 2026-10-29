use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use foxcore_api::DnsCategory;
use foxcore_route::domain::DomainBlocklist;
use foxcore_route::ruleset::{
    RuleSetVerificationPolicy, parse_trusted_categorized_rule_set, verify_rule_set,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[ignore = "Requires the hash-bound owned full dataset and metadata, outside Git"]
fn actual_full_artifact_verifies_counts_selection_and_temporary_signature() {
    let artifact = std::fs::read(std::env::var("FOXCORE_OWNED_FULL_ARTIFACT").unwrap()).unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("FOXCORE_OWNED_FULL_METADATA").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(artifact.len(), 19_187_352);
    assert_eq!(
        hex(&Sha256::digest(&artifact)),
        "2ac53fa40fb354086d5cd1d5a64d05fb3421b14c327d31cbb796aa3160f1ee8c"
    );
    let name = "foxhole-dns-categories-pro-full";
    let trusted = parse_trusted_categorized_rule_set(name, &artifact).unwrap();
    assert_eq!(trusted.block_entries(), 2_384_911);
    assert_eq!(trusted.allow_entries(), 0);
    assert_eq!(
        hex(&trusted.source_sha256()),
        metadata["tagged_input_sha256"].as_str().unwrap()
    );
    assert!(trusted.select_categories(None).is_err());
    let all = [
        DnsCategory::Malicious,
        DnsCategory::Telemetry,
        DnsCategory::Trackers,
        DnsCategory::Ads,
    ];
    for selection in [&[][..], &all[..]] {
        let selected = trusted.select_categories(Some(selection)).unwrap();
        let list = DomainBlocklist::default().with_rule_sets(vec![selected]);
        assert!(!list.blocks("unlisted-owned-fixture.invalid"));
    }
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let key = pair.public_key().as_ref();
    let mut manifest = serde_json::to_vec(&json!({
        "schema":3, "name":name, "format":"foxhole-dns-fst-v1", "sequence":7,
        "generated_at_unix":1000, "expires_at_unix":2000, "key_sha256":hex(&Sha256::digest(key)),
        "categories":metadata["categories"], "tiers":metadata["tiers"], "sources":metadata["sources"],
        "tagged_input_sha256":metadata["tagged_input_sha256"],
        "artifact":{"file":"dns-categories.fhds","size":artifact.len(),"sha256":hex(&Sha256::digest(&artifact)),
            "block_entries":2384911,"allow_entries":0,"category_entries":metadata["category_counts"]},
        "compatibility":{"core_schema":1,"category_schema":1}
    })).unwrap();
    manifest.push(b'\n');
    let signature = pair.sign(&SystemRandom::new(), &manifest).unwrap();
    let verified = verify_rule_set(
        &manifest,
        signature.as_ref(),
        key,
        &artifact,
        RuleSetVerificationPolicy::new(name, 7, 1500),
    )
    .unwrap();
    assert_eq!(verified.metadata().block_entries, 2_384_911);
    assert_eq!(
        verified.metadata().categorized_manifest_sha256,
        Some(Sha256::digest(&manifest).into())
    );
    assert!(
        verify_rule_set(
            &manifest,
            signature.as_ref(),
            key,
            &artifact,
            RuleSetVerificationPolicy::new(name, 8, 1500)
        )
        .is_err()
    );
}
