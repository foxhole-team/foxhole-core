use foxcore_route::domain::DomainBlocklist;
use foxcore_route::ruleset::parse_trusted_embedded_rule_set;

#[test]
fn dns_repository_v1_fixture_is_accepted_without_conversion() {
    let bytes = include_bytes!("fixtures/foxhole-dns-v1.fhds");
    let artifact = parse_trusted_embedded_rule_set(bytes).unwrap();
    assert_eq!(artifact.block_entries(), 2);
    assert_eq!(artifact.allow_entries(), 1);

    let list = DomainBlocklist::default().with_rule_sets(vec![artifact]);
    assert!(list.blocks("ads.example"));
    assert!(list.blocks("child.ads.example"));
    assert!(!list.blocks("safe.ads.example"));
    assert!(!list.blocks("child.safe.ads.example"));
    assert!(list.blocks("exact.example"));
    assert!(!list.blocks("child.exact.example"));
}
