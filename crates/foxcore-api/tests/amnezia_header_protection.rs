use foxcore_api::AmneziaConfig;
use serde_json::json;

const KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

#[test]
fn header_protection_is_preserved_and_redacted() {
    let config: AmneziaConfig = serde_json::from_value(json!({
        "header_protection_key":KEY,"init_junk_size":12,"response_junk_size":12,
        "cookie_junk_size":12,"transport_junk_size":12
    }))
    .expect("valid HPK must be retained");
    assert_eq!(
        serde_json::to_value(&config).unwrap()["header_protection_key"],
        KEY
    );
    assert!(!format!("{config:?}").contains(KEY));
}

#[test]
fn header_protection_refuses_declared_malformed_json_without_key_disclosure() {
    for value in [
        json!(null),
        json!(""),
        json!("not-a-key"),
        json!("AQID"),
        json!(42),
        json!([]),
    ] {
        let error =
            serde_json::from_value::<AmneziaConfig>(json!({"header_protection_key":value.clone()}))
                .unwrap_err();
        if let Some(text) = value.as_str().filter(|text| !text.is_empty()) {
            assert!(!error.to_string().contains(text));
        }
    }
}

#[test]
fn absent_header_protection_keeps_the_serialized_default_absent() {
    assert!(
        serde_json::to_value(AmneziaConfig::default())
            .unwrap()
            .get("header_protection_key")
            .is_none()
    );
}

#[test]
fn nonzero_keys_require_each_nonce_prefix_but_zero_keys_do_not() {
    let good:AmneziaConfig=serde_json::from_value(json!({"header_protection_key":KEY,"init_junk_size":12,"response_junk_size":12,"cookie_junk_size":12,"transport_junk_size":12})).unwrap();
    good.validate_header_protection_key().unwrap();
    for field in [
        "init_junk_size",
        "response_junk_size",
        "cookie_junk_size",
        "transport_junk_size",
    ] {
        let mut value = serde_json::to_value(&good).unwrap();
        value[field] = json!(11);
        let invalid: AmneziaConfig = serde_json::from_value(value).unwrap();
        assert!(invalid.validate_header_protection_key().is_err());
    }
    let zero: AmneziaConfig = serde_json::from_value(
        json!({"header_protection_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
    )
    .unwrap();
    zero.validate_header_protection_key().unwrap();
}
