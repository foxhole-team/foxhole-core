use foxcore_api::TlsConfig;
use serde_json::json;

#[test]
fn chrome_tls_keeps_its_fingerprint_and_explicit_websocket_alpn() {
    let value = json!({
        "enabled": true,
        "server_name": "proxy.example",
        "fingerprint": "chrome_151",
        "alpn": ["http/1.1"]
    });
    let tls: TlsConfig =
        serde_json::from_value(value).expect("ordinary TLS Chrome must be represented");
    let encoded = serde_json::to_value(tls).unwrap();
    assert_eq!(encoded["fingerprint"], "chrome_151");
    assert_eq!(encoded["alpn"], json!(["http/1.1"]));
    assert_eq!(encoded["server_name"], "proxy.example");
    assert_eq!(encoded["insecure"], false);
}

#[test]
fn unspecified_fingerprint_keeps_the_stock_tls_contract() {
    let tls: TlsConfig = serde_json::from_value(json!({"enabled":true})).unwrap();
    assert!(
        serde_json::to_value(tls)
            .unwrap()
            .get("fingerprint")
            .is_none()
    );
}

#[test]
fn unimplemented_fingerprints_are_rejected_instead_of_dropped() {
    for fingerprint in ["firefox_153", "randomized", "unknown-browser"] {
        assert!(
            serde_json::from_value::<TlsConfig>(json!({
                "enabled":true,"fingerprint":fingerprint
            }))
            .is_err()
        );
    }
}
