use foxcore_link::import_link;

#[test]
fn ordinary_tls_chrome_is_honoured_not_reported_as_dropped() {
    let imported = import_link("vless://11111111-1111-4111-8111-111111111111@proxy.example:443?security=tls&fp=chrome&sni=certificate.example&type=ws&host=websocket.example&path=%2Fowned&alpn=http%2F1.1").unwrap();
    assert!(
        imported.dropped.is_empty(),
        "Chrome fingerprint must be implemented: {:?}",
        imported.dropped
    );
    let value = serde_json::to_value(imported.outbound).unwrap();
    assert_eq!(value["tls"]["fingerprint"], "chrome_151");
    assert_eq!(value["tls"]["alpn"], serde_json::json!(["http/1.1"]));
    assert_eq!(value["tls"]["server_name"], "certificate.example");
    assert_eq!(value["transport"]["type"], "websocket");
    assert_eq!(value["transport"]["host"], "websocket.example");
    assert_eq!(value["transport"]["path"], "/owned");
}
