use foxcore_api::OutboundConfig;
use foxcore_link::{import_link, import_wireguard_conf};
use serde_json::json;

const KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
const CONF: &str = "[Interface]\nPrivateKey = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nAddress = 10.8.0.2/32\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n[Peer]\nPublicKey = CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\nAllowedIPs = 0.0.0.0/0\nEndpoint = edge.example:51820\n";
fn imported(text: &str) -> serde_json::Value {
    let value = import_wireguard_conf(text).unwrap();
    let OutboundConfig::Wireguard(config) = value.outbound else {
        panic!("expected WG")
    };
    serde_json::to_value(config.amnezia.unwrap()).unwrap()
}
#[test]
fn minimal_header_protection_profiles_use_independent_header_and_junk_defaults() {
    let value = imported(&CONF.replace("[Peer]", &format!("HeaderProtectionKey = {KEY}\n[Peer]")));
    assert_eq!(value["header_protection_key"], KEY);
    assert_eq!(value["junk_packet_count"], 0);
    assert_eq!(value["header_initiation"], 1);
    assert_eq!(value["header_response"], 2);
    assert_eq!(value["header_cookie"], 3);
    assert_eq!(value["header_transport"], 4);
}
#[test]
fn header_protection_requires_nonce_prefixes_and_interface_placement() {
    for field in ["S1", "S2", "S3", "S4"] {
        let text = CONF
            .replace(&format!("{field} = 12\n"), "")
            .replace("[Peer]", &format!("HeaderProtectionKey = {KEY}\n[Peer]"));
        assert!(import_wireguard_conf(&text).is_err());
    }
    let text = CONF.replace("[Peer]", &format!("[Peer]\nHeaderProtectionKey = {KEY}"));
    assert!(import_wireguard_conf(&text).is_err());
}
#[test]
fn malformed_header_keys_are_refused_without_disclosure() {
    for key in [
        "not-a-key",
        "",
        "AQID",
        "01020304",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB=",
    ] {
        let text = CONF.replace("[Peer]", &format!("HeaderProtectionKey = {key}\n[Peer]"));
        let error = import_wireguard_conf(&text).unwrap_err().to_string();
        if !key.is_empty() {
            assert!(!error.contains(key));
        }
    }
}
#[test]
fn uri_header_keys_are_retained_and_declared_empty_values_are_refused() {
    let base = "wireguard://BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc%3D@edge.example:51820?publickey=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk%3D&address=10.8.0.2%2F32&allowedips=0.0.0.0%2F0&s1=12&s2=12&s3=12&s4=12";
    let value = import_link(&format!("{base}&headerprotectionkey={KEY}")).unwrap();
    let OutboundConfig::Wireguard(config) = value.outbound else {
        panic!("expected WG")
    };
    assert_eq!(
        serde_json::to_value(config.amnezia.unwrap()).unwrap()["header_protection_key"],
        json!(KEY)
    );
    assert!(import_link(&format!("{base}&headerprotectionkey=")).is_err());
}

#[test]
fn escaped_header_key_uri_characters_are_decoded_without_value_loss() {
    let base = "wireguard://BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc%3D@edge.example:51820?publickey=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk%3D&address=10.8.0.2%2F32&allowedips=0.0.0.0%2F0&s1=12&s2=12&s3=12&s4=12";
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode([0xfb; 32]);
    assert!(key.contains('+') && key.contains('/') && key.ends_with('='));
    let encoded: String = url::form_urlencoded::byte_serialize(key.as_bytes()).collect();
    let profile = import_link(&format!("{base}&headerprotectionkey={encoded}")).unwrap();
    let OutboundConfig::Wireguard(config) = profile.outbound else {
        panic!("expected WG")
    };
    assert_eq!(
        serde_json::to_value(config.amnezia.unwrap()).unwrap()["header_protection_key"],
        key
    );
}

#[test]
fn zero_keys_allow_missing_prefixes_and_header_overlap_is_refused() {
    let mut plain = CONF.to_owned();
    for field in ["S1", "S2", "S3", "S4"] {
        plain = plain.replace(&format!("{field} = 12\n"), "");
    }
    let zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let value =
        imported(&plain.replace("[Peer]", &format!("HeaderProtectionKey = {zero}\n[Peer]")));
    assert_eq!(value["header_protection_key"], zero);
    assert_eq!(value["init_junk_size"], 0);
    assert_eq!(value["transport_junk_size"], 0);
    let collision = CONF.replace(
        "[Peer]",
        &format!("HeaderProtectionKey = {KEY}\nH1 = 2\n[Peer]"),
    );
    assert!(import_wireguard_conf(&collision).is_err());
}
