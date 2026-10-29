use foxcore_api::OutboundConfig;
use foxcore_link::{import_link, import_wireguard_conf};
use serde_json::json;

const CONF: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.0.2/32\nMTU = 1280\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.20:51820\n";

#[test]
fn content_padding_from_conf_is_retained_not_dropped() {
    for (raw, expected) in [
        ("13", json!(13)),
        ("65536", json!(65536)),
        ("65536-4294967295", json!("65536-4294967295")),
        ("0-0", json!(0)),
    ] {
        let text = CONF.replace(
            "MTU = 1280",
            &format!("MTU = 1280\nContentPaddingAddition = {raw}"),
        );
        let imported = import_wireguard_conf(&text).unwrap();
        assert!(
            !imported
                .dropped
                .iter()
                .any(|item| item.option == "contentpaddingaddition")
        );
        let OutboundConfig::Wireguard(config) = imported.outbound else {
            panic!("must remain WireGuard");
        };
        assert_eq!(
            serde_json::to_value(config.amnezia.unwrap()).unwrap()["content_padding_addition"],
            expected
        );
    }
}

#[test]
fn malformed_content_padding_is_refused_instead_of_ignored() {
    for value in [
        "",
        "-1",
        "4294967296",
        "1-4294967296",
        "3-1",
        "1-2-3",
        "false",
    ] {
        let text = CONF.replace(
            "MTU = 1280",
            &format!("MTU = 1280\nContentPaddingAddition = {value}"),
        );
        let failure = import_wireguard_conf(&text).expect_err("malformed CPA must not be dropped");
        assert!(
            failure
                .to_string()
                .to_ascii_lowercase()
                .contains("contentpadding")
        );
    }
}

#[test]
fn peer_content_padding_is_refused_as_an_interface_setting() {
    let text = CONF.replace("[Peer]", "[Peer]\nContentPaddingAddition = 13");
    assert!(import_wireguard_conf(&text).is_err());
}

#[test]
fn content_padding_uri_preserves_ranges_and_refuses_declared_empty_values() {
    let base = "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@203.0.113.20:51820?publickey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE%3D&address=10.8.0.2%2F32&allowedips=0.0.0.0%2F0";
    let imported = import_link(&format!("{base}&contentpaddingaddition=65536-4294967295")).unwrap();
    let OutboundConfig::Wireguard(config) = imported.outbound else {
        panic!("must remain WireGuard");
    };
    assert_eq!(
        serde_json::to_value(config.amnezia.unwrap()).unwrap()["content_padding_addition"],
        "65536-4294967295"
    );
    for suffix in ["", "-1", "4294967296", "3-1", "false"] {
        assert!(import_link(&format!("{base}&contentpaddingaddition={suffix}")).is_err());
    }
}
