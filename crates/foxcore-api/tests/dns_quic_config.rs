use foxcore_api::EngineConfig;
use serde_json::{Value, json};

fn profile(upstream: Value, bootstrap: bool) -> Value {
    let mut value = json!({
        "schema_version":1,
        "outbound":{"type":"vless","server":"group.example","port":443,
            "uuid":"d0cf0001-0000-4000-8000-000000000000"},
        "tun":{"mtu":1400,"ipv4":"10.0.0.2"}
    });
    if bootstrap {
        value["bootstrap_dns"] = json!({"domains":["group.example"],"upstreams":[upstream]});
    } else {
        value["dns"] = json!({"mode":"real_ip","route":"primary","upstreams":[upstream]});
    }
    value
}

#[test]
fn ordinary_quic_dns_keeps_the_requested_protocol_and_tls_identity() {
    for upstream in [
        json!({"type":"doq","host":"dns.example","port":853,"server_ip":"192.0.2.53",
            "insecure":false,"pinned_spki_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
        json!({"type":"doh3","url":"https://dns.example:18443/custom-dns","server_ip":"2001:db8::53",
            "insecure":false,"pinned_spki_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
    ] {
        let config = EngineConfig::parse(&profile(upstream.clone(), false).to_string())
            .expect("explicit DoQ/DoH3 must be represented rather than discarded or downgraded");
        assert_eq!(
            serde_json::to_value(&config.dns.upstreams[0]).unwrap(),
            upstream
        );
    }
}

#[test]
fn scoped_bootstrap_accepts_verified_doq_and_doh3() {
    for upstream in [
        json!({"type":"doq","host":"dns.example","port":853,"server_ip":"192.0.2.53","insecure":false}),
        json!({"type":"doh3","url":"https://dns.example/dns-query","server_ip":"2001:db8::53","insecure":false}),
    ] {
        let config = EngineConfig::parse(&profile(upstream.clone(), true).to_string()).expect(
            "scoped encrypted QUIC bootstrap with an explicit literal seed must be supported",
        );
        assert_eq!(
            serde_json::to_value(&config.bootstrap_dns.unwrap().upstreams[0]).unwrap(),
            upstream
        );
    }
}

#[test]
fn quic_dns_refuses_invalid_ports_urls_and_unsafe_bootstrap() {
    for upstream in [
        json!({"type":"doq","host":"dns.example","port":0}),
        json!({"type":"doq","host":"dns.example","port":53}),
        json!({"type":"doq","host":"dns.example","port":853,"pinned_spki_sha256":"bad"}),
        json!({"type":"doh3","url":"http://dns.example/dns-query"}),
        json!({"type":"doh3","url":"https://user:password@dns.example/dns-query"}),
        json!({"type":"doh3","url":"https://dns.example/dns-query#fragment"}),
        json!({"type":"doh3","url":"https://dns.example:0/dns-query"}),
    ] {
        assert!(EngineConfig::parse(&profile(upstream, false).to_string()).is_err());
    }
    for upstream in [
        json!({"type":"doq","host":"dns.example","port":853}),
        json!({"type":"doq","host":"dns.example","port":853,"server_ip":"192.0.2.53","insecure":true}),
        json!({"type":"doq","host":"dns.example","port":853,"server_ip":"224.0.0.1"}),
        json!({"type":"doh3","url":"https://dns.example/dns-query"}),
        json!({"type":"doh3","url":"https://dns.example/dns-query?token=value","server_ip":"192.0.2.53"}),
        json!({"type":"doh3","url":"https://dns.example/dns-query","server_ip":"192.0.2.53","insecure":true}),
    ] {
        assert!(EngineConfig::parse(&profile(upstream, true).to_string()).is_err());
    }
}
