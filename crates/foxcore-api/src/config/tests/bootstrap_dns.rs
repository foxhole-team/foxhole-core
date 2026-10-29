use super::*;

fn profile(policy: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "outbound": {"type":"vless", "server":"group.example", "port":443,
            "uuid":"d0cf0001-0000-4000-8000-000000000000"},
        "tun": {"mtu":1400,"ipv4":"10.0.0.1"},
        "bootstrap_dns": policy
    })
}

fn policy() -> serde_json::Value {
    serde_json::json!({"domains":["GROUP.example."],"upstreams":[{
        "type":"doh","url":"https://dns.example:18443/dns-query","server_ip":"192.0.2.53"
    }]})
}

#[test]
fn scoped_bootstrap_retains_the_endpoint_and_tls_identity() {
    for upstream in [
        serde_json::json!({"type":"udp","address":"192.0.2.53:53"}),
        serde_json::json!({"type":"tcp","address":"[2001:db8::53]:5353"}),
        serde_json::json!({"type":"dot","host":"dns.example","port":1853,"server_ip":"192.0.2.53","insecure":false}),
        serde_json::json!({"type":"doh","url":"https://dns.example:18443/dns-query","server_ip":"2001:db8::53","insecure":false}),
    ] {
        let mut policy = policy();
        policy["upstreams"] = serde_json::json!([upstream.clone()]);
        let mut document = profile(policy);
        document["outbound"]["tls"] =
            serde_json::json!({"enabled":true,"server_name":"tls.example","insecure":false});
        let config = EngineConfig::parse(&document.to_string()).unwrap();
        let bootstrap = config.bootstrap_dns.unwrap();
        assert_eq!(bootstrap.timeout_ms, 3000);
        assert_eq!(bootstrap.max_candidates, 8);
        assert!(bootstrap.matches("group.example"));
        assert!(!bootstrap.matches("other.group.example"));
        assert_eq!(
            serde_json::to_value(&bootstrap.upstreams[0]).unwrap(),
            upstream
        );
        let OutboundConfig::Vless(outbound) = config.outbound else {
            panic!("outbound changed")
        };
        assert_eq!(outbound.server, "group.example");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.server_ip, None);
        assert_eq!(outbound.tls.server_name.as_deref(), Some("tls.example"));
    }
}

#[test]
fn bootstrap_refuses_recursion_insecure_identity_and_unscoped_names() {
    let base = policy();
    let mut negatives = Vec::new();
    for domains in [
        serde_json::json!([]),
        serde_json::json!(["*.example"]),
        serde_json::json!(["other.example"]),
        serde_json::json!(["group.example", "GROUP.example."]),
    ] {
        let mut value = base.clone();
        value["domains"] = domains;
        negatives.push(value);
    }
    for upstream in [
        serde_json::json!({"type":"udp","address":"dns.example:53"}),
        serde_json::json!({"type":"udp","address":"255.255.255.255:53"}),
        serde_json::json!({"type":"tcp","address":"[fe80::1%7]:53"}),
        serde_json::json!({"type":"dot","host":"dns.example","port":1853,"server_ip":"255.255.255.255"}),
        serde_json::json!({"type":"dot","host":"dns.example","port":1853}),
        serde_json::json!({"type":"dot","host":"dns.example","port":1853,"server_ip":"192.0.2.53","insecure":true}),
        serde_json::json!({"type":"doh","url":"https://dns.example/dns-query?token=secret","server_ip":"192.0.2.53"}),
        serde_json::json!({"type":"doq","host":"dns.example","port":53,"server_ip":"192.0.2.53"}),
    ] {
        let mut value = base.clone();
        value["upstreams"] = serde_json::json!([upstream]);
        negatives.push(value);
    }
    for value in negatives {
        assert!(EngineConfig::parse(&profile(value).to_string()).is_err());
    }
    let mut pinned = profile(base);
    pinned["outbound"]["server_ip"] = serde_json::json!("192.0.2.2");
    assert!(EngineConfig::parse(&pinned.to_string()).is_err());
}

#[test]
fn bootstrap_limits_are_enforced_and_legacy_profiles_remain_valid() {
    let mut legacy = profile(policy());
    legacy.as_object_mut().unwrap().remove("bootstrap_dns");
    assert!(
        EngineConfig::parse(&legacy.to_string())
            .unwrap()
            .bootstrap_dns
            .is_none()
    );
    for (field, value) in [
        ("timeout_ms", 499),
        ("timeout_ms", 10001),
        ("max_candidates", 0),
        ("max_candidates", 9),
    ] {
        let mut value_policy = policy();
        value_policy[field] = serde_json::json!(value);
        assert!(EngineConfig::parse(&profile(value_policy).to_string()).is_err());
    }
    let mut value = policy();
    value["upstreams"] = serde_json::json!([]);
    assert!(EngineConfig::parse(&profile(value).to_string()).is_err());
}

#[test]
fn mapped_ipv6_cannot_bypass_resolver_ip_restrictions_or_zero_scope_rejection() {
    for ip in [
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ] {
        for upstream in [
            serde_json::json!({"type":"udp","address":format!("[{ip}]:53")}),
            serde_json::json!({"type":"tcp","address":format!("[{ip}]:53")}),
            serde_json::json!({"type":"dot","host":"dns.example","port":1853,"server_ip":ip}),
            serde_json::json!({"type":"doh","url":"https://dns.example:18443/dns-query","server_ip":ip}),
        ] {
            let mut value = policy();
            value["upstreams"] = serde_json::json!([upstream]);
            assert!(EngineConfig::parse(&profile(value).to_string()).is_err());
        }
    }
    for kind in ["udp", "tcp"] {
        let mut value = policy();
        value["upstreams"] = serde_json::json!([{"type":kind,"address":"[::1%0]:53"}]);
        assert!(EngineConfig::parse(&profile(value).to_string()).is_err());
    }
}
