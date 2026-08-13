use super::*;

#[test]
fn validates_dns_security_boundary_and_redacts_doh_url() {
    let parsed = EngineConfig::parse(
        r#"{
                "schema_version":1,
                "outbound":{
                    "type":"vless",
                    "server":"example.com",
                    "port":443,
                    "uuid":"d0cf0001-0000-4000-8000-000000000000"
                },
                "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
                "dns":{
                    "advertise":"10.77.0.1",
                    "mode":"fake_ip",
                    "route":"primary",
                    "upstreams":[{
                        "type":"doh",
                        "url":"https://resolver.example/dns-query?token=do-not-log"
                    }]
                }
            }"#,
    )
    .unwrap();
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("do-not-log"));
    assert!(debug.contains("REDACTED"));

    for invalid_dns in [
        r#"{"advertise":"not-an-ip"}"#,
        r#"{"upstreams":[{"type":"doh","url":"http://resolver.example/dns-query"}]}"#,
        r#"{"upstreams":[{"type":"doh","url":"https://user@resolver.example/dns-query"}]}"#,
        r#"{"upstreams":[{"type":"doh","url":"https://resolver.example/dns-query#fragment"}]}"#,
        r#"{"fake_ipv4_pool":"198.18.0.0/31"}"#,
        r#"{"upstream":"1.1.1.1","upstreams":[{"type":"udp","address":"8.8.8.8"}]}"#,
        r#"{"upstreams":[{"type":"udp","address":"1.1.1.1","unknown":true}]}"#,
    ] {
        let json = format!(
            r#"{{"schema_version":1,"outbound":{{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"}},"tun":{{"mtu":1400,"ipv4":"10.0.0.1"}},"dns":{invalid_dns}}}"#
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "invalid DNS config was accepted: {invalid_dns}"
        );
    }
}

#[test]
fn fake_ip_pools_cover_the_configured_cache_capacity() {
    let defaults = DnsConfig::default();
    assert_eq!(defaults.fake_ipv6_pool.to_string(), "fc00::/18");
    assert!(fake_ipv4_capacity(defaults.fake_ipv4_pool) >= defaults.cache_size as u128);
    assert!(fake_ipv6_capacity(defaults.fake_ipv6_pool) >= defaults.cache_size as u128);

    let too_small_v4 = DnsConfig {
        cache_size: 256,
        fake_ipv4_pool: "198.18.0.0/24".parse().unwrap(),
        ..DnsConfig::default()
    };
    assert!(matches!(
        too_small_v4.validate(),
        Err(ConfigError::Invalid(message)) if message.contains("dns.cache_size")
    ));

    let too_small_v6 = DnsConfig {
        cache_size: 256,
        fake_ipv6_pool: "fd00::/120".parse().unwrap(),
        ..DnsConfig::default()
    };
    assert!(matches!(
        too_small_v6.validate(),
        Err(ConfigError::Invalid(message)) if message.contains("dns.cache_size")
    ));
}

#[test]
fn validates_named_outbounds_and_route_references() {
    let parsed = EngineConfig::parse(
        r#"{
                "schema_version":1,
                "outbound":{
                    "type":"vless",
                    "server":"primary.example",
                    "port":443,
                    "uuid":"d0cf0001-0000-4000-8000-000000000000"
                },
                "outbounds":[
                    {
                        "id":"backup",
                        "outbound":{
                            "type":"shadowsocks",
                            "server":"backup.example",
                            "port":8388,
                            "method":"aes-128-gcm",
                            "password":"backup-secret"
                        }
                    },
                    {
                        "id":"tor",
                        "outbound":{
                            "type":"tor",
                            "state_dir":"/state",
                            "cache_dir":"/cache"
                        }
                    }
                ],
                "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
                "dns":{"route":"tor","mode":"fake_ip"},
                "routes":[
                    {
                        "domain_suffixes":[".backup.example"],
                        "action":{"type":"outbound","id":"backup"}
                    },
                    {
                        "domain_suffixes":[".onion"],
                        "action":{"type":"tor"}
                    }
                ]
            }"#,
    )
    .unwrap();
    assert_eq!(parsed.outbounds.len(), 2);
    assert!(!format!("{parsed:?}").contains("backup-secret"));

    for invalid_outbounds in [
        r#""outbounds":[{"id":"UPPER","outbound":{"type":"shadowsocks","server":"s","port":1,"method":"aes-128-gcm","password":"p"}}]"#,
        r#""outbounds":[{"id":"default","outbound":{"type":"shadowsocks","server":"s","port":1,"method":"aes-128-gcm","password":"p"}}]"#,
        r#""outbounds":[{"id":"same","outbound":{"type":"shadowsocks","server":"s","port":1,"method":"aes-128-gcm","password":"p"}},{"id":"same","outbound":{"type":"shadowsocks","server":"s","port":2,"method":"aes-128-gcm","password":"p"}}]"#,
        r#""outbounds":[{"id":"tor","outbound":{"type":"shadowsocks","server":"s","port":1,"method":"aes-128-gcm","password":"p"}}]"#,
        r#""routes":[{"action":{"type":"outbound","id":"missing"}}]"#,
        r#""routes":[{"action":{"type":"tor"}}]"#,
        r#""dns":{"route":"tor"}"#,
    ] {
        let json = format!(
            r#"{{"schema_version":1,"outbound":{{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"}},"tun":{{"mtu":1400,"ipv4":"10.0.0.1"}},{invalid_outbounds}}}"#
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "invalid outbound config was accepted: {invalid_outbounds}"
        );
    }
}

#[test]
fn continuity_defaults_to_the_behaviour_the_core_already_had() {
    let policy = PolicyConfig::parse(r#"{"traffic":{}}"#).unwrap();
    let continuity = policy.traffic.continuity;

    assert_eq!(continuity, ContinuityConfig::default());
    assert!(continuity.seamless_reconnect);
    assert!(continuity.seamless_failover);
    assert!(continuity.seamless_network_switch);
    assert!(continuity.split_tunnel_on_vpn_failure);
    // An all-seamless core never has anything to confirm, so the runtime
    // can skip the pause machinery entirely on the default configuration.
    assert!(!continuity.requires_confirmation());
}

#[test]
fn each_continuity_flag_is_separately_switchable() {
    for field in [
        "seamless_reconnect",
        "seamless_failover",
        "seamless_network_switch",
        "split_tunnel_on_vpn_failure",
    ] {
        let policy = PolicyConfig::parse(&format!(
            r#"{{"traffic":{{"continuity":{{"{field}":false}}}}}}"#
        ))
        .unwrap_or_else(|error| panic!("{field} should parse: {error}"));
        let continuity = policy.traffic.continuity;
        assert!(
            continuity.requires_confirmation(),
            "{field} off must require a confirmation"
        );
    }

    // A typo must not silently leave the core seamless: the app finds out
    // by a refused reload, not by a preference that quietly did nothing.
    assert!(
        PolicyConfig::parse(r#"{"traffic":{"continuity":{"seamless_reconect":false}}}"#).is_err()
    );
}

#[test]
fn a_confirmation_timeout_is_either_indefinite_or_a_usable_duration() {
    let indefinite =
        PolicyConfig::parse(r#"{"traffic":{"continuity":{"confirmation_timeout_ms":0}}}"#).unwrap();
    assert_eq!(indefinite.traffic.continuity.confirmation_timeout_ms, 0);

    // Half a second is not a dialog anyone can answer, and an hour is the
    // point past which a paused engine is just a leak of descriptors.
    assert!(
        PolicyConfig::parse(r#"{"traffic":{"continuity":{"confirmation_timeout_ms":500}}}"#)
            .is_err()
    );
    assert!(
        PolicyConfig::parse(r#"{"traffic":{"continuity":{"confirmation_timeout_ms":3600001}}}"#)
            .is_err()
    );
}

/// A hold waits, and there is no setting that makes it do anything else.
#[test]
fn a_hold_waits_by_default_and_nothing_configures_it_into_a_stop() {
    let config = ContinuityConfig::default();
    assert_eq!(config.confirmation_timeout_ms, 0);

    // A deadline is still settable. All it buys is being told the pause has
    // gone stale.
    let with_deadline =
        PolicyConfig::parse(r#"{"traffic":{"continuity":{"confirmation_timeout_ms":60000}}}"#)
            .unwrap();
    assert_eq!(
        with_deadline.traffic.continuity.confirmation_timeout_ms,
        60_000
    );
}

/// The variant that ended a hold by tearing the tunnel down is gone, and
/// the config that asks for it has to *fail*.
///
/// This is the whole point of removing it rather than defaulting it away.
/// A config carrying `stop_engine_leaving_network_open` was written by
/// someone who wanted the engine stopped on a timer; accepting that config
/// and then not stopping would be the same class of lie as stopping
/// silently — the app would believe it had a kill switch it does not have.
/// `deny_unknown_fields` on `ContinuityConfig` is what turns "no longer
/// implemented" into "refused at the door", so this test also pins that
/// attribute in place: drop it and the assertion below fails.
#[test]
fn a_policy_that_still_asks_the_deadline_to_stop_the_engine_is_refused() {
    for value in [
        "stop_engine_leaving_network_open",
        // Also the harmless one. The field is gone, not narrowed to a
        // single value, because a field with one legal value is an
        // invitation to believe there is another.
        "keep_blocking",
    ] {
        let error = PolicyConfig::parse(&format!(
            r#"{{"traffic":{{"continuity":{{"confirmation_timeout_action":"{value}"}}}}}}"#
        ))
        .expect_err("confirmation_timeout_action must not parse at all");
        let message = error.to_string();
        assert!(
            message.contains("confirmation_timeout_action"),
            "the refusal has to name the field the app has to remove, got: {message}"
        );
    }

    // And the same for a whole policy that is otherwise valid: the presence
    // of the field is the failure, not some other part of the document.
    assert!(
        PolicyConfig::parse(
            r#"{"traffic":{"continuity":{"seamless_reconnect":false,
                    "confirmation_timeout_ms":60000,
                    "confirmation_timeout_action":"keep_blocking"}}}"#
        )
        .is_err()
    );
    assert!(
        PolicyConfig::parse(
            r#"{"traffic":{"continuity":{"seamless_reconnect":false,
                    "confirmation_timeout_ms":60000}}}"#
        )
        .is_ok(),
        "the same policy without that field is exactly what an app should send"
    );
}

#[test]
fn vision_is_accepted_only_in_the_shape_it_actually_runs_in() {
    let vless = |flow: Option<&str>, tls: &str, transport: &str| {
        let flow = flow
            .map(|flow| format!(r#""flow":"{flow}","#))
            .unwrap_or_default();
        OutboundConfig::Vless(
            serde_json::from_str(&format!(
                r#"{{"server":"example.com","port":443,
                        "uuid":"d0cf0001-0000-4000-8000-000000000000",
                        {flow}"packet_encoding":"xudp",
                        "transport":{transport},"tls":{tls}}}"#
            ))
            .expect("fixture must parse"),
        )
    };
    const TLS13: &str = r#"{"enabled":true}"#;
    const RAW: &str = r#"{"type":"raw"}"#;
    const WEBSOCKET: &str = r#"{"type":"websocket","path":"/x"}"#;

    vless(Some(VLESS_FLOW_VISION), TLS13, RAW)
        .validate()
        .expect("Vision over raw TLS is the shape the implementation has");
    assert!(
        vless(Some("xtls-rprx-origin"), TLS13, RAW)
            .validate()
            .is_err(),
        "a flow we do not frame must not be advertised to the server"
    );
    assert!(
        vless(Some(VLESS_FLOW_VISION), TLS13, WEBSOCKET)
            .validate()
            .is_err(),
        "Vision has no defined shape over a WebSocket carrier"
    );
    assert!(
        vless(
            Some(VLESS_FLOW_VISION),
            r#"{"enabled":true,"max_version":"1.2"}"#,
            RAW
        )
        .validate()
        .is_err(),
        "the handover swaps outer 1.3 records for inner ones; 1.2 cannot hide it"
    );
    assert!(
        vless(Some(VLESS_FLOW_VISION), r#"{"enabled":false}"#, RAW)
            .validate()
            .is_err(),
        "there is nothing to hand over without an outer record layer"
    );
    // Without a flow none of the above applies.
    vless(None, TLS13, WEBSOCKET)
        .validate()
        .expect("plain VLESS keeps every carrier it had");
}

#[test]
fn parses_reloadable_policy_with_revision_guard() {
    let policy = PolicyConfig::parse(
        r#"{
                "expected_revision":7,
                "dns":{"route":"direct","upstreams":[{"type":"udp","address":"1.1.1.1"}]},
                "routes":[{
                    "uid":10123,
                    "package":"com.example.app",
                    "action":{"type":"outbound","id":"backup"}
                }]
            }"#,
    )
    .unwrap();
    assert_eq!(policy.expected_revision, Some(7));
    assert_eq!(policy.routes[0].uid, Some(10_123));

    assert!(
        PolicyConfig::parse(r#"{"routes":[{"package":"","action":{"type":"direct"}}]}"#).is_err()
    );
    assert!(PolicyConfig::parse(r#"{"unknown":true}"#).is_err());
    assert!(
        PolicyConfig::parse(
            r#"{"routes":[{"domain_suffixes":["bad domain"],"action":{"type":"direct"}}]}"#
        )
        .is_err()
    );
    assert!(PolicyConfig::parse(&" ".repeat(MAX_POLICY_CONFIG_BYTES + 1)).is_err());
    assert!(EngineConfig::parse(&" ".repeat(MAX_ENGINE_CONFIG_BYTES + 1)).is_err());
}

#[test]
fn anytls_is_bounded_and_its_password_is_redacted() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"anytls",
                "server":"edge.example",
                "port":443,
                "password":"outer-anytls-secret",
                "min_idle_session":2
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    let OutboundConfig::AnyTls(config) = &parsed.outbound else {
        panic!("profile must be AnyTLS");
    };
    assert!(config.tls.enabled);
    assert_eq!(config.min_idle_session, 2);
    assert!(!format!("{parsed:?}").contains("outer-anytls-secret"));

    assert!(
        EngineConfig::parse(&json.replace("\"min_idle_session\":2", "\"min_idle_session\":33"))
            .is_err()
    );
    assert!(
        EngineConfig::parse(&json.replace(
            "\"min_idle_session\":2",
            "\"min_idle_session\":2,\"tls\":{\"enabled\":false}"
        ))
        .is_err()
    );
}

#[test]
fn shadowtls_requires_strict_v3_and_an_explicit_secret_inner_protocol() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"shadowtls",
                "server":"front.example",
                "port":443,
                "password":"outer-shadowtls-secret",
                "inner":{
                    "type":"shadowsocks",
                    "method":"2022-blake3-aes-128-gcm",
                    "password":"inner-shadowsocks-secret"
                }
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    let OutboundConfig::ShadowTls(config) = &parsed.outbound else {
        panic!("profile must be ShadowTLS");
    };
    assert_eq!(config.tls.min_version, Some(TlsVersion::Tls13));
    assert_eq!(config.tls.max_version, Some(TlsVersion::Tls13));
    let rendered = format!("{parsed:?}");
    assert!(!rendered.contains("outer-shadowtls-secret"));
    assert!(!rendered.contains("inner-shadowsocks-secret"));

    let tls12 = json.replace(
            "\"password\":\"outer-shadowtls-secret\",",
            "\"password\":\"outer-shadowtls-secret\",\"tls\":{\"enabled\":true,\"min_version\":\"1.2\"},",
        );
    assert!(EngineConfig::parse(&tls12).is_err());
    let h2 = json.replace(
            "\"password\":\"outer-shadowtls-secret\",",
            "\"password\":\"outer-shadowtls-secret\",\"tls\":{\"enabled\":true,\"min_version\":\"1.3\",\"max_version\":\"1.3\",\"alpn\":[\"h2\"]},",
        );
    assert!(EngineConfig::parse(&h2).is_err());
    let missing_inner = json.replace("\"inner\":{", "\"wrong_inner\":{");
    assert!(EngineConfig::parse(&missing_inner).is_err());
}

#[test]
fn tuic_v5_is_typed_redacted_and_rejects_replayable_early_data() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"tuic",
                "server":"tuic.example",
                "port":443,
                "uuid":"2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365",
                "password":"tuic-password-secret",
                "congestion_control":"new_reno",
                "udp_relay_mode":"quic",
                "tls":{"enabled":true,"server_name":"tuic.example","alpn":["h3"]}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    let OutboundConfig::Tuic(config) = &parsed.outbound else {
        panic!("profile must be TUIC");
    };
    assert_eq!(config.congestion_control, TuicCongestionControl::NewReno);
    assert_eq!(config.udp_relay_mode, TuicUdpRelayMode::Quic);
    assert!(!config.zero_rtt_handshake);
    assert!(!format!("{parsed:?}").contains("tuic-password-secret"));

    let replayable = json.replace(
        "\"udp_relay_mode\":\"quic\",",
        "\"udp_relay_mode\":\"quic\",\"zero_rtt_handshake\":true,",
    );
    assert!(matches!(
        EngineConfig::parse(&replayable),
        Err(ConfigError::Invalid(message)) if message.contains("zero_rtt")
    ));
    let unsupported_bbr = json.replace("\"new_reno\"", "\"bbr\"");
    assert!(EngineConfig::parse(&unsupported_bbr).is_err());
}

#[test]
fn ech_is_typed_and_survives_a_round_trip() {
    let json = trojan_with_tls(&format!(
        "{{\"enabled\":true,\"server_name\":\"hidden.example\",\"ech\":{{\"mode\":\"required\",\"config_list\":\"{ECH_CONFIG_LIST}\"}}}}"
    ));
    let parsed = EngineConfig::parse(&json).unwrap();
    let OutboundConfig::Trojan(config) = &parsed.outbound else {
        panic!("profile must be Trojan");
    };
    assert_eq!(
        config.tls.ech,
        Some(EchConfig::Required {
            config_list: ECH_CONFIG_LIST.to_owned()
        })
    );
    // Re-serialising and re-parsing has to produce the same profile: the
    // app round-trips configs through this type, and an `ech` block that
    // survives only in one direction is an ECH setting that silently turns
    // itself off on the next save.
    let again = EngineConfig::parse(&serde_json::to_string(&parsed).unwrap()).unwrap();
    assert_eq!(again, parsed);

    let grease = trojan_with_tls("{\"enabled\":true,\"ech\":{\"mode\":\"grease_plaintext_sni\"}}");
    let OutboundConfig::Trojan(config) = &EngineConfig::parse(&grease).unwrap().outbound else {
        panic!("profile must be Trojan");
    };
    assert_eq!(config.tls.ech, Some(EchConfig::GreasePlaintextSni));
    assert_eq!(config.tls.ech.as_ref().unwrap().config_list(), None);
}

#[test]
fn ech_refuses_what_it_cannot_use() {
    let invalid = |tls: &str| {
        let json = trojan_with_tls(tls);
        match EngineConfig::parse(&json) {
            Err(ConfigError::Invalid(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    };

    // No silent third mode. `optional` describes a
    // plaintext-SNI fallback, and a profile asking for it must be told it
    // does not exist rather than served `required` or `grease`.
    assert!(
        EngineConfig::parse(&trojan_with_tls(
            "{\"enabled\":true,\"ech\":{\"mode\":\"optional\"}}"
        ))
        .is_err()
    );
    assert!(
        invalid(
            "{\"enabled\":true,\"ech\":{\"mode\":\"required\",\"config_list\":\"not base64!!\"}}"
        )
        .contains("base64")
    );
    assert!(
        invalid("{\"enabled\":true,\"ech\":{\"mode\":\"required\",\"config_list\":\"\"}}")
            .contains("must not be empty")
    );
    assert!(
        invalid("{\"enabled\":true,\"ech\":{\"mode\":\"required\",\"config_list\":\"AA==\"}}")
            .contains("too short")
    );
    // TLS off plus an ECH block is a profile that believes it is hiding an
    // SNI it never sends. Asked on VLESS, because Trojan refuses a
    // TLS-less profile one check earlier and would hide this one.
    let plaintext_vless = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless",
                "server":"vless.example",
                "port":443,
                "uuid":"2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365",
                "tls":{"enabled":false,"ech":{"mode":"grease_plaintext_sni"}}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(matches!(
        EngineConfig::parse(plaintext_vless),
        Err(ConfigError::Invalid(message)) if message.contains("tls.enabled=true")
    ));
    assert!(
        invalid(
            "{\"enabled\":true,\"max_version\":\"1.2\",\"ech\":{\"mode\":\"grease_plaintext_sni\"}}"
        )
        .contains("TLS 1.3")
    );
}

#[test]
fn ech_is_refused_where_the_acceptance_check_cannot_run() {
    // QUIC: the connection is a quinn connection, not a rustls one, so
    // "the server accepted ECH" cannot be asserted after the handshake.
    let tuic = r#"{
            "schema_version":1,
            "outbound":{
                "type":"tuic",
                "server":"tuic.example",
                "port":443,
                "uuid":"2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365",
                "password":"tuic-password-secret",
                "tls":{"enabled":true,"ech":{"mode":"grease_plaintext_sni"}}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(matches!(
        EngineConfig::parse(tuic),
        Err(ConfigError::Invalid(message)) if message.contains("QUIC")
    ));

    let hysteria2 = r#"{
            "schema_version":1,
            "outbound":{
                "type":"hysteria2",
                "server":"hy2.example",
                "port":443,
                "password":"hysteria2-password-secret",
                "tls":{"enabled":true,"ech":{"mode":"grease_plaintext_sni"}}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(matches!(
        EngineConfig::parse(hysteria2),
        Err(ConfigError::Invalid(message)) if message.contains("QUIC")
    ));

    // ShadowTLS: its v3 signature rewrites four bytes of the session id
    // after rustls has sealed the inner hello against them.
    let shadowtls = format!(
        r#"{{
            "schema_version":1,
            "outbound":{{
                "type":"shadowtls",
                "server":"front.example",
                "port":443,
                "password":"outer-shadowtls-secret",
                "tls":{{"enabled":true,"min_version":"1.3","max_version":"1.3","ech":{{"mode":"required","config_list":"{ECH_CONFIG_LIST}"}}}},
                "inner":{{
                    "type":"shadowsocks",
                    "method":"2022-blake3-aes-128-gcm",
                    "password":"inner-shadowsocks-secret"
                }}
            }},
            "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
        }}"#
    );
    assert!(matches!(
        EngineConfig::parse(&shadowtls),
        Err(ConfigError::Invalid(message)) if message.contains("ShadowTLS")
    ));
}
