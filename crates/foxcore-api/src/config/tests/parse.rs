use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::net::IpAddr;

#[test]
fn parses_legacy_vless_config_with_new_defaults() {
    let json = r#"{
            "schema_version": 1,
            "outbound": {
                "type": "vless",
                "server": "vpn.example.com",
                "port": 8443,
                "uuid": "d0cf0001-0000-4000-8000-000000000000"
            },
            "tun": { "mtu": 1500, "ipv4": "172.19.0.1" }
        }"#;
    let config = EngineConfig::parse(json).unwrap();
    // Spelled out rather than compared against the default function: the
    // point of the test is that a config which omits the field gets a
    // known number, and a change to that number should have to be typed
    // here too.
    assert_eq!(config.runtime.worker_threads, 4);
    assert!(matches!(config.outbound, OutboundConfig::Vless(_)));
}

#[test]
fn parses_a_redacted_authenticated_control_proxy() {
    let json = r#"{
            "schema_version": 1,
            "outbound": {
                "type": "vless",
                "server": "edge.example",
                "port": 443,
                "uuid": "d0cf0001-0000-4000-8000-000000000000"
            },
            "tun": { "mtu": 1500, "ipv4": "172.19.0.1" },
            "runtime": {
                "control_proxy": {
                    "http_port": 10809,
                    "username": "foxhole-runtime",
                    "password": "process-local-secret"
                }
            }
        }"#;

    let config = EngineConfig::parse(json).expect("control proxy should parse");
    let control = config
        .runtime
        .control_proxy
        .as_ref()
        .expect("control proxy should be retained");
    assert_eq!(control.http_port, 10_809);
    assert_eq!(control.username, "foxhole-runtime");
    assert_eq!(control.password.expose(), "process-local-secret");
    assert!(!format!("{:?}", config.runtime).contains("process-local-secret"));
}

#[test]
fn control_proxy_address_is_not_configurable() {
    let json = r#"{
            "schema_version": 1,
            "outbound": { "type": "direct" },
            "tun": { "mtu": 1500, "ipv4": "172.19.0.1" },
            "runtime": {
                "local_guard": true,
                "control_proxy": {
                    "http_port": 10809,
                    "username": "foxhole-runtime",
                    "password": "process-local-secret",
                    "listen": "0.0.0.0"
                }
            }
        }"#;

    assert!(EngineConfig::parse(json).is_err());
}

#[test]
fn control_proxy_refuses_unusable_credentials_and_port() {
    for control_proxy in [
        r#"{"http_port":0,"username":"foxhole-runtime","password":"secret"}"#,
        r#"{"http_port":10809,"username":"foxhole:runtime","password":"secret"}"#,
        r#"{"http_port":10809,"username":"foxhole-runtime","password":""}"#,
    ] {
        let json = format!(
            r#"{{
                    "schema_version": 1,
                    "outbound": {{ "type": "direct" }},
                    "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
                    "runtime": {{
                        "local_guard": true,
                        "control_proxy": {control_proxy}
                    }}
                }}"#
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "unsafe control proxy must be refused"
        );
    }
}

/// Named loopback inbounds, with the two shapes a caller actually writes: an
/// ephemeral port and a fixed one.
#[test]
fn parses_named_loopback_inbounds_and_keeps_their_secrets_out_of_debug() {
    let json = r#"{
            "schema_version": 1,
            "outbound": { "type": "direct" },
            "tun": { "mtu": 1500, "ipv4": "172.19.0.1" },
            "runtime": {
                "local_guard": true,
                "loopback_inbounds": [
                    {
                        "name": "webapp.mastodon",
                        "username": "app-a",
                        "password": "per-app-secret-a",
                        "upstream": "tor"
                    },
                    {
                        "name": "webapp.docs",
                        "http_port": 18081,
                        "username": "app-b",
                        "password": "per-app-secret-b",
                        "upstream": "direct",
                        "max_sessions": 2
                    }
                ]
            }
        }"#;

    let config = EngineConfig::parse(json).expect("named loopback inbounds should parse");
    let inbounds = &config.runtime.loopback_inbounds;
    assert_eq!(inbounds.len(), 2);
    // An omitted port means "ask the kernel", which is the recommended form on a
    // device with no port registry.
    assert_eq!(inbounds[0].http_port, 0);
    assert_eq!(inbounds[0].upstream, LoopbackUpstream::Tor);
    assert_eq!(inbounds[0].max_sessions, 8);
    assert_eq!(inbounds[1].http_port, 18_081);
    assert_eq!(inbounds[1].upstream, LoopbackUpstream::Direct);
    assert_eq!(inbounds[1].max_sessions, 2);
    let rendered = format!("{:?}", config.runtime);
    assert!(!rendered.contains("per-app-secret-a"));
    assert!(!rendered.contains("per-app-secret-b"));
}

#[test]
fn anonymous_loopback_requires_explicit_consent_and_never_discards_credentials() {
    for (extra, accepted) in [
        ("", false),
        (",\"allow_anonymous\":true", true),
        (",\"allow_anonymous\":false", false),
        (",\"username\":\"u\",\"password\":\"p\"", true),
        (
            ",\"allow_anonymous\":true,\"username\":\"u\",\"password\":\"p\"",
            false,
        ),
        (",\"allow_anonymous\":true,\"username\":\"u\"", false),
    ] {
        let inbound: super::super::LoopbackInboundConfig = serde_json::from_str(&format!(
            r#"{{"name":"local","upstream":"profile"{extra}}}"#
        ))
        .unwrap();
        assert_eq!(inbound.validate().is_ok(), accepted, "{extra}");
    }
}

/// The bind address is absent from the schema, exactly as it is for the control
/// proxy. A loopback inbound that could be widened to the LAN would be the LAN
/// surface without the network confirmation that surface exists to require.
#[test]
fn a_loopback_inbound_address_is_not_configurable() {
    let json = r#"{
            "schema_version": 1,
            "outbound": { "type": "direct" },
            "tun": { "mtu": 1500, "ipv4": "172.19.0.1" },
            "runtime": {
                "local_guard": true,
                "loopback_inbounds": [
                    {
                        "name": "webapp.a",
                        "http_port": 18081,
                        "username": "app-a",
                        "password": "secret-a",
                        "upstream": "profile",
                        "listen": "0.0.0.0"
                    }
                ]
            }
        }"#;

    assert!(EngineConfig::parse(json).is_err());
}

/// Every collision is refused, and each one for a reason of its own.
///
/// The credential rules are the ones that matter most: these listeners all sit
/// on `127.0.0.1`, where every app on the device can reach every port, so a
/// shared username or a shared password is a shared upstream — the web app on
/// the profile could use the port labelled Tor.
#[test]
fn loopback_inbounds_refuse_every_collision_that_would_merge_two_applications() {
    let entry = |name: &str, port: u16, user: &str, password: &str| {
        format!(
            r#"{{"name":"{name}","http_port":{port},"username":"{user}",
                 "password":"{password}","upstream":"profile"}}"#
        )
    };
    let cases = [
        // Same name twice: the app could no longer tell which port is which.
        vec![entry("a", 0, "u1", "p1"), entry("a", 0, "u2", "p2")],
        // Same fixed port: one of the two would not bind at all.
        vec![entry("a", 18081, "u1", "p1"), entry("b", 18081, "u2", "p2")],
        // Same username, and same password: either one makes the credential a
        // shared key to both listeners.
        vec![entry("a", 0, "shared", "p1"), entry("b", 0, "shared", "p2")],
        vec![entry("a", 0, "u1", "shared"), entry("b", 0, "u2", "shared")],
        // A name outside the identity charset. `:` in particular is the
        // separator the runtime namespaces its own components with.
        vec![entry("runtime:control-proxy", 0, "u1", "p1")],
        // A username with a colon cannot be encoded in a Basic credential.
        vec![entry("a", 0, "u:1", "p1")],
        // An empty password is an open proxy with extra steps.
        vec![entry("a", 0, "u1", "")],
    ];

    for case in cases {
        let json = format!(
            r#"{{
                "schema_version": 1,
                "outbound": {{ "type": "direct" }},
                "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
                "runtime": {{ "local_guard": true, "loopback_inbounds": [{}] }}
            }}"#,
            case.join(",")
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "colliding or unusable loopback inbounds must be refused: {case:?}"
        );
    }
}

/// A named inbound must not be able to take the control proxy's port or its
/// credentials either. They are the same kind of listener on the same interface.
#[test]
fn a_loopback_inbound_never_collides_with_the_control_proxy() {
    for inbound in [
        r#"{"name":"a","http_port":10809,"username":"u1","password":"p1","upstream":"profile"}"#,
        r#"{"name":"a","http_port":0,"username":"foxhole-runtime","password":"p1","upstream":"profile"}"#,
        r#"{"name":"a","http_port":0,"username":"u1","password":"process-local-secret","upstream":"profile"}"#,
    ] {
        let json = format!(
            r#"{{
                "schema_version": 1,
                "outbound": {{ "type": "direct" }},
                "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
                "runtime": {{
                    "local_guard": true,
                    "control_proxy": {{
                        "http_port": 10809,
                        "username": "foxhole-runtime",
                        "password": "process-local-secret"
                    }},
                    "loopback_inbounds": [{inbound}]
                }}
            }}"#
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "a named inbound must not shadow the control proxy: {inbound}"
        );
    }
}

/// The cap and the per-inbound session bound are both enforced in the schema,
/// so a profile that asks for too much is refused before anything binds.
#[test]
fn loopback_inbounds_are_bounded_in_count_and_in_sessions() {
    let entries = (0..=MAX_LOOPBACK_INBOUNDS)
        .map(|index| {
            format!(
                r#"{{"name":"a{index}","username":"u{index}","password":"p{index}",
                     "upstream":"profile"}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let too_many = format!(
        r#"{{
            "schema_version": 1,
            "outbound": {{ "type": "direct" }},
            "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
            "runtime": {{ "local_guard": true, "loopback_inbounds": [{entries}] }}
        }}"#
    );
    assert!(EngineConfig::parse(&too_many).is_err());

    for sessions in [0, u32::from(MAX_LOOPBACK_INBOUND_SESSIONS) + 1] {
        let json = format!(
            r#"{{
                "schema_version": 1,
                "outbound": {{ "type": "direct" }},
                "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
                "runtime": {{ "local_guard": true, "loopback_inbounds": [
                    {{"name":"a","username":"u","password":"p","upstream":"profile",
                      "max_sessions":{sessions}}}
                ]}}
            }}"#
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "max_sessions={sessions} is outside 1..={MAX_LOOPBACK_INBOUND_SESSIONS}"
        );
    }
}

/// The upstream vocabulary is closed. `auto`, `any` or a typo must not parse
/// into something that runs — an inbound whose route was guessed is the one
/// failure this feature cannot survive.
#[test]
fn a_loopback_inbound_upstream_is_one_of_exactly_three_words() {
    for upstream in ["profile", "tor", "direct"] {
        let json = format!(
            r#"{{
                "schema_version": 1,
                "outbound": {{ "type": "direct" }},
                "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
                "runtime": {{ "local_guard": true, "loopback_inbounds": [
                    {{"name":"a","username":"u","password":"p","upstream":"{upstream}"}}
                ]}}
            }}"#
        );
        let config =
            EngineConfig::parse(&json).unwrap_or_else(|error| panic!("{upstream}: {error}"));
        assert_eq!(
            config.runtime.loopback_inbounds[0].upstream.name(),
            upstream
        );
    }
    for upstream in ["auto", "vpn", "any", "Profile", ""] {
        let json = format!(
            r#"{{
                "schema_version": 1,
                "outbound": {{ "type": "direct" }},
                "tun": {{ "mtu": 1500, "ipv4": "172.19.0.1" }},
                "runtime": {{ "local_guard": true, "loopback_inbounds": [
                    {{"name":"a","username":"u","password":"p","upstream":"{upstream}"}}
                ]}}
            }}"#
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "'{upstream}' must not parse"
        );
    }
}

#[test]
fn parses_wireguard_outbound_with_typed_peer_settings() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"wireguard",
                "server":"edge.example","port":51820,
                "private_key":"ERERERERERERERERERERERERERERERERERERERERERE=",
                "peer_public_key":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
                "preshared_key":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
                "address":["10.8.0.2/32"],
                "allowed_ips":["0.0.0.0/0"],
                "mtu":1420,
                "persistent_keepalive_s":25
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let config = EngineConfig::parse(json).expect("wireguard outbound should parse");
    let OutboundConfig::Wireguard(wireguard) = config.outbound else {
        panic!("expected a wireguard outbound");
    };
    assert_eq!(wireguard.mtu, 1420);
    assert_eq!(wireguard.persistent_keepalive_s, Some(25));
    assert_eq!(wireguard.address.len(), 1);
}

#[test]
fn direct_primary_is_authorised_only_for_an_explicit_local_guard() {
    let direct = r#"{
            "schema_version":1,
            "outbound":{"type":"direct"},
            "tun":{"mtu":1400,"ipv4":"172.19.0.1"},
            "dns":{"mode":"real_ip","advertise":"172.19.0.2"},
            "runtime":{"local_guard":true}
        }"#;
    let parsed = EngineConfig::parse(direct).expect("an explicit local guard should parse");
    assert!(matches!(parsed.outbound, OutboundConfig::Direct(_)));
    assert!(parsed.runtime.local_guard);

    let unmarked = r#"{
            "schema_version":1,
            "outbound":{"type":"direct"},
            "tun":{"mtu":1400,"ipv4":"172.19.0.1"},
            "dns":{"mode":"real_ip","advertise":"172.19.0.2"}
        }"#;
    assert!(matches!(
        EngineConfig::parse(unmarked),
        Err(ConfigError::Invalid(message)) if message.contains("local_guard")
    ));

    let proxy_marked = direct.replace(
        r#"{"type":"direct"}"#,
        r#"{"type":"socks","server":"127.0.0.1","port":1080}"#,
    );
    assert!(matches!(
        EngineConfig::parse(&proxy_marked),
        Err(ConfigError::Invalid(message)) if message.contains("local_guard")
    ));
}

#[test]
fn accepts_a_bounded_outline_prefix_and_a_simple_obfs_carrier() {
    let prefixed = shadowsocks(r#","outline_prefix":[80,79,83,84,32]"#).unwrap();
    assert_eq!(prefixed.outline_prefix.as_deref(), Some(&b"POST "[..]));

    let obfuscated = shadowsocks(
            r#","udp":false,"obfs":{"mode":"http","host":"www.bing.com","uri":"/mail","method":"POST"}"#,
        )
        .unwrap();
    assert_eq!(
        obfuscated.obfs,
        Some(SimpleObfsConfig::Http {
            host: "www.bing.com".into(),
            uri: "/mail".into(),
            method: "POST".into(),
        })
    );
    // The two http fields have the defaults the reference plugin uses.
    let bare = shadowsocks(r#","udp":false,"obfs":{"mode":"http","host":"www.bing.com"}"#)
        .unwrap()
        .obfs;
    assert_eq!(
        bare,
        Some(SimpleObfsConfig::Http {
            host: "www.bing.com".into(),
            uri: "/".into(),
            method: "GET".into(),
        })
    );
}

#[test]
fn refuses_shadowsocks_carriers_that_contradict_each_other() {
    let refused = |extra: &str| {
        shadowsocks(extra)
            .expect_err(&format!("{extra} must be refused"))
            .to_string()
    };
    // Prefix bounds. Zero bytes is not "no prefix", and past 16 bytes the
    // salt stops being a salt.
    assert!(refused(r#","outline_prefix":[]"#).contains("must not be empty"));
    assert!(
        refused(r#","outline_prefix":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]"#)
            .contains("at most 16 bytes")
    );
    // A prefix disguises the first bytes of a raw connection. Under a
    // plugin those are the plugin's bytes, so the option means nothing and
    // is refused instead of being applied where it cannot be seen.
    assert!(
        refused(
            r#","udp":false,"outline_prefix":[80],"obfs":{"mode":"tls","host":"www.bing.com"}"#
        )
        .contains("no meaning under a plugin carrier")
    );
    assert!(
        refused(
            r#","udp":false,"outline_prefix":[80],"transport":{"type":"websocket","path":"/ws"}"#
        )
        .contains("no meaning under a plugin carrier")
    );
    // Two plugins on one connection is one plugin too many.
    assert!(
            refused(
                r#","udp":false,"obfs":{"mode":"tls","host":"www.bing.com"},"transport":{"type":"websocket","path":"/ws"}"#
            )
            .contains("mutually exclusive")
        );
    // simple-obfs never sees the datagram path.
    assert!(
        refused(r#","udp":true,"obfs":{"mode":"tls","host":"www.bing.com"}"#)
            .contains("carries TCP only")
    );
    // And its own fields are bounded like every other carrier's.
    assert!(refused(r#","udp":false,"obfs":{"mode":"http","host":"","uri":"/"}"#).contains("host"));
    assert!(
        refused(r#","udp":false,"obfs":{"mode":"http","host":"a.example","uri":"mail"}"#)
            .contains("path")
    );
    assert!(
        refused(r#","udp":false,"obfs":{"mode":"http","host":"a.example","method":"GET /x"}"#)
            .contains("HTTP token")
    );
    // An unknown mode is a closed enum away from becoming a silent default.
    assert!(shadowsocks(r#","udp":false,"obfs":{"mode":"quic","host":"a.example"}"#).is_err());
}

#[test]
fn parses_selector_with_inline_members() {
    let json = selector_json(
        &format!("[{SS_MEMBER_A},{SS_MEMBER_B}]"),
        r#","default":"node-b""#,
    );
    let config = EngineConfig::parse(&json).expect("selector outbound should parse");
    let OutboundConfig::Selector(selector) = config.outbound else {
        panic!("expected a selector outbound");
    };
    assert_eq!(selector.members.len(), 2);
    assert_eq!(selector.default.as_ref().unwrap().0, "node-b");
    assert_eq!(
        selector.member_timeout_ms(),
        DEFAULT_SELECTOR_MEMBER_TIMEOUT_MS
    );
}

#[test]
fn selector_default_must_name_a_member() {
    let json = selector_json(&format!("[{SS_MEMBER_A}]"), r#","default":"node-z""#);
    let error = EngineConfig::parse(&json).unwrap_err();
    assert!(
        error.to_string().contains("is not a member"),
        "unexpected error: {error}"
    );
}

#[test]
fn selector_rejects_an_empty_member_list() {
    let error = EngineConfig::parse(&selector_json("[]", "")).unwrap_err();
    assert!(
        error.to_string().contains("at least one member"),
        "unexpected error: {error}"
    );
}

#[test]
fn selector_rejects_duplicate_member_ids() {
    let json = selector_json(&format!("[{SS_MEMBER_A},{SS_MEMBER_A}]"), "");
    let error = EngineConfig::parse(&json).unwrap_err();
    assert!(
        error.to_string().contains("duplicate selector member"),
        "unexpected error: {error}"
    );
}

#[test]
fn selector_refuses_members_that_would_move_traffic_across_a_privacy_boundary() {
    // Failover between these would change whether the traffic is anonymised
    // at all, so they are refused at config time rather than at connect time.
    let tor = r#"{"id":"node-t","outbound":{"type":"tor","state_dir":"/data/tor","cache_dir":"/data/tor-cache"}}"#;
    let error = EngineConfig::parse(&selector_json(&format!("[{tor}]"), "")).unwrap_err();
    assert!(
        error.to_string().contains("must not be Tor or I2P"),
        "unexpected error: {error}"
    );

    let nested = r#"{"id":"node-n","outbound":{"type":"selector","members":[]}}"#;
    let error = EngineConfig::parse(&selector_json(&format!("[{nested}]"), "")).unwrap_err();
    assert!(
        error.to_string().contains("must not be selectors"),
        "unexpected error: {error}"
    );
}

#[test]
fn selector_refuses_a_wireguard_member() {
    let wireguard = format!(
        r#"{{"id":"node-w","outbound":{{"type":"wireguard","server":"edge.example","port":51820,"private_key":"{WG_PRIVATE_KEY}","peer_public_key":"{WG_PEER_PUBLIC_KEY}","address":["10.8.0.2/32"],"allowed_ips":["0.0.0.0/0"]}}}}"#
    );
    let error = EngineConfig::parse(&selector_json(&format!("[{wireguard}]"), "")).unwrap_err();
    assert!(
        error.to_string().contains("must not be WireGuard"),
        "unexpected error: {error}"
    );
}

#[test]
fn selector_member_ids_may_not_shadow_reserved_names() {
    let member = r#"{"id":"direct","outbound":{"type":"shadowsocks","server":"198.51.100.7","port":8388,"method":"aes-128-gcm","password":"pw"}}"#;
    let error = EngineConfig::parse(&selector_json(&format!("[{member}]"), "")).unwrap_err();
    assert!(
        error.to_string().contains("is reserved"),
        "unexpected error: {error}"
    );
}

/// Found on a real device: a config carrying only a blocklist validated
/// cleanly, no interceptor was built, and every blocked name resolved. A
/// firewall that fails open is worse than one that refuses to start.
#[test]
fn a_blocklist_without_an_interceptor_is_refused_rather_than_ignored() {
    let with_dns = |dns: &str| {
        format!(
            r#"{{"schema_version":1,
                     "outbound":{{"type":"trojan","server":"edge.example","port":443,
                                  "password":"pw","tls":{{"enabled":true}}}},
                     "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}},
                     "dns":{dns}}}"#
        )
    };

    let inert = with_dns(r#"{"blocklist":{"suffixes":["ads.example"]}}"#);
    let error = EngineConfig::parse(&inert).unwrap_err();
    assert!(
        error.to_string().contains("requires an interceptor"),
        "unexpected error: {error}"
    );

    // Building an interceptor is necessary and not sufficient — see
    // `dns_filtering_must_declare_itself_the_resolver` below. What makes a
    // filtering config valid is being the resolver the device asks.
    for dns in [
        r#"{"blocklist":{"suffixes":["ads.example"]},"advertise":"10.0.0.53"}"#,
        r#"{"blocklist":{"suffixes":["ads.example"]},"mode":"fake_ip"}"#,
        r#"{"blocklist":{"suffixes":["ads.example"]},"advertise":"10.0.0.53",
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
    ] {
        EngineConfig::parse(&with_dns(dns))
            .unwrap_or_else(|error| panic!("{dns} should be valid, got: {error}"));
    }

    // No blocklist and no interceptor stays legal: DNS simply passes through.
    EngineConfig::parse(&with_dns("{}")).expect("a config without DNS features is fine");
}

/// Upstreams make an interceptor. They do not make anybody ask it.
///
/// `dns.advertise` is the only field in the DNS document that reaches the
/// platform — the address the app hands `VpnService.Builder`. Without it
/// Android keeps the resolver it already had, and a `real_ip` config with a
/// blocklist and a full set of upstreams starts cleanly while the device
/// resolves outside the tunnel. Every component is doing its job in that
/// state and the feature is simply off, which is why it survives review.
///
/// This is also the second candidate from the D14 investigation, and the
/// reason it lived so long is worth writing next to the fix: **every
/// blocklist test in this file pinned `mode: "fake_ip"`**, the one mode in
/// which the hole cannot exist. A suite that only ever exercises the safe
/// mode passes over the unsafe one in silence — so the cases below are
/// deliberately `real_ip`, including the default, which *is* `real_ip`.
#[test]
fn dns_filtering_must_declare_itself_the_resolver() {
    let with_dns = |dns: &str| {
        format!(
            r#"{{"schema_version":1,
                     "outbound":{{"type":"trojan","server":"edge.example","port":443,
                                  "password":"pw","tls":{{"enabled":true}}}},
                     "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}},
                     "dns":{dns}}}"#
        )
    };

    for dns in [
        // The shape found in the field: filtering, upstreams, real_ip by
        // default, and nothing that tells the platform where to ask.
        r#"{"blocklist":{"suffixes":["ads.example"]},
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
        // The same thing said out loud rather than by default.
        r#"{"blocklist":{"suffixes":["ads.example"]},"mode":"real_ip",
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
        // A rule set is filtering too, and fails for the same reason.
        r#"{"rule_sets":[{"name":"foxhole-adguard-dns",
                              "public_key":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}],
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
    ] {
        let error = EngineConfig::parse(&with_dns(dns))
            .expect_err("filtering without an advertised resolver must not validate");
        assert!(
            error.to_string().contains("dns.advertise"),
            "the refusal has to name the field that fixes it, got: {error}"
        );
    }

    // Adding the advertised address is the whole fix.
    EngineConfig::parse(&with_dns(
        r#"{"blocklist":{"suffixes":["ads.example"]},"mode":"real_ip",
                "advertise":"10.0.0.53",
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
    ))
    .expect("a real_ip resolver that advertises itself is the supported shape");

    // fake_ip is exempt, and not by oversight: in that mode the interceptor
    // is the source of the addresses the flows carry, so a device answered
    // by something else gets ordinary routable addresses and the fake-IP
    // path visibly never engages, rather than filtering silently doing
    // nothing.
    EngineConfig::parse(&with_dns(
        r#"{"blocklist":{"suffixes":["ads.example"]},"mode":"fake_ip",
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
    ))
    .expect("fake_ip cannot reach the state this rule exists to refuse");

    // And a config that filters nothing is still free to do whatever: the
    // rule is about filtering that would not filter, not about resolvers.
    EngineConfig::parse(&with_dns(
        r#"{"mode":"real_ip","upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
    ))
    .expect("a plain resolver with no filtering is not what this rule is about");
}

#[test]
fn signed_dns_rule_set_config_pins_a_bounded_key_and_cannot_be_inert_or_duplicated() {
    let public_key = STANDARD.encode([4_u8; 65]);
    let source = DnsRuleSetConfig {
        name: "foxhole-adguard-dns".into(),
        public_key: public_key.clone(),
        minimum_sequence: 7,
        required: true,
    };
    let valid = DnsConfig {
        mode: DnsMode::FakeIp,
        rule_sets: vec![source.clone()],
        ..DnsConfig::default()
    };
    assert!(valid.validate().is_ok());

    let inert = DnsConfig {
        rule_sets: vec![source.clone()],
        ..DnsConfig::default()
    };
    assert!(inert.validate().is_err());

    let duplicate = DnsConfig {
        mode: DnsMode::FakeIp,
        rule_sets: vec![source.clone(), source],
        ..DnsConfig::default()
    };
    assert!(duplicate.validate().is_err());

    let decoded: DnsConfig = serde_json::from_value(serde_json::json!({
        "mode": "fake_ip",
        "rule_sets": [{
            "name": "foxhole-adguard-dns",
            "public_key": public_key
        }]
    }))
    .unwrap();
    assert!(decoded.rule_sets[0].required);
}

#[test]
fn intercepts_is_the_single_answer_the_data_plane_also_uses() {
    assert!(!DnsConfig::default().intercepts());
    assert!(
        DnsConfig {
            mode: DnsMode::FakeIp,
            ..DnsConfig::default()
        }
        .intercepts()
    );
    // The legacy single-upstream field counts too — the data plane migrates
    // it into `upstreams`, and a predicate that missed it would disagree
    // with the engine again.
    assert!(
        DnsConfig {
            upstream: Some("1.1.1.1:53".into()),
            ..DnsConfig::default()
        }
        .intercepts()
    );
}

/// The predicate D14 turns on, stated as the four cases that decide it.
///
/// The narrowness is the point. A gate on port 853 alone would refuse every
/// application that speaks encrypted DNS for itself; a gate on the address
/// alone would refuse ordinary traffic to a resolver that also serves
/// something else. What is being refused is *this* resolver asked over a
/// transport this core does not terminate, and nothing else.
#[test]
fn only_the_resolver_we_advertised_can_be_bypassed_on_853() {
    let advertising = DnsConfig {
        advertise: Some("10.0.0.53".into()),
        ..DnsConfig::default()
    };
    let ours: IpAddr = "10.0.0.53".parse().unwrap();
    let theirs: IpAddr = "9.9.9.9".parse().unwrap();

    assert!(advertising.bypasses_interceptor(ours, DNS_ENCRYPTED_PORT));
    assert!(
        !advertising.bypasses_interceptor(theirs, DNS_ENCRYPTED_PORT),
        "somebody else's DoT server is ordinary traffic and stays ordinary"
    );
    assert!(
        !advertising.bypasses_interceptor(ours, 53),
        "the plain port is the interceptor's own, and it is not a bypass of \
             itself"
    );
    assert!(
        !advertising.bypasses_interceptor(ours, 443),
        "443 to the resolver is indistinguishable from any other HTTPS, and \
             a guess here would refuse traffic on a hunch"
    );
    assert!(
        !DnsConfig::default().bypasses_interceptor(ours, DNS_ENCRYPTED_PORT),
        "a document that advertised nothing never told the platform where to \
             resolve, so no address on the wire is this resolver's"
    );
}

#[test]
fn tls_version_range_and_curves_parse_the_way_the_app_writes_them() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"trojan","server":"edge.example","port":443,"password":"pw",
                "tls":{"enabled":true,"min_version":"1.2","max_version":"1.3",
                       "curve_preferences":["x25519","secp256r1"]}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let config = EngineConfig::parse(json).expect("the app's TLS shape must parse");
    let OutboundConfig::Trojan(trojan) = config.outbound else {
        panic!("expected a Trojan outbound");
    };
    assert_eq!(trojan.tls.min_version, Some(TlsVersion::Tls12));
    assert_eq!(trojan.tls.max_version, Some(TlsVersion::Tls13));
    assert_eq!(
        trojan.tls.curve_preferences,
        vec![CurveGroup::X25519, CurveGroup::Secp256r1]
    );
}

#[test]
fn tls_version_range_and_curves_fail_closed_on_nonsense() {
    let with_tls = |tls: &str| {
        format!(
            r#"{{"schema_version":1,
                     "outbound":{{"type":"trojan","server":"edge.example","port":443,
                                  "password":"pw","tls":{tls}}},
                     "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}}}"#
        )
    };

    // An inverted range can never negotiate anything, and letting it through
    // would surface as an unexplained handshake failure at connect time.
    let inverted = with_tls(r#"{"enabled":true,"min_version":"1.3","max_version":"1.2"}"#);
    assert!(
        EngineConfig::parse(&inverted)
            .unwrap_err()
            .to_string()
            .contains("min_version")
    );

    // TLS 1.0/1.1 are not in the enum: a profile asking for them is asking
    // for a handshake the core will not speak.
    let ancient = with_tls(r#"{"enabled":true,"min_version":"1.0"}"#);
    assert!(EngineConfig::parse(&ancient).is_err());

    // A duplicate would make the pinned order ambiguous.
    let repeated = with_tls(r#"{"enabled":true,"curve_preferences":["x25519","x25519"]}"#);
    assert!(
        EngineConfig::parse(&repeated)
            .unwrap_err()
            .to_string()
            .contains("repeat")
    );

    // Options without TLS itself are a contradiction, not a hint.
    let disabled = with_tls(r#"{"enabled":false,"min_version":"1.3"}"#);
    assert!(EngineConfig::parse(&disabled).is_err());
}

#[test]
fn selector_probe_accepts_a_plain_http_target_and_refuses_the_rest() {
    let json = selector_json(
        &format!("[{SS_MEMBER_A}]"),
        r#","probe":{"url":"http://probe.example/generate_204","interval_ms":30000}"#,
    );
    let config = EngineConfig::parse(&json).expect("an http probe target should parse");
    let OutboundConfig::Selector(selector) = config.outbound else {
        panic!("expected a selector outbound");
    };
    let probe = selector.probe.unwrap();
    assert_eq!(
        probe.target().unwrap(),
        ("probe.example".to_owned(), 80, "/generate_204".to_owned())
    );
    assert_eq!(probe.tolerance_ms, 50, "the default must survive omission");

    // HTTPS would put a second TLS surface inside a health check, and
    // probing it as plaintext instead would measure something else.
    let https = selector_json(
        &format!("[{SS_MEMBER_A}]"),
        r#","probe":{"url":"https://probe.example/"}"#,
    );
    assert!(
        EngineConfig::parse(&https)
            .unwrap_err()
            .to_string()
            .contains("plain http")
    );

    // A one-second interval would probe every member sixty times a minute
    // on a battery-powered device.
    let fast = selector_json(
        &format!("[{SS_MEMBER_A}]"),
        r#","probe":{"url":"http://probe.example/","interval_ms":1000}"#,
    );
    assert!(
        EngineConfig::parse(&fast)
            .unwrap_err()
            .to_string()
            .contains("interval_ms")
    );
}
