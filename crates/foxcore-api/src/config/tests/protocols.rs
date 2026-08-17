use super::*;

#[test]
fn selector_member_timeout_must_be_bounded() {
    let json = selector_json(&format!("[{SS_MEMBER_A}]"), r#","member_timeout_ms":0"#);
    let error = EngineConfig::parse(&json).unwrap_err();
    assert!(
        error.to_string().contains("member_timeout_ms"),
        "unexpected error: {error}"
    );
}

#[test]
fn parses_amneziawg_obfuscation_parameters() {
    let json = amnezia_json(
        r#"{"junk_packet_count":4,"junk_min_size":40,"junk_max_size":80,
                "init_junk_size":16,"response_junk_size":24,
                "header_initiation":1633837924,"header_response":1701077858,
                "header_cookie":1768581996,"header_transport":1835954034}"#,
    );
    let config = EngineConfig::parse(&json).expect("AmneziaWG parameters should parse");
    let OutboundConfig::Wireguard(wireguard) = config.outbound else {
        panic!("expected a wireguard outbound");
    };
    let amnezia = wireguard.amnezia.expect("amnezia block should be kept");
    assert_eq!(amnezia.junk_packet_count, 4);
    assert_eq!(amnezia.init_junk_size, 16);
    assert_eq!(
        amnezia.header_transport,
        AmneziaHeaderRange::single(1_835_954_034)
    );
}

/// amnezia-vpn/amneziawg-go#141: an `I` slot that renders to nothing is put on
/// the wire as a zero-length UDP datagram. The tag list here is not empty — it is
/// `<d>`, which is zero-width because an init packet has no payload to carry.
#[test]
fn amneziawg_rejects_an_init_packet_that_renders_no_bytes() {
    let json = amnezia_json(r#"{"init_packets":[{"tags":[{"tag":"payload"}]}]}"#);
    let error = EngineConfig::parse(&json)
        .expect_err("a template that renders nothing would be sent as an empty datagram")
        .to_string();
    assert!(error.contains("at least one byte"), "unexpected: {error}");
}

/// The same empty datagram, reached down the junk path instead of the `I` path.
#[test]
fn amneziawg_rejects_junk_packets_that_would_be_empty() {
    let json = amnezia_json(
        r#"{"junk_packet_count":4,"junk_min_size":0,"junk_max_size":0,
                "init_junk_size":0,"response_junk_size":0}"#,
    );
    let error = EngineConfig::parse(&json)
        .expect_err("Jc with Jmax=0 asks for four zero-length datagrams")
        .to_string();
    assert!(error.contains("junk_max_size"), "unexpected: {error}");
}

/// `Jmax` below the MTU is the whole point of junk; at or above it every junk
/// datagram fragments, which is the signature upstream warns about.
#[test]
fn amneziawg_junk_fragments_only_at_or_above_the_mtu() {
    let mut amnezia = AmneziaConfig {
        junk_packet_count: 4,
        junk_min_size: 40,
        junk_max_size: 1279,
        ..AmneziaConfig::default()
    };
    assert!(!amnezia.junk_fragments_at_mtu(1280));
    amnezia.junk_max_size = 1280;
    assert!(amnezia.junk_fragments_at_mtu(1280));
    assert!(amnezia.junk_fragments_at_mtu(1279));
    // No junk, no fragments: Jmax is unread when Jc is zero.
    amnezia.junk_packet_count = 0;
    assert!(!amnezia.junk_fragments_at_mtu(1280));
}

/// The rule the helper above states, applied. A profile that lowered its own MTU
/// to 1280 and asks for 1280-byte junk is refused rather than clamped: clamping
/// would keep it working while sending a size the peer's generator never picked.
#[test]
fn amneziawg_refuses_junk_that_fragments_at_the_profile_mtu() {
    let junk = |max: u16| {
        format!(
            r#"{{"junk_packet_count":4,"junk_min_size":40,"junk_max_size":{max},
                    "init_junk_size":16,"response_junk_size":24}}"#
        )
    };
    let error = EngineConfig::parse(&amnezia_json_with_mtu(1280, &junk(1280)))
        .expect_err("junk at the MTU fragments every datagram, which is itself a signature")
        .to_string();
    assert!(error.contains("junk_max_size"), "unexpected: {error}");
    assert!(error.contains("1280"), "unexpected: {error}");
    // One byte below still fits the path, so it stays a valid profile.
    EngineConfig::parse(&amnezia_json_with_mtu(1280, &junk(1279)))
        .expect("junk below the MTU is the ordinary case and must keep parsing");
    // And `Jc = 0` never reads `Jmax`, so the comparison must not fire on it.
    EngineConfig::parse(&amnezia_json_with_mtu(
        1280,
        r#"{"junk_packet_count":0,"junk_min_size":0,"junk_max_size":1280}"#,
    ))
    .expect("without junk packets Jmax puts nothing on the wire");
}

/// `H1..H4` as AWG 2.0 intervals. A range is carried as a range and serialized
/// back to the `"lo-hi"` text a `.conf` carries, because the header is drawn
/// afresh per datagram and collapsing it would put a constant on the wire where
/// the profile asked for a moving target.
#[test]
fn amneziawg_header_ranges_round_trip_beside_single_values() {
    let json = amnezia_json(
        r#"{"header_initiation":"10-19","header_response":20,
                "header_cookie":"30-39","header_transport":"40-49"}"#,
    );
    let config = EngineConfig::parse(&json).expect("ranged headers should parse");
    let OutboundConfig::Wireguard(wireguard) = config.outbound else {
        panic!("expected a wireguard outbound");
    };
    let amnezia = wireguard.amnezia.expect("amnezia block should be kept");
    assert_eq!(
        amnezia.header_initiation,
        AmneziaHeaderRange::new(10, 19).unwrap()
    );
    assert_eq!(amnezia.header_response, AmneziaHeaderRange::single(20));
    assert!(!amnezia.header_initiation.is_single());
    assert!(amnezia.header_response.is_single());

    let text = serde_json::to_string(&amnezia).expect("the block should serialize");
    assert!(text.contains(r#""header_initiation":"10-19""#), "{text}");
    // The single value stays a bare number rather than becoming "20-20", so a 1.5
    // document written before ranges existed round-trips unchanged.
    assert!(text.contains(r#""header_response":20"#), "{text}");
}

/// Inverted bounds are upstream's own refusal in `u32_range_from_string`, and an
/// interval that overlaps another is ambiguous for exactly the datagrams that
/// draw the shared value — an intermittent tunnel rather than a broken one.
#[test]
fn amneziawg_refuses_inverted_and_overlapping_header_ranges() {
    let inverted = EngineConfig::parse(&amnezia_json(r#"{"header_initiation":"19-10"}"#))
        .expect_err("a range that ends before it starts names no header")
        .to_string();
    assert!(inverted.contains("19-10"), "unexpected: {inverted}");

    EngineConfig::parse(&amnezia_json(
        r#"{"header_initiation":"10-20","header_response":"20-30",
                "header_cookie":"40-49","header_transport":"50-59"}"#,
    ))
    .expect_err("two intervals sharing header 20 make that datagram untypeable");
}

#[test]
fn amneziawg_rejects_colliding_custom_headers() {
    let json = amnezia_json(
        r#"{"header_initiation":7,"header_response":7,
                "header_cookie":9,"header_transport":10}"#,
    );
    EngineConfig::parse(&json).expect_err(
        "two message types sharing a header make the peer undecodable, so it must fail closed",
    );
}

#[test]
fn wireguard_rejects_a_key_that_is_not_thirty_two_base64_bytes() {
    let short = "c2hvcnQtc2VjcmV0";
    let json = wireguard_json(short, r#"["10.8.0.2/32"]"#, r#"["0.0.0.0/0"]"#);
    let error = EngineConfig::parse(&json)
        .expect_err("a 12-byte key must not be accepted as an X25519 key")
        .to_string();
    assert!(error.contains("private_key"), "unexpected error: {error}");
    assert!(!error.contains(short), "the error leaked the key: {error}");
}

#[test]
fn wireguard_requires_an_interface_address_and_allowed_ips() {
    for (address, allowed_ips) in [
        (r#"[]"#, r#"["0.0.0.0/0"]"#),
        (r#"["10.8.0.2/32"]"#, r#"[]"#),
    ] {
        let json = wireguard_json(WG_PRIVATE_KEY, address, allowed_ips);
        EngineConfig::parse(&json)
            .expect_err("an empty L3 prefix list must fail closed, not default to a full tunnel");
    }
}

/// The owner's WireGuard profile, byte for byte the shape that ran on the
/// phone: a packet-tunnel primary and `dns.mode='fake_ip'`. It started, it
/// reported no error, and every clearnet TCP connection timed out after
/// twenty seconds because the destination the resolver invented
/// (`198.18.0.3`) was sealed into the datagram and sent to a peer that
/// routes nothing in `198.18.0.0/15`, as reproduced in device acceptance.
///
/// The same document with a proxy outbound is correct and stays accepted —
/// there the stack terminates the flow and dials by name, which is the
/// whole difference.
#[test]
fn fake_ip_dns_and_a_packet_tunnel_primary_refuse_to_start_together() {
    let with_dns = |outbound: &str, dns: &str| {
        format!(
            r#"{{
                    "schema_version":1,
                    "outbound":{outbound},
                    "tun":{{"mtu":1400,"ipv4":"10.0.0.2"}},
                    "dns":{dns}
                }}"#
        )
    };
    let wireguard = format!(
        r#"{{"type":"wireguard","server":"edge.example","port":51820,
                 "private_key":"{WG_PRIVATE_KEY}","peer_public_key":"{WG_PEER_PUBLIC_KEY}",
                 "address":["10.8.0.2/32"],"allowed_ips":["0.0.0.0/0"]}}"#
    );
    let proxy = r#"{"type":"vless","server":"edge.example","port":443,
             "uuid":"d0cf0001-0000-4000-8000-000000000000"}"#;

    let error = EngineConfig::parse(&with_dns(&wireguard, r#"{"mode":"fake_ip"}"#))
        .expect_err("a config that cannot carry a single clearnet flow must not start")
        .to_string();
    assert!(
        error.contains("fake_ip") && error.contains("packet tunnel"),
        "the refusal has to name both sides, not one: {error}"
    );
    assert!(
        error.contains("198.18.0.0/15"),
        "and the pool the address comes from, so the symptom is recognisable: {error}"
    );

    EngineConfig::parse(&with_dns(&wireguard, r#"{"mode":"real_ip"}"#))
        .expect("real-IP DNS is what a packet tunnel can carry, and it is proven on device");
    EngineConfig::parse(&with_dns(proxy, r#"{"mode":"fake_ip"}"#))
        .expect("fake-IP with a proxy outbound is the case it was designed for");
}

/// The same profile with the resolver a real subscription carries, and the
/// quieter half of the same problem.
///
/// `dns.route` defaults to `primary`, so a document that only lists
/// `dns.upstreams` — the ordinary way to configure a resolver — asks for the
/// primary outbound without naming it. On an L3 profile the registry's
/// default is the clearnet placeholder standing in for the tunnel, so every
/// intercepted lookup went out on a protected socket beside the tunnel:
/// every name the device visits, in the open, while the session looked
/// healthy and no counter moved.
#[test]
fn primary_routed_dns_and_a_packet_tunnel_primary_refuse_to_start_together() {
    let with_dns = |outbound: &str, dns: &str| {
        format!(
            r#"{{
                    "schema_version":1,
                    "outbound":{outbound},
                    "tun":{{"mtu":1400,"ipv4":"10.0.0.2"}},
                    "dns":{dns}
                }}"#
        )
    };
    let wireguard = format!(
        r#"{{"type":"wireguard","server":"edge.example","port":51820,
                 "private_key":"{WG_PRIVATE_KEY}","peer_public_key":"{WG_PEER_PUBLIC_KEY}",
                 "address":["10.8.0.2/32"],"allowed_ips":["0.0.0.0/0"]}}"#
    );
    let proxy = r#"{"type":"vless","server":"edge.example","port":443,
             "uuid":"d0cf0001-0000-4000-8000-000000000000"}"#;
    let upstreams = r#"{"mode":"real_ip","upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#;

    let error = EngineConfig::parse(&with_dns(&wireguard, upstreams))
        .expect_err("a profile whose every lookup would leave must not start")
        .to_string();
    assert!(
        error.contains("dns.route='primary'") && error.contains("packet tunnel"),
        "the refusal has to name both sides, not one: {error}"
    );

    EngineConfig::parse(&with_dns(
        &wireguard,
        r#"{"mode":"real_ip","route":"direct",
                "upstreams":[{"type":"udp","address":"1.1.1.1:53"}]}"#,
    ))
    .expect("resolving outside the tunnel stays available to a document that names it");
    EngineConfig::parse(&with_dns(proxy, upstreams))
        .expect("the same resolver on a proxy profile is the ordinary case");
    EngineConfig::parse(&with_dns(&wireguard, r#"{"mode":"real_ip"}"#))
        .expect("a profile that intercepts nothing has nothing to route");
}

/// The other half of the same contradiction, said in one step instead of
/// two. Overlay routing *requires* fake-IP so a `.onion` lookup never
/// reaches a clearnet resolver; a packet-tunnel primary cannot carry
/// fake-IP. Without this the answer to a real-IP WireGuard+Tor profile
/// would be "set fake_ip", which then fails on the rule above.
#[test]
fn a_packet_tunnel_primary_and_overlay_routing_do_not_share_a_profile() {
    let json = format!(
        r#"{{
                "schema_version":1,
                "outbound":{{"type":"wireguard","server":"edge.example","port":51820,
                    "private_key":"{WG_PRIVATE_KEY}","peer_public_key":"{WG_PEER_PUBLIC_KEY}",
                    "address":["10.8.0.2/32"],"allowed_ips":["0.0.0.0/0"]}},
                "outbounds":[{{"id":"tor","outbound":{{"type":"tor","state_dir":"/state","cache_dir":"/cache"}}}}],
                "tun":{{"mtu":1400,"ipv4":"10.0.0.2"}},
                "dns":{{"mode":"real_ip"}}
            }}"#
    );
    let error = EngineConfig::parse(&json)
        .expect_err("the two demands are incompatible and saying so once is the point")
        .to_string();
    assert!(
        error.contains("overlay routing") && error.contains("packet tunnel"),
        "unexpected error: {error}"
    );
}

#[test]
fn supports_all_seven_outbound_shapes() {
    let configs = [
        r#"{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"}"#,
        r#"{"type":"vmess","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000","cipher":"auto"}"#,
        r#"{"type":"hysteria2","server":"s","port":1,"password":"p","tls":{"enabled":true}}"#,
        r#"{"type":"trojan","server":"s","port":1,"password":"p","tls":{"enabled":true}}"#,
        r#"{"type":"shadowsocks","server":"s","port":1,"method":"aes-128-gcm","password":"p"}"#,
        r#"{"type":"i2p","socks_address":"127.0.0.1:4447"}"#,
        r#"{"type":"tor","state_dir":"/state","cache_dir":"/cache"}"#,
    ];
    for outbound in configs {
        let json = format!(
            r#"{{"schema_version":1,"outbound":{outbound},"tun":{{"mtu":1400,"ipv4":"10.0.0.1"}},"dns":{{"mode":"fake_ip"}}}}"#
        );
        EngineConfig::parse(&json).unwrap();
    }
}

#[test]
fn parses_http_upgrade_stream_transport() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless","server":"edge.example","port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "tls":{"enabled":true,"server_name":"edge.example"},
                "transport":{"type":"http_upgrade","path":"/tunnel","host":"cdn.example"}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    EngineConfig::parse(json).expect("http_upgrade transport should parse and validate");
}

#[test]
fn parses_grpc_stream_transport() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless","server":"edge.example","port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "tls":{"enabled":true,"server_name":"edge.example"},
                "transport":{"type":"grpc","service_name":"GunService","multi_mode":true}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    EngineConfig::parse(json).expect("grpc transport should parse and validate");
}

#[test]
fn parses_http2_stream_transport() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless","server":"edge.example","port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "tls":{"enabled":true,"server_name":"edge.example"},
                "transport":{"type":"http2","host":["cdn.example"],"path":"/stream","method":"PUT"}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    EngineConfig::parse(json).expect("http2 transport should parse and validate");
}

#[test]
fn tor_routing_requires_fake_ip_dns_so_onion_stays_inside_the_core() {
    // Without fake-IP the DNS gateway may not even be constructed, and then a
    // `.onion` lookup is forwarded to a clearnet resolver as ordinary port-53
    // traffic. Mirror of the existing I2P guard.
    let json = r#"{
            "schema_version":1,
            "outbound":{"type":"vless","server":"edge.example","port":443,
                        "uuid":"d0cf0001-0000-4000-8000-000000000000"},
            "outbounds":[{"id":"tor","outbound":{"type":"tor","state_dir":"/s","cache_dir":"/c"}}],
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(
        EngineConfig::parse(json).is_err(),
        "a registered Tor outbound with real-IP DNS must be rejected"
    );

    let with_fake_ip = json.replace(
        r#""tun":{"mtu":1400,"ipv4":"10.0.0.1"}"#,
        r#""tun":{"mtu":1400,"ipv4":"10.0.0.1"},"dns":{"mode":"fake_ip"}"#,
    );
    EngineConfig::parse(&with_fake_ip).expect("Tor with fake_ip DNS should validate");

    // Explicitly disabling Tor keeps a real-IP profile valid.
    let tor_off = json.replace(
        r#""tun":{"mtu":1400,"ipv4":"10.0.0.1"}"#,
        r#""tun":{"mtu":1400,"ipv4":"10.0.0.1"},"traffic":{"tor_enabled":false}"#,
    );
    EngineConfig::parse(&tor_off).expect("tor_enabled=false should stay valid on real-IP DNS");
}

#[test]
fn vmess_requires_modern_aead_and_redacts_uuid() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vmess",
                "server":"vmess.example",
                "port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "alter_id":0,
                "cipher":"chacha20-poly1305"
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    assert!(!format!("{parsed:?}").contains("d0cf0001-0000-4000-8000-000000000000"));
    assert!(EngineConfig::parse(&json.replace("\"alter_id\":0", "\"alter_id\":64")).is_err());
}

#[test]
fn validates_vless_reality_as_a_fail_closed_security_layer() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless",
                "server":"edge.example",
                "port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "reality":{
                    "server_name":"www.example.com",
                    "public_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
                    "short_id":"0123456789abcdef",
                    "fingerprint":"chrome",
                    "spider_x":"/private-fallback"
                }
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    let OutboundConfig::Vless(vless) = &parsed.outbound else {
        panic!("profile must be VLESS");
    };
    let reality = vless.reality.as_ref().expect("Reality must be present");
    assert_eq!(reality.handshake_timeout_ms, 15_000);
    assert_eq!(reality.fingerprint, RealityFingerprint::Chrome151);
    let debug = format!("{parsed:?}");
    assert!(!debug.contains(reality.public_key.expose()));
    assert!(!debug.contains(reality.short_id.expose()));
    assert!(!debug.contains("private-fallback"));

    for invalid in [
        json.replace("0123456789abcdef", "abc"),
        json.replace("\"reality\":{", "\"tls\":{\"enabled\":true},\"reality\":{"),
    ] {
        assert!(EngineConfig::parse(&invalid).is_err());
    }

    // REALITY is a security layer, not a carrier. A stream transport above it
    // is the ordinary shape of a REALITY node in the wild (gRPC especially),
    // and used to be rejected here for a limitation the wire does not have.
    for transport in [
        r#"{"type":"websocket","path":"/ws"}"#,
        r#"{"type":"http_upgrade","path":"/up"}"#,
        r#"{"type":"grpc","service_name":"fox"}"#,
        r#"{"type":"http2","path":"/h2"}"#,
    ] {
        let json = json.replace(
            "\"uuid\":\"d0cf0001-0000-4000-8000-000000000000\",",
            &format!(
                "\"uuid\":\"d0cf0001-0000-4000-8000-000000000000\",\"transport\":{transport},"
            ),
        );
        EngineConfig::parse(&json)
            .unwrap_or_else(|error| panic!("reality over {transport} must parse: {error}"));
    }

    // The fingerprint names build-specific hellos now. `chrome` was the only
    // value the field ever had, so a profile an installed app already saved
    // must keep parsing and must keep meaning the default profile.
    let fingerprint = |value: &str| -> RealityFingerprint {
        let json = json.replace(
            "\"fingerprint\":\"chrome\"",
            &format!("\"fingerprint\":{value}"),
        );
        let parsed = EngineConfig::parse(&json).unwrap_or_else(|error| {
            panic!("{value} must parse: {error}");
        });
        let OutboundConfig::Vless(vless) = &parsed.outbound else {
            panic!("profile must be VLESS");
        };
        vless.reality.as_ref().unwrap().fingerprint
    };
    // The bare name follows the current browser rather than pinning a build:
    // it is a promise to look like Chrome, and a table that stopped matching a
    // shipping Chrome would not keep that promise. The build-specific spellings
    // are how a caller pins one deliberately.
    assert_eq!(fingerprint("\"chrome\""), RealityFingerprint::Chrome151);
    assert_eq!(fingerprint("\"chrome_151\""), RealityFingerprint::Chrome151);
    assert_eq!(fingerprint("\"chrome_133\""), RealityFingerprint::Chrome133);
    assert_eq!(fingerprint("\"chrome_131\""), RealityFingerprint::Chrome131);
    assert_eq!(RealityFingerprint::default(), RealityFingerprint::Chrome151);

    // The other profiles, by both spellings: the short name a share link
    // carries and the build-specific name this core uses.
    for (value, expected) in [
        ("\"edge\"", RealityFingerprint::Edge85),
        ("\"edge_85\"", RealityFingerprint::Edge85),
        ("\"safari\"", RealityFingerprint::Safari263),
        ("\"safari_26_3\"", RealityFingerprint::Safari263),
        ("\"ios\"", RealityFingerprint::Ios14),
        ("\"ios_14\"", RealityFingerprint::Ios14),
        ("\"qq\"", RealityFingerprint::Qq111),
        ("\"qq_11_1\"", RealityFingerprint::Qq111),
        ("\"firefox\"", RealityFingerprint::Firefox153),
        ("\"firefox_153\"", RealityFingerprint::Firefox153),
        ("\"firefox_148\"", RealityFingerprint::Firefox148),
        // The one value that names no browser: uTLS' generator, ported in
        // `proto_reality::reality::randomized_hello`. It is a name this core
        // can produce bytes for — different bytes every connection — so it
        // belongs in the accepted list rather than the refused one below.
        ("\"randomized\"", RealityFingerprint::Randomized),
    ] {
        assert_eq!(fingerprint(value), expected, "fingerprint {value}");
    }

    // And the list stays closed: a uTLS parrot name this core cannot produce
    // bytes for is a refusal here, not a silent fall back to Chrome. The link
    // parser is where `fp=firefox` becomes a reported substitution; a *config*
    // naming a profile with no table is a malformed config.
    //
    // `360` and `android` are refused at both layers.
    for unknown in [
        "\"360\"",
        "\"android\"",
        "\"random\"",
        "\"chrome_999\"",
        "\"\"",
    ] {
        let json = json.replace(
            "\"fingerprint\":\"chrome\"",
            &format!("\"fingerprint\":{unknown}"),
        );
        assert!(
            EngineConfig::parse(&json).is_err(),
            "fingerprint {unknown} must be refused"
        );
    }
}

#[test]
fn validates_and_redacts_hysteria2_salamander_config() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"hysteria2",
                "server":"hy2.example",
                "port":443,
                "password":"hy2-auth-secret",
                "obfs":{"type":"salamander","password":"obfs-secret"},
                "tls":{"enabled":true}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("hy2-auth-secret"));
    assert!(!debug.contains("obfs-secret"));

    let empty = json.replace("obfs-secret", "");
    assert!(EngineConfig::parse(&empty).is_err());
    let unsupported = json.replace("salamander", "gecko");
    assert!(EngineConfig::parse(&unsupported).is_err());
}

#[test]
fn validates_bounded_websocket_transport_and_redacts_custom_headers() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless",
                "server":"ws.example",
                "port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "transport":{
                    "type":"websocket",
                    "path":"/proxy?mode=test",
                    "host":"front.example",
                    "headers":{"Authorization":"custom-header-secret"}
                },
                "tls":{"enabled":true}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    let parsed = EngineConfig::parse(json).unwrap();
    assert!(!format!("{parsed:?}").contains("custom-header-secret"));

    let reserved = json.replace("Authorization", "Connection");
    assert!(EngineConfig::parse(&reserved).is_err());
    let invalid_path = json.replace("/proxy?mode=test", "relative");
    assert!(EngineConfig::parse(&invalid_path).is_err());
}

#[test]
fn validates_custom_tor_policy_and_redacts_bridge_lines() {
    let bridge = "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956";
    let json = format!(
        r#"{{
                "schema_version":1,
                "outbound":{{
                    "type":"tor",
                    "state_dir":"/private/state",
                    "cache_dir":"/private/cache",
                    "bootstrap_timeout_s":90,
                    "stream_connect_timeout_s":12,
                    "isolate_streams":true,
                    "circuit":{{
                        "max_dirtiness_s":300,
                        "request_timeout_s":45,
                        "request_max_retries":8
                    }},
                    "bridges":["{bridge}"]
                }},
                "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}},
                "dns":{{"mode":"fake_ip"}}
            }}"#
    );
    let parsed = EngineConfig::parse(&json).unwrap();
    assert!(!format!("{parsed:?}").contains(bridge));

    let bad_timeout = json.replace(
        "\"stream_connect_timeout_s\":12",
        "\"stream_connect_timeout_s\":1",
    );
    assert!(EngineConfig::parse(&bad_timeout).is_err());
}

#[test]
fn tor_upstream_accepts_only_a_valid_stream_proxy() {
    let json = r#"{
            "schema_version":1,
            "outbound":{
                "type":"tor",
                "state_dir":"/private/state",
                "cache_dir":"/private/cache",
                "upstream":{
                    "type":"vless",
                    "server":"vpn.example",
                    "port":443,
                    "uuid":"d0cf0001-0000-4000-8000-000000000000"
                }
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
            "dns":{"mode":"fake_ip"}
        }"#;
    EngineConfig::parse(json).expect("a stream VPN may carry Arti guard connections");

    let direct = json.replace(
        r#"{
                    "type":"vless",
                    "server":"vpn.example",
                    "port":443,
                    "uuid":"d0cf0001-0000-4000-8000-000000000000"
                }"#,
        r#"{"type":"direct"}"#,
    );
    let error = EngineConfig::parse(&direct).unwrap_err().to_string();
    assert!(error.contains("stream proxy"));
}

#[test]
fn i2p_requires_loopback_fake_ip_and_explicit_route() {
    let non_loopback = r#"{
            "schema_version":1,
            "outbound":{"type":"i2p","socks_address":"192.0.2.1:4447"},
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
            "dns":{"mode":"fake_ip"}
        }"#;
    assert!(EngineConfig::parse(non_loopback).is_err());

    let no_fake_ip = r#"{
            "schema_version":1,
            "outbound":{"type":"i2p","socks_address":"127.0.0.1:4447"},
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(EngineConfig::parse(no_fake_ip).is_err());

    let missing_outbound = r#"{
            "schema_version":1,
            "outbound":{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"},
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
            "dns":{"mode":"fake_ip"},
            "routes":[{"domain_suffixes":[".i2p"],"action":{"type":"i2p"}}]
        }"#;
    assert!(EngineConfig::parse(missing_outbound).is_err());
}

#[test]
fn i2p_socks_credentials_are_paired_bounded_and_redacted() {
    let authenticated = r#"{
            "schema_version":1,
            "outbound":{
                "type":"i2p",
                "socks_address":"127.0.0.1:4447",
                "username":"foxhole",
                "password":"i2p-contract-secret"
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
            "dns":{"mode":"fake_ip"}
        }"#;
    let parsed = EngineConfig::parse(authenticated).expect("paired credentials are valid");
    assert!(!format!("{parsed:?}").contains("i2p-contract-secret"));

    let password_only = authenticated.replace(r#""username":"foxhole","#, "");
    assert!(EngineConfig::parse(&password_only).is_err());

    let empty_password =
        authenticated.replace(r#""password":"i2p-contract-secret""#, r#""password":"""#);
    assert!(EngineConfig::parse(&empty_password).is_err());

    let oversized_username = authenticated.replace(
        r#""username":"foxhole""#,
        &format!(r#""username":"{}""#, "x".repeat(256)),
    );
    assert!(EngineConfig::parse(&oversized_username).is_err());
}

#[test]
fn validates_unified_application_policy_and_private_network_switches() {
    let split = r#"{
            "schema_version":1,
            "outbound":{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"},
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"},
            "traffic":{
                "default_action":"direct",
                "tor_enabled":false,
                "i2p_enabled":false,
                "applications":[
                    {"package":"com.example.vpn","action":"vpn"},
                    {"package":"com.example.blocked","action":"block"}
                ]
            }
        }"#;
    let config = EngineConfig::parse(split).unwrap();
    assert!(config.traffic.requires_identity());

    let duplicate = split.replace(
        "com.example.blocked\",\"action\":\"block",
        "com.example.vpn\",\"action\":\"block",
    );
    assert!(EngineConfig::parse(&duplicate).is_err());

    let disabled_tor = split.replace(
        "{\"package\":\"com.example.vpn\",\"action\":\"vpn\"}",
        "{\"package\":\"com.example.vpn\",\"action\":\"tor\"}",
    );
    assert!(EngineConfig::parse(&disabled_tor).is_err());

    let missing_i2p = split.replace("\"i2p_enabled\":false", "\"i2p_enabled\":true");
    assert!(EngineConfig::parse(&missing_i2p).is_err());
}

/// The TCP idle window is its own field, and its default is a decision.
///
/// The mechanism that reads it cannot see a TCP keepalive — the stack
/// answers the empty ACK itself and the relay is never woken — so the value
/// is the only thing separating "this connection is dead" from "this
/// connection is a push channel between notifications". At the UDP window's
/// 300 s those two sentences were the same one.
///
/// The floor asserted here is thirty minutes because that is the top of the
/// band real keepalive intervals live in (~15 min cellular, 28–29 min
/// Wi-Fi, RFC 2177's 29-minute `IDLE` re-issue); a window that merely
/// *reaches* the top of that band is a window with no margin. The shipped
/// value doubles it. Pinned rather than asserted loosely because a later
/// pass tuning this number downwards for memory is exactly the change that
/// should have to read the paragraph above.
#[test]
fn the_tcp_idle_window_is_separate_from_the_udp_one_and_outlasts_keepalives() {
    let runtime = RuntimeConfig::default();
    assert_eq!(
        runtime.idle_timeout_s, 300,
        "the UDP window is unchanged; this pass moved TCP off it, not it off TCP"
    );
    assert!(
        runtime.tcp_idle_timeout_s >= 1_800,
        "an established TCP relay whose keepalives this core cannot see must \
             not be closed inside any keepalive interval in use; {} s is inside \
             the 15–29 minute band every push channel sits in",
        runtime.tcp_idle_timeout_s
    );

    // Additive: a config written before the field existed still parses, and
    // gets the decision rather than the UDP number.
    let without = r#"{"schema_version":1,"outbound":{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"},"tun":{"mtu":1400,"ipv4":"10.0.0.1"},"runtime":{"idle_timeout_s":60}}"#;
    let parsed = EngineConfig::parse(without).expect("a config that predates the field");
    assert_eq!(parsed.runtime.idle_timeout_s, 60);
    assert_eq!(
        parsed.runtime.tcp_idle_timeout_s, runtime.tcp_idle_timeout_s,
        "an app that only knows the old field must not silently hand its \
             value to the TCP relay as well"
    );

    // And it is settable, within the same range its UDP twin has.
    let with = without.replace("\"idle_timeout_s\":60", "\"tcp_idle_timeout_s\":900");
    assert_eq!(
        EngineConfig::parse(&with)
            .expect("an explicit window")
            .runtime
            .tcp_idle_timeout_s,
        900
    );
    let too_long = without.replace("\"idle_timeout_s\":60", "\"tcp_idle_timeout_s\":86401");
    assert!(EngineConfig::parse(&too_long).is_err());
    let too_short = without.replace("\"idle_timeout_s\":60", "\"tcp_idle_timeout_s\":4");
    assert!(EngineConfig::parse(&too_short).is_err());
}

#[test]
fn rejects_unknown_fields_and_bad_limits() {
    let unknown = r#"{"schema_version":1,"outbound":{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000","backdoor":true},"tun":{"mtu":1400,"ipv4":"10.0.0.1"}}"#;
    assert!(EngineConfig::parse(unknown).is_err());

    let bad_workers = r#"{"schema_version":1,"outbound":{"type":"vless","server":"s","port":1,"uuid":"d0cf0001-0000-4000-8000-000000000000"},"tun":{"mtu":1400,"ipv4":"10.0.0.1"},"runtime":{"worker_threads":99}}"#;
    assert!(EngineConfig::parse(bad_workers).is_err());
}

#[test]
fn validates_tls_before_runtime_and_redacts_vless_credential() {
    let disabled_with_options = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless",
                "server":"example.com",
                "port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "tls":{"enabled":false,"insecure":true}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(EngineConfig::parse(disabled_with_options).is_err());

    let invalid_pin = r#"{
            "schema_version":1,
            "outbound":{
                "type":"vless",
                "server":"example.com",
                "port":443,
                "uuid":"d0cf0001-0000-4000-8000-000000000000",
                "tls":{"enabled":true,"pinned_spki_sha256":"dG9vLXNob3J0"}
            },
            "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
        }"#;
    assert!(EngineConfig::parse(invalid_pin).is_err());

    let parsed = EngineConfig::parse(
        r#"{
                "schema_version":1,
                "outbound":{
                    "type":"vless",
                    "server":"example.com",
                    "port":443,
                    "uuid":"d0cf0001-0000-4000-8000-000000000000"
                },
                "tun":{"mtu":1400,"ipv4":"10.0.0.1"}
            }"#,
    )
    .unwrap();
    assert!(!format!("{parsed:?}").contains("d0cf0001"));
}

fn hysteria2_timing_json(timing: &str) -> String {
    format!(
        r#"{{
            "schema_version":1,
            "outbound":{{
                "type":"hysteria2",
                "server":"hy2.example",
                "port":443,
                "password":"hy2-auth-secret"{timing},
                "tls":{{"enabled":true}}
            }},
            "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}
        }}"#
    )
}

fn hysteria2_timing(timing: &str) -> Result<Hysteria2Config, ConfigError> {
    let parsed = EngineConfig::parse(&hysteria2_timing_json(timing))?;
    let OutboundConfig::Hysteria2(hy2) = parsed.outbound else {
        panic!("profile must be Hysteria2");
    };
    Ok(hy2)
}

/// A profile written before these fields existed must keep the exact QUIC
/// timing the hardcoded build used, or every live server sees new behaviour.
#[test]
fn defaults_hysteria2_quic_timing_to_the_previously_hardcoded_values() {
    let hy2 = hysteria2_timing("").unwrap();
    assert_eq!(hy2.keepalive_ms, 10_000);
    assert_eq!(hy2.idle_timeout_ms, 30_000);
}

#[test]
fn accepts_profile_driven_hysteria2_quic_timing() {
    let hy2 = hysteria2_timing(r#","keepalive_ms":45000,"idle_timeout_ms":120000"#).unwrap();
    assert_eq!(hy2.keepalive_ms, 45_000);
    assert_eq!(hy2.idle_timeout_ms, 120_000);
}

#[test]
fn refuses_hysteria2_quic_timing_outside_supported_ranges() {
    for invalid in [
        r#","keepalive_ms":999"#,
        r#","keepalive_ms":120001,"idle_timeout_ms":600000"#,
        r#","idle_timeout_ms":4999"#,
        r#","idle_timeout_ms":600001"#,
    ] {
        assert!(
            hysteria2_timing(invalid).is_err(),
            "timing {invalid} must be refused"
        );
    }
}

/// A keepalive that is not comfortably below the idle timeout cannot hold the
/// path open once a single PING is lost.
#[test]
fn refuses_hysteria2_keepalive_that_cannot_hold_the_idle_timeout_open() {
    for invalid in [
        r#","keepalive_ms":15000,"idle_timeout_ms":30000"#,
        r#","keepalive_ms":20000,"idle_timeout_ms":30000"#,
        r#","keepalive_ms":60000,"idle_timeout_ms":10000"#,
    ] {
        assert!(
            hysteria2_timing(invalid).is_err(),
            "timing {invalid} must be refused"
        );
    }
    assert!(hysteria2_timing(r#","keepalive_ms":14999,"idle_timeout_ms":30000"#).is_ok());
}
