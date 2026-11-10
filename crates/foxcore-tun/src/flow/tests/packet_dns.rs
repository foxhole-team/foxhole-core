use super::*;
use crate::split::{FlowKey, PacketRoute};
use etherparse::PacketBuilder;

fn make_engine() -> FlowEngine {
    let outbounds = Arc::new(OutboundRegistry::single(Arc::new(Outbound::direct(
        ProtectedDialer::host(),
    ))));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let rule = foxcore_api::RouteRule {
        exact_domains: vec!["example.com".into()],
        action: RouteAction::Direct,
        ..serde_json::from_value(json!({"action":{"type":"direct"}})).unwrap()
    };
    let routes = RouteTable::compile(
        vec![rule],
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
    );
    let metrics = Arc::new(FlowMetrics::default());
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
            DnsConfig {
                packet_resolvers: vec!["10.8.0.1".parse().unwrap()],
                ..Default::default()
            },
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        metrics,
        attributor: owner(10001),
        runtime: RuntimeConfig::default(),
        events: EventSink::none(),
        packet_tunnel: true,
        connections: Arc::new(TrafficMap::default()),
    })
}
fn owner(uid: u32) -> FlowAttributor {
    FlowAttributor::new(move |_, _, _| {
        Ok(Some(foxcore_api::FlowIdentity {
            uid,
            packages: vec!["app".into()],
            signing_digest: None,
        }))
    })
}
fn domain_routes(action: &str) -> RouteTable {
    RouteTable::compile(
        vec![
            serde_json::from_value(json!({"exact_domains":["example.com"],
            "action":{"type":action}}))
            .unwrap(),
        ],
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
    )
}
fn packet(payload: &[u8], response: bool) -> Vec<u8> {
    let (src, dst, sport, dport) = if response {
        ([10, 8, 0, 1], [10, 0, 0, 2], 53, 44000)
    } else {
        ([10, 0, 0, 2], [10, 8, 0, 1], 44000, 53)
    };
    let mut bytes = Vec::new();
    PacketBuilder::ipv4(src, dst, 64)
        .udp(sport, dport)
        .write(&mut bytes, payload)
        .unwrap();
    bytes
}
#[cfg_attr(miri, ignore = "tokio attribution worker")]
#[tokio::test]
async fn packet_dns_direct_routes_require_same_owner_and_current_dns_authority() {
    let engine = make_engine();
    let query = dns_query(0x1234);
    let request = packet(&query, false);
    let dns_key = FlowKey::from_packet(&request).unwrap();
    let flow = FlowKey {
        destination: "203.0.113.9".parse().unwrap(),
        destination_port: 443,
        source_port: 44001,
        protocol: 6,
        ..dns_key
    };
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Block);
    assert_eq!(
        engine.decide_packet(dns_key).await.route,
        PacketRoute::Tunnel
    );
    let mut answer = query.clone();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    engine.packet_dns.query(&request);
    engine.packet_dns.response(&packet(&answer, true));
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Stack);
    let mut other = engine.clone();
    other.attributor = owner(10002);
    assert_eq!(other.decide_packet(flow).await.route, PacketRoute::Block);
    let unselected_resolver = FlowKey {
        destination: "10.8.0.3".parse().unwrap(),
        ..dns_key
    };
    assert_eq!(
        engine.decide_packet(unselected_resolver).await.route,
        PacketRoute::Block
    );
    engine.policy.network_changed();
    engine.packet_dns.response(&packet(&answer, true));
    // A physical roam does not change the authenticated peer's DNS authority.
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Stack);
    let mut changed_dns = engine.policy.current.load().dns_config.clone();
    changed_dns
        .packet_resolvers
        .push("10.8.0.3".parse().unwrap());
    let rule = serde_json::from_value(json!({
        "exact_domains":["example.com"],"action":{"type":"direct"}
    }))
    .unwrap();
    engine
        .policy
        .reload(
            None,
            RouteTable::compile(
                vec![rule],
                RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
            ),
            changed_dns,
        )
        .unwrap();
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Block);
    assert_eq!(
        engine.decide_packet(dns_key).await.route,
        PacketRoute::Tunnel
    );
    engine.packet_dns.query(&request);
    engine.packet_dns.response(&packet(&answer, true));
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Stack);
}

#[cfg_attr(miri, ignore = "tokio attribution worker")]
#[tokio::test]
async fn managed_packet_dns_prevents_shared_android_cache_without_global_permissions() {
    let engine = make_engine();
    let query = dns_query(0x1234);
    let request = packet(&query, false);
    let key = FlowKey::from_packet(&request).unwrap();
    assert_eq!(engine.decide_packet(key).await.route, PacketRoute::Tunnel);
    assert!(engine.packet_dns.query(&request));
    let mut answer = query.clone();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    let mut response = bytes::BytesMut::from(packet(&answer, true).as_slice());
    assert!(engine.packet_dns.response_for_tun(&mut response));
    // The AOSP per-network cache does not retain a zero-TTL answer.
    let ttl = 20 + 8 + query.len() + 6;
    assert_eq!(&response[ttl..ttl + 4], &[0; 4]);
    let flow = FlowKey {
        destination: "203.0.113.9".parse().unwrap(),
        destination_port: 443,
        source_port: 44001,
        protocol: 6,
        ..key
    };
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Stack);
    let mut second = engine.clone();
    second.attributor = owner(10002);
    assert_eq!(second.decide_packet(flow).await.route, PacketRoute::Block);
    // A second caller must perform its own lookup, then receives its own binding.
    assert_eq!(second.decide_packet(key).await.route, PacketRoute::Tunnel);
    assert!(second.packet_dns.query(&request));
    let mut response = bytes::BytesMut::from(packet(&answer, true).as_slice());
    assert!(second.packet_dns.response_for_tun(&mut response));
    assert_eq!(&response[ttl..ttl + 4], &[0; 4]);
    assert_eq!(second.decide_packet(flow).await.route, PacketRoute::Stack);
}

#[cfg_attr(miri, ignore = "tokio attribution worker")]
#[tokio::test]
async fn packet_dns_binding_retention_never_retains_a_route_permission() {
    let engine = make_engine();
    let query = dns_query(7);
    let request = packet(&query, false);
    let key = FlowKey::from_packet(&request).unwrap();
    assert_eq!(engine.decide_packet(key).await.route, PacketRoute::Tunnel);
    assert!(engine.packet_dns.query(&request));
    let mut answer = query.clone();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    engine.packet_dns.response(&packet(&answer, true));
    let flow = FlowKey {
        destination: "203.0.113.9".parse().unwrap(),
        destination_port: 443,
        source_port: 44001,
        protocol: 6,
        ..key
    };
    assert_eq!(engine.decide_packet(flow).await.route, PacketRoute::Stack);
    for (action, expected) in [
        ("block", PacketRoute::Block),
        ("direct", PacketRoute::Stack),
    ] {
        let dns = engine.policy.current.load().dns_config.clone();
        let rule = serde_json::from_value(json!({"exact_domains":["example.com"],
            "action":{"type":action}}))
        .unwrap();
        engine
            .policy
            .reload(
                None,
                RouteTable::compile(
                    vec![rule],
                    RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
                ),
                dns,
            )
            .unwrap();
        assert_eq!(engine.decide_packet(flow).await.route, expected);
    }
}

#[test]
fn managed_packet_dns_mode_is_fixed_before_the_first_lookup() {
    let engine = make_engine();
    let snapshot = engine.policy.current.load_full();
    let mut unmanaged = snapshot.dns_config.clone();
    unmanaged.packet_resolvers.clear();
    let error = engine
        .policy
        .reload(None, domain_routes("direct"), unmanaged.clone())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(engine.policy.revision(), snapshot.revision);
    assert_eq!(engine.policy.current.load().dns_config, snapshot.dns_config);
    let store = FlowPolicyStore::new(
        1,
        domain_routes("direct"),
        unmanaged,
        engine.outbounds.clone(),
        engine.direct.clone(),
        engine.metrics.clone(),
        EventSink::none(),
    )
    .unwrap();
    let error = store
        .reload(None, domain_routes("direct"), snapshot.dns_config.clone())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(store.current.load().dns_config.packet_resolvers.is_empty());
}

#[cfg_attr(miri, ignore = "tokio attribution worker")]
#[tokio::test]
async fn packet_dns_continuation_requires_the_same_peer_and_dns_authority() {
    let engine = make_engine();
    let query = dns_query(7);
    let request = packet(&query, false);
    let key = FlowKey::from_packet(&request).unwrap();
    assert_eq!(engine.decide_packet(key).await.route, PacketRoute::Tunnel);
    assert!(engine.packet_dns.query(&request));
    let mut answer = query.clone();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    engine.packet_dns.response(&packet(&answer, true));
    let flow = FlowKey {
        destination: "203.0.113.9".parse().unwrap(),
        destination_port: 443,
        source_port: 44001,
        protocol: 6,
        ..key
    };
    let peer = engine.policy.packet_dns_peer;
    for same_peer in [true, false] {
        let mut next_peer = peer;
        if !same_peer {
            next_peer[0] ^= 1;
        }
        let dns = engine.policy.current.load().dns_config.clone();
        let policy = FlowPolicyStore::new_with_trusted_rule_sets_and_dns_continuation(
            2,
            domain_routes("direct"),
            dns,
            engine.outbounds.clone(),
            engine.direct.clone(),
            engine.metrics.clone(),
            EventSink::none(),
            Vec::new(),
            Vec::new(),
            Some(engine.policy.dns_for_continuation()),
        )
        .unwrap()
        .with_packet_dns_peer(next_peer);
        let mut successor = engine.clone();
        successor.policy = Arc::new(policy);
        successor.packet_dns = Arc::new(crate::packet_dns::PacketDnsTracker::for_policy(
            successor.policy.clone(),
        ));
        assert_eq!(
            successor.decide_packet(flow).await.route,
            if same_peer {
                PacketRoute::Stack
            } else {
                PacketRoute::Block
            }
        );
    }
}
#[cfg_attr(miri, ignore = "tokio attribution worker")]
#[tokio::test]
async fn packet_dns_bootstrap_never_bypasses_missing_identity_or_numeric_denial() {
    let mut engine = make_engine();
    engine.attributor = FlowAttributor::none();
    let dns = FlowKey {
        source: "10.0.0.2".parse().unwrap(),
        destination: "10.8.0.1".parse().unwrap(),
        source_port: 44000,
        destination_port: 53,
        protocol: 17,
    };
    assert_eq!(engine.decide_packet(dns).await.route, PacketRoute::Block);
    let engine = make_engine();
    let snapshot = engine.policy.current.load();
    let routes = RouteTable::compile(
        vec![
            serde_json::from_value(json!({"cidrs":["10.8.0.1/32"],"action":{"type":"block"}}))
                .unwrap(),
        ],
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
    );
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
            snapshot.dns_config.clone(),
            engine.outbounds.clone(),
            engine.direct.clone(),
            engine.metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    let mut blocked = engine.clone();
    blocked.policy = policy;
    blocked.packet_dns = Arc::new(crate::packet_dns::PacketDnsTracker::for_policy(
        blocked.policy.clone(),
    ));
    assert_eq!(blocked.decide_packet(dns).await.route, PacketRoute::Block);
}

#[cfg_attr(miri, ignore = "tokio attribution worker")]
#[tokio::test]
async fn packet_dns_metadata_without_domain_rules_preserves_unattributed_raw_dns() {
    let mut engine = make_engine();
    let dns_config = engine.policy.current.load().dns_config.clone();
    engine.policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(
                Vec::new(),
                RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
            ),
            dns_config,
            engine.outbounds.clone(),
            engine.direct.clone(),
            engine.metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    engine.attributor = FlowAttributor::none();
    engine.packet_dns = Arc::new(crate::packet_dns::PacketDnsTracker::for_policy(
        engine.policy.clone(),
    ));
    let dns = FlowKey {
        source: "10.0.0.2".parse().unwrap(),
        destination: "10.8.0.1".parse().unwrap(),
        source_port: 44000,
        destination_port: 53,
        protocol: 17,
    };
    assert_eq!(engine.decide_packet(dns).await.route, PacketRoute::Tunnel);
}
