use super::*;
use crate::FlowMetrics;
use foxcore_api::{
    BlockReason, Destination, DnsConfig, EventSink, FlowAttributor, FlowContext, IpTransport,
    RouteAction, RuntimeConfig,
};
use foxcore_dns::DnsCache;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_trafficmap::{FlowLane, TrafficMap};
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn fake_ip_destination_is_restored_to_its_domain() {
    let dns = DnsCache::new(8);
    let query = dns_query(0x1234);
    let response = dns
        .fake_response(
            &query,
            "198.18.0.0/15".parse().unwrap(),
            "fd00::/120".parse().unwrap(),
            300,
        )
        .unwrap();
    let fake_ip = IpAddr::V4(Ipv4Addr::new(
        response[response.len() - 4],
        response[response.len() - 3],
        response[response.len() - 2],
        response[response.len() - 1],
    ));

    let context = context_for(
        7,
        IpTransport::Tcp,
        SocketAddr::from(([10, 77, 0, 2], 49152)),
        SocketAddr::new(fake_ip, 443),
        &dns,
    );

    assert_eq!(context.generation, 7);
    assert_eq!(context.destination, Destination::new("example.com", 443));
    assert_eq!(context.domain_hint.as_deref(), Some("example.com"));
    assert_eq!(
        context.source,
        Some(SocketAddr::from(([10, 77, 0, 2], 49152)))
    );
}

#[test]
fn hot_reload_atomically_selects_the_new_named_outbound() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let backup = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(
        OutboundRegistry::new(
            default.clone(),
            HashMap::from([("backup".into(), backup.clone())]),
        )
        .unwrap(),
    );
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(
                Vec::new(),
                RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
            ),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    let context = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));

    let initial = policy.current.load();
    let selected = engine.select_outbound(&context, &initial.routes).unwrap();
    assert!(Arc::ptr_eq(&selected, &default));
    drop(initial);

    assert_eq!(
        policy
            .reload(
                Some(1),
                RouteTable::compile(
                    Vec::new(),
                    RouteAction::Outbound(foxcore_api::OutboundId("backup".into())),
                ),
                DnsConfig::default(),
            )
            .unwrap(),
        2
    );
    let reloaded = policy.current.load();
    let selected = engine.select_outbound(&context, &reloaded.routes).unwrap();
    assert!(Arc::ptr_eq(&selected, &backup));
}

/// The trap the packet path introduces: in packet-tunnel mode the registry's
/// default is a placeholder, so a stream flow routed to the primary must be
/// refused rather than handed that placeholder. Getting this wrong is a
/// clearnet leak that looks like a working tunnel.
#[test]
fn a_stream_flow_bound_for_the_packet_tunnel_is_blocked_not_sent_direct() {
    let placeholder = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(placeholder));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let routes = RouteTable::compile(
        Vec::new(),
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
    );
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(
                Vec::new(),
                RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
            ),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let context = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));

    let leaking = FlowEngine::new(FlowEngineContext {
        outbounds: outbounds.clone(),
        direct: direct.clone(),
        policy: policy.clone(),
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    assert!(
        leaking.select_outbound(&context, &routes).is_some(),
        "without the flag the placeholder is handed out — this is the leak the flag closes"
    );

    let guarded = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: true,
        connections: Arc::new(TrafficMap::default()),
    });
    assert!(
        guarded.select_outbound(&context, &routes).is_none(),
        "a flow that belongs to the L3 tunnel must never leave through the stack"
    );
}

#[test]
fn onion_destination_cannot_fall_back_to_direct_or_default() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(default));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    let context = FlowContext::new(1, IpTransport::Tcp, Destination::new("hidden.onion", 80));
    let current = policy.current.load();

    assert!(engine.select_outbound(&context, &current.routes).is_none());
}

#[test]
fn i2p_destination_cannot_fall_back_to_direct_or_default() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(default));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    let context = FlowContext::new(1, IpTransport::Tcp, Destination::new("service.i2p", 80));
    let current = policy.current.load();

    assert!(engine.select_outbound(&context, &current.routes).is_none());
}

/// The route on a row is the one that carried the bytes, including which
/// member of a group it went through.
#[test]
fn a_flow_records_the_lane_protocol_and_group_it_actually_used() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(default));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    let current = policy.current.load();

    let split = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    let selected = engine.select_route(&split, &current.routes).unwrap();
    assert_eq!(selected.route.lane, FlowLane::Direct);
    assert_eq!(selected.route.outbound, "direct");
    assert!(
        selected.route.outbound_id.is_none(),
        "a direct flow was never sent to a named outbound"
    );

    // An overlay destination is re-routed by the gate whatever the rule
    // said, so the map has to record the gate's answer, not the rule's.
    let onion = FlowContext::new(1, IpTransport::Tcp, Destination::new("hidden.onion", 80));
    assert_eq!(
        engine.select_route(&onion, &current.routes).err(),
        Some(BlockReason::Policy)
    );
}

fn dns_policy_for_continuation(
    generation: u64,
    config: DnsConfig,
    cache: Option<Arc<DnsCache>>,
    route: RouteAction,
) -> FlowPolicyStore {
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    FlowPolicyStore::new_with_trusted_rule_sets_and_dns_continuation(
        generation,
        RouteTable::compile(Vec::new(), route),
        config,
        Arc::new(OutboundRegistry::single(direct.clone())),
        direct,
        Arc::new(FlowMetrics::default()),
        EventSink::none(),
        Vec::new(),
        Vec::new(),
        cache,
    )
    .unwrap()
}

fn synthetic_address(cache: &DnsCache, query: &[u8], config: &DnsConfig) -> IpAddr {
    let response = cache
        .fake_response(
            query,
            config.fake_ipv4_pool,
            config.fake_ipv6_pool,
            config.fake_ttl_s,
        )
        .unwrap();
    let bytes = &response[response.len() - 4..];
    IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

#[test]
fn explicit_dns_continuation_keeps_allocator_and_uses_only_the_new_policy() {
    let config = DnsConfig {
        mode: foxcore_api::DnsMode::FakeIp,
        ..Default::default()
    };
    let previous = dns_policy_for_continuation(1, config.clone(), None, RouteAction::Direct);
    let query = dns_query(7);
    let cache = previous.dns_for_continuation();
    let address = synthetic_address(&cache, &query, &config);
    let response = cache
        .fake_response(&query, config.fake_ipv4_pool, config.fake_ipv6_pool, 300)
        .unwrap();
    assert!(cache.cache_response(&query, &response, true));
    let identity = foxcore_dns::DnsIdentity::new(10001, vec!["app".into()]);
    cache.learn_route_hints(&query, &response, &identity);
    assert!(cache.route_hints(&identity, address).is_some());

    let successor = dns_policy_for_continuation(
        2,
        config.clone(),
        Some(previous.dns_for_continuation()),
        RouteAction::Block,
    );
    let current = successor.current.load();
    assert!(current.dns.cached_response(&query, false).is_none());
    assert!(current.dns.route_hints(&identity, address).is_none());
    assert_eq!(
        current.dns.fake_domain(address).as_deref(),
        Some("example.com")
    );
    let context = context_for(
        2,
        IpTransport::Tcp,
        SocketAddr::from(([10, 77, 0, 2], 49152)),
        SocketAddr::new(address, 443),
        &current.dns,
    );
    assert_eq!(current.routes.decide(&context), &RouteAction::Block);
    assert!(!Arc::ptr_eq(&successor.outbounds, &previous.outbounds));
    let mut other_query = dns_query(8);
    other_query[13] = b'a';
    assert_ne!(
        synthetic_address(&current.dns, &other_query, &config),
        address
    );
}

#[test]
fn explicit_dns_continuation_reduced_capacity_cannot_withdraw_live_promises() {
    let config = DnsConfig {
        mode: foxcore_api::DnsMode::FakeIp,
        ..Default::default()
    };
    let previous = dns_policy_for_continuation(1, config.clone(), None, RouteAction::Direct);
    let cache = previous.dns_for_continuation();
    let first = synthetic_address(&cache, &dns_query(1), &config);
    let mut query = dns_query(2);
    query[13] = b'a';
    let second = synthetic_address(&cache, &query, &config);
    let reduced = DnsConfig {
        cache_size: 1,
        ..config.clone()
    };
    let successor =
        dns_policy_for_continuation(2, reduced.clone(), Some(cache), RouteAction::Direct);
    let current = successor.current.load();
    assert_eq!(
        current.dns.fake_domain(first).as_deref(),
        Some("example.com")
    );
    assert_eq!(
        current.dns.fake_domain(second).as_deref(),
        Some("axample.com")
    );
    query[13] = b'b';
    assert!(
        current
            .dns
            .fake_response(&query, reduced.fake_ipv4_pool, reduced.fake_ipv6_pool, 300)
            .is_none()
    );
}

#[test]
fn explicit_dns_continuation_does_not_reset_original_expiry() {
    let config = DnsConfig {
        mode: foxcore_api::DnsMode::FakeIp,
        fake_ttl_s: 1,
        ..Default::default()
    };
    let previous = dns_policy_for_continuation(1, config.clone(), None, RouteAction::Direct);
    let cache = previous.dns_for_continuation();
    let address = synthetic_address(&cache, &dns_query(1), &config);
    std::thread::sleep(std::time::Duration::from_millis(700));
    let successor = dns_policy_for_continuation(
        2,
        DnsConfig {
            fake_ttl_s: 300,
            ..config
        },
        Some(cache),
        RouteAction::Direct,
    );
    let current = successor.current.load();
    assert!(current.dns.fake_domain(address).is_some());
    std::thread::sleep(std::time::Duration::from_millis(450));
    assert!(
        current.dns.fake_domain(address).is_none(),
        "handoff extended the original TTL"
    );
}
