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
