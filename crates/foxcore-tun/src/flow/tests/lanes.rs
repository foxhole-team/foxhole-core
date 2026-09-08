use super::*;
use crate::FlowMetrics;
use foxcore_api::{
    BlockReason, Destination, DnsConfig, EventSink, FlowAttributor, FlowContext, IpTransport,
    RuntimeConfig,
};
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_trafficmap::{FlowLane, TrafficMap};
use std::sync::Arc;

#[test]
fn shared_dns_addresses_cannot_rebind_another_applications_route() {
    use foxcore_dns::{DnsCache, DnsIdentity};
    use std::net::IpAddr;
    let routes = RouteTable::compile_with_traffic(
        vec![
            serde_json::from_value(json!({
                "exact_domains": ["protected.invalid"], "action": {"type": "block"}
            }))
            .unwrap(),
        ],
        RouteAction::Direct,
        Default::default(),
        false,
        false,
    );
    for address in ["203.0.113.9", "2001:db8::9"] {
        for reverse_order in [false, true] {
            let cache = DnsCache::new(8);
            let address: IpAddr = address.parse().unwrap();
            let record_type: u16 = if address.is_ipv4() { 1 } else { 28 };
            let mut exchanges = [(10001, "protected.invalid"), (10002, "allowed.invalid")];
            if reverse_order {
                exchanges.reverse();
            }
            for (uid, domain) in exchanges {
                let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                for label in domain.split('.') {
                    query.push(label.len() as u8);
                    query.extend_from_slice(label.as_bytes());
                }
                query.push(0);
                query.extend_from_slice(&record_type.to_be_bytes());
                query.extend_from_slice(&1_u16.to_be_bytes());
                let mut answer = query.clone();
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer[7] = 1;
                answer.extend_from_slice(&[0xc0, 0x0c]);
                answer.extend_from_slice(&record_type.to_be_bytes());
                answer.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                let bytes = match address {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                };
                answer.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                answer.extend_from_slice(&bytes);
                cache.learn_route_hints(
                    &query,
                    &answer,
                    &DnsIdentity::new(uid, vec![format!("app.{uid}")]),
                );
            }
            for transport in [IpTransport::Tcp, IpTransport::Udp] {
                for (uid, expected) in [(10001, RouteAction::Block), (10002, RouteAction::Direct)] {
                    let mut context = context_for(
                        1,
                        transport,
                        "127.0.0.1:40000".parse().unwrap(),
                        (address, 443).into(),
                        &cache,
                    );
                    context.uid = Some(uid);
                    context.packages = vec![format!("app.{uid}")];
                    assert!(bind_dns_context(&mut context, &routes, &cache));
                    assert_eq!(routes.decide(&context), &expected);
                    context.uid = Some(10003);
                    context.domain_hint = None;
                    assert!(!bind_dns_context(&mut context, &routes, &cache));
                }
            }
        }
    }
}

#[test]
fn ordinary_reloads_preserve_revocation_of_every_live_epoch() {
    for kill in [false, true] {
        let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let policy = FlowPolicyStore::new(
            1,
            compiled(traffic(false), false, false),
            DnsConfig::default(),
            Arc::new(OutboundRegistry::single(direct.clone())),
            direct,
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap();
        let mut live = vec![policy.current.load().revocation.clone()];
        for revision in 1..=2 {
            policy
                .reload(
                    Some(revision),
                    compiled(traffic(false), false, false),
                    DnsConfig::default(),
                )
                .unwrap();
            live.push(policy.current.load().revocation.clone());
        }
        assert!(live.iter().all(|token| !token.is_cancelled()));
        if kill {
            policy
                .reload(
                    Some(3),
                    compiled(traffic(true), false, false),
                    DnsConfig::default(),
                )
                .unwrap();
        } else {
            policy.network_changed();
        }
        assert!(live.iter().all(|token| token.is_cancelled()));
        assert!(!policy.current.load().revocation.is_cancelled());
    }
}

#[test]
fn network_reload_and_rule_install_share_one_writer_transaction() {
    use std::sync::{Barrier, TryLockError};
    let (mut source, bundle) = signed_rule_set();
    source.required = false;
    let dns = DnsConfig {
        rule_sets: vec![source],
        ..DnsConfig::default()
    };
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            compiled(traffic(false), false, false),
            dns.clone(),
            Arc::new(OutboundRegistry::single(direct.clone())),
            direct,
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        let reload = scope.spawn(|| {
            barrier.wait();
            policy
                .reload(None, compiled(traffic(true), false, false), dns)
                .unwrap()
        });
        let install = scope.spawn(|| {
            barrier.wait();
            policy.install_dns_rule_set(bundle).unwrap()
        });
        policy.network_changed_transaction(|| {
            assert!(matches!(
                policy.reload.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            barrier.wait();
            assert_eq!(policy.revision(), 1);
        });
        let mut revisions = [reload.join().unwrap(), install.join().unwrap()];
        revisions.sort();
        assert_eq!(revisions, [2, 3]);
    });
    assert_eq!(policy.revision(), 3);
    assert!(policy.gates().kill_switch());
    assert_eq!(
        policy.reload.lock().unwrap().rule_sets["foxhole-test-dns"]
            .metadata()
            .sequence,
        7
    );
}

/// §6.4: the firewall must not stick. Disarming has to reach the next flow
/// with no restart, and arming has to reach flows that are already running
/// — a kill switch that only applies to connections nobody opened yet is
/// not a kill switch. Both directions are exercised on a real transition,
/// because a config that merely parses proves neither.
#[test]
fn arming_the_kill_switch_revokes_live_flows_and_disarming_frees_the_next_one() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(default));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            compiled(traffic(false), false, false),
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

    // A flow that is already running holds the snapshot it was decided
    // under; this is the handle its relay is selecting on.
    let live = policy.current.load().revocation.clone();
    assert!(
        engine
            .select_route(&context, &policy.current.load().routes)
            .is_ok()
    );

    policy
        .reload(
            Some(1),
            compiled(traffic(true), false, false),
            DnsConfig::default(),
        )
        .unwrap();
    assert!(
        live.is_cancelled(),
        "an armed kill switch must tear down the connections that are already open"
    );
    assert_eq!(
        engine
            .select_route(&context, &policy.current.load().routes)
            .err(),
        Some(BlockReason::KillSwitch)
    );

    let armed = policy.current.load().revocation.clone();
    policy
        .reload(
            Some(2),
            compiled(traffic(false), false, false),
            DnsConfig::default(),
        )
        .unwrap();
    assert!(
        engine
            .select_route(&context, &policy.current.load().routes)
            .is_ok(),
        "disarming must free the next flow without a restart"
    );
    assert!(
        !armed.is_cancelled(),
        "disarming revokes nothing: it is the permissive direction"
    );
}

#[test]
fn a_network_change_revokes_old_sockets_without_poisoning_new_flows() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let policy = FlowPolicyStore::new(
        1,
        compiled(traffic(false), false, false),
        DnsConfig::default(),
        Arc::new(OutboundRegistry::single(default)),
        Arc::new(Outbound::direct(ProtectedDialer::host())),
        Arc::new(FlowMetrics::default()),
        EventSink::none(),
    )
    .unwrap();

    let before = policy.current.load().revocation.clone();
    let revision = policy.revision();
    policy.network_changed();
    let after = policy.current.load().revocation.clone();

    assert!(before.is_cancelled(), "old-network flows must reconnect");
    assert!(
        !after.is_cancelled(),
        "the replacement snapshot must accept new-network flows"
    );
    assert_eq!(
        policy.revision(),
        revision,
        "a network move is not a policy change"
    );
}

/// The whole contract, in one test: four lanes carrying four applications at
/// the same time, and each lane that can fail failing in turn without
/// touching the other three.
///
/// Both halves of every failure are asserted, because only one of them is
/// obvious. The other three lanes keep routing — that is the availability
/// half, and it is what the all-or-nothing build could not do. And the lane
/// that failed is *refused*, not answered from somewhere else — that is the
/// half that matters more: a VPN whose apps quietly went out clearnet the
/// moment the tunnel failed to build would look like a working product.
#[test]
fn each_lane_can_fail_without_taking_the_other_three_down() {
    let lane_of = |engine: &FlowEngine, policy: &Arc<FlowPolicyStore>, context: &FlowContext| {
        engine
            .select_route(context, &policy.current.load().routes)
            .map(|selected| selected.route.lane)
    };
    let vpn = flow_for("com.example.vpn", "example.com");
    let tor = flow_for("com.example.tor", "example.com");
    let i2p = flow_for("com.example.i2p", "example.com");
    let clear = flow_for("com.example.direct", "example.com");

    // All four at once, which is the state the rest of the test breaks.
    let (engine, policy, _) = four_lane_engine(None);
    assert_eq!(lane_of(&engine, &policy, &vpn), Ok(FlowLane::Vpn));
    assert_eq!(lane_of(&engine, &policy, &tor), Ok(FlowLane::Tor));
    assert_eq!(lane_of(&engine, &policy, &i2p), Ok(FlowLane::I2p));
    assert_eq!(lane_of(&engine, &policy, &clear), Ok(FlowLane::Direct));

    for (down, blocked, carrying) in [
        (FlowLane::Vpn, &vpn, [&tor, &i2p, &clear]),
        (FlowLane::Tor, &tor, [&vpn, &i2p, &clear]),
        (FlowLane::I2p, &i2p, [&vpn, &tor, &clear]),
    ] {
        let (engine, policy, entries) = four_lane_engine(Some(down));
        assert_eq!(
            lane_of(&engine, &policy, blocked),
            Err(BlockReason::LaneUnavailable),
            "{down:?} could not be built, so its flows are refused with a reason that says so"
        );
        for context in carrying {
            assert!(
                lane_of(&engine, &policy, context).is_ok(),
                "{down:?} being down must not stop the lanes that are up"
            );
        }
        assert_ne!(
            lane_of(&engine, &policy, blocked),
            Ok(FlowLane::Direct),
            "a lane that is down must never be answered from the direct lane"
        );
        assert_eq!(
            entries[&down].refused(),
            2,
            "every flow the lane cost is counted where the reason for it lives"
        );
        for (lane, entry) in &entries {
            if *lane != down {
                assert_eq!(
                    entry.refused(),
                    0,
                    "{lane:?} refused nothing: it was never the lane that failed"
                );
            }
        }
    }

    // A `.onion` name with Tor down. It reaches the same refusal rather
    // than "the overlay is switched off", which would be untrue, and rather
    // than any lane that could put it on the open network.
    let (engine, policy, _) = four_lane_engine(Some(FlowLane::Tor));
    let onion = flow_for(
        "com.example.browser",
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    );
    assert_eq!(
        lane_of(&engine, &policy, &onion),
        Err(BlockReason::LaneUnavailable)
    );

    // The fourth lane fails differently — nothing is *built* for `direct`,
    // so what takes it down is a hold — and the same rule applies to it.
    let (engine, policy, _) = four_lane_engine(None);
    engine
        .continuity
        .interrupt(foxcore_api::ContinuityInterruption::VpnFailure);
    assert_eq!(
        lane_of(&engine, &policy, &clear),
        Ok(FlowLane::Direct),
        "with split-tunnel-on-VPN-failure on — the default — the direct lane is not held"
    );
    assert_eq!(lane_of(&engine, &policy, &tor), Ok(FlowLane::Tor));
    assert_eq!(lane_of(&engine, &policy, &i2p), Ok(FlowLane::I2p));
}

/// A lane that failed to build must not drag another one down through the
/// continuity gate.
///
/// The gate exists for a *live* session dying, and `VpnFailure` is the one
/// interruption that suspends a lane which did not itself fail. Refusing
/// before the dial is what keeps a Tor or I2P outbound that never built
/// from reaching it at all: no dial, no dial failure, no interruption.
#[test]
fn an_overlay_that_never_built_raises_no_interruption_at_all() {
    let (engine, policy, _) = four_lane_engine(Some(FlowLane::Tor));
    let tor = flow_for("com.example.tor", "example.com");
    assert_eq!(
        engine
            .select_route(&tor, &policy.current.load().routes)
            .err(),
        Some(BlockReason::LaneUnavailable)
    );
    assert!(
        engine.continuity.pending_token().is_none(),
        "an overlay that is down is not a question to put to the user about the VPN"
    );
    assert!(
        !engine.continuity.is_held(FlowLane::Vpn)
            && !engine.continuity.is_held(FlowLane::Direct)
            && !engine.continuity.is_held(FlowLane::I2p)
    );
}
