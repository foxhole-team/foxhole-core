use super::*;
use crate::FlowMetrics;
use crate::continuity::ContinuityGate;
use foxcore_api::{
    BlockReason, CoreEvent, Destination, DnsConfig, DnsRuleSetConfig, EventSink, FlowAttributor,
    FlowContext, IpTransport, RouteAction, RuntimeConfig,
};
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_route::ruleset::RuleSetBundle;
use foxcore_trafficmap::{CountingStream, FlowLane, FlowRoute, TrafficMap};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use foxcore_dialer::ProtectedDialer;
use foxcore_route::ruleset::{RULE_SET_FORMAT, RULE_SET_HEADER_LEN, RULE_SET_MAGIC};
use fst::MapBuilder;
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn fst_map(entries: &[(&str, u64)]) -> Vec<u8> {
    let mut builder = MapBuilder::memory();
    for (key, value) in entries {
        builder.insert(key, *value).unwrap();
    }
    builder.into_inner().unwrap()
}

fn signed_rule_set() -> (DnsRuleSetConfig, RuleSetBundle) {
    let source_sha256 = [7_u8; 32];
    let block = fst_map(&[("com.example", 1 << 1)]);
    let allow = fst_map(&[("com.example.safe", 1 << 1)]);
    let mut artifact = Vec::with_capacity(RULE_SET_HEADER_LEN + block.len() + allow.len());
    artifact.extend_from_slice(&RULE_SET_MAGIC);
    artifact.extend_from_slice(&1_u64.to_be_bytes());
    artifact.extend_from_slice(&1_u64.to_be_bytes());
    artifact.extend_from_slice(&(block.len() as u64).to_be_bytes());
    artifact.extend_from_slice(&(allow.len() as u64).to_be_bytes());
    artifact.extend_from_slice(&source_sha256);
    artifact.extend_from_slice(&[0_u8; 8]);
    artifact.extend_from_slice(&block);
    artifact.extend_from_slice(&allow);

    let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let manifest = serde_json::to_vec(&json!({
        "schema": 2,
        "name": "foxhole-test-dns",
        "format": RULE_SET_FORMAT,
        "sequence": 7,
        "generated_at_unix": now.saturating_sub(60),
        "expires_at_unix": now.saturating_add(3600),
        "key_sha256": hex(&Sha256::digest(&public_key)),
        "source": {
            "name": "FoxHole test",
            "repo": "https://example.invalid/foxhole-test",
            "commit": "0123456789abcdef",
            "license": "GPL-3.0-or-later",
            "input_path": "fixtures/filter.txt",
            "input_sha256": hex(&source_sha256)
        },
        "artifact": {
            "file": "foxhole-test.fhds",
            "size": artifact.len(),
            "sha256": hex(&Sha256::digest(&artifact)),
            "block_entries": 1,
            "allow_entries": 1
        },
        "compatibility": { "core_schema": 1 }
    }))
    .unwrap();
    let signature = key_pair
        .sign(&SystemRandom::new(), &manifest)
        .unwrap()
        .as_ref()
        .to_vec();
    (
        DnsRuleSetConfig {
            name: "foxhole-test-dns".into(),
            public_key: STANDARD.encode(public_key),
            minimum_sequence: 7,
            required: true,
        },
        RuleSetBundle {
            name: "foxhole-test-dns".into(),
            manifest,
            signature,
            artifact,
        },
    )
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn required_signed_dns_rule_set_is_present_before_the_first_query_and_survives_a_bad_update()
{
    let (rule_set, bundle) = signed_rule_set();
    let dns = DnsConfig {
        mode: foxcore_api::DnsMode::FakeIp,
        rule_sets: vec![rule_set],
        ..DnsConfig::default()
    };
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(default));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let routes = RouteTable::compile(Vec::new(), RouteAction::Direct);
    let missing = FlowPolicyStore::new(
        1,
        routes.clone(),
        dns.clone(),
        outbounds.clone(),
        direct.clone(),
        Arc::new(FlowMetrics::default()),
        EventSink::none(),
    )
    .err()
    .expect("a required filter cannot be silently absent");
    assert_eq!(missing.kind(), io::ErrorKind::NotFound);

    let policy = FlowPolicyStore::new_with_rule_sets(
        1,
        routes,
        dns,
        outbounds,
        direct,
        Arc::new(FlowMetrics::default()),
        EventSink::none(),
        vec![bundle.clone()],
    )
    .unwrap();
    let query = dns_query(0x1234);
    let proxy = policy.current.load().dns_proxy.clone().unwrap();
    let blocked = proxy.exchange_for_test(&query).await.unwrap();
    assert_eq!(blocked[3] & 0x0f, 3, "blocked name must receive NXDOMAIN");

    let revision = policy.revision();
    let mut tampered = bundle;
    *tampered.artifact.last_mut().unwrap() ^= 1;
    assert!(policy.install_dns_rule_set(tampered).is_err());
    assert_eq!(policy.revision(), revision);
    let still_blocked = policy
        .current
        .load()
        .dns_proxy
        .clone()
        .unwrap()
        .exchange_for_test(&query)
        .await
        .unwrap();
    assert_eq!(still_blocked[3] & 0x0f, 3);
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn identity_rules_use_bounded_platform_attribution_and_fail_closed() {
    let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(default));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let identity_rule = foxcore_api::RouteRule {
        uid: Some(10_123),
        package: Some("com.example.app".into()),
        exact_domains: Vec::new(),
        domain_suffixes: Vec::new(),
        cidrs: Vec::new(),
        ports: Vec::new(),
        network: None,
        transport: None,
        action: RouteAction::Direct,
        expires_at_ms: None,
    };
    let routes = RouteTable::compile(
        vec![identity_rule],
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
    );
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let expected_source = SocketAddr::from(([10, 77, 0, 2], 49152));
    let expected_destination = SocketAddr::from(([203, 0, 113, 8], 443));
    let attributor = FlowAttributor::new(move |transport, source, destination| {
        assert_eq!(transport, IpTransport::Tcp);
        assert_eq!(source, expected_source);
        assert_eq!(destination, expected_destination);
        Ok(Some(foxcore_api::FlowIdentity {
            uid: 10_123,
            packages: vec!["com.example.app".into()],
            signing_digest: None,
        }))
    });
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor,
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    let mut context = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    let current = policy.current.load();

    assert!(
        engine
            .attribute_context(
                &mut context,
                expected_source,
                expected_destination,
                &current.routes,
                IpTransport::Tcp,
            )
            .await
    );
    assert_eq!(context.uid, Some(10_123));
    assert_eq!(context.package.as_deref(), Some("com.example.app"));

    let mut unavailable = engine.clone();
    unavailable.attributor = FlowAttributor::none();
    let mut unattributed =
        FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    assert!(
        !unavailable
            .attribute_context(
                &mut unattributed,
                expected_source,
                expected_destination,
                &current.routes,
                IpTransport::Tcp,
            )
            .await
    );
}

/// Found on a real device: with `default_action="block"` every lookup
/// failed while `blocked_flows` stayed at zero and the event stream stayed
/// empty. A firewall that works but reports nothing is indistinguishable
/// from one that is broken.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_dns_query_refused_by_policy_is_counted_and_reported() {
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let policy = FlowPolicyStore::new(
        1,
        RouteTable::compile(Vec::new(), RouteAction::Block),
        DnsConfig::default(),
        outbounds,
        direct,
        metrics.clone(),
        sink,
    )
    .unwrap();
    let context = FlowContext::new(1, IpTransport::Udp, Destination::new("example.com", 53));

    assert!(
        exchange_dns(&policy, &context, &[0_u8; 12], &metrics)
            .await
            .is_none()
    );
    assert_eq!(metrics.snapshot().blocked_flows, 1);
    assert_eq!(
        *recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![CoreEvent::Blocked {
            reason: BlockReason::Policy,
            transport: IpTransport::Udp,
            destination: Destination::new("example.com", 53),
            uid: None,
            package: None,
        }]
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn failed_vpn_route_does_not_break_a_direct_split_route() {
    let vpn = Arc::new(
        Outbound::from_config(
            foxcore_api::OutboundConfig::I2p(foxcore_api::I2pConfig {
                socks_address: "127.0.0.1:4447".parse().unwrap(),
                username: None,
                password: None,
                connect_timeout_ms: 100,
                handshake_timeout_ms: 100,
            }),
            ProtectedDialer::host(),
        )
        .await
        .unwrap(),
    );
    let outbounds = Arc::new(OutboundRegistry::single(vpn));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let traffic = foxcore_api::TrafficPolicyConfig {
        default_action: foxcore_api::ApplicationRouteAction::Direct,
        applications: vec![foxcore_api::ApplicationRouteConfig {
            package: "com.example.vpn".into(),
            action: foxcore_api::ApplicationRouteAction::Vpn,
            expires_at_ms: None,
        }],
        tor_enabled: None,
        i2p_enabled: None,
        ..Default::default()
    };
    let routes = RouteTable::compile_with_traffic(
        Vec::new(),
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
        traffic,
        false,
        true,
    );
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = Destination::new(
        listener.local_addr().unwrap().ip().to_string(),
        listener.local_addr().unwrap().port(),
    );

    let mut vpn_context = FlowContext::new(1, IpTransport::Tcp, destination.clone());
    vpn_context.packages = vec!["com.example.vpn".into()];
    let current = policy.current.load();
    let selected_vpn = engine
        .select_outbound(&vpn_context, &current.routes)
        .unwrap();
    let vpn_error = match selected_vpn
        .connect_stream(&vpn_context, destination.clone())
        .await
    {
        Ok(_) => panic!("failed VPN route unexpectedly fell back to a working stream"),
        Err(error) => error,
    };
    assert_eq!(vpn_error.kind(), io::ErrorKind::PermissionDenied);

    let mut direct_context = FlowContext::new(1, IpTransport::Tcp, destination.clone());
    direct_context.packages = vec!["com.example.direct".into()];
    let selected_direct = engine
        .select_outbound(&direct_context, &current.routes)
        .unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let direct_stream = selected_direct
        .connect_stream(&direct_context, destination)
        .await
        .unwrap();
    let _accepted = accept.await.unwrap();
    drop(direct_stream);
}

/// D7, found on device: HTTP CONNECT and Naive have no UDP at all, and the
/// core refusing a datagram flow on them is correct. It was being counted
/// as a dial error and reported to nobody, so a working fail-closed core
/// read as a broken network. The I2P adapter refuses identically and is the
/// one TCP-only outbound this crate's tests can build.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_udp_flow_on_a_tcp_only_outbound_is_counted_and_reported_as_a_refusal() {
    let i2p = Arc::new(
        Outbound::from_config(
            foxcore_api::OutboundConfig::I2p(foxcore_api::I2pConfig {
                socks_address: "127.0.0.1:4447".parse().unwrap(),
                username: None,
                password: None,
                connect_timeout_ms: 100,
                handshake_timeout_ms: 100,
            }),
            ProtectedDialer::host(),
        )
        .await
        .unwrap(),
    );
    let outbounds = Arc::new(OutboundRegistry::single(i2p.clone()));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: metrics.clone(),
        events: sink,
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    let context = FlowContext::new(1, IpTransport::Udp, Destination::new("example.com", 443));

    assert!(
        engine
            .open_datagram(&i2p, &context, FlowLane::Vpn)
            .await
            .is_none()
    );

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.udp_unsupported, 1);
    assert_eq!(snapshot.blocked_flows, 1);
    assert_eq!(
        snapshot.dial_errors, 0,
        "a protocol refusing UDP is not the network failing"
    );
    assert_eq!(
        *recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![CoreEvent::Blocked {
            reason: BlockReason::UdpUnsupported,
            transport: IpTransport::Udp,
            destination: Destination::new("example.com", 443),
            uid: None,
            package: None,
        }]
    );
}

fn traffic(kill_switch: bool) -> foxcore_api::TrafficPolicyConfig {
    foxcore_api::TrafficPolicyConfig {
        default_action: foxcore_api::ApplicationRouteAction::Direct,
        kill_switch,
        ..Default::default()
    }
}

fn compiled(traffic: foxcore_api::TrafficPolicyConfig, tor: bool, i2p: bool) -> RouteTable {
    RouteTable::compile_with_traffic(
        Vec::new(),
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
        traffic,
        tor,
        i2p,
    )
}

/// The runtimes are independent. Turning one off must block exactly its
/// lane and leave the others carrying traffic — checked across a live
/// reload rather than on two separately-built configs, because the property
/// under test is the transition, not the config.
///
/// I2P stands in for the overlay here because Arti is an optional heavy
/// dependency this crate's tests do not build. The Tor gate is the same two
/// lines in `select_outbound` and `outbound_allowed`, and its fail-closed
/// half is covered by `onion_destination_cannot_fall_back_to_direct_or_default`.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn switching_one_overlay_off_leaves_the_other_lanes_carrying_traffic() {
    let vpn = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let i2p = Arc::new(
        Outbound::from_config(
            foxcore_api::OutboundConfig::I2p(foxcore_api::I2pConfig {
                socks_address: "127.0.0.1:4447".parse().unwrap(),
                username: None,
                password: None,
                connect_timeout_ms: 100,
                handshake_timeout_ms: 100,
            }),
            ProtectedDialer::host(),
        )
        .await
        .unwrap(),
    );
    let outbounds =
        Arc::new(OutboundRegistry::new(vpn, HashMap::from([("i2p".into(), i2p)])).unwrap());
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let split = foxcore_api::TrafficPolicyConfig {
        default_action: foxcore_api::ApplicationRouteAction::Vpn,
        applications: vec![foxcore_api::ApplicationRouteConfig {
            package: "com.example.direct".into(),
            action: foxcore_api::ApplicationRouteAction::Direct,
            expires_at_ms: None,
        }],
        ..Default::default()
    };
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            compiled(split.clone(), false, true),
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
    let tunnelled = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    let mut clear = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    clear.packages = vec!["com.example.direct".into()];
    let eepsite = FlowContext::new(1, IpTransport::Tcp, Destination::new("service.i2p", 80));

    let lane = |context: &FlowContext| {
        engine
            .select_route(context, &policy.current.load().routes)
            .map(|selected| selected.route.lane)
    };
    assert_eq!(lane(&tunnelled), Ok(FlowLane::Vpn));
    assert_eq!(lane(&clear), Ok(FlowLane::Direct));
    assert_eq!(lane(&eepsite), Ok(FlowLane::I2p));

    // I2P off, hot.
    policy
        .reload(
            Some(1),
            compiled(split.clone(), false, false),
            DnsConfig::default(),
        )
        .unwrap();
    assert_eq!(
        lane(&eepsite),
        Err(BlockReason::Policy),
        "a disabled overlay must fail closed, never fall back to clearnet"
    );
    assert_eq!(lane(&tunnelled), Ok(FlowLane::Vpn), "the VPN is untouched");
    assert_eq!(lane(&clear), Ok(FlowLane::Direct), "and so is the split");
    assert!(
        !policy.current.load().routes.tor_enabled(),
        "the Tor gate answers for itself and is not moved by the I2P switch"
    );

    // And back on, without a restart.
    policy
        .reload(Some(2), compiled(split, false, true), DnsConfig::default())
        .unwrap();
    assert_eq!(lane(&eepsite), Ok(FlowLane::I2p));
    assert_eq!(lane(&tunnelled), Ok(FlowLane::Vpn));
    assert_eq!(lane(&clear), Ok(FlowLane::Direct));
}

/// Which lanes are standing in this scenario. `None` is the healthy
/// four-lane profile; anything else names the one lane whose outbound could
/// not be built.
fn four_lane_engine(
    down: Option<FlowLane>,
) -> (
    FlowEngine,
    Arc<FlowPolicyStore>,
    HashMap<FlowLane, foxcore_outbound::DeferredOutbound>,
) {
    use foxcore_api::{
        ApplicationRouteAction, ApplicationRouteConfig, I2pConfig, OutboundConfig, RouteRule,
        SocksConfig, TorCircuitConfig, TorConfig,
    };
    use foxcore_outbound::{DeferredOutbound, OutboundKind};

    // Every lane's outbound is a registry entry, whether or not it was
    // built. The one named in `down` is left unbuilt; the rest are filled
    // with a `direct` outbound, which is how a lane is stood up here at all
    // — Arti is an optional heavy dependency this crate's tests do not
    // build, and a resolved entry still reports the kind the profile asked
    // for, which is what the overlay gates and the registry's canonical-id
    // rules read.
    let entry = |id: &str, kind: OutboundKind, config: OutboundConfig, lane: FlowLane| {
        let deferred = DeferredOutbound::new(
            id,
            kind,
            config,
            &io::Error::new(io::ErrorKind::TimedOut, "build timed out"),
        );
        if down != Some(lane) {
            deferred.resolve(Outbound::direct(ProtectedDialer::host()));
        }
        (Arc::new(Outbound::Deferred(deferred.clone())), deferred)
    };
    let (vpn, vpn_entry) = entry(
        "default",
        OutboundKind::Socks,
        OutboundConfig::Socks(SocksConfig {
            server: "127.0.0.1".into(),
            port: 1080,
            server_ip: None,
            username: None,
            password: None,
            handshake_timeout_ms: 100,
        }),
        FlowLane::Vpn,
    );
    let (tor, tor_entry) = entry(
        "tor",
        OutboundKind::Tor,
        OutboundConfig::Tor(TorConfig {
            state_dir: "/nonexistent/state".into(),
            cache_dir: "/nonexistent/cache".into(),
            upstream: None,
            bootstrap_timeout_s: 1,
            stream_connect_timeout_s: 1,
            isolate_streams: true,
            circuit: TorCircuitConfig::default(),
            bridges: Vec::new(),
            transports: Vec::new(),
        }),
        FlowLane::Tor,
    );
    let (i2p, i2p_entry) = entry(
        "i2p",
        OutboundKind::I2p,
        OutboundConfig::I2p(I2pConfig {
            socks_address: "127.0.0.1:4447".parse().unwrap(),
            username: None,
            password: None,
            connect_timeout_ms: 100,
            handshake_timeout_ms: 100,
        }),
        FlowLane::I2p,
    );
    let outbounds = Arc::new(
        OutboundRegistry::new(
            vpn,
            HashMap::from([("tor".into(), tor), ("i2p".into(), i2p)]),
        )
        .unwrap(),
    );
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));

    // Split by application, all four lanes at once. I2P is reached by a
    // route rule rather than an application entry because
    // `ApplicationRouteAction` has no I2P member; the lane is the same one
    // either way.
    let traffic = foxcore_api::TrafficPolicyConfig {
        default_action: ApplicationRouteAction::Vpn,
        applications: vec![
            ApplicationRouteConfig {
                package: "com.example.direct".into(),
                action: ApplicationRouteAction::Direct,
                expires_at_ms: None,
            },
            ApplicationRouteConfig {
                package: "com.example.tor".into(),
                action: ApplicationRouteAction::Tor,
                expires_at_ms: None,
            },
        ],
        ..Default::default()
    };
    let routes = RouteTable::compile_with_traffic(
        vec![RouteRule {
            uid: None,
            package: Some("com.example.i2p".into()),
            exact_domains: Vec::new(),
            domain_suffixes: Vec::new(),
            cidrs: Vec::new(),
            ports: Vec::new(),
            network: None,
            transport: None,
            action: RouteAction::I2p,
            expires_at_ms: None,
        }],
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
        traffic,
        true,
        true,
    );
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
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
    })
    .with_continuity(Arc::new(ContinuityGate::new(
        foxcore_api::ContinuityConfig::default(),
        EventSink::none(),
    )));
    (
        engine,
        policy,
        HashMap::from([
            (FlowLane::Vpn, vpn_entry),
            (FlowLane::Tor, tor_entry),
            (FlowLane::I2p, i2p_entry),
        ]),
    )
}

fn flow_for(package: &str, host: &str) -> FlowContext {
    let mut context = FlowContext::new(1, IpTransport::Tcp, Destination::new(host, 443));
    context.package = Some(package.to_owned());
    context.packages = vec![package.to_owned()];
    context
}

fn dns_query(transaction_id: u16) -> Vec<u8> {
    let mut packet = vec![
        0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    packet[..2].copy_from_slice(&transaction_id.to_be_bytes());
    packet
}

/// D9: `nativeStats` and `nativeConnections` disagreed by up to 37x. The
/// aggregate counters were written from `copy_bidirectional`'s return
/// value, which never arrives when the relay is torn down — and the kill
/// switch revoking live flows made that the common ending, not the rare
/// one. The map, fed by the counting stream as bytes passed, was right;
/// the summary the UI polls every second was not.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_relay_torn_down_mid_transfer_reports_the_same_bytes_to_both_views() {
    let metrics = Arc::new(FlowMetrics::default());
    let map = Arc::new(TrafficMap::default());
    let tracked = map.open(
        IpTransport::Tcp,
        "example.com".to_owned(),
        443,
        FlowRoute::new(FlowLane::Vpn, "vless"),
        vec!["com.example".to_owned()],
        Some(10_123),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = stream.split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    });
    let remote = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut counted =
        CountingStream::new(remote, tracked.flow().clone()).with_totals(metrics.clone());

    // A transfer that is still running when the flow is revoked.
    counted.write_all(&[7_u8; 4096]).await.unwrap();
    let mut echoed = [0_u8; 4096];
    counted.read_exact(&mut echoed).await.unwrap();
    drop(counted);
    echo.abort();

    let summary = metrics.snapshot();
    let row = &map.snapshot().connections[0];
    assert_eq!(row.bytes_up, 4096);
    assert_eq!(row.bytes_down, 4096);
    assert_eq!(
        (summary.bytes_up, summary.bytes_down),
        (row.bytes_up, row.bytes_down),
        "the cheap summary and the map must not be able to disagree: they are \
             the same numbers read at two prices"
    );
}

/// D12: every snapshot reported zero packages. Routing only resolves
/// identity when a rule needs it, so a policy with no per-app rules — the
/// ordinary case — left the map with no owner for anything, and per-app
/// bytes are a product requirement rather than a nice-to-have.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_flow_gets_its_owner_even_when_no_rule_needs_one() {
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    // No uid or package rules anywhere: routing needs no identity at all.
    let routes = RouteTable::compile(Vec::new(), RouteAction::Direct);
    assert!(
        !routes.requires_identity(),
        "this test is only meaningful when routing does not ask for identity"
    );
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let attributor = FlowAttributor::new(|_, _, _| {
        Ok(Some(foxcore_api::FlowIdentity {
            uid: 10_123,
            packages: vec!["com.example.app".into()],
            signing_digest: None,
        }))
    });
    let map = Arc::new(TrafficMap::default());
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor,
        runtime: RuntimeConfig::default(),
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: map.clone(),
    });

    // Routing declines to resolve, exactly as it does in production.
    let mut context = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    let source = SocketAddr::from(([10, 77, 0, 2], 49_152));
    let destination = SocketAddr::from(([203, 0, 113, 8], 443));
    assert!(
        engine
            .attribute_context(
                &mut context,
                source,
                destination,
                &policy.current.load().routes,
                IpTransport::Tcp,
            )
            .await
    );
    assert!(
        context.packages.is_empty(),
        "routing must not pay for an identity it does not use"
    );

    let tracked = map.open(
        IpTransport::Tcp,
        "example.com".to_owned(),
        443,
        FlowRoute::new(FlowLane::Vpn, "vless"),
        context.packages.clone(),
        context.uid,
    );
    assert!(
        map.snapshot().packages.is_empty(),
        "and this is what every snapshot looked like"
    );
    tracked.add_up(1_000);

    engine.attribute_for_telemetry(
        tracked.flow().clone(),
        IpTransport::Tcp,
        source,
        destination,
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && map.snapshot().packages.is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let snapshot = map.snapshot();
    assert_eq!(snapshot.packages[0].package, "com.example.app");
    assert_eq!(
        snapshot.packages[0].bytes_up, 1_000,
        "bytes that moved before the owner was known still belong to it: \
             totals are computed from the row, not accumulated as they arrive"
    );
    assert_eq!(snapshot.connections[0].uid, Some(10_123));
}

/// D10, third hypothesis. Track C ruled out the translator by experiment —
/// with the peer's own address on the tun the rewrite is the identity, and
/// TCP still did not establish — which leaves the question of whether the
/// split is sending user traffic to the stack instead of the tunnel. In
/// packet-tunnel mode the stack's default outbound is a refused
/// placeholder, so a TCP flow that lands there can never connect while
/// keepalives keep the tunnel looking alive.
///
/// This is the check, run against the routing a WireGuard profile actually
/// compiles: the engine's own default action, the traffic policy's default
/// of `Vpn`, and no per-app rules.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn in_packet_tunnel_mode_ordinary_tcp_is_decided_for_the_tunnel() {
    let placeholder = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(placeholder));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    // Exactly what CoreRuntime::start compiles for a WireGuard profile.
    let routes = RouteTable::compile_with_traffic(
        Vec::new(),
        RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
        foxcore_api::TrafficPolicyConfig::default(),
        false,
        false,
    );
    let metrics = Arc::new(FlowMetrics::default());
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: metrics.clone(),
        events: EventSink::none(),
        packet_tunnel: true,
        connections: Arc::new(TrafficMap::default()),
    });

    let tcp = crate::split::FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
        destination: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        source_port: 49_152,
        destination_port: 443,
        protocol: 6,
    };
    let decision = engine.decide_packet(tcp).await;
    assert_eq!(
        decision.route,
        crate::split::PacketRoute::Tunnel,
        "a plain TCP flow must be sealed into the tunnel; the stack's default \
             in this mode is a placeholder that select_outbound refuses, so a flow \
             sent there can never connect"
    );
    assert!(
        decision.flow.is_some(),
        "and it must carry the row that gives WireGuard per-app bytes (D4)"
    );

    // UDP takes the same path; DNS deliberately does not, because the
    // interceptor has to see it.
    let udp = crate::split::FlowKey {
        protocol: 17,
        ..tcp
    };
    assert_eq!(
        engine.decide_packet(udp).await.route,
        crate::split::PacketRoute::Tunnel
    );
    // DNS goes to the stack only when there is an interceptor to receive
    // it. With no resolver configured there is nothing to intercept, and
    // the tunnel is the right answer — which is why this needs its own
    // engine rather than an assertion on the one above.
    let intercepting = FlowPolicyStore::new(
        1,
        RouteTable::compile_with_traffic(
            Vec::new(),
            RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
            foxcore_api::TrafficPolicyConfig::default(),
            false,
            false,
        ),
        DnsConfig {
            mode: foxcore_api::DnsMode::FakeIp,
            ..DnsConfig::default()
        },
        engine.outbounds.clone(),
        engine.direct.clone(),
        metrics.clone(),
        EventSink::none(),
    )
    .unwrap();
    let mut resolving = engine.clone();
    resolving.policy = Arc::new(intercepting);
    let dns = crate::split::FlowKey {
        protocol: 17,
        destination_port: 53,
        ..tcp
    };
    assert_eq!(
        resolving.decide_packet(dns).await.route,
        crate::split::PacketRoute::Stack,
        "DNS must reach the interceptor, or a query would skip the blocklist"
    );
}

/// The defect §27 caught on the phone, at the line where it happens.
///
/// `example.com` is resolved through the same interceptor path the device
/// used, which answers out of `198.18.0.0/15`, and the flow to that answer
/// is then offered to the split. Before the guard the split said `Tunnel`
/// and meant it: the packet was translated, sealed, counted by the lane and
/// by the metrics, and sent to a peer that has no route to an RFC 2544
/// address — twenty seconds of silence with `untrans_up` unmoved and
/// nothing refused anywhere.
///
/// Two things are asserted together on purpose. That the flow no longer
/// goes to the tunnel is half the fix; that a record says *why* is the
/// other half, and the one D1, D2, D7 and D10 were all missing.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_clearnet_name_answered_with_a_fake_address_is_refused_instead_of_sealed() {
    let placeholder = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(placeholder));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let dns_config = DnsConfig {
        mode: foxcore_api::DnsMode::FakeIp,
        ..DnsConfig::default()
    };
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile_with_traffic(
                Vec::new(),
                RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
                foxcore_api::TrafficPolicyConfig::default(),
                false,
                false,
            ),
            dns_config.clone(),
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            sink.clone(),
        )
        .unwrap(),
    );
    // The address the application will connect to, produced by the same
    // call the interceptor makes rather than written down here: a literal
    // out of the pool would prove the containment check and not the path.
    let fake = {
        let snapshot = policy.current.load();
        let response = snapshot
            .dns
            .fake_response(
                &dns_query(0x2701),
                dns_config.fake_ipv4_pool,
                dns_config.fake_ipv6_pool,
                dns_config.fake_ttl_s,
            )
            .expect("fake-IP mode answers an A query locally");
        let octets = &response[response.len() - 4..];
        IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    };
    assert!(
        dns_config.fake_ipv4_pool.contains(&match fake {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => unreachable!("an A query is answered with A"),
        }),
        "the interceptor must have answered out of the synthetic pool"
    );

    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: metrics.clone(),
        events: sink,
        packet_tunnel: true,
        connections: Arc::new(TrafficMap::default()),
    });

    let syn = crate::split::FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        destination: fake,
        source_port: 49_152,
        destination_port: 80,
        protocol: 6,
    };
    let decision = engine.decide_packet(syn).await;
    assert_eq!(
        decision.route,
        crate::split::PacketRoute::Block,
        "sealing this packet puts {fake} on the wire, and no peer routes it"
    );
    assert!(
        decision.flow.is_none(),
        "a refused flow must not open a row that would report it as carried"
    );

    let drained = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let blocked = drained
        .iter()
        .find_map(|event| match event {
            CoreEvent::Blocked {
                reason: BlockReason::TunnelFakeIpUnroutable,
                destination,
                ..
            } => Some(destination),
            _ => None,
        })
        .expect("the refusal has to be auditable, or it is another silent drop");
    assert_eq!(
        blocked.host, "example.com",
        "and it has to name the host the user asked for, not the invented address"
    );
    assert_eq!(metrics.snapshot().blocked_flows, 1);

    // The refusal is about a *synthetic* destination, not about the prefix.
    // With `real_ip` nothing invents addresses, so the very same packet is
    // an ordinary flow to an ordinary address and the tunnel carries it.
    let literal = FlowPolicyStore::new(
        1,
        RouteTable::compile_with_traffic(
            Vec::new(),
            RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
            foxcore_api::TrafficPolicyConfig::default(),
            false,
            false,
        ),
        DnsConfig::default(),
        engine.outbounds.clone(),
        engine.direct.clone(),
        metrics.clone(),
        EventSink::none(),
    )
    .unwrap();
    let mut without_fake_ip = engine.clone();
    without_fake_ip.policy = Arc::new(literal);
    assert_eq!(
        without_fake_ip.decide_packet(syn).await.route,
        crate::split::PacketRoute::Tunnel,
        "a real address in the same prefix is a destination like any other"
    );
}

/// D10's fourth hypothesis, and the one the device numbers point at: a tun
/// that advertises IPv6 while the packet tunnel carries only IPv4.
///
/// It explains both anomalies with one mechanism. Android starts talking
/// ICMPv6 the moment a v6 address appears — router and neighbour
/// solicitation, MLD, DAD — and those have no ports, so `decide_packet`
/// sends them to the stack. That is `split_to_stack` counting eight packets
/// before a single DNS query exists. And any v6 flow that *does* reach the
/// tunnel is refused by the translator, because there is no v6 pair to map
/// it to.
///
/// The reason it breaks TCP while leaving DNS working is happy-eyeballs:
/// the lookup goes out over v4 to the interceptor and answers, then the SYN
/// goes out over v6 and falls into the hole.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_tun_that_advertises_a_family_the_tunnel_cannot_carry_black_holes_it() {
    let placeholder = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(placeholder));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let metrics = Arc::new(FlowMetrics::default());
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile_with_traffic(
                Vec::new(),
                RouteAction::Outbound(foxcore_api::OutboundId("default".into())),
                foxcore_api::TrafficPolicyConfig::default(),
                false,
                false,
            ),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: metrics.clone(),
        events: EventSink::none(),
        packet_tunnel: true,
        connections: Arc::new(TrafficMap::default()),
    });

    // 1. ICMPv6 has no ports, so it goes to the stack — before any DNS
    //    exists, which is exactly the shape of the eight.
    let icmpv6 = crate::split::FlowKey {
        source: "fd00::2".parse().unwrap(),
        destination: "ff02::2".parse().unwrap(),
        source_port: 0,
        destination_port: 0,
        protocol: 58,
    };
    assert_eq!(
        engine.decide_packet(icmpv6).await.route,
        crate::split::PacketRoute::Stack,
        "router/neighbour solicitation cannot be attributed and has no stream"
    );
    assert_eq!(metrics.snapshot().dns_queries, 0, "and no DNS has happened");

    // 2. A v6 SYN is decided for the tunnel — the routing has no opinion
    //    about address family — and then dies at the translator.
    let syn_v6 = crate::split::FlowKey {
        source: "fd00::2".parse().unwrap(),
        destination: "2606:4700::1111".parse().unwrap(),
        source_port: 49_152,
        destination_port: 443,
        protocol: 6,
    };
    assert_eq!(
        engine.decide_packet(syn_v6).await.route,
        crate::split::PacketRoute::Tunnel,
        "the split sends it on; nothing here knows the tunnel has no v6"
    );

    // 3. And this is where it vanishes: a translator built from a v4-only
    //    profile on a dual-stack tun has no v6 pair.
    let translator = crate::l3::AddressTranslator::new(vec![(
        IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
    )]);
    let mut packet = vec![0_u8; 60];
    packet[0] = 0x60; // IPv6
    packet[6] = 6; // TCP
    packet[8..24].copy_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(
        &"2606:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert_eq!(
        translator.to_tunnel_checked(&mut packet),
        Err(crate::l3::TranslationRefusal::NoMappingForFamily),
        "every v6 packet is lost here, which is the twenty"
    );

    // v4 through the same translator is fine, which is why the tunnel looks
    // alive and why this was so hard to see.
    let mut v4 = vec![0_u8; 40];
    v4[0] = 0x45;
    v4[9] = 6;
    v4[12..16].copy_from_slice(&Ipv4Addr::new(10, 8, 0, 2).octets());
    v4[16..20].copy_from_slice(&Ipv4Addr::new(93, 184, 216, 34).octets());
    assert!(translator.to_tunnel_checked(&mut v4).is_ok());
}

mod dnsflow;
mod lanes;
mod routing;
