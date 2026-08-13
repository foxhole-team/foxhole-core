use super::*;
use crate::FlowMetrics;
use crate::continuity::ContinuityGate;
use foxcore_api::{
    BlockReason, Destination, DnsConfig, EventSink, FlowAttributor, FlowContext, IpTransport,
    RouteAction, RuntimeConfig,
};
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_trafficmap::{FlowLane, TrafficMap};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// A held lane refuses new flows outright. The one thing it must never do
/// is answer them from another lane.
#[test]
fn a_held_lane_blocks_its_flows_and_never_reroutes_them() {
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
    let gate = Arc::new(ContinuityGate::new(
        foxcore_api::ContinuityConfig {
            split_tunnel_on_vpn_failure: false,
            ..Default::default()
        },
        EventSink::none(),
    ));
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
    .with_continuity(gate.clone());
    let context = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
    let routes = policy.current.load();

    assert!(engine.select_route(&context, &routes.routes).is_ok());

    engine.report_dial_failure(FlowLane::Vpn);

    assert_eq!(
        engine.select_route(&context, &routes.routes).err(),
        Some(BlockReason::ContinuityHeld),
        "a suspended VPN must not quietly send its flows out direct"
    );
    let token = gate.pending_token().expect("a hold raises a question");
    assert_eq!(gate.confirm(token), crate::ContinuityConfirm::Confirmed);
    assert!(engine.select_route(&context, &routes.routes).is_ok());
}

/// D13's root cause, in the shape a long session produces it.
///
/// `attribute_context` wraps a `spawn_blocking` in a timeout. The timeout
/// drops the join handle, which abandons the platform call without
/// stopping it, and the blocking pool is two threads wide. Half an hour of
/// traffic against a slow `ConnectivityManager` therefore leaves a queue of
/// calls nobody will ever read, and dropping the runtime waits for every
/// one of them — `nativeStop` hung for minutes on the device.
///
/// Ten short start/stop cycles cannot reproduce it, which is why it took a
/// phone to find: nothing has been abandoned yet. What reproduces it is a
/// backlog, so that is what this builds.
#[cfg_attr(
    miri,
    ignore = "builds a multi-thread tokio runtime with the I/O driver"
)]
#[test]
fn an_abandoned_attribution_backlog_does_not_run_after_the_generation_ends() {
    const CALLS: usize = 32;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        // The production ceiling. The whole defect lives in the gap between
        // how many calls can be queued and how many can run.
        .max_blocking_threads(2)
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let counter = entered.clone();
    let attributor = FlowAttributor::new(move |_, _, _| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Wedged exactly like a Binder call that never comes back.
        let _ = release_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv();
        Ok(None)
    });

    let identity_rule = foxcore_api::RouteRule {
        uid: Some(10_123),
        package: None,
        exact_domains: Vec::new(),
        domain_suffixes: Vec::new(),
        cidrs: Vec::new(),
        ports: Vec::new(),
        network: None,
        transport: None,
        action: RouteAction::Direct,
        expires_at_ms: None,
    };
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(vec![identity_rule], RouteAction::Direct),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
        .unwrap(),
    );
    let cancel = CancellationToken::new();
    let mut engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor,
        runtime: RuntimeConfig {
            attribution_timeout_ms: 25,
            ..RuntimeConfig::default()
        },
        metrics: Arc::new(FlowMetrics::default()),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    engine.shutdown = cancel.clone();

    let source = SocketAddr::from(([10, 77, 0, 2], 49_152));
    let destination = SocketAddr::from(([203, 0, 113, 8], 443));
    runtime.block_on(async {
        for _ in 0..CALLS {
            let mut context =
                FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
            // Every one of these times out and abandons its blocking task.
            assert!(
                !engine
                    .attribute_context(
                        &mut context,
                        source,
                        destination,
                        &policy.current.load().routes,
                        IpTransport::Tcp,
                    )
                    .await,
                "an attribution that never answers must fail closed"
            );
        }
    });

    // Only the pool's width can be inside the platform call at once; the
    // rest of the abandoned work is queued behind them.
    let inside_the_call = entered.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(inside_the_call, 2, "the blocking pool is two threads wide");

    // The generation ends, and the two wedged calls finally return. Tokio
    // *runs* the queued blocking tasks while shutting down rather than
    // dropping them — measured, not assumed — so without the guard every
    // abandoned call in the backlog is made now, one after another, two at
    // a time. That is the wait that turned into minutes on the device.
    cancel.cancel();
    for _ in 0..(CALLS * 2) {
        let _ = release_tx.send(());
    }
    runtime.shutdown_timeout(Duration::from_secs(10));

    assert_eq!(
        entered.load(std::sync::atomic::Ordering::SeqCst),
        inside_the_call,
        "a task that reached the front of the queue after its caller gave up \
             must not make the platform call: running the backlog at shutdown is \
             what made dropping the runtime take minutes"
    );
}

/// The other half of D9. 114 of 124 flows were reported as errors on a
/// device where all 27 probes succeeded, because every ordinary ending —
/// a peer resetting, an idle datagram session closing — was counted as a
/// failure. A counter that fires on success says nothing when it fires.
#[test]
fn an_ordinary_ending_is_not_counted_as_a_flow_error() {
    for kind in [
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
        io::ErrorKind::TimedOut,
    ] {
        assert!(
            is_ordinary_end(&io::Error::new(kind, "peer went away")),
            "{kind:?} is how a flow ends, not how it fails"
        );
    }
    // A real fault still counts, or the counter would mean nothing at all.
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Unsupported,
        io::ErrorKind::OutOfMemory,
    ] {
        assert!(
            !is_ordinary_end(&io::Error::new(kind, "broken")),
            "{kind:?}"
        );
    }
}
