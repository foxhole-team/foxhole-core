//! Live-flow revocation regressions for app blocking and the kill switch.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxcore_api::{
    CoreEvent, EventSink, FlowAttributor, FlowIdentity, RouteAction, RouteRule, RuntimeConfig,
};
use foxcore_route::RouteTable;
use foxcore_tun::{ConnectionTracker, FlowEngine, FlowMetrics, RevokeTarget, TunDevice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

mod tunlab;

use tunlab::{FLAG_ACK, FLAG_PSH, FLAG_RST, FLAG_SYN, Seen};

/// One client port per synthetic app.
const BLOCKED_PORT: u16 = 49_152;
const INNOCENT_PORT: u16 = 49_153;

const BLOCKED_APP: &str = "com.example.blocked";
const INNOCENT_APP: &str = "com.example.innocent";
const BLOCKED_UID: u32 = 10_101;
const INNOCENT_UID: u32 = 10_202;

const SOON: Duration = Duration::from_secs(5);

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_and_network_change_close_tcp_and_udp_from_before_two_reloads() {
    use foxcore_dialer::ProtectedDialer;
    use foxcore_outbound::{Outbound, OutboundRegistry};
    use foxcore_tun::{FlowEngineContext, FlowPolicyStore};
    for kill in [false, true] {
        let metrics = Arc::new(FlowMetrics::default());
        let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
        let routes = |kill_switch| {
            RouteTable::compile_with_traffic(
                Vec::new(),
                RouteAction::Direct,
                foxcore_api::TrafficPolicyConfig {
                    kill_switch,
                    ..Default::default()
                },
                false,
                false,
            )
        };
        let policy = Arc::new(
            FlowPolicyStore::new(
                1,
                routes(false),
                Default::default(),
                outbounds.clone(),
                direct.clone(),
                metrics.clone(),
                EventSink::none(),
            )
            .unwrap(),
        );
        let connections = Arc::new(ConnectionTracker::default());
        let engine = FlowEngine::new(FlowEngineContext {
            outbounds,
            direct,
            policy: policy.clone(),
            attributor: FlowAttributor::none(),
            runtime: RuntimeConfig::default(),
            metrics: metrics.clone(),
            events: EventSink::none(),
            packet_tunnel: false,
            connections: connections.clone(),
        });
        let wire = Wire::start(engine);
        let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
            .await
            .unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        let ack = wire.handshake(BLOCKED_PORT, tcp_port, 100).await;
        wire.send(
            BLOCKED_PORT,
            tcp_port,
            FLAG_ACK | FLAG_PSH,
            101,
            ack,
            b"before",
        )
        .await;
        let (mut peer, _) = tokio::time::timeout(SOON, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 16];
        peer.read_exact(&mut bytes[..6]).await.unwrap();
        assert_eq!(&bytes[..6], b"before");
        let udp = tokio::net::UdpSocket::bind((tunlab::SERVER, 0))
            .await
            .unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        wire.send_datagram(INNOCENT_PORT, udp_port, b"before").await;
        let (length, udp_peer) = tokio::time::timeout(SOON, udp.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..length], b"before");
        for revision in 1..=2 {
            policy
                .reload(Some(revision), routes(false), Default::default())
                .unwrap();
        }
        wire.send(
            BLOCKED_PORT,
            tcp_port,
            FLAG_ACK | FLAG_PSH,
            107,
            ack,
            b"retained",
        )
        .await;
        peer.read_exact(&mut bytes[..8]).await.unwrap();
        assert_eq!(&bytes[..8], b"retained");
        wire.send_datagram(INNOCENT_PORT, udp_port, b"retained")
            .await;
        let (length, peer_after) = tokio::time::timeout(SOON, udp.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..length], b"retained");
        assert_eq!(peer_after, udp_peer);
        if kill {
            policy
                .reload(Some(3), routes(true), Default::default())
                .unwrap();
        } else {
            policy.network_changed();
        }
        assert!(
            settles(SOON, || metrics.snapshot().flows_revoked == 2
                && connections.snapshot().connections.is_empty())
            .await
        );
        assert!(
            wire.watch(BLOCKED_PORT, SOON, |seen| seen.flags & FLAG_RST != 0)
                .await
                .is_some()
        );
        assert_eq!(
            tokio::time::timeout(SOON, peer.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        // The old UDP session cannot deliver a late upstream response after revocation.
        udp.send_to(b"late", udp_peer).await.unwrap();
        if kill {
            wire.send_datagram(INNOCENT_PORT, udp_port, b"forbidden")
                .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), udp.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
        }
        wire.stop().await;
    }
}

/// Test attributor keyed by client port.
fn attributor() -> FlowAttributor {
    FlowAttributor::new(|_transport, source: std::net::SocketAddr, _destination| {
        let identity = match source.port() {
            BLOCKED_PORT => FlowIdentity {
                uid: BLOCKED_UID,
                packages: vec![BLOCKED_APP.to_owned()],
                signing_digest: None,
            },
            INNOCENT_PORT => FlowIdentity {
                uid: INNOCENT_UID,
                packages: vec![INNOCENT_APP.to_owned()],
                signing_digest: None,
            },
            _ => return Ok(None),
        };
        Ok(Some(identity))
    })
}

/// Identity-aware route table that permits the named package.
fn routes_that_ask_who() -> RouteTable {
    RouteTable::compile(
        vec![RouteRule {
            uid: None,
            package: Some(BLOCKED_APP.to_owned()),
            exact_domains: Vec::new(),
            domain_suffixes: Vec::new(),
            cidrs: Vec::new(),
            ports: Vec::new(),
            network: None,
            transport: None,
            action: RouteAction::Direct,
            expires_at_ms: None,
        }],
        RouteAction::Direct,
    )
}

struct Wire {
    app: tokio::net::UnixDatagram,
    cancel: CancellationToken,
    running: tokio::task::JoinHandle<io::Result<()>>,
    _tun_fd_owner: foxcore_tun::TunFdOwner,
}

impl Wire {
    fn start(engine: FlowEngine) -> Self {
        let (app, device) = UnixDatagram::pair().expect("socketpair");
        app.set_nonblocking(true).expect("nonblocking");
        let app = tokio::net::UnixDatagram::from_std(app).expect("register the app side");
        let (device, tun_fd_owner) =
            TunDevice::from_owned_fd(OwnedFd::from(device)).expect("wrap the device side");
        let cancel = CancellationToken::new();
        let engine_cancel = cancel.clone();
        let running = tokio::spawn(async move { engine.run(device, 1500, engine_cancel).await });
        Self {
            app,
            cancel,
            running,
            _tun_fd_owner: tun_fd_owner,
        }
    }

    async fn send(
        &self,
        client_port: u16,
        destination_port: u16,
        flags: u8,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) {
        let packet = tunlab::segment_from(
            client_port,
            tunlab::SERVER,
            destination_port,
            flags,
            sequence,
            acknowledgement,
            payload,
        );
        self.app.send(&packet).await.expect("inject a segment");
    }

    async fn send_datagram(&self, client_port: u16, destination_port: u16, payload: &[u8]) {
        let packet = tunlab::datagram_from(client_port, tunlab::SERVER, destination_port, payload);
        self.app.send(&packet).await.expect("inject a datagram");
    }

    async fn watch(
        &self,
        client_port: u16,
        within: Duration,
        wanted: impl Fn(&Seen) -> bool,
    ) -> Option<Seen> {
        let deadline = tokio::time::Instant::now() + within;
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match tokio::time::timeout_at(deadline, self.app.recv(&mut buffer)).await {
                Ok(Ok(read)) if read != 0 => read,
                _ => return None,
            };
            if let Some(seen) = tunlab::tcp_for_port(&buffer[..read], client_port)
                && wanted(&seen)
            {
                return Some(seen);
            }
        }
    }

    async fn handshake(&self, client_port: u16, destination_port: u16, sequence: u32) -> u32 {
        self.send(client_port, destination_port, FLAG_SYN, sequence, 0, &[])
            .await;
        let seen = self
            .watch(client_port, SOON, |seen| {
                seen.flags & FLAG_SYN != 0 && seen.flags & FLAG_ACK != 0
            })
            .await
            .expect("the stack must answer the SYN");
        let acknowledgement = seen.sequence.wrapping_add(1);
        self.send(
            client_port,
            destination_port,
            FLAG_ACK,
            sequence.wrapping_add(1),
            acknowledgement,
            &[],
        )
        .await;
        acknowledgement
    }

    async fn stop(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.running).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Revoked {
    target: String,
    scope: Option<String>,
    count: u64,
}

#[derive(Clone, Default)]
struct Revocations(Arc<Mutex<Vec<Revoked>>>);

impl Revocations {
    fn sink(&self) -> EventSink {
        let seen = self.0.clone();
        EventSink::new(move |event| {
            if let CoreEvent::FlowsRevoked {
                target,
                scope,
                count,
            } = event
                && let Ok(mut seen) = seen.lock()
            {
                seen.push(Revoked {
                    target,
                    scope,
                    count,
                });
            }
        })
    }

    fn all(&self) -> Vec<Revoked> {
        self.0.lock().map(|seen| seen.clone()).unwrap_or_default()
    }
}

async fn settles(within: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ready()
}

async fn flow_of(connections: &Arc<ConnectionTracker>, package: &str) -> Option<u64> {
    let deadline = tokio::time::Instant::now() + SOON;
    while tokio::time::Instant::now() < deadline {
        if let Some(row) = connections
            .snapshot()
            .connections
            .into_iter()
            .find(|row| row.packages.iter().any(|owner| owner == package))
        {
            return Some(row.id);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_one_app_resets_its_connection_and_leaves_the_other_running() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let revocations = Revocations::default();
    let (engine, connections) = tunlab::engine_with_identity(
        metrics.clone(),
        RuntimeConfig::default(),
        routes_that_ask_who(),
        attributor(),
        revocations.sink(),
    );
    let wire = Wire::start(engine);

    let blocked_ack = wire.handshake(BLOCKED_PORT, port, 1_000).await;
    let (_blocked_far_end, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the blocked app's dial has to complete")
        .expect("accept the blocked app");
    let innocent_ack = wire.handshake(INNOCENT_PORT, port, 5_000).await;
    let (mut innocent_far_end, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the innocent app's dial has to complete")
        .expect("accept the innocent app");

    assert!(
        flow_of(&connections, BLOCKED_APP).await.is_some()
            && flow_of(&connections, INNOCENT_APP).await.is_some(),
        "both apps have to be on the map before one of them can be named"
    );

    let revoked = connections.revoke(&RevokeTarget::Package {
        package: BLOCKED_APP.to_owned(),
    });
    assert_eq!(revoked, 1, "exactly the blocked app's one live flow");

    let reset = wire
        .watch(BLOCKED_PORT, SOON, |seen| seen.flags & FLAG_RST != 0)
        .await;
    assert!(
        reset.is_some(),
        "a revoked flow has to be reset towards the application. Tearing the \
         relay down in silence leaves the app holding a connection that is \
         established and will never answer — which is what 'blocked' looked \
         like from inside the app before this existed"
    );
    assert!(
        settles(SOON, || metrics.snapshot().flows_revoked == 1).await,
        "and counted once: {:?}",
        metrics.snapshot().flows_revoked
    );

    // Verify the unrelated app in both directions after revocation.
    wire.send(
        INNOCENT_PORT,
        port,
        FLAG_ACK | FLAG_PSH,
        5_001,
        innocent_ack,
        b"still here",
    )
    .await;
    let mut arrived = [0_u8; 10];
    tokio::time::timeout(SOON, innocent_far_end.read_exact(&mut arrived))
        .await
        .expect("the untargeted app has to keep carrying traffic")
        .expect("read what the innocent app sent");
    assert_eq!(
        &arrived, b"still here",
        "blocking one app must not touch another app's connections"
    );
    innocent_far_end
        .write_all(b"and back")
        .await
        .expect("the far end answers");
    assert!(
        wire.watch(INNOCENT_PORT, SOON, |seen| seen.flags & FLAG_PSH != 0)
            .await
            .is_some(),
        "and the return direction has to keep working too"
    );
    assert!(
        wire.watch(INNOCENT_PORT, Duration::from_millis(300), |seen| seen.flags
            & FLAG_RST
            != 0)
            .await
            .is_none(),
        "nothing may reset the app that was not named"
    );

    let _ = blocked_ack;
    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_target_with_no_flows_disturbs_nothing() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let (engine, connections) = tunlab::engine_with_identity(
        metrics.clone(),
        RuntimeConfig::default(),
        routes_that_ask_who(),
        attributor(),
        EventSink::none(),
    );
    let wire = Wire::start(engine);

    let live_ack = wire.handshake(INNOCENT_PORT, port, 1_000).await;
    let (mut far_end, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the dial has to complete")
        .expect("accept the flow");
    assert!(flow_of(&connections, INNOCENT_APP).await.is_some());

    for target in [
        RevokeTarget::Package {
            package: "com.example.not.installed".to_owned(),
        },
        RevokeTarget::Uid { uid: 99_999 },
        RevokeTarget::Lane {
            lane: foxcore_tun::FlowLane::Tor,
        },
        RevokeTarget::Outbound {
            outbound: "no-such-outbound".to_owned(),
        },
        RevokeTarget::Flow { flow: 9_999 },
    ] {
        assert_eq!(
            connections.revoke(&target),
            0,
            "{target:?} matches nothing, which is a request already satisfied"
        );
    }

    wire.send(
        INNOCENT_PORT,
        port,
        FLAG_ACK | FLAG_PSH,
        1_001,
        live_ack,
        b"untouched",
    )
    .await;
    let mut arrived = [0_u8; 9];
    tokio::time::timeout(SOON, far_end.read_exact(&mut arrived))
        .await
        .expect("a revocation that matched nothing must not have reached this flow")
        .expect("read the live flow");
    assert_eq!(&arrived, b"untouched");
    assert_eq!(
        metrics.snapshot().flows_revoked,
        0,
        "nothing was revoked, so nothing may be counted as revoked"
    );

    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_twice_is_the_same_as_revoking_once() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let (engine, connections) = tunlab::engine_with_identity(
        metrics.clone(),
        RuntimeConfig::default(),
        routes_that_ask_who(),
        attributor(),
        EventSink::none(),
    );
    let wire = Wire::start(engine);

    wire.handshake(BLOCKED_PORT, port, 1_000).await;
    let (_far_end, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the dial has to complete")
        .expect("accept the flow");
    assert!(flow_of(&connections, BLOCKED_APP).await.is_some());

    let target = RevokeTarget::Uid { uid: BLOCKED_UID };
    assert_eq!(connections.revoke(&target), 1);
    assert!(
        wire.watch(BLOCKED_PORT, SOON, |seen| seen.flags & FLAG_RST != 0)
            .await
            .is_some(),
        "the first revoke resets the flow"
    );
    assert!(
        settles(SOON, || metrics.snapshot().flows_revoked == 1).await,
        "{:?}",
        metrics.snapshot()
    );
    // A repeated revoke must not tear down a flow twice.
    let second = connections.revoke(&target);
    assert!(
        second <= 1,
        "a second revoke cannot find more than the first"
    );
    assert!(
        !settles(Duration::from_millis(500), || metrics
            .snapshot()
            .flows_revoked
            > 1)
        .await,
        "a flow can only be torn down once: {:?}",
        metrics.snapshot()
    );

    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_datagram_flow_is_torn_down_and_its_session_freed() {
    let metrics = Arc::new(FlowMetrics::default());
    let (engine, connections) = tunlab::engine_with_identity(
        metrics.clone(),
        RuntimeConfig::default(),
        routes_that_ask_who(),
        attributor(),
        EventSink::none(),
    );
    let wire = Wire::start(engine);

    // A connected UDP socket reports an ICMP port-unreachable as ECONNREFUSED. Sending to a
    // hard-coded unused port therefore let Linux close the flow between the opened metric and
    // the map assertion. A real peer gives the test an observable happens-before edge after the
    // flow has been registered, without weakening production's peer pinning.
    let far_end = tokio::net::UdpSocket::bind((tunlab::SERVER, 0))
        .await
        .expect("bind UDP peer");
    let far_end_port = far_end.local_addr().expect("UDP peer address").port();

    wire.send_datagram(BLOCKED_PORT, far_end_port, b"hello")
        .await;
    let mut arrived = [0_u8; 5];
    let (length, _) = tokio::time::timeout(SOON, far_end.recv_from(&mut arrived))
        .await
        .expect("datagram must arrive before revoke")
        .expect("receive datagram before revoke");
    assert_eq!(&arrived[..length], b"hello");
    assert!(
        settles(SOON, || metrics.snapshot().udp_flows_opened == 1).await,
        "the datagram flow has to be open before it can be revoked: {:?}",
        metrics.snapshot()
    );
    assert!(
        flow_of(&connections, BLOCKED_APP).await.is_some(),
        "and on the map, with its owner"
    );

    assert_eq!(
        connections.revoke(&RevokeTarget::Package {
            package: BLOCKED_APP.to_owned()
        }),
        1
    );
    assert!(
        settles(SOON, || {
            let snapshot = metrics.snapshot();
            snapshot.flows_revoked == 1 && snapshot.flows_closed == 1
        })
        .await,
        "a revoked datagram flow has to end and be accounted as ended — the \
         stack session is released by the same drop: {:?}",
        metrics.snapshot()
    );
    assert!(
        connections.snapshot().connections.is_empty(),
        "and its row has to be gone from the map"
    );

    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_is_named_in_the_event_stream_even_when_it_finds_nothing() {
    let metrics = Arc::new(FlowMetrics::default());
    let revocations = Revocations::default();
    let connections = Arc::new(ConnectionTracker::default());

    let target = RevokeTarget::Package {
        package: BLOCKED_APP.to_owned(),
    };
    let count = connections.revoke(&target);
    revocations.sink().emit_with(|| CoreEvent::FlowsRevoked {
        target: target.kind().to_owned(),
        scope: target.scope(),
        count: count as u64,
    });

    assert_eq!(
        revocations.all(),
        vec![Revoked {
            target: "package".to_owned(),
            scope: Some(BLOCKED_APP.to_owned()),
            count: 0,
        }],
        "'the user blocked this app and it had nothing open' and 'the user \
         never blocked this app' are different facts"
    );
    assert_eq!(metrics.snapshot().flows_revoked, 0);
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_every_flow_resets_every_flow() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let (engine, connections) = tunlab::engine_with_identity(
        metrics.clone(),
        RuntimeConfig::default(),
        routes_that_ask_who(),
        attributor(),
        EventSink::none(),
    );
    let wire = Wire::start(engine);

    wire.handshake(BLOCKED_PORT, port, 1_000).await;
    let (_first, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the first dial has to complete")
        .expect("accept the first");
    wire.handshake(INNOCENT_PORT, port, 5_000).await;
    let (_second, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the second dial has to complete")
        .expect("accept the second");
    assert!(
        flow_of(&connections, BLOCKED_APP).await.is_some()
            && flow_of(&connections, INNOCENT_APP).await.is_some()
    );

    assert_eq!(connections.revoke(&RevokeTarget::All {}), 2);

    // Both relays are cancelled by the same revoke and may emit their resets in either order.
    // Two sequential `watch` calls are not independent: the first one consumes and discards
    // packets for the other client port while waiting for its own. Observe the shared wire once
    // and remember both outcomes so scheduler order cannot turn a real reset into a test timeout.
    let deadline = tokio::time::Instant::now() + SOON;
    let mut reset_seen = [false; 2];
    let mut buffer = [0_u8; 4_096];
    while !reset_seen.iter().all(|seen| *seen) {
        let read = match tokio::time::timeout_at(deadline, wire.app.recv(&mut buffer)).await {
            Ok(Ok(read)) if read != 0 => read,
            _ => break,
        };
        for (index, client_port) in [BLOCKED_PORT, INNOCENT_PORT].into_iter().enumerate() {
            if tunlab::tcp_for_port(&buffer[..read], client_port)
                .is_some_and(|seen| seen.flags & FLAG_RST != 0)
            {
                reset_seen[index] = true;
            }
        }
    }
    assert_eq!(
        reset_seen,
        [true, true],
        "every revoked flow has to be reset, not merely dropped"
    );
    assert!(
        settles(SOON, || metrics.snapshot().flows_revoked == 2).await,
        "{:?}",
        metrics.snapshot()
    );

    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_revoked_while_it_is_dialling_still_ends() {
    // Keep the outbound dial pending after the kernel completes its handshake.
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that never accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let (engine, connections) = tunlab::engine_with_identity(
        metrics.clone(),
        RuntimeConfig::default(),
        routes_that_ask_who(),
        attributor(),
        EventSink::none(),
    );
    let wire = Wire::start(engine);

    wire.handshake(BLOCKED_PORT, port, 1_000).await;
    assert!(
        flow_of(&connections, BLOCKED_APP).await.is_some(),
        "the row is opened before the dial, which is what makes it nameable"
    );

    assert_eq!(
        connections.revoke(&RevokeTarget::Package {
            package: BLOCKED_APP.to_owned()
        }),
        1
    );
    assert!(
        wire.watch(BLOCKED_PORT, SOON, |seen| seen.flags & FLAG_RST != 0)
            .await
            .is_some(),
        "a flow revoked during its dial has to end with a reset like any other"
    );

    drop(listener);
    wire.stop().await;
}
