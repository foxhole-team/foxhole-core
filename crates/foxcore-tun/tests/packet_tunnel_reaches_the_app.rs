//! What the L3 path tells the application, asked of the whole engine.
//!
//! Every existing test of these two refusals drives `PacketTunnelRelay::run`
//! directly, with a sink the test handed the relay itself. That proves the
//! relay speaks. It cannot prove the seam: in production the relay is built by
//! the runtime and the sink is attached by `FlowEngine::run_with_packet_tunnel`,
//! and a device run found `nativeDrainEvents` returning `EVENTS count=0` for a
//! whole scenario in which `tunnel_routing_loops` climbed to 44. Counters
//! through, events not — which is a statement about the seam
//! and about nothing else, so the seam is what these tests run.
//!
//! Same file covers the L3 half of D14: on this path a DoT probe at the
//! advertised resolver would be sealed into the tunnel rather than terminated,
//! so the decision that sends it to the stack instead is a packet-path decision
//! and has to be asserted as one.

#![cfg(feature = "wireguard")]

mod tunlab;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxcore_api::{
    CoreEvent, DnsBlocklistConfig, DnsConfig, EventSink, FlowAttributor, OutboundId, RouteAction,
    RuntimeConfig, SecretString, WireguardConfig,
};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::{Outbound, OutboundRegistry, PacketTunnelOutbound};
use foxcore_route::RouteTable;
use foxcore_tun::{
    ConnectionTracker, FlowEngine, FlowEngineContext, FlowMetrics, FlowPolicyStore,
    PacketTunnelRelay, TunDevice,
};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// The address on the tun, and the one the profile advertises as its resolver.
const TUN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const TUNNEL_V4: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const ADVERTISED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 53);
const SERVER_STATIC: [u8; 32] = [9_u8; 32];

fn base64(bytes: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn packet_tunnel(endpoint: SocketAddr) -> PacketTunnelOutbound {
    let config = WireguardConfig {
        server: endpoint.ip().to_string(),
        port: endpoint.port(),
        server_ip: Some(endpoint.ip()),
        private_key: SecretString::new(base64(&[7_u8; 32])),
        peer_public_key: SecretString::new(base64(
            &proto_wireguard::noise::public_key(&SERVER_STATIC).unwrap(),
        )),
        preshared_key: None,
        address: vec![format!("{TUNNEL_V4}/32").parse().unwrap()],
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        mtu: 1420,
        persistent_keepalive_s: None,
        reserved: None,
        amnezia: None,
    };
    PacketTunnelOutbound::wireguard(config, ProtectedDialer::host()).unwrap()
}

/// A minimal IPv4/UDP datagram from the tun's own address.
fn udp_packet(destination: Ipv4Addr, destination_port: u16) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&TUN_V4.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet
}

struct Lab {
    app: tokio::net::UnixDatagram,
    cancel: CancellationToken,
    running: tokio::task::JoinHandle<std::io::Result<()>>,
    _tun_fd_owner: foxcore_tun::TunFdOwner,
    metrics: Arc<FlowMetrics>,
    seen: Arc<Mutex<Vec<CoreEvent>>>,
}

impl Lab {
    /// The production assembly, in production order: the runtime builds the
    /// relay and hands it to the engine, and the engine is what attaches the
    /// audit sink to it. Any test that attached the sink itself would be
    /// testing a wiring nothing ships.
    async fn start(dns: DnsConfig, endpoint: SocketAddr) -> Self {
        let metrics = Arc::new(FlowMetrics::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let sink = EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event);
        });

        let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
        let policy = Arc::new(
            FlowPolicyStore::new(
                1,
                RouteTable::compile(
                    Vec::new(),
                    RouteAction::Outbound(OutboundId("primary".to_owned())),
                ),
                dns,
                outbounds.clone(),
                direct.clone(),
                metrics.clone(),
                EventSink::none(),
            )
            .expect("policy"),
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
            connections: Arc::new(ConnectionTracker::default()),
        });
        let relay = PacketTunnelRelay::connect(
            &packet_tunnel(endpoint),
            &[IpAddr::V4(TUN_V4)],
            metrics.clone(),
        )
        .await
        .expect("the relay should bind and connect its socket");

        let (app, device) = UnixDatagram::pair().expect("socketpair");
        app.set_nonblocking(true).expect("nonblocking");
        let app = tokio::net::UnixDatagram::from_std(app).expect("register the app side");
        // Kept in the lab below: the owner is what closes the descriptor, and
        // dropping it here would shut the device before the first packet.
        let (device, tun_fd_owner) =
            TunDevice::from_owned_fd(OwnedFd::from(device)).expect("wrap the device");
        let cancel = CancellationToken::new();
        let engine_cancel = cancel.clone();
        let running = tokio::spawn(async move {
            engine
                .run_with_packet_tunnel(device, 1500, relay, engine_cancel)
                .await
        });
        Self {
            app,
            cancel,
            _tun_fd_owner: tun_fd_owner,
            running,
            metrics,
            seen,
        }
    }

    async fn inject(&self, packet: Vec<u8>) {
        self.app.send(&packet).await.expect("inject a packet");
    }

    fn reasons(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(|event| {
                let value = serde_json::to_value(event).ok()?;
                Some(value.get("reason")?.as_str()?.to_owned())
            })
            .collect()
    }

    fn counter(&self, field: &str) -> u64 {
        serde_json::to_value(self.metrics.snapshot())
            .ok()
            .and_then(|value| value.get(field).and_then(serde_json::Value::as_u64))
            .unwrap_or_default()
    }

    /// Poll rather than sleep a fixed amount: the counter is the fact this test
    /// is waiting on, and a fixed sleep is either flaky or slow.
    async fn wait_for(&self, field: &str, at_least: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if self.counter(field) >= at_least {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{field} never reached {at_least}");
    }

    async fn stop(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.running).await;
    }
}

/// D15's routing loop, asked of the whole engine rather than of the relay.
///
/// The shape is what the platform produces when `protect()` did not take the
/// peer socket out of the tun it is serving: a datagram from the tun's own
/// address to the peer endpoint, address *and* port. The relay refuses to seal
/// it and counts it. The question here is only whether the application is told,
/// because on device it was not.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_routing_loop_is_reported_to_whoever_drains_events_not_only_counted() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let lab = Lab::start(DnsConfig::default(), endpoint).await;

    let looped = udp_packet(endpoint.ip().to_string().parse().unwrap(), endpoint.port());
    for _ in 0..4 {
        lab.inject(looped.clone()).await;
    }
    lab.wait_for("tunnel_routing_loops", 1).await;

    assert_eq!(
        lab.reasons(),
        vec!["tunnel_routing_loop".to_owned()],
        "the counter said this happened 44 times on device and the event stream \
         said nothing at all; an application that reads events rather than \
         counters has to learn the cause too — once, because the condition is a \
         packet flood and a record per lap would be a second denial of service"
    );

    lab.stop().await;
}

/// The other half of D15, on the same seam: a peer that has answered nothing
/// while we kept sending. Four `REKEY_TIMEOUT` windows pass on tokio's clock.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_silent_peer_is_reported_to_whoever_drains_events_not_only_counted() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let lab = Lab::start(DnsConfig::default(), endpoint).await;

    // One packet starts the handshake; nothing on the far side ever answers it.
    lab.inject(udp_packet(Ipv4Addr::new(93, 184, 216, 34), 443))
        .await;
    tokio::time::sleep(Duration::from_secs(25)).await;

    assert_eq!(
        lab.counter("tunnel_peer_silences"),
        1,
        "this test is only meaningful if the relay reached the verdict at all"
    );
    assert!(
        lab.reasons()
            .iter()
            .any(|reason| reason == "tunnel_peer_unresponsive"),
        "a tunnel that is down while every health counter reads zero is exactly \
         the state an event exists for: {:?}",
        lab.reasons()
    );

    lab.stop().await;
}

/// D14 on the L3 path. Without the split decision this flow is sealed into the
/// tunnel, and nothing downstream can refuse it in band: a packet tunnel has no
/// stack to answer with, so the probe would meet a black hole and Android would
/// wait out `kDotConnectTimeoutMs` — 127 seconds by default — before falling
/// back to the DNS we filter.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dot_probe_is_taken_off_the_l3_path_so_the_stack_can_refuse_it() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let dns = DnsConfig {
        advertise: Some(ADVERTISED.to_string()),
        blocklist: DnsBlocklistConfig {
            suffixes: vec!["ads.example".to_owned()],
            ..DnsBlocklistConfig::default()
        },
        ..DnsConfig::default()
    };
    let lab = Lab::start(dns, endpoint).await;

    lab.inject(udp_packet(ADVERTISED, 853)).await;
    lab.wait_for("split_to_stack", 1).await;

    assert_eq!(
        lab.counter("split_to_tunnel"),
        0,
        "sealed into the tunnel this probe is unanswerable, and an unanswered \
         probe is two minutes of DoT connect timeout before the device asks \
         again in the clear"
    );

    lab.stop().await;
}
