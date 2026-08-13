//! A tun the test drives by hand.
//!
//! The engine is run over a datagram socketpair, so a test can inject real
//! IPv4/TCP segments and read back the ones the core produces. Everything that
//! matters about a flow's life — the stack answering the SYN, the core dialling,
//! the relay running, the close coming back — is observable as packets, which is
//! the only place the application's view of the tunnel actually lives.
//!
//! Written against the wire on purpose: the counters were right in every defect
//! the netem lab found, and the application still saw nothing.

#![allow(dead_code)]

pub mod sender;

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

use foxcore_api::{DnsConfig, EventSink, FlowAttributor, RouteAction, RuntimeConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_tun::{
    ConnectionTracker, FlowEngine, FlowEngineContext, FlowMetrics, FlowPolicyStore, TunDevice,
};
use tokio_util::sync::CancellationToken;

pub const IPV4_HEADER: usize = 20;
pub const TCP_HEADER: usize = 20;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;
pub const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const SERVER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const CLIENT_PORT: u16 = 49_152;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;

/// RFC 1071, written out rather than reused from the production path so the
/// packets these tests inject are checked by different arithmetic than the one
/// the core uses to read them.
fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(u16::from_be_bytes([last, 0]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4/TCP segment to [`SERVER`], with an optional payload and no options.
pub fn segment(
    destination_port: u16,
    flags: u8,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    segment_to(
        SERVER,
        destination_port,
        flags,
        sequence,
        acknowledgement,
        payload,
    )
}

/// The same, aimed at an address the test chooses.
///
/// The address is a parameter because some verdicts are *about* it: the core
/// treats a flow to the resolver it advertised differently from the same flow
/// to anything else, and a lab that could only reach one destination could not
/// tell the two apart.
pub fn segment_to(
    server: Ipv4Addr,
    destination_port: u16,
    flags: u8,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    segment_from(
        CLIENT_PORT,
        server,
        destination_port,
        flags,
        sequence,
        acknowledgement,
        payload,
    )
}

/// The same, from a source port the test chooses.
///
/// The source port is what makes two segments two different *sessions* to the
/// stack, so any question about how many flows the core will hold at once has
/// to be asked with more than one of them. Everything above delegates here.
pub fn segment_from(
    client_port: u16,
    server: Ipv4Addr,
    destination_port: u16,
    flags: u8,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    let total = (IPV4_HEADER + TCP_HEADER + payload.len()) as u16;
    let mut ip = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x01,
        0x40,
        0x00,
        64,
        PROTOCOL_TCP,
        0x00,
        0x00,
    ];
    ip.extend_from_slice(&CLIENT.octets());
    ip.extend_from_slice(&server.octets());
    let header_checksum = internet_checksum(&[&ip]);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let mut tcp = Vec::with_capacity(TCP_HEADER + payload.len());
    tcp.extend_from_slice(&client_port.to_be_bytes());
    tcp.extend_from_slice(&destination_port.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&acknowledgement.to_be_bytes());
    // Data offset 5 words, no options.
    tcp.push(0x50);
    tcp.push(flags);
    tcp.extend_from_slice(&65_535_u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]); // checksum, filled below
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    tcp.extend_from_slice(payload);

    let pseudo = {
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&CLIENT.octets());
        pseudo.extend_from_slice(&server.octets());
        pseudo.push(0);
        pseudo.push(PROTOCOL_TCP);
        pseudo.extend_from_slice(&((TCP_HEADER + payload.len()) as u16).to_be_bytes());
        pseudo
    };
    let tcp_checksum = internet_checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    ip.extend_from_slice(&tcp);
    ip
}

/// One IPv4/UDP datagram from a source port the test chooses.
///
/// The UDP checksum is left at zero, which IPv4 defines as "not computed" and
/// which the stack does not verify — it slices headers rather than validating
/// them. A test that needed the checksum to mean something would be testing
/// `etherparse`.
pub fn datagram_from(
    client_port: u16,
    server: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    const UDP_HEADER: usize = 8;
    let total = (IPV4_HEADER + UDP_HEADER + payload.len()) as u16;
    let mut ip = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x02,
        0x40,
        0x00,
        64,
        PROTOCOL_UDP,
        0x00,
        0x00,
    ];
    ip.extend_from_slice(&CLIENT.octets());
    ip.extend_from_slice(&server.octets());
    let header_checksum = internet_checksum(&[&ip]);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    ip.extend_from_slice(&client_port.to_be_bytes());
    ip.extend_from_slice(&destination_port.to_be_bytes());
    ip.extend_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(payload);
    ip
}

/// A TCP segment the core sent to our client port.
///
/// The sequence number matters: the stack picks a random ISN, and an ACK that
/// does not name it leaves the session short of `Established` — which is the one
/// state `ipstack`'s `poll_shutdown` will send a FIN from. A test that
/// hard-codes the acknowledgement passes or fails on the stack's choice of
/// starting number rather than on the behaviour under test.
///
/// `window` is here because it is the only thing on the wire that can tell a
/// sender to stop, and whether it ever does is a question worth asking of a
/// stack in a measurement rather than in a comment.
#[derive(Debug, Clone, Copy)]
pub struct Seen {
    pub flags: u8,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub window: u16,
}

pub fn tcp_for_client(packet: &[u8]) -> Option<Seen> {
    tcp_for_port(packet, CLIENT_PORT)
}

/// The same, for a client port the test chose with [`segment_from`].
///
/// The port is the filter and not a returned field on purpose: a test that
/// drives several sessions at once has to be able to say *which* session a
/// segment belongs to, and matching by port at the point of the question is
/// what stops one session's reset from being read as another's.
pub fn tcp_for_port(packet: &[u8], client_port: u16) -> Option<Seen> {
    if packet.len() < IPV4_HEADER + TCP_HEADER || packet[0] >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if packet[9] != PROTOCOL_TCP || packet.len() < header_length + TCP_HEADER {
        return None;
    }
    let tcp = &packet[header_length..];
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    (destination_port == client_port).then(|| Seen {
        flags: tcp[13],
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        acknowledgement: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
    })
}

/// The stack alone over a datagram socketpair: no engine, no outbound, nothing
/// above it.
///
/// Everything P7.4 is about lives between the tun and the accepted stream, and
/// putting the engine in the way would mean measuring the engine. Returns the
/// application's side of the tun and the stack itself.
pub fn stack_over_socketpair(
    mtu: u16,
    read_buffer_size: Option<usize>,
) -> (
    tokio::net::UnixDatagram,
    foxcore_tun::ipstack::IpStack,
    foxcore_tun::TunFdOwner,
) {
    stack_over_socketpair_holding(mtu, read_buffer_size, None)
}

/// The same stack with its session table capped at a number the test can
/// actually reach.
///
/// The production cap is `max_tcp_flows + max_udp_flows` — 1536 — and a test
/// that filled it by hand would be measuring the socketpair rather than the
/// policy. The mechanism does not change with the number, so the number is a
/// parameter.
pub fn stack_over_socketpair_limited(
    mtu: u16,
    max_sessions: usize,
) -> (
    tokio::net::UnixDatagram,
    foxcore_tun::ipstack::IpStack,
    foxcore_tun::TunFdOwner,
) {
    stack_over_socketpair_holding(mtu, None, Some(max_sessions))
}

fn stack_over_socketpair_holding(
    mtu: u16,
    read_buffer_size: Option<usize>,
    max_sessions: Option<usize>,
) -> (
    tokio::net::UnixDatagram,
    foxcore_tun::ipstack::IpStack,
    foxcore_tun::TunFdOwner,
) {
    use foxcore_tun::ipstack::{IpStack, IpStackConfig, TcpConfig};

    let (app, device) = UnixDatagram::pair().expect("socketpair");
    app.set_nonblocking(true).expect("nonblocking");
    let app = tokio::net::UnixDatagram::from_std(app).expect("register the app side");
    // Returned rather than dropped here: the owner is what closes the
    // descriptor, so letting it fall at the end of this function would shut the
    // device the stack is about to read from.
    let (device, tun_fd_owner) =
        TunDevice::from_owned_fd(OwnedFd::from(device)).expect("wrap the device side");

    let mut config = IpStackConfig::default();
    config.mtu(mtu).expect("mtu");
    config.packet_information(false);
    if let Some(read_buffer_size) = read_buffer_size {
        let mut tcp = TcpConfig::default();
        tcp.read_buffer_size = read_buffer_size;
        config.with_tcp_config(tcp);
    }
    if let Some(max_sessions) = max_sessions {
        config.max_sessions(max_sessions);
    }
    (app, IpStack::new(config, device), tun_fd_owner)
}

pub fn engine(metrics: Arc<FlowMetrics>, runtime: RuntimeConfig) -> FlowEngine {
    engine_with_events(metrics, runtime, EventSink::none(), EventSink::none())
}

/// The same engine with its two event sinks supplied, so a test can ask what
/// the application would have been told rather than only what a counter says.
///
/// Two sinks and not one because they are two: the policy store emits on its
/// own decisions and the engine on the flow's, and a test that fed the same
/// recorder to both could not say which side spoke.
pub fn engine_with_events(
    metrics: Arc<FlowMetrics>,
    runtime: RuntimeConfig,
    policy_events: EventSink,
    flow_events: EventSink,
) -> FlowEngine {
    engine_with_dns(
        metrics,
        runtime,
        DnsConfig::default(),
        policy_events,
        flow_events,
    )
}

/// The same engine with the DNS document the profile would carry.
///
/// The default document intercepts nothing, which is the right shape for tests
/// about flows. It is the wrong one for tests about the resolver: half of what
/// the data plane decides about a flow — whether it is DNS at all, and whether
/// it is aimed at the address the core told the platform to use — is read out
/// of this document and out of nowhere else.
pub fn engine_with_dns(
    metrics: Arc<FlowMetrics>,
    runtime: RuntimeConfig,
    dns: DnsConfig,
    policy_events: EventSink,
    flow_events: EventSink,
) -> FlowEngine {
    let (engine, _) = engine_parts(
        metrics,
        runtime,
        dns,
        RouteTable::compile(Vec::new(), RouteAction::Direct),
        FlowAttributor::none(),
        policy_events,
        flow_events,
    );
    engine
}

/// An engine that knows who owns each flow, and the traffic map it records
/// them in.
///
/// Two things are needed for a question about *one app*, and neither is the
/// default. The attributor is what answers "who opened this", and a
/// [`RouteTable`] that asks for identity is what makes the engine consult it
/// before the flow opens rather than afterwards on the telemetry path — with no
/// per-app rules the owner arrives late and by a different route (D12), which
/// is correct on a device and a race in a test.
///
/// The map is returned because a caller that wants to revoke a flow has to be
/// able to name it, and the map is where the names are.
pub fn engine_with_identity(
    metrics: Arc<FlowMetrics>,
    runtime: RuntimeConfig,
    routes: RouteTable,
    attributor: FlowAttributor,
    flow_events: EventSink,
) -> (FlowEngine, Arc<ConnectionTracker>) {
    engine_parts(
        metrics,
        runtime,
        DnsConfig::default(),
        routes,
        attributor,
        EventSink::none(),
        flow_events,
    )
}

#[allow(clippy::too_many_arguments)]
fn engine_parts(
    metrics: Arc<FlowMetrics>,
    runtime: RuntimeConfig,
    dns: DnsConfig,
    routes: RouteTable,
    attributor: FlowAttributor,
    policy_events: EventSink,
    flow_events: EventSink,
) -> (FlowEngine, Arc<ConnectionTracker>) {
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            routes,
            dns,
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            policy_events,
        )
        .expect("policy"),
    );
    let connections = Arc::new(ConnectionTracker::default());
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor,
        runtime,
        metrics,
        events: flow_events,
        packet_tunnel: false,
        connections: connections.clone(),
    });
    (engine, connections)
}

/// A running engine and the application side of its tun.
pub struct Lab {
    app: tokio::net::UnixDatagram,
    cancel: CancellationToken,
    running: tokio::task::JoinHandle<io::Result<()>>,
    /// Closes the TUN descriptor when the lab goes away, which is the point at
    /// which the engine is done with it.
    _tun_fd_owner: foxcore_tun::TunFdOwner,
    /// Next sequence number the test will send.
    sequence: u32,
    /// What the test acknowledges: the stack's sequence plus one.
    acknowledgement: u32,
    port: u16,
    /// Where the current connection is aimed. Defaults to [`SERVER`]; a test
    /// asking about the resolver the core advertised has to name it.
    server: Ipv4Addr,
}

impl Lab {
    /// Multi-thread on purpose: `ipstack`'s `Drop` blocks on its session task
    /// through `block_in_place`, which is not available on a current-thread
    /// runtime — the same property that makes abandoning a stream more expensive
    /// than closing it.
    pub fn start(metrics: Arc<FlowMetrics>, runtime: RuntimeConfig) -> Self {
        Self::start_engine(engine(metrics, runtime))
    }

    /// The same, with an engine the test built itself — a recording event sink,
    /// usually.
    pub fn start_with(engine: FlowEngine) -> Self {
        Self::start_engine(engine)
    }

    fn start_engine(engine: FlowEngine) -> Self {
        // A datagram socketpair, not a pipe: the device the engine reads is a
        // packet boundary per read, and a stream would hand it two segments
        // glued together the first time the timing was unlucky.
        let (app, device) = UnixDatagram::pair().expect("socketpair");
        app.set_nonblocking(true).expect("nonblocking");
        let app = tokio::net::UnixDatagram::from_std(app).expect("register the app side");
        // Kept in the harness below: dropping it here would close the
        // descriptor before the first packet is injected.
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
            sequence: 1_000,
            acknowledgement: 0,
            port: 0,
            server: SERVER,
        }
    }

    /// Open a connection to `port` and complete the handshake.
    ///
    /// A half-open session would prove nothing: `Established` is the state the
    /// core dials from and the only one the stack will send a FIN out of.
    pub async fn open(&mut self, port: u16) {
        self.open_to(SERVER, port).await;
    }

    /// The same handshake, to an address the test names.
    ///
    /// Separate entry point rather than a field the caller sets first, so a
    /// test cannot open to one address and then send to another — which is a
    /// different flow to the stack and a silent mistrial.
    pub async fn open_to(&mut self, server: Ipv4Addr, port: u16) {
        self.server = server;
        self.port = port;
        self.send(FLAG_SYN, &[]).await;
        self.sequence += 1;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = self
                .next_segment(deadline)
                .await
                .expect("the stack must answer the SYN");
            if seen.flags & FLAG_SYN != 0 && seen.flags & FLAG_ACK != 0 {
                self.acknowledgement = seen.sequence.wrapping_add(1);
                self.send(FLAG_ACK, &[]).await;
                return;
            }
        }
    }

    pub async fn send(&mut self, flags: u8, payload: &[u8]) {
        let packet = segment_to(
            self.server,
            self.port,
            flags,
            self.sequence,
            self.acknowledgement,
            payload,
        );
        self.app.send(&packet).await.expect("inject a segment");
        self.sequence = self.sequence.wrapping_add(payload.len() as u32);
    }

    /// A TCP keepalive from the application.
    ///
    /// An empty segment one byte *behind* the sequence number the stack is
    /// expecting — that is the shape that makes a peer answer, and it is how
    /// `Tcb::check_pkt_type` recognises one. Its own method rather than a flag
    /// on [`Lab::send`] because it must not advance the sequence number: a
    /// keepalive carries no data, and a test that let it move the stream would
    /// be measuring a hole in the stream instead of liveness.
    ///
    /// What makes this worth having: the stack answers these *itself*, in its
    /// session task, so nothing above the stack ever learns that the connection
    /// is alive. Every timeout in the core has to be right about that or it is
    /// a timer that kills push channels.
    pub async fn keepalive(&mut self) {
        let packet = segment_to(
            self.server,
            self.port,
            FLAG_ACK,
            self.sequence.wrapping_sub(1),
            self.acknowledgement,
            &[],
        );
        self.app.send(&packet).await.expect("inject a keepalive");
    }

    /// The next segment the core sends to our client port, or `None` once the
    /// deadline passes.
    pub async fn next_segment(&self, deadline: tokio::time::Instant) -> Option<Seen> {
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match tokio::time::timeout_at(deadline, self.app.recv(&mut buffer)).await {
                Ok(Ok(read)) if read != 0 => read,
                _ => return None,
            };
            if let Some(seen) = tcp_for_client(&buffer[..read]) {
                return Some(seen);
            }
        }
    }

    /// Wait for the core's FIN and acknowledge it, leaving this side open.
    ///
    /// The lab injects packets and answers nothing on its own, which is right
    /// for every question about a flow the core ends. It is wrong for a question
    /// about a **half-closed** one: a FIN nobody acknowledges is retransmitted
    /// and then abandoned by `ipstack`, so the session reaches `Closed` in about
    /// a second and the relay ends on the stack's own timer rather than on the
    /// behaviour under test. A real application's stack acknowledges the FIN
    /// immediately and only *then* decides whether to close — a browser holding
    /// the socket in its connection pool never does.
    ///
    /// The acknowledgement counts the FIN's one sequence byte and assumes the
    /// segment carries no payload, which is what a close from a far end that has
    /// already sent everything looks like. Returns whether a FIN arrived at all.
    pub async fn acknowledge_close_within(&mut self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while let Some(seen) = self.next_segment(deadline).await {
            if seen.flags & FLAG_FIN == 0 {
                continue;
            }
            self.acknowledgement = seen.sequence.wrapping_add(1);
            self.send(FLAG_ACK, &[]).await;
            return true;
        }
        false
    }

    /// Whether the core closes this connection towards the application within
    /// `within`, as a FIN or an RST on the wire.
    pub async fn closed_within(&self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        while let Some(seen) = self.next_segment(deadline).await {
            if seen.flags & (FLAG_FIN | FLAG_RST) != 0 {
                return true;
            }
        }
        false
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.running).await;
    }
}
