//! The userspace TCP/IP stack, forked from `ipstack 1.0.0`.
//!
//! Copyright (c) Narrowlink, Apache-2.0. Adapted for FoxCore; the notice and the
//! upstream licence are in `LICENSE-APACHE-ipstack` beside this file and in
//! `THIRD_PARTY_NOTICES.md` at the root.
//!
//! # Why a fork rather than a dependency
//!
//! Because the defect is in the receive path, and the receive path is not
//! reachable from outside the crate. `ipstack 1.0.0` acknowledges data into an
//! **unbounded** channel and computes its advertised window from
//! `read_buffer_size − unordered_packets_total_len` — a subtrahend that counts
//! only what arrived out of order and is therefore almost always zero — then
//! floors that window at one MTU. Both halves were measured before this fork
//! existed and are covered by the tests beside this module:
//!
//! * a stream nothing ever read acknowledged **4 194 580 bytes**, window
//!   constant at 16384, in 169–194 ms;
//! * with `read_buffer_size = 1` the window sat at exactly 1500 and every one of
//!   512 KiB still arrived, one segment per round trip;
//! * a stream nobody ever `accept()`ed still completed its handshake.
//!
//! Nothing above the stack can repair any of that. `BacklogGuard` wraps the
//! *outbound* and cannot even be present during the dial, which is the window in
//! which one pushing application reached **375 MiB of RSS** on the netem bench.
//!
//! # What this fork changes
//!
//! 1. **The window counts everything the flow is holding.** `Tcb` tracks
//!    `unordered_len` and `unread_len` — bytes queued towards `poll_read` that
//!    no caller has taken — and advertises what is left of `read_buffer_size`
//!    after both. See [`stream::tcb::Tcb`].
//! 2. **The window may reach zero,** because a zero window is the only thing in
//!    TCP that means stop. The one-MTU floor in `write_packet_to_device` is
//!    gone.
//! 3. **The window reopens on the wire.** `poll_read` releases what a caller
//!    took and emits a window update when the peer believes the window is shut,
//!    with the RFC 1122 §4.2.3.3 silly-window condition on both sides.
//! 4. **Out-of-window data is dropped rather than buffered,** so the bound holds
//!    against a peer that ignores what it was told, and a refused segment is
//!    still answered — that is where a zero-window probe arrives.
//! 5. **`read_buffer_size` is floored at one MTU,** because a receive buffer
//!    smaller than a segment can hold no segment once the window means what it
//!    says.
//! 6. **The accept queue and the session table are bounded,** and a stack that
//!    is full refuses in the terms of the transport that asked. See
//!    [`IpStackConfig::max_sessions`] and [`accept_queue_depth`] for the policy
//!    and the numbers.
//!
//! Non-behavioural: `ahash` is replaced by the standard hasher and the crate's
//! rustdoc examples are gone (they referenced the `tun` crate, which is not a
//! dependency here). Everything else is upstream, formatted to this workspace's
//! rustfmt.

use packet::{NetworkPacket, NetworkTuple, TransportHeader};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

/// The reliable packet path for TCP sessions and packets back to the device.
///
/// TCP input is bounded by its advertised receive window, and dropping a
/// segment here would turn that working backpressure into a retransmission
/// stall. UDP has no window and deliberately does **not** use this alias; its
/// bounded/drop-counted path is [`SessionPacketSender::Udp`].
pub(crate) type PacketSender = UnboundedSender<NetworkPacket>;
pub(crate) type PacketReceiver = UnboundedReceiver<NetworkPacket>;
pub(crate) type SessionCollection = std::collections::HashMap<NetworkTuple, SessionPacketSender>;

/// Delivery path for packets that belong to an existing stack session.
///
/// TCP keeps its reliable, window-bounded channel. UDP has no receive window
/// and therefore uses a bounded channel with explicit loss accounting: a
/// stalled outbound must cost a fixed amount of memory rather than the life of
/// the VPN process.
#[derive(Clone, Debug)]
pub(crate) enum SessionPacketSender {
    Tcp(PacketSender),
    Udp {
        sender: mpsc::Sender<NetworkPacket>,
        dropped: Arc<AtomicU64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionPacketDelivery {
    Delivered,
    Dropped,
    Closed,
}

impl SessionPacketSender {
    pub(crate) fn tcp(sender: PacketSender) -> Self {
        Self::Tcp(sender)
    }

    pub(crate) fn udp(sender: mpsc::Sender<NetworkPacket>, dropped: Arc<AtomicU64>) -> Self {
        Self::Udp { sender, dropped }
    }

    pub(crate) fn send(&self, packet: NetworkPacket) -> SessionPacketDelivery {
        match self {
            Self::Tcp(sender) => match sender.send(packet) {
                Ok(()) => SessionPacketDelivery::Delivered,
                Err(_) => SessionPacketDelivery::Closed,
            },
            Self::Udp { sender, dropped } => match sender.try_send(packet) {
                Ok(()) => SessionPacketDelivery::Delivered,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    SessionPacketDelivery::Dropped
                }
                Err(mpsc::error::TrySendError::Closed(_)) => SessionPacketDelivery::Closed,
            },
        }
    }
}

/// The queue of streams the stack has opened and the engine has not taken yet.
///
/// Bounded, unlike the packet path above, because everything on it is *new
/// work*: refusing it costs one flow that never started, while refusing a
/// packet costs a flow that was working.
type AcceptSender = mpsc::Sender<IpStackStream>;
type AcceptReceiver = mpsc::Receiver<IpStackStream>;

mod error;
mod packet;
mod stream;

pub use self::error::{IpStackError, Result};
use self::stream::UdpStreamConfig;
pub use self::stream::{
    IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport,
};
pub use self::stream::{TcpConfig, TcpOptions};
pub use etherparse::IpNumber;

/// A flow identifier for a log line that must not carry the flow's addresses.
///
/// The stack's own diagnostics used to interpolate `NetworkTuple` directly —
/// source and destination address and port of the user's traffic — into records
/// at `warn` and `error`. Nothing read them, because no logger was ever
/// installed, so the leak was latent rather than actual; installing one without
/// this would have turned every failing connection into a logcat line naming
/// who the user was talking to. In a privacy VPN that is the wrong direction to
/// fail in.
///
/// The hash is salted per process, so two lines about the same flow can be
/// matched to each other within one run and to nothing at all outside it.
pub(crate) fn redacted(tuple: &NetworkTuple) -> String {
    use std::hash::BuildHasher;
    static SALT: std::sync::OnceLock<std::collections::hash_map::RandomState> =
        std::sync::OnceLock::new();
    let digest = SALT
        .get_or_init(std::collections::hash_map::RandomState::new)
        .hash_one(tuple);
    format!("flow={:08x}", digest as u32)
}

#[cfg(unix)]
const TTL: u8 = 64;

#[cfg(windows)]
const TTL: u8 = 128;

#[cfg(unix)]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "espidf"
))]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "espidf"
))]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x0A];
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

/// Minimum MTU required for IPv6 (per RFC 8200 §5: MTU ≥ 1280).
/// Also satisfies IPv4 minimum MTU (RFC 791 §3.1: 68 bytes).
const MIN_MTU: u16 = 1280;

/// Consecutive tun read failures before the stack gives up on the descriptor.
/// Matches `relay.rs`'s `MAX_RECEIVE_ERRORS`: a transient error is survivable,
/// a persistent one has to end the generation rather than silence it.
const MAX_TUN_READ_ERRORS: u32 = 8;

/// Sessions the stack will hold when nobody has said otherwise.
///
/// `flow::build_stack` always overrides this from `RuntimeConfig`, so on a
/// device the number below is never the one in force; it is what the stack
/// answers to a caller that drives it directly — the benches and the fork's own
/// measurements. The value is the sum of the two engine defaults
/// (`max_tcp_flows` 1024 + `max_udp_flows` 512) so that a stack built by hand
/// behaves like the one the engine builds.
const DEFAULT_MAX_SESSIONS: usize = 1024 + 512;

/// The most streams the accept queue will hold for an engine that has not taken
/// them yet.
///
/// The queue is a hand-off, not a backlog: the engine's accept loop does
/// nothing per stream but `tokio::spawn`, so anything sitting here is a burst,
/// and a burst deeper than this is a sender the engine will not catch up with.
///
/// It is capped *below* the session table on purpose, because the two bound
/// different things. Every TCP or UDP stream on this queue also occupies a
/// session-table slot, so for those the table is the real limit and this one
/// can only trip first. What it is actually here for is the traffic that
/// reaches the queue **without** a session at all — `UnknownTransport` (ICMP
/// and everything else with no ports) and `UnknownNetwork` (packets that did
/// not parse), each carrying a payload the size of an MTU. Those are the only
/// things the session table cannot bound, they are the cheapest packets in the
/// world to forge, and before this they accumulated without limit.
const ACCEPT_QUEUE_CEILING: usize = 256;

/// Datagrams retained for one established UDP flow while its outbound is busy.
///
/// The bound is in packets because every packet came from the TUN and is
/// already bounded by the configured MTU. At the Android MTU of 1400 this is
/// at most about 45 KiB per flow (plus channel bookkeeping), while a burst of
/// 32 packets remains large enough for ordinary QUIC/DNS traffic. UDP has no
/// backpressure signal to send to the application; dropping the newest packet
/// is the only bounded and protocol-honest outcome.
pub(crate) const UDP_SESSION_QUEUE_DEPTH: usize = 32;

/// How deep the accept queue is for a stack of `max_sessions`.
///
/// Never zero (`mpsc::channel` will not build one, and a stack that can accept
/// nothing is not a stack), and never deeper than the session table it serves,
/// so the two limits cannot contradict each other: whichever one is reached
/// first, the answer to the packet is identical.
fn accept_queue_depth(max_sessions: usize) -> usize {
    max_sessions.clamp(1, ACCEPT_QUEUE_CEILING)
}

/// Configuration for the IP stack.
///
/// This structure holds configuration parameters that control the behavior of the IP stack,
/// including network settings and protocol-specific timeouts.
///
#[non_exhaustive]
pub struct IpStackConfig {
    /// Maximum Transmission Unit (MTU) size in bytes.
    /// Default is `MIN_MTU` (1280).
    pub mtu: u16,
    /// Whether to include packet information headers (Unix platforms only).
    /// Default is `false`.
    pub packet_information: bool,
    /// TCP-specific configuration parameters.
    pub tcp_config: Arc<TcpConfig>,
    /// Timeout for UDP connections.
    /// Default is 30 seconds.
    pub udp_timeout: Duration,
    /// The most TCP and UDP sessions this stack will hold at once.
    ///
    /// # Why there is a number here at all
    ///
    /// Upstream has none: `SessionCollection` grows for every new tuple that
    /// arrives, and each entry carries a spawned task, a TCB and a receive
    /// buffer. On a phone the tun is reachable from every installed
    /// application, so "open connections faster than they are accepted" is a
    /// loop any app can write, and the end of it is the VPN service being
    /// killed for memory — which takes the tunnel down and, with it, the
    /// protection the user turned on.
    ///
    /// # What happens when it is reached
    ///
    /// New work is refused; work already in flight is untouched. Concretely:
    ///
    /// * a packet belonging to an existing TCP session is delivered. Existing
    ///   UDP sessions use a separate bounded ingress queue: once that queue is
    ///   full, newer datagrams are dropped and counted instead of allowing a
    ///   stalled consumer to grow memory without a ceiling.
    /// * a SYN for a session that does not exist is answered with a reset, so
    ///   the application fails immediately with `ECONNREFUSED` instead of
    ///   waiting out its SYN schedule. See
    ///   [`stream::refuse_with_reset`](self::stream::refuse_with_reset).
    /// * a datagram for a session that does not exist is dropped, and nothing
    ///   is allocated for it: no session, no stream, no queue entry. UDP has no
    ///   refusal on the wire, and a core that has just run out of room is not
    ///   the right place to start generating ICMP.
    ///
    /// # How it relates to the engine's own limit
    ///
    /// `flow::build_stack` sets this to `max_tcp_flows + max_udp_flows` — the
    /// exact number of flows the engine can serve at once, and the same sum
    /// `PacketSplitter` is already sized with. Larger would let the stack hold
    /// sessions the engine could never take; smaller would refuse flows the
    /// engine had room for. Because the engine's caps are per-transport and
    /// this one is shared, a burst of one transport can still fill the table
    /// while the other transport's slots sit free, so the engine keeps its own
    /// refusal for that case — a reset, for the same reason and with the same
    /// appearance on the wire.
    pub max_sessions: usize,
    /// Shared counter incremented when an established UDP flow's bounded input
    /// queue is full. `FlowEngine` installs its public metrics counter here;
    /// standalone stack users still get a private counter and the same bound.
    pub(crate) udp_queue_drops: Arc<AtomicU64>,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: MIN_MTU,
            packet_information: false,
            tcp_config: Arc::new(TcpConfig::default()),
            udp_timeout: Duration::from_secs(30),
            max_sessions: DEFAULT_MAX_SESSIONS,
            udp_queue_drops: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl IpStackConfig {
    /// Set custom TCP configuration.
    ///
    pub fn with_tcp_config(&mut self, config: TcpConfig) -> &mut Self {
        self.tcp_config = Arc::new(config);
        self
    }

    /// Set the UDP connection timeout.
    ///
    pub fn udp_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.udp_timeout = timeout;
        self
    }

    /// Set the session-table ceiling. See [`IpStackConfig::max_sessions`].
    ///
    /// Clamped to at least one rather than validated: a zero here is a
    /// configuration mistake somewhere above, and a stack that answers every
    /// SYN with a reset would be a very confusing way to report it.
    pub fn max_sessions(&mut self, max_sessions: usize) -> &mut Self {
        self.max_sessions = max_sessions.max(1);
        self
    }

    pub(crate) fn udp_queue_drop_counter(&mut self, counter: Arc<AtomicU64>) -> &mut Self {
        self.udp_queue_drops = counter;
        self
    }

    /// Set the Maximum Transmission Unit (MTU) size.
    ///
    pub fn mtu(&mut self, mtu: u16) -> Result<&mut Self, IpStackError> {
        if mtu < MIN_MTU {
            return Err(IpStackError::InvalidMtuSize(mtu));
        }
        self.mtu = mtu;
        Ok(self)
    }

    /// Set the Maximum Transmission Unit (MTU) size without validation.
    pub fn mtu_unchecked(&mut self, mtu: u16) -> &mut Self {
        self.mtu = mtu;
        self
    }

    /// Enable or disable packet information headers (Unix platforms only).
    ///
    /// When enabled on Unix platforms, the TUN device will include 4-byte packet
    /// information headers.
    ///
    pub fn packet_information(&mut self, packet_information: bool) -> &mut Self {
        self.packet_information = packet_information;
        self
    }
}

/// The main IP stack instance.
///
/// `IpStack` provides a userspace TCP/IP stack implementation for TUN devices.
/// It processes network packets and creates stream abstractions for TCP, UDP, and
/// unknown transport protocols.
///
pub struct IpStack {
    accept_receiver: AcceptReceiver,
    handle: JoinHandle<Result<()>>,
}

impl IpStack {
    /// Create a new IP stack instance.
    ///
    pub fn new<Device>(config: IpStackConfig, device: Device) -> IpStack
    where
        Device: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (accept_sender, accept_receiver) =
            mpsc::channel::<IpStackStream>(accept_queue_depth(config.max_sessions));
        IpStack {
            accept_receiver,
            handle: run(config, device, accept_sender),
        }
    }

    /// Accept an incoming network stream.
    ///
    /// This method waits for and returns the next incoming network connection or packet.
    /// The returned `IpStackStream` enum indicates the type of stream (TCP, UDP, or unknown).
    ///
    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        self.accept_receiver
            .recv()
            .await
            .ok_or(IpStackError::AcceptError)
    }

    /// Stop the IP-stack task and wait until it has dropped the TUN device.
    ///
    /// Aborting a Tokio task only schedules cancellation. Awaiting the handle
    /// is the ownership barrier that guarantees the task future — including
    /// its device — has actually been dropped before the runtime reports that
    /// this generation stopped.
    ///
    /// It does not wait, and the reason is measured rather than cautious.
    ///
    /// An aborted task is dropped when a worker thread next polls it. Awaiting
    /// the handle therefore makes the stop depend on the executor still making
    /// progress — and the executor is exactly what is not guaranteed at that
    /// moment. On a Pixel this was the whole failure: `phase=engine`,
    /// `engine_phase=loop_exited`, the loop having seen cancellation and the
    /// engine future never returning, the app force-killing the handle and then
    /// killing its own process to be sure the tunnel came down. A 250 ms
    /// `tokio::time::timeout` around the wait did not help, because a stalled
    /// runtime does not fire timers either; raising the worker count from two
    /// to four moved the failure from the first cycle to the eighth and did not
    /// remove it.
    ///
    /// So the barrier moves one level out, to where a ceiling exists by
    /// construction: the worker thread shuts the whole Tokio runtime down with
    /// `shutdown_timeout` and only then reports that the generation stopped.
    /// That still releases the device — dropping the runtime drops the task
    /// holding it — and it cannot hang, which the old barrier could.
    pub fn shutdown(&mut self) {
        self.handle.abort();
    }
}

impl Drop for IpStack {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn run<Device: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    config: IpStackConfig,
    mut device: Device,
    accept_sender: AcceptSender,
) -> JoinHandle<Result<()>> {
    let mut sessions: SessionCollection = SessionCollection::new();
    let (session_remove_tx, mut session_remove_rx) = mpsc::unbounded_channel::<NetworkTuple>();
    let pi = config.packet_information;
    let offset = if pi && cfg!(unix) { 4 } else { 0 };
    let mut buffer = vec![0_u8; config.mtu as usize + offset];
    // Reused for every packet written back to the tun; see
    // `process_upstream_recv` for what allocating it per packet cost.
    let mut up_scratch = Vec::with_capacity(config.mtu as usize + offset);
    let (up_pkt_sender, mut up_pkt_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

    tokio::spawn(async move {
        // A read error used to be spelled `Ok(n) = device.read(..)`, which
        // disables the branch on `Err` — no counter, no log, no exit. A
        // persistent error on the descriptor meant packets simply stopped
        // arriving from the tun, forever, while the task stayed alive and the
        // generation looked healthy from every angle the app can see. That is
        // the D1/D2/D7/D10 class: correct behaviour indistinguishable from
        // broken because nothing counted. `relay.rs` already spends an error
        // budget and gives up loudly; this is the same rule.
        let mut read_errors: u32 = 0;
        loop {
            select! {
                read = device.read(&mut buffer) => {
                    let n = match read {
                        Ok(n) => {
                            read_errors = 0;
                            n
                        }
                        Err(error) => {
                            read_errors += 1;
                            log::warn!(
                                "tun read failed ({read_errors}/{MAX_TUN_READ_ERRORS}): {error}"
                            );
                            if read_errors >= MAX_TUN_READ_ERRORS {
                                return Err(error.into());
                            }
                            continue;
                        }
                    };
                    // `offset` is the 4-byte packet-information header on
                    // Unix. A read shorter than it — a zero-length read on a
                    // descriptor being torn down is the realistic case —
                    // would make this range slice panic, inside a task whose
                    // panic the JNI boundary does not catch, taking the app
                    // with it. Upstream never guarded it because upstream is
                    // not linked into someone's phone.
                    let Some(packet) = buffer.get(offset..n) else {
                        log::warn!("short tun read: {n} bytes with a {offset}-byte header");
                        continue;
                    };
                    if let Err(e) = process_device_read(packet, &mut sessions, &session_remove_tx, &up_pkt_sender, &config, &accept_sender).await {
                        let io_err: std::io::Error = e.into();
                        if io_err.kind() == std::io::ErrorKind::ConnectionRefused {
                            log::trace!("Received junk data: {io_err}");
                        } else {
                            log::warn!("process_device_read error: {io_err}");
                        }
                    }
                }
                Some(network_tuple) = session_remove_rx.recv() => {
                    sessions.remove(&network_tuple);
                    log::debug!("session destroyed: {network_tuple}");
                }
                Some(packet) = up_pkt_receiver.recv() => {
                    process_upstream_recv(packet, &mut device, &mut up_scratch, #[cfg(unix)]pi).await?;
                }
                // Without this the loop panics rather than ends once both
                // channels close and the read branch is the only one left
                // disabled — `select!` with every branch disabled and no `else`
                // is a panic by definition.
                else => return Ok(()),
            }
        }
    })
}

/// Take one slot in the accept queue, or report that there is none.
///
/// `try_reserve` rather than `send().await`, and this is the load-bearing
/// choice on the whole path. Awaiting the queue would park the tun read loop —
/// the single task that also delivers packets to every established session and
/// writes every reply back to the device — behind an engine that is not
/// accepting. One application refusing to be dialled would then stall every
/// other flow on the device, which is a worse failure than the one being fixed
/// and is invisible from outside. Refusing is bounded; waiting is not.
///
/// A closed queue is an error rather than a refusal: it means the `IpStack` the
/// engine held is gone, and there is nothing left to accept anything.
fn reserve_accept(accept_sender: &AcceptSender) -> Result<Option<mpsc::Permit<'_, IpStackStream>>> {
    match accept_sender.try_reserve() {
        Ok(permit) => Ok(Some(permit)),
        Err(mpsc::error::TrySendError::Full(())) => Ok(None),
        Err(mpsc::error::TrySendError::Closed(())) => Err(IpStackError::AcceptError),
    }
}

/// Answer a packet the stack has no room to open a session for, in the terms of
/// the transport that asked.
///
/// Nothing here allocates a session, a stream, a task or a table entry, which
/// is the point: the refusal path is reachable by anyone who can send a packet
/// to the tun, so it has to cost strictly less than accepting would.
fn refuse_new_session(packet: &NetworkPacket, up_pkt_sender: &PacketSender, full: &str) {
    let tuple = packet.network_tuple();
    match packet.transport_header() {
        // A refusal that reaches the application as a refusal. Without it the
        // peer waits out its SYN retransmission schedule against a stack that
        // decided in microseconds.
        TransportHeader::Tcp(header) => {
            let payload_len = packet.payload.as_ref().map_or(0, Vec::len);
            if let Err(error) = stream::refuse_with_reset(
                up_pkt_sender,
                packet.dst_addr(),
                packet.src_addr(),
                header,
                payload_len,
            ) {
                log::warn!("{} reset not sent: {error}", redacted(&tuple));
            }
        }
        // Dropped, and deliberately in silence. A datagram has no acceptance to
        // withdraw, so there is nothing truthful to send back; ICMP port
        // unreachable would be a *new* packet emitted by a stack that has just
        // said it has no room, and a source a flood could aim at a third party.
        TransportHeader::Udp(_) | TransportHeader::Unknown => {}
    }
    log::debug!("{} refused: {full}", redacted(&tuple));
}

async fn process_device_read(
    data: &[u8],
    sessions: &mut SessionCollection,
    session_remove_tx: &UnboundedSender<NetworkTuple>,
    up_pkt_sender: &PacketSender,
    config: &IpStackConfig,
    accept_sender: &AcceptSender,
) -> Result<()> {
    let Ok(packet) = NetworkPacket::parse(data) else {
        // New work with nothing behind it, and the cheapest packet on the
        // device to produce: anything that does not parse lands here, carrying
        // a copy of itself. There is no session to refuse and no transport to
        // refuse it in, so a full queue drops it.
        let Some(permit) = reserve_accept(accept_sender)? else {
            log::debug!("accept queue full: unparseable packet dropped");
            return Ok(());
        };
        permit.send(IpStackStream::UnknownNetwork(data.to_owned()));
        return Ok(());
    };

    if let TransportHeader::Unknown = packet.transport_header() {
        // ICMP and everything else without ports. These never enter the session
        // table, so the accept queue is the only thing bounding them.
        let Some(permit) = reserve_accept(accept_sender)? else {
            log::debug!(
                "accept queue full: {} dropped",
                redacted(&packet.network_tuple())
            );
            return Ok(());
        };
        permit.send(IpStackStream::UnknownTransport(
            IpStackUnknownTransport::new(
                packet.src_addr().ip(),
                packet.dst_addr().ip(),
                packet.payload.unwrap_or_default(),
                &packet.ip,
                config.mtu,
                up_pkt_sender.clone(),
            ),
        ));
        return Ok(());
    }

    let network_tuple = packet.network_tuple();
    // Read before the entry borrows the table, and compared before anything is
    // built: a session that is refused must cost nothing that a session that is
    // accepted would have cost.
    let live_sessions = sessions.len();
    match sessions.entry(network_tuple) {
        std::collections::hash_map::Entry::Occupied(entry) => {
            // TCP remains lossless here because its advertised receive window
            // bounds the queue. UDP has no corresponding backpressure signal:
            // its per-flow queue drops newest-on-full and increments the shared
            // counter instead of allowing a stalled outbound to grow the heap.
            let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
            match entry.get().send(packet) {
                SessionPacketDelivery::Delivered => {
                    log::trace!("packet sent to stream: {network_tuple} len {len}");
                }
                SessionPacketDelivery::Dropped => {
                    log::trace!(
                        "{} UDP queue full: datagram dropped",
                        redacted(&network_tuple)
                    );
                }
                // The stream ended before its destroy notification was handled.
                // There is no receiver left, so dropping this packet is the only
                // truthful result; the queued notification removes the stale row.
                SessionPacketDelivery::Closed => {}
            }
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            if live_sessions >= config.max_sessions {
                refuse_new_session(&packet, up_pkt_sender, "session table full");
                return Ok(());
            }
            // Reserved before the stream is built, not after. Building first
            // and finding the queue full afterwards would mean a session that
            // answered a SYN and was then thrown away — the accept-then-abandon
            // shape this whole change exists to remove, moved inside the stack.
            let Some(permit) = reserve_accept(accept_sender)? else {
                refuse_new_session(&packet, up_pkt_sender, "accept queue full");
                return Ok(());
            };
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            let ip_stack_stream = create_stream(packet, config, up_pkt_sender.clone(), Some(tx))?;
            let session_remove_tx = session_remove_tx.clone();
            tokio::spawn(async move {
                rx.await.ok();
                if let Err(e) = session_remove_tx.send(network_tuple) {
                    // A teardown race, not a fault, and it is the *ordinary* end
                    // of a generation rather than a corner of one. The receiver
                    // of this channel lives in the stack's run loop, which
                    // `IpStack::shutdown` and `impl Drop for IpStack` abort
                    // outright; every session still open at that moment posts
                    // its tuple afterwards and finds nobody there. Nothing is
                    // lost by it — the table the tuple would have been removed
                    // from is dropped with the loop.
                    //
                    // At `error!` this was one line per live flow every time the
                    // tunnel stopped, which on the owner's device is a burst of
                    // dozens at the level a reader is entitled to treat as
                    // "something is wrong". Kept rather than removed because the
                    // same send failing while the loop is *running* would be a
                    // session that never leaves the table, and that is worth
                    // being able to see.
                    log::debug!(
                        "session removal not delivered ({}): {e} — the stack's run \
                         loop is gone, which is how a generation ends",
                        redacted(&network_tuple)
                    );
                }
            });
            let packet_sender = ip_stack_stream.stream_sender()?;
            permit.send(ip_stack_stream);
            entry.insert(packet_sender);
            log::debug!("session created: {network_tuple}");
        }
    }
    Ok(())
}

fn create_stream(
    packet: NetworkPacket,
    cfg: &IpStackConfig,
    up_pkt_sender: PacketSender,
    msgr: Option<::tokio::sync::oneshot::Sender<()>>,
) -> Result<IpStackStream> {
    let src_addr = packet.src_addr();
    let dst_addr = packet.dst_addr();
    match packet.transport_header() {
        TransportHeader::Tcp(h) => {
            let stream = IpStackTcpStream::new(
                src_addr,
                dst_addr,
                h.clone(),
                up_pkt_sender,
                cfg.mtu,
                msgr,
                cfg.tcp_config.clone(),
            )?;
            Ok(IpStackStream::Tcp(stream))
        }
        TransportHeader::Udp(_) => {
            let payload = packet.payload.unwrap_or_default();
            let stream = IpStackUdpStream::new(
                src_addr,
                dst_addr,
                payload,
                up_pkt_sender,
                UdpStreamConfig {
                    mtu: cfg.mtu,
                    timeout_interval: cfg.udp_timeout,
                    queue_drops: cfg.udp_queue_drops.clone(),
                },
                msgr,
            );
            Ok(IpStackStream::Udp(stream))
        }
        TransportHeader::Unknown => Err(IpStackError::UnsupportedTransportProtocol),
    }
}

/// Serialise one packet into `scratch` and write it to the device.
///
/// `scratch` is owned by the run loop and reused for every packet: this used to
/// allocate a fresh zero-capacity `Vec` per packet and let the serialiser grow
/// it a header field at a time, then — on unix with packet information — insert
/// four bytes at the front with `splice(0..0, ..)`, memmoving the entire packet
/// to make room. Both ran on every packet going to the tun.
async fn process_upstream_recv<Device: AsyncWrite + Unpin + 'static>(
    up_packet: NetworkPacket,
    device: &mut Device,
    scratch: &mut Vec<u8>,
    #[cfg(unix)] packet_information: bool,
) -> Result<()> {
    scratch.clear();
    // The prefix goes in first, so the packet is written once, in place, behind
    // it.
    #[cfg(unix)]
    if packet_information {
        let proto = if up_packet.src_addr().is_ipv4() {
            TUN_PROTO_IP4
        } else {
            TUN_PROTO_IP6
        };
        scratch.extend_from_slice(&TUN_FLAGS);
        scratch.extend_from_slice(&proto);
    }
    if up_packet.write_to(scratch).is_err() {
        log::warn!("to_bytes error");
        return Ok(());
    }
    device.write_all(scratch).await?;
    // device.flush().await?;

    Ok(())
}
