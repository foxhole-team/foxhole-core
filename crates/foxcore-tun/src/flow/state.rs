use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use foxcore_api::{DnsConfig, EventSink, FlowAttributor, RuntimeConfig};
use foxcore_dns::DnsCache;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_route::ruleset::{RuleSetArtifact, VerifiedRuleSet};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use foxcore_trafficmap::TrafficMap;

use crate::FlowMetrics;
use crate::continuity::ContinuityGate;
use crate::dns::DnsProxy;

/// How long a flow the core is giving up on waits for the application to
/// acknowledge its close. See [`FlowEngine::close_towards_app`].
pub(crate) const CLIENT_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a relay whose **remote half has closed** may carry nothing before
/// the core gives the flow slot back.
///
/// Not a second idle timeout — a different question with a different answer.
/// `RuntimeConfig::tcp_idle_timeout_s` is an hour because a silent connection
/// may still be alive: the stack absorbs the application's keepalives, so
/// "no bytes" and "no life" look identical from the relay, and the connections
/// that are silent for half an hour and alive are the ones a user notices going
/// away — messengers, mail, notifications. Every word of that argument depends
/// on something still being able to *arrive*. Once the far end has sent its FIN
/// nothing can: the only direction left is the application's own, and silence in
/// it has no innocent explanation of the kind the hour was bought for.
///
/// Half-open is still legitimate TCP and this is still a window rather than an
/// immediate close, because the application may have bytes to push to a peer
/// that has only stopped *sending*. The window is reset by any byte the flow
/// moves, so a half-open sender that is working is never touched by it; what it
/// bounds is the case where the peer is gone and the local side has nothing
/// left, which on the owner's Pixel was 77 sockets in `CLOSE_WAIT` and 77 of
/// `max_tcp_flows` held for an hour each.
///
/// Thirty seconds, and the number is borrowed rather than invented:
///
/// * It is [`crate::backlog::STALL_TIMEOUT`], the core's existing answer to
///   "this established transfer has moved nothing and is dead", chosen there
///   from the RTO backoff a congested-but-alive socket runs through (1, 2, 4, 8,
///   16 s). A half-open sender recovering from congestion clears that band with
///   room, which is the only false positive that would cost anything.
/// * It is what a proxy that has this state named already uses: HAProxy's
///   `timeout client-fin` / `timeout server-fin` govern exactly a half-closed
///   connection, and thirty seconds is the value its own documentation reaches
///   for.
/// * The ratio to the idle window is the point — 120×. The hour is the price of
///   not killing a live silent connection; after the peer's FIN there is no such
///   thing to protect, so the price is not worth paying.
///
/// Clamped to the configured idle window at the call site: a profile that asks
/// for a five-second TCP idle timeout must not get a thirty-second half-closed
/// one, because that would make the more specific state the more patient one.
pub(crate) const HALF_CLOSED_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) const IP_PROTOCOL_ICMP: u8 = 1;
#[cfg(feature = "wireguard")]
pub(super) const IP_PROTOCOL_TCP: u8 = 6;
#[cfg(feature = "wireguard")]
pub(super) const IP_PROTOCOL_UDP: u8 = 17;
/// Packets buffered between the tun and each destination. Bounded because the
/// queue is the only thing standing between a slow peer and the whole device's
/// memory; at an ordinary MTU this is a few hundred kilobytes per hop.
#[cfg(feature = "wireguard")]
pub(crate) const PACKET_QUEUE: usize = 256;
/// A tun read must fit the largest frame the interface can produce, or the read
/// truncates a packet into garbage the stack then tries to parse.
#[cfg(feature = "wireguard")]
pub(crate) const TUN_READ_HEADROOM: usize = 64;

/// The primary outbound is addressable under both names, and a route naming
/// either one means "the profile the user selected".
pub(crate) fn is_primary_outbound(id: &str) -> bool {
    matches!(id, "default" | "primary")
}

#[derive(Clone)]
pub struct FlowEngine {
    pub(crate) generation: u64,
    pub(crate) outbounds: Arc<OutboundRegistry>,
    pub(crate) direct: Arc<Outbound>,
    pub(crate) policy: Arc<FlowPolicyStore>,
    pub(crate) attributor: FlowAttributor,
    pub(crate) runtime: RuntimeConfig,
    pub(crate) metrics: Arc<FlowMetrics>,
    pub(crate) events: EventSink,
    /// The primary outbound is an L3 packet tunnel, not a stream proxy. Only
    /// `select_outbound` reads it, and only to refuse — see the comment there.
    pub(crate) packet_tunnel: bool,
    pub(crate) connections: Arc<TrafficMap>,
    /// Cancelled when this generation ends.
    ///
    /// Read by abandoned attribution tasks so they can decline to make a
    /// platform call nobody is waiting for — see [`FlowEngine::attribute_context`].
    pub(crate) shutdown: CancellationToken,
    /// Which lanes are suspended waiting for a user decision. Default is a gate
    /// that never holds, so an engine built without one behaves exactly as
    /// before.
    pub(crate) continuity: Arc<ContinuityGate>,
    pub(crate) tcp_slots: Arc<Semaphore>,
    pub(crate) udp_slots: Arc<Semaphore>,
    pub(crate) attribution_slots: Arc<Semaphore>,
    /// Relay buffers, shared by every TCP flow this engine runs.
    ///
    /// Sized from `runtime.relay_buffer_bytes` rather than from a constant,
    /// because that number is already load-bearing: `backlog::ceiling_for`
    /// derives a flow's backpressure ceiling from it, so a relay copying through
    /// a different size than the guard assumes would change how much a single
    /// flow may hold. The pool changes where the memory comes from and nothing
    /// else.
    pub(crate) relay_pool: Arc<foxcore_relay::BufferPool>,
}

pub(crate) struct FlowPolicySnapshot {
    pub(crate) revision: u64,
    pub(crate) routes: RouteTable,
    pub(crate) dns_config: DnsConfig,
    pub(crate) dns: Arc<DnsCache>,
    pub(crate) dns_proxy: Option<DnsProxy>,
    /// Cancelled when a reload revokes the flows that opened under this
    /// snapshot.
    ///
    /// New flows already see a policy change immediately — they read the
    /// `ArcSwap` on the way in. Live ones do not, and for one policy that is
    /// not acceptable: a kill switch that leaves established connections
    /// running is not a kill switch. Every relay selects on this, so arming it
    /// tears them down without a restart and without polling.
    pub(crate) revocation: CancellationToken,
}

#[derive(Default)]
pub(crate) struct PolicyMutable {
    pub(crate) rule_sets: HashMap<String, VerifiedRuleSet>,
    pub(crate) trusted_rule_sets: HashMap<String, RuleSetArtifact>,
}

/// Atomic route/DNS policy source shared by all new flows in one runtime.
///
/// Reloads are serialized off the packet hot path; readers use an atomic Arc
/// load and keep the selected revision for the lifetime of each flow.
pub struct FlowPolicyStore {
    pub(crate) generation: u64,
    pub(crate) outbounds: Arc<OutboundRegistry>,
    pub(crate) direct: Arc<Outbound>,
    /// Carried so a hot reload rebuilds the DNS interceptor against the same
    /// counters and audit sink. Rebuilding it without them would silently stop
    /// reporting blocked names after the first policy change.
    pub(crate) metrics: Arc<FlowMetrics>,
    pub(crate) events: EventSink,
    pub(crate) current: ArcSwap<FlowPolicySnapshot>,
    pub(crate) reload: Mutex<PolicyMutable>,
}
/// Immutable data-plane snapshot installed for one runtime generation.
///
/// Grouping these dependencies keeps the flow-engine boundary stable as new
/// outbound registries and reloadable policy snapshots are introduced.
pub struct FlowEngineContext {
    pub outbounds: Arc<OutboundRegistry>,
    pub direct: Arc<Outbound>,
    pub policy: Arc<FlowPolicyStore>,
    pub attributor: FlowAttributor,
    pub runtime: RuntimeConfig,
    pub metrics: Arc<FlowMetrics>,
    /// Audit sink. `EventSink::none()` disables auditing at zero cost.
    pub events: EventSink,
    /// Set when the primary outbound is a packet tunnel rather than a proxy.
    pub packet_tunnel: bool,
    /// Per-flow attribution: who is talking, to where, how much. The platform
    /// cannot supply this while the VPN is up — every tunnelled byte is
    /// attributed to the tun interface, not to the app behind it.
    pub connections: Arc<TrafficMap>,
}
