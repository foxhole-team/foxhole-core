use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;

use serde::Serialize;

#[derive(Debug)]
pub struct FlowMetrics {
    started: Instant,
    connected: AtomicBool,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    tcp_flows_opened: AtomicU64,
    udp_flows_opened: AtomicU64,
    flows_closed: AtomicU64,
    rejected_flows: AtomicU64,
    blocked_flows: AtomicU64,
    attribution_errors: AtomicU64,
    dial_errors: AtomicU64,
    flow_errors: AtomicU64,
    dns_queries: AtomicU64,
    dns_blocked: AtomicU64,
    dns_encrypted_bypass: AtomicU64,
    dns_truncated: AtomicU64,
    udp_unsupported: AtomicU64,
    udp_queue_dropped: Arc<AtomicU64>,
    tunnel_untranslated_up: AtomicU64,
    tunnel_untranslated_down: AtomicU64,
    split_to_tunnel: AtomicU64,
    split_to_stack: AtomicU64,
    split_blocked: AtomicU64,
    tunnel_unsealed: AtomicU64,
    tunnel_socket_errors: AtomicU64,
    tunnel_rebinds: AtomicU64,
    tunnel_rebind_failures: AtomicU64,
    tunnel_offline_packets: AtomicU64,
    tunnel_queue_dropped: AtomicU64,
    tunnel_receive_errors: AtomicU64,
    tunnel_routing_loops: AtomicU64,
    tunnel_peer_silences: AtomicU64,
    flow_backlogs_exceeded: AtomicU64,
    flow_idle_timeouts: AtomicU64,
    flow_half_closed_timeouts: AtomicU64,
    flows_revoked: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowSnapshot {
    pub uptime_s: u64,
    pub connected: bool,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub tcp_flows_opened: u64,
    pub udp_flows_opened: u64,
    pub flows_closed: u64,
    pub active_flows: u64,
    pub rejected_flows: u64,
    pub blocked_flows: u64,
    pub attribution_errors: u64,
    pub dial_errors: u64,
    pub flow_errors: u64,
    /// Queries the interceptor answered or forwarded. Together with
    /// `dns_blocked` this replaces the app's current source for these numbers,
    /// which is parsing lines out of a debug log.
    pub dns_queries: u64,
    pub dns_blocked: u64,
    /// Derived, not stored: a consumer that computed it itself would get it
    /// wrong the moment a new refusal reason is added.
    pub dns_allowed: u64,
    /// Flows to the advertised resolver on the DoT port that were refused so
    /// the same question would come back on the one the interceptor reads.
    ///
    /// Deliberately **not** folded into `dns_blocked`: nothing was blocked
    /// here. No name was refused, no answer withheld — a transport was, and the
    /// query that follows is answered normally. Counting the two together would
    /// put "2 names blocked" on a screen for a device that blocked none, which
    /// is the D7 mistake in a different place.
    ///
    /// What a non-zero value means: the device tried encrypted DNS straight to
    /// our resolver, and from here on its lookups are filtered again. What a
    /// zero means on a `real_ip` profile with a blocklist and Private DNS on
    /// "Automatic" is that the probe never reached us — worth a look, because
    /// that was the D14 state.
    pub dns_encrypted_bypass: u64,
    /// DNS answers that did not fit one datagram and were replaced with a
    /// truncation reply so the client would retry over TCP.
    ///
    /// Non-zero and rising with no matching TCP queries means something in
    /// the path is dropping the retry; non-zero on its own is normal for
    /// DNSSEC and large TXT records.
    pub dns_truncated: u64,
    /// Datagram flows the selected outbound cannot carry as datagrams.
    ///
    /// Separate from `dial_errors` on purpose: this is the core correctly
    /// declining to rewrite UDP onto TCP, not the network failing. Folded into
    /// the dial counter it read as connectivity trouble on a profile that was
    /// working exactly as specified (D7).
    ///
    /// Not the same claim as "the protocol is TCP-only". HTTP CONNECT, Naive
    /// and I2P have no UDP at all, but VLESS Vision on UDP/443 and Shadowsocks
    /// over a stream transport are *flow*-level refusals on protocols that
    /// otherwise carry datagrams. The honest reading is "this outbound cannot
    /// carry this datagram"; a UI must not derive the protocol from it.
    pub udp_unsupported: u64,
    /// Datagram packets discarded because an established UDP flow's bounded
    /// input queue was full while its outbound was stalled or slow.
    ///
    /// This is packet loss, not a rejected flow and not a network error. A
    /// rising value says the memory bound is actively protecting the process;
    /// sustained growth says the selected outbound is not keeping up.
    pub udp_queue_dropped: u64,
    /// L3 packets the address translator refused, by direction.
    ///
    /// These are user packets dropped on the floor. They were dropped in
    /// silence — no counter, no event, no log — which is why a WireGuard tunnel
    /// that translated nothing was indistinguishable from one that worked:
    /// handshakes and keepalives bypass translation entirely, so bytes moved
    /// and DNS resolved through the stack while not one TCP connection could
    /// be established (D10). A non-zero value here means the tunnel is losing
    /// the user's traffic, and `blocked` events say which of the two causes it
    /// is.
    pub tunnel_untranslated_up: u64,
    pub tunnel_untranslated_down: u64,
    /// Packets the L3 split sent each way, in packet-tunnel mode.
    ///
    /// `split_to_stack` is the one to watch: in packet-tunnel mode it should
    /// only ever count DNS, overlay names and protocols without ports. If
    /// ordinary TCP is landing there, the flow reaches a stack whose default
    /// outbound is a refused placeholder, and no connection can establish while
    /// keepalives keep the tunnel looking alive.
    pub split_to_tunnel: u64,
    pub split_to_stack: u64,
    pub split_blocked: u64,
    /// The last two ways a packet could still vanish on the L3 path without
    /// anyone noticing.
    ///
    /// `tunnel_unsealed` counts packets the peer state machine declined to
    /// encrypt — normal while a handshake is in flight, a defect if it never
    /// stops. `tunnel_socket_errors` counts sealed datagrams the socket
    /// refused. Both used to `continue` in silence, which is the same shape as
    /// the drop that cost D10 three device runs to localise; with them lit,
    /// every step from tun to wire now says whether it passed a packet on.
    pub tunnel_unsealed: u64,
    pub tunnel_socket_errors: u64,
    /// How the packet tunnel survived a network change.
    ///
    /// The socket the relay was given at start is bound to one network. When
    /// the phone moves from Wi-Fi to mobile that socket is on a dead interface,
    /// and the failure is the worst-looking kind there is: the peer state
    /// machine keeps producing handshakes and keepalives, every counter above
    /// keeps moving, and not one user packet arrives. `tunnel_rebinds` counts
    /// the sockets recreated for the new network — one per change the app
    /// reported — and is the only outside evidence that roaming happened at
    /// all.
    ///
    /// `tunnel_rebind_failures` counts attempts that did not produce a
    /// protected socket. A rising value with `tunnel_offline_packets` also
    /// rising is the tunnel refusing to carry traffic rather than carrying it
    /// unprotected, which is the trade this path is required to make: a socket
    /// that never passed `protect()` would put the user's packets on the wire
    /// outside the VPN.
    pub tunnel_rebinds: u64,
    pub tunnel_rebind_failures: u64,
    /// User packets dropped because the relay has no live socket. Non-zero
    /// means the tunnel is down and saying so, not down in silence.
    pub tunnel_offline_packets: u64,
    /// User packets the peer state machine dropped from its own queue to make
    /// room for a newer one, because no session exists to seal them with.
    ///
    /// The queue is bounded on purpose — a peer that never answers must cost a
    /// fixed amount of memory — but the drop used to happen with no counter at
    /// all, which is the same silent-loss shape as D10. A rising value here with
    /// `bytes_up` flat is the honest reading of "this tunnel is accepting the
    /// user's packets and carrying none of them".
    pub tunnel_queue_dropped: u64,
    /// Errors the peer socket returned instead of a datagram.
    ///
    /// A connected UDP socket surfaces the peer's ICMP errors on the receive
    /// side, and one of those while a peer starts up is routine. This exists
    /// because a *run* of them is not, and because the branch used to discard
    /// them entirely: tokio hands a non-`WouldBlock` error back without clearing
    /// the registration's readiness, so the relay's receive arm was ready again
    /// immediately and the `continue` was an unbounded spin on one CPU core with
    /// every health counter reading zero (D15, found on device).
    pub tunnel_receive_errors: u64,
    /// Packets the tun handed the relay that were addressed to the relay's own
    /// peer endpoint.
    ///
    /// This is the tunnel's own output coming back — a WireGuard socket that
    /// `protect()` did not take out of the tun it is serving — and sealing it
    /// would make the core the amplifier of a routing loop that never leaves the
    /// device. Non-zero means the platform is routing the peer socket into the
    /// tun, which no counter could show before: the loop burns a core, bills
    /// gigabytes and sends nothing.
    pub tunnel_routing_loops: u64,
    /// Times the relay reported that its peer had answered nothing while it was
    /// sending.
    ///
    /// One per silent stretch, not one per second. Zero on a tunnel that is
    /// merely idle: the clock only runs once something has actually been handed
    /// to the socket.
    pub tunnel_peer_silences: u64,
    /// Flows torn down because their outbound stopped accepting bytes.
    ///
    /// The userspace stack has no end-to-end backpressure: it acknowledges
    /// in-order data into an unbounded queue and its advertised window can
    /// never close, so an outbound that stalls while the application keeps
    /// sending grows the heap until the process is killed for memory. From
    /// outside that is "the app closed by itself", and until this counter
    /// existed there was no observable sign of it at all — not a counter, not
    /// an event, not a log.
    ///
    /// **The condition is time, not volume**, and the name is older than the
    /// rule. It counted flows that had accumulated more than a fixed number of
    /// unsent bytes until the netem lab showed that test killing three of three
    /// ordinary uploads on a clean link: a fast writer and a slow socket
    /// accumulate exactly like a stalled one, so no byte threshold can separate
    /// them. What it counts now is an outbound that accepted *nothing* for
    /// `backlog::STALL_TIMEOUT` while the flow held bytes for it. The volume
    /// ceiling still exists and now applies backpressure instead of a verdict,
    /// so it never reaches this counter.
    ///
    /// This is a refusal standing in for backpressure, and it should be zero.
    /// A non-zero value on a device is worth reading as "one flow's outbound
    /// stopped accepting for long enough to matter", not as a capacity limit
    /// to raise.
    pub flow_backlogs_exceeded: u64,
    /// TCP flows the core closed for passing no bytes in either direction.
    ///
    /// Until this existed a stalled TCP relay had no timeout at all:
    /// `idle_timeout_s` reached the stack's UDP sessions and the split table
    /// and stopped there, so a flow whose far end went away was held until the
    /// application closed it or the generation ended. Measured with a black
    /// hole applied to established flows, eleven of them sat unchanged for the
    /// last 91 seconds of the run, and `max_tcp_flows` is 1024 — bounded and
    /// visible, but a slot that never comes back.
    ///
    /// A non-zero value is the core reclaiming those slots and telling the
    /// application so with a real close, rather than dropping the session in
    /// silence. It is not an error: an idle timeout on a flow nobody was using
    /// is the mechanism working.
    pub flow_idle_timeouts: u64,
    /// TCP flows the core reclaimed after the far end closed and the
    /// application's own half went quiet.
    ///
    /// `copy_bidirectional` ends a relay only when **both** directions are
    /// finished, so a peer that sends FIN while the application keeps its half
    /// open finishes one and parks the other forever. Until this counter existed
    /// so did the flows: the outbound's socket sat in `CLOSE_WAIT` and one of
    /// `max_tcp_flows` stayed spent until `tcp_idle_timeout_s` — an hour —
    /// expired. Measured on device over thirty minutes: 77 such sockets, not one
    /// of which cleared, while established flows drained from 34 to 5.
    ///
    /// Not an error and not a block. A rising value on a browsing device is the
    /// ordinary shape of HTTP keep-alive being reclaimed on time; what would be
    /// worth reading is this staying at zero while `active_flows` climbs and
    /// never falls.
    pub flow_half_closed_timeouts: u64,
    /// Live flows the core tore down because something revoked them.
    ///
    /// Counted where the teardown happens, not where the request is made, so
    /// this is flows that actually ended rather than flows that were signalled.
    /// The two differ by the flows that finished on their own in between, and
    /// the difference is not an error.
    ///
    /// Three things reach it, and they are one mechanism at three scopes: a
    /// targeted `revoke_flows` — "block this app now" — an armed kill switch,
    /// and a network change, the last two revoking every flow that belongs to a
    /// policy snapshot that has been replaced.
    ///
    /// Not an error counter. A rising value with no user action behind it means
    /// the device is changing networks, which is worth knowing but is not a
    /// fault.
    pub flows_revoked: u64,
}

impl Default for FlowMetrics {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            connected: AtomicBool::new(false),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            tcp_flows_opened: AtomicU64::new(0),
            udp_flows_opened: AtomicU64::new(0),
            flows_closed: AtomicU64::new(0),
            rejected_flows: AtomicU64::new(0),
            blocked_flows: AtomicU64::new(0),
            attribution_errors: AtomicU64::new(0),
            dial_errors: AtomicU64::new(0),
            flow_errors: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            dns_blocked: AtomicU64::new(0),
            dns_encrypted_bypass: AtomicU64::new(0),
            dns_truncated: AtomicU64::new(0),
            udp_unsupported: AtomicU64::new(0),
            udp_queue_dropped: Arc::new(AtomicU64::new(0)),
            tunnel_untranslated_up: AtomicU64::new(0),
            tunnel_untranslated_down: AtomicU64::new(0),
            split_to_tunnel: AtomicU64::new(0),
            split_to_stack: AtomicU64::new(0),
            split_blocked: AtomicU64::new(0),
            tunnel_unsealed: AtomicU64::new(0),
            tunnel_socket_errors: AtomicU64::new(0),
            tunnel_rebinds: AtomicU64::new(0),
            tunnel_rebind_failures: AtomicU64::new(0),
            tunnel_offline_packets: AtomicU64::new(0),
            tunnel_queue_dropped: AtomicU64::new(0),
            tunnel_receive_errors: AtomicU64::new(0),
            tunnel_routing_loops: AtomicU64::new(0),
            tunnel_peer_silences: AtomicU64::new(0),
            flow_backlogs_exceeded: AtomicU64::new(0),
            flow_idle_timeouts: AtomicU64::new(0),
            flow_half_closed_timeouts: AtomicU64::new(0),
            flows_revoked: AtomicU64::new(0),
        }
    }
}

/// The engine's summary is fed from the same counting stream as the map, so a
/// flow that is torn down mid-transfer contributes to both or to neither.
impl foxcore_trafficmap::ByteCounters for FlowMetrics {
    fn add_up(&self, bytes: u64) {
        FlowMetrics::add_up(self, bytes);
    }

    fn add_down(&self, bytes: u64) {
        FlowMetrics::add_down(self, bytes);
    }
}

impl FlowMetrics {
    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Release);
    }

    pub fn add_up(&self, bytes: u64) {
        self.bytes_up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_down(&self, bytes: u64) {
        self.bytes_down.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn open_tcp(&self) {
        self.tcp_flows_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn open_udp(&self) {
        self.udp_flows_opened.fetch_add(1, Ordering::Relaxed);
    }

    pub fn close_flow(&self) {
        self.flows_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reject_flow(&self) {
        self.rejected_flows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn block_flow(&self) {
        self.blocked_flows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn attribution_error(&self) {
        self.attribution_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dial_error(&self) {
        self.dial_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn flow_error(&self) {
        self.flow_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Counted once per query the interceptor accepted for processing, before
    /// any refusal is decided.
    pub fn dns_query(&self) {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_blocked(&self) {
        self.dns_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// A flow to the advertised resolver on the DoT port, refused so the same
    /// question comes back on the port the interceptor reads. Apart from
    /// `dns_blocked` on purpose — see [`FlowSnapshot::dns_encrypted_bypass`].
    pub fn dns_encrypted_bypass(&self) {
        self.dns_encrypted_bypass.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dns_truncated(&self) {
        self.dns_truncated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_unsupported(&self) {
        self.udp_unsupported.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn udp_queue_drop_counter(&self) -> Arc<AtomicU64> {
        self.udp_queue_dropped.clone()
    }

    /// Where the L3 split sent a packet. Counted per packet, not per flow: the
    /// question these answer is "did the traffic go where the decision said",
    /// and a per-flow count cannot show a flow whose packets went two ways.
    pub fn split_to_tunnel(&self) {
        self.split_to_tunnel.fetch_add(1, Ordering::Relaxed);
    }

    pub fn split_to_stack(&self) {
        self.split_to_stack.fetch_add(1, Ordering::Relaxed);
    }

    pub fn split_blocked(&self) {
        self.split_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// A packet the peer state machine would not seal — usually because no
    /// session exists yet, which is ordinary during a handshake and a defect if
    /// it never stops.
    pub fn tunnel_unsealed(&self) {
        self.tunnel_unsealed.fetch_add(1, Ordering::Relaxed);
    }

    /// A sealed datagram the socket refused.
    pub fn tunnel_socket_error(&self) {
        self.tunnel_socket_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// A socket recreated for a network the app reported. Success and failure
    /// are separate counters rather than one with a sign, because a rebind that
    /// keeps failing is a tunnel that is down and a rebind that succeeds is a
    /// tunnel that roamed, and reading one number cannot tell them apart.
    pub fn tunnel_rebind(&self) {
        self.tunnel_rebinds.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tunnel_rebind_failure(&self) {
        self.tunnel_rebind_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A user packet the relay dropped because it has no protected socket to
    /// put it on.
    pub fn tunnel_offline_packet(&self) {
        self.tunnel_offline_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// A user packet the peer state machine dropped from its own queue because
    /// it had nowhere to seal it and no room left to hold it.
    pub fn tunnel_queue_dropped(&self) {
        self.tunnel_queue_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// An error the peer socket returned instead of a datagram.
    pub fn tunnel_receive_error(&self) {
        self.tunnel_receive_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// A packet from the tun addressed to this relay's own peer endpoint.
    pub fn tunnel_routing_loop(&self) {
        self.tunnel_routing_loops.fetch_add(1, Ordering::Relaxed);
    }

    /// One stretch during which the relay sent and the peer answered nothing.
    pub fn tunnel_peer_silent(&self) {
        self.tunnel_peer_silences.fetch_add(1, Ordering::Relaxed);
    }

    /// A flow torn down because its outbound accepted nothing for long enough
    /// to stop being a slow link and start being a dead one.
    ///
    /// Kept apart from `flow_errors` deliberately: that counter is the network
    /// failing, this one is the core refusing, and folding a correct
    /// fail-closed refusal into a connectivity counter is the mistake D7 was.
    pub fn flow_backlog_exceeded(&self) {
        self.flow_backlogs_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP flow closed because nothing moved through it for the idle window.
    ///
    /// Apart from `flow_errors` for the same reason as above: nothing failed
    /// here. The flow was carrying no traffic and the core took its slot back.
    pub fn flow_idle_timeout(&self) {
        self.flow_idle_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// A TCP flow reclaimed because its far end had closed and the application
    /// had nothing left to send.
    ///
    /// Apart from `flow_idle_timeouts` because the two say different things
    /// about the same device. An idle timeout is a connection that may well have
    /// been alive and was quiet for an hour; this is a connection whose peer was
    /// demonstrably gone, and its window is thirty seconds. Folding them
    /// together would hide exactly the thing the counter exists to show — that
    /// the flow table is being handed back promptly rather than an hour late.
    pub fn flow_half_closed_timeout(&self) {
        self.flow_half_closed_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A live flow torn down because it was revoked.
    ///
    /// Apart from `flow_errors` and from `blocked_flows` for the same reason
    /// the other refusals are: nothing failed and no rule refused this flow —
    /// it was allowed, it ran, and then the user or the network ended it.
    pub fn revoke_flow(&self) {
        self.flows_revoked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tunnel_untranslated_up(&self) {
        self.tunnel_untranslated_up.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tunnel_untranslated_down(&self) {
        self.tunnel_untranslated_down
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> FlowSnapshot {
        let tcp_flows_opened = self.tcp_flows_opened.load(Ordering::Relaxed);
        let udp_flows_opened = self.udp_flows_opened.load(Ordering::Relaxed);
        let flows_closed = self.flows_closed.load(Ordering::Relaxed);
        let dns_queries = self.dns_queries.load(Ordering::Relaxed);
        let dns_blocked = self.dns_blocked.load(Ordering::Relaxed);
        FlowSnapshot {
            uptime_s: self.started.elapsed().as_secs(),
            connected: self.connected.load(Ordering::Acquire),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            tcp_flows_opened,
            udp_flows_opened,
            flows_closed,
            active_flows: tcp_flows_opened
                .saturating_add(udp_flows_opened)
                .saturating_sub(flows_closed),
            rejected_flows: self.rejected_flows.load(Ordering::Relaxed),
            blocked_flows: self.blocked_flows.load(Ordering::Relaxed),
            attribution_errors: self.attribution_errors.load(Ordering::Relaxed),
            dial_errors: self.dial_errors.load(Ordering::Relaxed),
            flow_errors: self.flow_errors.load(Ordering::Relaxed),
            dns_queries,
            dns_blocked,
            dns_allowed: dns_queries.saturating_sub(dns_blocked),
            dns_encrypted_bypass: self.dns_encrypted_bypass.load(Ordering::Relaxed),
            dns_truncated: self.dns_truncated.load(Ordering::Relaxed),
            udp_unsupported: self.udp_unsupported.load(Ordering::Relaxed),
            udp_queue_dropped: self.udp_queue_dropped.load(Ordering::Relaxed),
            tunnel_untranslated_up: self.tunnel_untranslated_up.load(Ordering::Relaxed),
            tunnel_untranslated_down: self.tunnel_untranslated_down.load(Ordering::Relaxed),
            split_to_tunnel: self.split_to_tunnel.load(Ordering::Relaxed),
            split_to_stack: self.split_to_stack.load(Ordering::Relaxed),
            split_blocked: self.split_blocked.load(Ordering::Relaxed),
            tunnel_unsealed: self.tunnel_unsealed.load(Ordering::Relaxed),
            tunnel_socket_errors: self.tunnel_socket_errors.load(Ordering::Relaxed),
            tunnel_rebinds: self.tunnel_rebinds.load(Ordering::Relaxed),
            tunnel_rebind_failures: self.tunnel_rebind_failures.load(Ordering::Relaxed),
            tunnel_offline_packets: self.tunnel_offline_packets.load(Ordering::Relaxed),
            tunnel_queue_dropped: self.tunnel_queue_dropped.load(Ordering::Relaxed),
            tunnel_receive_errors: self.tunnel_receive_errors.load(Ordering::Relaxed),
            tunnel_routing_loops: self.tunnel_routing_loops.load(Ordering::Relaxed),
            tunnel_peer_silences: self.tunnel_peer_silences.load(Ordering::Relaxed),
            flow_backlogs_exceeded: self.flow_backlogs_exceeded.load(Ordering::Relaxed),
            flow_idle_timeouts: self.flow_idle_timeouts.load(Ordering::Relaxed),
            flow_half_closed_timeouts: self.flow_half_closed_timeouts.load(Ordering::Relaxed),
            flows_revoked: self.flows_revoked.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_flows_saturate_instead_of_underflowing() {
        let metrics = FlowMetrics::default();
        metrics.open_tcp();
        metrics.close_flow();
        metrics.close_flow();
        assert_eq!(metrics.snapshot().active_flows, 0);
    }

    #[test]
    fn dns_allowed_is_derived_and_never_underflows() {
        let metrics = FlowMetrics::default();
        for _ in 0..3 {
            metrics.dns_query();
        }
        metrics.dns_blocked();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.dns_queries, 3);
        assert_eq!(snapshot.dns_blocked, 1);
        assert_eq!(snapshot.dns_allowed, 2);

        // A refusal counted without its query — the ordering the interceptor
        // avoids, but the snapshot must still not wrap around.
        let metrics = FlowMetrics::default();
        metrics.dns_blocked();
        assert_eq!(metrics.snapshot().dns_allowed, 0);
    }

    #[test]
    fn udp_queue_loss_counter_is_shared_with_the_stack() {
        let metrics = FlowMetrics::default();
        let stack_counter = metrics.udp_queue_drop_counter();
        stack_counter.fetch_add(3, Ordering::Relaxed);
        assert_eq!(metrics.snapshot().udp_queue_dropped, 3);
    }
}
