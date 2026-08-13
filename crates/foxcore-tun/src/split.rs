//! Per-packet split between the L3 tunnel and the userspace stack.
//!
//! With a packet tunnel as the primary outbound, `vpn` traffic must stay at L3
//! while `direct`, `tor` and `block` still need the stack that terminates and
//! re-dials them. The decision therefore has to be made on the packet, before
//! anything is terminated.
//!
//! Deciding costs an identity lookup, so it is made once per flow and cached on
//! the 5-tuple. The cache is bounded: a re-decision is merely work, but an
//! unbounded table is a device-wide failure.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use foxcore_trafficmap::{FlowHandle, PacketKey};
use tokio_util::sync::CancellationToken;

const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const IPV6_HEADER: usize = 40;

/// Where one packet goes once it has been read off the tun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketRoute {
    /// Straight into the L3 packet tunnel, untouched above the IP layer.
    Tunnel,
    /// Into the userspace stack, which terminates it and re-dials through a
    /// proxy outbound — `direct`, `tor` and named proxies all live here.
    Stack,
    /// Dropped: firewall, kill switch or a flow with no identity.
    Block,
}

/// The 5-tuple a flow is identified by on the tun.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Read the tuple out of an IP packet. Protocols without ports (ICMP, and
    /// any IPv6 extension header chain this does not walk) get port 0, which
    /// still separates them per protocol and address pair.
    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        match packet.first()? >> 4 {
            IPV4_VERSION => Self::from_ipv4(packet),
            IPV6_VERSION => Self::from_ipv6(packet),
            _ => None,
        }
    }

    fn from_ipv4(packet: &[u8]) -> Option<Self> {
        let header_len = usize::from(packet.first()? & 0x0f) * 4;
        if header_len < 20 || packet.len() < header_len {
            return None;
        }
        let protocol = packet[9];
        let source = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
        let destination = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
        // A non-first fragment has no ports; treating it as port 0 keeps it with
        // the other fragments of a protocol rather than inventing a tuple.
        let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0;
        let (source_port, destination_port) = if fragmented {
            (0, 0)
        } else {
            ports(packet, header_len, protocol)
        };
        Some(Self {
            source: source.into(),
            destination: destination.into(),
            source_port,
            destination_port,
            protocol,
        })
    }

    fn from_ipv6(packet: &[u8]) -> Option<Self> {
        if packet.len() < IPV6_HEADER {
            return None;
        }
        let protocol = packet[6];
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
        let (source_port, destination_port) = ports(packet, IPV6_HEADER, protocol);
        Some(Self {
            source: source.into(),
            destination: destination.into(),
            source_port,
            destination_port,
            protocol,
        })
    }
}

fn ports(packet: &[u8], header_len: usize, protocol: u8) -> (u16, u16) {
    if !matches!(protocol, PROTOCOL_TCP | PROTOCOL_UDP) || packet.len() < header_len + 4 {
        return (0, 0);
    }
    (
        u16::from_be_bytes([packet[header_len], packet[header_len + 1]]),
        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
    )
}

impl From<FlowKey> for PacketKey {
    fn from(key: FlowKey) -> Self {
        Self::new(
            key.source,
            key.source_port,
            key.destination,
            key.destination_port,
            key.protocol,
        )
    }
}

/// What deciding a flow produced: where its packets go, and — for traffic that
/// stays at L3 — the traffic-map row that will carry its bytes.
///
/// The row travels with the decision because they have exactly the same
/// lifetime: the flow is visible for as long as the split remembers it, and
/// evicting the decision must close the row rather than leave a connection on
/// screen that nothing will ever update again.
pub struct PacketDecision {
    pub route: PacketRoute,
    pub flow: Option<FlowHandle>,
    /// Cancelled when the answer this decision was is no longer the answer:
    /// the policy snapshot it was decided under has been replaced. See
    /// [`PacketDecision::voided_by`].
    pub voided_by: Option<CancellationToken>,
}

impl PacketDecision {
    pub fn new(route: PacketRoute) -> Self {
        Self {
            route,
            flow: None,
            voided_by: None,
        }
    }

    pub fn with_flow(route: PacketRoute, flow: FlowHandle) -> Self {
        Self {
            route,
            flow: Some(flow),
            voided_by: None,
        }
    }

    /// Tie this decision to the life of a policy snapshot.
    ///
    /// A reload, a kill switch and a network change all install a new snapshot
    /// and then cancel the old one's token — that is how a live L4 flow learns
    /// it is over. An L3 flow has no relay to wait on the token, so the decision
    /// carries it instead and is re-taken on the next packet.
    ///
    /// Without this the only thing that reached a cached decision was the idle
    /// timer: a WireGuard flow that kept sending stayed on the route it was
    /// given at its first packet, through a reload, through a kill switch, and
    /// through `revoke_flows` — which cancelled the row's token, reported the
    /// flow revoked, and changed nothing about where its packets went.
    #[must_use]
    pub fn voided_by(mut self, token: CancellationToken) -> Self {
        self.voided_by = Some(token);
        self
    }
}

struct Decision {
    route: PacketRoute,
    last_seen_ms: u64,
    /// Dropped with the entry, which closes the traffic-map row and releases
    /// its 5-tuple binding.
    flow: Option<FlowHandle>,
    voided_by: Option<CancellationToken>,
}

impl Decision {
    /// Whether this decision has stopped being one.
    ///
    /// Two things void it, and they are different questions. The policy token
    /// says the snapshot that answered is gone; the flow's own token says this
    /// particular flow was revoked — `revoke_flows(App)` while the policy did
    /// not move at all. Either way the next packet is decided again rather than
    /// routed on the strength of an answer nobody stands behind any more.
    fn is_void(&self) -> bool {
        self.voided_by
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
            || self
                .flow
                .as_ref()
                .is_some_and(|handle| handle.flow().revocation().is_cancelled())
    }
}

/// Conntrack for the split decision.
///
/// Deciding needs the packet's owning application, which is a comparatively
/// expensive lookup, so it happens once per flow. The entry expires on idle so
/// a policy reload reaches long-lived flows without a restart.
pub struct PacketSplitter {
    decisions: HashMap<FlowKey, Decision>,
    capacity: usize,
    idle_timeout_ms: u64,
}

impl PacketSplitter {
    pub fn new(capacity: usize, idle_timeout_ms: u64) -> Self {
        Self {
            decisions: HashMap::new(),
            capacity: capacity.max(1),
            idle_timeout_ms,
        }
    }

    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Route one packet, calling `decide` only when this flow has no live
    /// decision. A packet that is not IP at all is blocked: the tun should never
    /// produce one, and guessing is worse than dropping.
    pub fn route(
        &mut self,
        packet: &[u8],
        now_ms: u64,
        decide: impl FnOnce(&FlowKey) -> PacketRoute,
    ) -> PacketRoute {
        let Some(key) = FlowKey::from_packet(packet) else {
            return PacketRoute::Block;
        };
        if let Some(existing) = self.decisions.get_mut(&key) {
            if now_ms.saturating_sub(existing.last_seen_ms) <= self.idle_timeout_ms
                && !existing.is_void()
            {
                existing.last_seen_ms = now_ms;
                return existing.route;
            }
            // Removed rather than overwritten below, so the handle drops here
            // and the traffic-map row closes even if `decide` blocks this flow
            // and never opens a new one.
            self.decisions.remove(&key);
        }
        let route = decide(&key);
        self.insert(key, PacketDecision::new(route), now_ms);
        route
    }

    /// The live decision for a flow, if there is one.
    ///
    /// Split out from [`PacketSplitter::route`] because deciding is
    /// asynchronous on Android — resolving the owning app is a Binder round
    /// trip with a timeout — and a synchronous closure cannot await it. The
    /// caller looks up, awaits its own decision on a miss, and inserts.
    pub fn lookup(&mut self, key: &FlowKey, now_ms: u64) -> Option<PacketRoute> {
        let existing = self.decisions.get_mut(key)?;
        if now_ms.saturating_sub(existing.last_seen_ms) > self.idle_timeout_ms || existing.is_void()
        {
            // Same reason as in `route`: the row goes with the decision, and a
            // miss here is answered by a fresh `decide` that may not open one.
            self.decisions.remove(key);
            return None;
        }
        existing.last_seen_ms = now_ms;
        Some(existing.route)
    }

    pub fn insert(&mut self, key: FlowKey, decision: PacketDecision, now_ms: u64) {
        if self.decisions.len() >= self.capacity {
            self.evict(now_ms);
        }
        self.decisions.insert(
            key,
            Decision {
                route: decision.route,
                last_seen_ms: now_ms,
                flow: decision.flow,
                voided_by: decision.voided_by,
            },
        );
    }

    /// Drop idle entries first, then the least recently seen one at a time.
    ///
    /// It used to clear the whole table when every entry was still live, on the
    /// reasoning that re-deciding is only work. Re-deciding is not only work.
    /// Each dropped entry closes a `FlowHandle`, and each close rebinds the
    /// traffic map; at a capacity of `max_tcp_flows + max_udp_flows` that is
    /// over fifteen hundred closes in one burst, inside the task that owns the
    /// packet path. Every live L3 flow loses its accounting binding at the same
    /// moment, per-app counters reset, the connection list blinks out whole, and
    /// the next packet of each surviving flow goes back through attribution —
    /// which waits on a Binder call. A phone with short-lived flows from a
    /// browser and a messenger reaches capacity long before the idle timeout
    /// expires, so this was reachable in ordinary use rather than under stress.
    ///
    /// Evicting one entry costs a scan of the table, which happens only at
    /// capacity and is cheap next to the rebind it replaces.
    fn evict(&mut self, now_ms: u64) {
        let idle_timeout_ms = self.idle_timeout_ms;
        self.decisions
            .retain(|_, decision| now_ms.saturating_sub(decision.last_seen_ms) <= idle_timeout_ms);
        while self.decisions.len() >= self.capacity {
            let Some(oldest) = self
                .decisions
                .iter()
                .min_by_key(|(_, decision)| decision.last_seen_ms)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.decisions.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const APP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    fn udp_packet(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&APP.octets());
        packet[16..20].copy_from_slice(&REMOTE.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    fn icmp_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 1;
        packet[12..16].copy_from_slice(&APP.octets());
        packet[16..20].copy_from_slice(&REMOTE.octets());
        packet
    }

    #[test]
    fn the_five_tuple_identifies_a_flow_by_addresses_ports_and_protocol() {
        let key = FlowKey::from_packet(&udp_packet(40_000, 443)).expect("a valid IPv4 UDP packet");

        assert_eq!(key.source, IpAddr::V4(APP));
        assert_eq!(key.destination, IpAddr::V4(REMOTE));
        assert_eq!(key.source_port, 40_000);
        assert_eq!(key.destination_port, 443);
        assert_eq!(key.protocol, 17);
    }

    #[test]
    fn a_protocol_without_ports_still_yields_a_key() {
        let key = FlowKey::from_packet(&icmp_packet()).expect("ICMP is still a flow");

        assert_eq!(key.protocol, 1);
        assert_eq!(key.source_port, 0);
        assert_eq!(key.destination_port, 0);
    }

    #[test]
    fn the_decision_is_taken_once_and_reused_for_the_rest_of_the_flow() {
        let mut splitter = PacketSplitter::new(16, 30_000);
        let packet = udp_packet(40_000, 443);
        let mut decisions = 0;

        for _ in 0..5 {
            let route = splitter.route(&packet, 0, |_| {
                decisions += 1;
                PacketRoute::Tunnel
            });
            assert_eq!(route, PacketRoute::Tunnel);
        }

        assert_eq!(
            decisions, 1,
            "identity resolution must not run once per packet"
        );
    }

    #[test]
    fn the_decision_is_handed_the_flow_it_is_about() {
        let mut splitter = PacketSplitter::new(16, 30_000);

        let route = splitter.route(&udp_packet(40_000, 443), 0, |key| {
            // Policy needs the tuple: identity resolution starts from the
            // source port, and destination rules read the address.
            assert_eq!(key.destination_port, 443);
            assert_eq!(key.source, IpAddr::V4(APP));
            PacketRoute::Tunnel
        });

        assert_eq!(route, PacketRoute::Tunnel);
    }

    #[test]
    fn a_different_flow_is_decided_separately() {
        let mut splitter = PacketSplitter::new(16, 30_000);
        splitter.route(&udp_packet(40_000, 443), 0, |_| PacketRoute::Tunnel);

        let route = splitter.route(&udp_packet(40_001, 443), 0, |_| PacketRoute::Stack);

        assert_eq!(
            route,
            PacketRoute::Stack,
            "a second flow must get its own decision, not the neighbour's"
        );
    }

    #[test]
    fn an_idle_flow_is_decided_again_so_a_policy_reload_takes_effect() {
        let mut splitter = PacketSplitter::new(16, 30_000);
        let packet = udp_packet(40_000, 443);
        splitter.route(&packet, 0, |_| PacketRoute::Tunnel);

        let route = splitter.route(&packet, 30_001, |_| PacketRoute::Block);

        assert_eq!(
            route,
            PacketRoute::Block,
            "a decision must not outlive the idle timeout, or a reload never reaches old flows"
        );
    }

    #[test]
    fn the_cache_never_grows_past_its_capacity() {
        let mut splitter = PacketSplitter::new(8, 30_000);

        for port in 0..1_000_u16 {
            splitter.route(&udp_packet(port, 443), 0, |_| PacketRoute::Tunnel);
        }

        assert!(
            splitter.len() <= 8,
            "a flood of short flows must not grow the table without bound, got {}",
            splitter.len()
        );
    }

    /// Reaching capacity used to empty the table, so a burst of new flows threw
    /// away the decision of every live one at once. Now the oldest entry goes
    /// and the newest arrivals stay.
    #[test]
    fn a_full_table_gives_up_its_oldest_entry_and_not_all_of_them() {
        let mut splitter = PacketSplitter::new(4, 30_000);

        // Ports 0..4 at t=0, then one more at t=1: only the oldest may go.
        for port in 0..4_u16 {
            splitter.route(&udp_packet(port, 443), 0, |_| PacketRoute::Tunnel);
        }
        splitter.route(&udp_packet(100, 443), 1, |_| PacketRoute::Tunnel);

        assert!(splitter.len() <= 4, "table grew past capacity");
        assert!(
            splitter.len() >= 3,
            "a full table dropped more than the entry it needed room for, leaving {}",
            splitter.len()
        );
    }

    #[test]
    fn a_packet_that_is_not_ip_is_refused_rather_than_guessed_at() {
        assert!(FlowKey::from_packet(&[0_u8; 4]).is_none());
        assert!(FlowKey::from_packet(&[]).is_none());
    }
}
