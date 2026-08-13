//! Per-flow accounting for traffic that never reaches a stream.
//!
//! An L3 packet tunnel — WireGuard, AmneziaWG — carries whole IP packets. There
//! is no `CountingStream` to wrap because nothing in that path is a stream: the
//! packet is translated, sealed and written to a socket. Without this table the
//! tunnel's bytes exist only as a global total, so the app draws a live tunnel
//! as idle and can never say which app is using it (D4, found on device).
//!
//! Both directions are read per packet, so the table must not take a lock. It
//! is an `ArcSwap` of an immutable map: readers are wait-free, and the O(n)
//! rebuild is paid once per *flow*, on the same cold path that already does an
//! identity lookup.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::map::LiveFlow;

/// The 5-tuple as it appears on the wire, in the direction the flow was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
}

impl PacketKey {
    pub fn new(
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            source,
            destination,
            source_port,
            destination_port,
            protocol,
        }
    }

    /// The same flow seen from the other end. A reply arriving from the tunnel
    /// carries this tuple, and it is the only thing tying it back to the app
    /// that sent the request.
    pub fn reversed(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
        }
    }
}

/// Lock-free 5-tuple to flow table for the packet path.
#[derive(Default)]
pub struct PacketAccounting {
    table: ArcSwap<HashMap<PacketKey, Arc<LiveFlow>>>,
}

impl PacketAccounting {
    pub(crate) fn bind(&self, key: PacketKey, flow: Arc<LiveFlow>) {
        self.table.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.insert(key, flow.clone());
            next
        });
    }

    pub(crate) fn unbind(&self, key: &PacketKey) {
        // Checked first so a flow that was never bound — every stream flow —
        // does not rebuild the map on close.
        if !self.table.load().contains_key(key) {
            return;
        }
        self.table.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.remove(key);
            next
        });
    }

    /// Count bytes leaving the device. Returns whether the flow was known: a
    /// packet with no entry is traffic this map is not tracking, not an error.
    pub fn count_up(&self, key: &PacketKey, bytes: u64) -> bool {
        match self.table.load().get(key) {
            Some(flow) => {
                flow.add_up(bytes);
                true
            }
            None => false,
        }
    }

    /// Count bytes arriving. `key` is the tuple as it appears on the inbound
    /// packet, so it is reversed before the lookup.
    pub fn count_down(&self, key: &PacketKey, bytes: u64) -> bool {
        match self.table.load().get(&key.reversed()) {
            Some(flow) => {
                flow.add_down(bytes);
                true
            }
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.table.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn key() -> PacketKey {
        PacketKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            40_000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            6,
        )
    }

    #[test]
    fn a_reply_is_matched_by_the_reversed_tuple() {
        let outbound = key();
        let inbound = outbound.reversed();

        assert_eq!(inbound.source, outbound.destination);
        assert_eq!(inbound.destination_port, outbound.source_port);
        assert_eq!(inbound.reversed(), outbound);
    }

    #[test]
    fn an_unknown_packet_is_reported_rather_than_attributed_to_someone() {
        let accounting = PacketAccounting::default();
        assert!(!accounting.count_up(&key(), 100));
        assert!(!accounting.count_down(&key().reversed(), 100));
    }
}
