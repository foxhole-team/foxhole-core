//! Which way a flow actually left the device.
//!
//! The distinction the UI needs is not "what did the policy say" but "what
//! carried the bytes". Those differ in the two cases that matter most: a
//! selector group names one thing and sends through another, and a `.onion`
//! or `.i2p` destination is re-routed by the overlay gate regardless of what
//! the matching rule asked for. Recording the decision instead of the outcome
//! would draw a map of intentions.

use serde::{Deserialize, Serialize};

/// The four ways traffic can leave, kept separate everywhere a byte is counted.
///
/// This is the split the user actually reasons about — "is this app on the VPN
/// or in the clear" — and it is deliberately not the same axis as the protocol
/// name: `vless`, `trojan` and `wireguard` are all the VPN lane.
///
/// `Deserialize` as well as `Serialize` because a lane is also something a
/// caller *names*: [`crate::RevokeTarget::Lane`] arrives as JSON from outside
/// the process, and the two directions must agree on the spelling or a target
/// would parse into a lane nobody meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowLane {
    /// Through the selected profile: a proxy outbound or the L3 packet tunnel.
    Vpn,
    Tor,
    I2p,
    /// Out through the protected dialer, unwrapped. Split-tunnel `direct`
    /// rules and nothing else — a lane a flow can only reach by an explicit
    /// policy decision, never by a fallback.
    Direct,
}

/// Every lane, in a fixed order. Snapshots keep this order so a UI can bind
/// rows to positions instead of re-sorting on every poll.
pub const LANES: [FlowLane; 4] = [
    FlowLane::Vpn,
    FlowLane::Tor,
    FlowLane::I2p,
    FlowLane::Direct,
];

pub(crate) const LANE_COUNT: usize = LANES.len();

impl FlowLane {
    pub fn name(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Tor => "tor",
            Self::I2p => "i2p",
            Self::Direct => "direct",
        }
    }

    /// Position in [`LANES`], and the bit this lane occupies wherever a set of
    /// lanes is held in one word.
    pub fn index(self) -> usize {
        match self {
            Self::Vpn => 0,
            Self::Tor => 1,
            Self::I2p => 2,
            Self::Direct => 3,
        }
    }
}

/// The route one flow took, as it was at the moment the flow opened.
///
/// `member` is resolved here rather than read from the selector later on
/// purpose: by the time a screen renders, failover may have moved the group,
/// and a row that then claims the *current* member would be reporting a server
/// that never carried these bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowRoute {
    pub lane: FlowLane,
    /// The protocol that carried it — `vless`, `wireguard`, `direct`, `tor`.
    pub outbound: &'static str,
    /// The configured outbound the router selected, when it named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_id: Option<String>,
    /// The selector member in use when the flow opened, for a group outbound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

impl FlowRoute {
    pub fn new(lane: FlowLane, outbound: &'static str) -> Self {
        Self {
            lane,
            outbound,
            outbound_id: None,
            member: None,
        }
    }

    pub fn with_outbound_id(mut self, id: impl Into<String>) -> Self {
        self.outbound_id = Some(id.into());
        self
    }

    pub fn with_member(mut self, member: impl Into<String>) -> Self {
        self.member = Some(member.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_indexes_cover_every_lane_exactly_once() {
        let mut seen = [false; LANE_COUNT];
        for lane in LANES {
            assert!(!seen[lane.index()], "two lanes share a counter slot");
            seen[lane.index()] = true;
        }
        assert!(seen.into_iter().all(|slot| slot));
    }

    #[test]
    fn a_route_serializes_the_member_that_carried_it() {
        let route = FlowRoute::new(FlowLane::Vpn, "vless")
            .with_outbound_id("default")
            .with_member("node-b");
        let json = serde_json::to_string(&route).unwrap();
        assert!(json.contains(r#""lane":"vpn""#), "{json}");
        assert!(json.contains(r#""member":"node-b""#), "{json}");
    }

    #[test]
    fn a_route_without_a_group_omits_the_group_fields() {
        let json = serde_json::to_string(&FlowRoute::new(FlowLane::Direct, "direct")).unwrap();
        assert_eq!(json, r#"{"lane":"direct","outbound":"direct"}"#);
    }
}
