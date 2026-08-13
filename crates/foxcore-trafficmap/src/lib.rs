//! The traffic map: the live picture of what the core is carrying.
//!
//! Split out of the data plane on purpose. This crate depends on the shared
//! type vocabulary and nothing else — no TUN, no outbounds, no routing table —
//! so the map can be read, serialized and tested without dragging a data plane
//! behind it, and so nothing here can quietly grow a dependency on the packet
//! path it is supposed to observe.
//!
//! Three rules hold everywhere in this crate:
//!
//! 1. **Nothing blocks the hot path.** Byte accounting is relaxed atomics; the
//!    change stream is a bounded channel with `try_send` and drop-on-full; the
//!    L3 5-tuple table is an `ArcSwap` read without a lock.
//! 2. **Rendering is capped, accounting is not.** A snapshot returns the
//!    busiest rows and says how many it left out; the totals stay exact.
//! 3. **The map records what happened, not what was intended.** A flow carries
//!    the lane, protocol and selector member that actually moved its bytes.

#![forbid(unsafe_code)]

mod events;
mod map;
mod packet;
mod route;

pub use events::{DEFAULT_TRAFFIC_EVENT_CAPACITY, TrafficEvent, TrafficEventDrain};
pub use map::{
    ByteCounters, ConnectionRow, CountingStream, DEFAULT_CONNECTION_ROWS, FlowHandle, LaneTotals,
    LaneTraffic, LiveFlow, PackageLaneTraffic, PackageTraffic, RevokeTarget, TrafficMap,
    TrafficSnapshot,
};
pub use packet::{PacketAccounting, PacketKey};
pub use route::{FlowLane, FlowRoute, LANES};
