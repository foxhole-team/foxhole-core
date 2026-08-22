#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
// Raised for the Tor build. Compiling `proto-tor` widens the outbound enum
// enough that the resolver's future — `exchange` awaiting an upstream awaiting
// a dial awaiting a Tor circuit — overflows rustc's default query depth while
// it computes the layout. Nothing here recurses; the type is simply deep, and
// the whole `tor` feature failed to build without this. Found by checking the
// feature rather than by anyone asking for it, which is also why "three
// runtimes switch seamlessly" had nothing to run on.
#![recursion_limit = "256"]

mod arena;
mod backlog;
mod continuity;
mod device;
mod dns;
pub mod enginephase;
mod flow;
mod halfclose;
mod icmp;
mod ingress;
mod l3;
mod metrics;
/// The bounded TUN network stack and its packet-level regression surface.
pub mod netstack;
#[cfg(feature = "wireguard")]
mod relay;
#[cfg(test)]
mod smoltcp_poc;
mod split;

/// Public because the benchmarks that justify it drive it directly — the two
/// hops it serves are private and need a descriptor. See
/// `benches/packet_path.rs`.
pub use arena::PacketArena;
pub use continuity::{ContinuityConfirm, ContinuityExpiry, ContinuityGate, ContinuityOutcome};
pub use device::{TunDevice, TunFdOwner, live_devices, open_named_fd, wait_for_devices_released};
pub use flow::{FlowEngine, FlowEngineContext, FlowPolicyStore, PolicyGates};
/// The name the traffic map had while it only tracked connections. Kept so the
/// test harness outside this track keeps building; new code should say
/// [`TrafficMap`].
pub use foxcore_trafficmap::TrafficMap as ConnectionTracker;
// The traffic map is its own crate: it observes the data plane and must not be
// reachable *from* it in the other direction. Re-exported here so the engine's
// consumers keep one import path for the types they hand to `FlowEngine`.
pub use foxcore_trafficmap::{
    ConnectionRow, CountingStream, DEFAULT_CONNECTION_ROWS, FlowHandle, FlowLane, FlowRoute,
    LiveFlow, PackageTraffic, PacketAccounting, PacketKey, RevokeTarget, TrafficMap,
    TrafficSnapshot,
};
pub use icmp::echo_reply_v4;
pub use ingress::{IngressChannels, StackDevice, classify};
pub use l3::AddressTranslator;
pub use metrics::{FlowMetrics, FlowSnapshot};
#[cfg(feature = "wireguard")]
pub use relay::PacketTunnelRelay;
pub use split::{FlowKey, PacketDecision, PacketRoute, PacketSplitter};

/// Case-insensitive "is this name inside the overlay TLD" test.
///
/// Runs per DNS query and per flow, so it compares bytes in place: lowercasing
/// into a fresh `String` here was a per-flow allocation (final.txt §21).
fn has_overlay_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.').as_bytes();
    let suffix = suffix.as_bytes();
    match domain.len().checked_sub(suffix.len()) {
        None => false,
        // The bare TLD itself.
        Some(0) => domain.eq_ignore_ascii_case(suffix),
        // Otherwise the suffix must start on a label boundary, so that
        // `nototonion` never matches `onion`.
        Some(offset) => domain[offset - 1] == b'.' && domain[offset..].eq_ignore_ascii_case(suffix),
    }
}

pub(crate) fn is_onion(domain: &str) -> bool {
    has_overlay_suffix(domain, "onion")
}

pub(crate) fn is_i2p(domain: &str) -> bool {
    has_overlay_suffix(domain, "i2p")
}

#[cfg(test)]
mod overlay_tests {
    use super::{is_i2p, is_onion};

    #[test]
    fn overlay_suffixes_respect_label_boundaries_and_case() {
        assert!(is_onion("onion"));
        assert!(is_onion("Hidden.ONION."));
        assert!(is_onion("a.b.onion"));
        assert!(!is_onion("nototonion"));
        assert!(!is_onion("onion.example.com"));

        assert!(is_i2p("service.i2p"));
        assert!(is_i2p("I2P"));
        assert!(!is_i2p("noti2p"));
    }
}
