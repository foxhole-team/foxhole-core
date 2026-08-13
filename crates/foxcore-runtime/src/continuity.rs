use super::*;

use std::io;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use foxcore_api::{ContinuityInterruption, OutboundConfig, TrafficPolicyConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::{InterruptionSink, Outbound, OutboundRegistry};
use foxcore_tun::{ContinuityExpiry, ContinuityGate};
use serde::Serialize;

/// What the app needs to render a pending confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuityState {
    pub held_lanes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_token: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interruption: Option<ContinuityInterruption>,
    /// The deadline passed and nobody answered. The hold is still up and still
    /// answerable — this is how long it has been going on, not a different
    /// state.
    ///
    /// Polled as well as published because the event queue drops under load: a
    /// screen that only learned this from an event would, on a bad minute, show
    /// a hold as if it had just happened.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub expired: bool,
}

/// Notices when a confirmation deadline passes, and says so. That is all it
/// does.
///
/// This used to stop the engine, on the reasoning that "off has to end
/// somewhere" and that the traffic was blocked either way, so the only choice
/// left was whether a half-torn engine kept its descriptors. That reasoning
/// omits the platform. Stopping the engine closes the tun descriptor, Android
/// takes the interface down behind it, and the device is then on the open
/// network — so the choice was never between two blocked states, it was between
/// blocked and clearnet, and it was being made silently on a timer. Device
/// acceptance caught that transition.
///
/// The first fix made stopping opt-in, under a name that admitted the cost. The
/// name was the whole of the protection, and it protected the reader of the
/// config rather than the holder of the phone. So the option is gone: the hold
/// outlives its deadline, always, and this thread never touches the engine. It
/// still publishes the expiry, because the silence around that moment was half
/// the original defect.
///
/// Parks on `wake` between holds. A hold with no deadline — the default, and
/// what a spent deadline leaves behind — has nothing to watch, so the watch
/// parks through that too.
pub(crate) fn continuity_watch(gate: Arc<ContinuityGate>, wake: mpsc::Receiver<()>) {
    loop {
        // Disconnected means the engine dropped its end: nothing left to watch.
        if wake.recv().is_err() {
            return;
        }
        while let Some(deadline) = gate.deadline() {
            let now = Instant::now();
            if now >= deadline {
                // The hold stays up with the tunnel under it, in both
                // outcomes. The deadline is spent, so the loop re-reads `None`
                // and parks.
                //
                // Written as an exhaustive match over an enum this arm covers
                // entirely: if a third outcome is ever added to
                // `ContinuityExpiry`, it stops compiling here, which is where
                // somebody has to argue for it.
                match gate.expire(now) {
                    ContinuityExpiry::KeptBlocking | ContinuityExpiry::Nothing => continue,
                }
            }
            match wake.recv_timeout(deadline.saturating_duration_since(now)) {
                // Another interruption, or a confirmation. Either way the
                // deadline is re-read rather than assumed.
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

pub(crate) fn resolve_network_gates(
    traffic: &TrafficPolicyConfig,
    outbounds: &OutboundRegistry,
) -> (bool, bool) {
    (
        traffic
            .tor_enabled
            .unwrap_or_else(|| outbounds.tor().is_some()),
        traffic
            .i2p_enabled
            .unwrap_or_else(|| outbounds.i2p().is_some()),
    )
}

impl Drop for CoreRuntime {
    fn drop(&mut self) {
        // A force kill already handed the worker to the quarantine list, and
        // this is the last `Arc` falling right behind it. `stop` would find the
        // worker in `STOPPING` and sit on its completion channel for the whole
        // `STOP_TIMEOUT` — three seconds on the service thread, inside the very
        // call that promises never to wait for the worker.
        //
        // The guard belongs here and not in `stop`: a caller who asks to stop
        // an abandoned worker is asking to observe its exit, and that
        // observation is how the app learns a leaked descriptor came back. A
        // destructor is asking for nothing and may not block for it.
        if lock(&self.worker.thread).is_none() {
            return;
        }
        if self.stop() == StopResult::TimedOut {
            // A destructor may not block forever. Keep ownership of a late
            // worker globally; Android's process lease prevents a replacement
            // from starting until this worker has actually exited.
            self.worker.quarantine();
        }
    }
}

pub(crate) async fn create_outbound(
    config: OutboundConfig,
    dialer: ProtectedDialer,
    handshake_timeout_ms: u64,
    interruption: Option<InterruptionSink>,
) -> io::Result<Outbound> {
    if matches!(&config, OutboundConfig::Tor(_)) {
        return Outbound::from_config_with_interruption_sink(config, dialer, interruption).await;
    }
    tokio::time::timeout(
        Duration::from_millis(handshake_timeout_ms),
        Outbound::from_config_with_interruption_sink(config, dialer, interruption),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "outbound handshake timed out"))?
}
