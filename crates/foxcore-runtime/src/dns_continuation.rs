use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use foxcore_dns::DnsCache;
use foxcore_tun::FlowPolicyStore;

use crate::{CoreRuntime, StopResult, WORKER_STOPPED};

pub(crate) const DNS_REVOKED: u8 = 3;

/// Escalated retirement of a successor that lost its continuation owner.
#[derive(Debug, Clone, Copy)]
pub struct DnsContinuationCleanupError {
    pub(crate) force_stop: StopResult,
}

impl DnsContinuationCleanupError {
    pub fn force_stop_result(&self) -> StopResult {
        self.force_stop
    }
}

impl std::fmt::Display for DnsContinuationCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "revoked DNS successor cleanup timed out; force stop returned {:?}",
            self.force_stop
        )
    }
}

impl std::error::Error for DnsContinuationCleanupError {}

pub fn dns_continuation_cleanup_result(error: &io::Error) -> Option<StopResult> {
    error
        .get_ref()?
        .downcast_ref::<DnsContinuationCleanupError>()
        .map(DnsContinuationCleanupError::force_stop_result)
}

pub(crate) fn retire_revoked_successor(runtime: &CoreRuntime, refusal: io::Error) -> io::Error {
    if runtime.stop() != StopResult::TimedOut {
        return refusal;
    }
    let force_stop = runtime.force_kill();
    io::Error::new(
        if force_stop == StopResult::TimedOut {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::WouldBlock
        },
        DnsContinuationCleanupError { force_stop },
    )
}

/// DNS promises retained explicitly for a replacement on the same live TUN session.
///
/// The caller must discard this capability when that TUN session ends. It owns
/// neither the descriptor nor the worker; old routes/outbounds are never applied
/// to the successor. Import is allowed only after a clean worker join.
#[derive(Clone)]
pub struct DnsContinuation {
    pub(crate) policy: Arc<FlowPolicyStore>,
    pub(crate) stop_fence: Arc<AtomicU8>,
    pub(crate) packet_tunnel: bool,
}

impl DnsContinuation {
    pub fn is_ready(&self) -> bool {
        self.stop_fence.load(Ordering::Acquire) == WORKER_STOPPED
    }

    /// Permanently invalidate this continuation and every outstanding clone.
    pub fn revoke(&self) {
        self.stop_fence.store(DNS_REVOKED, Ordering::Release);
    }

    pub(crate) fn dns_for_start(&self, packet_tunnel: bool) -> io::Result<Arc<DnsCache>> {
        self.check_ready()?;
        // A flow generation can retain fake promises even after DNS switched to
        // real-IP. A packet-tunnel generation cannot route those destinations.
        if packet_tunnel && !self.packet_tunnel {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a flow DNS continuation cannot be imported into an L3 packet tunnel",
            ));
        }
        Ok(self.policy.dns_for_continuation())
    }

    pub(crate) fn check_ready(&self) -> io::Result<()> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DNS continuation requires a clean joined predecessor and a live owner lease",
            ))
        }
    }
}

impl CoreRuntime {
    /// Capture before stop; the independently shared join fence controls later use.
    pub fn dns_continuation(&self) -> DnsContinuation {
        DnsContinuation {
            policy: self.policy.clone(),
            stop_fence: self.worker.dns_stop_fence.clone(),
            packet_tunnel: self.packet_tunnel,
        }
    }
}
