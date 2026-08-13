//! An outbound that is not there yet.
//!
//! Building the outbound set used to be all-or-nothing: the builds ran in
//! parallel and the results were collected with `?`, so one outbound that
//! failed took the whole engine down with it. On a device that meant a Tor
//! bootstrap failing on a censored network — or on a state directory the app
//! had given the wrong permissions — and the VPN, I2P and direct lanes never
//! starting either. Device acceptance reproduced exactly that, and the engine
//! reported it as a failed start rather than as one lane being down.
//!
//! A failed build now produces one of these in the real outbound's place. It
//! sits in the registry under the same id, reports the same [`OutboundKind`],
//! refuses every flow routed to it with a reason the app can read, and counts
//! what it refused. The engine starts; the other lanes carry traffic.
//!
//! It is also the seam for coming back. [`DeferredOutbound::resolve`] puts the
//! real outbound inside the entry the registry is already holding, so a lane
//! that comes up ten minutes later does so without a new registry, a new flow
//! engine, or a new tun — and without touching a single live flow on the lanes
//! that were working all along.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use foxcore_api::{OutboundConfig, OutboundUnavailable, UnavailableReason};

use crate::{InterruptionSink, Outbound, OutboundKind};

/// The registry entry for an outbound whose build failed.
///
/// Cloning is cheap and shares state: the copy the flow engine reaches through
/// the registry and the copy the retry pass holds are the same entry, which is
/// what lets a rebuild reach live routing without replacing anything.
#[derive(Clone)]
pub struct DeferredOutbound {
    inner: Arc<Inner>,
}

struct Inner {
    id: String,
    kind: OutboundKind,
    /// Kept so the outbound can be built again from the same profile. A retry
    /// that re-read the config from the app would be a different outbound
    /// wearing this one's id.
    config: OutboundConfig,
    /// The real outbound, once there is one. `load` is lock-free, which matters
    /// because the flow path asks on every flow.
    resolved: ArcSwapOption<Outbound>,
    failure: Mutex<Failure>,
    refused: AtomicU64,
    /// The registry installs this once at start; an outbound built later has to
    /// get it too, or a lane that recovered would be the one lane whose
    /// self-repair nobody is told about.
    sink: Mutex<Option<InterruptionSink>>,
    /// One rebuild at a time. Retries are driven by events the app reports —
    /// a network change, a reload, an explicit call — and those arrive in
    /// bursts; without this, a phone flipping between Wi-Fi and mobile would
    /// stack a Tor bootstrap per flip.
    building: AtomicBool,
}

#[derive(Clone)]
struct Failure {
    reason: UnavailableReason,
    message: String,
    attempts: u32,
}

impl DeferredOutbound {
    /// Record a build failure as a registry entry.
    pub fn new(
        id: impl Into<String>,
        kind: OutboundKind,
        config: OutboundConfig,
        error: &io::Error,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                id: id.into(),
                kind,
                config,
                resolved: ArcSwapOption::empty(),
                failure: Mutex::new(Failure {
                    reason: UnavailableReason::of(error),
                    message: error.to_string(),
                    attempts: 1,
                }),
                refused: AtomicU64::new(0),
                sink: Mutex::new(None),
                building: AtomicBool::new(false),
            }),
        }
    }

    pub fn id(&self) -> &str {
        &self.inner.id
    }

    /// The kind the *profile* asked for, whether or not it was ever built.
    ///
    /// Deliberately not "unknown": the registry's canonical-id checks and the
    /// overlay gates both key on this, so an unavailable Tor outbound has to
    /// still be the Tor outbound. A lane that vanished from the registry when
    /// its build failed would have its flows refused as a *policy* denial, and
    /// `.onion` names would be refused as "the overlay is switched off" — two
    /// sentences that are not true.
    pub fn kind(&self) -> OutboundKind {
        self.inner.kind
    }

    pub fn config(&self) -> OutboundConfig {
        self.inner.config.clone()
    }

    /// The real outbound, if it has been built.
    pub fn resolved(&self) -> Option<Arc<Outbound>> {
        self.inner.resolved.load_full()
    }

    pub fn is_available(&self) -> bool {
        self.inner.resolved.load().is_some()
    }

    /// The error a flow routed here is refused with.
    ///
    /// `NotConnected` rather than a timeout or a refusal: nothing was dialled
    /// and nothing timed out. The outbound is not there.
    pub fn error(&self) -> io::Error {
        let failure = self.failure();
        io::Error::new(
            io::ErrorKind::NotConnected,
            format!(
                "outbound '{}' ({}) is unavailable [{}]: {}",
                self.inner.id,
                self.inner.kind.name(),
                failure.reason.name(),
                failure.message
            ),
        )
    }

    /// Count one flow this entry refused, and say why.
    ///
    /// Called on the flow path, which is why it is an atomic add and a short
    /// lock rather than an event: the count is read from the snapshot, and a
    /// lane that is refusing thousands of flows must not cost thousands of
    /// events.
    pub fn note_refusal(&self) -> UnavailableReason {
        self.inner.refused.fetch_add(1, Ordering::Relaxed);
        self.failure().reason
    }

    pub fn refused(&self) -> u64 {
        self.inner.refused.load(Ordering::Relaxed)
    }

    pub fn reason(&self) -> UnavailableReason {
        self.failure().reason
    }

    pub fn attempts(&self) -> u32 {
        self.failure().attempts
    }

    /// Whether another build attempt is worth making at all.
    ///
    /// False for a profile that cannot work — a malformed key does not become
    /// well-formed because the network came back — and false for an entry that
    /// is already up or already building.
    pub fn is_retryable(&self) -> bool {
        !self.is_available() && self.failure().reason.is_retryable()
    }

    /// Claim the right to attempt a rebuild. `false` when one is already
    /// running or the entry is already up.
    ///
    /// The claim is released by [`DeferredOutbound::resolve`] or
    /// [`DeferredOutbound::record_failure`], so an attempt that panics leaves
    /// the entry claimed and no further attempt is made — refusing forever is
    /// the safe direction for this particular latch.
    pub fn begin_attempt(&self) -> bool {
        if self.is_available() {
            return false;
        }
        self.inner
            .building
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Put the real outbound in place. Returns the number of attempts it took.
    ///
    /// Everything routed to this id dials through the new outbound from the
    /// next flow onwards. Flows already running on other lanes are untouched:
    /// they hold their own streams and never look at this entry again.
    pub fn resolve(&self, outbound: Outbound) -> u32 {
        if let Some(sink) = self.inner.sink.lock().ok().and_then(|sink| sink.clone()) {
            outbound.install_interruption_sink(&sink);
        }
        // The attempt that worked counts too, so "attempts" reads the same way
        // whether the lane came up or is still down: how many builds it took.
        let attempts = {
            let mut failure = self.lock_failure();
            failure.attempts = failure.attempts.saturating_add(1);
            failure.attempts
        };
        self.inner.resolved.store(Some(Arc::new(outbound)));
        self.inner.building.store(false, Ordering::Release);
        attempts
    }

    /// Record an attempt that failed. Returns the new state, and whether the
    /// class of failure changed.
    ///
    /// The caller uses "changed" to decide whether to publish an event: a Tor
    /// bootstrap that times out on every network change for an hour is one
    /// piece of news, not sixty, and the event queue it would fill is shared
    /// with the events that are.
    pub fn record_failure(&self, error: &io::Error) -> (UnavailableReason, bool) {
        let reason = UnavailableReason::of(error);
        let changed = {
            let mut failure = self.lock_failure();
            let changed = failure.reason != reason;
            failure.reason = reason;
            failure.message = error.to_string();
            failure.attempts = failure.attempts.saturating_add(1);
            changed
        };
        self.inner.building.store(false, Ordering::Release);
        (reason, changed)
    }

    /// What the snapshot publishes for this entry.
    pub fn state(&self) -> OutboundUnavailable {
        let failure = self.failure();
        OutboundUnavailable {
            id: self.inner.id.clone(),
            kind: self.inner.kind.name().to_owned(),
            reason: failure.reason,
            message: failure.message,
            attempts: failure.attempts,
            refused: self.refused(),
        }
    }

    pub(crate) fn install_interruption_sink(&self, sink: &InterruptionSink) {
        if let Ok(mut held) = self.inner.sink.lock() {
            *held = Some(sink.clone());
        }
        if let Some(outbound) = self.resolved() {
            outbound.install_interruption_sink(sink);
        }
    }

    pub fn interruption_sink(&self) -> Option<InterruptionSink> {
        self.inner.sink.lock().ok().and_then(|sink| sink.clone())
    }

    fn failure(&self) -> Failure {
        self.lock_failure().clone()
    }

    /// A poisoned lock here would mean a panic while recording a failure. The
    /// state behind it is three plain fields with no invariant between them, so
    /// the recorded value is still readable and refusing to read it would turn
    /// one panic into a lane that can never report why it is down.
    fn lock_failure(&self) -> std::sync::MutexGuard<'_, Failure> {
        self.inner
            .failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl std::fmt::Debug for DeferredOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let failure = self.failure();
        f.debug_struct("DeferredOutbound")
            .field("id", &self.inner.id)
            .field("kind", &self.inner.kind)
            .field("available", &self.is_available())
            .field("reason", &failure.reason)
            .field("attempts", &failure.attempts)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxcore_api::SocksConfig;
    use foxcore_dialer::ProtectedDialer;

    fn config() -> OutboundConfig {
        OutboundConfig::Socks(SocksConfig {
            server: "127.0.0.1".into(),
            port: 1080,
            server_ip: None,
            username: None,
            password: None,
            handshake_timeout_ms: 100,
        })
    }

    fn deferred(error: io::Error) -> DeferredOutbound {
        DeferredOutbound::new("proxy", OutboundKind::Socks, config(), &error)
    }

    /// The dial path has to go *through* a resolved entry, not stop at it.
    ///
    /// `Outbound::connect_stream` unrolls the one level of indirection by hand
    /// rather than recursing, because a recursive future would have to be
    /// boxed. Hand-written unwrapping is exactly the kind of thing that reads
    /// correct and refuses every flow in practice, so it is dialled here rather
    /// than inspected.
    #[tokio::test]
    async fn a_resolved_entry_carries_traffic_rather_than_standing_in_the_way() {
        use foxcore_api::{Destination, FlowContext, IpTransport};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = [0_u8; 4];
            stream.read_exact(&mut received).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
            received
        });

        let entry = deferred(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        let outbound = Outbound::Deferred(entry.clone());
        let context = FlowContext::new(
            1,
            IpTransport::Tcp,
            Destination::new(address.ip().to_string(), address.port()),
        );
        let destination = context.destination.clone();
        assert_eq!(
            outbound
                .connect_stream(&context, destination.clone())
                .await
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::NotConnected),
            "while it is not there, it refuses"
        );

        entry.begin_attempt();
        entry.resolve(Outbound::direct(ProtectedDialer::host()));

        let mut stream = outbound
            .connect_stream(&context, destination)
            .await
            .expect("a resolved entry dials through the outbound it holds");
        stream.write_all(b"ping").await.unwrap();
        let mut answer = [0_u8; 4];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"pong");
        assert_eq!(&server.await.unwrap(), b"ping");
    }

    #[test]
    fn an_unavailable_entry_refuses_and_counts_what_it_refused() {
        let entry = deferred(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        assert!(!entry.is_available());
        assert_eq!(entry.note_refusal(), UnavailableReason::Timeout);
        assert_eq!(entry.note_refusal(), UnavailableReason::Timeout);
        assert_eq!(entry.refused(), 2);
        let state = entry.state();
        assert_eq!(state.id, "proxy");
        assert_eq!(state.kind, "socks");
        assert_eq!(state.refused, 2);
        assert_eq!(state.attempts, 1);
    }

    #[test]
    fn resolving_puts_the_real_outbound_in_the_entry_the_registry_already_holds() {
        let entry = deferred(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        // The copy routing would be holding.
        let routing = entry.clone();
        assert!(!routing.is_available());

        assert!(entry.begin_attempt());
        entry.resolve(Outbound::direct(ProtectedDialer::host()));

        assert!(
            routing.is_available(),
            "a rebuild has to reach the entry routing already holds, or it needs a new registry"
        );
        assert!(routing.resolved().is_some());
    }

    #[test]
    fn only_one_rebuild_runs_at_a_time() {
        let entry = deferred(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        assert!(entry.begin_attempt());
        assert!(
            !entry.begin_attempt(),
            "a burst of network changes must not stack one bootstrap per change"
        );
        entry.record_failure(&io::Error::new(io::ErrorKind::TimedOut, "again"));
        assert!(entry.begin_attempt(), "and the next burst may try again");
    }

    #[test]
    fn a_repeated_identical_failure_is_not_news_but_a_different_one_is() {
        let entry = deferred(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        let (reason, changed) =
            entry.record_failure(&io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        assert_eq!(reason, UnavailableReason::Timeout);
        assert!(!changed);
        let (reason, changed) = entry.record_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state directory",
        ));
        assert_eq!(reason, UnavailableReason::Permissions);
        assert!(changed);
        assert_eq!(entry.attempts(), 3, "the attempt at start counts as one");
    }

    #[test]
    fn a_profile_that_cannot_work_is_not_retried() {
        let entry = deferred(io::Error::new(io::ErrorKind::InvalidInput, "bad key"));
        assert!(!entry.is_retryable());
        let entry = deferred(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
        assert!(entry.is_retryable());
        entry.begin_attempt();
        entry.resolve(Outbound::direct(ProtectedDialer::host()));
        assert!(
            !entry.is_retryable(),
            "and neither is one that is already up"
        );
    }
}
