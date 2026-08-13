//! A group of interchangeable proxy nodes with one active member.
//!
//! The Android app wraps every imported profile in a selector tagged `proxy`
//! and points `route.final` at it, so this type is on the path of every real
//! profile — not a convenience for multi-node setups.
//!
//! Two properties matter more than the delegation itself:
//!
//! * **Members are built lazily.** A subscription is tens of nodes; handshaking
//!   all of them at startup would cost a QUIC or TLS round trip per node before
//!   the first packet moves. Each member is constructed once, on first use.
//! * **Failover never crosses a privacy boundary.** `SelectorConfig::validate`
//!   refuses Tor, I2P, WireGuard and nested selectors as members, so every
//!   member of a live group is a stream proxy of the same trust class. Moving a
//!   flow between them changes which server sees it, never whether the traffic
//!   is protected at all.

use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use foxcore_api::{
    ContinuityInterruption, Destination, FlowContext, IpTransport, OutboundConfig, SelectorConfig,
    UrlTestConfig,
};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;

use crate::Outbound;

/// One node of the group. `built` is populated on first use and never replaced,
/// so a member that completed a handshake keeps its session across failovers.
struct SelectorMember {
    id: String,
    config: OutboundConfig,
    built: OnceCell<Arc<Outbound>>,
}

struct SelectorInner {
    members: Vec<SelectorMember>,
    /// Index into `members`. Read on every connect and written only when a
    /// failover succeeds, so the common path is a relaxed load.
    active: AtomicUsize,
    selection_revision: AtomicU64,
    selection_commit: Mutex<()>,
    member_timeout: Duration,
    dialer: ProtectedDialer,
    /// Pushed to when failover lands on a different member. Set once, at
    /// startup, by the registry.
    interruption: OnceLock<crate::InterruptionSink>,
}

#[derive(Clone)]
pub struct SelectorOutbound {
    inner: Arc<SelectorInner>,
}

struct SelectionReservation<'a> {
    selector: &'a SelectorOutbound,
    active: usize,
    revision: u64,
    finished: bool,
}

impl SelectionReservation<'_> {
    fn revision(&self) -> u64 {
        self.revision
    }

    fn finish(mut self, winner: Option<usize>) -> bool {
        let finished = self
            .selector
            .finish_reservation(self.active, self.revision, winner);
        self.finished = true;
        finished
    }
}

impl Drop for SelectionReservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.selector
                .finish_reservation(self.active, self.revision, None);
        }
    }
}

impl SelectorOutbound {
    /// Builds the group without contacting anything. Validation has already
    /// rejected an empty member list, so `active` always points at a real
    /// member.
    pub fn new(config: SelectorConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        Self::new_with_interruption_sink(config, dialer, None)
    }

    pub(crate) fn new_with_interruption_sink(
        config: SelectorConfig,
        dialer: ProtectedDialer,
        interruption: Option<crate::InterruptionSink>,
    ) -> io::Result<Self> {
        if config.members.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selector must contain at least one member",
            ));
        }
        let member_timeout = Duration::from_millis(config.member_timeout_ms());
        let default = config.default.clone();
        let members: Vec<SelectorMember> = config
            .members
            .into_iter()
            .map(|named| SelectorMember {
                id: named.id.0,
                config: named.outbound,
                built: OnceCell::new(),
            })
            .collect();
        let active = match &default {
            Some(id) => members
                .iter()
                .position(|member| member.id == id.0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "selector default is not one of its members",
                    )
                })?,
            None => 0,
        };
        let interruption_cell = OnceLock::new();
        if let Some(interruption) = interruption {
            let _ = interruption_cell.set(interruption);
        }
        let selector = Self {
            inner: Arc::new(SelectorInner {
                members,
                active: AtomicUsize::new(active),
                selection_revision: AtomicU64::new(0),
                selection_commit: Mutex::new(()),
                member_timeout,
                dialer,
                interruption: interruption_cell,
            }),
        };
        if let Some(probe) = config.probe {
            let (host, port, path) = probe
                .target()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            let destination = Destination::new(host.clone(), port);
            selector.spawn_probe(
                probe,
                ProbeTarget {
                    // `Connection: close` keeps a probe from leaving a session
                    // open on every member on every round.
                    request: format!(
                        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    ),
                    context: FlowContext::new(0, IpTransport::Tcp, destination.clone()),
                    destination,
                },
            );
        }
        Ok(selector)
    }

    /// Id of the member currently carrying traffic. Exposed for the state
    /// snapshot: a user looking at "which node am I on" must see the node that
    /// failover actually landed on, not the one they picked.
    pub fn active_id(&self) -> &str {
        let index = self.inner.active.load(Ordering::Relaxed);
        // `active` is only ever set to an index that came from `members`.
        &self.inner.members[index].id
    }

    /// See [`crate::OutboundRegistry::set_interruption_sink`].
    pub fn set_interruption_sink(&self, sink: crate::InterruptionSink) {
        let _ = self.inner.interruption.set(sink);
    }

    pub fn member_ids(&self) -> impl Iterator<Item = &str> {
        self.inner.members.iter().map(|member| member.id.as_str())
    }

    /// Pins the active member by id. Returns `false` for an unknown id rather
    /// than silently keeping the old one, so a stale UI cannot believe it
    /// switched nodes.
    pub fn select(&self, id: &str) -> bool {
        match self.inner.members.iter().position(|member| member.id == id) {
            Some(index) => {
                let _commit = lock(&self.inner.selection_commit);
                let revision = self.inner.selection_revision.load(Ordering::Relaxed);
                if self.inner.active.load(Ordering::Relaxed) != index || revision & 1 != 0 {
                    self.inner.active.store(index, Ordering::Release);
                    let increment = if revision & 1 == 0 { 2 } else { 1 };
                    self.inner
                        .selection_revision
                        .store(revision.wrapping_add(increment), Ordering::Release);
                }
                true
            }
            None => false,
        }
    }

    fn selection(&self) -> (usize, u64) {
        let _commit = lock(&self.inner.selection_commit);
        (
            self.inner.active.load(Ordering::Acquire),
            self.inner.selection_revision.load(Ordering::Acquire),
        )
    }

    fn selection_is(&self, active: usize, revision: u64) -> bool {
        let _commit = lock(&self.inner.selection_commit);
        self.inner.active.load(Ordering::Acquire) == active
            && self.inner.selection_revision.load(Ordering::Acquire) == revision
    }

    fn reserve(&self, active: usize, revision: u64) -> Option<SelectionReservation<'_>> {
        let _commit = lock(&self.inner.selection_commit);
        if self.inner.active.load(Ordering::Acquire) != active
            || self.inner.selection_revision.load(Ordering::Acquire) != revision
            || revision & 1 != 0
        {
            return None;
        }
        let reserved = revision.wrapping_add(1);
        self.inner
            .selection_revision
            .store(reserved, Ordering::Release);
        Some(SelectionReservation {
            selector: self,
            active,
            revision: reserved,
            finished: false,
        })
    }

    fn finish_reservation(&self, active: usize, reserved: u64, winner: Option<usize>) -> bool {
        let _commit = lock(&self.inner.selection_commit);
        if self.inner.active.load(Ordering::Acquire) != active
            || self.inner.selection_revision.load(Ordering::Acquire) != reserved
            || reserved & 1 == 0
        {
            return false;
        }
        if let Some(winner) = winner {
            self.inner.active.store(winner, Ordering::Release);
        }
        self.inner
            .selection_revision
            .store(reserved.wrapping_add(1), Ordering::Release);
        true
    }

    /// Builds a member if it has not been built yet.
    ///
    /// A failed build is not cached: `get_or_try_init` leaves the cell empty on
    /// error, so a node that was unreachable once is retried on a later flow
    /// rather than being written off for the life of the generation.
    async fn member(&self, index: usize) -> io::Result<Arc<Outbound>> {
        let member = &self.inner.members[index];
        let outbound = member
            .built
            .get_or_try_init(|| async {
                Outbound::from_config_with_interruption_sink(
                    member.config.clone(),
                    self.inner.dialer.clone(),
                    self.inner.interruption.get().cloned(),
                )
                .await
                .map(|outbound| {
                    // Members are built lazily, so the sink cannot be
                    // installed once at startup — a node that first carries
                    // traffic an hour in would otherwise reconnect silently.
                    if let Some(sink) = self.inner.interruption.get() {
                        outbound.install_interruption_sink(sink);
                    }
                    Arc::new(outbound)
                })
            })
            .await?;
        Ok(outbound.clone())
    }

    /// Walks members from the active one, returning the first success and
    /// promoting whichever member answered.
    ///
    /// `attempt` is retried per member, so both construction and the connect
    /// itself are covered by the same failover — a node whose TLS handshake
    /// fails is as dead as one whose TCP connect fails.
    async fn failover<T, F, Fut>(&self, attempt: F) -> io::Result<T>
    where
        F: Fn(Arc<Outbound>) -> Fut + Send,
        Fut: Future<Output = io::Result<T>> + Send,
        T: Send,
    {
        let count = self.inner.members.len();
        let (start, revision) = self.selection();
        let start = start % count;
        if revision & 1 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "selector transition is already pending",
            ));
        }
        let mut last_error = None;
        let mut reservation = None;
        for offset in 0..count {
            let index = (start + offset) % count;
            if offset == 1 {
                let Some(reserved) = self.reserve(start, revision) else {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "selector changed before failover",
                    ));
                };
                let reserved_revision = reserved.revision();
                reservation = Some(reserved);
                if let Some(sink) = self.inner.interruption.get()
                    && !sink(ContinuityInterruption::SelectorMember).wait().await
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "selector failover confirmation became stale",
                    ));
                }
                if !self.selection_is(start, reserved_revision) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "selector changed while failover was pending",
                    ));
                }
            }
            let result = match self.member(index).await {
                Ok(outbound) => {
                    match tokio::time::timeout(self.inner.member_timeout, attempt(outbound)).await {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "selector member connect timed out",
                        )),
                    }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(value) => {
                    if offset != 0 {
                        if !reservation
                            .take()
                            .expect("failover reserved before alternatives")
                            .finish(Some(index))
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "selector changed during failover",
                            ));
                        }
                    } else if !self.selection_is(start, revision) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "selector changed during connect",
                        ));
                    }
                    return Ok(value);
                }
                Err(error) => {
                    last_error = Some(io::Error::new(
                        error.kind(),
                        format!(
                            "selector member '{}' failed: {error}",
                            self.inner.members[index].id
                        ),
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "selector has no reachable member",
            )
        }))
    }

    pub async fn connect_stream(
        &self,
        context: &FlowContext,
        destination: Destination,
    ) -> io::Result<BoxStream> {
        self.failover(|outbound| {
            let destination = destination.clone();
            async move { outbound.connect_leaf_stream(context, destination).await }
        })
        .await
    }

    pub async fn connect_datagram(&self, context: &FlowContext) -> io::Result<BoxDatagramSession> {
        self.failover(|outbound| async move { outbound.connect_leaf_datagram(context).await })
            .await
    }

    /// Only built members exist to notify; an unbuilt one will pick up the new
    /// network when it is first used.
    pub fn network_changed(&self) {
        for member in &self.inner.members {
            if let Some(outbound) = member.built.get() {
                outbound.network_changed();
            }
        }
    }

    pub fn reconnects(&self) -> u64 {
        self.inner
            .members
            .iter()
            .filter_map(|member| member.built.get())
            .fold(0, |total, outbound| {
                total.saturating_add(outbound.reconnects())
            })
    }

    /// Start the latency probe, if the profile asked for one.
    ///
    /// The task holds a `Weak`, so it ends by itself once the generation that
    /// owns this group is dropped — there is no cancellation token to thread
    /// through the registry, and a forgotten one cannot leave a task probing
    /// through outbounds nobody uses any more.
    fn spawn_probe(&self, probe: UrlTestConfig, target: ProbeTarget) {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let interval = Duration::from_millis(probe.interval_ms);
            loop {
                tokio::time::sleep(interval).await;
                let Some(inner) = weak.upgrade() else { return };
                SelectorOutbound { inner }
                    .probe_once(&target, Duration::from_millis(probe.tolerance_ms))
                    .await;
            }
        });
    }

    /// Measure every member once and promote the fastest.
    ///
    /// A member that fails to answer is not ranked at all rather than ranked
    /// last: "slow" and "down" are different facts, and treating a dead node as
    /// merely slow would let it win a round where everything else is worse.
    async fn probe_once(&self, target: &ProbeTarget, tolerance: Duration) {
        let mut best: Option<(usize, Duration)> = None;
        let mut active_latency = None;
        let (active, revision) = self.selection();
        if revision & 1 != 0 {
            return;
        }
        for index in 0..self.inner.members.len() {
            let Some(latency) = self.probe_member(index, target).await else {
                continue;
            };
            if index == active {
                active_latency = Some(latency);
            }
            if best.is_none_or(|(_, current)| latency < current) {
                best = Some((index, latency));
            }
        }
        if let Some(winner) = pick_winner(active, active_latency, best, tolerance) {
            let Some(reserved) = self.reserve(active, revision) else {
                return;
            };
            if let Some(sink) = self.inner.interruption.get()
                && !sink(ContinuityInterruption::SelectorMember).wait().await
            {
                return;
            }
            reserved.finish(Some(winner));
        }
    }

    /// Time one member's round trip to the probe target, or `None` if it failed.
    async fn probe_member(&self, index: usize, target: &ProbeTarget) -> Option<Duration> {
        let started = Instant::now();
        let attempt = async {
            let outbound = self.member(index).await.ok()?;
            let mut stream = outbound
                .connect_leaf_stream(&target.context, target.destination.clone())
                .await
                .ok()?;
            stream.write_all(target.request.as_bytes()).await.ok()?;
            let code = read_probe_status(&mut stream).await?;
            (200..400).contains(&code).then_some(())
        };
        tokio::time::timeout(self.inner.member_timeout, attempt)
            .await
            .ok()
            .flatten()
            .map(|()| started.elapsed())
    }
}

const MAX_PROBE_STATUS_LINE: usize = 1024;

async fn read_probe_status<S: AsyncRead + Unpin>(stream: &mut S) -> Option<u16> {
    let mut line = Vec::with_capacity(64);
    let mut chunk = [0_u8; 64];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        line.extend_from_slice(&chunk[..read]);
        if let Some(end) = line.windows(2).position(|bytes| bytes == b"\r\n") {
            return (end <= MAX_PROBE_STATUS_LINE)
                .then(|| parse_probe_status(&line[..end]))
                .flatten();
        }
        if line.len() > MAX_PROBE_STATUS_LINE {
            return None;
        }
    }
}

fn parse_probe_status(line: &[u8]) -> Option<u16> {
    if line.len() < 12
        || !line.starts_with(b"HTTP/1.")
        || !line.get(7)?.is_ascii_digit()
        || line.get(8) != Some(&b' ')
    {
        return None;
    }
    let code = line.get(9..12)?;
    code.iter().all(u8::is_ascii_digit).then_some(())?;
    std::str::from_utf8(code).ok()?.parse().ok()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Decide whether a probe round should move the active member.
///
/// Kept separate from the measuring so the part with the interesting failure
/// modes — flapping, and unseating a healthy member on noise — can be tested
/// without a network.
fn pick_winner(
    active: usize,
    active_latency: Option<Duration>,
    best: Option<(usize, Duration)>,
    tolerance: Duration,
) -> Option<usize> {
    let (winner, latency) = best?;
    if winner == active {
        return None;
    }
    match active_latency {
        // Only unseat a working member by a margin. Without this two nodes a
        // millisecond apart trade places every round, and every trade costs the
        // next flows a fresh connection.
        Some(current) => (latency.saturating_add(tolerance) < current).then_some(winner),
        // The active member did not answer this round; anything that did beats
        // it, and waiting for a margin against nothing would pin traffic to a
        // node that is down.
        None => Some(winner),
    }
}

/// The pieces of the probe URL the prober needs, resolved once.
struct ProbeTarget {
    destination: Destination,
    request: String,
    context: FlowContext,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use foxcore_api::{NamedOutboundConfig, OutboundId, SecretString, ShadowsocksConfig};

    use super::*;

    fn member(id: &str, port: u16) -> NamedOutboundConfig {
        NamedOutboundConfig {
            id: OutboundId(id.to_owned()),
            outbound: OutboundConfig::Shadowsocks(ShadowsocksConfig {
                server: "198.51.100.7".into(),
                port,
                server_ip: None,
                method: "aes-128-gcm".into(),
                password: SecretString::new("pw"),
                udp: true,
                transport: Default::default(),
                tls: Default::default(),
                outline_prefix: None,
                obfs: None,
            }),
        }
    }

    fn dialer() -> ProtectedDialer {
        ProtectedDialer::host()
    }

    #[test]
    fn default_member_becomes_active() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: Some(OutboundId("b".into())),
                member_timeout_ms: None,
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        assert_eq!(selector.active_id(), "b");
    }

    #[test]
    fn missing_default_is_refused_rather_than_silently_ignored() {
        let result = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080)],
                default: Some(OutboundId("nope".into())),
                member_timeout_ms: None,
                probe: None,
            },
            dialer(),
        );
        let Err(error) = result else {
            panic!("a default naming no member must not fall back to the first one");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn first_member_is_active_without_an_explicit_default() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: None,
                member_timeout_ms: None,
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        assert_eq!(selector.active_id(), "a");
        assert_eq!(
            selector.member_ids().collect::<Vec<_>>(),
            vec!["a", "b"],
            "member order is the failover order and must be preserved"
        );
    }

    #[test]
    fn select_rejects_an_unknown_id() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: None,
                member_timeout_ms: None,
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        assert!(selector.select("b"));
        assert_eq!(selector.active_id(), "b");
        assert!(!selector.select("ghost"));
        assert_eq!(
            selector.active_id(),
            "b",
            "a rejected selection must not move the active member"
        );
    }

    #[test]
    fn a_cancelled_transition_releases_its_reservation() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: None,
                member_timeout_ms: None,
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        let (active, revision) = selector.selection();
        let reserved = selector.reserve(active, revision).unwrap();
        assert_eq!(selector.selection().1 & 1, 1);
        drop(reserved);
        let (_, released) = selector.selection();
        assert_eq!(released & 1, 0);
        assert!(selector.reserve(active, released).is_some());
    }

    #[test]
    fn selecting_the_active_member_cancels_a_pending_transition() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: None,
                member_timeout_ms: None,
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        let (active, revision) = selector.selection();
        let reserved = selector.reserve(active, revision).unwrap();

        assert!(selector.select("a"));
        assert_eq!(selector.active_id(), "a");
        assert_eq!(selector.selection().1 & 1, 0);
        assert!(!reserved.finish(Some(1)));
        assert_eq!(selector.active_id(), "a");
    }

    #[tokio::test]
    async fn a_group_that_moves_the_user_says_so_instead_of_waiting_to_be_asked() {
        use std::sync::Mutex;

        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: None,
                member_timeout_ms: Some(500),
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        selector.set_interruption_sink(Arc::new(move |interruption| {
            recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(interruption);
            foxcore_api::ContinuityPermit::Proceed
        }));

        // The first node refuses, the second answers: the user's traffic has
        // moved to a different server and that fact has to leave the crate.
        let attempts = AtomicUsize::new(0);
        selector
            .failover(|_outbound| async {
                if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    Err(io::Error::other("first node is down"))
                } else {
                    Ok(())
                }
            })
            .await
            .expect("the second member answered");
        assert_eq!(selector.active_id(), "b");
        assert_eq!(
            seen.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            [ContinuityInterruption::SelectorMember],
            "a member change must be pushed exactly once"
        );

        // Staying on the same node is not an interruption, and a sink that
        // fired on every successful connect would be useless noise.
        seen.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        selector
            .failover(|_outbound| async { Ok(()) })
            .await
            .unwrap();
        assert!(
            seen.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_disallowed_failover_opens_no_candidate_before_confirmation() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081)],
                default: None,
                member_timeout_ms: Some(500),
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        let (called_tx, called_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let called = Arc::new(Mutex::new(Some(called_tx)));
        let release = Arc::new(Mutex::new(Some(release_rx)));
        let sink_calls = Arc::new(AtomicUsize::new(0));
        let calls = sink_calls.clone();
        selector.set_interruption_sink(Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            if let Some(called) = lock(&called).take() {
                let _ = called.send(());
            }
            let wait = lock(&release).take().unwrap();
            foxcore_api::ContinuityPermit::Wait(Box::pin(async move { wait.await.is_ok() }))
        }));

        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let task = {
            let selector = selector.clone();
            tokio::spawn(async move {
                selector
                    .failover(move |_| {
                        let counter = counter.clone();
                        async move {
                            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                                Err(io::Error::other("active member failed"))
                            } else {
                                Ok(())
                            }
                        }
                    })
                    .await
            })
        };

        called_rx.await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(selector.active_id(), "a");
        assert_eq!(
            selector
                .failover(|_| async { Err::<(), _>(io::Error::other("active member failed")) })
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(sink_calls.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(selector.active_id(), "b");
    }

    #[tokio::test]
    async fn a_stale_failover_cannot_overwrite_a_new_selection() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081), member("c", 1082)],
                default: None,
                member_timeout_ms: Some(500),
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        let (called_tx, called_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let called = Arc::new(Mutex::new(Some(called_tx)));
        let release = Arc::new(Mutex::new(Some(release_rx)));
        selector.set_interruption_sink(Arc::new(move |_| {
            if let Some(called) = lock(&called).take() {
                let _ = called.send(());
            }
            let wait = lock(&release).take().unwrap();
            foxcore_api::ContinuityPermit::Wait(Box::pin(async move { wait.await.is_ok() }))
        }));

        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let task = {
            let selector = selector.clone();
            tokio::spawn(async move {
                selector
                    .failover(move |_| {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            Err::<(), _>(io::Error::other("active member failed"))
                        }
                    })
                    .await
            })
        };

        called_rx.await.unwrap();
        assert!(selector.select("c"));
        release_tx.send(()).unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(selector.active_id(), "c");
    }

    #[tokio::test]
    async fn every_member_is_tried_before_the_group_fails() {
        // Both members point at a discard address on a port nothing listens on,
        // so the only way to reach the error is to have walked the whole group.
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1), member("b", 1)],
                default: None,
                member_timeout_ms: Some(200),
                probe: None,
            },
            dialer(),
        )
        .unwrap();
        let context = FlowContext::new(
            1,
            foxcore_api::IpTransport::Tcp,
            Destination::new("example.invalid", 443),
        );
        let Err(error) = selector
            .connect_stream(&context, Destination::new("example.invalid", 443))
            .await
        else {
            panic!("no member is reachable, so the group must not report success");
        };
        assert!(
            error.to_string().contains("selector member 'b' failed"),
            "the last attempted member must be named in the error, got: {error}"
        );
    }

    #[test]
    fn a_probe_round_only_unseats_a_working_member_by_a_margin() {
        let tolerance = Duration::from_millis(50);
        let ms = Duration::from_millis;

        assert_eq!(
            pick_winner(0, Some(ms(100)), Some((1, ms(90))), tolerance),
            None,
            "10ms is inside the tolerance; switching here is how a group flaps"
        );
        assert_eq!(
            pick_winner(0, Some(ms(100)), Some((1, ms(20))), tolerance),
            Some(1),
            "a decisively faster member should win"
        );
        assert_eq!(
            pick_winner(0, Some(ms(100)), Some((0, ms(100))), tolerance),
            None,
            "the active member winning its own round changes nothing"
        );
    }

    #[test]
    fn a_probe_round_leaves_a_member_that_answered_nothing() {
        let tolerance = Duration::from_millis(50);
        // The active member did not answer. Requiring a margin against a
        // measurement that does not exist would pin traffic to a dead node.
        assert_eq!(
            pick_winner(0, None, Some((2, Duration::from_millis(400))), tolerance),
            Some(2)
        );
        // Nothing answered at all — including the active member. Staying put is
        // the only honest move: there is no evidence any other node is better.
        assert_eq!(pick_winner(0, None, None, tolerance), None);
    }

    #[tokio::test]
    async fn a_fragmented_probe_status_line_is_read_to_its_terminator() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            for fragment in [b"HT".as_slice(), b"TP/1.1 ", b"204 No Content\r", b"\n"] {
                server.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(read_probe_status(&mut client).await, Some(204));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn an_invalid_or_unbounded_probe_status_is_refused() {
        let (mut client, mut server) = tokio::io::duplex(MAX_PROBE_STATUS_LINE * 2);
        let writer = tokio::spawn(async move {
            server
                .write_all(&vec![b'x'; MAX_PROBE_STATUS_LINE + 1])
                .await
                .unwrap();
        });
        assert_eq!(read_probe_status(&mut client).await, None);
        writer.await.unwrap();
        assert_eq!(parse_probe_status(b"ICY 200 OK"), None);
        assert_eq!(parse_probe_status(b"HTTP/1.x 200 Nope"), None);
        assert_eq!(parse_probe_status(b"HTTP/1.1 2x0 Nope"), None);
    }

    /// Exercises the failover loop itself with an injected attempt, because a
    /// real promotion needs one member to fail and the next to succeed — which
    /// no amount of unreachable addresses can produce.
    #[tokio::test]
    async fn the_member_that_answered_becomes_active_and_is_tried_first_next_time() {
        let selector = SelectorOutbound::new(
            SelectorConfig {
                members: vec![member("a", 1080), member("b", 1081), member("c", 1082)],
                default: None,
                member_timeout_ms: Some(1_000),
                probe: None,
            },
            dialer(),
        )
        .unwrap();

        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let answered = selector
            .failover(move |_member| {
                let counter = counter.clone();
                async move {
                    // Only the second member answers.
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(io::Error::new(io::ErrorKind::ConnectionRefused, "down"))
                    } else {
                        Ok(7_u8)
                    }
                }
            })
            .await
            .expect("the second member answered, so the group must succeed");
        assert_eq!(answered, 7);
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "'c' must not be tried");
        assert_eq!(
            selector.active_id(),
            "b",
            "the member that answered has to become the active one"
        );

        // Next connect starts from the promoted member, not from the head of
        // the list: re-probing a node already known to be down on every flow is
        // exactly the latency a group is supposed to remove.
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        selector
            .failover(move |_member| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(0_u8)
                }
            })
            .await
            .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
