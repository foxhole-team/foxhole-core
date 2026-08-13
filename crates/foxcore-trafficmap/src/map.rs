//! Who is talking, to where, by which route, and how much.
//!
//! The aggregate counters in the flow engine answer "is the tunnel moving
//! bytes". They cannot answer "which app is moving them, and did they go
//! through the VPN or straight out", and the platform cannot answer it either:
//! while the VPN is up, Android's own `NetworkStats` attributes every tunnelled
//! byte to the tun interface, not to the app behind it. The core is the only
//! place that knows both, because it already resolves the owning package and
//! chooses the outbound per flow.
//!
//! The row cap bounds *rendering*, not tracking. Every live flow is tracked:
//! how many can exist at once is already bounded by the engine's flow
//! semaphores, so the table cannot grow without limit. What a screen must not
//! do is render thousands of rows, so a snapshot returns the busiest `rows` of
//! them and says how many it left out. Accounting stays exact — a number that
//! silently stops adding up is worse than no number at all, and the anomaly
//! detector is watching these totals.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use foxcore_api::IpTransport;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::events::{
    DEFAULT_TRAFFIC_EVENT_CAPACITY, TrafficEvent, TrafficEventDrain, TrafficEventQueue,
};
use crate::packet::{PacketAccounting, PacketKey};
use crate::route::{FlowLane, FlowRoute, LANE_COUNT, LANES};

/// Live rows kept for the UI. Bounded so a busy device cannot grow the
/// snapshot without limit.
pub const DEFAULT_CONNECTION_ROWS: usize = 2_000;

#[derive(Debug, Default)]
struct LaneCounters {
    up: AtomicU64,
    down: AtomicU64,
    opened: AtomicU64,
    closed: AtomicU64,
}

/// Per-lane totals, shared by the map and by every flow on that lane.
///
/// Held behind an `Arc` rather than reached through the map so a flow can add
/// its bytes to both its own row and its lane with two relaxed atomics and no
/// lock — this runs on every read and write of every flow.
#[derive(Debug, Default)]
pub struct LaneTotals {
    lanes: [LaneCounters; LANE_COUNT],
}

impl LaneTotals {
    fn add_up(&self, lane: FlowLane, bytes: u64) {
        self.lanes[lane.index()]
            .up
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn add_down(&self, lane: FlowLane, bytes: u64) {
        self.lanes[lane.index()]
            .down
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn opened(&self, lane: FlowLane) {
        self.lanes[lane.index()]
            .opened
            .fetch_add(1, Ordering::Relaxed);
    }

    fn closed(&self, lane: FlowLane) {
        self.lanes[lane.index()]
            .closed
            .fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<LaneTraffic> {
        LANES
            .into_iter()
            .map(|lane| {
                let counters = &self.lanes[lane.index()];
                let opened = counters.opened.load(Ordering::Relaxed);
                let closed = counters.closed.load(Ordering::Relaxed);
                LaneTraffic {
                    lane,
                    bytes_up: counters.up.load(Ordering::Relaxed),
                    bytes_down: counters.down.load(Ordering::Relaxed),
                    flows_opened: opened,
                    flows_live: opened.saturating_sub(closed),
                }
            })
            .collect()
    }
}

/// One flow, while it is open.
///
/// Byte counters are atomics rather than a locked struct: they are touched on
/// every read and write of the flow, and a mutex there would put the whole data
/// path behind one lock.
#[derive(Debug)]
pub struct LiveFlow {
    pub id: u64,
    pub transport: IpTransport,
    /// The destination as the flow addressed it — a domain when one was known,
    /// otherwise the literal address. This is what the user recognises.
    pub host: String,
    pub port: u16,
    pub route: FlowRoute,
    /// Who owns this flow.
    ///
    /// Mutable because it can arrive after the flow does. Routing only resolves
    /// identity when a rule needs it, so with no per-app rules nothing in the
    /// map had an owner at all (D12) — and resolving it inline for telemetry
    /// would put a platform round trip in front of every connection's first
    /// byte. It is resolved off the critical path instead and filled in here.
    /// Nothing is lost by the delay: totals are computed from the row's current
    /// owner at snapshot and at close, never incrementally.
    identity: Mutex<FlowIdentity>,
    opened_at: Instant,
    up: AtomicU64,
    down: AtomicU64,
    lanes: Arc<LaneTotals>,
    /// Cancelled when this one flow is revoked. See [`TrafficMap::revoke`].
    ///
    /// # Why the stop signal lives in the map
    ///
    /// This crate observes the data plane and is not reachable from it in the
    /// other direction, which is the reason it is a crate at all. A token here
    /// does not change that, and the distinction is worth being precise about:
    /// cancelling it *does nothing by itself*. It sets a flag and wakes
    /// whoever is waiting. What a cancelled token means — a reset towards the
    /// application for TCP, a torn-down session for UDP — is decided entirely
    /// by the engine, in the engine's own crate. The map never calls into the
    /// data plane and gains no ability to.
    ///
    /// It lives here because this is the only structure that knows which flows
    /// exist *and* who owns each one. A second registry in the engine would
    /// have to duplicate the uid, the package list, the lane and the outbound
    /// id, and the two would disagree the first time one of them was updated
    /// and the other was not.
    revocation: CancellationToken,
}

impl LiveFlow {
    /// The handle a relay waits on to learn that this flow has been revoked.
    ///
    /// Cloned rather than borrowed: the relay holds it across every await in
    /// the flow's life, and borrowing would tie it to the map's lock.
    pub fn revocation(&self) -> CancellationToken {
        self.revocation.clone()
    }

    /// Whether this flow has been revoked. For a caller that is about to start
    /// work rather than one already waiting.
    pub fn is_revoked(&self) -> bool {
        self.revocation.is_cancelled()
    }

    pub fn add_up(&self, bytes: u64) {
        self.up.fetch_add(bytes, Ordering::Relaxed);
        self.lanes.add_up(self.route.lane, bytes);
    }

    pub fn add_down(&self, bytes: u64) {
        self.down.fetch_add(bytes, Ordering::Relaxed);
        self.lanes.add_down(self.route.lane, bytes);
    }

    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    /// Record who owns this flow, once the platform has answered.
    ///
    /// Ignored when the owner is already known: routing may have resolved it
    /// inline, and a later best-effort answer must not overwrite the one the
    /// policy actually acted on.
    pub fn set_identity(&self, uid: Option<u32>, packages: Vec<String>) {
        let mut identity = lock(&self.identity);
        if identity.packages.is_empty() && identity.uid.is_none() {
            *identity = FlowIdentity { packages, uid };
        }
    }

    pub fn packages(&self) -> Vec<String> {
        lock(&self.identity).packages.clone()
    }

    pub fn uid(&self) -> Option<u32> {
        lock(&self.identity).uid
    }

    /// Whether `target` names this flow.
    ///
    /// Identity is read once, under one lock: a flow whose owner arrives while
    /// this is being evaluated must be either wholly in or wholly out, never
    /// matched on its uid and missed on its package.
    fn matches(&self, target: &RevokeTarget) -> bool {
        match target {
            RevokeTarget::All {} => true,
            RevokeTarget::Flow { flow } => self.id == *flow,
            RevokeTarget::Lane { lane } => self.route.lane == *lane,
            RevokeTarget::Outbound { outbound } => {
                self.route.outbound_id.as_deref() == Some(outbound.as_str())
            }
            RevokeTarget::Uid { uid } => lock(&self.identity).uid == Some(*uid),
            RevokeTarget::Package { package } => lock(&self.identity)
                .packages
                .iter()
                .any(|owner| owner == package),
        }
    }

    fn snapshot(&self) -> ConnectionRow {
        let identity = lock(&self.identity).clone();
        ConnectionRow {
            id: self.id,
            transport: self.transport,
            host: self.host.clone(),
            port: self.port,
            outbound: self.route.outbound,
            route: self.route.clone(),
            packages: identity.packages,
            uid: identity.uid,
            age_ms: self.opened_at.elapsed().as_millis() as u64,
            bytes_up: self.bytes_up(),
            bytes_down: self.bytes_down(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FlowIdentity {
    packages: Vec<String>,
    uid: Option<u32>,
}

/// Which live flows a revocation applies to.
///
/// # Why the caller names this instead of the policy inferring it
///
/// A policy reload preserves flows that are already open, and for a route
/// change that is right: nobody wants a download killed because a rule was
/// reordered. For a `Block` it is wrong — the user taps "block this app" and
/// the app keeps talking over the TCP connections it already has until they
/// close on their own, which for a security product is a promise that is not
/// kept.
///
/// The policy layer cannot tell the two apart, because the difference is not in
/// the document: the same edited rule list arrives either way. So the two are
/// separate calls. `reload_policy` decides what happens to the *next* flow and
/// never touches a live one; this decides which live flows stop. A caller that
/// wants both does both, in that order, and gets a state where nothing can slip
/// through in between: the new policy is already refusing new flows by the time
/// the old ones are cut.
///
/// # Reading the JSON
///
/// Internally tagged on `kind`, one required field per kind:
///
/// ```json
/// {"kind": "all"}
/// {"kind": "lane",     "lane": "vpn"}
/// {"kind": "uid",      "uid": 10123}
/// {"kind": "package",  "package": "com.example.app"}
/// {"kind": "outbound", "outbound": "default"}
/// {"kind": "flow",     "flow": 42}
/// ```
///
/// Unknown kinds and missing fields are parse errors rather than a fallback to
/// anything: the permissive reading of a malformed target would be to revoke
/// too little, and the destructive one to revoke too much. Neither is a guess
/// worth making on the user's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevokeTarget {
    /// Every live flow. The kill switch, and a profile switch.
    ///
    /// Not the same as arming the kill switch: this stops the flows that exist
    /// and says nothing about the ones that follow. A caller that wants both
    /// reloads a blocking policy as well.
    ///
    /// Spelled as an empty struct variant rather than a unit one, and that is
    /// load-bearing. `deny_unknown_fields` does not reach a unit variant of an
    /// internally-tagged enum — serde accepts and discards whatever else is in
    /// the object — so `{"kind":"all","package":"com.example"}`, which is what
    /// a caller writes when it means the *package* kind and gets the tag wrong,
    /// parsed as "revoke every flow on the device". Of the two ways to
    /// misread a malformed target that is the destructive one.
    All {},
    /// Every flow on one lane — the VPN went away, or the user turned an
    /// overlay off and its circuits must not outlive the switch.
    Lane { lane: FlowLane },
    /// Every flow owned by one Android uid.
    ///
    /// The uid rather than the package is the one a shared-uid app cannot
    /// escape, and it is what the platform attributor answers with first.
    Uid { uid: u32 },
    /// Every flow owned by one package name.
    ///
    /// A flow matches if the package is anywhere in its owner list, because a
    /// shared uid genuinely has several owners and blocking one of them has to
    /// reach the connections it is using.
    Package { package: String },
    /// Every flow the router sent to one configured outbound, by its id.
    ///
    /// This is what a live flow records of the routing decision — see
    /// [`FlowRoute::outbound_id`]. It is deliberately **not** "every flow that
    /// matched rule N": a `RouteRule` has no id in the config schema, and a
    /// flow does not record which rule chose it, so a rule-scoped revocation
    /// would need both a new config field and a new field on every flow. The
    /// outbound id is the identifier that already exists on both sides.
    Outbound { outbound: String },
    /// One flow, by the id its row carries in the traffic map.
    ///
    /// For "close this connection" on a screen that is already showing the
    /// row. Ids are unique within a generation and are never reused, so a stale
    /// tap from an old screen revokes nothing rather than something else.
    Flow { flow: u64 },
}

impl RevokeTarget {
    /// Parse a target document. The error is the serde message, which names the
    /// field or the kind that was wrong.
    pub fn parse(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|error| error.to_string())
    }

    /// Which kind of target this is, for the audit record.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::All {} => "all",
            Self::Lane { .. } => "lane",
            Self::Uid { .. } => "uid",
            Self::Package { .. } => "package",
            Self::Outbound { .. } => "outbound",
            Self::Flow { .. } => "flow",
        }
    }

    /// The argument as text, for the audit record beside [`Self::kind`].
    ///
    /// `None` only for `All`, which has no argument. The journal wants both:
    /// "the user blocked com.example and it cost three connections" is the
    /// entry, and a kind on its own cannot say which app.
    pub fn scope(&self) -> Option<String> {
        match self {
            Self::All {} => None,
            Self::Lane { lane } => Some(lane.name().to_owned()),
            Self::Uid { uid } => Some(uid.to_string()),
            Self::Package { package } => Some(package.clone()),
            Self::Outbound { outbound } => Some(outbound.clone()),
            Self::Flow { flow } => Some(flow.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionRow {
    pub id: u64,
    pub transport: IpTransport,
    pub host: String,
    pub port: u16,
    /// Kept beside `route` because the app's existing connection screen reads
    /// this field by name; removing it would be a breaking ABI change for a
    /// value `route.outbound` also carries.
    pub outbound: &'static str,
    pub route: FlowRoute,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    pub age_ms: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LaneTraffic {
    pub lane: FlowLane,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub flows_opened: u64,
    pub flows_live: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PackageLaneTraffic {
    pub lane: FlowLane,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageTraffic {
    pub package: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Where this app's bytes went. An app that is half on the VPN and half
    /// direct is exactly the case a split-tunnel screen exists to show, and a
    /// single total cannot express it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lanes: Vec<PackageLaneTraffic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrafficSnapshot {
    pub connections: Vec<ConnectionRow>,
    /// Per-app totals, live flows included. Sorted by traffic, most first — the
    /// screen wants the busy apps, and sorting here keeps every consumer from
    /// inventing its own order.
    pub packages: Vec<PackageTraffic>,
    /// Per-lane totals, in [`crate::LANES`] order.
    pub lanes: Vec<LaneTraffic>,
    /// Live flows this snapshot did not render. Their bytes are still in
    /// `packages` and `lanes` — only the rows are missing.
    pub omitted_rows: usize,
    /// Change-stream updates lost since the last drain, so a consumer that
    /// only reads snapshots still learns that the stream is behind.
    pub dropped_events: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Bytes {
    up: u64,
    down: u64,
}

impl Bytes {
    fn add(&mut self, up: u64, down: u64) {
        self.up = self.up.saturating_add(up);
        self.down = self.down.saturating_add(down);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PackageTotals {
    total: Bytes,
    lanes: [Bytes; LANE_COUNT],
}

impl PackageTotals {
    fn add(&mut self, lane: FlowLane, up: u64, down: u64) {
        self.total.add(up, down);
        self.lanes[lane.index()].add(up, down);
    }
}

/// Live flows, per-app and per-lane totals for one runtime generation.
pub struct TrafficMap {
    live: Mutex<BTreeMap<u64, Arc<LiveFlow>>>,
    /// Totals for flows that have already closed. The live ones are added at
    /// snapshot time, so a long download is visible while it is running rather
    /// than appearing all at once when it ends.
    closed: Mutex<HashMap<String, PackageTotals>>,
    lanes: Arc<LaneTotals>,
    tunnel: Arc<PacketAccounting>,
    events: TrafficEventQueue,
    next_id: AtomicU64,
    rows: usize,
}

impl Default for TrafficMap {
    fn default() -> Self {
        Self::new(DEFAULT_CONNECTION_ROWS)
    }
}

impl TrafficMap {
    pub fn new(rows: usize) -> Self {
        Self {
            live: Mutex::new(BTreeMap::new()),
            closed: Mutex::new(HashMap::new()),
            lanes: Arc::new(LaneTotals::default()),
            tunnel: Arc::new(PacketAccounting::default()),
            events: TrafficEventQueue::new(DEFAULT_TRAFFIC_EVENT_CAPACITY),
            next_id: AtomicU64::new(1),
            rows: rows.max(1),
        }
    }

    /// The lock-free 5-tuple table the L3 packet path counts through.
    pub fn tunnel(&self) -> &Arc<PacketAccounting> {
        &self.tunnel
    }

    /// Register a flow. The returned handle removes it and folds its bytes into
    /// the owning app's and lane's totals when dropped, so a forgotten close is
    /// not a way to leak a row.
    pub fn open(
        self: &Arc<Self>,
        transport: IpTransport,
        host: String,
        port: u16,
        route: FlowRoute,
        packages: Vec<String>,
        uid: Option<u32>,
    ) -> FlowHandle {
        let lane = route.lane;
        let flow = Arc::new(LiveFlow {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            transport,
            host,
            port,
            route,
            identity: Mutex::new(FlowIdentity { packages, uid }),
            opened_at: Instant::now(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            lanes: self.lanes.clone(),
            revocation: CancellationToken::new(),
        });
        self.lanes.opened(lane);
        lock(&self.live).insert(flow.id, flow.clone());
        self.events.publish(TrafficEvent::Opened {
            id: flow.id,
            transport: flow.transport,
            host: flow.host.clone(),
            port: flow.port,
            route: flow.route.clone(),
            packages: flow.packages(),
            uid: lock(&flow.identity).uid,
        });
        FlowHandle {
            map: self.clone(),
            flow,
            packet_key: None,
        }
    }

    pub fn drain_events(&self, max: usize) -> TrafficEventDrain {
        self.events.drain(max)
    }

    /// Stop the live flows `target` names. Returns how many were signalled.
    ///
    /// Zero is an ordinary answer, not an error: revoking an app that is not
    /// talking, or a lane nothing is on, is a request that was already
    /// satisfied. Nothing distinguishes "no such app" from "that app has no
    /// open connections" here, and nothing should — the caller asked for a
    /// state, and the state holds either way.
    ///
    /// Idempotent, and safe to call while traffic is moving. Cancelling a token
    /// twice is a no-op, so a second revoke of the same target reports the
    /// flows that have not finished tearing down yet and does nothing to them.
    ///
    /// # What this does not do
    ///
    /// It does not change policy. Every flow it stops may be opened again by
    /// the very next packet, because what a *new* flow is allowed to do is
    /// decided by the route table and this never touches it. Revocation is the
    /// second half of blocking an app, never the whole of it.
    ///
    /// # Why the lock is not held while flows tear down
    ///
    /// The tokens are collected under the lock and cancelled after it is
    /// dropped. Cancelling wakes the relay tasks, and a woken relay ends by
    /// dropping its [`FlowHandle`], which takes the same lock to remove its
    /// row — on a current-thread runtime that is a deadlock, and on any runtime
    /// it is the map's lock held across other tasks' teardown.
    pub fn revoke(&self, target: &RevokeTarget) -> usize {
        let doomed: Vec<CancellationToken> = {
            let live = lock(&self.live);
            live.values()
                .filter(|flow| flow.matches(target))
                .map(|flow| flow.revocation.clone())
                .collect()
        };
        let count = doomed.len();
        for token in doomed {
            token.cancel();
        }
        count
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        let live = lock(&self.live);
        let mut totals: HashMap<String, PackageTotals> = lock(&self.closed).clone();
        // Every live flow is accounted for; only the rendering is capped below.
        let mut connections: Vec<ConnectionRow> = live
            .values()
            .map(|flow| {
                let row = flow.snapshot();
                for package in &row.packages {
                    totals.entry(package.clone()).or_default().add(
                        row.route.lane,
                        row.bytes_up,
                        row.bytes_down,
                    );
                }
                row
            })
            .collect();
        drop(live);

        // Busiest first: a screen that can show a hundred rows should get the
        // hundred worth looking at, not the hundred that happened to open first.
        connections.sort_by(|left, right| {
            let left_total = left.bytes_up.saturating_add(left.bytes_down);
            let right_total = right.bytes_up.saturating_add(right.bytes_down);
            right_total
                .cmp(&left_total)
                .then_with(|| left.id.cmp(&right.id))
        });
        let omitted_rows = connections.len().saturating_sub(self.rows);
        connections.truncate(self.rows);

        let mut packages: Vec<PackageTraffic> = totals
            .into_iter()
            .map(|(package, totals)| PackageTraffic {
                package,
                bytes_up: totals.total.up,
                bytes_down: totals.total.down,
                lanes: LANES
                    .into_iter()
                    .filter_map(|lane| {
                        let bytes = totals.lanes[lane.index()];
                        (bytes.up != 0 || bytes.down != 0).then_some(PackageLaneTraffic {
                            lane,
                            bytes_up: bytes.up,
                            bytes_down: bytes.down,
                        })
                    })
                    .collect(),
            })
            .collect();
        packages.sort_by(|left, right| {
            let left_total = left.bytes_up.saturating_add(left.bytes_down);
            let right_total = right.bytes_up.saturating_add(right.bytes_down);
            right_total
                .cmp(&left_total)
                .then_with(|| left.package.cmp(&right.package))
        });

        TrafficSnapshot {
            connections,
            packages,
            lanes: self.lanes.snapshot(),
            omitted_rows,
            dropped_events: self.events.dropped(),
        }
    }

    fn close(&self, flow: &LiveFlow, packet_key: Option<PacketKey>) {
        if let Some(key) = packet_key {
            // Before the row goes: a packet arriving after this point has no
            // flow to be counted against, and holding the binding open would
            // keep the closed flow alive in the table.
            self.tunnel.unbind(&key);
        }
        lock(&self.live).remove(&flow.id);
        self.lanes.closed(flow.route.lane);
        let up = flow.bytes_up();
        let down = flow.bytes_down();
        self.events.publish(TrafficEvent::Closed {
            id: flow.id,
            bytes_up: up,
            bytes_down: down,
        });
        if up == 0 && down == 0 {
            return;
        }
        let mut closed = lock(&self.closed);
        for package in &lock(&flow.identity).packages {
            closed
                .entry(package.clone())
                .or_default()
                .add(flow.route.lane, up, down);
        }
    }
}

/// Aggregate byte counters fed alongside the map.
///
/// The engine keeps a cheap summary the UI polls once a second and a map it
/// asks for only when a screen is open. They have to agree, so they are fed
/// from the same place — see [`CountingStream`].
pub trait ByteCounters: Send + Sync {
    fn add_up(&self, bytes: u64);
    fn add_down(&self, bytes: u64);
}

/// Counts what passes through, so a flow's numbers are current while it runs.
///
/// `copy_bidirectional` only reports totals when it returns, which for a long
/// download is when the download ends. Wrapping the remote side means the UI
/// sees a transfer in progress instead of nothing followed by a jump.
///
/// It also means the numbers survive a relay that never returns at all. The
/// aggregate counters used to be written from `copy_bidirectional`'s return
/// value, so a flow torn down by cancellation or by an armed kill switch
/// contributed nothing to them while contributing everything to the map — the
/// two disagreed by up to 37x on the device (D9). Arming the kill switch
/// revokes live flows, which made that branch the common one rather than the
/// rare one.
pub struct CountingStream<S> {
    inner: S,
    flow: Arc<LiveFlow>,
    totals: Option<Arc<dyn ByteCounters>>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, flow: Arc<LiveFlow>) -> Self {
        Self {
            inner,
            flow,
            totals: None,
        }
    }

    /// Also report to the engine's aggregate counters.
    pub fn with_totals(mut self, totals: Arc<dyn ByteCounters>) -> Self {
        self.totals = Some(totals);
        self
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if polled.is_ready() {
            // Read *from the remote* is what arrived for the user.
            let read = buf.filled().len().saturating_sub(before);
            self.flow.add_down(read as u64);
            if let Some(totals) = &self.totals {
                totals.add_down(read as u64);
            }
        }
        polled
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(written)) = &polled {
            self.flow.add_up(*written as u64);
            if let Some(totals) = &self.totals {
                totals.add_up(*written as u64);
            }
        }
        polled
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Removes the flow from the live view and settles its accounting on drop.
pub struct FlowHandle {
    map: Arc<TrafficMap>,
    flow: Arc<LiveFlow>,
    packet_key: Option<PacketKey>,
}

impl FlowHandle {
    pub fn flow(&self) -> &Arc<LiveFlow> {
        &self.flow
    }

    pub fn id(&self) -> u64 {
        self.flow.id
    }

    /// Bind this flow to a 5-tuple so the L3 packet path can count it in both
    /// directions. Dropping the handle releases the binding.
    pub fn bind_packet_flow(mut self, key: PacketKey) -> Self {
        self.map.tunnel.bind(key, self.flow.clone());
        self.packet_key = Some(key);
        self
    }

    pub fn add_up(&self, bytes: u64) {
        self.flow.add_up(bytes);
    }

    pub fn add_down(&self, bytes: u64) {
        self.flow.add_down(bytes);
    }
}

impl Drop for FlowHandle {
    fn drop(&mut self) {
        self.map.close(&self.flow, self.packet_key);
    }
}

/// A poisoned lock means another task panicked while holding it. The contents
/// are still consistent, and losing every later flow's accounting over someone
/// else's panic helps nobody.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn map(rows: usize) -> Arc<TrafficMap> {
        Arc::new(TrafficMap::new(rows))
    }

    fn open(map: &Arc<TrafficMap>, host: &str, package: &str, lane: FlowLane) -> FlowHandle {
        map.open(
            IpTransport::Tcp,
            host.to_owned(),
            443,
            FlowRoute::new(lane, "vless"),
            vec![package.to_owned()],
            Some(10_123),
        )
    }

    #[test]
    fn a_live_flow_is_visible_while_it_runs_not_only_when_it_ends() {
        let map = map(8);
        let flow = open(&map, "example.com", "com.example", FlowLane::Vpn);
        flow.add_up(100);
        flow.add_down(900);

        let snapshot = map.snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].bytes_down, 900);
        assert_eq!(snapshot.packages[0].package, "com.example");
        assert_eq!(snapshot.packages[0].bytes_up, 100);
        assert_eq!(snapshot.packages[0].bytes_down, 900);
    }

    #[test]
    fn closing_a_flow_removes_the_row_and_keeps_the_total() {
        let map = map(8);
        let flow = open(&map, "example.com", "com.example", FlowLane::Vpn);
        flow.add_up(10);
        flow.add_down(20);
        drop(flow);

        let snapshot = map.snapshot();
        assert!(snapshot.connections.is_empty());
        assert_eq!(snapshot.packages[0].bytes_up, 10);
        assert_eq!(snapshot.packages[0].bytes_down, 20);
    }

    #[test]
    fn a_flow_is_never_counted_twice_across_the_close() {
        let map = map(8);
        let first = open(&map, "a.example", "com.example", FlowLane::Vpn);
        first.add_up(5);
        drop(first);
        let second = open(&map, "b.example", "com.example", FlowLane::Vpn);
        second.add_up(7);

        // 5 settled + 7 live. Double counting here would make the totals grow
        // every time a flow ended, which reads as a traffic spike that never
        // happened — and the anomaly detector is watching exactly that.
        assert_eq!(map.snapshot().packages[0].bytes_up, 12);
    }

    #[test]
    fn the_row_cap_bounds_rendering_but_never_accounting() {
        let map = map(2);
        let flows: Vec<_> = (0..5)
            .map(|index| {
                let flow = open(
                    &map,
                    &format!("{index}.example"),
                    "com.example",
                    FlowLane::Vpn,
                );
                flow.add_up(10);
                flow
            })
            .collect();

        let snapshot = map.snapshot();
        assert_eq!(snapshot.connections.len(), 2, "the view is bounded");
        assert_eq!(snapshot.omitted_rows, 3, "and says how much it is missing");
        assert_eq!(
            snapshot.packages[0].bytes_up, 50,
            "every flow's bytes count, row or no row"
        );
        drop(flows);
    }

    #[test]
    fn totals_are_sorted_by_traffic_so_every_consumer_agrees() {
        let map = map(8);
        let quiet = open(&map, "a.example", "com.quiet", FlowLane::Vpn);
        quiet.add_up(1);
        let busy = open(&map, "b.example", "com.busy", FlowLane::Vpn);
        busy.add_down(1_000);

        let snapshot = map.snapshot();
        assert_eq!(snapshot.packages[0].package, "com.busy");
        assert_eq!(snapshot.packages[1].package, "com.quiet");
    }

    #[test]
    fn a_flow_with_no_identity_is_not_attributed_to_anyone() {
        let map = map(8);
        let flow = map.open(
            IpTransport::Udp,
            "203.0.113.7".to_owned(),
            51_820,
            FlowRoute::new(FlowLane::Direct, "direct"),
            Vec::new(),
            None,
        );
        flow.add_up(64);

        let snapshot = map.snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        assert!(
            snapshot.packages.is_empty(),
            "inventing an owner would put someone else's traffic on an app"
        );
        // The lane total still moves: the bytes exist even when the owner does not.
        let vpn_and_direct: u64 = snapshot.lanes.iter().map(|lane| lane.bytes_up).sum::<u64>();
        assert_eq!(vpn_and_direct, 64);
    }

    /// The split-tunnel screen's whole reason to exist: one app, two lanes.
    #[test]
    fn one_app_on_two_lanes_is_reported_as_two_lanes_not_one_total() {
        let map = map(8);
        let tunnelled = open(&map, "a.example", "com.example", FlowLane::Vpn);
        tunnelled.add_up(100);
        let clear = open(&map, "b.example", "com.example", FlowLane::Direct);
        clear.add_down(70);

        let snapshot = map.snapshot();
        let package = &snapshot.packages[0];
        assert_eq!(package.bytes_up, 100);
        assert_eq!(package.bytes_down, 70);
        assert_eq!(
            package.lanes,
            vec![
                PackageLaneTraffic {
                    lane: FlowLane::Vpn,
                    bytes_up: 100,
                    bytes_down: 0,
                },
                PackageLaneTraffic {
                    lane: FlowLane::Direct,
                    bytes_up: 0,
                    bytes_down: 70,
                },
            ],
            "a single total cannot say which half of this app was protected"
        );

        let vpn = snapshot.lanes[FlowLane::Vpn.index()];
        assert_eq!(vpn.lane, FlowLane::Vpn);
        assert_eq!(vpn.bytes_up, 100);
        assert_eq!(vpn.flows_live, 1);
        let direct = snapshot.lanes[FlowLane::Direct.index()];
        assert_eq!(direct.bytes_down, 70);
    }

    #[test]
    fn the_route_a_flow_took_survives_a_later_failover() {
        let map = map(8);
        let flow = map.open(
            IpTransport::Tcp,
            "example.com".to_owned(),
            443,
            FlowRoute::new(FlowLane::Vpn, "vless")
                .with_outbound_id("default")
                .with_member("node-a"),
            vec!["com.example".to_owned()],
            None,
        );
        flow.add_up(10);

        let row = &map.snapshot().connections[0];
        assert_eq!(row.route.member.as_deref(), Some("node-a"));
        assert_eq!(row.route.outbound_id.as_deref(), Some("default"));
        assert_eq!(row.outbound, "vless");
    }

    #[test]
    fn the_change_stream_reports_opens_closes_and_what_it_lost() {
        let map = map(8);
        let flow = open(&map, "a.example", "com.example", FlowLane::Tor);
        let id = flow.id();
        flow.add_up(11);
        drop(flow);

        let drain = map.drain_events(16);
        assert_eq!(drain.dropped, 0);
        assert_eq!(drain.events.len(), 2);
        assert!(matches!(
            &drain.events[0],
            TrafficEvent::Opened { id: opened, route, .. }
                if *opened == id && route.lane == FlowLane::Tor
        ));
        assert_eq!(
            drain.events[1],
            TrafficEvent::Closed {
                id,
                bytes_up: 11,
                bytes_down: 0,
            }
        );
    }

    /// The data plane must never wait for a screen. A map nobody is draining
    /// keeps counting; only the change stream degrades, and it says so.
    #[test]
    fn a_consumer_that_stopped_reading_loses_updates_and_never_stalls_a_flow() {
        let map = Arc::new(TrafficMap::new(8));
        let mut flows = Vec::new();
        for index in 0..(DEFAULT_TRAFFIC_EVENT_CAPACITY + 64) {
            let flow = open(
                &map,
                &format!("{index}.example"),
                "com.example",
                FlowLane::Vpn,
            );
            flow.add_up(1);
            flows.push(flow);
        }

        let snapshot = map.snapshot();
        assert_eq!(
            snapshot.packages[0].bytes_up,
            (DEFAULT_TRAFFIC_EVENT_CAPACITY + 64) as u64,
            "accounting must be exact even when the change stream overflowed"
        );
        assert!(snapshot.dropped_events > 0);
        let drain = map.drain_events(usize::MAX);
        assert!(drain.dropped > 0, "a silent loss would read as quiet");
        assert_eq!(map.drain_events(4).dropped, 0);
    }

    #[test]
    fn a_revocation_reaches_the_flows_it_names_and_no_others() {
        let map = map(8);
        let blocked = open(&map, "a.example", "com.blocked", FlowLane::Vpn);
        let other = open(&map, "b.example", "com.other", FlowLane::Vpn);

        assert_eq!(
            map.revoke(&RevokeTarget::Package {
                package: "com.blocked".to_owned()
            }),
            1
        );
        assert!(blocked.flow().is_revoked());
        assert!(
            !other.flow().is_revoked(),
            "blocking one app must not touch another app's connections"
        );
    }

    #[test]
    fn revoking_a_target_with_no_flows_is_a_no_op_rather_than_an_error() {
        let map = map(8);
        let live = open(&map, "a.example", "com.example", FlowLane::Vpn);

        assert_eq!(
            map.revoke(&RevokeTarget::Package {
                package: "com.not.installed".to_owned()
            }),
            0,
            "a target nothing matches is a request that was already satisfied"
        );
        assert_eq!(
            map.revoke(&RevokeTarget::Lane {
                lane: FlowLane::Tor
            }),
            0
        );
        assert_eq!(map.revoke(&RevokeTarget::Flow { flow: 9_999 }), 0);
        assert!(
            !live.flow().is_revoked(),
            "and it must not have reached anything"
        );
    }

    #[test]
    fn every_target_selects_what_it_names() {
        let map = map(8);
        let vpn = map.open(
            IpTransport::Tcp,
            "a.example".to_owned(),
            443,
            FlowRoute::new(FlowLane::Vpn, "vless").with_outbound_id("primary"),
            vec!["com.first".to_owned()],
            Some(10_001),
        );
        let direct = map.open(
            IpTransport::Udp,
            "b.example".to_owned(),
            53,
            FlowRoute::new(FlowLane::Direct, "direct"),
            vec!["com.second".to_owned()],
            Some(10_002),
        );

        assert_eq!(map.revoke(&RevokeTarget::Uid { uid: 10_001 }), 1);
        assert!(vpn.flow().is_revoked() && !direct.flow().is_revoked());

        assert_eq!(
            map.revoke(&RevokeTarget::Outbound {
                outbound: "primary".to_owned()
            }),
            1,
            "already-revoked flows still match: revoking is idempotent, not consuming"
        );
        assert_eq!(
            map.revoke(&RevokeTarget::Outbound {
                outbound: "secondary".to_owned()
            }),
            0
        );

        assert_eq!(map.revoke(&RevokeTarget::Flow { flow: direct.id() }), 1);
        assert!(direct.flow().is_revoked());

        assert_eq!(map.revoke(&RevokeTarget::All {}), 2);
    }

    #[test]
    fn a_target_document_parses_as_written_and_refuses_anything_else() {
        assert_eq!(
            RevokeTarget::parse(r#"{"kind":"all"}"#),
            Ok(RevokeTarget::All {})
        );
        assert_eq!(
            RevokeTarget::parse(r#"{"kind":"lane","lane":"vpn"}"#),
            Ok(RevokeTarget::Lane {
                lane: FlowLane::Vpn
            })
        );
        assert_eq!(
            RevokeTarget::parse(r#"{"kind":"uid","uid":10123}"#),
            Ok(RevokeTarget::Uid { uid: 10_123 })
        );
        assert_eq!(
            RevokeTarget::parse(r#"{"kind":"package","package":"com.example.app"}"#),
            Ok(RevokeTarget::Package {
                package: "com.example.app".to_owned()
            })
        );
        assert_eq!(
            RevokeTarget::parse(r#"{"kind":"outbound","outbound":"default"}"#),
            Ok(RevokeTarget::Outbound {
                outbound: "default".to_owned()
            })
        );
        assert_eq!(
            RevokeTarget::parse(r#"{"kind":"flow","flow":42}"#),
            Ok(RevokeTarget::Flow { flow: 42 })
        );

        // Every one of these used to have a plausible "helpful" reading. None
        // of them get one: guessing wrong here either leaves an app talking
        // after the user blocked it, or cuts every connection on the device.
        for refused in [
            r#"{"kind":"everything"}"#,
            r#"{"kind":"package"}"#,
            r#"{"kind":"package","packge":"com.example"}"#,
            r#"{"kind":"lane","lane":"clearnet"}"#,
            r#"{"kind":"uid","uid":-1}"#,
            r#"{"kind":"all","package":"com.example"}"#,
            r#"{}"#,
            "",
            "null",
        ] {
            assert!(
                RevokeTarget::parse(refused).is_err(),
                "{refused} must not parse into a target"
            );
        }
    }

    #[test]
    fn a_packet_flow_is_counted_in_both_directions_and_released_on_close() {
        let map = map(8);
        let key = PacketKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            40_000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
            6,
        );
        let flow = map
            .open(
                IpTransport::Tcp,
                "93.184.216.34".to_owned(),
                443,
                FlowRoute::new(FlowLane::Vpn, "wireguard"),
                vec!["com.example".to_owned()],
                Some(10_123),
            )
            .bind_packet_flow(key);

        assert!(map.tunnel().count_up(&key, 120));
        assert!(map.tunnel().count_down(&key.reversed(), 340));

        let snapshot = map.snapshot();
        assert_eq!(snapshot.connections[0].bytes_up, 120);
        assert_eq!(snapshot.connections[0].bytes_down, 340);
        assert_eq!(snapshot.packages[0].package, "com.example");
        assert_eq!(snapshot.lanes[FlowLane::Vpn.index()].bytes_down, 340);

        drop(flow);
        assert!(
            map.tunnel().is_empty(),
            "a closed flow must not keep its 5-tuple bound"
        );
        assert!(!map.tunnel().count_up(&key, 1));
    }
}
