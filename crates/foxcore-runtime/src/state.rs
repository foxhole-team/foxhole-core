use super::*;

use std::fmt;
use std::io;
use std::sync::atomic::AtomicBool;
#[cfg(target_os = "android")]
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use foxcore_api::{FlowAttributor, LoopbackUpstream};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::OutboundRegistry;
use foxcore_tun::{ContinuityGate, FlowMetrics, FlowPolicyStore, TrafficMap};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub(crate) const STOP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the worker waits for its own blocking pool before abandoning it.
///
/// Dropping a Tokio runtime waits for every blocking task, including the ones
/// it starts *while* shutting down, and a platform call cannot be cancelled.
/// That wait has no ceiling, so the worker takes one here — inside `STOP_TIMEOUT`,
/// so it still gets to report that it finished.
pub(crate) const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// How long the worker waits, after its runtime is down, for the TUN device to
/// actually be dropped.
///
/// Inside `STOP_TIMEOUT` alongside the shutdown grace, and polled on a plain
/// thread so no stalled executor can extend it. Expiring is not fatal: it is
/// recorded, and the app reads it instead of being told a descriptor is free
/// when it is not.
pub(crate) const DEVICE_RELEASE_BUDGET: Duration = Duration::from_millis(750);
/// How long a join may take *after* the thread said it was done. Expected to be
/// microseconds; the budget exists so the answer is never "forever".
pub(crate) const JOIN_GRACE: Duration = Duration::from_millis(250);
pub(crate) const JOIN_POLL: Duration = Duration::from_millis(2);
pub(crate) const WORKER_RUNNING: u8 = 0;
pub(crate) const WORKER_STOPPING: u8 = 1;
pub(crate) const WORKER_STOPPED: u8 = 2;
/// Ceiling on the refusal message a reload leaves behind. It exists to be read
/// by a person in a log line, and a serde error on a large document carries a
/// tail nobody reads.
pub(crate) const MAX_POLICY_ERROR_CHARS: usize = 512;

#[cfg(target_os = "android")]
pub(crate) static ANDROID_WORKER_ACTIVE: AtomicU8 = AtomicU8::new(0);
/// Where the last stop of any generation in this process spent its budget.
///
/// Handle-free on purpose: the caller that most needs this has just been told
/// its stop timed out, and the handle it would have asked is the one it is
/// about to force-kill. See [`stop_diagnostics`].
pub fn last_stop_diagnostics_json() -> String {
    stop_diagnostics::json()
}

/// The LAN proxy status document for a handle that does not resolve.
///
/// Handle-free because there is nothing to ask: the engine is not running, so
/// the honest answer is the same well-formed "stopped" document a live engine
/// gives before anything is started. The app parses one shape either way, which
/// matters most in the case it hits first — the screen opening before the
/// tunnel is up.
pub fn lan_proxy_stopped_status_json() -> &'static str {
    LAN_PROXY_STOPPED
}

/// The named-loopback-inbound document for a handle that does not resolve.
///
/// Same reasoning as [`lan_proxy_stopped_status_json`]: an empty list is the
/// truthful answer for an engine that is not running, and it is the *same shape*
/// as a running one, so the app parses one document rather than a document and a
/// special case.
pub fn loopback_inbounds_empty_json() -> &'static str {
    LOOPBACK_INBOUNDS_EMPTY
}

pub struct CoreRuntime {
    pub(crate) generation: u64,
    /// The root runtime's executor. LAN listeners are spawned on it rather than
    /// on one of their own: a component that owned threads would be a second
    /// place the lifecycle lives.
    pub(crate) tokio_handle: tokio::runtime::Handle,
    pub(crate) cancel: CancellationToken,
    pub(crate) dialer: ProtectedDialer,
    /// The budget one outbound build gets. Kept on the handle because a lane
    /// that was not there at start is rebuilt through the same path, on the
    /// same terms, minutes later.
    pub(crate) handshake_timeout_ms: u64,
    pub(crate) outbounds: Arc<OutboundRegistry>,
    pub(crate) policy: Arc<FlowPolicyStore>,
    /// Whether this generation's primary outbound carries flows as IP packets.
    ///
    /// Kept on the handle because a reload can change DNS while it cannot
    /// change the outbound: `dns.mode='fake_ip'` is answerable only where a
    /// stack restores the name, and that is exactly what this generation does
    /// not have. Without it the refusal would only exist at start, and the
    /// documented reload example turns a working tunnel into a black hole.
    pub(crate) packet_tunnel: bool,
    pub(crate) attributor: FlowAttributor,
    pub(crate) attribution_available: bool,
    pub(crate) metrics: Arc<FlowMetrics>,
    /// Per-flow attribution for this generation. Held by the handle, not the
    /// engine thread, so the app can still read the last state after a stop.
    pub(crate) connections: Arc<TrafficMap>,
    /// Audit events produced by this generation, waiting to be drained by the
    /// app. Owned by the runtime handle rather than the engine thread so a
    /// consumer can still read what happened after the engine stopped.
    pub(crate) events: Arc<EventQueue>,
    pub(crate) last_error: Arc<Mutex<Option<String>>>,
    /// Why the most recent reload was refused, in words.
    ///
    /// Apart from `last_error`, which is about this generation *existing* — a
    /// TUN that would not open, a Tokio runtime that would not build — and is
    /// read by the start path. A refused reload leaves the generation exactly
    /// as it was, so folding the two would let a policy typo overwrite the
    /// reason the engine failed to come up.
    ///
    /// It exists because one refusal code cannot be acted on without it. Seven
    /// of the eight name the thing that was wrong — no Tor in this build, an
    /// outbound the generation does not have, a revision somebody else already
    /// moved — and the app can respond to each. `Invalid` (-1) means "the
    /// document does not parse or does not validate", which covers a missing
    /// comma and a field that was removed two releases ago, and those are not
    /// the same bug.
    pub(crate) last_policy_error: Mutex<Option<String>>,
    pub(crate) components: ComponentManager,
    /// Authenticated app-only CONNECT surface. Kept on the root handle so no
    /// listener, credential or lease can outlive this runtime generation.
    pub(crate) control_proxy: Mutex<Option<LanProxyHandle>>,
    /// The control proxy's credentials, as digests.
    ///
    /// Kept so a named inbound started later — through the JNI call, which the
    /// config validator never sees — cannot be given the same ones. It is the
    /// same listener on the same interface; sharing credentials with it is
    /// sharing its upstream.
    pub(crate) control_proxy_credentials: Mutex<Option<CredentialFingerprint>>,
    /// Named loopback CONNECT listeners, one per application the app routes
    /// separately.
    ///
    /// A `Vec` rather than a map because the order is what the app drew them in
    /// and the list is bounded by `MAX_LOOPBACK_INBOUNDS`; a lookup over sixteen
    /// entries costs nothing worth a second data structure. Beside
    /// `control_proxy` and for the same reason: the handles own the listeners,
    /// the credentials and the leases, so a generation that stops takes every
    /// one of them with it.
    pub(crate) loopback_inbounds: Mutex<Vec<LoopbackInboundSession>>,
    /// The user-facing LAN ingress, when the app has started one.
    ///
    /// Beside `control_proxy` and for the same reason: the handle owns the
    /// listeners, the credentials and the runtime leases, so a generation that
    /// stops takes them with it. It is also the only place the app's view of
    /// the feature comes from — before it existed the JNI layer could start
    /// nothing, and the app drew a saved toggle as if it were live state.
    pub(crate) lan_proxy: Mutex<Option<LanProxySession>>,
    /// Why the most recent LAN start or stop was refused, in words.
    ///
    /// Separate from `last_policy_error` for the same reason that one is
    /// separate from `last_error`: they answer different questions and folding
    /// them lets one feature's typo overwrite another's diagnosis. Read through
    /// the status document rather than a call of its own, because the app has
    /// to draw the state and the reason together or not at all.
    pub(crate) last_lan_error: Mutex<Option<String>>,
    pub(crate) availability: Arc<AtomicBool>,
    /// Which lanes are suspended waiting for the user, and the token that
    /// releases them.
    pub(crate) continuity: Arc<ContinuityGate>,
    /// The Android network the app last reported while a hold was up. Applied
    /// on confirmation, not before: `seamless_network_switch` off means every
    /// network change is an explicit reconnect, and binding sockets to the new
    /// network first would be the silent half of one.
    pub(crate) deferred_network: Mutex<Option<u64>>,
    /// Bumped once per network change this generation is allowed to act on.
    ///
    /// The proxy path needs nothing like it — rebinding the dialer changes the
    /// next socket, and there is a next socket. The L3 path has exactly one,
    /// created in `PacketTunnelRelay::connect`, and it is the relay's own task
    /// that has to replace it: swapping a socket out from under a live
    /// `select!` is not something a second owner can do, and rebinding from
    /// this thread would mean awaiting a platform call on the caller's thread.
    ///
    /// A counter rather than a flag so a change that lands while the relay is
    /// mid-rebind is not lost.
    pub(crate) network_epoch: watch::Sender<u64>,
    pub(crate) continuity_watch: Mutex<Option<ContinuityWatch>>,
    /// The same provider every component leases through. Held so share
    /// publication can take a Tor lease without reaching into the component
    /// manager, and without becoming a second place leases are issued.
    pub(crate) lease_provider: Arc<dyn RuntimeLeaseProvider>,
    /// The encrypted share vault, once the app has unlocked one.
    ///
    /// Owned here rather than beside the runtime so there is still exactly one
    /// root: the vault is reachable only through a live engine handle, and a
    /// stop drops it along with everything else this generation owned. It is
    /// attached rather than constructed at start because its key comes from the
    /// Android Keystore on a screen the user reaches later.
    pub(crate) share: Mutex<Option<Arc<ShareManager>>>,
    pub(crate) worker: RuntimeWorker,
}

/// A started LAN proxy, with the one fact its handle does not carry.
///
/// `LanProxyHandle` knows its binding, its addresses and its state; it does not
/// know which preset routed it there, because the component resolves the preset
/// into two routes at start and keeps the routes. The app has to show the
/// preset, so it is kept beside the handle rather than re-derived from a pair of
/// routes that no longer name it.
pub(crate) struct LanProxySession {
    pub(crate) preset: LanProxyPreset,
    pub(crate) handle: LanProxyHandle,
}

/// One running named loopback inbound.
///
/// The name and the upstream are kept beside the handle because neither is
/// recoverable from it: the handle knows its `ComponentId` and its bound
/// address, and the app needs to match "the inbound I asked for" to "the port
/// that answered".
pub(crate) struct LoopbackInboundSession {
    pub(crate) name: String,
    pub(crate) upstream: LoopbackUpstream,
    /// `None` for an anonymous listener: it has no credential to collide with,
    /// and its separation from the others is its port.
    pub(crate) credentials: Option<CredentialFingerprint>,
    pub(crate) handle: LanProxyHandle,
}

/// Enough of one loopback listener's credentials to tell whether another
/// listener would share them, and nothing more.
///
/// Digests rather than the values, because this outlives the call that supplied
/// them: the component holds the real credentials in a zeroizing buffer behind
/// its own lock, and a second plaintext copy on the runtime handle — reachable
/// from every control-plane call for the life of the generation — would be a
/// second place for a password to end up in a heap dump.
///
/// Two digests rather than one over the pair, because the rule is that *neither
/// half* may repeat: usernames are not secret, so a shared password under two
/// names is still one key to two upstreams.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredentialFingerprint {
    username: [u8; 32],
    password: [u8; 32],
}

impl CredentialFingerprint {
    pub(crate) fn new(username: &str, password: &str) -> Self {
        Self {
            username: digest(b"foxhole-loopback-username-v1", username.as_bytes()),
            password: digest(b"foxhole-loopback-password-v1", password.as_bytes()),
        }
    }

    /// Whether these two listeners would answer to any of the same credentials.
    ///
    /// A plain comparison, deliberately: both sides are values this process was
    /// handed by the application through its own configuration, checked before
    /// anything binds. The constant-time comparison that matters is the one in
    /// `foxcore-component`, against what a client on the socket presents.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.username == other.username || self.password == other.password
    }
}

impl fmt::Debug for CredentialFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialFingerprint([REDACTED])")
    }
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

/// Control-plane thread that watches for the interruptions nothing can report
/// directly, and enforces the confirmation deadline.
pub(crate) struct ContinuityWatch {
    pub(crate) thread: JoinHandle<()>,
}

/// What a confirmation attempt did. Mirrors [`ContinuityConfirm`] across the
/// FFI boundary, where an enum is an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmResult {
    Confirmed,
    NothingPending,
    StaleToken,
}

/// Why a policy reload was refused.
///
/// Typed because the app cannot act on a message. "This build has no Tor" is a
/// permanent property of the library the user installed — the screen should say
/// so and stop offering the switch — while "the policy is malformed" is a bug in
/// the app and "the revision moved" is a retry. All three used to arrive as the
/// same `IllegalStateException` with prose inside it (D11), so the app could
/// only ever show the same shrug.
///
/// The numbers are ABI: they cross the FFI boundary and must not be reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyRefusal {
    /// The document does not parse or does not validate.
    Invalid = 1,
    /// A route names an outbound this generation does not have.
    UnknownOutbound = 2,
    /// Tor was asked for and this engine has none — either the feature is not
    /// compiled in or the profile registered no Tor outbound.
    TorUnavailable = 3,
    I2pUnavailable = 4,
    /// Tor or I2P routing without fake-IP DNS, which would let a `.onion`
    /// lookup leave as ordinary port-53 traffic.
    OverlayRequiresFakeIp = 5,
    /// The policy routes by app, and this platform gave no way to attribute a
    /// flow to one.
    IdentityUnavailable = 6,
    /// `expected_revision` did not match: someone else reloaded first.
    RevisionConflict = 7,
    /// Fake-IP DNS asked of a generation whose primary outbound is an L3 packet
    /// tunnel. Nothing in that path restores a name from an address, so every
    /// clearnet flow would be sealed with a destination no peer routes.
    PacketTunnelRejectsFakeIp = 8,
    /// `dns.route='primary'` asked of a generation whose primary outbound is an
    /// L3 packet tunnel. There is no stream outbound to resolve through, only
    /// the clearnet placeholder standing in for the tunnel, so every intercepted
    /// lookup would leave beside the tunnel instead of inside it.
    PacketTunnelRejectsPrimaryDns = 9,
}

/// A refused reload: the code the app switches on, and the detail a log wants.
#[derive(Debug, Clone)]
pub struct PolicyError {
    pub refusal: PolicyRefusal,
    pub message: String,
}

impl PolicyError {
    pub(crate) fn new(refusal: PolicyRefusal, message: impl Into<String>) -> Self {
        Self {
            refusal,
            message: message.into(),
        }
    }

    pub fn code(&self) -> u8 {
        self.refusal as u8
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PolicyError {}

impl From<PolicyError> for io::Error {
    fn from(error: PolicyError) -> Self {
        let kind = match error.refusal {
            PolicyRefusal::RevisionConflict => io::ErrorKind::WouldBlock,
            PolicyRefusal::IdentityUnavailable => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, error.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopResult {
    Stopped,
    AlreadyStopped,
    TimedOut,
}

pub(crate) static QUARANTINED_WORKERS: OnceLock<Mutex<Vec<JoinHandle<()>>>> = OnceLock::new();
