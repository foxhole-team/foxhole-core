//! The LAN proxy component: SOCKS5 and HTTP CONNECT on the phone's Wi-Fi
//! address, for the other devices on that network.
//!
//! This is the component with the largest blast radius in the platform, because
//! unlike everything else here it *listens*. Four rules constrain it, and each
//! one exists because the obvious implementation gets it wrong:
//!
//! 1. **There is no anonymous access on the LAN.** The SOCKS greeting offers
//!    method `0x02` and never `0x00`, so a client cannot negotiate its way out
//!    of authentication; HTTP answers `407` until it presents credentials. A
//!    proxy that authenticates "when configured" is a proxy that is open
//!    whenever the configuration is wrong.
//!
//!    A *named loopback inbound* may be anonymous, and only it. It is bound to
//!    `127.0.0.1`, so its reachable set is the apps on this phone rather than
//!    the network — a different question, answered by the person holding the
//!    phone. The permission is structural, not a flag: the credentials are an
//!    `Option` on the loopback plan alone, and `start_with_binding` refuses a
//!    credential-less plan on a confirmed-LAN binding.
//! 2. **Listeners bind to one address, and it is never a wildcard.** `0.0.0.0`
//!    and `::` are refused outright, as is a cellular or unknown interface. A
//!    wildcard bind on a phone is reachable from the mobile network, which is
//!    not a LAN and not what anyone asked for.
//! 3. **A network the user has not confirmed is not bound at all.** The
//!    fingerprint covers the transport, the interface and the SSID hash;
//!    without an SSID hash — no location permission — no network is ever
//!    considered known, so the answer is to ask rather than to guess.
//! 4. **A network change closes the listeners and invalidates the
//!    credentials.** Not "eventually": the sockets are dropped and the shared
//!    credentials are taken, so a handshake already in flight fails too. The
//!    same credentials on a different network are the definition of a proxy
//!    following the user somewhere they did not intend.
//!
//! Where accepted traffic goes is a preset — VPN, Tor, or Mixed — and it is
//! fail-closed in the same way every other route in this core is: if the
//! required upstream is not available the session is refused. There is no
//! representable state in which LAN traffic leaves directly.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use foxcore_relay::{BufferPool, copy_bidirectional_pooled};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    ComponentError, ComponentEventKind, ComponentId, Inner, LeasePurpose, RuntimeKind,
    RuntimeLease, lock, push_event,
};

/// Concurrent LAN sessions. A phone is not a proxy server; this is enough for a
/// laptop and a tablet and low enough that a hostile client on the same Wi-Fi
/// cannot exhaust the device's descriptors.
const MAX_SESSIONS: usize = 64;
/// Largest HTTP request head accepted before the client is dropped.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Largest SOCKS domain name, which is what the wire format allows anyway.
const MAX_DOMAIN_BYTES: usize = 255;
const RELAY_BUFFER: usize = 32 * 1024;
/// Relay buffers for the LAN sessions, taken from a pool rather than allocated
/// per connection.
///
/// `tokio::io::copy_bidirectional_with_sizes` owns its buffers, so every
/// accepted session used to allocate and zero 64 KiB it would overwrite before
/// reading — measured at 11.4 % of cycles on the proxy profile, on a path whose
/// connections are short by nature.
///
/// Sixteen idle buffers, not `2 * MAX_SESSIONS`. The cap bounds what stays
/// resident *after* a burst, not how many sessions may run: a 65th buffer is
/// still allocated on demand and simply not kept. Sixty-four sessions are what
/// the proxy refuses to exceed, but the shape it is built for is a laptop and a
/// tablet, so eight concurrent sessions' worth — 512 KiB — is the size of cache
/// that pays for itself. Anything larger is memory a phone holds for a peak that
/// happens once.
static RELAY_POOL: BufferPool = BufferPool::new(RELAY_BUFFER, 16);
/// Bytes taken from the client in one read while collecting a request head.
const HEAD_READ_BUFFER: usize = 1024;

/// Total time a client has to finish its handshake, from the first byte to a
/// target this proxy can dial.
///
/// A session permit is taken at `accept` and held until the session ends, so
/// without a deadline a client that connects and says nothing holds one for the
/// life of the process. Sixty-four of those — `MAX_SESSIONS` — and the proxy
/// serves nobody, which any device on the same Wi-Fi could arrange, and on a
/// build with `runtime.control_proxy` any app on the phone could arrange
/// through loopback. Rule 1 in this module's header claims the opposite.
///
/// Fifteen seconds is the same budget the share server gives a request head,
/// and it is the budget under test as well.
///
/// It used to be two seconds under `cfg(test)`, on the reasoning that exactly
/// one test has to outlast the deadline and a suite that spent fifteen seconds
/// proving it would not be run. The reasoning was right about that test and
/// wrong about everything else in the file: the same constant is the deadline
/// for *every* handshake, so on a machine that was busy compiling the rest of
/// the workspace, ten unrelated socket tests lost their handshake to it and
/// failed as "early eof" — a flake that only ever appears in the full run,
/// which is the one run that gates a release.
///
/// The one test that needs a short deadline now asks for one
/// ([`start_with_handshake_timeout`]); nothing else pays for it. A paused clock
/// is still not an option here: these tests drive real loopback sockets, and
/// tokio advances a paused clock whenever the runtime is idle, which is most of
/// a socket read.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Time allowed to reach a VPN or direct upstream once the client has named a
/// target.
const UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// A fresh managed-bridge Tor route can legitimately spend longer building its
/// first usable circuit. It remains bounded because the dial holds a session
/// slot until it succeeds, fails, or the listener is stopped.
const TOR_UPSTREAM_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(75);
/// Time allowed to hand the client its reply, before the relay starts.
///
/// These writes are a handful of bytes and normally complete into an empty
/// socket buffer. The deadline exists so that "the slot is bounded until the
/// relay begins" holds without an exception for a peer that stops reading.
const REPLY_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const SOCKS_VERSION: u8 = 5;
const SOCKS_AUTH_USERPASS: u8 = 2;
const SOCKS_AUTH_NONE: u8 = 0;
const SOCKS_AUTH_UNACCEPTABLE: u8 = 0xff;
const SOCKS_AUTH_SUBNEGOTIATION: u8 = 1;
const SOCKS_CMD_CONNECT: u8 = 1;
const SOCKS_REPLY_OK: u8 = 0;
const SOCKS_REPLY_REFUSED: u8 = 5;
const SOCKS_REPLY_NOT_ALLOWED: u8 = 2;
const SOCKS_REPLY_CMD_UNSUPPORTED: u8 = 7;
const SOCKS_REPLY_ADDRESS_UNSUPPORTED: u8 = 8;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;

/// How the device is attached to the network the listeners would bind to.
///
/// `Cellular` and `Unknown` exist so they can be refused by name: a binding
/// that simply lacked a transport would be indistinguishable from one nobody
/// filled in, and the fail-closed answer to "I do not know" has to be no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanTransport {
    Wifi,
    Ethernet,
    Cellular,
    Unknown,
}

/// The exact network the listeners are pinned to.
///
/// Every field is required because every field is part of the answer to "is
/// this still the network the user agreed to". The Android side fills it from
/// the active `Network`; nothing here is inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkBinding {
    pub network_handle: u64,
    pub interface_name: String,
    pub local_address: IpAddr,
    /// SHA-256 of the SSID. The hash rather than the name: this is stored,
    /// compared and journalled, and none of those need the network's name.
    ///
    /// `None` when the platform would not tell us — no location permission.
    /// A binding without one can never be recognised as previously confirmed.
    pub ssid_hash: Option<[u8; 32]>,
    pub transport: LanTransport,
    /// The runtime generation this binding was observed in.
    pub generation: u64,
}

impl NetworkBinding {
    /// What "the same network" means for confirmation purposes.
    ///
    /// Deliberately not the network handle: Android mints a new one every time
    /// Wi-Fi reconnects, so a handle-keyed confirmation would ask the user
    /// again on every reconnect and train them to click yes. Deliberately not
    /// the address either, since DHCP moves it.
    pub fn fingerprint(&self) -> Option<[u8; 32]> {
        let ssid = self.ssid_hash?;
        let mut hasher = Sha256::new();
        hasher.update(b"foxhole-lan-network-v1");
        hasher.update([transport_tag(self.transport)]);
        hasher.update((self.interface_name.len() as u64).to_be_bytes());
        hasher.update(self.interface_name.as_bytes());
        hasher.update(ssid);
        Some(hasher.finalize().into())
    }

    /// Whether this binding may carry listeners at all.
    ///
    /// Refusing here rather than at bind time is the point: a wildcard address
    /// binds perfectly well, and the failure would be invisible.
    fn validate(&self) -> Result<(), ComponentError> {
        if !matches!(self.transport, LanTransport::Wifi | LanTransport::Ethernet) {
            return Err(ComponentError::LanBindingRefused);
        }
        if self.interface_name.is_empty()
            || self.interface_name.len() > 32
            || !self.interface_name.is_ascii()
            || self
                .interface_name
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ComponentError::LanBindingRefused);
        }
        // Belt and braces beside the transport check: a mislabelled binding on
        // a modem interface must still not bind.
        if is_cellular_interface(&self.interface_name) {
            return Err(ComponentError::LanBindingRefused);
        }
        // The whole reason this check exists. A wildcard on a phone is
        // reachable from the mobile network, which is not a LAN.
        if self.local_address.is_unspecified() || self.local_address.is_multicast() {
            return Err(ComponentError::LanBindingRefused);
        }
        Ok(())
    }
}

fn transport_tag(transport: LanTransport) -> u8 {
    match transport {
        LanTransport::Wifi => 1,
        LanTransport::Ethernet => 2,
        LanTransport::Cellular => 3,
        LanTransport::Unknown => 4,
    }
}

/// Interface names Android uses for the modem. Not exhaustive across vendors,
/// which is why it is a second line of defence and not the first one.
fn is_cellular_interface(name: &str) -> bool {
    const PREFIXES: [&str; 6] = ["rmnet", "ccmni", "pdp_ip", "seth_", "qmimux", "wwan"];
    let lowered = name.to_ascii_lowercase();
    PREFIXES.iter().any(|prefix| lowered.starts_with(prefix))
}

/// Where traffic accepted on the LAN goes.
///
/// `Direct` is not a variant, and that is the design: a LAN proxy whose
/// upstream could fall back to the open network would carry another device's
/// traffic in the clear while presenting itself as the phone's tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanProxyPreset {
    Vpn,
    Tor,
    /// SOCKS through the VPN, HTTP through Tor. The split people actually
    /// want: a browser on Tor, everything else on the faster tunnel.
    Mixed,
}

/// The upstream one accepted session was routed to.
///
/// `Direct` is reachable from a *named loopback inbound* and from nowhere else.
/// [`LanProxyPreset`] has no mapping that produces it — `socks_route` and
/// `http_route` are total functions over three variants and neither mentions it
/// — so a LAN listener still cannot carry another device's traffic in the clear
/// no matter what the configuration says. `a_lan_preset_can_never_route_direct`
/// is the test that keeps that true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanRoute {
    Vpn,
    Tor,
    /// Out through the protected dialer, around the TUN. Only ever the result of
    /// a configuration that named it for one process-local listener.
    Direct,
}

impl LanRoute {
    pub fn name(self) -> &'static str {
        match self {
            Self::Vpn => "vpn",
            Self::Tor => "tor",
            Self::Direct => "direct",
        }
    }
}

fn upstream_connect_timeout(route: LanRoute) -> std::time::Duration {
    match route {
        LanRoute::Tor => TOR_UPSTREAM_CONNECT_TIMEOUT,
        LanRoute::Vpn | LanRoute::Direct => UPSTREAM_CONNECT_TIMEOUT,
    }
}

impl LanProxyPreset {
    fn socks_route(self) -> LanRoute {
        match self {
            Self::Tor => LanRoute::Tor,
            Self::Vpn | Self::Mixed => LanRoute::Vpn,
        }
    }

    fn http_route(self) -> LanRoute {
        match self {
            Self::Vpn => LanRoute::Vpn,
            Self::Tor | Self::Mixed => LanRoute::Tor,
        }
    }

    fn runtimes(self) -> &'static [RuntimeKind] {
        match self {
            Self::Vpn => &[RuntimeKind::Vpn],
            Self::Tor => &[RuntimeKind::Tor],
            Self::Mixed => &[RuntimeKind::Vpn, RuntimeKind::Tor],
        }
    }
}

/// A byte stream the LAN session relays to.
pub trait LanIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> LanIo for T {}

/// What an upstream returns. Boxed rather than an `async fn` because the trait
/// is used behind `dyn`: the root runtime supplies the one real implementation
/// and tests supply their own.
pub type LanConnect = std::pin::Pin<Box<dyn Future<Output = io::Result<Box<dyn LanIo>>> + Send>>;

/// How a LAN session reaches the internet.
///
/// A trait rather than a direct dependency on the outbound registry: this crate
/// is the component control plane and has no business owning protocol code, and
/// the root runtime is the only thing entitled to hand out a tunnel.
pub trait LanUpstream: Send + Sync + 'static {
    /// Must fail rather than choose a different route. A `Vpn` request that
    /// cannot be served is an error, never a direct connection.
    fn connect(&self, route: LanRoute, host: String, port: u16) -> LanConnect;
}

/// The lifecycle stage-2 asks the component to expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanProxyState {
    Stopped,
    CheckingPermission,
    ResolvingNetwork,
    AcquiringComponents,
    BindingListeners,
    Ready,
    Degraded,
    NetworkLost,
    Stopping,
    Failed,
}

/// Mandatory credentials. There is no variant of this without a password.
pub struct LanCredentials {
    username: String,
    password: Zeroizing<Vec<u8>>,
}

impl LanCredentials {
    /// Both fields are required and bounded. An empty password is refused here
    /// rather than accepted and compared, because a proxy whose password is the
    /// empty string is an open proxy with extra steps.
    pub fn new(username: impl Into<String>, password: impl Into<Vec<u8>>) -> Option<Self> {
        let username = username.into();
        let password = Zeroizing::new(password.into());
        let usable = |value: &[u8]| !value.is_empty() && value.len() <= 255;
        (usable(username.as_bytes()) && usable(&password) && username.is_ascii())
            .then_some(Self { username, password })
    }

    fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        // Constant time, and both halves are always compared: an early return
        // on a wrong username leaks which half was wrong.
        let user = self.username.as_bytes().ct_eq(username);
        let secret = self.password.as_slice().ct_eq(password);
        (user & secret).into()
    }
}

impl std::fmt::Debug for LanCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LanCredentials")
            .field("username", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

pub struct LanProxyConfig {
    pub id: ComponentId,
    pub preset: LanProxyPreset,
    /// Zero means "do not offer this protocol at all", which is how a caller
    /// runs SOCKS without HTTP or the other way round.
    pub socks_port: u16,
    pub http_port: u16,
    pub credentials: LanCredentials,
}

/// One named, authenticated, loopback-only HTTP CONNECT listener.
///
/// The difference from [`LanProxyConfig`] is not cosmetic. A LAN proxy is one
/// surface with a preset; these are *many* surfaces, each the whole route for
/// one application, so the route is named per inbound rather than derived, the
/// session cap is per inbound rather than shared, and there is no SOCKS half —
/// the only client is an Android `Proxy`, which speaks CONNECT.
///
/// No address and no interface, exactly as [`start_loopback`] takes none: the
/// component binds `127.0.0.1` itself and a caller cannot widen it.
pub struct LoopbackInbound {
    pub id: ComponentId,
    /// `0` binds an ephemeral port; read it back from
    /// [`LanProxyHandle::http_address`].
    pub http_port: u16,
    /// `None` raises the listener without authentication. Allowed here and
    /// nowhere else: this one listens on loopback, so "anonymous" means the
    /// apps already on this device, not the network around it.
    pub credentials: Option<LanCredentials>,
    pub route: LanRoute,
    /// Concurrent sessions. Clamped into `1..=MAX_SESSIONS` here rather than
    /// trusted: a zero would be a listener that accepts and refuses everything,
    /// which looks exactly like a broken upstream from the app's side.
    pub max_sessions: usize,
}

/// Shared with every in-flight handshake.
///
/// Taking the credentials out of here is what "invalidated" means: a session
/// that is mid-authentication when the network changes fails, rather than
/// completing against a password that is no longer valid for the network it is
/// on.
struct AuthState {
    credentials: std::sync::Mutex<Option<LanCredentials>>,
    generation: AtomicU64,
    /// Fixed when the listener is built and never written again.
    ///
    /// Deliberately not expressed as "credentials is None": that state already
    /// means *invalidated*, and folding the two together would turn the network
    /// change that takes the credentials away into a listener that suddenly
    /// accepts everyone.
    anonymous: bool,
}

impl AuthState {
    /// Whether this listener was built to ask for nothing. The generation is
    /// still checked: an anonymous inbound dies with its generation like any
    /// other.
    fn allows_anonymous(&self, generation: u64) -> bool {
        self.anonymous && self.generation.load(Ordering::Acquire) == generation
    }

    fn verify(&self, generation: u64, username: &[u8], password: &[u8]) -> bool {
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        lock(&self.credentials)
            .as_ref()
            .is_some_and(|credentials| credentials.matches(username, password))
    }

    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        *lock(&self.credentials) = None;
    }
}

struct SessionContext {
    components: Arc<Inner>,
    id: ComponentId,
    auth: Arc<AuthState>,
    generation: u64,
    upstream: Arc<dyn LanUpstream>,
    route: LanRoute,
    slots: Arc<Semaphore>,
    /// Fields rather than constants so a test can prove the deadline releases
    /// the slot without spending the production budget in wall clock.
    handshake_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
}

impl SessionContext {
    fn report(&self, kind: ComponentEventKind) {
        let mut state = lock(&self.components.state);
        push_event(&mut state, &self.id, LeasePurpose::LanProxy, kind);
    }
}

/// A running LAN proxy. Dropping it closes the listeners and releases the
/// runtime leases.
pub struct LanProxyHandle {
    components: Arc<Inner>,
    id: ComponentId,
    cancel: CancellationToken,
    auth: Arc<AuthState>,
    state: std::sync::Mutex<LanProxyState>,
    binding: NetworkBinding,
    socks_address: Option<SocketAddr>,
    http_address: Option<SocketAddr>,
    /// Held for exactly as long as the listeners are: releasing them is what
    /// lets the shared VPN/Tor runtime stop once nothing needs it.
    _leases: Vec<Arc<dyn RuntimeLease>>,
}

impl LanProxyHandle {
    pub fn state(&self) -> LanProxyState {
        *lock(&self.state)
    }

    pub fn binding(&self) -> &NetworkBinding {
        &self.binding
    }

    /// Where a device on this network reaches the proxies. The app has to show
    /// these; they are not derivable from the binding alone because either
    /// protocol may be switched off.
    pub fn socks_address(&self) -> Option<SocketAddr> {
        self.socks_address
    }

    pub fn http_address(&self) -> Option<SocketAddr> {
        self.http_address
    }

    /// The network moved. Close everything and invalidate the credentials.
    ///
    /// Not a reconfiguration: the caller must confirm the new network and start
    /// again. Rebinding silently is how a proxy ends up serving a coffee shop's
    /// Wi-Fi with the credentials the user set up at home.
    pub fn network_changed(&self) {
        self.cancel.cancel();
        self.auth.invalidate();
        *lock(&self.state) = LanProxyState::NetworkLost;
        let mut state = lock(&self.components.state);
        push_event(
            &mut state,
            &self.id,
            LeasePurpose::LanProxy,
            ComponentEventKind::LanProxyNetworkLost,
        );
    }

    pub fn stop(&self) {
        self.cancel.cancel();
        self.auth.invalidate();
        let already = std::mem::replace(&mut *lock(&self.state), LanProxyState::Stopped);
        if already != LanProxyState::Stopped {
            let mut state = lock(&self.components.state);
            // The identity is freed here and nowhere else. `start` refuses a
            // duplicate id, so a proxy that stopped without giving its name back
            // could never be started again for the life of the runtime — the
            // second start failed identically to a bad password or an
            // unconfirmed network, which is what made it look like anything but
            // a leak of state. Stopping is the one moment the name is certainly
            // free, and `Drop` comes through here too, so there is no path that
            // ends a proxy without releasing it.
            state.lan_proxies.remove(&self.id);
            push_event(
                &mut state,
                &self.id,
                LeasePurpose::LanProxy,
                ComponentEventKind::LanProxyStopped,
            );
        }
    }
}

impl Drop for LanProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What one call to [`start_with_binding`] is asked to bind.
///
/// The listeners carry a route each rather than a preset, because the two
/// callers name them differently: a LAN proxy derives both from
/// [`LanProxyPreset`], and a named loopback inbound *is* one route. Folding them
/// into one shape is what lets the authentication, the handshake deadline, the
/// session cap and the fail-closed refusal be one piece of code — writing a
/// second CONNECT server for the loopback inbounds would be a second place for
/// "authenticates when configured" to appear.
struct InboundPlan {
    id: ComponentId,
    /// `None` means the protocol is not offered at all. `Some(0)` means bind an
    /// ephemeral port — never the same thing, which is why this is an `Option`
    /// and not a bare port with a magic zero.
    socks: Option<(u16, LanRoute)>,
    http: Option<(u16, LanRoute)>,
    /// `None` is an anonymous listener, which `start_with_binding` accepts only
    /// on an internal loopback binding.
    credentials: Option<LanCredentials>,
    runtimes: Vec<RuntimeKind>,
    max_sessions: usize,
    /// Carried per plan rather than read from the constant at the point of use,
    /// so the one test that has to outlast the deadline can shorten it without
    /// shortening it for every other handshake in the process.
    handshake_timeout: std::time::Duration,
}

/// Bind and start. Called through `ComponentManager::start_lan_proxy`.
pub(crate) fn start(
    components: Arc<Inner>,
    handle: tokio::runtime::Handle,
    config: LanProxyConfig,
    binding: NetworkBinding,
    upstream: Arc<dyn LanUpstream>,
) -> Result<LanProxyHandle, ComponentError> {
    start_with_binding(
        components,
        handle,
        lan_plan(config, HANDSHAKE_TIMEOUT),
        binding,
        upstream,
        BindingAuthorization::ConfirmedLan,
    )
}

/// [`start`] with a deadline of the caller's choosing.
///
/// Exists for one test — the one that proves a silent client's session slot is
/// given back — because that test has to sit out the deadline in wall clock.
/// Every other handshake in the process keeps [`HANDSHAKE_TIMEOUT`].
#[cfg(test)]
pub(crate) fn start_with_handshake_timeout(
    components: Arc<Inner>,
    handle: tokio::runtime::Handle,
    config: LanProxyConfig,
    binding: NetworkBinding,
    upstream: Arc<dyn LanUpstream>,
    handshake_timeout: std::time::Duration,
) -> Result<LanProxyHandle, ComponentError> {
    start_with_binding(
        components,
        handle,
        lan_plan(config, handshake_timeout),
        binding,
        upstream,
        BindingAuthorization::ConfirmedLan,
    )
}

/// Bind the root runtime's private control surface.
///
/// Neither the address nor the interface comes from configuration. Keeping
/// their construction in this crate makes a wildcard or LAN bind
/// unrepresentable at the public component boundary.
pub(crate) fn start_loopback(
    components: Arc<Inner>,
    handle: tokio::runtime::Handle,
    config: LanProxyConfig,
    generation: u64,
    upstream: Arc<dyn LanUpstream>,
) -> Result<LanProxyHandle, ComponentError> {
    start_with_binding(
        components,
        handle,
        lan_plan(config, HANDSHAKE_TIMEOUT),
        loopback_binding(generation),
        upstream,
        BindingAuthorization::InternalLoopback,
    )
}

/// Bind one named loopback inbound. Called through
/// `ComponentManager::start_loopback_inbound`.
///
/// Same binding, same authorization and same server as the control proxy; only
/// the route, the cap and the absence of a SOCKS half differ.
pub(crate) fn start_loopback_inbound(
    components: Arc<Inner>,
    handle: tokio::runtime::Handle,
    config: LoopbackInbound,
    generation: u64,
    upstream: Arc<dyn LanUpstream>,
) -> Result<LanProxyHandle, ComponentError> {
    let runtimes = match config.route {
        LanRoute::Vpn => vec![RuntimeKind::Vpn],
        LanRoute::Tor => vec![RuntimeKind::Tor],
        // A direct inbound still dies with the generation that authorised it —
        // that is exactly what `RuntimeKind::Root` is for. Taking no lease at
        // all would leave a listener alive across a stop.
        LanRoute::Direct => vec![RuntimeKind::Root],
    };
    let plan = InboundPlan {
        id: config.id,
        socks: None,
        http: Some((config.http_port, config.route)),
        credentials: config.credentials,
        runtimes,
        max_sessions: config.max_sessions.clamp(1, MAX_SESSIONS),
        handshake_timeout: HANDSHAKE_TIMEOUT,
    };
    start_with_binding(
        components,
        handle,
        plan,
        loopback_binding(generation),
        upstream,
        BindingAuthorization::InternalLoopback,
    )
}

fn lan_plan(config: LanProxyConfig, handshake_timeout: std::time::Duration) -> InboundPlan {
    // A zero port on the LAN surface has always meant "do not offer this
    // protocol", and it keeps meaning that: an ephemeral LAN port is a number
    // the user would have to read off a screen and type into another device.
    InboundPlan {
        id: config.id,
        socks: (config.socks_port != 0).then_some((config.socks_port, config.preset.socks_route())),
        http: (config.http_port != 0).then_some((config.http_port, config.preset.http_route())),
        credentials: Some(config.credentials),
        runtimes: config.preset.runtimes().to_vec(),
        max_sessions: MAX_SESSIONS,
        handshake_timeout,
    }
}

fn loopback_binding(generation: u64) -> NetworkBinding {
    NetworkBinding {
        network_handle: 0,
        interface_name: "lo".into(),
        local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ssid_hash: None,
        transport: LanTransport::Ethernet,
        generation: generation.max(1),
    }
}

#[derive(Clone, Copy)]
enum BindingAuthorization {
    ConfirmedLan,
    InternalLoopback,
}

fn start_with_binding(
    components: Arc<Inner>,
    handle: tokio::runtime::Handle,
    config: InboundPlan,
    binding: NetworkBinding,
    upstream: Arc<dyn LanUpstream>,
    authorization: BindingAuthorization,
) -> Result<LanProxyHandle, ComponentError> {
    binding.validate()?;
    if config.socks.is_none() && config.http.is_none() {
        return Err(ComponentError::LanBindingRefused);
    }
    // The one place anonymity is decided, and it is decided by the binding
    // rather than by the caller's intent: a plan without credentials is a
    // loopback plan or it is nothing.
    if config.credentials.is_none()
        && !matches!(authorization, BindingAuthorization::InternalLoopback)
    {
        return Err(ComponentError::LanBindingRefused);
    }
    match authorization {
        BindingAuthorization::ConfirmedLan => {
            // CHECKING_PERMISSION / RESOLVING_NETWORK: a network we cannot
            // fingerprint is never "the one from last time", so the answer is
            // to ask.
            let fingerprint = binding
                .fingerprint()
                .ok_or(ComponentError::LanNetworkNotConfirmed)?;
            if !lock(&components.state)
                .confirmed_networks
                .contains(&fingerprint)
            {
                return Err(ComponentError::LanNetworkNotConfirmed);
            }
        }
        BindingAuthorization::InternalLoopback => {
            if binding.network_handle != 0
                || binding.interface_name != "lo"
                || binding.local_address != IpAddr::V4(Ipv4Addr::LOCALHOST)
                || binding.ssid_hash.is_some()
                || binding.transport != LanTransport::Ethernet
            {
                return Err(ComponentError::LanBindingRefused);
            }
        }
    }
    {
        let state = lock(&components.state);
        if state.lan_proxies.contains(&config.id) {
            return Err(ComponentError::AlreadyExists);
        }
    }

    // ACQUIRING_COMPONENTS, before anything is bound: a listener that is up
    // while its upstream is not would answer a client and then refuse it.
    let mut leases = Vec::new();
    for runtime in &config.runtimes {
        leases.push(components.provider.acquire(*runtime)?);
    }

    // BINDING_LISTENERS. Bound synchronously so a failure is reported to the
    // caller instead of disappearing into a task.
    let socks = bind(&binding, config.socks.map(|(port, _)| port))?;
    let http = bind(&binding, config.http.map(|(port, _)| port))?;
    let socks_address = socks
        .as_ref()
        .and_then(|listener| listener.local_addr().ok());
    let http_address = http
        .as_ref()
        .and_then(|listener| listener.local_addr().ok());

    let cancel = CancellationToken::new();
    let anonymous = config.credentials.is_none();
    let auth = Arc::new(AuthState {
        credentials: std::sync::Mutex::new(config.credentials),
        generation: AtomicU64::new(binding.generation.max(1)),
        anonymous,
    });
    let generation = auth.generation.load(Ordering::Acquire);
    let slots = Arc::new(Semaphore::new(config.max_sessions.clamp(1, MAX_SESSIONS)));

    for (listener, protocol, route) in [
        (socks, Protocol::Socks, config.socks.map(|(_, route)| route)),
        (http, Protocol::Http, config.http.map(|(_, route)| route)),
    ] {
        let (Some(listener), Some(route)) = (listener, route) else {
            continue;
        };
        let context = SessionContext {
            components: components.clone(),
            id: config.id.clone(),
            auth: auth.clone(),
            generation,
            upstream: upstream.clone(),
            route,
            slots: slots.clone(),
            handshake_timeout: config.handshake_timeout,
            connect_timeout: upstream_connect_timeout(route),
        };
        let cancel = cancel.clone();
        handle.spawn(async move {
            let listener = match TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            accept_loop(listener, protocol, Arc::new(context), cancel).await;
        });
    }

    {
        let mut state = lock(&components.state);
        state.lan_proxies.insert(config.id.clone());
        push_event(
            &mut state,
            &config.id,
            LeasePurpose::LanProxy,
            ComponentEventKind::LanProxyReady,
        );
    }
    Ok(LanProxyHandle {
        components,
        id: config.id,
        cancel,
        auth,
        state: std::sync::Mutex::new(LanProxyState::Ready),
        binding,
        socks_address,
        http_address,
        _leases: leases,
    })
}

/// `None` is "not offered"; `Some(0)` is "let the kernel choose".
///
/// Those were the same value before named inbounds existed, and they cannot be:
/// a named inbound has exactly one listener, so "not offered" is not a state it
/// has, while an ephemeral port is the only sane default on a phone with no port
/// registry.
fn bind(
    binding: &NetworkBinding,
    port: Option<u16>,
) -> Result<Option<StdTcpListener>, ComponentError> {
    let Some(port) = port else {
        return Ok(None);
    };
    // Exactly one address. Never a wildcard, and never chosen here — it is the
    // address the platform reported for the confirmed network.
    let listener = StdTcpListener::bind(SocketAddr::new(binding.local_address, port))
        .map_err(|_| ComponentError::LanBindFailed)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| ComponentError::LanBindFailed)?;
    Ok(Some(listener))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Socks,
    Http,
}

/// How long the accept loop waits after an error before trying again.
///
/// Short enough that a transient error costs a caller nothing they would
/// notice, long enough that a permanent one cannot occupy a worker thread.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

async fn accept_loop(
    listener: TcpListener,
    protocol: Protocol,
    context: Arc<SessionContext>,
    cancel: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _peer)) = accepted else {
            // A transient accept error must not take the listener down; a fatal
            // one repeats and the cancellation path is the way out.
            //
            // The sleep is what makes that sentence true. A persistent error —
            // `EMFILE` is the realistic one, and this listener can reach it —
            // returns immediately every time, and `continue` has no await point
            // of its own, so the loop spun at the speed of the syscall. This
            // runtime has two worker threads by default: one spinning task is
            // half the executor, and everything else on it, including the
            // barrier a stop waits on, stops being polled promptly. The device
            // symptom was a stop that missed its whole three-second budget with
            // the engine loop never returning.
            tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            continue;
        };
        let Ok(permit) = context.slots.clone().try_acquire_owned() else {
            // Refusing is the bounded answer. A device on the same Wi-Fi must
            // not be able to spend the phone's descriptors.
            continue;
        };
        let context = context.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = serve(stream, protocol, context) => {}
            }
        });
    }
}

async fn serve(mut stream: TcpStream, protocol: Protocol, context: Arc<SessionContext>) {
    // Every read in the handshake is under one deadline, and that deadline is
    // what bounds the session permit this task holds. Without it the handshakes
    // waited on `read_exact` with no way out but the client's goodwill.
    let target = tokio::time::timeout(context.handshake_timeout, async {
        match protocol {
            Protocol::Socks => socks_handshake(&mut stream, &context)
                .await
                .map(|(host, port)| (host, port, Vec::new())),
            Protocol::Http => http_handshake(&mut stream, &context).await,
        }
    })
    .await
    .ok()
    .flatten();
    let Some((host, port, pipelined)) = target else {
        return;
    };

    // Fail-closed: an upstream that cannot be reached is refused, never
    // replaced. This is the single line that keeps a LAN proxy from carrying
    // somebody else's traffic in the clear. Bounded rather than awaited
    // outright: a dial that never returns holds the slot exactly as a silent
    // client does, and an upstream is entitled to hang — a Tor circuit that
    // cannot be built produces no error of its own.
    let upstream = tokio::time::timeout(
        context.connect_timeout,
        context.upstream.connect(context.route, host, port),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let Some(mut upstream) = upstream else {
        context.report(ComponentEventKind::LanProxyRefused);
        let _ = tokio::time::timeout(REPLY_WRITE_TIMEOUT, async {
            match protocol {
                Protocol::Socks => socks_reply(&mut stream, SOCKS_REPLY_REFUSED).await,
                Protocol::Http => {
                    stream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await
                }
            }
        })
        .await;
        return;
    };

    let established = tokio::time::timeout(REPLY_WRITE_TIMEOUT, async {
        match protocol {
            Protocol::Socks => socks_reply(&mut stream, SOCKS_REPLY_OK).await,
            Protocol::Http => {
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
            }
        }
    })
    .await;
    if !matches!(established, Ok(Ok(()))) {
        return;
    }
    // Whatever the client pipelined behind its CONNECT head. The buffered head
    // read may have taken those bytes off the socket with it, and a tunnel that
    // silently dropped its first payload would stall with both sides waiting.
    if !pipelined.is_empty() {
        let forwarded =
            tokio::time::timeout(REPLY_WRITE_TIMEOUT, upstream.write_all(&pipelined)).await;
        if !matches!(forwarded, Ok(Ok(()))) {
            return;
        }
    }
    let _ = copy_bidirectional_pooled(&RELAY_POOL, &mut stream, &mut upstream).await;
}

/// The SOCKS5 greeting, authentication and CONNECT request.
///
/// The greeting is where "no anonymous access" is actually enforced: `0x02` is
/// the only method ever selected, so a client offering only `0x00` is told
/// `0xff` and disconnected rather than served.
async fn socks_handshake(
    stream: &mut TcpStream,
    context: &SessionContext,
) -> Option<(String, u16)> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await.ok()?;
    if header[0] != SOCKS_VERSION || header[1] == 0 {
        return None;
    }
    let mut methods = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut methods).await.ok()?;
    if !methods.contains(&SOCKS_AUTH_USERPASS) {
        // Deliberately not falling back to `SOCKS_AUTH_NONE` even when the
        // client offers it — that constant exists here only to be refused.
        let _ = methods.contains(&SOCKS_AUTH_NONE);
        let _ = stream
            .write_all(&[SOCKS_VERSION, SOCKS_AUTH_UNACCEPTABLE])
            .await;
        context.report(ComponentEventKind::LanProxyAuthFailed);
        return None;
    }
    stream
        .write_all(&[SOCKS_VERSION, SOCKS_AUTH_USERPASS])
        .await
        .ok()?;

    let mut auth_header = [0_u8; 2];
    stream.read_exact(&mut auth_header).await.ok()?;
    if auth_header[0] != SOCKS_AUTH_SUBNEGOTIATION {
        return None;
    }
    let mut username = vec![0_u8; usize::from(auth_header[1])];
    stream.read_exact(&mut username).await.ok()?;
    let mut password_len = [0_u8; 1];
    stream.read_exact(&mut password_len).await.ok()?;
    let mut password = Zeroizing::new(vec![0_u8; usize::from(password_len[0])]);
    stream.read_exact(&mut password).await.ok()?;
    if !context
        .auth
        .verify(context.generation, &username, &password)
    {
        let _ = stream.write_all(&[SOCKS_AUTH_SUBNEGOTIATION, 1]).await;
        context.report(ComponentEventKind::LanProxyAuthFailed);
        return None;
    }
    stream
        .write_all(&[SOCKS_AUTH_SUBNEGOTIATION, 0])
        .await
        .ok()?;

    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await.ok()?;
    if request[0] != SOCKS_VERSION {
        return None;
    }
    if request[1] != SOCKS_CMD_CONNECT {
        // BIND and UDP ASSOCIATE would each need a listener or a datagram
        // relay of their own; refusing is honest and keeps the surface at one
        // command.
        let _ = socks_reply(stream, SOCKS_REPLY_CMD_UNSUPPORTED).await;
        return None;
    }
    let host = match request[3] {
        SOCKS_ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await.ok()?;
            IpAddr::from(octets).to_string()
        }
        SOCKS_ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await.ok()?;
            IpAddr::from(octets).to_string()
        }
        SOCKS_ATYP_DOMAIN => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await.ok()?;
            if length[0] == 0 || usize::from(length[0]) > MAX_DOMAIN_BYTES {
                let _ = socks_reply(stream, SOCKS_REPLY_ADDRESS_UNSUPPORTED).await;
                return None;
            }
            let mut domain = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut domain).await.ok()?;
            let domain = String::from_utf8(domain).ok()?;
            if !is_sane_host(&domain) {
                let _ = socks_reply(stream, SOCKS_REPLY_NOT_ALLOWED).await;
                return None;
            }
            domain
        }
        _ => {
            let _ = socks_reply(stream, SOCKS_REPLY_ADDRESS_UNSUPPORTED).await;
            return None;
        }
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await.ok()?;
    Some((host, u16::from_be_bytes(port)))
}

async fn socks_reply(stream: &mut TcpStream, reply: u8) -> io::Result<()> {
    // The bound address is reported as 0.0.0.0:0 on purpose: the client does
    // not need the phone's upstream address, and telling it would leak which
    // interface the tunnel is on.
    stream
        .write_all(&[SOCKS_VERSION, reply, 0, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

/// HTTP `CONNECT` with mandatory `Proxy-Authorization`.
///
/// Only `CONNECT`. Plain HTTP proxying would mean rewriting requests and
/// forwarding cleartext on the user's behalf, which is a much larger surface
/// for a feature whose point is to tunnel another device.
async fn http_handshake(
    stream: &mut TcpStream,
    context: &SessionContext,
) -> Option<(String, u16, Vec<u8>)> {
    let (head, pipelined) = read_head(stream).await?;
    let head = String::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let mut request = lines.next()?.split(' ');
    if !request.next()?.eq_ignore_ascii_case("CONNECT") {
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await;
        return None;
    }
    let authority = request.next()?.to_owned();

    let mut credentials = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("proxy-authorization") {
            credentials = decode_basic(value.trim());
        }
    }
    let authorized = context.auth.allows_anonymous(context.generation)
        || credentials.is_some_and(|(username, password)| {
            context
                .auth
                .verify(context.generation, username.as_bytes(), &password)
        });
    if !authorized {
        context.report(ComponentEventKind::LanProxyAuthFailed);
        let _ = stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"foxhole\"\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await;
        return None;
    }

    let (host, port) = authority.rsplit_once(':')?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if !is_sane_host(&host) {
        return None;
    }
    Some((host, port.parse().ok()?, pipelined))
}

/// The request head, plus whatever arrived behind it.
///
/// Read in buffers rather than a byte at a time. The byte-at-a-time form cost
/// one `read_exact` — one syscall, one poll of this task — per byte, so a full
/// 8 KiB head was 8192 of them on a phone that is also carrying the tunnel.
///
/// The trailing bytes are returned rather than discarded because a buffered
/// read can pull the client's first tunnelled bytes off the socket along with
/// the head, and the caller has to put them back on the wire.
async fn read_head<R: AsyncRead + Unpin>(reader: &mut R) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::new();
    let mut buffer = [0_u8; HEAD_READ_BUFFER];
    loop {
        // The terminator can straddle two reads, so the scan starts three bytes
        // before what this read appends.
        let scanned = head.len().saturating_sub(3);
        let budget = MAX_HEAD_BYTES.checked_sub(head.len()).filter(|l| *l > 0)?;
        // Taken before the slice: `buffer.len()` inside the index expression is
        // an immutable borrow while the mutable one is already open.
        let take = budget.min(buffer.len());
        let count = reader.read(&mut buffer[..take]).await.ok()?;
        if count == 0 {
            return None;
        }
        head.extend_from_slice(&buffer[..count]);
        if let Some(offset) = head[scanned..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            let end = scanned + offset;
            let pipelined = head[end + 4..].to_vec();
            head.truncate(end);
            return Some((head, pipelined));
        }
    }
}

fn decode_basic(value: &str) -> Option<(String, Zeroizing<Vec<u8>>)> {
    use base64::Engine as _;

    let encoded = value
        .strip_prefix("Basic ")
        .or(value.strip_prefix("basic "))?;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?,
    );
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let username = String::from_utf8(decoded[..separator].to_vec()).ok()?;
    Some((username, Zeroizing::new(decoded[separator + 1..].to_vec())))
}

/// Cheap sanity, not resolution. The upstream validates properly; this only
/// stops obviously malformed authority strings from becoming a dial.
fn is_sane_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_DOMAIN_BYTES
        && host.is_ascii()
        && !host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn wifi(address: IpAddr) -> NetworkBinding {
        NetworkBinding {
            network_handle: 7,
            interface_name: "wlan0".into(),
            local_address: address,
            ssid_hash: Some([9_u8; 32]),
            transport: LanTransport::Wifi,
            generation: 1,
        }
    }

    #[test]
    fn a_wildcard_bind_is_refused_because_it_would_reach_the_mobile_network() {
        for address in [
            IpAddr::from(Ipv4Addr::UNSPECIFIED),
            IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED),
        ] {
            assert_eq!(
                wifi(address).validate(),
                Err(ComponentError::LanBindingRefused)
            );
        }
        assert!(
            wifi(IpAddr::from(Ipv4Addr::new(192, 168, 1, 20)))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn cellular_and_unknown_networks_are_refused_by_transport_and_by_interface() {
        let address = IpAddr::from(Ipv4Addr::new(10, 20, 30, 40));
        for transport in [LanTransport::Cellular, LanTransport::Unknown] {
            let mut binding = wifi(address);
            binding.transport = transport;
            assert_eq!(
                binding.validate(),
                Err(ComponentError::LanBindingRefused),
                "{transport:?}"
            );
        }
        // Mislabelled as Wi-Fi, but the interface says otherwise. Two checks
        // because the vendor list cannot be complete and the transport can be
        // wrong.
        let mut mislabelled = wifi(address);
        mislabelled.interface_name = "rmnet_data0".into();
        assert_eq!(
            mislabelled.validate(),
            Err(ComponentError::LanBindingRefused)
        );
    }

    #[test]
    fn a_network_with_no_ssid_can_never_be_recognised() {
        let mut binding = wifi(IpAddr::from(Ipv4Addr::new(192, 168, 1, 20)));
        assert!(binding.fingerprint().is_some());

        binding.ssid_hash = None;
        assert!(
            binding.fingerprint().is_none(),
            "without an SSID there is nothing to recognise, so the answer must be to ask"
        );
    }

    #[test]
    fn the_fingerprint_survives_a_reconnect_but_not_a_different_network() {
        let base = wifi(IpAddr::from(Ipv4Addr::new(192, 168, 1, 20)));

        // Android mints a new handle and DHCP moves the address on every
        // reconnect; asking the user again each time trains them to click yes.
        let mut reconnected = base.clone();
        reconnected.network_handle = 99;
        reconnected.local_address = IpAddr::from(Ipv4Addr::new(192, 168, 1, 57));
        reconnected.generation = 4;
        assert_eq!(base.fingerprint(), reconnected.fingerprint());

        let mut elsewhere = base.clone();
        elsewhere.ssid_hash = Some([1_u8; 32]);
        assert_ne!(base.fingerprint(), elsewhere.fingerprint());
    }

    #[test]
    fn credentials_are_mandatory_and_compared_whole() {
        assert!(LanCredentials::new("user", b"".to_vec()).is_none());
        assert!(LanCredentials::new("", b"secret".to_vec()).is_none());

        let credentials = LanCredentials::new("user", b"secret".to_vec()).unwrap();
        assert!(credentials.matches(b"user", b"secret"));
        assert!(!credentials.matches(b"user", b"wrong"));
        assert!(!credentials.matches(b"other", b"secret"));
        assert!(
            !format!("{credentials:?}").contains("secret"),
            "a password must not survive a debug rendering"
        );
    }

    #[test]
    fn invalidating_credentials_fails_every_generation_including_the_current_one() {
        let auth = AuthState {
            credentials: std::sync::Mutex::new(LanCredentials::new("user", b"secret".to_vec())),
            generation: AtomicU64::new(1),
            anonymous: false,
        };
        assert!(auth.verify(1, b"user", b"secret"));

        auth.invalidate();

        assert!(
            !auth.verify(1, b"user", b"secret"),
            "a handshake already in flight must not complete against a network that changed"
        );
        assert!(!auth.verify(2, b"user", b"secret"));
    }

    #[test]
    fn presets_never_resolve_to_a_direct_route() {
        assert_eq!(LanProxyPreset::Vpn.socks_route(), LanRoute::Vpn);
        assert_eq!(LanProxyPreset::Vpn.http_route(), LanRoute::Vpn);
        assert_eq!(LanProxyPreset::Tor.socks_route(), LanRoute::Tor);
        assert_eq!(LanProxyPreset::Tor.http_route(), LanRoute::Tor);
        // Mixed is the split people actually want: browser on Tor, the rest on
        // the faster tunnel.
        assert_eq!(LanProxyPreset::Mixed.socks_route(), LanRoute::Vpn);
        assert_eq!(LanProxyPreset::Mixed.http_route(), LanRoute::Tor);
        assert_eq!(
            LanProxyPreset::Mixed.runtimes(),
            &[RuntimeKind::Vpn, RuntimeKind::Tor]
        );
        // Named for the first time here, because `LanRoute::Direct` now exists:
        // named loopback inbounds can reach it and a LAN binding must not. The
        // equalities above already imply this, but only to a reader who knows
        // the whole variant list — and the variant list is the thing that grew.
        for preset in [
            LanProxyPreset::Vpn,
            LanProxyPreset::Tor,
            LanProxyPreset::Mixed,
        ] {
            assert_ne!(preset.socks_route(), LanRoute::Direct, "{preset:?}");
            assert_ne!(preset.http_route(), LanRoute::Direct, "{preset:?}");
            assert!(
                !preset.runtimes().contains(&RuntimeKind::Root),
                "{preset:?} must hold a privacy runtime, not the bare root lease"
            );
        }
    }

    #[test]
    fn only_tor_receives_the_extended_upstream_connect_budget() {
        assert_eq!(
            upstream_connect_timeout(LanRoute::Vpn),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            upstream_connect_timeout(LanRoute::Direct),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            upstream_connect_timeout(LanRoute::Tor),
            std::time::Duration::from_secs(75)
        );
    }

    #[test]
    fn basic_credentials_are_decoded_only_from_a_basic_challenge() {
        use base64::Engine as _;

        let encoded = base64::engine::general_purpose::STANDARD.encode("user:secret");
        let (username, password) = decode_basic(&format!("Basic {encoded}")).unwrap();
        assert_eq!(username, "user");
        assert_eq!(password.as_slice(), b"secret");

        assert!(decode_basic(&format!("Bearer {encoded}")).is_none());
        assert!(decode_basic("Basic !!!not-base64!!!").is_none());
        // No colon: not a credential, and must not become username-with-empty-
        // password.
        let malformed = base64::engine::general_purpose::STANDARD.encode("nocolon");
        assert!(decode_basic(&format!("Basic {malformed}")).is_none());
    }

    #[test]
    fn a_host_that_could_smuggle_a_request_line_is_refused() {
        assert!(is_sane_host("example.com"));
        assert!(!is_sane_host(""));
        assert!(!is_sane_host("exa mple.com"));
        assert!(!is_sane_host("example.com\r\nHost: evil"));
    }

    // ---- end-to-end over real listeners ----

    use std::sync::Mutex as StdMutex;

    use crate::{ComponentManager, RuntimeLeaseProvider};

    struct AlwaysAvailable;
    impl RuntimeLease for AlwaysAvailable {
        fn is_available(&self) -> bool {
            true
        }
    }

    /// Hands out leases for whatever the preset asks, and records what it was
    /// asked for so a test can prove the LAN proxy takes them through the same
    /// provider as everything else.
    struct RecordingProvider {
        acquired: StdMutex<Vec<RuntimeKind>>,
        unavailable: Option<RuntimeKind>,
    }

    impl RuntimeLeaseProvider for RecordingProvider {
        fn acquire(&self, runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError> {
            if self.unavailable == Some(runtime) {
                return Err(ComponentError::RuntimeUnavailable);
            }
            self.acquired.lock().unwrap().push(runtime);
            Ok(Arc::new(AlwaysAvailable))
        }
    }

    /// An upstream that either connects to a local echo server or refuses.
    struct TestUpstream {
        echo: Option<SocketAddr>,
        seen: Arc<StdMutex<Vec<(LanRoute, String, u16)>>>,
    }

    impl LanUpstream for TestUpstream {
        fn connect(&self, route: LanRoute, host: String, port: u16) -> LanConnect {
            self.seen.lock().unwrap().push((route, host, port));
            let echo = self.echo;
            Box::pin(async move {
                let echo = echo.ok_or_else(|| io::Error::other("no upstream"))?;
                let stream = TcpStream::connect(echo).await?;
                Ok(Box::new(stream) as Box<dyn LanIo>)
            })
        }
    }

    struct HangingUpstream {
        started: Arc<tokio::sync::Notify>,
    }

    impl LanUpstream for HangingUpstream {
        fn connect(&self, _route: LanRoute, _host: String, _port: u16) -> LanConnect {
            let started = self.started.clone();
            Box::pin(async move {
                started.notify_one();
                std::future::pending::<io::Result<Box<dyn LanIo>>>().await
            })
        }
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        address
    }

    fn free_port() -> u16 {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn loopback_binding() -> NetworkBinding {
        NetworkBinding {
            network_handle: 1,
            interface_name: "wlan0".into(),
            local_address: IpAddr::from(Ipv4Addr::LOCALHOST),
            ssid_hash: Some([3_u8; 32]),
            transport: LanTransport::Wifi,
            generation: 1,
        }
    }

    struct Harness {
        manager: ComponentManager,
        handle: LanProxyHandle,
        seen: Arc<StdMutex<Vec<(LanRoute, String, u16)>>>,
        acquired: Arc<RecordingProvider>,
    }

    async fn harness(preset: LanProxyPreset, echo: Option<SocketAddr>) -> Harness {
        harness_with_handshake_timeout(preset, echo, HANDSHAKE_TIMEOUT).await
    }

    /// The deadline the whole suite used to share, now asked for by name.
    ///
    /// Only `silent_sessions_give_their_slots_back_instead_of_locking_the_listener`
    /// wants it short: it has to outlast the deadline in wall clock, and it is
    /// the only test that does.
    const SHORT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    async fn harness_with_handshake_timeout(
        preset: LanProxyPreset,
        echo: Option<SocketAddr>,
        handshake_timeout: std::time::Duration,
    ) -> Harness {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider.clone());
        let binding = loopback_binding();
        manager.confirm_lan_network(&binding).unwrap();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let handle = manager
            .start_lan_proxy_with_handshake_timeout(
                tokio::runtime::Handle::current(),
                LanProxyConfig {
                    id: ComponentId::new("lan:test").unwrap(),
                    preset,
                    socks_port: free_port(),
                    http_port: free_port(),
                    credentials: LanCredentials::new("user", b"secret".to_vec()).unwrap(),
                },
                binding,
                Arc::new(TestUpstream {
                    echo,
                    seen: seen.clone(),
                }),
                handshake_timeout,
            )
            .expect("a confirmed Wi-Fi binding must start");
        Harness {
            manager,
            handle,
            seen,
            acquired: provider,
        }
    }

    async fn socks_authenticate(stream: &mut TcpStream, password: &[u8]) -> [u8; 2] {
        stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_USERPASS])
            .await
            .unwrap();
        let mut selected = [0_u8; 2];
        stream.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [SOCKS_VERSION, SOCKS_AUTH_USERPASS]);

        let mut request = vec![SOCKS_AUTH_SUBNEGOTIATION, 4];
        request.extend_from_slice(b"user");
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        stream.write_all(&request).await.unwrap();
        let mut verdict = [0_u8; 2];
        stream.read_exact(&mut verdict).await.unwrap();
        verdict
    }

    async fn socks_connect(stream: &mut TcpStream, host: &str, port: u16) -> [u8; 10] {
        let mut request = vec![SOCKS_VERSION, SOCKS_CMD_CONNECT, 0, SOCKS_ATYP_DOMAIN];
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    }

    /// The rule the whole component exists to keep. A client that offers only
    /// anonymous SOCKS must be told no — a proxy that falls back to `0x00`
    /// because the client asked is an open proxy on somebody's Wi-Fi.
    #[tokio::test]
    async fn a_socks_client_offering_only_anonymous_access_is_refused() {
        let harness = harness(LanProxyPreset::Vpn, None).await;
        let mut stream = TcpStream::connect(harness.handle.socks_address().unwrap())
            .await
            .unwrap();

        stream
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_NONE])
            .await
            .unwrap();

        let mut selected = [0_u8; 2];
        stream.read_exact(&mut selected).await.unwrap();
        assert_eq!(
            selected,
            [SOCKS_VERSION, SOCKS_AUTH_UNACCEPTABLE],
            "anonymous access must not be negotiable"
        );
        assert!(harness.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_never_reaches_an_upstream() {
        let harness = harness(LanProxyPreset::Vpn, None).await;
        let mut stream = TcpStream::connect(harness.handle.socks_address().unwrap())
            .await
            .unwrap();

        assert_eq!(
            socks_authenticate(&mut stream, b"wrong").await,
            [SOCKS_AUTH_SUBNEGOTIATION, 1]
        );
        assert!(harness.seen.lock().unwrap().is_empty());
    }

    /// A device on the same Wi-Fi opens every session slot and then says
    /// nothing. Before the handshake had a deadline those permits were held for
    /// the life of the runtime: the listener stayed up, answered no one, and
    /// neither the snapshot nor the event queue said why — the exact state the
    /// module header claims is prevented. The laptop this feature exists for
    /// could not connect again until the tunnel was restarted.
    #[tokio::test]
    async fn silent_sessions_give_their_slots_back_instead_of_locking_the_listener() {
        let echo = echo_server().await;
        let harness = harness_with_handshake_timeout(
            LanProxyPreset::Vpn,
            Some(echo),
            SHORT_HANDSHAKE_TIMEOUT,
        )
        .await;
        let address = harness.handle.socks_address().unwrap();

        let mut idle = Vec::new();
        for _ in 0..MAX_SESSIONS {
            idle.push(TcpStream::connect(address).await.unwrap());
        }

        // Every one of them is now sitting in the handshake, saying nothing.
        tokio::time::sleep(SHORT_HANDSHAKE_TIMEOUT + std::time::Duration::from_millis(500)).await;

        let mut stream = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            socks_authenticate(&mut stream, b"secret").await,
            [SOCKS_AUTH_SUBNEGOTIATION, 0],
            "the listener still owes every slot to a client that never spoke"
        );
        let reply = socks_connect(&mut stream, "example.com", 443).await;
        assert_eq!(reply[1], SOCKS_REPLY_OK);

        // The silent connections stay open until the end of the scope: the
        // point is that the listener recovered while they were still there.
        assert_eq!(idle.len(), MAX_SESSIONS);
    }

    #[tokio::test]
    async fn an_authenticated_socks_session_reaches_the_preset_upstream_and_relays() {
        let echo = echo_server().await;
        let harness = harness(LanProxyPreset::Vpn, Some(echo)).await;
        let mut stream = TcpStream::connect(harness.handle.socks_address().unwrap())
            .await
            .unwrap();

        assert_eq!(
            socks_authenticate(&mut stream, b"secret").await,
            [SOCKS_AUTH_SUBNEGOTIATION, 0]
        );
        let reply = socks_connect(&mut stream, "example.com", 443).await;
        assert_eq!(reply[1], SOCKS_REPLY_OK);

        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        assert_eq!(
            *harness.seen.lock().unwrap(),
            vec![(LanRoute::Vpn, "example.com".to_owned(), 443)]
        );
        // Same provider as every other component; no second supervisor.
        assert_eq!(
            *harness.acquired.acquired.lock().unwrap(),
            vec![RuntimeKind::Vpn]
        );
    }

    #[tokio::test]
    async fn an_http_client_gets_407_without_credentials_and_200_with_them() {
        let echo = echo_server().await;
        let harness = harness(LanProxyPreset::Vpn, Some(echo)).await;
        let address = harness.handle.http_address().unwrap();

        let mut anonymous = TcpStream::connect(address).await.unwrap();
        anonymous
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        anonymous.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response).to_string();
        assert!(response.starts_with("HTTP/1.1 407"), "{response}");
        assert!(response.contains("Proxy-Authenticate: Basic"), "{response}");
        assert!(harness.seen.lock().unwrap().is_empty());

        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("user:secret");
        let mut authorized = TcpStream::connect(address).await.unwrap();
        authorized
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut established = vec![0_u8; 39];
        authorized.read_exact(&mut established).await.unwrap();
        assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        authorized.write_all(b"pong").await.unwrap();
        let mut echoed = [0_u8; 4];
        authorized.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pong");
    }

    #[tokio::test]
    async fn internal_control_proxy_is_fixed_to_authenticated_loopback() {
        let echo = echo_server().await;
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider.clone());
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let handle = manager
            .start_loopback_proxy(
                tokio::runtime::Handle::current(),
                LanProxyConfig {
                    id: ComponentId::new("runtime:control-proxy").unwrap(),
                    preset: LanProxyPreset::Vpn,
                    socks_port: 0,
                    http_port: free_port(),
                    credentials: LanCredentials::new("user", b"secret".to_vec()).unwrap(),
                },
                7,
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: seen.clone(),
                }),
            )
            .expect("loopback control proxy must not need LAN confirmation");
        let address = handle.http_address().expect("HTTP listener");
        assert_eq!(address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(handle.binding().interface_name, "lo");
        assert_eq!(handle.binding().network_handle, 0);
        assert_eq!(
            provider.acquired.lock().unwrap().as_slice(),
            &[RuntimeKind::Vpn]
        );

        let mut anonymous = TcpStream::connect(address).await.unwrap();
        anonymous
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        anonymous.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 407"));
        assert!(seen.lock().unwrap().is_empty());

        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("user:secret");
        let mut authorized = TcpStream::connect(address).await.unwrap();
        authorized
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut established = vec![0_u8; 39];
        authorized.read_exact(&mut established).await.unwrap();
        assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[(LanRoute::Vpn, "example.com".into(), 443)]
        );
    }

    /// Mixed is not cosmetic: the two listeners must actually resolve to
    /// different upstreams, and both leases must have been taken up front.
    #[tokio::test]
    async fn the_mixed_preset_sends_socks_to_the_vpn_and_http_to_tor() {
        let echo = echo_server().await;
        let harness = harness(LanProxyPreset::Mixed, Some(echo)).await;

        let mut socks = TcpStream::connect(harness.handle.socks_address().unwrap())
            .await
            .unwrap();
        socks_authenticate(&mut socks, b"secret").await;
        socks_connect(&mut socks, "socks.example", 443).await;

        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("user:secret");
        let mut http = TcpStream::connect(harness.handle.http_address().unwrap())
            .await
            .unwrap();
        http.write_all(
            format!(
                "CONNECT http.example:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut established = vec![0_u8; 39];
        http.read_exact(&mut established).await.unwrap();

        let seen = harness.seen.lock().unwrap().clone();
        assert!(
            seen.contains(&(LanRoute::Vpn, "socks.example".to_owned(), 443)),
            "{seen:?}"
        );
        assert!(
            seen.contains(&(LanRoute::Tor, "http.example".to_owned(), 443)),
            "{seen:?}"
        );
        let mut acquired = harness.acquired.acquired.lock().unwrap().clone();
        acquired.sort_by_key(|kind| format!("{kind:?}"));
        assert_eq!(acquired, vec![RuntimeKind::Tor, RuntimeKind::Vpn]);
    }

    /// Fail-closed: an upstream that cannot be reached is refused. There is no
    /// state in which a LAN client's traffic leaves this device directly.
    #[tokio::test]
    async fn an_unreachable_upstream_refuses_the_session_rather_than_replacing_it() {
        let harness = harness(LanProxyPreset::Vpn, None).await;
        let mut stream = TcpStream::connect(harness.handle.socks_address().unwrap())
            .await
            .unwrap();

        socks_authenticate(&mut stream, b"secret").await;
        let reply = socks_connect(&mut stream, "example.com", 443).await;

        assert_eq!(
            reply[1], SOCKS_REPLY_REFUSED,
            "the only honest answer is no; a direct connection here is the leak"
        );
        let drain = harness
            .manager
            .drain_events(&ComponentId::new("lan:test").unwrap(), 16);
        assert!(
            drain
                .events
                .iter()
                .any(|event| event.kind == ComponentEventKind::LanProxyRefused),
            "{drain:?}"
        );
    }

    #[tokio::test]
    async fn stop_cancels_a_pending_tor_connect_without_waiting_for_its_budget() {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider);
        let started = Arc::new(tokio::sync::Notify::new());
        let handle = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                LoopbackInbound {
                    id: ComponentId::new("runtime:tor-stop").unwrap(),
                    http_port: 0,
                    credentials: Some(LanCredentials::new("user", b"secret".to_vec()).unwrap()),
                    route: LanRoute::Tor,
                    max_sessions: 1,
                },
                1,
                Arc::new(HangingUpstream {
                    started: started.clone(),
                }),
            )
            .unwrap();

        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("user:secret");
        let mut stream = TcpStream::connect(handle.http_address().unwrap())
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
            .await
            .expect("the Tor dial must have started");

        handle.stop();

        let mut byte = [0_u8; 1];
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "stop must drop the pending session and its permit: {closed:?}"
        );
    }

    #[tokio::test]
    async fn an_unconfirmed_network_never_binds_a_listener() {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider.clone());
        let socks_port = free_port();

        let refused = manager.start_lan_proxy(
            tokio::runtime::Handle::current(),
            LanProxyConfig {
                id: ComponentId::new("lan:test").unwrap(),
                preset: LanProxyPreset::Vpn,
                socks_port,
                http_port: 0,
                credentials: LanCredentials::new("user", b"secret".to_vec()).unwrap(),
            },
            loopback_binding(),
            Arc::new(TestUpstream {
                echo: None,
                seen: Arc::new(StdMutex::new(Vec::new())),
            }),
        );

        assert_eq!(refused.err(), Some(ComponentError::LanNetworkNotConfirmed));
        assert!(
            provider.acquired.lock().unwrap().is_empty(),
            "an unconfirmed network must not even reach the lease provider"
        );
        // Nothing is listening, so the port is still free.
        assert!(
            StdTcpListener::bind(SocketAddr::new(
                IpAddr::from(Ipv4Addr::LOCALHOST),
                socks_port
            ))
            .is_ok()
        );
    }

    /// The sequence a single start cannot show: run, stop, run again under the
    /// same identity.
    ///
    /// `start` refuses a duplicate id and `stop` used to leave the id in the
    /// registry, so the second start failed for the rest of the runtime's life.
    /// It failed as a zero handle — the same answer a wrong password and an
    /// unconfirmed network give — which is exactly why every test that started
    /// one proxy and stopped there stayed green, and why the device run read as
    /// a network problem.
    #[tokio::test]
    async fn a_proxy_that_stopped_can_be_started_again_under_the_same_identity() {
        let echo = echo_server().await;
        let harness = harness(LanProxyPreset::Vpn, Some(echo)).await;

        harness.handle.stop();
        assert_eq!(harness.handle.state(), LanProxyState::Stopped);

        let restarted = harness
            .manager
            .start_lan_proxy(
                tokio::runtime::Handle::current(),
                LanProxyConfig {
                    id: ComponentId::new("lan:test").unwrap(),
                    preset: LanProxyPreset::Vpn,
                    socks_port: free_port(),
                    http_port: free_port(),
                    credentials: LanCredentials::new("user", b"secret".to_vec()).unwrap(),
                },
                loopback_binding(),
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: harness.seen.clone(),
                }),
            )
            .expect("a stopped proxy must be startable again under its own id");
        assert_eq!(restarted.state(), LanProxyState::Ready);

        // Started is not the same as serving. The second proxy has to carry a
        // session, not merely occupy the name the first one gave back.
        let mut stream = TcpStream::connect(restarted.socks_address().unwrap())
            .await
            .unwrap();
        assert_eq!(
            socks_authenticate(&mut stream, b"secret").await,
            [SOCKS_AUTH_SUBNEGOTIATION, 0]
        );
        assert_eq!(
            socks_connect(&mut stream, "example.com", 80).await[1],
            0,
            "the restarted proxy must complete a CONNECT, not just bind"
        );

        // The first handle is still alive and will be dropped at the end of this
        // test. Its drop must not take the running proxy's identity with it:
        // releasing is guarded by the stopped-once transition precisely so a
        // stale handle cannot evict its successor.
        drop(harness);
        assert_eq!(restarted.state(), LanProxyState::Ready);
    }

    /// The transition stage-2 cares about: the network moved, so the listeners
    /// close and the credentials stop working — including for a client that was
    /// already connected and authenticated.
    #[tokio::test]
    async fn a_network_change_closes_the_listeners_and_invalidates_the_credentials() {
        let echo = echo_server().await;
        let harness = harness(LanProxyPreset::Vpn, Some(echo)).await;
        let socks_address = harness.handle.socks_address().unwrap();

        // A client mid-handshake: greeted and about to authenticate.
        let mut early = TcpStream::connect(socks_address).await.unwrap();
        early
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_USERPASS])
            .await
            .unwrap();
        let mut selected = [0_u8; 2];
        early.read_exact(&mut selected).await.unwrap();

        harness.handle.network_changed();
        assert_eq!(harness.handle.state(), LanProxyState::NetworkLost);

        // The credentials are gone, so the in-flight handshake cannot complete
        // even though it started on the old network.
        let mut request = vec![SOCKS_AUTH_SUBNEGOTIATION, 4];
        request.extend_from_slice(b"user");
        request.push(6);
        request.extend_from_slice(b"secret");
        let _ = early.write_all(&request).await;
        let mut verdict = [0_u8; 2];
        let refused = match early.read_exact(&mut verdict).await {
            Ok(_) => verdict == [SOCKS_AUTH_SUBNEGOTIATION, 1],
            // The listener task was cancelled outright, which is at least as
            // closed as a refusal.
            Err(_) => true,
        };
        assert!(
            refused,
            "credentials must not survive the network they were bound to"
        );

        // And nothing new is accepted: the port is free again.
        let rebound = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if StdTcpListener::bind(socks_address).is_ok() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(rebound.is_ok(), "the listener must actually be closed");

        let drain = harness
            .manager
            .drain_events(&ComponentId::new("lan:test").unwrap(), 16);
        assert!(
            drain
                .events
                .iter()
                .any(|event| event.kind == ComponentEventKind::LanProxyNetworkLost),
            "{drain:?}"
        );
    }

    #[tokio::test]
    async fn a_preset_whose_runtime_is_unavailable_never_binds() {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: Some(RuntimeKind::Tor),
        });
        let manager = ComponentManager::new(provider);
        let binding = loopback_binding();
        manager.confirm_lan_network(&binding).unwrap();
        let socks_port = free_port();

        let refused = manager.start_lan_proxy(
            tokio::runtime::Handle::current(),
            LanProxyConfig {
                id: ComponentId::new("lan:test").unwrap(),
                preset: LanProxyPreset::Tor,
                socks_port,
                http_port: 0,
                credentials: LanCredentials::new("user", b"secret".to_vec()).unwrap(),
            },
            binding,
            Arc::new(TestUpstream {
                echo: None,
                seen: Arc::new(StdMutex::new(Vec::new())),
            }),
        );

        assert_eq!(refused.err(), Some(ComponentError::RuntimeUnavailable));
        assert!(
            StdTcpListener::bind(SocketAddr::new(
                IpAddr::from(Ipv4Addr::LOCALHOST),
                socks_port
            ))
            .is_ok(),
            "a listener must never be up while its upstream is not"
        );
    }

    // ------------------------------------------------ named loopback inbounds

    fn inbound(name: &str, route: LanRoute, max_sessions: usize) -> LoopbackInbound {
        LoopbackInbound {
            id: ComponentId::new(name).unwrap(),
            http_port: 0,
            credentials: Some(LanCredentials::new("user", b"secret".to_vec()).unwrap()),
            route,
            max_sessions,
        }
    }

    async fn connect_through(
        address: SocketAddr,
        credentials: Option<&str>,
        target: &str,
    ) -> String {
        use base64::Engine as _;

        let mut stream = TcpStream::connect(address).await.unwrap();
        let head = match credentials {
            Some(credentials) => {
                let token = base64::engine::general_purpose::STANDARD.encode(credentials);
                format!("CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n")
            }
            None => format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"),
        };
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut response = vec![0_u8; 64];
        let read = stream.read(&mut response).await.unwrap();
        response.truncate(read);
        String::from_utf8_lossy(&response).into_owned()
    }

    /// The whole reason the type exists: two inbounds, two credentials, two
    /// upstreams — and the routes they resolve to are the ones they were named
    /// with, not a shared default.
    #[tokio::test]
    async fn two_named_inbounds_carry_their_own_route_and_their_own_credentials() {
        let echo = echo_server().await;
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider.clone());
        let seen = Arc::new(StdMutex::new(Vec::new()));

        let mut profile = inbound("webapp.a", LanRoute::Vpn, 4);
        let mut tor = inbound("webapp.b", LanRoute::Tor, 4);
        tor.credentials = Some(LanCredentials::new("other", b"another".to_vec()).unwrap());
        profile.credentials = Some(LanCredentials::new("one", b"first".to_vec()).unwrap());

        let mut handles = Vec::new();
        for config in [profile, tor] {
            handles.push(
                manager
                    .start_loopback_inbound(
                        tokio::runtime::Handle::current(),
                        config,
                        3,
                        Arc::new(TestUpstream {
                            echo: Some(echo),
                            seen: seen.clone(),
                        }),
                    )
                    .expect("a named loopback inbound needs no network confirmation"),
            );
        }

        for handle in &handles {
            let address = handle.http_address().expect("HTTP listener");
            assert_eq!(
                address.ip(),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "the bind address is the component's choice and is never configurable"
            );
            assert!(address.port() != 0, "an ephemeral port must be reported");
            assert!(
                handle.socks_address().is_none(),
                "a named inbound has no SOCKS half"
            );
        }

        let first = handles[0].http_address().unwrap();
        let second = handles[1].http_address().unwrap();
        assert_ne!(first.port(), second.port());

        assert!(
            connect_through(first, Some("one:first"), "a.example:443")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            connect_through(second, Some("other:another"), "b.example:443")
                .await
                .starts_with("HTTP/1.1 200")
        );

        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.contains(&(LanRoute::Vpn, "a.example".to_owned(), 443)),
            "{seen:?}"
        );
        assert!(
            seen.contains(&(LanRoute::Tor, "b.example".to_owned(), 443)),
            "{seen:?}"
        );

        let mut acquired = provider.acquired.lock().unwrap().clone();
        acquired.sort_by_key(|kind| format!("{kind:?}"));
        assert_eq!(acquired, vec![RuntimeKind::Tor, RuntimeKind::Vpn]);
    }

    /// One inbound's credentials must not open another's port.
    ///
    /// Every loopback listener is reachable by every app on the device, so the
    /// credential is the only separator there is. If it were shared, the app on
    /// the profile could dial the port labelled Tor and the labels would mean
    /// nothing.
    #[tokio::test]
    async fn a_named_inbound_refuses_another_inbounds_credentials() {
        let echo = echo_server().await;
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider);
        let seen = Arc::new(StdMutex::new(Vec::new()));

        let mut other = inbound("webapp.b", LanRoute::Vpn, 4);
        other.credentials = Some(LanCredentials::new("other", b"another".to_vec()).unwrap());
        let handle = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                inbound("webapp.a", LanRoute::Vpn, 4),
                3,
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: seen.clone(),
                }),
            )
            .unwrap();
        let _other = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                other,
                3,
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: seen.clone(),
                }),
            )
            .unwrap();

        let address = handle.http_address().unwrap();
        assert!(
            connect_through(address, None, "a.example:443")
                .await
                .starts_with("HTTP/1.1 407"),
            "authentication is mandatory and not configurable"
        );
        assert!(
            connect_through(address, Some("other:another"), "a.example:443")
                .await
                .starts_with("HTTP/1.1 407"),
            "the neighbouring inbound's credentials must not open this one"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "no unauthenticated request may reach an upstream"
        );
    }

    /// An inbound whose upstream is down answers `502`, and the request never
    /// reaches the network.
    ///
    /// This is the sentence the whole feature rests on: a web app labelled Tor
    /// that fell through to direct would leave in clear text under a label that
    /// says it did not.
    #[tokio::test]
    async fn a_named_inbound_whose_upstream_is_down_refuses_instead_of_falling_through() {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider);
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let handle = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                inbound("webapp.tor", LanRoute::Tor, 4),
                3,
                // `echo: None` is an upstream that always errors — the shape a
                // Tor lane has when the overlay gate is off or no circuit builds.
                Arc::new(TestUpstream {
                    echo: None,
                    seen: seen.clone(),
                }),
            )
            .unwrap();

        let response = connect_through(
            handle.http_address().unwrap(),
            Some("user:secret"),
            "hidden.example:443",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "the only honest answer is a refusal, got {response:?}"
        );
        let drain = manager.drain_events(&ComponentId::new("webapp.tor").unwrap(), 16);
        assert!(
            drain
                .events
                .iter()
                .any(|event| event.kind == ComponentEventKind::LanProxyRefused),
            "{drain:?}"
        );
    }

    /// The anonymous loopback listener the owner asked for: an app points at
    /// `127.0.0.1:port` and gets the tunnel, with no password to type in.
    ///
    /// Worth a test of its own rather than a flag flip, because "no credentials"
    /// and "credentials not valid yet" are one field apart and the second one is
    /// what a network change leaves behind.
    #[tokio::test]
    async fn a_named_inbound_without_credentials_serves_anonymously() {
        let echo = echo_server().await;
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider);
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let mut config = inbound("webapp.open", LanRoute::Vpn, 4);
        config.credentials = None;
        let handle = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                config,
                3,
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: seen.clone(),
                }),
            )
            .unwrap();

        let response =
            connect_through(handle.http_address().unwrap(), None, "example.test:443").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "an anonymous loopback inbound must accept a request with no credentials, got {response:?}"
        );
    }

    /// And the same absence on the LAN is refused at the binding, before a
    /// socket exists.
    ///
    /// Asserted where it is enforced rather than trusted to the types: the LAN
    /// path builds its credentials as `Some`, and this proves that a plan that
    /// did not could still not bind.
    #[tokio::test]
    async fn an_anonymous_plan_is_refused_on_a_confirmed_lan_binding() {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider);
        let binding = loopback_binding();
        manager.confirm_lan_network(&binding).unwrap();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let refused = start_with_binding(
            manager.inner_for_test(),
            tokio::runtime::Handle::current(),
            InboundPlan {
                id: ComponentId::new("lan:open").unwrap(),
                socks: None,
                http: Some((0, LanRoute::Vpn)),
                credentials: None,
                runtimes: vec![RuntimeKind::Vpn],
                max_sessions: 4,
                handshake_timeout: SHORT_HANDSHAKE_TIMEOUT,
            },
            binding,
            Arc::new(TestUpstream {
                echo: None,
                seen: seen.clone(),
            }),
            BindingAuthorization::ConfirmedLan,
        );
        assert!(
            matches!(refused, Err(ComponentError::LanBindingRefused)),
            "an anonymous LAN listener must not exist, got {:?}",
            refused.err(),
        );
    }

    /// A named inbound for a runtime this generation does not have never binds.
    ///
    /// The port is checked afterwards rather than the error alone: "refused" and
    /// "refused *and* left nothing listening" are different claims, and only the
    /// second one keeps an app from finding a socket that answers and then
    /// cannot serve.
    #[tokio::test]
    async fn a_named_inbound_without_its_runtime_never_binds() {
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: Some(RuntimeKind::Tor),
        });
        let manager = ComponentManager::new(provider);
        let port = free_port();
        let mut config = inbound("webapp.tor", LanRoute::Tor, 4);
        config.http_port = port;

        let refused = manager.start_loopback_inbound(
            tokio::runtime::Handle::current(),
            config,
            3,
            Arc::new(TestUpstream {
                echo: None,
                seen: Arc::new(StdMutex::new(Vec::new())),
            }),
        );

        assert_eq!(refused.err(), Some(ComponentError::RuntimeUnavailable));
        assert!(
            StdTcpListener::bind(SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port)).is_ok(),
            "a listener must never be up while its upstream is not"
        );
    }

    /// The per-inbound session cap is real: the (cap + 1)-th concurrent client
    /// is dropped rather than served.
    ///
    /// Without it one web app could take every session slot on the device, and
    /// the failure would look like every *other* app's proxy being broken.
    #[tokio::test]
    async fn the_per_inbound_session_cap_bounds_one_inbound_and_not_the_others() {
        let echo = echo_server().await;
        let provider = Arc::new(RecordingProvider {
            acquired: StdMutex::new(Vec::new()),
            unavailable: None,
        });
        let manager = ComponentManager::new(provider);
        let seen = Arc::new(StdMutex::new(Vec::new()));

        let capped = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                inbound("webapp.capped", LanRoute::Vpn, 1),
                3,
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: seen.clone(),
                }),
            )
            .unwrap();
        let mut roomy = inbound("webapp.roomy", LanRoute::Vpn, 4);
        roomy.credentials = Some(LanCredentials::new("other", b"another".to_vec()).unwrap());
        let roomy = manager
            .start_loopback_inbound(
                tokio::runtime::Handle::current(),
                roomy,
                3,
                Arc::new(TestUpstream {
                    echo: Some(echo),
                    seen: seen.clone(),
                }),
            )
            .unwrap();

        use base64::Engine as _;
        let token = base64::engine::general_purpose::STANDARD.encode("user:secret");
        let address = capped.http_address().unwrap();

        // One live session, held open by not closing it.
        let mut held = TcpStream::connect(address).await.unwrap();
        held.write_all(
            format!(
                "CONNECT held.example:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut established = vec![0_u8; 39];
        held.read_exact(&mut established).await.unwrap();

        // The second one is accepted by the kernel and then dropped without a
        // reply, because there is no slot for it.
        let mut over = TcpStream::connect(address).await.unwrap();
        over.write_all(
            format!(
                "CONNECT over.example:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        // Either an orderly EOF or an RST, depending on how the platform
        // reports a socket that was closed with unread bytes on it. What must
        // never arrive is a `200`.
        //
        // Under a deadline, and the deadline is the point: with the cap gone
        // this session is *served*, the relay holds the socket open, and an
        // unbounded read here turns a failing test into a hung suite — which is
        // how this test was found to be right for the wrong reason. Two seconds
        // is the same budget the handshake gets under `cfg(test)`.
        let mut response = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            over.read_to_end(&mut response),
        )
        .await;
        assert!(
            read.is_ok(),
            "the over-cap session was served and is still open; the cap did not hold"
        );
        assert!(
            response.is_empty(),
            "the cap must refuse rather than serve, got {:?}",
            String::from_utf8_lossy(&response)
        );

        // The neighbour is untouched: the cap is per inbound, not per process.
        assert!(
            connect_through(
                roomy.http_address().unwrap(),
                Some("other:another"),
                "roomy.example:443"
            )
            .await
            .starts_with("HTTP/1.1 200"),
            "one inbound's cap must not close another inbound's door"
        );
    }
}
