use super::*;

use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    pub mtu: u16,
    pub ipv4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
}

/// Authenticated, process-local HTTP CONNECT surface owned by the root runtime.
///
/// The listener address is intentionally absent from the schema: FoxCore binds
/// this surface to IPv4 loopback itself, so malformed or attacker-controlled
/// configuration cannot turn it into a LAN or wildcard listener.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProxyConfig {
    pub http_port: u16,
    pub username: String,
    pub password: SecretString,
}

impl ControlProxyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.http_port == 0 {
            return Err(ConfigError::Invalid(
                "runtime.control_proxy.http_port must be non-zero".into(),
            ));
        }
        if self.username.is_empty()
            || self.username.len() > 64
            || !self.username.is_ascii()
            || self.username.contains(':')
            || self
                .username
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ConfigError::Invalid(
                "runtime.control_proxy.username must be 1..=64 printable ASCII bytes without ':' or whitespace"
                    .into(),
            ));
        }
        if self.password.is_empty() || self.password.expose().len() > 255 {
            return Err(ConfigError::Invalid(
                "runtime.control_proxy.password must be 1..=255 UTF-8 bytes".into(),
            ));
        }
        Ok(())
    }
}

/// How many named loopback inbounds one generation may hold.
///
/// A ceiling rather than a comfort: every entry is a bound socket, a credential
/// held in memory and a session semaphore, and the caller that fills this list
/// is a UI list the user edits. Sixteen is the same order as
/// `max_named_outbounds`, which is the other list an app builds per profile.
pub const MAX_LOOPBACK_INBOUNDS: usize = 16;
/// Concurrent sessions one named inbound may carry, and the ceiling on the
/// configured value.
///
/// Named inbounds exist to separate *one application each*, so the realistic
/// number is small. The default is deliberately below the LAN proxy's 64: a web
/// app that opens eight simultaneous CONNECTs is already unusual, and a low cap
/// is what keeps one misbehaving app from spending the phone's descriptors on
/// the tunnel everything else is sharing.
pub const DEFAULT_LOOPBACK_INBOUND_SESSIONS: u16 = 8;
pub const MAX_LOOPBACK_INBOUND_SESSIONS: u16 = 64;

/// Where one named loopback inbound sends what it accepts.
///
/// Three variants and no fourth. In particular there is no "whatever is
/// available": an inbound the user labelled Tor that quietly used the profile
/// would be the same failure the LAN proxy's missing `direct` preset exists to
/// prevent, one process closer to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoopbackUpstream {
    /// The active profile's outbound — the same one the TUN's own flows use.
    Profile,
    /// The Tor lane. Refused, never downgraded, when this build has no Tor, the
    /// profile has no Tor outbound, or the overlay gate is off.
    Tor,
    /// The protected dialer, unwrapped: out through the physical network even
    /// while the TUN is up. The one upstream that is not a tunnel, and it is
    /// only ever reached because a configuration named it.
    Direct,
}

impl LoopbackUpstream {
    pub fn name(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Tor => "tor",
            Self::Direct => "direct",
        }
    }
}

/// One authenticated, loopback-only HTTP CONNECT listener with a name.
///
/// The reason this type exists at all: on Android every web app runs in one
/// process under one uid, so the TUN cannot tell them apart and per-app routing
/// through it is not representable. Handing each app a *different* loopback
/// proxy is the only separation there is, which makes the name, the credentials
/// and the upstream one indivisible unit.
///
/// As with [`ControlProxyConfig`], the bind address is absent from the schema on
/// purpose. FoxCore binds `127.0.0.1` itself; a configuration cannot widen one of
/// these to the LAN, and the LAN surface — with its network confirmation — is
/// where that request belongs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopbackInboundConfig {
    /// Stable identity, unique within the list. The app uses it to find the
    /// bound port again in the status document, so it must survive a restart of
    /// the engine that the port number does not.
    pub name: String,
    /// `0` asks the kernel for an ephemeral port and the status document
    /// reports the one that was bound.
    ///
    /// Recommended, and it is not a convenience: a phone has no port registry,
    /// so a fixed port is a coin flip against every other app on the device, and
    /// losing that flip is a listener that will not bind at all.
    #[serde(default)]
    pub http_port: u16,
    /// Explicit consent to let any application on this device use the listener.
    #[serde(default)]
    pub allow_anonymous: bool,
    /// Omitted credentials require `allow_anonymous`; partial credentials are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    pub upstream: LoopbackUpstream,
    #[serde(default = "default_loopback_inbound_sessions")]
    pub max_sessions: u16,
}

fn default_loopback_inbound_sessions() -> u16 {
    DEFAULT_LOOPBACK_INBOUND_SESSIONS
}

impl LoopbackInboundConfig {
    /// Everything one entry can be wrong about on its own. Whatever depends on
    /// the other entries — a repeated name, port or credential — is checked in
    /// [`RuntimeConfig::validate`], which is the only place that can see them.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !is_loopback_inbound_name(&self.name) {
            return Err(ConfigError::Invalid(
                "runtime.loopback_inbounds[].name must be 1..=64 bytes of [A-Za-z0-9._-]".into(),
            ));
        }
        match (&self.username, &self.password) {
            (None, None) if self.allow_anonymous => {}
            (Some(username), Some(password)) if !self.allow_anonymous => {
                if username.is_empty()
                    || username.len() > 64
                    || !username.is_ascii()
                    || username.contains(':')
                    || username
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
                {
                    return Err(ConfigError::Invalid(
                        "runtime.loopback_inbounds[].username must be 1..=64 printable ASCII \
                         bytes without ':' or whitespace"
                            .into(),
                    ));
                }
                if password.is_empty() || password.expose().len() > 255 {
                    return Err(ConfigError::Invalid(
                        "runtime.loopback_inbounds[].password must be 1..=255 UTF-8 bytes".into(),
                    ));
                }
            }
            // Half a credential is the shape a listener ends up in when a form
            // was filled in and abandoned, and it is the one shape that must not
            // silently become "anonymous".
            _ => {
                return Err(ConfigError::Invalid(
                    "runtime.loopback_inbounds[] requires credentials or explicit allow_anonymous, never both"
                        .into(),
                ));
            }
        }
        if !(1..=MAX_LOOPBACK_INBOUND_SESSIONS).contains(&self.max_sessions) {
            return Err(ConfigError::Invalid(format!(
                "runtime.loopback_inbounds[].max_sessions must be in 1..={MAX_LOOPBACK_INBOUND_SESSIONS}"
            )));
        }
        Ok(())
    }
}

/// The identity charset, and it is not an accident that it is narrower than the
/// username's: a name becomes a `ComponentId`, which allows `:` — and `:` is the
/// separator the runtime uses to keep its own component identities (
/// `runtime:control-proxy`) out of a namespace the app writes into.
fn is_loopback_inbound_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Authorises a direct primary only for the app's on-device DNS/firewall guard.
    #[serde(default)]
    pub local_guard: bool,
    /// Optional authenticated loopback proxy used by app-owned validation and
    /// IP refreshes. It shares this runtime's outbound and lifecycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_proxy: Option<ControlProxyConfig>,
    /// Named loopback-only CONNECT listeners, one per application the app wants
    /// to route separately. Empty on every configuration that predates them,
    /// which is what makes the field additive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loopback_inbounds: Vec<LoopbackInboundConfig>,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    #[serde(default = "default_blocking_threads")]
    pub max_blocking_threads: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// How long a **UDP** session and a split-table entry may sit unused.
    ///
    /// Held apart from [`RuntimeConfig::tcp_idle_timeout_s`] because the two
    /// answer different questions. A UDP session has no liveness of its own:
    /// silence is the only state it has, and reclaiming it early costs a
    /// re-created session. A TCP connection is *established* on both ends,
    /// which is why it gets its own field and its own number.
    #[serde(default = "default_idle_timeout_s")]
    pub idle_timeout_s: u64,
    /// How long an established **TCP** relay may carry nothing in either
    /// direction before the core closes it towards the application.
    ///
    /// Separate from [`RuntimeConfig::idle_timeout_s`] because of one property
    /// of the stack, measured rather than assumed: **the stack answers the
    /// application's TCP keepalives itself.** An empty ACK never reaches the
    /// relay, so it moves no counter, and a connection whose entire liveness is
    /// a keepalive looks exactly like a dead one from here. Sharing the UDP
    /// field would have made "silent for five minutes" the sentence — and the
    /// connections that are silent for five minutes and alive are push
    /// channels: messengers and notifications.
    ///
    /// See [`default_tcp_idle_timeout_s`] for why the default is what it is.
    #[serde(default = "default_tcp_idle_timeout_s")]
    pub tcp_idle_timeout_s: u64,
    #[serde(default = "default_relay_buffer")]
    pub relay_buffer_bytes: usize,
    #[serde(default = "default_max_tcp_flows")]
    pub max_tcp_flows: usize,
    #[serde(default = "default_max_udp_flows")]
    pub max_udp_flows: usize,
    #[serde(default = "default_attribution_timeout_ms")]
    pub attribution_timeout_ms: u64,
    #[serde(default = "default_max_attribution_tasks")]
    pub max_attribution_tasks: usize,
}

impl RuntimeConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if let Some(control_proxy) = &self.control_proxy {
            control_proxy.validate()?;
        }
        self.validate_loopback_inbounds()?;
        if !(1..=4).contains(&self.worker_threads) {
            return Err(ConfigError::Invalid(
                "runtime.worker_threads must be in 1..=4".into(),
            ));
        }
        if !(1..=8).contains(&self.max_blocking_threads) {
            return Err(ConfigError::Invalid(
                "runtime.max_blocking_threads must be in 1..=8".into(),
            ));
        }
        if !(4 * 1024..=256 * 1024).contains(&self.relay_buffer_bytes) {
            return Err(ConfigError::Invalid(
                "runtime.relay_buffer_bytes must be in 4096..=262144".into(),
            ));
        }
        if self.max_tcp_flows == 0 || self.max_udp_flows == 0 {
            return Err(ConfigError::Invalid(
                "runtime flow limits must be non-zero".into(),
            ));
        }
        if !(100..=120_000).contains(&self.connect_timeout_ms) {
            return Err(ConfigError::Invalid(
                "runtime.connect_timeout_ms must be in 100..=120000".into(),
            ));
        }
        if !(100..=300_000).contains(&self.handshake_timeout_ms) {
            return Err(ConfigError::Invalid(
                "runtime.handshake_timeout_ms must be in 100..=300000".into(),
            ));
        }
        if !(5..=86_400).contains(&self.idle_timeout_s) {
            return Err(ConfigError::Invalid(
                "runtime.idle_timeout_s must be in 5..=86400".into(),
            ));
        }
        // The same range as the UDP window, and deliberately so: a range says
        // what the core can be asked for, not what it recommends. The floor is
        // low because a test and an operator debugging a stuck relay both want
        // it low; the recommendation is `default_tcp_idle_timeout_s`, and it is
        // twelve times the floor of this range's UDP twin.
        if !(5..=86_400).contains(&self.tcp_idle_timeout_s) {
            return Err(ConfigError::Invalid(
                "runtime.tcp_idle_timeout_s must be in 5..=86400".into(),
            ));
        }
        if self.max_tcp_flows > 32_768 || self.max_udp_flows > 32_768 {
            return Err(ConfigError::Invalid(
                "runtime flow limits must not exceed 32768".into(),
            ));
        }
        if !(25..=2_000).contains(&self.attribution_timeout_ms) {
            return Err(ConfigError::Invalid(
                "runtime.attribution_timeout_ms must be in 25..=2000".into(),
            ));
        }
        if !(1..=64).contains(&self.max_attribution_tasks) {
            return Err(ConfigError::Invalid(
                "runtime.max_attribution_tasks must be in 1..=64".into(),
            ));
        }
        Ok(())
    }

    /// The rules that need the whole list in front of them.
    ///
    /// Every one of them is about a *collision*, and every collision is the same
    /// bug wearing a different hat: two applications that were supposed to be
    /// separated end up on one listener, or one of them cannot bind at all. The
    /// credential checks in particular are the point of the feature — these
    /// listeners all sit on `127.0.0.1`, where every app on the phone can reach
    /// every port, so the credential is the *only* thing that keeps the web app
    /// on Tor out of the one on the profile.
    fn validate_loopback_inbounds(&self) -> Result<(), ConfigError> {
        if self.loopback_inbounds.len() > MAX_LOOPBACK_INBOUNDS {
            return Err(ConfigError::Invalid(format!(
                "runtime.loopback_inbounds must hold at most {MAX_LOOPBACK_INBOUNDS} entries"
            )));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut ports = std::collections::BTreeSet::new();
        let mut usernames = std::collections::BTreeSet::new();
        let mut passwords = std::collections::BTreeSet::new();
        if let Some(control_proxy) = &self.control_proxy {
            ports.insert(control_proxy.http_port);
            usernames.insert(control_proxy.username.as_str());
            passwords.insert(control_proxy.password.expose());
        }
        for inbound in &self.loopback_inbounds {
            inbound.validate()?;
            if !names.insert(inbound.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "runtime.loopback_inbounds has two entries named '{}'",
                    inbound.name
                )));
            }
            // Port 0 is "ask the kernel", and two of those collide with nothing.
            if inbound.http_port != 0 && !ports.insert(inbound.http_port) {
                return Err(ConfigError::Invalid(format!(
                    "runtime.loopback_inbounds reuses port {} — an inbound that cannot bind is \
                     an application with no route rather than a shared one",
                    inbound.http_port
                )));
            }
            // Anonymous entries are skipped rather than compared: they have no
            // credential to repeat, and their separation is the port.
            if let Some(username) = inbound.username.as_deref()
                && !usernames.insert(username)
            {
                return Err(ConfigError::Invalid(
                    "runtime.loopback_inbounds reuses a username — every loopback listener is \
                     reachable by every app on the device, so a shared credential is a shared \
                     upstream"
                        .into(),
                ));
            }
            if let Some(password) = inbound.password.as_ref()
                && !passwords.insert(password.expose())
            {
                return Err(ConfigError::Invalid(
                    "runtime.loopback_inbounds reuses a password — every loopback listener is \
                     reachable by every app on the device, so a shared credential is a shared \
                     upstream"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            local_guard: false,
            control_proxy: None,
            loopback_inbounds: Vec::new(),
            worker_threads: default_worker_threads(),
            max_blocking_threads: default_blocking_threads(),
            connect_timeout_ms: default_connect_timeout_ms(),
            handshake_timeout_ms: default_handshake_timeout_ms(),
            idle_timeout_s: default_idle_timeout_s(),
            tcp_idle_timeout_s: default_tcp_idle_timeout_s(),
            relay_buffer_bytes: default_relay_buffer(),
            max_tcp_flows: default_max_tcp_flows(),
            max_udp_flows: default_max_udp_flows(),
            attribution_timeout_ms: default_attribution_timeout_ms(),
            max_attribution_tasks: default_max_attribution_tasks(),
        }
    }
}

/// Four, not two.
///
/// Two was a phone-battery decision made before the data plane had this much
/// on it: the flow engine, the DNS interceptor, per-flow relays, a control
/// proxy listener and — since Tor became a default feature — Arti's own tasks,
/// all on the same executor. Two workers means any two tasks that stop
/// yielding stall the entire runtime, and a stalled runtime does not fire
/// timers, which is how a stop with a 250 ms ceiling inside it still took the
/// whole three-second budget on a Pixel and ended with the app killing its own
/// process.
///
/// The validator already allowed up to four; the default simply had not moved.
/// Tokio parks idle workers, so the cost of the two extra threads on an idle
/// tunnel is two parked threads, not two busy ones.
fn default_worker_threads() -> usize {
    4
}

/// Six, not two.
///
/// This pool has three tenants and they are not interchangeable. Two of them
/// are on the data path and hold a thread for microseconds: the platform DNS
/// resolver (`foxcore-dialer`) and flow attribution (`foxcore-tun`). The third
/// is file sharing, which holds one for the length of a transfer, paced by
/// whoever is downloading — up to `MAX_DOWNLOADS` of them at once. At two
/// threads a single slow download left one for everything else and two left
/// none, so every dial by hostname queued behind a stranger's download and
/// then failed on `connect_timeout_ms`.
///
/// Six is the data-path reservation (two) plus the cap the share server now
/// keeps for itself (four). The validator's ceiling is eight; blocking threads
/// are created on demand and retired when idle, so an idle tunnel pays nothing
/// for the headroom.
fn default_blocking_threads() -> usize {
    6
}

fn default_connect_timeout_ms() -> u64 {
    10_000
}

fn default_handshake_timeout_ms() -> u64 {
    15_000
}

fn default_idle_timeout_s() -> u64 {
    300
}

/// One hour of complete silence before an established TCP relay is reclaimed.
///
/// Twelve times [`default_idle_timeout_s`], and the gap is the point. The
/// mechanism that reads this counts bytes the *outbound* moved, and the stack
/// answers the application's TCP keepalives without ever waking the relay — so
/// "no bytes" and "no life" are the same observation here, and the number is
/// the only thing standing between a live push channel and a close it did
/// nothing to deserve.
///
/// Why an hour, and not the five minutes the UDP field carries:
///
/// * **Every keepalive interval that exists in practice is below thirty
///   minutes,** because that is the band middleboxes tolerate: ~15 min on
///   cellular, 28–29 min on Wi-Fi, and RFC 2177 requires an IMAP client to
///   re-issue `IDLE` at least every 29 minutes for exactly this reason.
///   Anything shorter wastes radio; anything longer does not survive the path.
///   At 300 s the core sat *below* that entire band — the one place a timeout
///   must never sit. An hour clears its top by roughly two.
/// * **Application heartbeats were never the hazard**; they carry bytes and
///   reset this window. The hazard is the bare TCP keepalive, which is an empty
///   ACK the stack absorbs, and the connections that lean on it are the ones a
///   user notices immediately: messengers, mail, notifications.
/// * **Not RFC 5382's 2 h 4 min**, the floor a conforming NAT must give an
///   established connection, even though the core holds the same kind of state
///   for the same kind of peer. A flow silent for an hour is silent on its
///   *outbound* leg too, and that leg crosses the same middleboxes the
///   application was keeping alive against. Holding our slot past the point
///   where the path has dropped its own buys nothing but the slot.
/// * **The two failures are not symmetric.** Too long costs memory on flows
///   nobody is using — bounded by `max_tcp_flows` (1024) times two relay
///   buffers, freed when the window passes, and *visible* if it ever bites,
///   because exhausting that table raises `BlockReason::FlowLimit` and is
///   counted. Too short kills a connection that was working, reports nothing
///   that names the application, and is indistinguishable from the network's
///   fault. The second is worse, so the number leans long.
fn default_tcp_idle_timeout_s() -> u64 {
    3_600
}

fn default_relay_buffer() -> usize {
    16 * 1024
}

fn default_max_tcp_flows() -> usize {
    1024
}

fn default_max_udp_flows() -> usize {
    512
}

fn default_attribution_timeout_ms() -> u64 {
    250
}

fn default_max_attribution_tasks() -> usize {
    16
}

pub(super) fn default_true() -> bool {
    true
}
