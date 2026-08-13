use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

impl Destination {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn authority(&self) -> String {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

impl fmt::Debug for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Destination")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowContext {
    pub generation: u64,
    pub transport: IpTransport,
    /// Full client 2-tuple. Protocols that need per-socket identity (XUDP's
    /// Global ID) require the port, not just the address.
    pub source: Option<SocketAddr>,
    pub destination: Destination,
    pub domain_hint: Option<String>,
    pub uid: Option<u32>,
    pub package: Option<String>,
    pub packages: Vec<String>,
    pub network: Option<NetworkType>,
    /// SHA-256 of the app's signing certificate, resolved by the platform control
    /// plane. Quarantine uses it so a repackaged app cannot inherit trust from a
    /// package name alone (final.txt §15).
    pub signing_digest: Option<[u8; 32]>,
}

impl FlowContext {
    pub fn new(generation: u64, transport: IpTransport, destination: Destination) -> Self {
        Self {
            generation,
            transport,
            source: None,
            destination,
            domain_hint: None,
            uid: None,
            package: None,
            packages: Vec::new(),
            network: None,
            signing_digest: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowIdentity {
    pub uid: u32,
    pub packages: Vec<String>,
    /// See [`FlowContext::signing_digest`]. `None` when the platform did not (or
    /// could not) resolve it.
    pub signing_digest: Option<[u8; 32]>,
}

/// Why the data plane refused a flow. Carried in [`CoreEvent::Blocked`] so the UI
/// can report *why* something was blocked, not merely *that* it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// The global kill switch is armed.
    KillSwitch,
    /// The compiled policy returned `Block` — an explicit rule, quarantine, or a
    /// default-block allowlist.
    Policy,
    /// Identity was required by the policy but could not be attributed.
    Unattributed,
    /// Bounded per-transport concurrency was exhausted.
    FlowLimit,
    /// A DNS name matched the blocklist.
    DnsBlocklist,
    /// `.onion`/`.i2p` refused because the overlay is disabled or unregistered.
    DnsOverlayGate,
    /// The selected outbound cannot carry this flow as datagrams, so it was
    /// refused rather than rewritten onto TCP.
    ///
    /// Usually because the protocol has no UDP at all — HTTP CONNECT, Naive and
    /// I2P are TCP-only — but not always: VLESS Vision on UDP/443 and
    /// Shadowsocks over a stream transport are flow-level refusals on protocols
    /// that otherwise carry datagrams. Do not read a protocol out of this.
    ///
    /// Distinct from a dial failure on purpose: this refusal is correct and
    /// permanent for this profile, while a dial error is transient and about
    /// the network. Counting the two together (D7, found on device) made a
    /// working fail-closed refusal read as connectivity trouble.
    UdpUnsupported,
    /// The lane is suspended waiting for the user to confirm a repair
    /// `traffic.continuity` no longer lets the core make on its own.
    ///
    /// Not a policy denial: nothing about this flow was refused, and it is
    /// allowed again the moment the confirmation arrives. Reported separately
    /// so a screen can say "waiting for you" instead of "blocked by a rule".
    ContinuityHeld,
    /// An L3 packet carried an address the tunnel does not map, so it was
    /// dropped rather than put on the wire with the wrong source.
    ///
    /// Outbound this means the address on the tun is not the one the engine was
    /// configured with — the platform put something else on the interface, and
    /// the core cannot observe that directly. Every user packet is lost while
    /// it holds, and the tunnel still looks alive: handshakes and keepalives
    /// never pass through translation, and DNS is answered by the interceptor
    /// on the stack side. That combination is what made this invisible (D10).
    TunnelAddressMismatch,
    /// The tunnel has no address of this packet's family, so that whole family
    /// is lost. A profile with only an IPv4 address on a tun that also carries
    /// IPv6 does exactly this.
    TunnelFamilyUnmapped,
    /// A clearnet name was answered with a fake address and its flow was routed
    /// to an L3 packet tunnel, which has no stack to restore the name from.
    ///
    /// Sealing it would put a destination out of the fake-IP pool on the wire —
    /// `198.18.0.0/15` is RFC 2544, reserved for benchmarking and routed by
    /// nobody — so the flow is refused instead. Found on device: the packet was
    /// translated, sealed and sent, every counter agreed, and the connection
    /// timed out twenty seconds later in device acceptance. Overlay names never reach
    /// this: their flows go to the stack before routing is consulted.
    TunnelFakeIpUnroutable,
    /// The L3 packet tunnel has no protected socket, so the packet was dropped
    /// instead of being put on the wire.
    ///
    /// Raised when the network moved under a live tunnel and the replacement
    /// socket could not be built — the platform refused to protect it, refused
    /// to bind it to the new network, or the peer's endpoint stopped resolving
    /// on it. Continuing on the old socket is not an alternative: it is bound
    /// to an interface that no longer routes, which is the failure this whole
    /// path exists to end (handshakes and keepalives keep moving, every byte
    /// counter keeps rising, and no user packet arrives).
    ///
    /// Not a policy denial and not permanent. The relay keeps retrying, and a
    /// successful rebind resumes the same WireGuard session — keys, counters
    /// and all — because endpoint roaming is a protocol feature.
    TunnelSocketUnavailable,
    /// A flow was torn down because its outbound took **no bytes at all** for
    /// `STALL_TIMEOUT` while unsent data was being held for it.
    ///
    /// The name is older than the rule and is kept on purpose: this is a
    /// persisted dictionary, and renaming a variant costs more than the
    /// mismatch does. What changed is the test. The original
    /// one was volume — more unsent bytes than one flow may hold — and volume
    /// cannot separate a stalled flow from a fast one **at any threshold**: the
    /// guard never parks its writer, so the tun side delivers at memory speed
    /// while a socket does not, and the held amount grows as
    /// `(tun read rate − outbound write rate) × time` for every real upload
    /// over every real link. Measured on an *unimpaired* local link, three of
    /// three uploads died after 0.4–1.4 MiB. What separates the two is
    /// progress, so the verdict is time without any, and the volume ceiling
    /// became backpressure — past it the guard returns `Pending` instead of
    /// accepting more.
    ///
    /// Reached when the outbound stops accepting while the application on the
    /// device keeps sending. The userspace stack has no end-to-end
    /// backpressure — it acknowledges in-order data into an unbounded queue and
    /// its advertised window can never close — so nothing upstream ever slows
    /// the sender down, and the memory grows until the kernel ends the process.
    /// From outside that is "the app closed by itself", with no counter, no
    /// event and no log.
    ///
    /// A refusal is not the right answer; bounding the stack's queue is, and
    /// that is a fork of it. This is the interim: the same failure, named and
    /// counted, and confined to the one flow that caused it.
    FlowBacklogExceeded,
    /// The outbound this flow's lane needs could not be built, so the lane has
    /// nothing to carry the flow with.
    ///
    /// The engine is running and the other lanes are carrying traffic: a
    /// profile with apps on the VPN, on Tor, on I2P and on direct keeps three
    /// of those working while the fourth reports this. Which one it is, why,
    /// and how many flows it has refused are in the runtime snapshot; the class
    /// of failure is in [`CoreEvent::OutboundUnavailable`].
    ///
    /// Never a downgrade. A flow that reaches this is refused, not sent out by
    /// another lane — a VPN that failed to build and whose traffic quietly went
    /// clearnet is the exact outcome the whole isolation contract exists to
    /// prevent.
    ///
    /// Distinct from [`BlockReason::Policy`] on purpose. Before this existed,
    /// an outbound missing from the registry and an outbound the policy refuses
    /// produced the same event, so "my apps stopped working" and "my apps are
    /// configured not to work" were the same sentence.
    LaneUnavailable,
    /// The tun handed the packet tunnel a datagram addressed to the packet
    /// tunnel's own peer endpoint, so sealing it would send the tunnel's own
    /// output back into the tunnel.
    ///
    /// This is a routing loop, and it is self-sustaining: every trip adds a
    /// WireGuard header and comes back, so one packet becomes an unbounded
    /// stream that never leaves the device. It costs a whole CPU core, it bills
    /// the user for traffic the wire never carried, and — until this reason
    /// existed — not one counter moved while it happened (D15, found on
    /// device: `bytes_up` claimed ~2.9 GB against 479 bytes the OS had actually
    /// sent).
    ///
    /// The core cannot fix the cause, which is a WireGuard socket whose
    /// `protect()`/network bind did not take it out of the tun it is serving.
    /// It can refuse to be the amplifier, and say which packet it refused.
    TunnelRoutingLoop,
    /// The packet tunnel has been sending for longer than several handshake
    /// attempts and the peer has not returned one authenticated byte.
    ///
    /// Not a policy denial: nothing is refused because of this, and the relay
    /// keeps retrying. It exists because the opposite state is indistinguishable
    /// from a working tunnel from inside the process — the state machine keeps
    /// producing handshakes, the socket keeps accepting them, and every health
    /// counter stays at zero. A peer that has answered nothing across several
    /// `REKEY_TIMEOUT` windows is a tunnel that is down, and something has to
    /// say so before the battery does.
    TunnelPeerUnresponsive,
    /// A flow aimed at the resolver this profile advertised, on the DoT port,
    /// refused so that the question comes back on one the interceptor reads.
    ///
    /// The filter must not depend on which transport an application used to ask
    /// a name. It did: the interceptor is entered on `destination.port == 53`,
    /// and Android's opportunistic Private DNS — **the default**, "Automatic" —
    /// probes DoT on 853 against the address the link advertises. Through a
    /// VPN that address is `dns.advertise`, our own. On device the probe
    /// succeeded, every query afterwards went to 853, and the blocklist, the
    /// rule sets, the overlay gates and fake-IP saw *nothing*, with every
    /// counter clean and the UI still drawing the blocklist as on during
    /// device acceptance.
    ///
    /// Not a leak, which is why this took a device to find: those queries went
    /// **inside** the tunnel. The user was protected and unfiltered at the same
    /// time, and that combination has no symptom.
    ///
    /// Refusing is the whole fix, because of what Android does next: a failed
    /// probe in opportunistic mode falls back to cleartext DNS on 53, which the
    /// interceptor already answers and filters. So the refusal does not remove
    /// encrypted DNS from the device — it moves the encryption to the hop that
    /// can carry it, `dns.upstreams`, where the core speaks DoT/DoH itself and
    /// the plaintext leg is the one inside the tunnel, to our own resolver.
    ///
    /// The refusal is in band and immediate — a closed connection, not a
    /// silent drop — because the two are not the same to the prober. Android
    /// bounds the DoT connect at `kDotConnectTimeoutMs`, 127 seconds by
    /// default; a black hole costs that before the fallback, a close costs a
    /// round trip.
    ///
    /// **Strict Private DNS is not served by this and cannot be.** With
    /// `private_dns_mode=hostname` there is no fallback at all: a probe that
    /// fails means the device resolves nothing. It only reaches this refusal
    /// when the hostname the user chose resolves to the advertised address —
    /// `one.one.one.one` against `dns.advertise: 1.1.1.1` is exactly that
    /// shape — and terminating TLS here instead would not help, because a
    /// certificate this core mints is not one that hostname validates against.
    /// That is why this is a named reason with a counter rather than a drop:
    /// the one user it breaks gets a cause instead of a mystery.
    DnsEncryptedBypass,
}

/// One auditable thing the data plane did.
///
/// Serialization is part of the ABI: the app reads these off
/// `nativeDrainEvents` as JSON, and the security journal persists them. Adding
/// a variant is additive; renaming a field is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreEvent {
    Blocked {
        reason: BlockReason,
        transport: IpTransport,
        destination: Destination,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package: Option<String>,
    },
    /// A name the resolver refused. Kept separate from [`CoreEvent::Blocked`]
    /// because a refused *name* has no transport, port or owning app — folding
    /// it into a flow event would mean inventing all three.
    DnsBlocked {
        reason: BlockReason,
        domain: String,
        /// Which app asked. The security journal keys its DNS records on this,
        /// and the resolver is the only place that knows both the name and the
        /// caller — the flow that follows a refused lookup never happens.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package: Option<String>,
        /// Which rule set refused. `None` for an uncategorised list and for the
        /// overlay gates, which are not a filter category at all — reporting a
        /// guess here would put a category on the screen that no list claimed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<crate::DnsCategory>,
    },
    ConfigApplied {
        revision: u64,
        /// What it replaced. The journal records a change, not a state, and a
        /// record that cannot say what came before is not an audit trail.
        previous_revision: u64,
    },
    /// The core reached a repair that `traffic.continuity` no longer lets it
    /// perform on its own.
    ///
    /// From this event the affected lane is blocked, never downgraded: there is
    /// no state in which this fires and packets continue by another route. The
    /// app either confirms — which costs a full reconnect — or stops the engine.
    ConfirmationRequired {
        interruption: ContinuityInterruption,
        /// Monotonic. A confirmation carrying an older token is refused, so a
        /// dialog the user answers late cannot resume a lane that has since
        /// failed again for a different reason.
        token: u64,
        /// When this question stops being fresh, at which point
        /// [`CoreEvent::ConfirmationExpired`] follows. `None` — the default —
        /// means never: the hold simply waits. An elapsed deadline does nothing
        /// to the traffic; it is a report, and the hold goes on holding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in_ms: Option<u64>,
    },
    /// A confirmation deadline passed and nobody had answered.
    ///
    /// Fires **once** per hold: the deadline is spent when it passes, and a
    /// hold that outlives it is simply an indefinite one from then on.
    ///
    /// Nothing changed except that the core now says so. The lanes are still
    /// held, the tunnel is still up, and `token` still confirms — that is the
    /// only thing this can mean, because the setting that let a deadline stop
    /// the engine has been removed.
    ///
    /// It carried an `action` field while that setting existed. The field is
    /// gone rather than pinned to its one remaining value: a constant in an
    /// event is read as a variable by whoever comes next, and this particular
    /// variable used to have "protection ends here" as its other value.
    ///
    /// This event exists because its absence was the quietest failure in the
    /// core: on device the deadline passed, the tunnel went away, traffic went
    /// to clearnet, and the event drain around that moment reported nothing at
    /// all. The tunnel no longer goes away — and the report
    /// stays, because a pause that has lasted since morning is still something
    /// the screen has to be able to say.
    ConfirmationExpired {
        interruption: ContinuityInterruption,
        /// The same token [`CoreEvent::ConfirmationRequired`] carried. Still
        /// valid: an expired question is a question that has been waiting a
        /// long time, not a closed one.
        token: u64,
    },
    /// An outbound in the profile could not be built, and the engine started
    /// without it.
    ///
    /// This is the event that keeps a partial start from being a silent one.
    /// Every lane but this one is carrying traffic; flows that need this one
    /// are refused with [`BlockReason::LaneUnavailable`] until it comes back.
    /// It fires at start and again on any retry that fails with a *different*
    /// class — a repeated identical failure is not news and would fill the
    /// queue that the interesting events share.
    OutboundUnavailable {
        /// The configured id, or `default` for the primary.
        id: String,
        kind: String,
        reason: crate::UnavailableReason,
        /// The build failure verbatim.
        message: String,
        /// Build attempts so far, including the one at start.
        attempts: u32,
    },
    /// An outbound that was unavailable is now carrying traffic.
    ///
    /// Reached without restarting the engine or the tun: the outbound is put
    /// into the registry entry that was refusing for it, so live flows on the
    /// other lanes are not touched and the next flow on this one is dialled
    /// normally.
    OutboundRestored {
        id: String,
        kind: String,
        /// How many attempts it took, counting the one at start.
        attempts: u32,
    },
    /// Live flows were stopped because something asked for them by name.
    ///
    /// The record of a *deliberate* teardown, and the reason it is separate
    /// from [`CoreEvent::Blocked`]: nothing here was refused. Every one of
    /// these flows was allowed by the policy in force, ran, and was then ended
    /// — by the user blocking an app, by a quarantine, or by the kill switch.
    /// Folding the two together would put "N blocked" on a screen for a device
    /// that blocked nothing, which is the mistake D7 was.
    ///
    /// Emitted even when `count` is zero, because the request is the auditable
    /// thing. "The user blocked this app and it had nothing open" and "the user
    /// never blocked this app" are different facts and a journal that cannot
    /// tell them apart is missing the one that matters.
    FlowsRevoked {
        /// Which kind of target named them: `all`, `lane`, `uid`, `package`,
        /// `outbound` or `flow`.
        target: String,
        /// The target's argument as text — the package name, the lane, the
        /// outbound id. Absent for `all`, which has none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// How many live flows the request reached. Zero is an ordinary
        /// answer: the app was not talking.
        count: u64,
    },
}

/// The self-repair the core stopped short of.
///
/// Each variant names a distinct decision, because the user may well want the
/// core to redial the same server silently but ask before it moves them to a
/// different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityInterruption {
    /// The proxy session died; `seamless_reconnect` is off.
    ProxySession,
    /// The active selector member failed; `seamless_failover` is off.
    SelectorMember,
    /// The default network changed; `seamless_network_switch` is off.
    NetworkSwitch,
    /// The VPN outbound failed and `split_tunnel_on_vpn_failure` is off, so the
    /// direct lane was suspended with it rather than left carrying clearnet
    /// traffic at the moment the tunnel died.
    VpnFailure,
}

pub type ContinuityWait = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;

pub enum ContinuityPermit {
    Proceed,
    Wait(ContinuityWait),
}

impl ContinuityPermit {
    pub async fn wait(self) -> bool {
        match self {
            Self::Proceed => true,
            Self::Wait(wait) => wait.await,
        }
    }
}

type EventCallback = Arc<dyn Fn(CoreEvent) + Send + Sync>;

/// Audit sink for the data plane.
///
/// The callback **must not** block, `.await`, or call into the platform
/// synchronously — it runs on the flow path. The intended implementation is a
/// bounded queue with `try_send` and drop-on-full: final.txt §18 requires that the
/// data plane never waits for a consumer, and that a saturated journal degrades by
/// dropping low-priority events rather than by stalling traffic.
#[derive(Clone, Default)]
pub struct EventSink {
    callback: Option<EventCallback>,
}

impl EventSink {
    pub fn none() -> Self {
        Self { callback: None }
    }

    pub fn new(callback: impl Fn(CoreEvent) + Send + Sync + 'static) -> Self {
        Self {
            callback: Some(Arc::new(callback)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.callback.is_some()
    }

    /// Build and emit only when a sink is installed. Blocking is a cold path, but
    /// the event still clones a destination and a package name, so it must not be
    /// constructed when nobody is listening.
    pub fn emit_with(&self, event: impl FnOnce() -> CoreEvent) {
        if let Some(callback) = &self.callback {
            callback(event());
        }
    }
}

impl fmt::Debug for EventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventSink")
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

type AttributeCallback = Arc<
    dyn Fn(IpTransport, SocketAddr, SocketAddr) -> io::Result<Option<FlowIdentity>> + Send + Sync,
>;
type InvalidateCallback = Arc<dyn Fn() + Send + Sync>;

/// Platform connection-owner lookup. The callback is synchronous because
/// Android exposes a Binder-backed synchronous API; the TUN engine always
/// invokes it on the bounded blocking pool.
#[derive(Clone, Default)]
pub struct FlowAttributor {
    callback: Option<AttributeCallback>,
    invalidator: Option<InvalidateCallback>,
}

impl FlowAttributor {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn new(
        callback: impl Fn(IpTransport, SocketAddr, SocketAddr) -> io::Result<Option<FlowIdentity>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            callback: Some(Arc::new(callback)),
            invalidator: None,
        }
    }

    pub fn new_with_invalidator(
        callback: impl Fn(IpTransport, SocketAddr, SocketAddr) -> io::Result<Option<FlowIdentity>>
        + Send
        + Sync
        + 'static,
        invalidator: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Self {
            callback: Some(Arc::new(callback)),
            invalidator: Some(Arc::new(invalidator)),
        }
    }

    pub fn is_available(&self) -> bool {
        self.callback.is_some()
    }

    pub fn resolve(
        &self,
        transport: IpTransport,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<FlowIdentity>> {
        match &self.callback {
            Some(callback) => callback(transport, source, destination),
            None => Ok(None),
        }
    }

    /// Drop platform-side identity caches after an atomic application-policy reload.
    /// This never closes the TUN or an existing flow.
    pub fn invalidate(&self) {
        if let Some(invalidator) = &self.invalidator {
            invalidator();
        }
    }
}

impl fmt::Debug for FlowAttributor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowAttributor")
            .field("available", &self.is_available())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OutboundId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum RouteAction {
    Outbound(OutboundId),
    Direct,
    Block,
    Tor,
    I2p,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub exact_domains: Vec<String>,
    #[serde(default)]
    pub domain_suffixes: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub network: Option<NetworkType>,
    #[serde(default)]
    pub transport: Option<IpTransport>,
    pub action: RouteAction,
    /// Wall-clock deadline in milliseconds since the epoch. Once it passes the
    /// rule stops matching, so temporary blocks lapse without a policy reload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sink_builds_nothing_when_no_sink_is_installed() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // The data plane calls this on every refused flow, so a disabled sink must
        // not pay for cloning a destination and a package name.
        let built = Arc::new(AtomicUsize::new(0));
        let counter = built.clone();
        EventSink::none().emit_with(|| {
            counter.fetch_add(1, Ordering::Relaxed);
            CoreEvent::ConfigApplied {
                revision: 1,
                previous_revision: 0,
            }
        });
        assert_eq!(built.load(Ordering::Relaxed), 0);

        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let sink = EventSink::new(move |event| recorder.lock().unwrap().push(event));
        let counter = built.clone();
        sink.emit_with(|| {
            counter.fetch_add(1, Ordering::Relaxed);
            CoreEvent::ConfigApplied {
                revision: 7,
                previous_revision: 6,
            }
        });
        assert_eq!(built.load(Ordering::Relaxed), 1);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[CoreEvent::ConfigApplied {
                revision: 7,
                previous_revision: 6,
            }]
        );
    }

    #[test]
    fn ipv6_authority_is_bracketed() {
        assert_eq!(
            Destination::new("2001:db8::1", 443).authority(),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn flow_attributor_is_explicit_and_debug_safe() {
        let source = SocketAddr::from(([10, 0, 0, 2], 40000));
        let destination = SocketAddr::from(([203, 0, 113, 1], 443));
        let attributor =
            FlowAttributor::new(move |transport, actual_source, actual_destination| {
                assert_eq!(transport, IpTransport::Tcp);
                assert_eq!(actual_source, source);
                assert_eq!(actual_destination, destination);
                Ok(Some(FlowIdentity {
                    uid: 10_001,
                    packages: vec!["com.example".into()],
                    signing_digest: None,
                }))
            });

        assert!(attributor.is_available());
        assert_eq!(
            attributor
                .resolve(IpTransport::Tcp, source, destination)
                .unwrap()
                .unwrap()
                .uid,
            10_001
        );
        assert_eq!(
            format!("{attributor:?}"),
            "FlowAttributor { available: true }"
        );
    }
}
