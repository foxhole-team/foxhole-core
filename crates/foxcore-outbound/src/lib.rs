#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use foxcore_api::{
    ContinuityInterruption, ContinuityPermit, Destination, FlowContext, OutboundConfig,
};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{
    BoxDatagramSession, BoxStream, Datagram, datagram_channel, with_authenticated_peer,
};
#[cfg(feature = "anytls")]
use proto_anytls::AnyTlsOutbound;
#[cfg(feature = "http")]
use proto_http::HttpProxyOutbound;
#[cfg(feature = "hysteria2")]
use proto_hysteria2::Hysteria2Outbound;
#[cfg(feature = "i2p")]
use proto_i2p::I2pOutbound;
#[cfg(feature = "naive")]
use proto_naive::NaiveOutbound;
#[cfg(feature = "shadowsocks")]
use proto_shadowsocks::ShadowsocksOutbound;
#[cfg(feature = "shadowtls")]
use proto_shadowtls::ShadowTlsOutbound;
#[cfg(feature = "socks")]
use proto_socks::SocksOutbound;
#[cfg(feature = "tor")]
use proto_tor::{TorOutbound, TorTcpDialer};
#[cfg(feature = "trojan")]
use proto_trojan::TrojanOutbound;
#[cfg(feature = "tuic")]
use proto_tuic::TuicOutbound;
#[cfg(feature = "vless")]
use proto_vless::VlessOutbound;
#[cfg(feature = "vmess")]
use proto_vmess::VmessOutbound;

pub mod deferred;
#[cfg(feature = "wireguard")]
pub mod packet_tunnel;
pub mod selector;

pub use deferred::DeferredOutbound;
#[cfg(feature = "wireguard")]
pub use packet_tunnel::PacketTunnelOutbound;
pub use selector::SelectorOutbound;

/// How a profile moves traffic: as a proxied stream, or as raw IP packets.
///
/// This is the seam that keeps L3 protocols out of the proxy enum.
/// A packet tunnel carries its own routing/MTU/DNS contract and must never be
/// layered on a second userspace TCP stack.
pub enum OutboundMode {
    Proxy(Outbound),
    #[cfg(feature = "wireguard")]
    PacketTunnel(PacketTunnelOutbound),
}

impl OutboundMode {
    pub async fn from_config(config: OutboundConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        match config {
            OutboundConfig::Direct(_) => Ok(Self::Proxy(Outbound::direct(dialer))),
            #[cfg(feature = "wireguard")]
            OutboundConfig::Wireguard(config) => Ok(Self::PacketTunnel(
                PacketTunnelOutbound::wireguard(config, dialer)?,
            )),
            #[cfg(not(feature = "wireguard"))]
            OutboundConfig::Wireguard(_) => Err(feature_disabled("wireguard")),
            proxy => Ok(Self::Proxy(Outbound::from_config(proxy, dialer).await?)),
        }
    }

    pub fn proxy(outbound: Outbound) -> Self {
        Self::Proxy(outbound)
    }
}

impl OutboundKind {
    /// What a profile asks for, before anything is built.
    ///
    /// Needed because a build that fails still has to be filed under the right
    /// protocol: the registry's canonical-id rules and the overlay gates both
    /// read [`Outbound::kind`], and an unavailable Tor outbound that stopped
    /// being the Tor outbound would take the `.onion` gate down with it.
    pub fn of(config: &OutboundConfig) -> Self {
        match config {
            OutboundConfig::Direct(_) => Self::Direct,
            OutboundConfig::Vless(_) => Self::Vless,
            OutboundConfig::Vmess(_) => Self::Vmess,
            OutboundConfig::Hysteria2(_) => Self::Hysteria2,
            OutboundConfig::Tuic(_) => Self::Tuic,
            OutboundConfig::Trojan(_) => Self::Trojan,
            OutboundConfig::Shadowsocks(_) => Self::Shadowsocks,
            OutboundConfig::I2p(_) => Self::I2p,
            OutboundConfig::Tor(_) => Self::Tor,
            OutboundConfig::Selector(_) => Self::Selector,
            OutboundConfig::Socks(_) => Self::Socks,
            OutboundConfig::Http(_) => Self::Http,
            OutboundConfig::Naive(_) => Self::Naive,
            OutboundConfig::AnyTls(_) => Self::AnyTls,
            OutboundConfig::ShadowTls(_) => Self::ShadowTls,
            OutboundConfig::Wireguard(_) => Self::Wireguard,
        }
    }

    /// Stable identifier for telemetry. A `&'static str` rather than `Debug`,
    /// because the app keys traffic rows on this and a rename of the enum must
    /// not silently rename a field it reads.
    pub fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Wireguard => "wireguard",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::I2p => "i2p",
            Self::Tor => "tor",
            Self::Selector => "selector",
            Self::Socks => "socks",
            Self::Http => "http",
            Self::Naive => "naive",
            Self::AnyTls => "anytls",
            Self::ShadowTls => "shadowtls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Direct,
    /// An L3 packet tunnel. Never a value of [`Outbound::kind`] on a built
    /// outbound — a tunnel has no stream semantics and lives outside the enum —
    /// but a WireGuard profile that failed to build still has to say what it
    /// was, and the traffic map already labels its lane `wireguard`.
    Wireguard,
    Vless,
    Vmess,
    Hysteria2,
    Tuic,
    Trojan,
    Shadowsocks,
    I2p,
    Tor,
    Selector,
    Socks,
    Http,
    Naive,
    AnyTls,
    ShadowTls,
}

#[derive(Clone)]
pub enum Outbound {
    Direct(DirectOutbound),
    /// A configured outbound whose build failed, standing in for it.
    ///
    /// A variant rather than an absence from the registry, for the same reason
    /// [`Outbound::Selector`] is a variant: every caller that already handles
    /// an `Outbound` handles this for free, and the alternative — a lane that
    /// disappears when its build fails — makes its flows indistinguishable from
    /// flows a policy rule refused. See [`deferred`].
    Deferred(DeferredOutbound),
    /// A group of interchangeable proxy members. It is a variant rather than a
    /// registry concept so that every caller that already handles an `Outbound`
    /// — routing, DNS, the flow engine — handles a group for free.
    Selector(SelectorOutbound),
    #[cfg(feature = "vless")]
    Vless(VlessOutbound),
    #[cfg(feature = "vmess")]
    Vmess(VmessOutbound),
    #[cfg(feature = "hysteria2")]
    Hysteria2(Hysteria2Outbound),
    #[cfg(feature = "tuic")]
    Tuic(TuicOutbound),
    #[cfg(feature = "trojan")]
    Trojan(TrojanOutbound),
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(ShadowsocksOutbound),
    #[cfg(feature = "i2p")]
    I2p(I2pOutbound),
    #[cfg(feature = "tor")]
    Tor(TorOutbound),
    #[cfg(feature = "socks")]
    Socks(SocksOutbound),
    #[cfg(feature = "http")]
    Http(HttpProxyOutbound),
    #[cfg(feature = "naive")]
    Naive(NaiveOutbound),
    #[cfg(feature = "anytls")]
    AnyTls(AnyTlsOutbound),
    #[cfg(feature = "shadowtls")]
    ShadowTls(ShadowTlsOutbound),
}

/// Immutable outbound set used by one data-plane generation.
///
/// The primary outbound is addressable as `default` and `primary`; additional
/// IDs are exact, validated configuration keys.
/// Callback for [`OutboundRegistry::set_interruption_sink`].
pub type InterruptionSink = Arc<dyn Fn(ContinuityInterruption) -> ContinuityPermit + Send + Sync>;

#[derive(Clone)]
pub struct OutboundRegistry {
    default: Arc<Outbound>,
    named: Arc<HashMap<String, Arc<Outbound>>>,
    /// Set when `default` is only a stand-in for an L3 packet tunnel.
    ///
    /// The registry has to hold *something* under `default` — routing, DNS, the
    /// LAN ingress and the flow engine all assume one exists — but a packet
    /// tunnel has no stream semantics, so what it holds is a `direct` outbound
    /// that dials on a protected socket, outside the tunnel. Every consumer
    /// that can reach `default` therefore has to know it must not be handed
    /// out, and the flag lives here so the answer is the same everywhere
    /// instead of being re-derived per caller — which is how the DNS
    /// interceptor and the LAN proxy came to lack it.
    packet_tunnel_primary: bool,
}

impl OutboundRegistry {
    pub fn single(default: Arc<Outbound>) -> Self {
        Self {
            default,
            named: Arc::new(HashMap::new()),
            packet_tunnel_primary: false,
        }
    }

    pub fn new(default: Arc<Outbound>, named: HashMap<String, Arc<Outbound>>) -> io::Result<Self> {
        if named.keys().any(|id| {
            id.is_empty() || matches!(id.as_str(), "default" | "primary" | "direct" | "block")
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "named outbound registry contains an empty or reserved id",
            ));
        }
        for (id, outbound) in &named {
            if (id == "tor") != (outbound.kind() == OutboundKind::Tor) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a named Tor outbound must use exactly the canonical id 'tor'",
                ));
            }
            if (id == "i2p") != (outbound.kind() == OutboundKind::I2p) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a named I2P outbound must use exactly the canonical id 'i2p'",
                ));
            }
        }
        Ok(Self {
            default,
            named: Arc::new(named),
            packet_tunnel_primary: false,
        })
    }

    /// Mark `default` as the placeholder standing in for an L3 packet tunnel.
    ///
    /// A builder rather than a constructor argument so every existing caller
    /// keeps the answer it already had: a registry that is not marked has a real
    /// primary, which is the case for every proxy profile.
    #[must_use]
    pub fn with_packet_tunnel_primary(mut self) -> Self {
        self.packet_tunnel_primary = true;
        self
    }

    /// Whether [`Self::default`] is a clearnet placeholder rather than the
    /// primary outbound.
    ///
    /// Anything that would send a *flow* through the default must refuse when
    /// this is true. Reading the default's `kind()` cannot answer it — the
    /// placeholder is a genuine direct outbound and is indistinguishable from
    /// the primary of a profile that really is direct.
    pub fn primary_is_packet_tunnel(&self) -> bool {
        self.packet_tunnel_primary
    }

    pub fn default(&self) -> &Arc<Outbound> {
        &self.default
    }

    pub fn get(&self, id: &str) -> Option<&Arc<Outbound>> {
        match id {
            "default" | "primary" => Some(&self.default),
            id => self.named.get(id),
        }
    }

    pub fn tor(&self) -> Option<&Arc<Outbound>> {
        self.named
            .get("tor")
            .filter(|outbound| outbound.kind() == OutboundKind::Tor)
            .or_else(|| (self.default.kind() == OutboundKind::Tor).then_some(&self.default))
    }

    /// Publish a hidden service on the configured Tor outbound.
    ///
    /// Routed through the registry rather than exposed on the Tor client so the
    /// answer to "may this run" stays where every other such answer lives: no
    /// Tor outbound in the profile, no onion service. The caller gets an address
    /// and a queue of accepted streams — never something it could dial out with.
    ///
    /// A Tor lane whose build failed at start keeps its registry entry as a
    /// [`DeferredOutbound`] and fills the real outbound in behind it when a
    /// retry succeeds — the entry itself is never replaced. So this looks
    /// through the entry rather than at it: matching `Outbound::Tor` directly
    /// would refuse to publish over a Tor client that is up and carrying
    /// traffic, purely because it happened to arrive late.
    #[cfg(feature = "onion-service")]
    pub fn launch_onion_service(
        &self,
        nickname: &str,
        port: u16,
    ) -> io::Result<proto_tor::OnionService> {
        let Some(entry) = self.tor() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "publishing an onion service needs a Tor outbound in the profile",
            ));
        };
        // Held for the call: the built outbound lives behind the deferred
        // entry's `ArcSwap`, and a borrow of it may not outlive this `Arc`.
        let live = Outbound::behind(entry)?;
        let Outbound::Tor(tor) = live.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "publishing an onion service needs a Tor outbound in the profile",
            ));
        };
        tor.launch_onion_service(nickname, port)
    }

    pub fn i2p(&self) -> Option<&Arc<Outbound>> {
        self.named
            .get("i2p")
            .filter(|outbound| outbound.kind() == OutboundKind::I2p)
            .or_else(|| (self.default.kind() == OutboundKind::I2p).then_some(&self.default))
    }

    pub fn network_changed(&self) {
        self.default.network_changed();
        for outbound in self.named.values() {
            outbound.network_changed();
        }
    }

    /// Every entry that stands in for an outbound, whether or not it has since
    /// been filled.
    ///
    /// The retry pass and the snapshot both start here. Sorted by id so two
    /// snapshots taken a second apart do not differ by hash order alone.
    pub fn deferred(&self) -> Vec<DeferredOutbound> {
        let mut entries: Vec<DeferredOutbound> = std::iter::once(self.default.as_ref())
            .chain(self.named.values().map(Arc::as_ref))
            .filter_map(|outbound| match outbound {
                Outbound::Deferred(deferred) => Some(deferred.clone()),
                _ => None,
            })
            .collect();
        entries.sort_unstable_by(|left, right| left.id().cmp(right.id()));
        entries
    }

    /// The lanes that are not carrying traffic, and why.
    ///
    /// Empty for the ordinary case, so a screen can hide the row rather than
    /// draw one that always reads "nothing is wrong". A non-empty value means
    /// the engine started without part of the profile: those flows are refused
    /// with [`foxcore_api::BlockReason::LaneUnavailable`] and everything else
    /// is running.
    pub fn unavailable(&self) -> Vec<foxcore_api::OutboundUnavailable> {
        self.deferred()
            .into_iter()
            .filter(|deferred| !deferred.is_available())
            .map(|deferred| deferred.state())
            .collect()
    }

    /// Push contract for self-repair the core performed on its own.
    ///
    /// Replaces reading [`Self::reconnects`] and [`Self::selector_state`] on a
    /// timer: those answer "did anything change since last time", which costs a
    /// wakeup per tick on a phone whether or not anything did. The sink runs on
    /// the path that made the change, so it carries the same obligations as
    /// `EventSink` — it must not block, `.await`, or call the platform
    /// synchronously.
    ///
    /// Set once, at startup. Only the interruptions this crate can observe are
    /// pushed: `ProxySession` when a QUIC session is re-established underneath
    /// live flows, and `SelectorMember` when failover lands on a different node.
    pub fn set_interruption_sink(&self, sink: InterruptionSink) {
        self.default.install_interruption_sink(&sink);
        for outbound in self.named.values() {
            outbound.install_interruption_sink(&sink);
        }
    }

    pub fn reconnects(&self) -> u64 {
        self.named
            .values()
            .fold(self.default.reconnects(), |total, outbound| {
                total.saturating_add(outbound.reconnects())
            })
    }

    /// Which member each selector is currently sending through.
    ///
    /// Observed on a device: the selector picks correctly, urltest re-picks on
    /// its own schedule, and none of it is visible — the app shows the group
    /// name and the user has no way to learn which server their traffic is
    /// actually on, or that it moved. A selector nobody can observe is a
    /// selector nobody can trust.
    ///
    /// The default outbound is included under its config tag when it is itself
    /// a selector, because "the default" is exactly the case a user is most
    /// likely to be looking at.
    pub fn selector_state(&self) -> Vec<(&str, &str)> {
        let mut state = Vec::new();
        if let Outbound::Selector(selector) = self.default.as_ref() {
            // Named "default" rather than left out: it is the outbound a user
            // is most likely looking at, and omitting it would make an empty
            // list mean both "no selectors" and "only the default is one".
            state.push(("default", selector.active_id()));
        }
        for (tag, outbound) in self.named.iter() {
            if let Outbound::Selector(selector) = outbound.as_ref() {
                state.push((tag.as_str(), selector.active_id()));
            }
        }
        state.sort_unstable_by_key(|(tag, _)| *tag);
        state
    }

    pub fn len(&self) -> usize {
        1 + self.named.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

impl Outbound {
    /// The outbound a registry entry actually is right now.
    ///
    /// Every entry is itself, except a lane whose build failed at start: that
    /// one stays a [`DeferredOutbound`] in the registry forever and holds the
    /// real outbound behind it once a retry succeeds. Anything that matches on
    /// the entry's variant instead of asking this will refuse a lane that
    /// recovered — it is still `Deferred` from the outside, and reads as
    /// missing.
    ///
    /// `Err` for an entry that has not been filled in: the same
    /// [`DeferredOutbound::error`] the flow path refuses with, so "the lane is
    /// down" and "there is no such lane" stay different sentences.
    ///
    /// One level, like the unwrap in [`Outbound::connect_stream`]: a deferred
    /// entry never resolves to another deferred one.
    pub fn behind(entry: &Arc<Self>) -> io::Result<Arc<Self>> {
        match entry.as_ref() {
            Self::Deferred(deferred) => deferred.resolved().ok_or_else(|| deferred.error()),
            _ => Ok(entry.clone()),
        }
    }

    pub async fn from_config(config: OutboundConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        Self::from_config_with_interruption_sink(config, dialer, None).await
    }

    pub async fn from_config_with_interruption_sink(
        config: OutboundConfig,
        dialer: ProtectedDialer,
        interruption: Option<InterruptionSink>,
    ) -> io::Result<Self> {
        foxcore_transport::ensure_process_crypto_provider()?;
        let interruption = interruption.as_ref();
        match config {
            OutboundConfig::Direct(_) => Ok(Outbound::direct(dialer)),
            OutboundConfig::Vless(config) => build_vless(config, dialer).await,
            OutboundConfig::Vmess(config) => build_vmess(config, dialer).await,
            OutboundConfig::Hysteria2(config) => {
                build_hysteria2(config, dialer, interruption).await
            }
            OutboundConfig::Tuic(config) => build_tuic(config, dialer, interruption).await,
            OutboundConfig::Trojan(config) => build_trojan(config, dialer).await,
            OutboundConfig::Shadowsocks(config) => build_shadowsocks(config, dialer).await,
            OutboundConfig::I2p(config) => build_i2p(config, dialer).await,
            OutboundConfig::Tor(config) => build_tor(config, dialer).await,
            OutboundConfig::Selector(config) => Ok(Outbound::Selector(
                SelectorOutbound::new_with_interruption_sink(
                    config,
                    dialer,
                    interruption.cloned(),
                )?,
            )),
            OutboundConfig::Socks(config) => build_socks(config, dialer).await,
            OutboundConfig::Http(config) => build_http(config, dialer).await,
            OutboundConfig::Naive(config) => build_naive(config, dialer).await,
            OutboundConfig::AnyTls(config) => build_anytls(config, dialer).await,
            OutboundConfig::ShadowTls(config) => build_shadowtls(config, dialer).await,
            // Not a downgrade path: an L3 tunnel has no stream semantics, so the
            // only honest answer is to refuse and let the caller use
            // `OutboundMode`.
            OutboundConfig::Wireguard(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WireGuard is a packet tunnel and cannot be used as a proxy outbound",
            )),
        }
    }

    pub fn direct(dialer: ProtectedDialer) -> Self {
        Self::Direct(DirectOutbound { dialer })
    }

    pub fn kind(&self) -> OutboundKind {
        match self {
            Self::Direct(_) => OutboundKind::Direct,
            // The kind the profile asked for, built or not. See
            // [`DeferredOutbound::kind`] for why this must not read "unknown".
            Self::Deferred(outbound) => outbound.kind(),
            Self::Selector(_) => OutboundKind::Selector,
            #[cfg(feature = "socks")]
            Self::Socks(_) => OutboundKind::Socks,
            #[cfg(feature = "http")]
            Self::Http(_) => OutboundKind::Http,
            #[cfg(feature = "naive")]
            Self::Naive(_) => OutboundKind::Naive,
            #[cfg(feature = "anytls")]
            Self::AnyTls(_) => OutboundKind::AnyTls,
            #[cfg(feature = "shadowtls")]
            Self::ShadowTls(_) => OutboundKind::ShadowTls,
            #[cfg(feature = "vless")]
            Self::Vless(_) => OutboundKind::Vless,
            #[cfg(feature = "vmess")]
            Self::Vmess(_) => OutboundKind::Vmess,
            #[cfg(feature = "hysteria2")]
            Self::Hysteria2(_) => OutboundKind::Hysteria2,
            #[cfg(feature = "tuic")]
            Self::Tuic(_) => OutboundKind::Tuic,
            #[cfg(feature = "trojan")]
            Self::Trojan(_) => OutboundKind::Trojan,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => OutboundKind::Shadowsocks,
            #[cfg(feature = "i2p")]
            Self::I2p(_) => OutboundKind::I2p,
            #[cfg(feature = "tor")]
            Self::Tor(_) => OutboundKind::Tor,
        }
    }

    pub async fn connect_stream(
        &self,
        context: &FlowContext,
        destination: Destination,
    ) -> io::Result<BoxStream> {
        let resolved;
        let target = match self {
            // Exactly one level of indirection, unrolled by hand. A deferred
            // entry never resolves to another deferred one, so this terminates;
            // writing it as recursion would make the future recursive and force
            // it to be boxed, which is the cost `connect_leaf_stream` exists to
            // avoid.
            Self::Deferred(deferred) => match deferred.resolved() {
                Some(outbound) => {
                    resolved = outbound;
                    resolved.as_ref()
                }
                None => return Err(deferred.error()),
            },
            outbound => outbound,
        };
        match target {
            Self::Selector(outbound) => outbound.connect_stream(context, destination).await,
            leaf => leaf.connect_leaf_stream(context, destination).await,
        }
    }

    /// Connect through an outbound that is known not to be a group.
    ///
    /// A selector reaches its members through this instead of
    /// [`Outbound::connect_stream`], which is what keeps the two from being
    /// mutually recursive. Config validation already refuses a selector inside
    /// a selector; routing the member call here is how that refusal becomes
    /// something the compiler can see, so neither future has to be boxed.
    pub(crate) async fn connect_leaf_stream(
        &self,
        _context: &FlowContext,
        destination: Destination,
    ) -> io::Result<BoxStream> {
        match self {
            Self::Direct(outbound) => outbound.connect_stream(&destination).await,
            // Reached only for an entry that is still unavailable —
            // [`Outbound::connect_stream`] unwraps a resolved one before it
            // gets here — and for the case config validation already forbids, a
            // group member that is itself a registry entry.
            Self::Deferred(deferred) => Err(deferred.error()),
            Self::Selector(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a selector must not be a member of a selector",
            )),
            #[cfg(feature = "vless")]
            Self::Vless(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "vmess")]
            Self::Vmess(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "hysteria2")]
            Self::Hysteria2(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "tuic")]
            Self::Tuic(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "trojan")]
            Self::Trojan(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "i2p")]
            Self::I2p(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "tor")]
            Self::Tor(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "socks")]
            Self::Socks(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "http")]
            Self::Http(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "naive")]
            Self::Naive(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "anytls")]
            Self::AnyTls(outbound) => outbound.connect_stream(&destination).await,
            #[cfg(feature = "shadowtls")]
            Self::ShadowTls(outbound) => outbound.connect_stream(&destination).await,
        }
    }

    pub async fn connect_datagram(&self, context: &FlowContext) -> io::Result<BoxDatagramSession> {
        let resolved;
        // Same one-level unwrap as `connect_stream`, same reason.
        let target = match self {
            Self::Deferred(deferred) => match deferred.resolved() {
                Some(outbound) => {
                    resolved = outbound;
                    resolved.as_ref()
                }
                None => return Err(deferred.error()),
            },
            outbound => outbound,
        };
        match target {
            Self::Selector(outbound) => outbound.connect_datagram(context).await,
            leaf => leaf.connect_leaf_datagram(context).await,
        }
    }

    /// See [`Outbound::connect_leaf_stream`]: same reason, datagram side.
    pub(crate) async fn connect_leaf_datagram(
        &self,
        context: &FlowContext,
    ) -> io::Result<BoxDatagramSession> {
        match self {
            Self::Direct(outbound) => outbound.connect_datagram(&context.destination).await,
            Self::Deferred(deferred) => Err(deferred.error()),
            Self::Selector(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a selector must not be a member of a selector",
            )),
            #[cfg(feature = "vless")]
            Self::Vless(outbound) => {
                outbound
                    .connect_datagram(&context.destination, context.source)
                    .await
            }
            #[cfg(feature = "vmess")]
            Self::Vmess(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "hysteria2")]
            Self::Hysteria2(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "tuic")]
            Self::Tuic(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "trojan")]
            Self::Trojan(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "i2p")]
            Self::I2p(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "tor")]
            Self::Tor(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "socks")]
            Self::Socks(outbound) => outbound.connect_datagram(&context.destination).await,
            // TCP-only by protocol: the crate refuses rather than degrading.
            #[cfg(feature = "http")]
            Self::Http(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "naive")]
            Self::Naive(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "anytls")]
            Self::AnyTls(outbound) => outbound.connect_datagram(&context.destination).await,
            #[cfg(feature = "shadowtls")]
            Self::ShadowTls(outbound) => outbound.connect_datagram(&context.destination).await,
        }
    }

    pub fn network_changed(&self) {
        match self {
            #[cfg(feature = "hysteria2")]
            Self::Hysteria2(outbound) => outbound.network_changed(),
            #[cfg(feature = "tuic")]
            Self::Tuic(outbound) => outbound.network_changed(),
            #[cfg(feature = "tor")]
            Self::Tor(outbound) => outbound.network_changed(),
            Self::Selector(outbound) => outbound.network_changed(),
            // A network change is also the commonest reason an outbound that
            // could not be built now can be. The rebuild itself is not started
            // here — this call is synchronous and a bootstrap is not — it is
            // driven by the runtime's retry pass, which runs on the same event.
            Self::Deferred(deferred) => {
                if let Some(outbound) = deferred.resolved() {
                    outbound.network_changed();
                }
            }
            Self::Direct(_) => {}
            #[cfg(feature = "vless")]
            Self::Vless(_) => {}
            #[cfg(feature = "vmess")]
            Self::Vmess(_) => {}
            #[cfg(feature = "trojan")]
            Self::Trojan(_) => {}
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => {}
            #[cfg(feature = "i2p")]
            Self::I2p(_) => {}
            #[cfg(feature = "socks")]
            Self::Socks(_) => {}
            #[cfg(feature = "http")]
            Self::Http(_) => {}
            #[cfg(feature = "naive")]
            Self::Naive(_) => {}
            #[cfg(feature = "anytls")]
            Self::AnyTls(outbound) => outbound.network_changed(),
            #[cfg(feature = "shadowtls")]
            Self::ShadowTls(_) => {}
        }
    }

    /// Hand the sink to whatever inside this outbound can repair itself.
    ///
    /// Outbounds with no session to lose are silently skipped: there is no
    /// event for them to miss.
    pub(crate) fn install_interruption_sink(&self, sink: &InterruptionSink) {
        match self {
            Self::Selector(outbound) => outbound.set_interruption_sink(sink.clone()),
            // Kept, not dropped: the sink is installed once at start, and an
            // outbound built minutes later would otherwise be the one whose
            // self-repair nobody hears about.
            Self::Deferred(deferred) => deferred.install_interruption_sink(sink),
            #[cfg(feature = "hysteria2")]
            Self::Hysteria2(outbound) => {
                let sink = sink.clone();
                outbound.set_reconnect_hook(Arc::new(move || {
                    sink(ContinuityInterruption::ProxySession)
                }));
            }
            #[cfg(feature = "tuic")]
            Self::Tuic(outbound) => {
                let sink = sink.clone();
                outbound.set_reconnect_hook(Arc::new(move || {
                    sink(ContinuityInterruption::ProxySession)
                }));
            }
            _ => {}
        }
    }

    pub fn reconnects(&self) -> u64 {
        match self {
            #[cfg(feature = "hysteria2")]
            Self::Hysteria2(outbound) => outbound.reconnects(),
            #[cfg(feature = "tuic")]
            Self::Tuic(outbound) => outbound.reconnects(),
            Self::Selector(outbound) => outbound.reconnects(),
            Self::Deferred(deferred) => deferred
                .resolved()
                .map_or(0, |outbound| outbound.reconnects()),
            Self::Direct(_) => 0,
            #[cfg(feature = "vless")]
            Self::Vless(_) => 0,
            #[cfg(feature = "vmess")]
            Self::Vmess(_) => 0,
            #[cfg(feature = "trojan")]
            Self::Trojan(_) => 0,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => 0,
            #[cfg(feature = "i2p")]
            Self::I2p(_) => 0,
            #[cfg(feature = "tor")]
            Self::Tor(_) => 0,
            #[cfg(feature = "socks")]
            Self::Socks(_) => 0,
            #[cfg(feature = "http")]
            Self::Http(_) => 0,
            #[cfg(feature = "naive")]
            Self::Naive(_) => 0,
            #[cfg(feature = "anytls")]
            Self::AnyTls(_) => 0,
            #[cfg(feature = "shadowtls")]
            Self::ShadowTls(_) => 0,
        }
    }
}

#[cfg(feature = "vless")]
async fn build_vless(
    config: foxcore_api::VlessConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Vless(VlessOutbound::new(config, dialer).await?))
}

#[cfg(feature = "vmess")]
async fn build_vmess(
    config: foxcore_api::VmessConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Vmess(VmessOutbound::new(config, dialer).await?))
}

#[cfg(not(feature = "vmess"))]
async fn build_vmess(
    _config: foxcore_api::VmessConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("vmess"))
}

#[cfg(not(feature = "vless"))]
async fn build_vless(
    _config: foxcore_api::VlessConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("vless"))
}

#[cfg(feature = "hysteria2")]
async fn build_hysteria2(
    config: foxcore_api::Hysteria2Config,
    dialer: ProtectedDialer,
    interruption: Option<&InterruptionSink>,
) -> io::Result<Outbound> {
    let reconnect_hook = interruption.map(|sink| {
        let sink = sink.clone();
        Arc::new(move || sink(ContinuityInterruption::ProxySession))
            as Arc<dyn Fn() -> ContinuityPermit + Send + Sync>
    });
    Ok(Outbound::Hysteria2(
        Hysteria2Outbound::new_with_reconnect_hook(config, dialer, reconnect_hook).await?,
    ))
}

#[cfg(not(feature = "hysteria2"))]
async fn build_hysteria2(
    _config: foxcore_api::Hysteria2Config,
    _dialer: ProtectedDialer,
    _interruption: Option<&InterruptionSink>,
) -> io::Result<Outbound> {
    Err(feature_disabled("hysteria2"))
}

#[cfg(feature = "tuic")]
async fn build_tuic(
    config: foxcore_api::TuicConfig,
    dialer: ProtectedDialer,
    interruption: Option<&InterruptionSink>,
) -> io::Result<Outbound> {
    let reconnect_hook = interruption.map(|sink| {
        let sink = sink.clone();
        Arc::new(move || sink(ContinuityInterruption::ProxySession))
            as Arc<dyn Fn() -> ContinuityPermit + Send + Sync>
    });
    Ok(Outbound::Tuic(
        TuicOutbound::new_with_reconnect_hook(config, dialer, reconnect_hook).await?,
    ))
}

#[cfg(not(feature = "tuic"))]
async fn build_tuic(
    _config: foxcore_api::TuicConfig,
    _dialer: ProtectedDialer,
    _interruption: Option<&InterruptionSink>,
) -> io::Result<Outbound> {
    Err(feature_disabled("tuic"))
}

#[cfg(feature = "trojan")]
async fn build_trojan(
    config: foxcore_api::TrojanConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Trojan(TrojanOutbound::new(config, dialer).await?))
}

#[cfg(not(feature = "trojan"))]
async fn build_trojan(
    _config: foxcore_api::TrojanConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("trojan"))
}

#[cfg(feature = "shadowsocks")]
async fn build_shadowsocks(
    config: foxcore_api::ShadowsocksConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Shadowsocks(
        ShadowsocksOutbound::new(config, dialer).await?,
    ))
}

#[cfg(not(feature = "shadowsocks"))]
async fn build_shadowsocks(
    _config: foxcore_api::ShadowsocksConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("shadowsocks"))
}

#[cfg(feature = "i2p")]
async fn build_i2p(
    config: foxcore_api::I2pConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::I2p(I2pOutbound::new(config)?))
}

#[cfg(not(feature = "i2p"))]
async fn build_i2p(
    _config: foxcore_api::I2pConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("i2p"))
}

#[cfg(feature = "tor")]
async fn build_tor(
    mut config: foxcore_api::TorConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    let tor_dialer = if let Some(upstream_config) = config.upstream.take() {
        build_tor_upstream_dialer(*upstream_config, dialer).await?
    } else {
        TorTcpDialer::protected(dialer)
    };
    Ok(Outbound::Tor(TorOutbound::new(config, tor_dialer).await?))
}

#[cfg(feature = "tor")]
async fn build_tor_upstream_dialer(
    config: OutboundConfig,
    dialer: ProtectedDialer,
) -> io::Result<TorTcpDialer> {
    foxcore_transport::ensure_process_crypto_provider()?;
    let outbound = match config {
        OutboundConfig::Vless(config) => build_vless(config, dialer).await,
        OutboundConfig::Vmess(config) => build_vmess(config, dialer).await,
        OutboundConfig::Hysteria2(config) => build_hysteria2(config, dialer, None).await,
        OutboundConfig::Tuic(config) => build_tuic(config, dialer, None).await,
        OutboundConfig::Trojan(config) => build_trojan(config, dialer).await,
        OutboundConfig::Shadowsocks(config) => build_shadowsocks(config, dialer).await,
        OutboundConfig::Socks(config) => build_socks(config, dialer).await,
        OutboundConfig::Http(config) => build_http(config, dialer).await,
        OutboundConfig::Naive(config) => build_naive(config, dialer).await,
        OutboundConfig::AnyTls(config) => build_anytls(config, dialer).await,
        OutboundConfig::ShadowTls(config) => build_shadowtls(config, dialer).await,
        OutboundConfig::Direct(_)
        | OutboundConfig::I2p(_)
        | OutboundConfig::Tor(_)
        | OutboundConfig::Wireguard(_)
        | OutboundConfig::Selector(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Tor upstream must be a stream proxy",
        )),
    }?;
    tor_dialer_from_leaf(outbound)
}

#[cfg(feature = "tor")]
fn tor_dialer_from_leaf(outbound: Outbound) -> io::Result<TorTcpDialer> {
    macro_rules! leaf_dialer {
        ($leaf:ident) => {{
            let leaf = Arc::new($leaf);
            TorTcpDialer::new(move |address| {
                let leaf = leaf.clone();
                async move {
                    let destination = Destination::new(address.ip().to_string(), address.port());
                    leaf.connect_stream(&destination).await
                }
            })
        }};
    }

    let dialer = match outbound {
        #[cfg(feature = "vless")]
        Outbound::Vless(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "vmess")]
        Outbound::Vmess(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "hysteria2")]
        Outbound::Hysteria2(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "tuic")]
        Outbound::Tuic(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "trojan")]
        Outbound::Trojan(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "shadowsocks")]
        Outbound::Shadowsocks(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "socks")]
        Outbound::Socks(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "http")]
        Outbound::Http(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "naive")]
        Outbound::Naive(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "anytls")]
        Outbound::AnyTls(leaf) => leaf_dialer!(leaf),
        #[cfg(feature = "shadowtls")]
        Outbound::ShadowTls(leaf) => leaf_dialer!(leaf),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Tor upstream must be a concrete stream proxy",
            ));
        }
    };
    Ok(dialer)
}

#[cfg(not(feature = "tor"))]
async fn build_tor(
    _config: foxcore_api::TorConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("tor"))
}

#[cfg(feature = "socks")]
async fn build_socks(
    config: foxcore_api::SocksConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Socks(SocksOutbound::new(config, dialer).await?))
}

#[cfg(not(feature = "socks"))]
async fn build_socks(
    _config: foxcore_api::SocksConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("socks"))
}

#[cfg(feature = "http")]
async fn build_http(
    config: foxcore_api::HttpProxyConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Http(
        HttpProxyOutbound::new(config, dialer).await?,
    ))
}

#[cfg(not(feature = "http"))]
async fn build_http(
    _config: foxcore_api::HttpProxyConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("http"))
}

#[cfg(feature = "naive")]
async fn build_naive(
    config: foxcore_api::NaiveConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::Naive(NaiveOutbound::new(config, dialer).await?))
}

#[cfg(not(feature = "naive"))]
async fn build_naive(
    _config: foxcore_api::NaiveConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("naive"))
}

#[cfg(feature = "anytls")]
async fn build_anytls(
    config: foxcore_api::AnyTlsConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::AnyTls(AnyTlsOutbound::new(config, dialer).await?))
}

#[cfg(not(feature = "anytls"))]
async fn build_anytls(
    _config: foxcore_api::AnyTlsConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("anytls"))
}

#[cfg(feature = "shadowtls")]
async fn build_shadowtls(
    config: foxcore_api::ShadowTlsConfig,
    dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Ok(Outbound::ShadowTls(
        ShadowTlsOutbound::new(config, dialer).await?,
    ))
}

#[cfg(not(feature = "shadowtls"))]
async fn build_shadowtls(
    _config: foxcore_api::ShadowTlsConfig,
    _dialer: ProtectedDialer,
) -> io::Result<Outbound> {
    Err(feature_disabled("shadowtls"))
}

#[cfg(not(all(
    feature = "vless",
    feature = "vmess",
    feature = "hysteria2",
    feature = "tuic",
    feature = "trojan",
    feature = "shadowsocks",
    feature = "i2p",
    feature = "tor",
    feature = "socks",
    feature = "http",
    feature = "naive",
    feature = "anytls",
    feature = "shadowtls"
)))]
fn feature_disabled(protocol: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{protocol} support is not compiled into this FoxCore build"),
    )
}

#[derive(Clone)]
pub struct DirectOutbound {
    dialer: ProtectedDialer,
}

impl DirectOutbound {
    async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        Ok(Box::new(
            self.dialer
                .connect_tcp_server(&destination.host, destination.port, None)
                .await?,
        ))
    }

    async fn connect_datagram(&self, destination: &Destination) -> io::Result<BoxDatagramSession> {
        // One datagram session belongs to one flow and therefore one remote.
        // Connect the socket to the address resolved for that flow instead of
        // receiving from an unconnected wildcard socket. Besides surfacing
        // peer errors correctly, this makes the kernel discard datagrams from
        // every other source. That source pin is security-critical for a DNS
        // upstream configured by hostname: transaction IDs are observable on a
        // shared network and are not an authentication mechanism.
        let (socket, pinned_address) = self
            .dialer
            .connect_udp_server_with_address(&destination.host, destination.port, None)
            .await?;
        let (session, mut channels) = datagram_channel(64);
        let session = with_authenticated_peer(
            session,
            Destination::new(pinned_address.ip().to_string(), pinned_address.port()),
        );
        let default_destination = destination.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_536];
            loop {
                tokio::select! {
                    _ = channels.cancel.cancelled() => break,
                    outgoing = channels.uplink.recv() => {
                        let Some(outgoing) = outgoing else { break };
                        let destination = if outgoing.destination.host.is_empty() {
                            &default_destination
                        } else {
                            &outgoing.destination
                        };
                        if destination != &default_destination {
                            // A session is connected and source-pinned for one
                            // flow. Silently sending a different destination to
                            // that peer would be data corruption; opening a new
                            // session is the caller's responsibility.
                            continue;
                        }
                        if socket.send(&outgoing.payload).await.is_err() {
                            break;
                        }
                    }
                    received = socket.recv(&mut buffer) => {
                        let Ok(length) = received else { break };
                        let datagram = Datagram::new(
                            Destination::new(
                                pinned_address.ip().to_string(),
                                pinned_address.port(),
                            ),
                            Bytes::copy_from_slice(&buffer[..length]),
                        );
                        if channels.downlink.send(datagram).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "i2p")]
    use foxcore_api::I2pConfig;
    use foxcore_api::IpTransport;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A registry entry that stood in for a failed build and was filled in
    /// later. The lane recovered; the entry did not change shape, and anything
    /// that matches on the variant sees a lane that is still missing.
    fn deferred_tor_entry() -> DeferredOutbound {
        DeferredOutbound::new(
            "tor",
            OutboundKind::Tor,
            OutboundConfig::Tor(foxcore_api::TorConfig {
                state_dir: "/nonexistent/tor/state".into(),
                cache_dir: "/nonexistent/tor/cache".into(),
                upstream: None,
                bootstrap_timeout_s: 1,
                stream_connect_timeout_s: 1,
                isolate_streams: true,
                circuit: Default::default(),
                bridges: Vec::new(),
                transports: Vec::new(),
            }),
            &io::Error::new(io::ErrorKind::TimedOut, "Arti bootstrap timed out"),
        )
    }

    #[test]
    fn a_lane_that_recovered_is_looked_through_rather_than_matched_on() {
        let deferred = deferred_tor_entry();
        let entry: Arc<Outbound> = Arc::new(Outbound::Deferred(deferred.clone()));

        let Err(down) = Outbound::behind(&entry) else {
            panic!("the lane has not come back yet and must be refused");
        };
        assert_eq!(
            down.kind(),
            io::ErrorKind::NotConnected,
            "a lane that is down is not a lane that was never configured"
        );

        deferred.begin_attempt();
        deferred.resolve(Outbound::direct(ProtectedDialer::host()));

        let Ok(live) = Outbound::behind(&entry) else {
            panic!("the entry has been filled in and must resolve");
        };
        assert!(
            matches!(live.as_ref(), Outbound::Direct(_)),
            "the entry is still Deferred from the outside; what is behind it is the outbound"
        );
    }

    /// Publishing over a Tor lane that came back late.
    ///
    /// The registry entry stays `Deferred` for the life of the generation, so
    /// matching `Outbound::Tor` on it refuses to publish while Tor is up and
    /// carrying traffic. Reaching a real hidden service needs a bootstrapped
    /// Arti, which no test here has; what is asserted instead is that the
    /// deferred entry is *seen* — a lane that is down is refused as down, in
    /// its own words, rather than as a profile with no Tor outbound in it.
    #[cfg(feature = "onion-service")]
    #[tokio::test]
    async fn publishing_over_a_deferred_tor_lane_reports_the_lane_not_a_missing_profile() {
        let deferred = deferred_tor_entry();
        let registry = OutboundRegistry::new(
            Arc::new(Outbound::direct(ProtectedDialer::host())),
            HashMap::from([(
                "tor".to_owned(),
                Arc::new(Outbound::Deferred(deferred.clone())),
            )]),
        )
        .expect("a deferred Tor entry keeps the canonical id");

        let Err(refused) = registry.launch_onion_service("fox", 80) else {
            panic!("Tor is not up, so nothing can be published on it");
        };
        assert_eq!(
            refused.kind(),
            io::ErrorKind::NotConnected,
            "the lane is down and says so; Unsupported would send the user looking for a \
             configuration mistake that is not there: {refused}"
        );
        assert!(
            refused.to_string().contains("unavailable"),
            "and it is the lane's own refusal, the one the flow path uses: {refused}"
        );
    }

    #[cfg(feature = "shadowsocks")]
    #[tokio::test]
    async fn the_registry_reports_which_member_each_selector_is_on() {
        use foxcore_api::{
            NamedOutboundConfig, OutboundId, SecretString, SelectorConfig, ShadowsocksConfig,
        };

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

        let selector = |default: &str| SelectorConfig {
            members: vec![member("tokyo", 1080), member("berlin", 1081)],
            default: Some(OutboundId(default.into())),
            member_timeout_ms: None,
            probe: None,
        };

        let default = Arc::new(
            Outbound::from_config(
                OutboundConfig::Selector(selector("berlin")),
                ProtectedDialer::host(),
            )
            .await
            .unwrap(),
        );
        let mut named = HashMap::new();
        named.insert(
            "overlay".to_owned(),
            Arc::new(
                Outbound::from_config(
                    OutboundConfig::Selector(selector("tokyo")),
                    ProtectedDialer::host(),
                )
                .await
                .unwrap(),
            ),
        );
        named.insert(
            "plain".to_owned(),
            Arc::new(Outbound::direct(ProtectedDialer::host())),
        );

        let registry = OutboundRegistry::new(default, named).unwrap();
        assert_eq!(
            registry.selector_state(),
            vec![("default", "berlin"), ("overlay", "tokyo")],
            "a non-selector outbound must not appear, and the default must"
        );
    }

    #[tokio::test]
    async fn a_config_without_selectors_reports_nothing_rather_than_an_empty_group() {
        let registry =
            OutboundRegistry::single(Arc::new(Outbound::direct(ProtectedDialer::host())));
        assert!(registry.selector_state().is_empty());
    }

    #[tokio::test]
    async fn direct_tcp_uses_the_same_outbound_api() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let byte = stream.read_u8().await.unwrap();
            stream.write_u8(byte + 1).await.unwrap();
        });
        let destination = Destination::new(address.ip().to_string(), address.port());
        let context = FlowContext::new(1, IpTransport::Tcp, destination.clone());
        let outbound = Outbound::direct(ProtectedDialer::host());
        assert_eq!(outbound.kind(), OutboundKind::Direct);
        let mut stream = outbound
            .connect_stream(&context, destination)
            .await
            .unwrap();
        stream.write_u8(7).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 8);
        server.await.unwrap();
    }

    /// A hostname must not erase the source address enforced by direct UDP.
    /// The DNS layer consumes this numeric marker when deciding whether a
    /// response is allowed to satisfy a query.
    #[tokio::test]
    async fn direct_udp_exports_the_numeric_peer_resolved_for_a_hostname() {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let dialer = ProtectedDialer::new(
            foxcore_dialer::SocketCallbacks::none().with_resolver(move |host, port, network| {
                assert_eq!(host, "resolver.test");
                assert_eq!(port, address.port());
                assert_eq!(network, 7);
                Ok(vec![address])
            }),
            std::time::Duration::from_secs(1),
        );
        dialer.set_network_handle(7);
        let destination = Destination::new("resolver.test", address.port());
        let context = FlowContext::new(1, IpTransport::Udp, destination.clone());
        let outbound = Outbound::direct(dialer);

        let session = outbound.connect_datagram(&context).await.unwrap();
        assert_eq!(
            session.authenticated_peer(),
            Some(Destination::new(address.ip().to_string(), address.port())),
            "the hostname's chosen address must remain attached to the session"
        );

        session
            .send(Datagram::new(
                destination,
                Bytes::from_static(b"source-pinned"),
            ))
            .await
            .unwrap();
        let mut payload = [0_u8; 32];
        let (length, peer) = upstream.recv_from(&mut payload).await.unwrap();
        assert_eq!(&payload[..length], b"source-pinned");
        upstream.send_to(b"answer", peer).await.unwrap();
        assert_eq!(session.recv().await.unwrap().payload, b"answer"[..]);
    }

    #[cfg(feature = "i2p")]
    #[tokio::test]
    async fn registry_exposes_only_the_canonical_i2p_outbound() {
        let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let i2p = Arc::new(
            Outbound::from_config(
                OutboundConfig::I2p(I2pConfig {
                    socks_address: "127.0.0.1:4447".parse().unwrap(),
                    username: None,
                    password: None,
                    connect_timeout_ms: 1_000,
                    handshake_timeout_ms: 1_000,
                }),
                ProtectedDialer::host(),
            )
            .await
            .unwrap(),
        );
        let registry =
            OutboundRegistry::new(default, HashMap::from([("i2p".to_owned(), i2p.clone())]))
                .unwrap();

        assert!(Arc::ptr_eq(registry.i2p().unwrap(), &i2p));
        assert_eq!(registry.i2p().unwrap().kind(), OutboundKind::I2p);
    }

    #[cfg(feature = "wireguard")]
    fn wireguard_config() -> foxcore_api::WireguardConfig {
        foxcore_api::WireguardConfig {
            server: "edge.example".into(),
            port: 51820,
            server_ip: Some("192.0.2.10".parse().unwrap()),
            private_key: foxcore_api::SecretString::new(
                "l40T7xeXzdV13X8f/1IjcRR0wbrACb0bebRqcN01mbQ=",
            ),
            peer_public_key: foxcore_api::SecretString::new(
                "/94rCPHnchHT/rfGYWR3oBaNKtGcelLi4ainYamMiTc=",
            ),
            preshared_key: None,
            address: vec!["10.8.0.2/32".parse().unwrap()],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            mtu: 1420,
            persistent_keepalive_s: Some(25),
            reserved: None,
            amnezia: None,
        }
    }

    #[cfg(feature = "wireguard")]
    #[tokio::test]
    async fn a_wireguard_profile_builds_a_packet_tunnel_and_never_a_proxy_outbound() {
        let mode = OutboundMode::from_config(
            OutboundConfig::Wireguard(wireguard_config()),
            ProtectedDialer::host(),
        )
        .await
        .expect("a wireguard profile must build");
        assert!(matches!(mode, OutboundMode::PacketTunnel(_)));

        assert!(
            Outbound::from_config(
                OutboundConfig::Wireguard(wireguard_config()),
                ProtectedDialer::host(),
            )
            .await
            .is_err(),
            "an L3 tunnel must not be reachable through the proxy enum"
        );
    }

    #[tokio::test]
    async fn a_proxy_profile_still_builds_a_proxy_mode() {
        let mode = OutboundMode::proxy(Outbound::direct(ProtectedDialer::host()));
        assert!(matches!(mode, OutboundMode::Proxy(_)));
    }

    #[test]
    fn registry_resolves_primary_alias_and_named_outbound() {
        let default = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let backup = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let registry =
            OutboundRegistry::new(default.clone(), HashMap::from([("backup".into(), backup)]))
                .unwrap();

        assert!(Arc::ptr_eq(registry.get("default").unwrap(), &default));
        assert!(Arc::ptr_eq(registry.get("primary").unwrap(), &default));
        assert!(registry.get("backup").is_some());
        assert!(registry.get("missing").is_none());
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
    }
}
