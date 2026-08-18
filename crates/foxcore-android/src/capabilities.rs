use std::sync::OnceLock;

use foxcore_api::{
    CAPABILITIES_SCHEMA_VERSION, CORE_ABI_VERSION, CORE_VERSION, DEFAULT_LOOPBACK_INBOUND_SESSIONS,
    MAX_LOOPBACK_INBOUND_SESSIONS, MAX_LOOPBACK_INBOUNDS, SCHEMA_VERSION,
};
use serde::Serialize;

#[derive(Serialize)]
struct NativeCapabilities {
    capabilities_schema_version: u32,
    abi_version: u32,
    config_schema_version: u32,
    core_version: &'static str,
    protocols: Vec<ProtocolCapability>,
    tls: TlsCapabilities,
    dns: DnsCapabilities,
    routing: RoutingCapabilities,
    share: ShareCapabilities,
    lan_proxy: LanProxyCapabilities,
    loopback_inbounds: LoopbackInboundCapabilities,
    maturity: MaturityCapabilities,
    protocol_matrix: ProtocolMatrix,
}

/// Named loopback CONNECT listeners: the per-application ingress Web Apps are
/// built on.
///
/// `compiled` is the feature-detection flag, exactly as `lan_proxy.compiled` is:
/// a library that predates `nativeStartLoopbackInbound` has no
/// `loopback_inbounds` key at all, so an app can tell the two apart without
/// probing for a symbol.
#[derive(Serialize)]
struct LoopbackInboundCapabilities {
    /// `nativeStartLoopbackInbound`, `nativeStopLoopbackInbound` and
    /// `nativeLoopbackInbounds` are exported by this library.
    compiled: bool,
    /// The `upstream` vocabulary, published so the app does not hardcode it.
    upstreams: &'static [&'static str],
    /// How many may exist in one generation.
    max_inbounds: u16,
    max_sessions_per_inbound: u16,
    default_sessions_per_inbound: u16,
    /// `http_port: 0` binds an ephemeral port and the status document reports
    /// it. The recommended form: a phone has no port registry.
    ephemeral_port: bool,
    /// HTTP CONNECT only. There is no SOCKS half — the client is an Android
    /// `Proxy`, which speaks CONNECT.
    socks5: bool,
    http_connect: bool,
    /// Not optional and not configurable, and every inbound's credentials are
    /// required to differ from every other's: these all listen on `127.0.0.1`,
    /// where every app on the device can reach every port, so the credential is
    /// the only separation there is.
    mandatory_credentials: bool,
    distinct_credentials_enforced: bool,
    /// The bind address is absent from the schema. A configuration cannot widen
    /// one of these to the LAN; that request belongs to the LAN surface, which
    /// has its own network confirmation.
    configurable_bind_address: bool,
    /// An inbound whose upstream is unavailable refuses the session (`502`) and
    /// never falls through to a direct connection.
    fail_closed_upstream: bool,
}

/// The structured view of what each protocol can do.
///
/// Beside `protocols`, never instead of it: ABI v1 froze that list and an app
/// built against it keeps reading exactly what it read before. What this adds is
/// the part the Android side was re-deriving in Kotlin — which carriers a
/// profile may configure, whether REALITY or Vision are reachable at all,
/// whether the protocol is a packet tunnel, whether fake-IP can be used with it,
/// and what a policy reload does to flows that are already open.
///
/// Every value here is read off the code that enforces it. Where the code has no
/// answer, the field is absent rather than guessed.
#[derive(Serialize)]
struct ProtocolMatrix {
    /// The closed vocabularies this block uses, so a UI can switch on them
    /// without carrying a copy that drifts.
    vocabulary: MatrixVocabulary,
    protocols: Vec<ProtocolMatrixEntry>,
}

#[derive(Serialize)]
struct MatrixVocabulary {
    data_plane: &'static [&'static str],
    stream_carrier: &'static [&'static str],
    existing_flow_outcome: &'static [&'static str],
}

/// How a protocol's flows reach the network. Three values and no fourth.
mod data_plane {
    /// A stream/datagram proxy: the core opens one outbound connection per flow
    /// and relays. The flow holds the outbound it was opened with.
    pub const STREAM_PROXY: &str = "stream_proxy";
    /// An L3 tunnel: IP packets are sealed and sent whole, and the routing
    /// decision is cached on the 5-tuple rather than owned by a relay task.
    pub const PACKET_TUNNEL: &str = "packet_tunnel";
    /// A group of stream proxies. It carries nothing itself; every capability
    /// below is the member's.
    pub const GROUP: &str = "group";
}

/// What happens to a flow that is **already open** when something changes.
mod flow_outcome {
    /// The flow keeps the outbound it opened with and runs to completion.
    pub const PRESERVED: &str = "preserved";
    /// The flow is cut: TCP is reset towards the application, UDP stops and its
    /// session is released.
    pub const REVOKED: &str = "revoked";
    /// The decision is re-taken, but only after the flow has been idle for
    /// `runtime.idle_timeout_s`. A flow that keeps transmitting keeps the
    /// decision it had.
    pub const REEVALUATED_AFTER_IDLE: &str = "reevaluated_after_idle";
}

/// What a change does to flows that are already open, per protocol.
///
/// Per protocol because it genuinely differs, and the difference is not a detail
/// an app can infer: a stream proxy's flow is owned by a relay task that watches
/// two cancellation tokens, while an L3 flow is a cached entry in the split
/// table that no task is waiting on. The same reload reaches one and not the
/// other.
#[derive(Serialize)]
struct ExistingFlowBehavior {
    /// `nativeReloadPolicy` with a policy that does *not* arm the kill switch.
    on_policy_reload: &'static str,
    /// A reload whose new policy has the kill switch armed.
    on_kill_switch: &'static str,
    /// `nativeNetworkChanged`.
    on_network_change: &'static str,
    /// Whether `nativeRevokeFlows` reaches a flow of this kind. When `false` the
    /// call still returns a count — the row matched and its token was
    /// cancelled — but nothing is watching that token on this data plane, so the
    /// flow keeps moving packets until its decision expires.
    revocable_by_call: bool,
}

#[derive(Serialize)]
struct ProtocolMatrixEntry {
    /// Joins to `protocols[].id`. The two lists always carry the same ids.
    id: &'static str,
    /// The same value as `protocols[].id == this` carries, from the same `cfg!`.
    compiled: bool,
    data_plane: &'static str,
    /// Stream carriers a profile may configure, from the protocol's own
    /// `transport` field. Empty when the protocol has no such field — which is
    /// a statement about the schema, not about the wire.
    stream_carriers: &'static [&'static str],
    /// The protocol's config carries a TLS block that goes through
    /// `foxcore-transport`.
    tls: bool,
    /// ECH is configurable on this protocol. Agrees with `tls.ech_refused_by` by
    /// construction.
    ech: bool,
    /// A REALITY block is representable in this protocol's config.
    reality: bool,
    /// The XTLS Vision flow is representable in this protocol's config.
    vision: bool,
    /// The transport is QUIC rather than TCP.
    quic: bool,
    /// The same value as `protocols[].udp`.
    udp: bool,
    /// `dns.mode='fake_ip'` may be used with this protocol as the **primary**
    /// outbound.
    fake_ip_as_primary: bool,
    /// Routing anything to this protocol *requires* `dns.mode='fake_ip'`, or the
    /// config is refused.
    fake_ip_required: bool,
    existing_flow_behavior: ExistingFlowBehavior,
}

/// The five carriers `StreamTransportConfig` can express.
const STREAM_CARRIERS: &[&str] = &["raw", "websocket", "http_upgrade", "grpc", "http2"];
/// Protocols whose config has no `transport` field at all.
const NO_STREAM_CARRIERS: &[&str] = &[];

/// A stream proxy's flow is owned by a relay task holding two cancellation
/// tokens: the policy snapshot's, cancelled by a reload only when that reload
/// arms the kill switch, and its own, cancelled by `nativeRevokeFlows`. A
/// network change installs a fresh snapshot and cancels the old token.
const STREAM_PROXY_FLOWS: ExistingFlowBehavior = ExistingFlowBehavior {
    on_policy_reload: flow_outcome::PRESERVED,
    on_kill_switch: flow_outcome::REVOKED,
    on_network_change: flow_outcome::REVOKED,
    revocable_by_call: true,
};

/// An L3 flow has no relay task. Its decision is an entry in the split table,
/// keyed on the 5-tuple and re-taken only after the entry has been idle — so a
/// reload, the kill switch and a network change all reach it on that schedule
/// and not before, and the per-flow revocation token nothing is awaiting does
/// not stop packets.
const PACKET_TUNNEL_FLOWS: ExistingFlowBehavior = ExistingFlowBehavior {
    on_policy_reload: flow_outcome::REEVALUATED_AFTER_IDLE,
    on_kill_switch: flow_outcome::REEVALUATED_AFTER_IDLE,
    on_network_change: flow_outcome::REEVALUATED_AFTER_IDLE,
    revocable_by_call: false,
};

/// How far a feature is from being something a user should rely on.
///
/// `compiled: true` has always answered "is the code in this build", and the
/// app has been reading it as if it also answered "is this ready". Those are
/// different questions and the second one was never asked, so the Android side
/// inferred it — from the version number, from whether a row existed at all.
/// This block is the answer being stated instead of inferred.
///
/// Deliberately additive: the strings live here and in a new `maturity` key on
/// each protocol, and nothing that was already in the document moved or
/// changed meaning. An older app that does not read these keys is unaffected.
mod maturity {
    /// Implemented, covered in-tree, and exercised against an independent
    /// implementation at least once on a real network.
    pub const STABLE: &str = "stable";
    /// Implemented and covered in-tree, but **not** verified against an
    /// independent peer — or last verified before the current cycle. Expected
    /// to work; not evidenced end to end.
    pub const BETA: &str = "beta";
    /// Implemented with a known gap: a missing sub-feature, an unproven
    /// assumption, or a path that has never carried real traffic.
    pub const EXPERIMENTAL: &str = "experimental";
    /// Not in this build. Always paired with `compiled: false`.
    pub const UNAVAILABLE: &str = "unavailable";
}

/// The maturity vocabulary, published so the app does not hardcode it.
#[derive(Serialize)]
struct MaturityCapabilities {
    /// The four states, worst to best, so a UI can sort and threshold without
    /// knowing the words.
    states: &'static [&'static str],
    /// One line per state, in the same order as `states`.
    definitions: &'static [&'static str],
    /// Highest state anything in this build claims. `stable` requires evidence
    /// against an independent peer; where that evidence is older than the
    /// current release cycle, the feature is `beta` and this ceiling says so.
    ceiling: &'static str,
    /// Whether an independent-peer interop run happened for *this* build. When
    /// `false`, every `stable` below rests on an earlier run recorded in
    /// `docs/interop.md`, and the app should not present it as freshly proven.
    live_interop_verified_this_build: bool,
    /// Non-protocol features that carry their own maturity, keyed the same way
    /// the blocks above are named.
    features: &'static [FeatureMaturity],
}

#[derive(Serialize)]
struct FeatureMaturity {
    id: &'static str,
    maturity: &'static str,
    /// Why it is not `stable`, or what the remaining gap is. Empty when the
    /// state speaks for itself.
    note: &'static str,
}

/// The LAN ingress: SOCKS5 and HTTP CONNECT on the phone's own network address,
/// for the other devices on it.
///
/// A block rather than a bare flag because "the core has a LAN proxy" is not one
/// question. The app has to know that the JNI calls exist at all (`compiled` —
/// this is the feature-detection flag: a library that predates the calls has no
/// `lan_proxy` key), which presets it may offer, and which of the component's
/// refusals are permanent properties rather than transient failures. Every
/// negative below is a rule the component enforces and the UI should therefore
/// not offer a switch for.
#[derive(Serialize)]
struct LanProxyCapabilities {
    /// `nativeConfirmLanNetwork`, `nativeStartLanProxy`, `nativeStopLanProxy`
    /// and `nativeLanProxyStatus` are exported by this library.
    compiled: bool,
    presets: &'static [&'static str],
    socks5: bool,
    http_connect: bool,
    /// Authentication is not optional and not configurable. SOCKS offers method
    /// `0x02` and never `0x00`; HTTP answers `407` until credentials arrive.
    mandatory_credentials: bool,
    /// A network must be confirmed before listeners bind, and the confirmation
    /// covers one Android `Network` and one engine generation — it is held in
    /// memory and never persisted, so the app must confirm again after a
    /// reconnect or a restart.
    session_network_confirmation: bool,
    /// `0.0.0.0` and `::` are refused: a wildcard bind on a phone is reachable
    /// from the mobile network, which is not a LAN.
    wildcard_bind: bool,
    /// A cellular or unknown transport is refused, by transport and again by
    /// interface name.
    cellular_bind: bool,
    /// A network change closes the listeners and invalidates the credentials
    /// rather than rebinding. The app must confirm the new network and start
    /// again.
    rebinds_on_network_change: bool,
    /// There is no `direct` preset. Traffic accepted on the LAN leaves through
    /// the VPN or through Tor or it does not leave.
    direct_preset: bool,
}

/// What the encrypted share vault can do in this build.
#[derive(Serialize)]
struct ShareCapabilities {
    /// The vault itself: create, add files, revoke, and decrypt locally.
    compiled: bool,
    /// Publication as a Tor onion service. Off unless the `onion-service`
    /// feature is compiled in, and declared so the app can hide the button
    /// rather than offer one that always fails.
    ///
    /// There is no other publication transport and there will not be one: a
    /// share served anywhere Tor is not is the fallback the component exists to
    /// refuse. `false` here means local export only.
    onion_publication: bool,
}

#[derive(Serialize)]
struct ProtocolCapability {
    id: &'static str,
    compiled: bool,
    implementation: &'static str,
    tcp: bool,
    udp: bool,
    transports: &'static [&'static str],
    unsupported: &'static [&'static str],
    /// One of [`maturity`]. Separate from `compiled` on purpose: `compiled`
    /// says the code is here, this says whether it has been shown to work.
    maturity: &'static str,
}

/// The shared TLS boundary every stream protocol wraps itself in.
///
/// Declared once rather than repeated inside each protocol's `transports`,
/// because it is literally one piece of code (`foxcore-transport::tls`) and a
/// per-protocol answer would let the same build say two things.
#[derive(Serialize)]
struct TlsCapabilities {
    /// Encrypted Client Hello with an `ECHConfigList` carried in the profile,
    /// fail-closed: a server that does not accept the offer is refused, never
    /// retried in the clear.
    ech: bool,
    /// A GREASE ECH extension for a profile that wants the cover but has no
    /// config list. Encrypts nothing — the SNI is in the clear — and the config
    /// field is named `grease_plaintext_sni` so that the profile says so too.
    ech_grease: bool,
    /// Reading the `ECHConfigList` out of the `HTTPS` (type 65) DNS record
    /// instead of the profile.
    ///
    /// `false`, and it is the honest kind of false: the record has to be
    /// fetched over DoH/DoT, or the config leaks in the same query it was meant
    /// to protect, and that is a change to the resolver rather than to this
    /// boundary. Until it exists, an operator has to paste the list into the
    /// profile.
    ech_from_https_rr: bool,
    /// Protocols in this build that refuse `tls.ech` at config time, so an app
    /// can grey the switch out instead of offering one that fails on load.
    ech_refused_by: &'static [&'static str],
    reality_fingerprints_implemented: &'static [&'static str],
    reality_fingerprints_substituted: &'static [&'static str],
    reality_fingerprint_substitute: &'static str,
    reality_fingerprints_refused: &'static [&'static str],
}

#[derive(Serialize)]
struct DnsCapabilities {
    udp: bool,
    tcp: bool,
    dot: bool,
    doh_http2: bool,
    fake_ip: bool,
    private_namespaces_fail_closed: &'static [&'static str],
}

#[derive(Serialize)]
struct RoutingCapabilities {
    multi_outbound: bool,
    atomic_policy_reload: bool,
    uid_package_split: bool,
    unified_application_policy: bool,
    firewall_block_action: bool,
    /// Tor and I2P can be switched on and off while the tunnel is up, without
    /// tearing it down. Renamed from `private_network_hot_toggle`, which every
    /// reader took to mean a toggle for the *local* network — a thing that does
    /// not exist in this core and never did.
    overlay_network_hot_toggle: bool,
    shared_uid_conflict_fail_closed: bool,
    existing_flows_preserved_on_reload: bool,
    outbound_failure_isolated: bool,
    max_named_outbounds: u8,
    /// Members a single `selector` may hold. The app needs this to decide
    /// whether a subscription fits in one group before it builds the config.
    max_selector_members: u16,
    /// Share links and subscriptions can be parsed by the core itself. Without
    /// this the app has to carry a second parser for the same format, and the
    /// two disagree at exactly the edge cases that matter.
    link_import: bool,
    /// A subscription imports the lines that parse and reports the ones that do
    /// not, instead of refusing the whole body over a single `tg://` notice.
    lenient_subscription_import: bool,
    /// `nativeReloadPolicy` answers a refusal with a negative typed code rather
    /// than an exception carrying prose. Declared so an app can tell a build
    /// that distinguishes "no Tor in this library" from "bad policy" from one
    /// that cannot.
    typed_policy_refusals: bool,
}

/// Build the structured view.
///
/// Every field below is annotated with where it was read from. The rule for this
/// function is the one the whole document rests on: a value comes from the code
/// that enforces it, never from the protocol's specification. Where the code
/// cannot answer — which datagram framing a profile ends up using, for one — the
/// field does not exist rather than being filled in.
fn protocol_matrix() -> ProtocolMatrix {
    /// `crates/foxcore-api/src/config/outbound.rs` — `is_packet_tunnel()`
    /// matches `Wireguard` and nothing else, and `crates/foxcore-api/src/config
    /// /engine.rs` refuses `dns.mode='fake_ip'` for exactly that case.
    fn stream(
        id: &'static str,
        compiled: bool,
        stream_carriers: &'static [&'static str],
        tls: bool,
        ech: bool,
        quic: bool,
        udp: bool,
    ) -> ProtocolMatrixEntry {
        ProtocolMatrixEntry {
            id,
            compiled,
            data_plane: data_plane::STREAM_PROXY,
            stream_carriers,
            tls,
            ech,
            reality: false,
            vision: false,
            quic,
            udp,
            fake_ip_as_primary: true,
            fake_ip_required: false,
            existing_flow_behavior: STREAM_PROXY_FLOWS,
        }
    }

    ProtocolMatrix {
        vocabulary: MatrixVocabulary {
            data_plane: &[
                data_plane::STREAM_PROXY,
                data_plane::PACKET_TUNNEL,
                data_plane::GROUP,
            ],
            // `StreamTransportConfig` has exactly these five variants
            // (crates/foxcore-api/src/config/transport.rs).
            stream_carrier: STREAM_CARRIERS,
            existing_flow_outcome: &[
                flow_outcome::PRESERVED,
                flow_outcome::REVOKED,
                flow_outcome::REEVALUATED_AFTER_IDLE,
            ],
        },
        protocols: vec![
            // `VlessConfig` is the only config in the schema with a `reality`
            // block and the only one with a `flow` field, which is where
            // `VLESS_FLOW_VISION` is accepted.
            ProtocolMatrixEntry {
                reality: true,
                vision: true,
                ..stream(
                    "vless",
                    cfg!(feature = "vless"),
                    STREAM_CARRIERS,
                    true,
                    true,
                    false,
                    cfg!(feature = "vless"),
                )
            },
            stream(
                "vmess",
                cfg!(feature = "vmess"),
                STREAM_CARRIERS,
                true,
                true,
                false,
                cfg!(feature = "vmess"),
            ),
            // QUIC, and ECH is refused at config time: the offer has no
            // meaning over a QUIC handshake this core does not drive through
            // rustls' ECH path. See `tls.ech_refused_by`, which this agrees
            // with by construction.
            stream(
                "hysteria2",
                cfg!(feature = "hysteria2"),
                NO_STREAM_CARRIERS,
                true,
                false,
                true,
                cfg!(feature = "hysteria2"),
            ),
            stream(
                "tuic",
                cfg!(feature = "tuic"),
                NO_STREAM_CARRIERS,
                true,
                false,
                true,
                cfg!(feature = "tuic"),
            ),
            stream(
                "trojan",
                cfg!(feature = "trojan"),
                STREAM_CARRIERS,
                true,
                true,
                false,
                cfg!(feature = "trojan"),
            ),
            stream(
                "shadowsocks",
                cfg!(feature = "shadowsocks"),
                STREAM_CARRIERS,
                true,
                true,
                false,
                cfg!(feature = "shadowsocks"),
            ),
            // AnyTLS owns its multiplexing above the TLS stream, so its config
            // deliberately has no `transport` field: a second WebSocket or H2
            // layer would be a different wire protocol.
            stream(
                "anytls",
                cfg!(feature = "anytls"),
                NO_STREAM_CARRIERS,
                true,
                true,
                false,
                cfg!(feature = "anytls"),
            ),
            stream(
                "shadowtls",
                cfg!(feature = "shadowtls"),
                NO_STREAM_CARRIERS,
                true,
                false,
                false,
                cfg!(feature = "shadowtls"),
            ),
            // The two L3 profiles. `fake_ip_as_primary: false` is not a
            // preference: `EngineConfig::validate` refuses the combination
            // outright, because a clearnet name answered from the fake pool
            // gets sealed as the packet's destination and no peer can route it.
            ProtocolMatrixEntry {
                id: "wireguard",
                compiled: cfg!(feature = "wireguard"),
                data_plane: data_plane::PACKET_TUNNEL,
                stream_carriers: NO_STREAM_CARRIERS,
                tls: false,
                ech: false,
                reality: false,
                vision: false,
                quic: false,
                udp: cfg!(feature = "wireguard"),
                fake_ip_as_primary: false,
                fake_ip_required: false,
                existing_flow_behavior: PACKET_TUNNEL_FLOWS,
            },
            ProtocolMatrixEntry {
                id: "amneziawg",
                compiled: cfg!(feature = "wireguard"),
                data_plane: data_plane::PACKET_TUNNEL,
                stream_carriers: NO_STREAM_CARRIERS,
                tls: false,
                ech: false,
                reality: false,
                vision: false,
                quic: false,
                udp: cfg!(feature = "wireguard"),
                fake_ip_as_primary: false,
                fake_ip_required: false,
                existing_flow_behavior: PACKET_TUNNEL_FLOWS,
            },
            // HTTP/2 CONNECT over mandatory TLS, and the H2 layer is the
            // protocol rather than a configurable carrier.
            stream(
                "naive",
                cfg!(feature = "naive"),
                NO_STREAM_CARRIERS,
                true,
                true,
                false,
                false,
            ),
            // `SocksConfig` has no `tls` field: SOCKS over TLS is not
            // representable, which is why v1 lists `tls` as unsupported.
            stream(
                "socks",
                cfg!(feature = "socks"),
                NO_STREAM_CARRIERS,
                false,
                false,
                false,
                cfg!(feature = "socks"),
            ),
            // CONNECT has no datagram form; the outbound refuses UDP rather
            // than carrying it over TCP.
            stream(
                "http",
                cfg!(feature = "http"),
                NO_STREAM_CARRIERS,
                true,
                true,
                false,
                false,
            ),
            // A group carries nothing of its own. `SelectorConfig::validate`
            // refuses a member that is a selector, Tor, I2P or WireGuard, so
            // every member is a stream proxy and the group's flow behaviour is
            // the stream-proxy one.
            ProtocolMatrixEntry {
                id: "selector",
                compiled: true,
                data_plane: data_plane::GROUP,
                stream_carriers: NO_STREAM_CARRIERS,
                tls: false,
                ech: false,
                reality: false,
                vision: false,
                quic: false,
                udp: true,
                fake_ip_as_primary: true,
                fake_ip_required: false,
                existing_flow_behavior: STREAM_PROXY_FLOWS,
            },
            // Tor and I2P *require* fake-IP when anything is routed to them:
            // without it a `.onion`/`.i2p` lookup leaves as ordinary port-53
            // traffic to a clearnet resolver, and `EngineConfig::validate`
            // refuses the profile rather than allowing that.
            ProtocolMatrixEntry {
                fake_ip_required: true,
                ..stream(
                    "tor",
                    cfg!(feature = "tor"),
                    NO_STREAM_CARRIERS,
                    false,
                    false,
                    false,
                    false,
                )
            },
            ProtocolMatrixEntry {
                fake_ip_required: true,
                ..stream(
                    "i2p",
                    cfg!(feature = "i2p"),
                    NO_STREAM_CARRIERS,
                    false,
                    false,
                    false,
                    false,
                )
            },
        ],
    }
}

/// The maturity of onion publication, which is `unavailable` when the build
/// cannot publish at all.
///
/// A `const` rather than the `if` written inline in the feature list: that list
/// is a `&'static [FeatureMaturity]` built from a literal, and an `if` in it
/// stops rvalue static promotion — the slice then borrows a temporary and does
/// not compile. A `const` is evaluated before promotion and the literal stays a
/// literal.
const ONION_PUBLICATION_MATURITY: &str = if cfg!(feature = "onion-service") {
    maturity::EXPERIMENTAL
} else {
    maturity::UNAVAILABLE
};

/// A protocol that is not in this build is `unavailable`, whatever the maturity
/// of the implementation would be if it were here.
///
/// Applied in one place rather than written into each entry, because the two
/// facts are declared at sixteen separate sites and only one of them follows the
/// build. `maturity` is a literal — `beta` for VLESS is a statement about how
/// well VLESS works, made once — while `compiled` is `cfg!(feature = ...)`, so a
/// build that selects its protocols (see `crates/foxcore-android/Cargo.toml`)
/// produced a document saying `compiled: false, maturity: "beta"` for every
/// protocol it left out. The app sorts profiles on `maturity`, so that reads as
/// a working protocol and is offered — a button that cannot do anything.
///
/// Found by building with no protocol features at all, which is exactly the
/// build nobody could make before the feature set became a build input.
fn settle_maturity(mut protocols: Vec<ProtocolCapability>) -> Vec<ProtocolCapability> {
    for protocol in &mut protocols {
        if !protocol.compiled {
            protocol.maturity = maturity::UNAVAILABLE;
        }
    }
    protocols
}

pub(crate) fn capabilities_json() -> &'static str {
    static DOCUMENT: OnceLock<String> = OnceLock::new();
    DOCUMENT.get_or_init(|| {
        serde_json::to_string(&NativeCapabilities {
            capabilities_schema_version: CAPABILITIES_SCHEMA_VERSION,
            abi_version: CORE_ABI_VERSION,
            config_schema_version: SCHEMA_VERSION,
            core_version: CORE_VERSION,
            protocols: settle_maturity(vec![
                ProtocolCapability {
                    id: "vless",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "vless"),
                    implementation: "native",
                    tcp: cfg!(feature = "vless"),
                    udp: cfg!(feature = "vless"),
                    transports: &[
                        "tcp",
                        "tls",
                        // Kept because ABI v1 froze the name, and it is still
                        // true: the REALITY hello is a fixed table, not a uTLS
                        // surface. What it no longer means is "one hardcoded
                        // literal" — the names below say what the table now
                        // actually contains.
                        "reality_chrome_static",
                        "reality_chrome_151",
                        "reality_chrome_133",
                        "reality_chrome_131",
                        // The REALITY hello's own extension 0xfe0d, not the
                        // rustls one already listed as `ech_grease`.
                        "reality_ech_grease",
                        // X25519MLKEM768 offered and executed, alongside plain
                        // X25519 (draft-ietf-tls-ecdhe-mlkem).
                        "reality_x25519mlkem768",
                        "websocket",
                        "http_upgrade",
                        "grpc",
                        "http2",
                        "udp_over_tcp",
                        "xudp",
                        "packetaddr",
                        "vision",
                        "ech",
                        "ech_grease",
                    ],
                    unsupported: &[
                        // Vision carries streams, not datagrams: a UDP flow to
                        // 443 on a Vision profile is refused rather than sent
                        // through a path that cannot frame it.
                        "vision_udp443",
                        "websocket_early_data",
                        "reality_other_fingerprints",
                        "reality_mldsa65",
                        "reality_crawler_fallback",
                        // The hello offers TLS 1.2 suites and versions because
                        // Chrome does. A server that selects either is refused,
                        // not downgraded to.
                        "reality_tls12",
                        // A HelloRetryRequest is recognised and refused with
                        // its own message. Chrome would answer one; this client
                        // does not re-send a hello for another group.
                        "reality_hello_retry_request",
                        // The hello offers `compress_certificate` (brotli)
                        // because Chrome does. A server that answers with a
                        // CompressedCertificate is refused — RFC 8879 is not
                        // implemented.
                        "reality_certificate_compression",
                        // No PSK, no session ticket storage, no 0-RTT: every
                        // REALITY connection is a full handshake. A browser
                        // that reconnects fifty times and resumes none of them
                        // is an anomaly no ClientHello shape hides, and it is
                        // recorded here rather than implied.
                        "reality_session_resumption",
                    ],
                },
                ProtocolCapability {
                    id: "vmess",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "vmess"),
                    implementation: "native_aead",
                    tcp: cfg!(feature = "vmess"),
                    udp: cfg!(feature = "vmess"),
                    transports: &[
                        "tcp",
                        "tls",
                        "websocket",
                        "http_upgrade",
                        "grpc",
                        "http2",
                        "aead",
                        "ech",
                        "ech_grease",
                    ],
                    unsupported: &[
                        "legacy_alter_id",
                        "xudp",
                        "mux",
                        "reality",
                        "fingerprint_emulation",
                    ],
                },
                ProtocolCapability {
                    id: "hysteria2",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "hysteria2"),
                    implementation: "native",
                    tcp: cfg!(feature = "hysteria2"),
                    udp: cfg!(feature = "hysteria2"),
                    transports: &[
                        "quic",
                        "http3",
                        "salamander",
                        "brutal_congestion",
                        "port_hopping",
                    ],
                    unsupported: &["gecko", "realms", "ech"],
                },
                ProtocolCapability {
                    id: "tuic",
                    maturity: maturity::EXPERIMENTAL,
                    compiled: cfg!(feature = "tuic"),
                    implementation: "native_clean_room_v5",
                    tcp: cfg!(feature = "tuic"),
                    udp: cfg!(feature = "tuic"),
                    transports: &[
                        "quic",
                        "tls_exporter_auth",
                        "native_udp",
                        "quic_stream_udp",
                        "cubic",
                        "new_reno",
                        "bounded_reassembly",
                    ],
                    unsupported: &[
                        "bbr",
                        "zero_rtt",
                        "udp_over_stream_extension",
                        "port_hopping",
                        "ech",
                    ],
                },
                ProtocolCapability {
                    id: "trojan",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "trojan"),
                    implementation: "native",
                    tcp: cfg!(feature = "trojan"),
                    udp: cfg!(feature = "trojan"),
                    transports: &[
                        "tcp",
                        "tls",
                        "websocket",
                        "http_upgrade",
                        "grpc",
                        "http2",
                        "udp_over_tcp",
                        "ech",
                        "ech_grease",
                    ],
                    unsupported: &[],
                },
                ProtocolCapability {
                    id: "shadowsocks",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "shadowsocks"),
                    implementation: "native",
                    tcp: cfg!(feature = "shadowsocks"),
                    udp: cfg!(feature = "shadowsocks"),
                    transports: &[
                        "aead",
                        "aead_2022",
                        "websocket",
                        "v2ray_plugin",
                        "simple_obfs_http",
                        "simple_obfs_tls",
                        "outline_prefix",
                        "ech",
                        "ech_grease",
                    ],
                    // Two SIP003 plugins are named above because both are
                    // carriers this core speaks natively. `sip003_plugins`
                    // stays unsupported as a family: every other plugin in it
                    // needs a subprocess, and a profile naming one must fail
                    // rather than be served whichever one we happen to have.
                    // The prefix is AEAD-only — an AEAD-2022 stream carries a
                    // request-salt echo Outline never specified a prefix for.
                    unsupported: &[
                        "sip003_plugins",
                        "outline_prefix_aead_2022",
                        "outline_prefix_udp",
                        "outline_dynamic_key",
                    ],
                },
                ProtocolCapability {
                    id: "anytls",
                    maturity: maturity::EXPERIMENTAL,
                    compiled: cfg!(feature = "anytls"),
                    implementation: "native_clean_room_v2",
                    tcp: cfg!(feature = "anytls"),
                    udp: cfg!(feature = "anytls"),
                    transports: &[
                        "tls",
                        "session_reuse",
                        "multiplex",
                        "bounded_padding",
                        "padding_update",
                        "synack",
                        "uot_v2",
                        "ech",
                        "ech_grease",
                    ],
                    unsupported: &[
                        "v1_server",
                        "custom_transport",
                        "tls_fingerprint_emulation",
                        "proactive_heartbeat",
                    ],
                },
                ProtocolCapability {
                    id: "shadowtls",
                    maturity: maturity::EXPERIMENTAL,
                    compiled: cfg!(feature = "shadowtls"),
                    implementation: "native_clean_room_strict_v3_embedded_shadowsocks",
                    tcp: cfg!(feature = "shadowtls"),
                    udp: cfg!(feature = "shadowtls"),
                    transports: &[
                        "tls13",
                        "server_proof",
                        "chained_hmac",
                        "inner_shadowsocks",
                        "uot_v2",
                    ],
                    unsupported: &[
                        "v1",
                        "v2",
                        "tls12_non_strict",
                        "generic_detour",
                        "non_shadowsocks_inner",
                        "share_link",
                        "tls_fingerprint_emulation",
                        "h2_muddled_fallback",
                        "ech",
                    ],
                },
                // Declared only now that the packet path is connected. While the
                // relay existed but the TUN loop never called it, saying
                // `compiled` here would have promised a tunnel that carried
                // nothing.
                ProtocolCapability {
                    id: "wireguard",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "wireguard"),
                    implementation: "native_l3_packet_tunnel",
                    tcp: cfg!(feature = "wireguard"),
                    udp: cfg!(feature = "wireguard"),
                    transports: &[
                        "udp",
                        "noise_ikpsk2",
                        "reserved_header",
                        "keepalive",
                        "conf_file_import",
                    ],
                    // No roaming: the peer socket is connected to one endpoint
                    // for the life of the generation.
                    unsupported: &["endpoint_roaming", "server_role"],
                },
                ProtocolCapability {
                    id: "amneziawg",
                    maturity: maturity::EXPERIMENTAL,
                    compiled: cfg!(feature = "wireguard"),
                    implementation: "native_l3_packet_tunnel",
                    tcp: cfg!(feature = "wireguard"),
                    udp: cfg!(feature = "wireguard"),
                    transports: &[
                        "jc",
                        "jmin",
                        "jmax",
                        "s1",
                        "s2",
                        "s3",
                        "s4",
                        "h1",
                        "h2",
                        "h3",
                        "h4",
                        "i1_i5_init_packets",
                        "init_packet_timestamp_tag",
                        "conf_file_import",
                        "h1_h4_ranges",
                    ],
                    unsupported: &["endpoint_roaming", "server_role", "vpn_container_link"],
                },
                ProtocolCapability {
                    id: "naive",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "naive"),
                    implementation: "native_h2_connect_with_padding",
                    tcp: cfg!(feature = "naive"),
                    udp: false,
                    transports: &["tls", "http2", "padding_variant1", "ech", "ech_grease"],
                    // The TLS ClientHello is rustls', not Chromium's. A profile
                    // gated on a browser fingerprint will not pass, and saying
                    // otherwise would be the lie this document exists to avoid.
                    unsupported: &[
                        "udp",
                        "chromium_tls_fingerprint",
                        "rst_stream_padding",
                        "response_header_padding",
                    ],
                },
                ProtocolCapability {
                    id: "socks",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "socks"),
                    implementation: "native_socks5",
                    tcp: cfg!(feature = "socks"),
                    udp: cfg!(feature = "socks"),
                    transports: &["tcp", "udp_associate", "userpass_auth", "remote_dns"],
                    unsupported: &["tls", "socks4", "gssapi_auth"],
                },
                ProtocolCapability {
                    id: "http",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "http"),
                    implementation: "native_http_connect",
                    tcp: cfg!(feature = "http"),
                    // CONNECT has no datagram form. The outbound refuses UDP
                    // rather than quietly carrying it over TCP.
                    udp: false,
                    transports: &[
                        "tcp",
                        "tls",
                        "basic_auth",
                        "custom_headers",
                        "ech",
                        "ech_grease",
                    ],
                    unsupported: &["udp"],
                },
                // Not a wire protocol, but the app looks outbound types up in
                // this list, and it wraps every imported profile in a selector.
                // Reporting it here is what tells the app the profile will run.
                ProtocolCapability {
                    id: "selector",
                    maturity: maturity::BETA,
                    compiled: true,
                    implementation: "native_lazy_members_with_failover",
                    tcp: true,
                    udp: true,
                    transports: &["manual_select", "connect_failover", "urltest_probe"],
                    // The probe speaks plain HTTP. Probing an https target as
                    // plaintext would measure a different thing than it claims,
                    // so it is refused rather than downgraded.
                    unsupported: &["urltest_https_probe"],
                },
                ProtocolCapability {
                    id: "tor",
                    maturity: maturity::BETA,
                    compiled: cfg!(feature = "tor"),
                    implementation: "in_process_arti",
                    tcp: cfg!(feature = "tor"),
                    udp: false,
                    // Managed pluggable transports are configured and handed to
                    // Arti: `proto-tor` pushes them into the bridge builder and
                    // `pt-client` is on in every build that has Tor at all.
                    // Declaring them unsupported here was a false contract —
                    // this document is what the Android layer reads to decide
                    // what the core can do, so it must match the code rather
                    // than describe an older plan.
                    transports: &[
                        "tcp",
                        "onion",
                        "remote_dns",
                        "direct_bridges",
                        "pluggable_transports",
                    ],
                    unsupported: &["udp"],
                },
                ProtocolCapability {
                    id: "i2p",
                    maturity: maturity::EXPERIMENTAL,
                    compiled: cfg!(feature = "i2p"),
                    implementation: "external_i2pd_socks5_loopback",
                    tcp: cfg!(feature = "i2p"),
                    udp: false,
                    transports: &[
                        "tcp",
                        "remote_naming",
                        "fake_ip",
                        "socks5_username_password",
                    ],
                    unsupported: &["udp", "process_ownership", "clearnet"],
                },
            ]),
            tls: TlsCapabilities {
                // Not behind a cargo feature: the ECH path is in every build of
                // foxcore-transport, and `true` here is checked by
                // crates/foxcore-transport/tests/ech.rs reading the bytes off a
                // socket rather than by anyone's word for it.
                ech: true,
                ech_grease: true,
                ech_from_https_rr: false,
                ech_refused_by: &["hysteria2", "tuic", "shadowtls"],
                reality_fingerprints_implemented: &[
                    "chrome_151",
                    "chrome_133",
                    "chrome_131",
                    "edge_85",
                    "safari_26_3",
                    "ios_14",
                    "qq_11_1",
                    "firefox_153",
                    "firefox_148",
                    "random",
                    "randomized",
                ],
                reality_fingerprints_substituted: &[],
                reality_fingerprint_substitute: "chrome_151",
                reality_fingerprints_refused: &["360", "android"],
            },
            dns: DnsCapabilities {
                udp: true,
                tcp: true,
                dot: true,
                doh_http2: true,
                fake_ip: true,
                private_namespaces_fail_closed: &["onion", "i2p"],
            },
            routing: RoutingCapabilities {
                multi_outbound: true,
                atomic_policy_reload: true,
                uid_package_split: cfg!(target_os = "android"),
                unified_application_policy: true,
                firewall_block_action: true,
                overlay_network_hot_toggle: true,
                shared_uid_conflict_fail_closed: true,
                existing_flows_preserved_on_reload: true,
                outbound_failure_isolated: true,
                max_named_outbounds: 16,
                max_selector_members: 64,
                link_import: true,
                lenient_subscription_import: true,
                typed_policy_refusals: true,
            },
            share: ShareCapabilities {
                compiled: true,
                onion_publication: cfg!(feature = "onion-service"),
            },
            lan_proxy: LanProxyCapabilities {
                compiled: true,
                // `tor` and `mixed` are offered whether or not this build has
                // Tor: the preset is a routing choice, and a profile with no Tor
                // outbound refuses the lease at start with the same error a Tor
                // route gets anywhere else. Declaring them absent here would
                // hide the preset from a build that can serve it as soon as the
                // profile has a Tor lane.
                presets: &["vpn", "tor", "mixed"],
                socks5: true,
                http_connect: true,
                mandatory_credentials: true,
                session_network_confirmation: true,
                wildcard_bind: false,
                cellular_bind: false,
                rebinds_on_network_change: false,
                direct_preset: false,
            },
            loopback_inbounds: LoopbackInboundCapabilities {
                compiled: true,
                upstreams: &["profile", "tor", "direct"],
                max_inbounds: MAX_LOOPBACK_INBOUNDS as u16,
                max_sessions_per_inbound: MAX_LOOPBACK_INBOUND_SESSIONS,
                default_sessions_per_inbound: DEFAULT_LOOPBACK_INBOUND_SESSIONS,
                ephemeral_port: true,
                socks5: false,
                http_connect: true,
                mandatory_credentials: true,
                distinct_credentials_enforced: true,
                configurable_bind_address: false,
                fail_closed_upstream: true,
            },
            protocol_matrix: protocol_matrix(),
            maturity: MaturityCapabilities {
                states: &[
                    maturity::UNAVAILABLE,
                    maturity::EXPERIMENTAL,
                    maturity::BETA,
                    maturity::STABLE,
                ],
                definitions: &[
                    "not compiled into this build",
                    "implemented with a known gap or an unproven assumption",
                    "implemented and covered in-tree, not verified against an independent peer \
                     in this cycle",
                    "implemented, covered in-tree, and verified against an independent peer",
                ],
                // Nothing claims `stable`. The bar for it is evidence against an
                // independent implementation collected for the build being
                // shipped, and no such run happened for this one — see
                // docs/interop.md. Raising this ceiling is a release decision
                // backed by a run, not an edit.
                ceiling: maturity::BETA,
                live_interop_verified_this_build: false,
                features: &[
                    FeatureMaturity {
                        id: "tls.ech",
                        maturity: maturity::BETA,
                        note: "bytes checked off a socket by \
                               crates/foxcore-transport/tests/ech.rs; no live ECH server",
                    },
                    FeatureMaturity {
                        id: "tls.reality_fingerprints",
                        maturity: maturity::EXPERIMENTAL,
                        note: "profiles are transcribed from uTLS, not from a first-party \
                               capture, and have not been checked against a live REALITY \
                               server or a live censor — see fingerprints/*.json",
                    },
                    FeatureMaturity {
                        id: "routing.fail_closed",
                        maturity: maturity::BETA,
                        note: "enforced and covered in-tree; not re-verified on a device in \
                               this cycle",
                    },
                    FeatureMaturity {
                        id: "routing.existing_flows_preserved_on_reload",
                        maturity: maturity::BETA,
                        note: "a Block rule added by a reload does not cancel live flows; only \
                               the kill switch and a network change do",
                    },
                    FeatureMaturity {
                        id: "dns.fake_ip",
                        maturity: maturity::BETA,
                        note: "",
                    },
                    FeatureMaturity {
                        id: "lan_proxy",
                        maturity: maturity::EXPERIMENTAL,
                        note: "the JNI surface is new in this build and has not been driven \
                               from the application on a device",
                    },
                    FeatureMaturity {
                        id: "loopback_inbounds",
                        maturity: maturity::EXPERIMENTAL,
                        note: "the JNI surface is new in this build; covered in-tree, including \
                               the refusal paths, but never driven from the application on a \
                               device",
                    },
                    FeatureMaturity {
                        id: "share.onion_publication",
                        // The one entry in this list whose subject can be absent
                        // from the build: everything else here is compiled
                        // unconditionally. Without `onion-service` there is no
                        // publication transport at all — `share.onion_publication`
                        // is `false` a few lines up — and describing it as
                        // `experimental` would tell the app the button is worth
                        // showing. Protocols get this treatment from
                        // [`settle_maturity`]; this list is `&'static`, so it
                        // says so here.
                        maturity: ONION_PUBLICATION_MATURITY,
                        note: "onion publication has not been exercised end to end against an \
                               external downloader in this cycle",
                    },
                ],
            },
        })
        .unwrap_or_else(|_| "{}".to_owned())
    })
}

/// The schema for the document above, shipped beside it.
///
/// `include_str!` rather than a path read at run time: the test that checks the
/// two against each other must fail to *compile* if the file goes missing, not
/// pass because it found nothing to check.
#[cfg(test)]
const CAPABILITIES_SCHEMA: &str = include_str!("../capabilities.schema.json");

#[cfg(test)]
mod schema {
    //! A JSON Schema validator, for the subset `capabilities.schema.json` uses.
    //!
    //! Hand-written rather than a dependency, and the reason is the same one
    //! that keeps this workspace's dependency list short: a validator is a
    //! hundred lines here, and the alternative is a crate — with its own
    //! transitive tree, its own licence to clear and its own SBOM entry — on the
    //! strength of one test. The subset is exactly what the schema uses:
    //! `$ref` into `$defs`, `type`, `properties`, `required`,
    //! `additionalProperties: false`, `items`, `enum`, `const` and `minimum`.
    //!
    //! A keyword the schema uses and this does not implement would be silently
    //! ignored, which is a validator that passes everything — so
    //! `every_keyword_the_schema_uses_is_implemented` walks the schema and
    //! fails on any keyword outside the list.

    use serde_json::Value;

    /// Keywords this validator acts on. Anything else in the schema is either
    /// documentation (`title`, `description`, `$schema`, `$id`) or a keyword
    /// that would be ignored, and the second kind is refused by the test.
    pub const IMPLEMENTED: &[&str] = &[
        "$ref",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minimum",
    ];
    pub const IGNORED: &[&str] = &["$schema", "$id", "title", "description", "$defs"];

    pub fn validate(document: &Value, schema: &Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        check(document, schema, schema, "$", &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
        let name = reference.strip_prefix("#/$defs/")?;
        root.get("$defs")?.get(name)
    }

    fn check(value: &Value, schema: &Value, root: &Value, path: &str, errors: &mut Vec<String>) {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            match resolve(root, reference) {
                Some(target) => check(value, target, root, path, errors),
                None => errors.push(format!("{path}: unresolvable $ref {reference}")),
            }
            return;
        }
        if let Some(expected) = schema.get("const")
            && value != expected
        {
            errors.push(format!("{path}: expected {expected}, found {value}"));
            return;
        }
        if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
            && !allowed.contains(value)
        {
            errors.push(format!("{path}: {value} is not one of {allowed:?}"));
            return;
        }
        if let Some(kind) = schema.get("type").and_then(Value::as_str) {
            let matches = match kind {
                "object" => value.is_object(),
                "array" => value.is_array(),
                "string" => value.is_string(),
                "boolean" => value.is_boolean(),
                "integer" => value.is_i64() || value.is_u64(),
                "number" => value.is_number(),
                other => {
                    errors.push(format!("{path}: schema uses unknown type '{other}'"));
                    return;
                }
            };
            if !matches {
                errors.push(format!("{path}: expected {kind}, found {value}"));
                return;
            }
        }
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
            && value.as_f64().is_some_and(|actual| actual < minimum)
        {
            errors.push(format!("{path}: {value} is below the minimum {minimum}"));
        }
        if let Some(object) = value.as_object() {
            let properties = schema.get("properties").and_then(Value::as_object);
            for name in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !object.contains_key(name) {
                    errors.push(format!("{path}: missing required property '{name}'"));
                }
            }
            let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
            for (name, child) in object {
                match properties.and_then(|properties| properties.get(name)) {
                    Some(child_schema) => {
                        check(child, child_schema, root, &format!("{path}.{name}"), errors)
                    }
                    None if closed => errors.push(format!("{path}: unexpected property '{name}'")),
                    None => {}
                }
            }
        }
        if let (Some(array), Some(items)) = (value.as_array(), schema.get("items")) {
            for (index, child) in array.iter().enumerate() {
                check(child, items, root, &format!("{path}[{index}]"), errors);
            }
        }
    }

    /// Every keyword the schema uses, so a test can prove none is ignored.
    pub fn keywords(schema: &Value, found: &mut Vec<String>) {
        match schema {
            Value::Object(map) => {
                for (key, child) in map {
                    // Below `properties` and `$defs` the keys are names, not
                    // keywords; the values under them are schemas again.
                    if key == "properties" || key == "$defs" {
                        for nested in child.as_object().into_iter().flatten().map(|(_, v)| v) {
                            keywords(nested, found);
                        }
                        found.push(key.clone());
                        continue;
                    }
                    found.push(key.clone());
                    keywords(child, found);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| keywords(item, found)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABI_V1_FIXTURE: &str = include_str!("../../../fixtures/abi/v1/capabilities.json");

    #[test]
    fn the_substituted_fingerprints_are_the_ones_the_parser_accepts() {
        let document: serde_json::Value = serde_json::from_str(capabilities_json()).unwrap();
        let tls = &document["tls"];

        let implemented: Vec<&str> = tls["reality_fingerprints_implemented"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let substituted: Vec<&str> = tls["reality_fingerprints_substituted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();

        let refused: Vec<&str> = tls["reality_fingerprints_refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();

        fn short(name: &str) -> &str {
            match name {
                "chrome_151" | "chrome_133" | "chrome_131" => "chrome",
                "edge_85" => "edge",
                "safari_26_3" => "safari",
                "ios_14" => "ios",
                "qq_11_1" => "qq",
                "firefox_153" | "firefox_148" => "firefox",
                other => other,
            }
        }
        let mut accounted: Vec<&str> = implemented
            .iter()
            .chain(substituted.iter())
            .chain(refused.iter())
            .map(|name| short(name))
            .chain(["", "chrome_131", "chrome_133"])
            .collect();
        accounted.sort_unstable();
        accounted.dedup();
        let mut known: Vec<&str> = foxcore_link::UTLS_PARROT_NAMES.to_vec();
        known.sort_unstable();
        known.dedup();
        assert_eq!(
            accounted, known,
            "the capabilities document and foxcore-link disagree about uTLS parrot names"
        );

        for name in &refused {
            assert!(
                !substituted.contains(name),
                "{name} is both refused and substituted"
            );
            assert!(
                !implemented.contains(name),
                "{name} is both refused and implemented"
            );
        }

        assert!(
            implemented.contains(&tls["reality_fingerprint_substitute"].as_str().unwrap()),
            "the substitute hello is not one of the implemented tables"
        );

        let vless = document["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == "vless")
            .expect("vless is in the document");
        assert!(
            vless["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry == "reality_other_fingerprints"),
            "reality_other_fingerprints was removed from unsupported, but \
             360/android are still refused"
        );
    }

    #[test]
    fn the_frozen_abi_v1_document_is_still_readable() {
        let old: serde_json::Value = serde_json::from_str(ABI_V1_FIXTURE).unwrap();
        let new: serde_json::Value = serde_json::from_str(capabilities_json()).unwrap();
        let mut problems = Vec::new();
        compare_abi("", &old, &new, &mut problems);
        assert!(problems.is_empty(), "ABI v1 regressions: {problems:#?}");
    }

    fn compare_abi(
        path: &str,
        old: &serde_json::Value,
        new: &serde_json::Value,
        problems: &mut Vec<String>,
    ) {
        use serde_json::Value;
        match (old, new) {
            (Value::Object(old_map), Value::Object(new_map)) => {
                for (key, value) in old_map {
                    let where_ = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    match new_map.get(key) {
                        None => problems.push(format!("{where_}: removed")),
                        Some(next) => compare_abi(&where_, value, next, problems),
                    }
                }
            }
            (Value::Array(old_items), Value::Array(new_items)) => {
                if path.ends_with("unsupported") {
                    return; // shrinking is a capability gain
                }
                for item in old_items {
                    let still_there = match item.get("id") {
                        Some(id) => new_items
                            .iter()
                            .any(|candidate| candidate.get("id") == Some(id)),
                        None => new_items.contains(item),
                    };
                    if !still_there {
                        problems.push(format!("{path}: entry {item} disappeared"));
                    }
                }
            }
            (Value::Bool(true), Value::Bool(false)) => {
                problems.push(format!("{path}: true -> false"));
            }
            _ => {}
        }
    }

    #[test]
    fn capability_document_is_versioned_and_truthful() {
        let document: serde_json::Value = serde_json::from_str(capabilities_json()).unwrap();
        assert_eq!(document["abi_version"], CORE_ABI_VERSION);
        assert_eq!(document["config_schema_version"], SCHEMA_VERSION);
        assert_eq!(document["capabilities_schema_version"], 1);

        // The security journal is the app's, in Kotlin: the Rust port was
        // removed, so the document must not claim one. A stale `true`
        // here is worse than a missing block — it is a promise the linker
        // cannot keep.
        assert!(document.get("journal").is_none());
        assert!(document["routing"]["link_import"].as_bool().unwrap());
        assert!(
            document["routing"]["lenient_subscription_import"]
                .as_bool()
                .unwrap()
        );

        // Brutal is implemented in proto-hysteria2 and was going undeclared, so
        // the app had no way to learn the core can hold a target rate.
        let hysteria2 = document["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|protocol| protocol["id"] == "hysteria2")
            .unwrap();
        assert!(
            hysteria2["transports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|transport| transport == "brutal_congestion")
        );

        // Understating is as much of a lie as overstating, and a quieter one:
        // the app hides a feature the core has and nobody finds out. Each of
        // these was implemented and still declared missing.
        // A build without the feature must say so rather than offer a button
        // that always fails; a build with it must not understate either.
        assert_eq!(document["share"]["compiled"], true);
        assert_eq!(
            document["share"]["onion_publication"],
            cfg!(feature = "onion-service")
        );

        // The LAN proxy is the exact shape of the understatement above: the
        // component was complete and the document said nothing, so the app had
        // no way to learn the calls existed. `compiled` is what it
        // feature-detects on — an older library has no `lan_proxy` key at all.
        let lan = &document["lan_proxy"];
        assert_eq!(lan["compiled"], true);
        let presets = lan["presets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(presets, ["vpn", "tor", "mixed"]);
        // There is no direct preset and there must never be one: it would carry
        // another device's traffic in the clear while presenting itself as the
        // phone's tunnel.
        assert!(!presets.contains(&"direct".to_owned()));
        assert_eq!(lan["direct_preset"], false);
        // Each of these is a rule the component enforces. A `true` here would be
        // a switch the app offers and the core always refuses.
        assert_eq!(lan["mandatory_credentials"], true);
        assert_eq!(lan["session_network_confirmation"], true);
        assert_eq!(lan["wildcard_bind"], false);
        assert_eq!(lan["cellular_bind"], false);
        assert_eq!(lan["rebinds_on_network_change"], false);

        let protocols = document["protocols"].as_array().unwrap();
        let capability = |id: &str| {
            protocols
                .iter()
                .find(|protocol| protocol["id"] == id)
                .unwrap_or_else(|| panic!("{id} must be declared"))
                .clone()
        };
        let lists = |protocol: &serde_json::Value, key: &str| {
            protocol[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };

        let vless = capability("vless");
        assert!(lists(&vless, "transports").contains(&"vision".to_owned()));
        assert!(lists(&vless, "transports").contains(&"packetaddr".to_owned()));
        assert!(!lists(&vless, "unsupported").contains(&"vision".to_owned()));
        // The one thing Vision genuinely cannot do, named so the app can refuse
        // that profile rather than discover it as a dead UDP flow.
        assert!(lists(&vless, "unsupported").contains(&"vision_udp443".to_owned()));

        let vmess = capability("vmess");
        assert_eq!(vmess["udp"], cfg!(feature = "vmess"));
        assert!(!lists(&vmess, "unsupported").contains(&"udp".to_owned()));

        let hysteria2_ports = capability("hysteria2");
        assert!(lists(&hysteria2_ports, "transports").contains(&"port_hopping".to_owned()));
        assert!(!lists(&hysteria2_ports, "unsupported").contains(&"port_hopping".to_owned()));

        let shadowsocks = capability("shadowsocks");
        for carrier in [
            "websocket",
            "v2ray_plugin",
            "simple_obfs_http",
            "simple_obfs_tls",
        ] {
            assert!(lists(&shadowsocks, "transports").contains(&carrier.to_owned()));
        }
        // Two plugins, so the family stays a negative claim: a profile naming
        // any other must fail rather than be served one of the two we have.
        assert!(lists(&shadowsocks, "unsupported").contains(&"sip003_plugins".to_owned()));
        // The prefix works, and the two shapes of it that do not are named one
        // by one so the app refuses those profiles instead of finding out.
        assert!(lists(&shadowsocks, "transports").contains(&"outline_prefix".to_owned()));
        assert!(
            lists(&shadowsocks, "unsupported").contains(&"outline_prefix_aead_2022".to_owned())
        );
        assert!(lists(&shadowsocks, "unsupported").contains(&"outline_prefix_udp".to_owned()));

        let wireguard = capability("wireguard");
        assert!(lists(&wireguard, "transports").contains(&"conf_file_import".to_owned()));
        assert!(!lists(&wireguard, "unsupported").contains(&"conf_file_import".to_owned()));

        let amneziawg = capability("amneziawg");
        for extension in [
            "s3",
            "s4",
            "i1_i5_init_packets",
            "init_packet_timestamp_tag",
            "conf_file_import",
        ] {
            assert!(
                lists(&amneziawg, "transports").contains(&extension.to_owned()),
                "AmneziaWG implements {extension} and must advertise it"
            );
        }
        for stale_refusal in ["i1_i5_signatures", "itime", "link_import"] {
            assert!(
                !lists(&amneziawg, "unsupported").contains(&stale_refusal.to_owned()),
                "AmneziaWG no longer refuses {stale_refusal}"
            );
        }

        // ECH is declared in two places — once as a property of the shared TLS
        // boundary, once per protocol — and the two must agree, because an app
        // that reads either one has to get the same answer. The list of
        // protocols that refuse it is checked against the profile parser
        // itself: a refusal that stops being real must not keep being
        // advertised, and vice versa.
        let tls = &document["tls"];
        assert_eq!(tls["ech"], true);
        assert_eq!(tls["ech_grease"], true);
        assert_eq!(
            tls["ech_from_https_rr"], false,
            "the HTTPS RR path belongs to the resolver and is not in this build"
        );
        let refused = tls["ech_refused_by"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        for id in &refused {
            let protocol = capability(id);
            assert!(
                lists(&protocol, "unsupported").contains(&"ech".to_owned()),
                "{id} is in tls.ech_refused_by but does not say so in its own list"
            );
        }
        for protocol in protocols {
            let id = protocol["id"].as_str().unwrap().to_owned();
            if lists(protocol, "transports").contains(&"ech".to_owned()) {
                assert!(
                    !refused.contains(&id),
                    "{id} both offers ECH and is listed as refusing it"
                );
                assert!(
                    lists(protocol, "transports").contains(&"ech_grease".to_owned()),
                    "{id} offers ECH but not the GREASE mode; every profile that \
                     can configure one can configure the other"
                );
            }
        }
        for id in [
            "vless",
            "vmess",
            "trojan",
            "shadowsocks",
            "anytls",
            "naive",
            "http",
        ] {
            assert!(
                lists(&capability(id), "transports").contains(&"ech".to_owned()),
                "{id} carries TLS through foxcore-transport and therefore has ECH"
            );
        }

        // Nothing may be in both lists: a reader that checked the wrong one
        // would get the opposite answer.
        for protocol in protocols {
            let declared = lists(protocol, "transports");
            for missing in lists(protocol, "unsupported") {
                assert!(
                    !declared.contains(&missing),
                    "{} claims and denies {missing}",
                    protocol["id"]
                );
            }
        }

        let i2p = protocols
            .iter()
            .find(|protocol| protocol["id"] == "i2p")
            .unwrap();
        assert_eq!(i2p["compiled"], cfg!(feature = "i2p"));
        assert_eq!(i2p["implementation"], "external_i2pd_socks5_loopback");
        assert_eq!(i2p["udp"], false);

        let tor = protocols
            .iter()
            .find(|protocol| protocol["id"] == "tor")
            .unwrap();
        assert_eq!(tor["compiled"], cfg!(feature = "tor"));

        let hysteria2 = protocols
            .iter()
            .find(|protocol| protocol["id"] == "hysteria2")
            .unwrap();
        assert!(
            hysteria2["transports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|transport| transport == "salamander")
        );
        assert!(
            !hysteria2["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|extension| extension == "obfs")
        );
        // The app wraps every profile in a selector, so a core that did not
        // announce it would be telling the app nothing will start.
        let selector = protocols
            .iter()
            .find(|protocol| protocol["id"] == "selector")
            .expect("selector must be advertised: every imported profile uses one");
        assert_eq!(selector["compiled"], true);
        assert!(
            selector["transports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|transport| transport == "urltest_probe")
        );
        assert!(
            selector["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|extension| extension == "urltest_https_probe"),
            "an https probe target is refused, and the app has to be able to see that"
        );

        assert_eq!(document["routing"]["unified_application_policy"], true);
        assert_eq!(document["routing"]["outbound_failure_isolated"], true);
        assert_eq!(document["routing"]["max_selector_members"], 64);

        // CONNECT has no datagram form; claiming UDP here would make the app
        // route datagrams into an outbound that can only refuse them.
        let http = protocols
            .iter()
            .find(|protocol| protocol["id"] == "http")
            .unwrap();
        assert_eq!(http["udp"], false);
        assert!(
            http["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|extension| extension == "udp")
        );

        // Naive's TLS is rustls', not Chromium's — a profile gated on a browser
        // fingerprint must be able to see that before it tries.
        let naive = protocols
            .iter()
            .find(|protocol| protocol["id"] == "naive")
            .unwrap();
        assert!(
            naive["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|extension| extension == "chromium_tls_fingerprint")
        );

        let anytls = protocols
            .iter()
            .find(|protocol| protocol["id"] == "anytls")
            .unwrap();
        assert_eq!(anytls["compiled"], cfg!(feature = "anytls"));
        assert!(
            anytls["transports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|transport| transport == "uot_v2")
        );

        let shadowtls = protocols
            .iter()
            .find(|protocol| protocol["id"] == "shadowtls")
            .unwrap();
        assert_eq!(shadowtls["compiled"], cfg!(feature = "shadowtls"));
        assert!(
            shadowtls["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|extension| extension == "generic_detour")
        );
    }

    /// Maturity is a separate axis from `compiled`, and the document has to keep
    /// it separate or the app is back to inferring readiness from presence.
    #[test]
    fn every_feature_declares_a_maturity_from_the_published_vocabulary() {
        let document: serde_json::Value = serde_json::from_str(capabilities_json()).unwrap();
        let block = &document["maturity"];

        let states: Vec<&str> = block["states"]
            .as_array()
            .unwrap()
            .iter()
            .map(|state| state.as_str().unwrap())
            .collect();
        assert_eq!(
            states,
            ["unavailable", "experimental", "beta", "stable"],
            "the vocabulary is ordered worst to best and the app sorts on it"
        );
        assert_eq!(
            block["definitions"].as_array().unwrap().len(),
            states.len(),
            "one definition per state, in the same order"
        );

        let rank = |state: &str| states.iter().position(|known| *known == state);
        let ceiling = block["ceiling"].as_str().unwrap();
        let ceiling_rank = rank(ceiling).expect("the ceiling is one of the published states");

        for protocol in document["protocols"].as_array().unwrap() {
            let id = protocol["id"].as_str().unwrap();
            let state = protocol["maturity"]
                .as_str()
                .unwrap_or_else(|| panic!("{id} declares no maturity"));
            let state_rank =
                rank(state).unwrap_or_else(|| panic!("{id} claims unknown maturity {state}"));

            assert!(
                state_rank <= ceiling_rank,
                "{id} claims {state}, above the document's own ceiling of {ceiling}"
            );

            // The one place the two axes are allowed to agree: code that is not
            // in the build cannot be anything but `unavailable`, and code that
            // is in the build must not be described as absent.
            let compiled = protocol["compiled"].as_bool().unwrap();
            assert_eq!(
                state == "unavailable",
                !compiled,
                "{id}: compiled={compiled} contradicts maturity={state}"
            );
        }

        for feature in block["features"].as_array().unwrap() {
            let id = feature["id"].as_str().unwrap();
            let state = feature["maturity"].as_str().unwrap();
            let state_rank =
                rank(state).unwrap_or_else(|| panic!("{id} claims unknown maturity {state}"));
            assert!(
                state_rank <= ceiling_rank,
                "{id} claims {state}, above the ceiling of {ceiling}"
            );
        }

        // The protocol rule again, applied to the one entry in that list whose
        // subject can be absent from the build. Everything else there is
        // compiled unconditionally, so this is the only place the two axes can
        // disagree — and a `maturity` that outlived its `compiled` is how the
        // app ends up offering a publication button no build behind it can
        // answer.
        let onion = block["features"]
            .as_array()
            .unwrap()
            .iter()
            .find(|feature| feature["id"] == "share.onion_publication")
            .expect("share.onion_publication declares a maturity");
        assert_eq!(
            onion["maturity"] == "unavailable",
            !document["share"]["onion_publication"].as_bool().unwrap(),
            "share.onion_publication: the maturity and the flag must agree about whether \
             this build can publish at all"
        );

        // `stable` means "checked against something we did not write". Until a
        // run for this build says so, the flag stays false and the ceiling stays
        // below `stable`; the two must not drift apart.
        let verified = block["live_interop_verified_this_build"].as_bool().unwrap();
        assert_eq!(
            verified,
            ceiling == "stable",
            "a `stable` ceiling requires an interop run for this build, and vice versa"
        );
    }

    // ------------------------------------------------------------- schema

    fn schema() -> serde_json::Value {
        serde_json::from_str(CAPABILITIES_SCHEMA).expect("capabilities.schema.json must be JSON")
    }

    fn document() -> serde_json::Value {
        serde_json::from_str(capabilities_json()).unwrap()
    }

    /// The document the library actually emits, against the schema shipped
    /// beside it.
    ///
    /// This is the one thing that keeps the two from drifting. A field added to
    /// the struct and not to the schema fails on `additionalProperties`; a field
    /// removed from the struct fails on `required`; a value outside a published
    /// vocabulary fails on `enum`. All three have happened to this document
    /// before it had a schema — the difference is that they were found by an app
    /// on a device.
    #[test]
    fn the_emitted_document_validates_against_the_shipped_schema() {
        if let Err(errors) = schema::validate(&document(), &schema()) {
            panic!(
                "the capabilities document does not match capabilities.schema.json:\n  {}",
                errors.join("\n  ")
            );
        }
    }

    /// The validator is a subset of JSON Schema, so a keyword the schema uses
    /// and it does not implement would be silently ignored — which is a gate
    /// that passes everything.
    #[test]
    fn every_keyword_the_schema_uses_is_implemented_by_the_checker() {
        let mut found = Vec::new();
        schema::keywords(&schema(), &mut found);
        found.sort_unstable();
        found.dedup();
        for keyword in &found {
            assert!(
                schema::IMPLEMENTED.contains(&keyword.as_str())
                    || schema::IGNORED.contains(&keyword.as_str()),
                "capabilities.schema.json uses '{keyword}', which the checker ignores; \
                 implement it in `mod schema` or take it out of the schema"
            );
        }
    }

    /// And the checker actually refuses things. A validator nobody has seen
    /// reject anything is indistinguishable from `Ok(())`.
    #[test]
    fn the_checker_rejects_the_mistakes_it_exists_to_catch() {
        let schema = schema();
        let reject = |document: serde_json::Value, why: &str| {
            assert!(
                schema::validate(&document, &schema).is_err(),
                "the checker must refuse {why}"
            );
        };

        let mut missing = document();
        missing.as_object_mut().unwrap().remove("protocol_matrix");
        reject(missing, "a document missing a required block");

        let mut extra = document();
        extra.as_object_mut().unwrap().insert(
            "journal".to_owned(),
            serde_json::Value::Bool(true),
            // The exact key the older document was accused of carrying, and a
            // promise the linker could not keep.
        );
        reject(extra, "a block nobody declared");

        let mut wrong_type = document();
        wrong_type["routing"]["max_named_outbounds"] = serde_json::json!("sixteen");
        reject(wrong_type, "a number that arrived as a string");

        let mut outside_vocabulary = document();
        outside_vocabulary["protocol_matrix"]["protocols"][0]["existing_flow_behavior"]["on_kill_switch"] =
            serde_json::json!("probably_fine");
        reject(outside_vocabulary, "a value outside a published vocabulary");

        let mut relaxed_invariant = document();
        relaxed_invariant["loopback_inbounds"]["configurable_bind_address"] =
            serde_json::json!(true);
        reject(
            relaxed_invariant,
            "a loopback inbound that claims a configurable bind address",
        );
    }

    // ----------------------------------------------------- protocol matrix

    /// The matrix restates two things v1 already published, and it must restate
    /// them exactly. An app that reads `protocols[].udp` and one that reads
    /// `protocol_matrix.protocols[].udp` have to get the same answer, or the
    /// second block is worse than not having it.
    #[test]
    fn the_matrix_never_contradicts_the_frozen_list() {
        let document = document();
        let v1 = document["protocols"].as_array().unwrap();
        let matrix = document["protocol_matrix"]["protocols"].as_array().unwrap();

        let ids = |list: &[serde_json::Value]| {
            list.iter()
                .map(|entry| entry["id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(v1),
            ids(matrix),
            "the two lists carry the same protocols in the same order"
        );

        for (frozen, entry) in v1.iter().zip(matrix) {
            let id = frozen["id"].as_str().unwrap();
            assert_eq!(frozen["compiled"], entry["compiled"], "{id}: compiled");
            assert_eq!(frozen["udp"], entry["udp"], "{id}: udp");
        }
    }

    /// ECH is now stated in three places — `tls.ech_refused_by`, each protocol's
    /// `transports`/`unsupported`, and the matrix. Two of those were already
    /// checked against each other; this closes the third.
    #[test]
    fn the_matrix_agrees_with_the_tls_block_about_ech() {
        let document = document();
        let refused = document["tls"]["ech_refused_by"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        for entry in document["protocol_matrix"]["protocols"].as_array().unwrap() {
            let id = entry["id"].as_str().unwrap().to_owned();
            let ech = entry["ech"].as_bool().unwrap();
            if refused.contains(&id) {
                assert!(
                    !ech,
                    "{id} refuses ECH at config time but the matrix offers it"
                );
            }
            // ECH is a property of the shared TLS boundary, so a protocol that
            // carries no TLS of its own cannot have it.
            if !entry["tls"].as_bool().unwrap() {
                assert!(!ech, "{id} claims ECH without a TLS block to carry it");
            }
        }
    }

    /// The three facts the matrix exists to state, pinned to the code that
    /// enforces them.
    ///
    /// Each of these was something the Android side had been deriving in Kotlin
    /// from a flat list of strings, which is a second implementation of a rule
    /// the core already owns — and the two only have to disagree once.
    #[test]
    fn the_matrix_states_the_rules_the_config_validator_enforces() {
        let document = document();
        let matrix = document["protocol_matrix"]["protocols"].as_array().unwrap();
        let entry = |id: &str| {
            matrix
                .iter()
                .find(|entry| entry["id"] == id)
                .unwrap_or_else(|| panic!("{id} must be in the matrix"))
        };

        // `EngineConfig::validate` refuses `dns.mode='fake_ip'` with an L3
        // primary: the fake address is sealed into the packet and no peer can
        // route it. The two L3 profiles are the only ones.
        for id in ["wireguard", "amneziawg"] {
            assert_eq!(entry(id)["data_plane"], "packet_tunnel", "{id}");
            assert_eq!(entry(id)["fake_ip_as_primary"], false, "{id}");
        }
        for entry in matrix {
            let id = entry["id"].as_str().unwrap();
            assert_eq!(
                entry["data_plane"] == "packet_tunnel",
                entry["fake_ip_as_primary"] == false,
                "{id}: fake-IP is refused for exactly the packet tunnels"
            );
        }

        // And it refuses a profile that routes to Tor or I2P *without*
        // fake-IP, because a `.onion` lookup would otherwise leave as ordinary
        // port-53 traffic to a clearnet resolver.
        for entry in matrix {
            let id = entry["id"].as_str().unwrap();
            assert_eq!(
                entry["fake_ip_required"].as_bool().unwrap(),
                matches!(id, "tor" | "i2p"),
                "{id}: fake-IP is required for exactly the overlay networks"
            );
        }

        // REALITY and Vision are representable in one config and one only.
        for entry in matrix {
            let id = entry["id"].as_str().unwrap();
            assert_eq!(entry["reality"].as_bool().unwrap(), id == "vless", "{id}");
            assert_eq!(entry["vision"].as_bool().unwrap(), id == "vless", "{id}");
        }

        // A selector carries nothing of its own, and its members can only be
        // stream proxies — `SelectorConfig::validate` refuses a selector, a Tor,
        // an I2P or a WireGuard member.
        let selector = entry("selector");
        assert_eq!(selector["data_plane"], "group");
        assert_eq!(
            selector["existing_flow_behavior"],
            entry("vless")["existing_flow_behavior"],
            "a group's flows behave like the stream proxies it can hold"
        );
    }

    /// The honest asymmetry, stated rather than implied.
    ///
    /// A stream flow is owned by a relay task holding the policy snapshot's
    /// cancellation token and its own; an L3 flow is a cached entry in the split
    /// table that no task is awaiting. So the same reload reaches one
    /// immediately and the other only after it goes idle, and `nativeRevokeFlows`
    /// returns a count for both while stopping only the first. The app has to be
    /// able to read that instead of assuming the coarse
    /// `routing.existing_flows_preserved_on_reload`.
    #[test]
    fn existing_flow_behaviour_is_stated_per_data_plane_and_differs() {
        let document = document();
        let matrix = document["protocol_matrix"]["protocols"].as_array().unwrap();
        let outcomes = document["protocol_matrix"]["vocabulary"]["existing_flow_outcome"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();

        let mut planes = std::collections::BTreeMap::new();
        for entry in matrix {
            let id = entry["id"].as_str().unwrap();
            let behavior = &entry["existing_flow_behavior"];
            for field in ["on_policy_reload", "on_kill_switch", "on_network_change"] {
                let outcome = behavior[field].as_str().unwrap().to_owned();
                assert!(
                    outcomes.contains(&outcome),
                    "{id}.{field} is '{outcome}', outside the published vocabulary"
                );
            }
            planes.insert(
                entry["data_plane"].as_str().unwrap().to_owned(),
                behavior.clone(),
            );
        }

        let stream = &planes["stream_proxy"];
        assert_eq!(stream["on_policy_reload"], "preserved");
        assert_eq!(stream["on_kill_switch"], "revoked");
        assert_eq!(stream["revocable_by_call"], true);

        let tunnel = &planes["packet_tunnel"];
        assert_eq!(
            tunnel["on_policy_reload"], "reevaluated_after_idle",
            "an L3 decision is cached on the 5-tuple and re-taken only after the idle window"
        );
        assert_eq!(
            tunnel["revocable_by_call"], false,
            "nothing on the packet path awaits the per-flow revocation token; \
             claiming otherwise here is the promise this block exists to stop"
        );
        assert_ne!(
            stream["on_policy_reload"], tunnel["on_policy_reload"],
            "if these ever agree, the per-protocol field has stopped earning its place"
        );
    }

    /// The loopback-inbound block, and the negatives in it that are rules rather
    /// than settings. A `true` on any of them would be a switch the app offers
    /// and the core always refuses.
    #[test]
    fn the_loopback_inbound_block_states_rules_the_core_enforces() {
        let document = document();
        let block = &document["loopback_inbounds"];
        assert_eq!(block["compiled"], true);
        assert_eq!(
            block["upstreams"].as_array().unwrap(),
            &["profile", "tor", "direct"]
        );
        assert_eq!(block["max_inbounds"], MAX_LOOPBACK_INBOUNDS as u64);
        assert_eq!(
            block["max_sessions_per_inbound"],
            MAX_LOOPBACK_INBOUND_SESSIONS
        );
        assert_eq!(
            block["default_sessions_per_inbound"],
            DEFAULT_LOOPBACK_INBOUND_SESSIONS
        );
        assert_eq!(block["mandatory_credentials"], true);
        assert_eq!(block["distinct_credentials_enforced"], true);
        assert_eq!(block["fail_closed_upstream"], true);
        // The bind address is not in the schema and never will be. A config that
        // could widen one of these to the LAN would be the LAN surface without
        // the network confirmation that surface exists to require.
        assert_eq!(block["configurable_bind_address"], false);
        assert_eq!(block["socks5"], false);
        assert_eq!(block["http_connect"], true);

        // The two ingress blocks agree about the one thing they share: neither
        // has a direct-by-default state, and both authenticate always.
        assert_eq!(
            document["lan_proxy"]["mandatory_credentials"],
            block["mandatory_credentials"]
        );
    }
}
