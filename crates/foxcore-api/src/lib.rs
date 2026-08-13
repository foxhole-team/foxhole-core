#![forbid(unsafe_code)]

mod availability;
mod config;
mod flow;
mod secret;

pub use availability::{OutboundUnavailable, UnavailableReason};

pub use config::{
    AmneziaConfig, AmneziaInitPacket, AmneziaInitTag, AnyTlsConfig, ApplicationRouteAction,
    ApplicationRouteConfig, ContinuityConfig, ControlProxyConfig, CurveGroup,
    DEFAULT_LOOPBACK_INBOUND_SESSIONS, DnsBlocklistCategoryConfig, DnsBlocklistConfig, DnsCategory,
    DnsConfig, DnsMode, DnsRoute, DnsRuleSetConfig, DnsUpstream, EchConfig, EngineConfig,
    HttpProxyConfig, Hysteria2Config, Hysteria2ObfsConfig, Hysteria2PortRange, I2pConfig,
    KnownAppConfig, LoopbackInboundConfig, LoopbackUpstream, MAX_LOOPBACK_INBOUND_SESSIONS,
    MAX_LOOPBACK_INBOUNDS, NaiveConfig, NamedOutboundConfig, OutboundConfig, PacketEncoding,
    PolicyConfig, RealityConfig, RealityFingerprint, RuntimeConfig, SCHEMA_VERSION, SelectorConfig,
    ShadowTlsConfig, ShadowTlsInnerConfig, ShadowsocksConfig, SimpleObfsConfig, SocksConfig,
    StreamTransportConfig, TlsConfig, TlsVersion, TorCircuitConfig, TorConfig, TorTransportConfig,
    TrafficPolicyConfig, TrojanConfig, TuicConfig, TuicCongestionControl, TuicUdpRelayMode,
    TunConfig, UrlTestConfig, VLESS_FLOW_VISION, VlessConfig, VmessCipher, VmessConfig,
    WireguardConfig, decode_signing_digest,
};
pub use flow::{
    BlockReason, ContinuityInterruption, ContinuityPermit, ContinuityWait, CoreEvent, Destination,
    EventSink, FlowAttributor, FlowContext, FlowIdentity, IpTransport, NetworkType, OutboundId,
    PortRange, RouteAction, RouteRule,
};
pub use secret::SecretString;

pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CORE_ABI_VERSION: u32 = 1;
pub const CAPABILITIES_SCHEMA_VERSION: u32 = 1;
