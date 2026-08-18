#![forbid(unsafe_code)]

mod availability;
mod config;
mod flow;
mod secret;

pub use availability::{OutboundUnavailable, UnavailableReason};

pub use config::{
    AmneziaConfig, AmneziaHeaderRange, AmneziaInitPacket, AmneziaInitTag, AmneziaTimerRange,
    AmneziaTimers, AnyTlsConfig, ApplicationRouteAction, ApplicationRouteConfig, ContinuityConfig,
    ControlProxyConfig, CurveGroup, DEFAULT_LOOPBACK_INBOUND_SESSIONS, DnsBlocklistCategoryConfig,
    DnsBlocklistConfig, DnsCategory, DnsConfig, DnsMode, DnsRoute, DnsRuleSetConfig, DnsUpstream,
    EchConfig, EngineConfig, HttpProxyConfig, Hysteria2Config, Hysteria2ObfsConfig,
    Hysteria2PortRange, I2pConfig, KnownAppConfig, LoopbackInboundConfig, LoopbackUpstream,
    MAX_LOOPBACK_INBOUND_SESSIONS, MAX_LOOPBACK_INBOUNDS, NaiveConfig, NamedOutboundConfig,
    OutboundConfig, PacketEncoding, PolicyConfig, RealityConfig, RealityFingerprint, RuntimeConfig,
    SCHEMA_VERSION, SelectorConfig, ShadowTlsConfig, ShadowTlsInnerConfig, ShadowsocksConfig,
    SimpleObfsConfig, SocksConfig, StreamTransportConfig, TlsConfig, TlsVersion, TorCircuitConfig,
    TorConfig, TorTransportConfig, TrafficPolicyConfig, TrojanConfig, TuicConfig,
    TuicCongestionControl, TuicUdpRelayMode, TunConfig, UrlTestConfig,
    VLESS_ENCRYPTION_ML_KEM_768_CIPHERTEXT_LEN, VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN,
    VLESS_ENCRYPTION_ML_KEM_768_SECRET_LEN, VLESS_ENCRYPTION_SUITE,
    VLESS_ENCRYPTION_X25519_KEY_LEN, VLESS_FLOW_VISION, VlessConfig, VlessEncryptionError,
    VlessEncryptionKey, VlessEncryptionMode, VlessEncryptionPadding, VlessEncryptionPaddingRange,
    VlessEncryptionParams, VmessCipher, VmessConfig, WireguardConfig, decode_signing_digest,
    parse_amnezia_header_range, parse_amnezia_timer_range, parse_vless_encryption,
    parse_vless_encryption_padding,
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
