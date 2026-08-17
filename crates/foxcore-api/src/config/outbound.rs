use super::*;
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundConfig {
    Direct(DirectConfig),
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Hysteria2(Hysteria2Config),
    Tuic(TuicConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    I2p(I2pConfig),
    Tor(TorConfig),
    /// L3 packet tunnel. It never joins the proxy `Outbound` enum: the runtime
    /// maps it to `OutboundMode::PacketTunnel`.
    Wireguard(WireguardConfig),
    /// A group of interchangeable proxy nodes with one active member.
    Selector(SelectorConfig),
    Socks(SocksConfig),
    Http(HttpProxyConfig),
    Naive(NaiveConfig),
    #[serde(rename = "anytls")]
    AnyTls(AnyTlsConfig),
    #[serde(rename = "shadowtls")]
    ShadowTls(ShadowTlsConfig),
}

/// Explicit direct primary used only by the app's on-device DNS/firewall guard.
///
/// The empty shape is intentional: there is no endpoint or hidden fallback to configure. Engine
/// validation additionally requires `runtime.local_guard=true`, so an imported VPN profile cannot
/// silently become a clear-network profile by changing only its outbound type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DirectConfig {}

/// Budget for a proxy handshake that is not the TCP connect itself. A proxy
/// that accepts the connection and then stalls must not pin a flow forever.
const DEFAULT_PROXY_HANDSHAKE_TIMEOUT_MS: u64 = 15_000;
const MAX_PROXY_HANDSHAKE_TIMEOUT_MS: u64 = 120_000;
/// Bounded so a hostile config cannot make the CONNECT request itself huge.
const MAX_HTTP_PROXY_HEADERS: usize = 32;
const MAX_HTTP_PROXY_HEADER_BYTES: usize = 8192;

fn default_proxy_handshake_timeout_ms() -> u64 {
    DEFAULT_PROXY_HANDSHAKE_TIMEOUT_MS
}

/// Plain SOCKS5 (RFC 1928/1929). Carries no transport layer of its own, which
/// is why it is normally a LAN or loopback hop rather than an internet one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksConfig {
    pub server: String,
    pub port: u16,
    /// Pre-resolved proxy address, so reaching the proxy never depends on
    /// in-tunnel DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    #[serde(default = "default_proxy_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

/// Plain HTTP CONNECT (RFC 9110 §9.3.6). TCP only — a datagram has no CONNECT
/// tunnel to travel in, and the protocol refuses rather than degrading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProxyConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    /// Extra request headers. Values are secrets — they commonly carry CDN or
    /// edge tokens — so they never reach `Debug` or an error string.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, SecretString>,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default = "default_proxy_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

/// NaiveProxy: HTTP/2 CONNECT with the padding scheme its README specifies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NaiveConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    /// TLS is mandatory. `tls.server_name` is the SNI; `tls.alpn` must be empty
    /// or exactly `["h2"]`.
    #[serde(default = "default_naive_tls")]
    pub tls: TlsConfig,
    /// Require the padding protocol. Turning it off makes the profile a plain
    /// HTTP/2 CONNECT proxy, which is a different thing on the wire — so it is
    /// an explicit choice and never an automatic fallback.
    #[serde(default = "default_true")]
    pub padding: bool,
    #[serde(default = "default_proxy_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

/// AnyTLS v2 client configuration.
///
/// AnyTLS owns its multiplexing and padding above the TLS stream, so the
/// transport surface is deliberately smaller than VLESS/VMess: inserting a
/// second WebSocket/H2 layer would change the documented wire protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnyTlsConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub password: SecretString,
    #[serde(default = "default_anytls_tls")]
    pub tls: TlsConfig,
    #[serde(default = "default_anytls_idle_check_interval_ms")]
    pub idle_session_check_interval_ms: u64,
    #[serde(default = "default_anytls_idle_timeout_ms")]
    pub idle_session_timeout_ms: u64,
    #[serde(default)]
    pub min_idle_session: usize,
    #[serde(default = "default_proxy_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

/// The data protocol carried inside ShadowTLS.
///
/// ShadowTLS v3 is a transport, not a destination-carrying proxy. FoxCore does
/// not yet have the general `StreamDialer` detour seam, so the production
/// slice exposes the canonical ShadowTLS → Shadowsocks composition explicitly
/// instead of accepting a destination and silently ignoring it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShadowTlsInnerConfig {
    Shadowsocks {
        method: String,
        password: SecretString,
        /// ShadowTLS is TCP-only. UDP is carried using UoT v2 over the
        /// inner Shadowsocks stream when this is enabled.
        #[serde(default = "default_true")]
        udp_over_tcp: bool,
    },
}

/// Strict ShadowTLS v3 client with an explicit inner data protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub password: SecretString,
    #[serde(default = "default_shadowtls_tls")]
    pub tls: TlsConfig,
    pub inner: ShadowTlsInnerConfig,
    #[serde(default = "default_proxy_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

fn default_naive_tls() -> TlsConfig {
    TlsConfig {
        enabled: true,
        alpn: vec!["h2".to_owned()],
        ..TlsConfig::default()
    }
}

fn default_anytls_tls() -> TlsConfig {
    TlsConfig {
        enabled: true,
        ..TlsConfig::default()
    }
}

fn default_shadowtls_tls() -> TlsConfig {
    TlsConfig {
        enabled: true,
        min_version: Some(TlsVersion::Tls13),
        max_version: Some(TlsVersion::Tls13),
        ..TlsConfig::default()
    }
}

const fn default_anytls_idle_check_interval_ms() -> u64 {
    30_000
}

const fn default_anytls_idle_timeout_ms() -> u64 {
    30_000
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            server_ip: None,
            username: None,
            password: None,
            handshake_timeout_ms: DEFAULT_PROXY_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            server_ip: None,
            username: None,
            password: None,
            headers: BTreeMap::new(),
            tls: TlsConfig::default(),
            handshake_timeout_ms: DEFAULT_PROXY_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

impl Default for NaiveConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            server_ip: None,
            username: None,
            password: None,
            tls: default_naive_tls(),
            padding: true,
            handshake_timeout_ms: DEFAULT_PROXY_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

impl Default for AnyTlsConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            server_ip: None,
            password: SecretString::default(),
            tls: default_anytls_tls(),
            idle_session_check_interval_ms: default_anytls_idle_check_interval_ms(),
            idle_session_timeout_ms: default_anytls_idle_timeout_ms(),
            min_idle_session: 0,
            handshake_timeout_ms: DEFAULT_PROXY_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

fn validate_proxy_credentials(
    protocol: &str,
    username: &Option<String>,
    password: &Option<SecretString>,
) -> Result<(), ConfigError> {
    // Half a credential pair is a configuration mistake that would otherwise
    // authenticate as nobody and look like a working anonymous proxy.
    if username.is_some() != password.is_some() {
        return Err(ConfigError::Invalid(format!(
            "{protocol} username and password must be set together"
        )));
    }
    if username.as_ref().is_some_and(|value| value.is_empty()) {
        return Err(ConfigError::Invalid(format!(
            "{protocol} username must not be empty"
        )));
    }
    Ok(())
}

fn validate_proxy_handshake_timeout(protocol: &str, value: u64) -> Result<(), ConfigError> {
    if !(1..=MAX_PROXY_HANDSHAKE_TIMEOUT_MS).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{protocol} handshake_timeout_ms must be 1..={MAX_PROXY_HANDSHAKE_TIMEOUT_MS}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedOutboundConfig {
    pub id: crate::OutboundId,
    pub outbound: OutboundConfig,
}

impl OutboundConfig {
    /// Whether this outbound carries flows as IP packets instead of streams.
    ///
    /// The distinction decides whether anything in the path can restore a name
    /// from an address: a proxy outbound terminates the flow on the userspace
    /// stack and re-dials by name, while a packet tunnel seals what the
    /// application built. The runtime asks the same question when it decides
    /// which of the two data paths to build, so the predicate lives here and
    /// both callers use it.
    pub fn is_packet_tunnel(&self) -> bool {
        matches!(self, Self::Wireguard(_))
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Direct(_) => Ok(()),
            Self::Vless(config) => {
                validate_server(&config.server, config.port)?;
                validate_uuid("VLESS", config.uuid.expose())?;
                config.tls.validate()?;
                config.transport.validate()?;
                if let Some(reality) = &config.reality {
                    if config.tls != TlsConfig::default() {
                        return Err(ConfigError::Invalid(
                            "VLESS Reality and ordinary TLS are mutually exclusive".into(),
                        ));
                    }
                    // REALITY is a security layer, not a carrier: it takes the
                    // place of `tls`, and whatever stream transport the profile
                    // names then rides inside its record layer. Every transport
                    // in the schema is a byte stream, so there is nothing here
                    // to gate on.
                    reality.validate()?;
                }
                validate_vless(config)
            }
            Self::Vmess(config) => {
                validate_server(&config.server, config.port)?;
                validate_uuid("VMess", config.uuid.expose())?;
                if config.alter_id != 0 {
                    return Err(ConfigError::Invalid(
                        "VMess legacy alter_id is not supported; use AEAD with alter_id=0".into(),
                    ));
                }
                config.tls.validate()?;
                config.transport.validate()
            }
            Self::Hysteria2(config) => {
                validate_server(&config.server, config.port)?;
                require_secret("hysteria2 password", &config.password)?;
                if let Some(Hysteria2ObfsConfig::Salamander { password }) = &config.obfs {
                    require_secret("hysteria2 salamander password", password)?;
                    if password.expose().len() > MAX_HYSTERIA2_OBFS_KEY_BYTES {
                        return Err(ConfigError::Invalid(format!(
                            "hysteria2 salamander password must be at most {MAX_HYSTERIA2_OBFS_KEY_BYTES} bytes"
                        )));
                    }
                }
                if !config.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "Hysteria2 requires TLS to be enabled".into(),
                    ));
                }
                validate_hysteria2_hopping(config)?;
                validate_hysteria2_timing(config)?;
                config.tls.reject_ech(ECH_NOT_OVER_QUIC)?;
                config.tls.validate()
            }
            Self::Tuic(config) => {
                validate_server(&config.server, config.port)?;
                validate_uuid("TUIC", config.uuid.expose())?;
                require_secret("TUIC password", &config.password)?;
                if !config.tcp && !config.udp {
                    return Err(ConfigError::Invalid(
                        "TUIC must enable at least one of tcp or udp".into(),
                    ));
                }
                if config.zero_rtt_handshake {
                    return Err(ConfigError::Invalid(
                        "TUIC zero_rtt_handshake is disabled: replayable early data is not accepted by FoxCore"
                            .into(),
                    ));
                }
                if !(1_000..=120_000).contains(&config.heartbeat_ms) {
                    return Err(ConfigError::Invalid(
                        "TUIC heartbeat_ms must be in 1000..=120000".into(),
                    ));
                }
                if !(5_000..=600_000).contains(&config.idle_timeout_ms) {
                    return Err(ConfigError::Invalid(
                        "TUIC idle_timeout_ms must be in 5000..=600000".into(),
                    ));
                }
                if !config.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "TUIC requires TLS to be enabled".into(),
                    ));
                }
                config.tls.reject_ech(ECH_NOT_OVER_QUIC)?;
                config.tls.validate()
            }
            Self::Trojan(config) => {
                validate_server(&config.server, config.port)?;
                require_secret("Trojan password", &config.password)?;
                if !config.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "Trojan requires TLS to be enabled".into(),
                    ));
                }
                config.transport.validate()?;
                config.tls.validate()
            }
            Self::Shadowsocks(config) => {
                validate_server(&config.server, config.port)?;
                config.tls.validate()?;
                config.transport.validate()?;
                if !matches!(config.transport, StreamTransportConfig::Raw) && config.udp {
                    // The plugin carries TCP only. Leaving `udp` on would send
                    // datagrams straight at the server port in the clear of the
                    // carrier, which is a different protocol than the profile
                    // describes — and the plugin port usually will not answer.
                    return Err(ConfigError::Invalid(
                        "Shadowsocks over a stream transport carries TCP only; set udp=false"
                            .into(),
                    ));
                }
                require_secret("Shadowsocks password", &config.password)?;
                if config.method.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "Shadowsocks method must not be empty".into(),
                    ));
                }
                validate_shadowsocks_carriers(config)?;
                Ok(())
            }
            Self::Wireguard(config) => {
                validate_server(&config.server, config.port)?;
                validate_wireguard_key("private_key", &config.private_key)?;
                validate_wireguard_key("peer_public_key", &config.peer_public_key)?;
                if let Some(preshared_key) = &config.preshared_key {
                    validate_wireguard_key("preshared_key", preshared_key)?;
                }
                if config.address.is_empty() {
                    return Err(ConfigError::Invalid(
                        "WireGuard address must list at least one interface prefix".into(),
                    ));
                }
                if config.allowed_ips.is_empty() {
                    return Err(ConfigError::Invalid(
                        "WireGuard allowed_ips must be explicit; an empty list is not a default route"
                            .into(),
                    ));
                }
                if let Some(amnezia) = &config.amnezia {
                    // The MTU goes in because `Jmax` is only judgeable against it.
                    amnezia.validate(config.mtu)?;
                }
                Ok(())
            }
            Self::Selector(config) => config.validate(),
            Self::Socks(config) => {
                validate_server(&config.server, config.port)?;
                validate_proxy_credentials("SOCKS5", &config.username, &config.password)?;
                validate_proxy_handshake_timeout("SOCKS5", config.handshake_timeout_ms)
            }
            Self::Http(config) => {
                validate_server(&config.server, config.port)?;
                validate_proxy_credentials("HTTP proxy", &config.username, &config.password)?;
                validate_proxy_handshake_timeout("HTTP proxy", config.handshake_timeout_ms)?;
                if config.headers.len() > MAX_HTTP_PROXY_HEADERS {
                    return Err(ConfigError::Invalid(format!(
                        "HTTP proxy headers must contain at most {MAX_HTTP_PROXY_HEADERS} entries"
                    )));
                }
                for (name, value) in &config.headers {
                    // A name carrying CR/LF would let a config inject a whole
                    // extra request line into the CONNECT.
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_graphic() && byte != b':')
                    {
                        return Err(ConfigError::Invalid(
                            "HTTP proxy header names must be non-empty printable ASCII without ':'"
                                .into(),
                        ));
                    }
                    let value = value.expose();
                    if value.len() > MAX_HTTP_PROXY_HEADER_BYTES
                        || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
                    {
                        return Err(ConfigError::Invalid(format!(
                            "HTTP proxy header '{name}' is too large or contains CR/LF"
                        )));
                    }
                }
                config.tls.validate()
            }
            Self::Naive(config) => {
                validate_server(&config.server, config.port)?;
                validate_proxy_credentials("Naive", &config.username, &config.password)?;
                validate_proxy_handshake_timeout("Naive", config.handshake_timeout_ms)?;
                if !config.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "Naive requires TLS to be enabled".into(),
                    ));
                }
                if !config.tls.alpn.is_empty() && config.tls.alpn != ["h2"] {
                    return Err(ConfigError::Invalid(
                        "Naive requires ALPN to be empty or exactly [\"h2\"]".into(),
                    ));
                }
                config.tls.validate()
            }
            Self::AnyTls(config) => {
                validate_server(&config.server, config.port)?;
                require_secret("AnyTLS password", &config.password)?;
                validate_proxy_handshake_timeout("AnyTLS", config.handshake_timeout_ms)?;
                if !config.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "AnyTLS requires TLS to be enabled".into(),
                    ));
                }
                if !(1_000..=3_600_000).contains(&config.idle_session_check_interval_ms) {
                    return Err(ConfigError::Invalid(
                        "AnyTLS idle_session_check_interval_ms must be in 1000..=3600000".into(),
                    ));
                }
                if !(1_000..=3_600_000).contains(&config.idle_session_timeout_ms) {
                    return Err(ConfigError::Invalid(
                        "AnyTLS idle_session_timeout_ms must be in 1000..=3600000".into(),
                    ));
                }
                if config.min_idle_session > 32 {
                    return Err(ConfigError::Invalid(
                        "AnyTLS min_idle_session must be at most 32".into(),
                    ));
                }
                config.tls.validate()
            }
            Self::ShadowTls(config) => {
                validate_server(&config.server, config.port)?;
                require_secret("ShadowTLS password", &config.password)?;
                validate_proxy_handshake_timeout("ShadowTLS", config.handshake_timeout_ms)?;
                if !config.tls.enabled {
                    return Err(ConfigError::Invalid(
                        "ShadowTLS v3 requires TLS to be enabled".into(),
                    ));
                }
                if config.tls.min_version == Some(TlsVersion::Tls12)
                    || config.tls.max_version == Some(TlsVersion::Tls12)
                {
                    return Err(ConfigError::Invalid(
                        "ShadowTLS v3 strict mode requires TLS 1.3".into(),
                    ));
                }
                if !config.tls.alpn.is_empty() && config.tls.alpn != ["http/1.1"] {
                    return Err(ConfigError::Invalid(
                        "ShadowTLS muddled fallback requires ALPN to be empty or exactly [\"http/1.1\"]"
                            .into(),
                    ));
                }
                config.tls.reject_ech(ECH_NOT_UNDER_SHADOWTLS)?;
                match &config.inner {
                    ShadowTlsInnerConfig::Shadowsocks {
                        method, password, ..
                    } => {
                        if method.trim().is_empty() {
                            return Err(ConfigError::Invalid(
                                "ShadowTLS inner Shadowsocks method must not be empty".into(),
                            ));
                        }
                        require_secret("ShadowTLS inner Shadowsocks password", password)?;
                    }
                }
                config.tls.validate()
            }
            Self::I2p(config) => {
                if !config.socks_address.ip().is_loopback() || config.socks_address.port() == 0 {
                    return Err(ConfigError::Invalid(
                        "I2P socks_address must be a non-zero loopback socket address".into(),
                    ));
                }
                validate_proxy_credentials("I2P SOCKS5", &config.username, &config.password)?;
                if config
                    .username
                    .as_ref()
                    .is_some_and(|value| value.len() > u8::MAX as usize)
                {
                    return Err(ConfigError::Invalid(
                        "I2P SOCKS5 username must contain 1..=255 bytes".into(),
                    ));
                }
                if config.password.as_ref().is_some_and(|value| {
                    value.is_empty() || value.expose().len() > u8::MAX as usize
                }) {
                    return Err(ConfigError::Invalid(
                        "I2P SOCKS5 password must contain 1..=255 bytes".into(),
                    ));
                }
                if !(100..=60_000).contains(&config.connect_timeout_ms) {
                    return Err(ConfigError::Invalid(
                        "I2P connect_timeout_ms must be in 100..=60000".into(),
                    ));
                }
                if !(100..=60_000).contains(&config.handshake_timeout_ms) {
                    return Err(ConfigError::Invalid(
                        "I2P handshake_timeout_ms must be in 100..=60000".into(),
                    ));
                }
                Ok(())
            }
            Self::Tor(config) => {
                if config.state_dir.trim().is_empty() || config.cache_dir.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "Tor state_dir and cache_dir must not be empty".into(),
                    ));
                }
                if !(10..=600).contains(&config.bootstrap_timeout_s) {
                    return Err(ConfigError::Invalid(
                        "Tor bootstrap_timeout_s must be in 10..=600".into(),
                    ));
                }
                if !(5..=120).contains(&config.stream_connect_timeout_s) {
                    return Err(ConfigError::Invalid(
                        "Tor stream_connect_timeout_s must be in 5..=120".into(),
                    ));
                }
                if let Some(upstream) = &config.upstream {
                    match upstream.as_ref() {
                        Self::Direct(_)
                        | Self::I2p(_)
                        | Self::Tor(_)
                        | Self::Wireguard(_)
                        | Self::Selector(_) => {
                            return Err(ConfigError::Invalid(
                                "Tor upstream must be a stream proxy".into(),
                            ));
                        }
                        stream_proxy => stream_proxy.validate()?,
                    }
                }
                if !(60..=3600).contains(&config.circuit.max_dirtiness_s) {
                    return Err(ConfigError::Invalid(
                        "Tor circuit.max_dirtiness_s must be in 60..=3600".into(),
                    ));
                }
                if !(10..=300).contains(&config.circuit.request_timeout_s) {
                    return Err(ConfigError::Invalid(
                        "Tor circuit.request_timeout_s must be in 10..=300".into(),
                    ));
                }
                if !(1..=32).contains(&config.circuit.request_max_retries) {
                    return Err(ConfigError::Invalid(
                        "Tor circuit.request_max_retries must be in 1..=32".into(),
                    ));
                }
                if config.bridges.len() > 16 {
                    return Err(ConfigError::Invalid(
                        "Tor bridges must contain at most 16 entries".into(),
                    ));
                }
                for bridge in &config.bridges {
                    let bridge = bridge.expose();
                    if bridge.is_empty()
                        || bridge.len() > 1024
                        || bridge.chars().any(char::is_control)
                    {
                        return Err(ConfigError::Invalid(
                            "Tor bridge lines must be in 1..=1024 bytes without control characters"
                                .into(),
                        ));
                    }
                }
                if config.transports.len() > 8 {
                    return Err(ConfigError::Invalid(
                        "Tor transports must contain at most 8 entries".into(),
                    ));
                }
                let mut transport_protocols = HashSet::new();
                for transport in &config.transports {
                    if transport.protocols.is_empty() || transport.protocols.len() > 16 {
                        return Err(ConfigError::Invalid(
                            "Tor transport protocols must contain 1..=16 entries".into(),
                        ));
                    }
                    for protocol in &transport.protocols {
                        if protocol.is_empty()
                            || protocol.len() > 64
                            || !protocol.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                            })
                            || !transport_protocols.insert(protocol.as_str())
                        {
                            return Err(ConfigError::Invalid(
                                "Tor transport protocols must be unique safe identifiers".into(),
                            ));
                        }
                    }
                    if transport.path.len() > 4096
                        || !std::path::Path::new(&transport.path).is_absolute()
                        || transport.path.chars().any(char::is_control)
                    {
                        return Err(ConfigError::Invalid(
                            "Tor transport path must be a bounded absolute path".into(),
                        ));
                    }
                    if transport.arguments.len() > 32
                        || transport.arguments.iter().any(|argument| {
                            let argument = argument.expose();
                            argument.is_empty()
                                || argument.len() > 2048
                                || argument.chars().any(char::is_control)
                        })
                    {
                        return Err(ConfigError::Invalid(
                            "Tor transport arguments must contain bounded non-control values"
                                .into(),
                        ));
                    }
                }
                for bridge in &config.bridges {
                    let transport = bridge
                        .expose()
                        .split_ascii_whitespace()
                        .next()
                        .unwrap_or("");
                    let looks_like_address = transport.contains(':') || transport.starts_with('[');
                    if !looks_like_address && !transport_protocols.contains(transport) {
                        return Err(ConfigError::Invalid(
                            "Tor bridge requires a configured pluggable transport".into(),
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}
