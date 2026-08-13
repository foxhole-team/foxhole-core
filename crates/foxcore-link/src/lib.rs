#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use foxcore_api::{
    AnyTlsConfig, Hysteria2Config, Hysteria2ObfsConfig, Hysteria2PortRange, OutboundConfig,
    PacketEncoding, RealityConfig, RealityFingerprint, SecretString, ShadowsocksConfig,
    SimpleObfsConfig, StreamTransportConfig, TlsConfig, TrojanConfig, VLESS_FLOW_VISION,
    VlessConfig, VmessCipher, VmessConfig,
};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

const MAX_LINK_BYTES: usize = 16 * 1024;
const MAX_SUBSCRIPTION_BYTES: usize = 1024 * 1024;
const MAX_SUBSCRIPTION_PROFILES: usize = 256;
const MAX_HYSTERIA2_OBFS_PASSWORD_BYTES: usize = 1024;
const MAX_REPORTED_SCHEME_BYTES: usize = 64;
/// Mirrors the core's own default so a link that says nothing keeps saying it.
const DEFAULT_HYSTERIA2_HOP_INTERVAL_MS: u64 = 30_000;
const MAX_REALITY_SPIDER_X_BYTES: usize = 2048;

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("invalid share link: {0}")]
    Url(#[from] url::ParseError),
    #[error("unsupported share-link scheme {0}")]
    Scheme(String),
    #[error("unsupported share-link option: {0}")]
    Unsupported(String),
    #[error("invalid share link: {0}")]
    Invalid(String),
    #[error("invalid subscription: {0}")]
    Subscription(String),
    #[error("subscription item {index}: {source}")]
    SubscriptionItem {
        index: usize,
        #[source]
        source: Box<LinkError>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportedProfile {
    pub name: Option<String>,
    pub outbound: OutboundConfig,
    /// Options the link carried that this core recognises and does not apply.
    ///
    /// Empty for a profile that was imported whole. Non-empty means the profile
    /// works, but not in every respect the provider wrote down — which the user
    /// is entitled to know without losing the server over it.
    pub dropped: Vec<DroppedOption>,
}

/// A parameter that was understood and deliberately not carried out.
///
/// The rule for putting something here rather than refusing the profile is
/// narrow: **the option must not be able to change a byte on the wire.** A
/// dropped `mtu` or `reserved` would produce a tunnel that looks configured and
/// is not, so those stay fatal. A dropped resolver hint changes where queries go
/// — which matters, and is exactly why it is reported — but the tunnel it
/// describes is still the tunnel that gets built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedOption {
    /// The option name as it appeared in the link, e.g. `dns`. Never its value:
    /// this struct is meant to be safe to log, and a subscription's parameter
    /// values are untrusted input.
    pub option: String,
    /// What the core does instead. Written for a person, not for a parser.
    pub reason: String,
}

/// Secret-free protocol shape used by diagnostics and compatibility probes.
///
/// The values are closed enums on purpose: callers can log them without ever
/// exposing endpoints, credentials, SNI, WebSocket paths, or arbitrary query
/// values from an untrusted subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileShape {
    pub scheme: ProfileScheme,
    pub transport: ProfileTransport,
    pub security: ProfileSecurity,
    pub flow: ProfileFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileScheme {
    Vless,
    Vmess,
    Hysteria2,
    Hysteria,
    Trojan,
    Shadowsocks,
    ShadowsocksR,
    TrojanGo,
    Tuic,
    Juicity,
    Mieru,
    Snell,
    Wireguard,
    AnyTls,
    ShadowTls,
    Naive,
    Socks,
    Http,
    Ssh,
    Masque,
    Brook,
    Tor,
    I2p,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTransport {
    Raw,
    Websocket,
    Grpc,
    Http2,
    Quic,
    Kcp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileSecurity {
    None,
    Tls,
    Reality,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFlow {
    None,
    Vision,
    Other,
}

impl ProfileShape {
    pub const fn label(self) -> &'static str {
        match (self.scheme, self.transport, self.security, self.flow) {
            (
                ProfileScheme::Vless,
                ProfileTransport::Raw,
                ProfileSecurity::None,
                ProfileFlow::None,
            ) => "vless/raw/none",
            (
                ProfileScheme::Vless,
                ProfileTransport::Raw,
                ProfileSecurity::Tls,
                ProfileFlow::None,
            ) => "vless/raw/tls",
            (
                ProfileScheme::Vless,
                ProfileTransport::Raw,
                ProfileSecurity::Reality,
                ProfileFlow::None,
            ) => "vless/raw/reality",
            (
                ProfileScheme::Vless,
                ProfileTransport::Raw,
                ProfileSecurity::Reality,
                ProfileFlow::Vision,
            ) => "vless/raw/reality/vision",
            (
                ProfileScheme::Vless,
                ProfileTransport::Websocket,
                ProfileSecurity::None,
                ProfileFlow::None,
            ) => "vless/ws/none",
            (
                ProfileScheme::Vless,
                ProfileTransport::Websocket,
                ProfileSecurity::Tls,
                ProfileFlow::None,
            ) => "vless/ws/tls",
            (
                ProfileScheme::Vmess,
                ProfileTransport::Raw,
                ProfileSecurity::None,
                ProfileFlow::None,
            ) => "vmess/raw/none",
            (
                ProfileScheme::Vmess,
                ProfileTransport::Raw,
                ProfileSecurity::Tls,
                ProfileFlow::None,
            ) => "vmess/raw/tls",
            (
                ProfileScheme::Vmess,
                ProfileTransport::Websocket,
                ProfileSecurity::None,
                ProfileFlow::None,
            ) => "vmess/ws/none",
            (
                ProfileScheme::Vmess,
                ProfileTransport::Websocket,
                ProfileSecurity::Tls,
                ProfileFlow::None,
            ) => "vmess/ws/tls",
            (ProfileScheme::Hysteria2, _, ProfileSecurity::Tls, _) => "hysteria2/quic/tls",
            (ProfileScheme::Trojan, ProfileTransport::Raw, ProfileSecurity::Tls, _) => {
                "trojan/raw/tls"
            }
            (ProfileScheme::Shadowsocks, ProfileTransport::Raw, ProfileSecurity::None, _) => {
                "shadowsocks/raw/none"
            }
            (ProfileScheme::Shadowsocks, _, _, _) => "shadowsocks/plugin",
            (ProfileScheme::ShadowsocksR, _, _, _) => "shadowsocksr",
            (ProfileScheme::TrojanGo, _, _, _) => "trojan-go",
            (ProfileScheme::Hysteria, _, _, _) => "hysteria1",
            (ProfileScheme::Tuic, _, _, _) => "tuic",
            (ProfileScheme::Juicity, _, _, _) => "juicity",
            (ProfileScheme::Mieru, _, _, _) => "mieru",
            (ProfileScheme::Snell, _, _, _) => "snell",
            (ProfileScheme::Wireguard, _, _, _) => "wireguard",
            (ProfileScheme::AnyTls, _, _, _) => "anytls",
            (ProfileScheme::ShadowTls, _, _, _) => "shadowtls",
            (ProfileScheme::Naive, _, _, _) => "naive",
            (ProfileScheme::Socks, _, _, _) => "socks",
            (ProfileScheme::Http, _, _, _) => "http",
            (ProfileScheme::Ssh, _, _, _) => "ssh",
            (ProfileScheme::Masque, _, _, _) => "masque",
            (ProfileScheme::Brook, _, _, _) => "brook",
            (ProfileScheme::Tor, _, _, _) => "tor",
            (ProfileScheme::I2p, _, _, _) => "i2p",
            _ => "other",
        }
    }
}

pub fn import_link(value: &str) -> Result<ImportedProfile, LinkError> {
    validate_link_envelope(value)?;
    let scheme = link_scheme(value)?;
    match scheme.as_str() {
        "vless" => import_vless(value),
        "vmess" => import_vmess(value),
        "hysteria2" | "hy2" => import_hysteria2(value),
        "trojan" => import_trojan(value),
        "ss" => import_shadowsocks(value),
        "wg" | "wireguard" => import_wireguard(value),
        "socks" | "socks4" | "socks5" => import_socks(value),
        "http" | "https" => import_http_proxy(value),
        "naive" | "naive+https" => import_naive(value),
        "anytls" => import_anytls(value),
        _ => Err(LinkError::Scheme(scheme)),
    }
}

fn import_vmess(value: &str) -> Result<ImportedProfile, LinkError> {
    let payload = value
        .strip_prefix("vmess://")
        .or_else(|| value.strip_prefix("VMESS://"))
        .ok_or_else(|| LinkError::Invalid("VMess link has an invalid scheme".into()))?;
    let payload = payload.split('#').next().unwrap_or_default();
    let decoded = decode_base64_bytes(payload)
        .ok_or_else(|| LinkError::Invalid("VMess payload is not valid base64".into()))?;
    if decoded.len() > MAX_LINK_BYTES {
        return Err(LinkError::Invalid(
            "decoded VMess document exceeds the link size limit".into(),
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| LinkError::Invalid("VMess payload is not valid JSON".into()))?;
    let object = document
        .as_object()
        .ok_or_else(|| LinkError::Invalid("VMess document must be a JSON object".into()))?;
    reject_unknown_vmess_fields(object)?;

    if vmess_string(object, "v")?.is_some_and(|version| version != "2") {
        return Err(LinkError::Unsupported(
            "VMess document version is not supported".into(),
        ));
    }
    let server = vmess_required_string(object, "add", "server")?.to_owned();
    let port = vmess_u16(object, "port")?
        .filter(|port| *port != 0)
        .ok_or_else(|| LinkError::Invalid("VMess server port is missing or zero".into()))?;
    let uuid = vmess_required_string(object, "id", "UUID")?;
    let alter_id = vmess_u16(object, "aid")?.unwrap_or(0);
    if alter_id != 0 {
        return Err(LinkError::Unsupported(
            "VMess legacy alterId is not implemented; use AEAD alterId=0".into(),
        ));
    }
    let cipher = match vmess_string(object, "scy")?
        .or(vmess_string(object, "security")?)
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "auto" => VmessCipher::Auto,
        "aes-128-gcm" => VmessCipher::Aes128Gcm,
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => VmessCipher::Chacha20Poly1305,
        "none" | "zero" => VmessCipher::None,
        _ => {
            return Err(LinkError::Unsupported(
                "VMess data cipher is not implemented".into(),
            ));
        }
    };

    require_vmess_noop(object, "type", &["", "none"])?;
    require_vmess_disabled(object, "mux")?;
    // XUDP exists for VMess too, but only the VLESS carrier is implemented here.
    for field in ["packetEncoding", "packet_encoding"] {
        require_vmess_noop(object, field, &["", "none"])?;
    }
    for field in ["pbk", "sid", "spx"] {
        if object.contains_key(field) {
            return Err(LinkError::Unsupported(
                "VMess Reality fields are not implemented".into(),
            ));
        }
    }
    if vmess_string(object, "fp")?.is_some_and(|value| !value.is_empty()) {
        return Err(LinkError::Unsupported(
            "VMess TLS fingerprint emulation is not implemented".into(),
        ));
    }

    let transport = match vmess_string(object, "net")?
        .unwrap_or("tcp")
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "tcp" | "raw" => {
            if vmess_string(object, "path")?.is_some_and(|value| !value.is_empty())
                || vmess_string(object, "host")?.is_some_and(|value| !value.is_empty())
            {
                return Err(LinkError::Unsupported(
                    "VMess raw transport cannot use WebSocket path/host".into(),
                ));
            }
            StreamTransportConfig::Raw
        }
        "ws" | "websocket" => StreamTransportConfig::Websocket {
            path: vmess_string(object, "path")?
                .filter(|value| !value.is_empty())
                .unwrap_or("/")
                .to_owned(),
            host: vmess_string(object, "host")?
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            headers: Default::default(),
        },
        _ => {
            return Err(LinkError::Unsupported(
                "VMess transport is not implemented".into(),
            ));
        }
    };

    let tls_mode = vmess_string(object, "tls")?
        .unwrap_or("")
        .to_ascii_lowercase();
    let tls_enabled = match tls_mode.as_str() {
        "" | "none" => false,
        "tls" => true,
        "reality" => {
            return Err(LinkError::Unsupported(
                "VMess over Reality is not implemented".into(),
            ));
        }
        _ => {
            return Err(LinkError::Unsupported(
                "VMess security mode is not implemented".into(),
            ));
        }
    };
    let insecure = ["insecure", "allowInsecure", "skip-cert-verify"]
        .into_iter()
        .map(|field| vmess_bool(object, field))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .any(|value| value);
    if !tls_enabled
        && (insecure
            || vmess_string(object, "sni")?.is_some_and(|value| !value.is_empty())
            || vmess_string(object, "alpn")?.is_some_and(|value| !value.is_empty()))
    {
        return Err(LinkError::Unsupported(
            "VMess TLS options require tls=tls".into(),
        ));
    }
    let server_ip = vmess_string(object, "server_ip")?
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|_| LinkError::Invalid("VMess server_ip is not an IP address".into()))
        })
        .transpose()?;

    Ok(ImportedProfile {
        name: vmess_string(object, "ps")?
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        dropped: Vec::new(),
        outbound: OutboundConfig::Vmess(VmessConfig {
            server,
            port,
            server_ip,
            uuid: SecretString::new(uuid),
            alter_id,
            cipher,
            transport,
            tls: TlsConfig {
                enabled: tls_enabled,
                server_name: vmess_string(object, "sni")?
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned),
                insecure,
                pinned_spki_sha256: None,
                alpn: vmess_string(object, "alpn")?
                    .map(|value| {
                        value
                            .split(',')
                            .filter(|part| !part.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                ..TlsConfig::default()
            },
        }),
    })
}

fn reject_unknown_vmess_fields(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), LinkError> {
    const ALLOWED: &[&str] = &[
        "add",
        "aid",
        "allowInsecure",
        "alpn",
        "fp",
        "host",
        "id",
        "insecure",
        "mux",
        "net",
        "packetEncoding",
        "packet_encoding",
        "path",
        "pbk",
        "port",
        "ps",
        "scy",
        "security",
        "server_ip",
        "sid",
        "skip-cert-verify",
        "sni",
        "spx",
        "tfo",
        "tls",
        "type",
        "v",
    ];
    let mut unknown = object.keys().filter(|key| !ALLOWED.contains(&key.as_str()));
    if unknown.next().is_some() {
        Err(LinkError::Unsupported(
            "VMess document contains an unknown field".into(),
        ))
    } else {
        Ok(())
    }
}

fn vmess_required_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
    label: &str,
) -> Result<&'a str, LinkError> {
    vmess_string(object, field)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LinkError::Invalid(format!("VMess {label} is missing")))
}

fn vmess_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<&'a str>, LinkError> {
    match object.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(LinkError::Invalid(format!(
            "VMess field {field} must be a string"
        ))),
    }
}

fn vmess_u16(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<u16>, LinkError> {
    match object.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => value
            .parse()
            .map(Some)
            .map_err(|_| LinkError::Invalid(format!("VMess field {field} is not a u16"))),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| LinkError::Invalid(format!("VMess field {field} is not a u16"))),
        Some(_) => Err(LinkError::Invalid(format!(
            "VMess field {field} is not a u16"
        ))),
    }
}

fn vmess_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<bool>, LinkError> {
    match object.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(value)) => Ok(Some(*value)),
        Some(serde_json::Value::String(value)) => parse_bool(value).map(Some),
        Some(serde_json::Value::Number(value)) if value.as_u64() == Some(0) => Ok(Some(false)),
        Some(serde_json::Value::Number(value)) if value.as_u64() == Some(1) => Ok(Some(true)),
        Some(_) => Err(LinkError::Invalid(format!(
            "VMess field {field} is not a boolean"
        ))),
    }
}

fn require_vmess_noop(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    accepted: &[&str],
) -> Result<(), LinkError> {
    if vmess_string(object, field)?.is_some_and(|value| !accepted.contains(&value)) {
        Err(LinkError::Unsupported(format!(
            "VMess field {field} is not implemented"
        )))
    } else {
        Ok(())
    }
}

fn require_vmess_disabled(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<(), LinkError> {
    if vmess_bool(object, field)?.unwrap_or(false) {
        Err(LinkError::Unsupported(format!(
            "VMess field {field}=true is not implemented"
        )))
    } else {
        Ok(())
    }
}

/// Import a bounded plaintext or base64-encoded URI subscription.
///
/// No network access happens here. Callers own download policy, TLS validation,
/// and secret storage; this function only parses the response body.
pub fn import_subscription(value: &str) -> Result<Vec<ImportedProfile>, LinkError> {
    if value.is_empty() || value.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(format!(
            "body length must be in 1..={MAX_SUBSCRIPTION_BYTES} bytes"
        )));
    }
    let text = decode_subscription_body(value)?;
    if text.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(
            "decoded body exceeds the subscription size limit".into(),
        ));
    }

    let mut profiles = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if profiles.len() == MAX_SUBSCRIPTION_PROFILES {
            return Err(LinkError::Subscription(format!(
                "profile count exceeds {MAX_SUBSCRIPTION_PROFILES}"
            )));
        }
        let profile = import_link(line).map_err(|source| LinkError::SubscriptionItem {
            index: line_index + 1,
            source: Box::new(source),
        })?;
        profiles.push(profile);
    }
    if profiles.is_empty() {
        return Err(LinkError::Subscription(
            "subscription contains no profiles".into(),
        ));
    }
    Ok(profiles)
}

/// One line of a subscription that did not import, described without quoting it.
///
/// The line itself is never carried. A subscription line *is* a credential — a
/// VLESS UUID, a Shadowsocks password, a Hysteria2 secret — and a rejection
/// report is the most likely thing in this whole crate to end up in a log, a
/// bug report or a screenshot. What a caller actually needs to act is the line
/// number and the reason, and those are safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedLine {
    /// One-based, so it lines up with what a text editor shows.
    pub index: usize,
    /// The URL scheme, when the line had a recognisable one. Not a secret: it
    /// is the part that says `tg` or `vless`, never the part after it.
    pub scheme: Option<String>,
    /// Why it was refused, reduced to a closed diagnostic category. The strict
    /// importer still returns the detailed error to its direct caller, but this
    /// report is deliberately safe to persist or paste into a bug report.
    pub reason: String,
}

/// What a lenient subscription import produced.
#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionImport {
    pub profiles: Vec<ImportedProfile>,
    /// Lines that did not become profiles. Reported rather than discarded: a
    /// user whose subscription lost four of its twelve servers is entitled to
    /// know, and silence would read as "the provider only sent eight".
    pub rejected: Vec<RejectedLine>,
}

/// Imports every line that parses, reporting the ones that did not.
///
/// Real subscriptions are not clean lists. Providers routinely append a `tg://`
/// support-channel link, an `https://` notice, an expiry banner or a protocol
/// this build does not carry. [`import_subscription`] refuses the whole body on
/// the first such line, which means one advertising line costs the user every
/// server they paid for — observed on a real subscription, where a single
/// `tg://` rejected all ten profiles.
///
/// This is the import an app should call. The strict one remains for callers
/// that genuinely need all-or-nothing.
///
/// Still refuses outright when the body is oversized, undecodable, or yields no
/// profiles at all — those are failures of the subscription, not of one line.
pub fn import_subscription_partial(value: &str) -> Result<SubscriptionImport, LinkError> {
    if value.is_empty() || value.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(format!(
            "body length must be in 1..={MAX_SUBSCRIPTION_BYTES} bytes"
        )));
    }
    let text = decode_subscription_body(value)?;
    if text.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(
            "decoded body exceeds the subscription size limit".into(),
        ));
    }

    let mut profiles = Vec::new();
    let mut rejected = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if profiles.len() == MAX_SUBSCRIPTION_PROFILES {
            // The cap is a memory bound, not a preference. Everything past it
            // is reported as refused rather than dropped, so a truncated import
            // never looks like a complete one.
            rejected.push(RejectedLine {
                index: line_index + 1,
                scheme: link_scheme(line).ok(),
                reason: format!("profile count exceeds {MAX_SUBSCRIPTION_PROFILES}"),
            });
            continue;
        }
        match import_link(line) {
            Ok(profile) => profiles.push(profile),
            Err(error) => rejected.push(RejectedLine {
                index: line_index + 1,
                scheme: link_scheme(line).ok(),
                reason: safe_rejection_reason(&error),
            }),
        }
    }
    if profiles.is_empty() {
        return Err(LinkError::Subscription(
            "subscription contains no profiles".into(),
        ));
    }
    Ok(SubscriptionImport { profiles, rejected })
}

/// Reduce an import error to a fixed UI/log-safe category.
///
/// Detailed parser errors can legitimately contain a decoded query option. A subscription line is
/// a credential, so those details stay on the strict call boundary and never enter the partial
/// import report that applications commonly persist, display, or attach to a bug report.
fn safe_rejection_reason(error: &LinkError) -> String {
    let category = match error {
        LinkError::Url(_) | LinkError::Invalid(_) => "invalid share link",
        LinkError::Scheme(_) => "unsupported share-link scheme",
        LinkError::Unsupported(_) => "unsupported share-link option",
        LinkError::Subscription(_) => "invalid subscription item",
        LinkError::SubscriptionItem { source, .. } => return safe_rejection_reason(source),
    };
    category.to_owned()
}

/// Inspect every profile in a bounded subscription without importing secrets.
///
/// This is deliberately less strict than [`import_subscription`]: unsupported
/// protocols still produce a closed, log-safe shape so production probes can
/// report exactly which protocol module is missing.
pub fn inspect_subscription(value: &str) -> Result<Vec<ProfileShape>, LinkError> {
    if value.is_empty() || value.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(format!(
            "body length must be in 1..={MAX_SUBSCRIPTION_BYTES} bytes"
        )));
    }
    let text = decode_subscription_body(value)?;
    if text.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(
            "decoded body exceeds the subscription size limit".into(),
        ));
    }

    let mut shapes = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if shapes.len() == MAX_SUBSCRIPTION_PROFILES {
            return Err(LinkError::Subscription(format!(
                "profile count exceeds {MAX_SUBSCRIPTION_PROFILES}"
            )));
        }
        let shape = inspect_link_shape(line).map_err(|source| LinkError::SubscriptionItem {
            index: line_index + 1,
            source: Box::new(source),
        })?;
        shapes.push(shape);
    }
    if shapes.is_empty() {
        return Err(LinkError::Subscription(
            "subscription contains no profiles".into(),
        ));
    }
    Ok(shapes)
}

/// Import the first profile matching a closed, secret-free scheme selector.
///
/// This is intended for interoperability probes and migration tools that need
/// to test one supported protocol even while the same subscription still
/// contains protocols scheduled for later implementation.
pub fn import_first_profile_by_scheme(
    value: &str,
    requested: ProfileScheme,
) -> Result<ImportedProfile, LinkError> {
    if value.is_empty() || value.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(format!(
            "body length must be in 1..={MAX_SUBSCRIPTION_BYTES} bytes"
        )));
    }
    let text = decode_subscription_body(value)?;
    if text.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(LinkError::Subscription(
            "decoded body exceeds the subscription size limit".into(),
        ));
    }
    let mut profile_count = 0usize;
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        profile_count = profile_count.saturating_add(1);
        if profile_count > MAX_SUBSCRIPTION_PROFILES {
            return Err(LinkError::Subscription(format!(
                "profile count exceeds {MAX_SUBSCRIPTION_PROFILES}"
            )));
        }
        let shape = inspect_link_shape(line).map_err(|source| LinkError::SubscriptionItem {
            index: line_index + 1,
            source: Box::new(source),
        })?;
        if shape.scheme == requested {
            return import_link(line).map_err(|source| LinkError::SubscriptionItem {
                index: line_index + 1,
                source: Box::new(source),
            });
        }
    }
    Err(LinkError::Subscription(
        "subscription contains no profile for the requested protocol".into(),
    ))
}

pub fn inspect_link_shape(value: &str) -> Result<ProfileShape, LinkError> {
    validate_link_envelope(value)?;
    let scheme = link_scheme(value)?;
    match scheme.as_str() {
        "vless" => inspect_vless_shape(value),
        "vmess" => inspect_vmess_shape(value),
        "hysteria2" | "hy2" => Ok(ProfileShape {
            scheme: ProfileScheme::Hysteria2,
            transport: ProfileTransport::Quic,
            security: ProfileSecurity::Tls,
            flow: ProfileFlow::None,
        }),
        "trojan" => Ok(ProfileShape {
            scheme: ProfileScheme::Trojan,
            transport: ProfileTransport::Raw,
            security: ProfileSecurity::Tls,
            flow: ProfileFlow::None,
        }),
        "ss" => inspect_shadowsocks_shape(value),
        "ssr" => Ok(opaque_shape(ProfileScheme::ShadowsocksR)),
        "trojan-go" | "trojan+ws" => Ok(opaque_shape(ProfileScheme::TrojanGo)),
        "hysteria" | "hy" => Ok(opaque_shape(ProfileScheme::Hysteria)),
        "tuic" => Ok(opaque_shape(ProfileScheme::Tuic)),
        "juicity" => Ok(opaque_shape(ProfileScheme::Juicity)),
        "mieru" => Ok(opaque_shape(ProfileScheme::Mieru)),
        "snell" => Ok(opaque_shape(ProfileScheme::Snell)),
        "wg" | "wireguard" => Ok(opaque_shape(ProfileScheme::Wireguard)),
        "anytls" => Ok(ProfileShape {
            scheme: ProfileScheme::AnyTls,
            transport: ProfileTransport::Raw,
            security: ProfileSecurity::Tls,
            flow: ProfileFlow::None,
        }),
        "shadowtls" => Ok(opaque_shape(ProfileScheme::ShadowTls)),
        "naive" | "naive+https" => Ok(opaque_shape(ProfileScheme::Naive)),
        "socks" | "socks4" | "socks5" => Ok(opaque_shape(ProfileScheme::Socks)),
        "http" | "https" => Ok(opaque_shape(ProfileScheme::Http)),
        "ssh" => Ok(opaque_shape(ProfileScheme::Ssh)),
        "masque" | "h3" | "http3" => Ok(opaque_shape(ProfileScheme::Masque)),
        "brook" => Ok(opaque_shape(ProfileScheme::Brook)),
        "tor" => Ok(opaque_shape(ProfileScheme::Tor)),
        "i2p" => Ok(opaque_shape(ProfileScheme::I2p)),
        _ => Ok(ProfileShape {
            scheme: ProfileScheme::Other,
            transport: ProfileTransport::Other,
            security: ProfileSecurity::Other,
            flow: ProfileFlow::Other,
        }),
    }
}

fn inspect_shadowsocks_shape(value: &str) -> Result<ProfileShape, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    Ok(ProfileShape {
        scheme: ProfileScheme::Shadowsocks,
        transport: if query.get("plugin").is_some_and(|plugin| !plugin.is_empty()) {
            ProfileTransport::Other
        } else {
            ProfileTransport::Raw
        },
        security: ProfileSecurity::None,
        flow: ProfileFlow::None,
    })
}

const fn opaque_shape(scheme: ProfileScheme) -> ProfileShape {
    ProfileShape {
        scheme,
        transport: ProfileTransport::Other,
        security: ProfileSecurity::Other,
        flow: ProfileFlow::Other,
    }
}

fn inspect_vless_shape(value: &str) -> Result<ProfileShape, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    Ok(ProfileShape {
        scheme: ProfileScheme::Vless,
        transport: classify_transport(query.get("type").map(String::as_str)),
        security: classify_security(query.get("security").map(String::as_str)),
        flow: classify_flow(query.get("flow").map(String::as_str)),
    })
}

#[derive(Deserialize)]
struct VmessShapeDocument {
    #[serde(default)]
    net: Option<String>,
    #[serde(default)]
    tls: Option<String>,
}

fn inspect_vmess_shape(value: &str) -> Result<ProfileShape, LinkError> {
    let payload = value
        .strip_prefix("vmess://")
        .or_else(|| value.strip_prefix("VMESS://"))
        .ok_or_else(|| LinkError::Invalid("VMess link has an invalid scheme".into()))?;
    let payload = payload.split('#').next().unwrap_or_default();
    let decoded = decode_base64_bytes(payload)
        .ok_or_else(|| LinkError::Invalid("VMess payload is not valid base64".into()))?;
    if decoded.len() > MAX_LINK_BYTES {
        return Err(LinkError::Invalid(
            "decoded VMess document exceeds the link size limit".into(),
        ));
    }
    let document: VmessShapeDocument = serde_json::from_slice(&decoded)
        .map_err(|_| LinkError::Invalid("VMess payload is not valid JSON".into()))?;
    Ok(ProfileShape {
        scheme: ProfileScheme::Vmess,
        transport: classify_transport(document.net.as_deref()),
        security: classify_security(document.tls.as_deref()),
        flow: ProfileFlow::None,
    })
}

fn classify_transport(value: Option<&str>) -> ProfileTransport {
    match value.unwrap_or("tcp").to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => ProfileTransport::Raw,
        "ws" | "websocket" => ProfileTransport::Websocket,
        "grpc" => ProfileTransport::Grpc,
        "h2" | "http" | "http2" => ProfileTransport::Http2,
        "quic" => ProfileTransport::Quic,
        "kcp" | "mkcp" => ProfileTransport::Kcp,
        _ => ProfileTransport::Other,
    }
}

fn classify_security(value: Option<&str>) -> ProfileSecurity {
    match value.unwrap_or("none").to_ascii_lowercase().as_str() {
        "" | "none" => ProfileSecurity::None,
        "tls" => ProfileSecurity::Tls,
        "reality" => ProfileSecurity::Reality,
        _ => ProfileSecurity::Other,
    }
}

fn classify_flow(value: Option<&str>) -> ProfileFlow {
    match value.unwrap_or("").to_ascii_lowercase().as_str() {
        "" | "none" => ProfileFlow::None,
        "xtls-rprx-vision" | "vision" => ProfileFlow::Vision,
        _ => ProfileFlow::Other,
    }
}

fn validate_link_envelope(value: &str) -> Result<(), LinkError> {
    if value.is_empty() || value.len() > MAX_LINK_BYTES {
        return Err(LinkError::Invalid(format!(
            "link length must be in 1..={MAX_LINK_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(LinkError::Invalid(
            "link must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn link_scheme(value: &str) -> Result<String, LinkError> {
    let scheme = value
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .ok_or_else(|| LinkError::Invalid("missing URI scheme".into()))?;
    let bytes = scheme.as_bytes();
    let valid = bytes.len() <= MAX_REPORTED_SCHEME_BYTES
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'-' | b'.'));
    if !valid {
        return Err(LinkError::Invalid("invalid URI scheme".into()));
    }
    Ok(scheme.to_ascii_lowercase())
}

fn import_vless(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    if url.password().is_some() {
        return Err(LinkError::Invalid(
            "VLESS credential must be a single percent-encoded UUID".into(),
        ));
    }
    let query = query(&url)?;
    reject_unknown_options(
        &query,
        &[
            "alpn",
            "allowinsecure",
            "encryption",
            "flow",
            "fp",
            "headertype",
            "host",
            "insecure",
            "mux",
            "peer",
            "pin",
            "pinned_spki_sha256",
            "path",
            "pbk",
            "security",
            "server_ip",
            "skip-cert-verify",
            "sni",
            "sid",
            "packetencoding",
            "spx",
            "type",
        ],
    )?;
    let transport = vless_transport(&query)?;
    require_disabled(&query, "mux")?;
    let flow = vless_flow(&query)?;
    if flow.is_some() {
        // Refuse here rather than let the profile import and fail at start:
        // an imported profile that cannot run is a worse answer than a link
        // that says why.
        if !matches!(transport, StreamTransportConfig::Raw) {
            return Err(LinkError::Unsupported(
                "VLESS Vision requires raw TCP transport".into(),
            ));
        }
        if !matches!(
            query.get("security").map(String::as_str),
            Some("tls") | Some("reality")
        ) {
            return Err(LinkError::Unsupported(
                "VLESS Vision requires REALITY or TLS".into(),
            ));
        }
    }
    // Vision forces XUDP: the reference client rewrites every UDP flow into a
    // Mux carrier, so a link that asks for anything else is asking for a wire
    // shape that does not exist. Recording `xudp` in the profile keeps that
    // visible instead of applying it behind the user's back.
    let packet_encoding = match (&flow, vless_packet_encoding(&query)?) {
        (Some(_), PacketEncoding::None) if !query.contains_key("packetencoding") => {
            PacketEncoding::Xudp
        }
        (Some(_), PacketEncoding::None) => {
            return Err(LinkError::Unsupported(
                "VLESS Vision carries UDP as XUDP; packetEncoding=none is not available".into(),
            ));
        }
        (_, encoding) => encoding,
    };
    if query
        .get("encryption")
        .is_some_and(|encryption| encryption != "none")
    {
        return Err(LinkError::Unsupported(
            "VLESS encryption must be none".into(),
        ));
    }
    let security = query.get("security").map(String::as_str).unwrap_or("none");
    let (tls, reality) = match security {
        "none" => {
            require_noop(&query, "fp", &["", "chrome"])?;
            require_noop(&query, "spx", &["", "/"])?;
            reject_options_requiring_security(&query, &["pbk", "sid"])?;
            for option in [
                "alpn",
                "allowinsecure",
                "insecure",
                "peer",
                "pin",
                "pinned_spki_sha256",
                "skip-cert-verify",
                "sni",
            ] {
                if query.contains_key(option) {
                    return Err(LinkError::Unsupported(format!(
                        "VLESS {option} requires TLS or Reality"
                    )));
                }
            }
            (TlsConfig::default(), None)
        }
        "tls" => {
            reject_options_requiring_security(&query, &["pbk", "sid", "spx"])?;
            if query.contains_key("fp") {
                return Err(LinkError::Unsupported(
                    "VLESS TLS client fingerprint emulation is not implemented".into(),
                ));
            }
            (tls_config(&query, true)?, None)
        }
        "reality" => {
            if !matches!(transport, StreamTransportConfig::Raw) {
                return Err(LinkError::Unsupported(
                    "VLESS Reality currently requires raw TCP transport".into(),
                ));
            }
            for option in [
                "alpn",
                "allowinsecure",
                "insecure",
                "peer",
                "pin",
                "pinned_spki_sha256",
                "skip-cert-verify",
            ] {
                if query.contains_key(option) {
                    return Err(LinkError::Unsupported(format!(
                        "VLESS Reality cannot use ordinary TLS option {option}"
                    )));
                }
            }
            (TlsConfig::default(), Some(reality_config(&query)?))
        }
        _ => {
            return Err(LinkError::Unsupported(
                "requested VLESS security mode is not implemented".into(),
            ));
        }
    };
    let (server, port) = endpoint(&url)?;
    let uuid = decode_component(url.username())?;
    if uuid.is_empty() {
        return Err(LinkError::Invalid("missing VLESS UUID".into()));
    }
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::Vless(VlessConfig {
            server,
            port,
            server_ip: server_ip(&query)?,
            uuid: SecretString::new(uuid),
            flow,
            transport,
            packet_encoding,
            tls,
            reality,
        }),
    })
}

fn reject_options_requiring_security(
    query: &HashMap<String, String>,
    options: &[&str],
) -> Result<(), LinkError> {
    if let Some(option) = options.iter().find(|option| query.contains_key(**option)) {
        Err(LinkError::Unsupported(format!(
            "VLESS {option} requires Reality"
        )))
    } else {
        Ok(())
    }
}

fn reality_config(query: &HashMap<String, String>) -> Result<RealityConfig, LinkError> {
    let public_key = query
        .get("pbk")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LinkError::Invalid("VLESS Reality requires pbk".into()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| LinkError::Invalid("VLESS Reality pbk is not valid base64url".into()))?;
    if decoded.len() != 32 {
        return Err(LinkError::Invalid(
            "VLESS Reality pbk must decode to 32 bytes".into(),
        ));
    }
    let server_name = query
        .get("sni")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| LinkError::Invalid("VLESS Reality requires sni".into()))?;
    let short_id = query.get("sid").cloned().unwrap_or_default();
    if short_id.len() > 16
        || !short_id.len().is_multiple_of(2)
        || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(LinkError::Invalid(
            "VLESS Reality sid must contain an even number of 0..=16 hexadecimal characters".into(),
        ));
    }
    // Xray's `fp=` names a uTLS parrot family, not a build. `fp=chrome` is the
    // only value this core can honour, and it maps to the one Chrome profile
    // that is the default; a link asking for `firefox` or `safari` is refused
    // rather than quietly served a Chrome hello, because the whole point of the
    // parameter is which bytes go on the wire.
    let fingerprint = match query.get("fp").map(String::as_str).unwrap_or("chrome") {
        "" | "chrome" => RealityFingerprint::default(),
        other => {
            return Err(LinkError::Unsupported(format!(
                "VLESS Reality fp={other} is not implemented; this core sends fp=chrome only"
            )));
        }
    };
    let spider_x = query.get("spx").cloned().map(SecretString::new);
    if spider_x
        .as_ref()
        .is_some_and(|value| value.expose().len() > MAX_REALITY_SPIDER_X_BYTES)
    {
        return Err(LinkError::Invalid(
            "VLESS Reality spx exceeds 2048 bytes".into(),
        ));
    }
    Ok(RealityConfig {
        server_name,
        public_key: SecretString::new(public_key.clone()),
        short_id: SecretString::new(short_id),
        fingerprint,
        handshake_timeout_ms: 15_000,
        spider_x,
    })
}

/// `packetEncoding` selects how UDP reaches the server. Only the two encodings
/// this core actually implements are accepted; anything else fails closed rather
/// than silently falling back to plain UDP-over-stream.
/// The `flow=` parameter, accepted only for the one flow FoxCore implements.
///
/// `xtls-rprx-vision-udp443` is refused rather than trimmed to its base name:
/// the suffix is a promise to carry UDP/443, which this core does not, and
/// importing it as plain Vision would silently break QUIC instead of saying so.
fn vless_flow(query: &HashMap<String, String>) -> Result<Option<String>, LinkError> {
    match query.get("flow").map(String::as_str).unwrap_or_default() {
        "" | "none" => Ok(None),
        VLESS_FLOW_VISION => Ok(Some(VLESS_FLOW_VISION.to_owned())),
        other => Err(LinkError::Unsupported(format!(
            "VLESS flow {other} is not implemented"
        ))),
    }
}

fn vless_packet_encoding(query: &HashMap<String, String>) -> Result<PacketEncoding, LinkError> {
    match query
        .get("packetencoding")
        .map(String::as_str)
        .unwrap_or_default()
    {
        "" | "none" => Ok(PacketEncoding::None),
        "xudp" => Ok(PacketEncoding::Xudp),
        "packetaddr" | "packet" => Ok(PacketEncoding::Packetaddr),
        other => Err(LinkError::Unsupported(format!(
            "VLESS packetEncoding {other} is not implemented"
        ))),
    }
}

fn vless_transport(query: &HashMap<String, String>) -> Result<StreamTransportConfig, LinkError> {
    match query.get("type").map(String::as_str).unwrap_or("tcp") {
        "tcp" | "raw" => {
            require_noop(query, "headertype", &["", "none"])?;
            if query.contains_key("path") || query.contains_key("host") {
                return Err(LinkError::Unsupported(
                    "VLESS raw transport cannot use WebSocket path/host".into(),
                ));
            }
            Ok(StreamTransportConfig::Raw)
        }
        "ws" | "websocket" => {
            require_noop(query, "headertype", &["", "none"])?;
            Ok(StreamTransportConfig::Websocket {
                path: query.get("path").cloned().unwrap_or_else(|| "/".into()),
                host: query.get("host").cloned().filter(|host| !host.is_empty()),
                headers: Default::default(),
            })
        }
        "httpupgrade" => Ok(StreamTransportConfig::HttpUpgrade {
            path: query.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: query.get("host").cloned().filter(|host| !host.is_empty()),
            headers: Default::default(),
        }),
        "grpc" | "gun" => Ok(StreamTransportConfig::Grpc {
            service_name: query
                .get("servicename")
                .cloned()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    LinkError::Unsupported("gRPC transport without serviceName".into())
                })?,
            multi_mode: query.get("mode").map(String::as_str) == Some("multi"),
            authority: query
                .get("authority")
                .cloned()
                .filter(|authority| !authority.is_empty()),
        }),
        "http" | "h2" => Ok(StreamTransportConfig::Http2 {
            // Xray encodes several fronting hosts as a comma separated list.
            host: query
                .get("host")
                .map(|host| {
                    host.split(',')
                        .map(str::trim)
                        .filter(|host| !host.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            path: query.get("path").cloned().unwrap_or_else(|| "/".into()),
            method: query
                .get("method")
                .cloned()
                .filter(|method| !method.is_empty())
                .unwrap_or_else(|| "PUT".into()),
        }),
        _ => Err(LinkError::Unsupported(
            "requested transport type is not implemented".into(),
        )),
    }
}

fn import_hysteria2(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(
        &query,
        &[
            "alpn",
            "allowinsecure",
            "downmbps",
            "hopinterval",
            "insecure",
            "mport",
            "obfs",
            "obfs-password",
            "peer",
            "pin",
            "pinned_spki_sha256",
            "security",
            "server_ip",
            "skip-cert-verify",
            "sni",
            "upmbps",
        ],
    )?;
    require_noop(&query, "security", &["", "tls"])?;
    let (server, port) = endpoint(&url)?;
    let password = credential(&url)?;
    let obfs = hysteria2_obfs(&query)?;
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::Hysteria2(Hysteria2Config {
            server,
            port,
            server_ip: server_ip(&query)?,
            password: SecretString::new(password),
            up_mbps: integer(&query, "upmbps")?.unwrap_or(0),
            down_mbps: integer(&query, "downmbps")?.unwrap_or(0),
            obfs,
            server_ports: hysteria2_port_ranges(&query)?,
            hop_interval_ms: integer(&query, "hopinterval")?
                .map(u64::from)
                .map(|seconds| seconds.saturating_mul(1_000))
                .unwrap_or(DEFAULT_HYSTERIA2_HOP_INTERVAL_MS),
            tls: tls_config(&query, true)?,
        }),
    })
}

/// The de-facto port-hopping parameter: `mport=20000-50000,443`.
///
/// A `Url` will not hold a range in its port position, so the range travels as a
/// query parameter the way every client that supports hopping writes it. A value
/// we cannot parse is refused rather than dropped — importing a hopping profile
/// as a single-port one hands the user a server the ISP is already throttling.
fn hysteria2_port_ranges(
    query: &HashMap<String, String>,
) -> Result<Vec<Hysteria2PortRange>, LinkError> {
    let Some(value) = query.get("mport").filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut ranges = Vec::new();
    for part in value.split([',', '|']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once(['-', ':']) {
            Some((start, end)) => (start, end),
            None => (part, part),
        };
        let start: u16 = start.trim().parse().map_err(|_| {
            LinkError::Invalid(format!("Hysteria2 mport {part} is not a port range"))
        })?;
        let end: u16 = end.trim().parse().map_err(|_| {
            LinkError::Invalid(format!("Hysteria2 mport {part} is not a port range"))
        })?;
        if start == 0 || start > end {
            return Err(LinkError::Invalid(format!(
                "Hysteria2 mport {part} is not a port range"
            )));
        }
        ranges.push(Hysteria2PortRange { start, end });
    }
    Ok(ranges)
}

fn hysteria2_obfs(
    query: &HashMap<String, String>,
) -> Result<Option<Hysteria2ObfsConfig>, LinkError> {
    match (query.get("obfs"), query.get("obfs-password")) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(LinkError::Invalid(
            "Hysteria2 obfs requires obfs-password".into(),
        )),
        (None, Some(_)) => Err(LinkError::Invalid(
            "Hysteria2 obfs-password requires obfs".into(),
        )),
        (Some(kind), Some(password)) if kind == "salamander" => {
            if password.is_empty() || password.len() > MAX_HYSTERIA2_OBFS_PASSWORD_BYTES {
                return Err(LinkError::Invalid(format!(
                    "Hysteria2 obfs-password length must be in 1..={MAX_HYSTERIA2_OBFS_PASSWORD_BYTES} bytes"
                )));
            }
            Ok(Some(Hysteria2ObfsConfig::Salamander {
                password: SecretString::new(password.clone()),
            }))
        }
        (Some(kind), Some(_)) => Err(LinkError::Unsupported(format!("Hysteria2 obfs={kind}"))),
    }
}

fn import_trojan(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(
        &query,
        &[
            "alpn",
            "allowinsecure",
            "insecure",
            "peer",
            "pin",
            "pinned_spki_sha256",
            "authority",
            "headertype",
            "host",
            "method",
            "mode",
            "path",
            "security",
            "server_ip",
            "servicename",
            "skip-cert-verify",
            "sni",
            "type",
        ],
    )?;
    require_noop(&query, "security", &["", "tls"])?;
    let (server, port) = endpoint(&url)?;
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::Trojan(TrojanConfig {
            server,
            port,
            server_ip: server_ip(&query)?,
            password: SecretString::new(credential(&url)?),
            tls: tls_config(&query, true)?,
            transport: vless_transport(&query)?,
        }),
    })
}

/// WireGuard's default port, used when the link omits one. Unlike the proxy
/// schemes this is fixed by the protocol rather than by `Url`'s scheme table.
const WIREGUARD_DEFAULT_PORT: u16 = 51820;

/// `reserved=1,2,3` — the three header bytes some providers use as a client id.
///
/// Exactly three are required. A shorter or longer list is a different idea of
/// what the field means, and padding it with zeros would send an identifier the
/// profile never asked for.
fn wireguard_reserved(value: &str) -> Result<[u8; 3], LinkError> {
    let mut bytes = [0_u8; 3];
    let mut seen = 0;
    for part in value.split(',') {
        let byte = part.trim().parse::<u8>().map_err(|_| {
            LinkError::Invalid("WireGuard reserved must be comma-separated 0..=255 values".into())
        })?;
        if seen == bytes.len() {
            return Err(LinkError::Invalid(
                "WireGuard reserved must carry exactly three values".into(),
            ));
        }
        bytes[seen] = byte;
        seen += 1;
    }
    if seen != bytes.len() {
        return Err(LinkError::Invalid(
            "WireGuard reserved must carry exactly three values".into(),
        ));
    }
    Ok(bytes)
}

fn wireguard_networks(field: &str, value: &str) -> Result<Vec<ipnet::IpNet>, LinkError> {
    let mut networks = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        networks.push(
            part.parse::<ipnet::IpNet>()
                .map_err(|_| LinkError::Invalid(format!("WireGuard {field} is not a prefix")))?,
        );
    }
    if networks.is_empty() {
        return Err(LinkError::Invalid(format!(
            "WireGuard {field} must list at least one prefix"
        )));
    }
    Ok(networks)
}

fn import_wireguard(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(
        &query,
        &[
            "address",
            "addresses",
            "allowed-ips",
            "allowed_ips",
            "allowedips",
            "dns",
            "keepalive",
            "mtu",
            "persistent_keepalive",
            "persistentkeepalive",
            "pre-shared-key",
            "preshared_key",
            "presharedkey",
            "public-key",
            "public_key",
            "publickey",
            "reserved",
            "server_ip",
        ],
    )?;
    // `dns=` is reported, not fatal. See `wireguard_dns_note`.
    let dropped = wireguard_dns_note(query.contains_key("dns"));
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| LinkError::Invalid("missing server host".into()))?
        .to_owned();
    let port = url.port().unwrap_or(WIREGUARD_DEFAULT_PORT);
    let first = |names: &[&str]| names.iter().find_map(|name| query.get(*name)).cloned();

    let private_key = credential(&url)?;
    let peer_public_key = first(&["publickey", "public_key", "public-key"]).ok_or_else(|| {
        LinkError::Invalid("WireGuard link is missing the peer public key".into())
    })?;
    let address = first(&["address", "addresses"]).ok_or_else(|| {
        LinkError::Invalid("WireGuard link is missing the interface address".into())
    })?;
    // Absent allowed-ips means the full route in every client that speaks this
    // link format, so it is a default rather than an omission.
    let allowed_ips = first(&["allowed_ips", "allowedips", "allowed-ips"])
        .unwrap_or_else(|| "0.0.0.0/0, ::/0".to_owned());
    let mtu = match query.get("mtu") {
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|mtu| (576..=65_535).contains(mtu))
            .ok_or_else(|| LinkError::Invalid("WireGuard mtu must be 576..=65535".into()))?,
        None => 1420,
    };
    let persistent_keepalive_s =
        match first(&["keepalive", "persistentkeepalive", "persistent_keepalive"]) {
            Some(value) => {
                Some(value.parse::<u16>().map_err(|_| {
                    LinkError::Invalid("WireGuard keepalive must be 0..=65535".into())
                })?)
            }
            None => None,
        };
    let reserved = match query.get("reserved") {
        Some(value) => Some(wireguard_reserved(value)?),
        None => None,
    };
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped,
        outbound: OutboundConfig::Wireguard(foxcore_api::WireguardConfig {
            server: host,
            port,
            server_ip: server_ip(&query)?,
            private_key: SecretString::new(private_key),
            peer_public_key: SecretString::new(peer_public_key),
            preshared_key: first(&["presharedkey", "preshared_key", "pre-shared-key"])
                .map(SecretString::new),
            address: wireguard_networks("address", &address)?,
            allowed_ips: wireguard_networks("allowed_ips", &allowed_ips)?,
            mtu,
            persistent_keepalive_s,
            reserved,
            amnezia: None,
        }),
    })
}

/// Import a wg-quick / AmneziaWG `.conf` (INI) file.
///
/// This is not a link, so it has its own entry point: the format users actually
/// receive from a WireGuard provider is a file, and asking them to hand-convert
/// it into a `wg://` URL is where profiles get typed in wrong.
///
/// Strict on purpose. An unknown key is refused rather than skipped, because
/// every key in this file changes what goes on the wire or where it goes, and a
/// tunnel that silently ignored one would be a different tunnel than the one the
/// provider issued.
pub fn import_wireguard_conf(value: &str) -> Result<ImportedProfile, LinkError> {
    if value.len() > MAX_LINK_BYTES {
        return Err(LinkError::Invalid("WireGuard config is too large".into()));
    }
    let mut interface: Vec<(String, String)> = Vec::new();
    let mut peer: Vec<(String, String)> = Vec::new();
    let mut section = ConfSection::None;
    let mut peers = 0_usize;

    for line in value.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = match name.trim().to_ascii_lowercase().as_str() {
                "interface" => ConfSection::Interface,
                "peer" => {
                    peers += 1;
                    ConfSection::Peer
                }
                other => {
                    return Err(LinkError::Invalid(format!(
                        "unknown WireGuard config section [{other}]"
                    )));
                }
            };
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            return Err(LinkError::Invalid(format!(
                "WireGuard config line is not key = value: {line}"
            )));
        };
        // A base64 key ends in '=' padding, so only the first separator counts.
        let entry = (key.trim().to_ascii_lowercase(), raw.trim().to_owned());
        match section {
            ConfSection::Interface => interface.push(entry),
            ConfSection::Peer => peer.push(entry),
            ConfSection::None => {
                return Err(LinkError::Invalid(
                    "WireGuard config has a key outside any section".into(),
                ));
            }
        }
    }

    if peers != 1 {
        // The core carries one peer tunnel. Importing the first of several
        // would drop routes the file said belong elsewhere.
        return Err(LinkError::Unsupported(
            "WireGuard config must contain exactly one [Peer]".into(),
        ));
    }

    let find = |entries: &[(String, String)], name: &str| -> Option<String> {
        entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    let require = |entries: &[(String, String)], name: &str, label: &str| {
        find(entries, name)
            .ok_or_else(|| LinkError::Invalid(format!("WireGuard config is missing {label}")))
    };

    for (key, _) in interface.iter().chain(peer.iter()) {
        if !WIREGUARD_CONF_KEYS.contains(&key.as_str()) {
            return Err(LinkError::Unsupported(format!(
                "WireGuard config key {key} is not implemented"
            )));
        }
    }
    // Same rule as the link form: reported, not fatal.
    let dropped = wireguard_dns_note(find(&interface, "dns").is_some());
    for hook in [
        "preup",
        "postup",
        "predown",
        "postdown",
        "table",
        "saveconfig",
    ] {
        if find(&interface, hook).is_some() {
            // These run shell commands or rewrite the host routing table.
            return Err(LinkError::Unsupported(format!(
                "WireGuard config {hook} is a host-side wg-quick directive this core does not run"
            )));
        }
    }

    let endpoint = require(&peer, "endpoint", "Endpoint")?;
    let (server, port) = split_wireguard_endpoint(&endpoint)?;
    let mtu = match find(&interface, "mtu") {
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|mtu| (576..=65_535).contains(mtu))
            .ok_or_else(|| LinkError::Invalid("WireGuard mtu must be 576..=65535".into()))?,
        None => 1420,
    };
    let persistent_keepalive_s = match find(&peer, "persistentkeepalive") {
        Some(value) if value.eq_ignore_ascii_case("off") => None,
        Some(value) => Some(
            value
                .parse::<u16>()
                .map_err(|_| LinkError::Invalid("WireGuard keepalive must be 0..=65535".into()))?,
        ),
        None => None,
    };

    Ok(ImportedProfile {
        // The file format has no name field; the caller labels the profile.
        name: None,
        dropped,
        outbound: OutboundConfig::Wireguard(foxcore_api::WireguardConfig {
            server,
            port,
            server_ip: None,
            private_key: SecretString::new(require(&interface, "privatekey", "PrivateKey")?),
            peer_public_key: SecretString::new(require(&peer, "publickey", "PublicKey")?),
            preshared_key: find(&peer, "presharedkey").map(SecretString::new),
            address: wireguard_networks("address", &require(&interface, "address", "Address")?)?,
            allowed_ips: wireguard_networks(
                "allowed_ips",
                &find(&peer, "allowedips").unwrap_or_else(|| "0.0.0.0/0, ::/0".to_owned()),
            )?,
            mtu,
            persistent_keepalive_s,
            reserved: None,
            amnezia: amnezia_from_conf(&interface)?,
        }),
    })
}

enum ConfSection {
    None,
    Interface,
    Peer,
}

/// Every key the importer understands. Lower-cased; anything else is refused.
const WIREGUARD_CONF_KEYS: &[&str] = &[
    "address",
    "allowedips",
    "dns",
    "endpoint",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "jc",
    "jmax",
    "jmin",
    "listenport",
    "mtu",
    "persistentkeepalive",
    "presharedkey",
    "privatekey",
    "publickey",
    "s1",
    "s2",
    "s3",
    "s4",
];

/// AmneziaWG 1.5 block, or `None` when the file is plain WireGuard.
///
/// Partial blocks are refused instead of being filled in with defaults: a peer
/// configured with `S1` but not the matching headers decodes nothing, and a
/// half-obfuscated tunnel fails in a way that looks like a network problem.
fn amnezia_from_conf(
    interface: &[(String, String)],
) -> Result<Option<foxcore_api::AmneziaConfig>, LinkError> {
    const OBFUSCATION_KEYS: [&str; 9] = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"];
    /// 2.0 additions. Independently optional: upstream defaults S3/S4 to zero
    /// and H1..H4 to 1..4, so a file that carries only an init packet is a
    /// complete configuration and refusing it would reject a valid profile.
    const EXTENSION_KEYS: [&str; 7] = ["s3", "s4", "i1", "i2", "i3", "i4", "i5"];
    let present: Vec<&str> = OBFUSCATION_KEYS
        .into_iter()
        .filter(|key| interface.iter().any(|(name, _)| name == key))
        .collect();
    let has_extensions = EXTENSION_KEYS
        .into_iter()
        .any(|key| interface.iter().any(|(name, _)| name == key));
    if present.is_empty() {
        if !has_extensions {
            return Ok(None);
        }
        // 2.0 keys alone: everything 1.5 keeps its default, which is what the
        // reference does. Dropping them because the older block is absent would
        // silently import a plain WireGuard profile.
        return Ok(Some(foxcore_api::AmneziaConfig {
            cookie_junk_size: optional_small(interface, "s3")?,
            transport_junk_size: optional_small(interface, "s4")?,
            init_packets: amnezia_init_packets(interface)?,
            ..foxcore_api::AmneziaConfig::default()
        }));
    }
    if present.len() != OBFUSCATION_KEYS.len() {
        let missing: Vec<&str> = OBFUSCATION_KEYS
            .into_iter()
            .filter(|key| !present.contains(key))
            .collect();
        return Err(LinkError::Invalid(format!(
            "AmneziaWG config is incomplete, missing: {}",
            missing.join(", ")
        )));
    }
    let number = |key: &str| -> Result<u32, LinkError> {
        interface
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
            .unwrap_or_default()
            .parse::<u32>()
            .map_err(|_| LinkError::Invalid(format!("AmneziaWG {key} must be a number")))
    };
    let small = |key: &str| -> Result<u16, LinkError> {
        u16::try_from(number(key)?)
            .map_err(|_| LinkError::Invalid(format!("AmneziaWG {key} must fit in 16 bits")))
    };
    Ok(Some(foxcore_api::AmneziaConfig {
        cookie_junk_size: optional_small(interface, "s3")?,
        transport_junk_size: optional_small(interface, "s4")?,
        init_packets: amnezia_init_packets(interface)?,
        junk_packet_count: small("jc")?,
        junk_min_size: small("jmin")?,
        junk_max_size: small("jmax")?,
        init_junk_size: small("s1")?,
        response_junk_size: small("s2")?,
        header_initiation: number("h1")?,
        header_response: number("h2")?,
        header_cookie: number("h3")?,
        header_transport: number("h4")?,
    }))
}

/// The note a WireGuard `dns=` produces, or nothing when there was none.
///
/// This used to reject the profile. The reasoning was sound — the resolver comes
/// from `DnsConfig`, there is nowhere in an outbound to honour a per-profile
/// one, and accepting the parameter while ignoring it would be a silent
/// substitution. The conclusion was wrong in practice: the owner's subscription
/// carries exactly one `wireguard://` server and it carries `dns=`, so the
/// "honest error" was really "your only WireGuard server does not exist".
///
/// It qualifies for a note rather than a refusal on the one test that matters:
/// **it cannot change a byte the tunnel puts on the wire.** The peer, the keys,
/// the allowed prefixes and the MTU are all unaffected; what changes is where
/// queries go, and that is what the note says out loud so the app can show it
/// and the user can point `dns.upstreams` wherever they meant to.
fn wireguard_dns_note(present: bool) -> Vec<DroppedOption> {
    if !present {
        return Vec::new();
    }
    vec![DroppedOption {
        option: "dns".to_owned(),
        reason: "the resolver comes from the engine's dns configuration; \
                 this profile's own DNS server is not used"
            .to_owned(),
    }]
}

/// An optional AmneziaWG 2.0 numeric field. Absent is 1.5 behaviour.
fn optional_small(interface: &[(String, String)], key: &str) -> Result<u16, LinkError> {
    match interface.iter().find(|(name, _)| name == key) {
        None => Ok(0),
        Some((_, value)) => value
            .parse::<u16>()
            .map_err(|_| LinkError::Invalid(format!("AmneziaWG {key} must be a 16-bit number"))),
    }
}

/// `I1..I5`, parsed once here into the typed tag chain the core carries.
///
/// The keys are positional, so a gap is refused rather than closed up: a file
/// with `I1` and `I3` is describing a template order that the reference would
/// send as I1 then I3, and quietly renumbering it to I1, I2 would put different
/// bytes on the wire than the file asked for.
fn amnezia_init_packets(
    interface: &[(String, String)],
) -> Result<Vec<foxcore_api::AmneziaInitPacket>, LinkError> {
    let mut packets = Vec::new();
    let mut seen_gap = false;
    for index in 1..=5 {
        let key = format!("i{index}");
        let Some((_, spec)) = interface.iter().find(|(name, _)| *name == key) else {
            seen_gap = true;
            continue;
        };
        if seen_gap {
            return Err(LinkError::Invalid(
                "AmneziaWG init packets must be numbered from I1 without gaps".into(),
            ));
        }
        packets.push(foxcore_api::AmneziaInitPacket {
            tags: parse_amnezia_tags(spec, &key)?,
        });
    }
    Ok(packets)
}

/// The reference's `<key arg>` syntax.
///
/// Faithful in the two places it looks wrong: text outside the brackets is
/// discarded, and an unknown key is an error rather than a skipped element —
/// silently dropping one shortens every packet the profile meant to send.
fn parse_amnezia_tags(
    spec: &str,
    key: &str,
) -> Result<Vec<foxcore_api::AmneziaInitTag>, LinkError> {
    use foxcore_api::AmneziaInitTag as Tag;

    let bad = || LinkError::Invalid(format!("AmneziaWG {key} template is malformed"));
    let mut tags = Vec::new();
    let mut rest = spec;
    while let Some(start) = rest.find('<') {
        let end = rest[start..].find('>').ok_or_else(bad)? + start;
        let body = &rest[start + 1..end];
        rest = &rest[end + 1..];
        let mut fields = body.split_whitespace();
        let name = fields.next().ok_or_else(bad)?;
        let argument = fields.next().unwrap_or_default();
        let len = || argument.parse::<u16>().map_err(|_| bad());
        tags.push(match name {
            "b" => {
                let hex = argument.strip_prefix("0x").unwrap_or(argument);
                if hex.is_empty()
                    || !hex.len().is_multiple_of(2)
                    || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(bad());
                }
                Tag::Bytes {
                    hex: hex.to_ascii_lowercase(),
                }
            }
            "t" => Tag::Timestamp,
            "r" => Tag::Random { len: len()? },
            "rc" => Tag::RandomLetters { len: len()? },
            "rd" => Tag::RandomDigits { len: len()? },
            "d" => Tag::Payload,
            "ds" => Tag::PayloadBase64,
            "dz" => Tag::PayloadSize { len: len()? },
            _ => return Err(bad()),
        });
    }
    if tags.is_empty() {
        return Err(bad());
    }
    Ok(tags)
}

/// `host:port`, including the bracketed IPv6 form wg-quick writes.
fn split_wireguard_endpoint(value: &str) -> Result<(String, u16), LinkError> {
    let invalid = || LinkError::Invalid(format!("WireGuard Endpoint {value} is not host:port"));
    let (host, port) = match value.strip_prefix('[') {
        Some(rest) => {
            let (host, tail) = rest.split_once(']').ok_or_else(invalid)?;
            (host.to_owned(), tail.strip_prefix(':').ok_or_else(invalid)?)
        }
        None => {
            let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
            (host.to_owned(), port)
        }
    };
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if host.is_empty() || port == 0 {
        return Err(invalid());
    }
    Ok((host, port))
}

/// Endpoint of a plain proxy link.
///
/// `Url` drops a port that is its scheme's default, so `https://proxy:443`
/// parses with no port at all. Reusing [`endpoint`] here would reject the most
/// ordinary form of the link as malformed.
fn proxy_endpoint(url: &Url) -> Result<(String, u16), LinkError> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| LinkError::Invalid("missing server host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| LinkError::Invalid("missing server port".into()))?;
    Ok((host.to_owned(), port))
}

/// `user:password@` for the plain proxies.
///
/// Unlike [`credential`] both halves are meaningful here, and a half-filled
/// pair is refused: a link carrying only a username would otherwise import as
/// an anonymous proxy that looks configured.
fn user_password(url: &Url) -> Result<(Option<String>, Option<SecretString>), LinkError> {
    let username = decode_component(url.username())?;
    let password = match url.password() {
        Some(password) => Some(decode_component(password)?),
        None => None,
    };
    match (username.is_empty(), password) {
        (true, None) => Ok((None, None)),
        (false, Some(password)) => Ok((Some(username), Some(SecretString::new(password)))),
        _ => Err(LinkError::Invalid(
            "proxy credentials must supply both a username and a password".into(),
        )),
    }
}

fn import_socks(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(&query, &["server_ip", "udp"])?;
    // SOCKS4 has no authentication and no IPv6 or domain addressing; importing
    // it as SOCKS5 would be a different protocol wearing the same name.
    if link_scheme(value)? == "socks4" {
        return Err(LinkError::Unsupported("SOCKS4".into()));
    }
    let (server, port) = proxy_endpoint(&url)?;
    let (username, password) = user_password(&url)?;
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::Socks(foxcore_api::SocksConfig {
            server,
            port,
            server_ip: server_ip(&query)?,
            username,
            password,
            ..Default::default()
        }),
    })
}

fn import_http_proxy(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(
        &query,
        &[
            "allowinsecure",
            "alpn",
            "insecure",
            "pin",
            "pinned_spki_sha256",
            "server_ip",
            "skip-cert-verify",
            "sni",
        ],
    )?;
    // `http(s)://` is also what a subscription URL looks like. A proxy endpoint
    // has no path, so refusing one keeps a pasted subscription from importing
    // as a proxy profile instead of failing loudly. (`endpoint` already demands
    // an explicit port, which most subscription URLs omit.)
    if !matches!(url.path(), "" | "/") {
        return Err(LinkError::Invalid(
            "an HTTP proxy link carries no path — this looks like a subscription URL".into(),
        ));
    }
    // The scheme is the only thing that decides whether the hop to the proxy is
    // encrypted, so it is read from the scheme and never from a query option.
    let over_tls = link_scheme(value)? == "https";
    let (server, port) = proxy_endpoint(&url)?;
    let (username, password) = user_password(&url)?;
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::Http(foxcore_api::HttpProxyConfig {
            server,
            port,
            server_ip: server_ip(&query)?,
            username,
            password,
            tls: tls_config(&query, over_tls)?,
            ..Default::default()
        }),
    })
}

fn import_naive(value: &str) -> Result<ImportedProfile, LinkError> {
    // `naive+https://` is the form the real subscription carries. The bare
    // `naive://` scheme is refused rather than assumed to mean the same thing:
    // Naive is TLS-only, and inventing the transport is exactly the kind of
    // guess that turns into a downgrade.
    let scheme = link_scheme(value)?;
    if scheme != "naive+https" {
        return Err(LinkError::Unsupported(format!(
            "naive scheme '{scheme}' (only naive+https:// carries the required TLS)"
        )));
    }
    let suffix = value
        .strip_prefix("naive+https://")
        .ok_or_else(|| LinkError::Invalid("a Naive link must start with naive+https://".into()))?;
    let normalised = format!("https://{suffix}");
    let url = Url::parse(&normalised)?;
    let query = query(&url)?;
    reject_unknown_options(
        &query,
        &[
            "allowinsecure",
            "insecure",
            "padding",
            "pin",
            "pinned_spki_sha256",
            "server_ip",
            "skip-cert-verify",
            "sni",
        ],
    )?;
    let (server, port) = proxy_endpoint(&url)?;
    let (username, password) = user_password(&url)?;
    let mut tls = tls_config(&query, true)?;
    // The protocol negotiates over HTTP/2 and nothing else.
    tls.alpn = vec!["h2".to_owned()];
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::Naive(foxcore_api::NaiveConfig {
            server,
            port,
            server_ip: server_ip(&query)?,
            username,
            password,
            tls,
            // Absent means on. A link that switched padding off silently would
            // import as a plain H2 proxy while still being called Naive.
            padding: !matches!(
                query.get("padding").map(String::as_str),
                Some("0" | "false")
            ),
            ..Default::default()
        }),
    })
}

/// Import the documented AnyTLS URI:
/// `anytls://password@host[:port]/?sni=...&insecure=0|1#name`.
fn import_anytls(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(&query, &["insecure", "sni"])?;
    let server = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| LinkError::Invalid("missing server host".into()))?
        .to_owned();
    let port = url.port().unwrap_or(443);
    let password = credential(&url)?;
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped: Vec::new(),
        outbound: OutboundConfig::AnyTls(AnyTlsConfig {
            server,
            port,
            password: SecretString::new(password),
            tls: TlsConfig {
                enabled: true,
                server_name: query.get("sni").cloned(),
                insecure: query
                    .get("insecure")
                    .map(|value| parse_bool(value))
                    .transpose()?
                    .unwrap_or(false),
                ..TlsConfig::default()
            },
            ..AnyTlsConfig::default()
        }),
    })
}

fn import_shadowsocks(value: &str) -> Result<ImportedProfile, LinkError> {
    let url = Url::parse(value)?;
    let query = query(&url)?;
    reject_unknown_options(&query, &["outline", "plugin", "prefix", "server_ip", "udp"])?;
    let plugin = shadowsocks_plugin(&query)?;
    let ShadowsocksPlugin {
        transport,
        tls: plugin_tls,
        obfs,
        dropped,
    } = plugin;
    // `outline=1` only marks the vendor of an otherwise standard AEAD key. The
    // remaining Outline-specific behaviour, dynamic config keys, is its own
    // fetch-and-parse step and stays rejected.
    require_noop(&query, "outline", &["", "1", "true"])?;
    let outline_prefix = query
        .get("prefix")
        .filter(|value| !value.is_empty())
        .map(|value| outline_prefix(value))
        .transpose()?;
    let (server, port) = endpoint(&url)?;
    let credentials = if let Some(password) = url.password() {
        format!(
            "{}:{}",
            decode_component(url.username())?,
            decode_component(password)?
        )
    } else {
        decode_base64_text(url.username())?
    };
    let (method, password) = credentials
        .split_once(':')
        .ok_or_else(|| LinkError::Invalid("Shadowsocks credentials need method:password".into()))?;
    if method.is_empty() || password.is_empty() {
        return Err(LinkError::Invalid(
            "empty Shadowsocks method or password".into(),
        ));
    }
    let tunnelled = !matches!(transport, StreamTransportConfig::Raw) || obfs.is_some();
    Ok(ImportedProfile {
        name: profile_name(&url)?,
        dropped,
        outbound: OutboundConfig::Shadowsocks(ShadowsocksConfig {
            server,
            port,
            server_ip: server_ip(&query)?,
            method: method.to_owned(),
            password: SecretString::new(password),
            udp: match query
                .get("udp")
                .map(|value| parse_bool(value))
                .transpose()?
            {
                // Asking for UDP over a TCP-only carrier is a contradiction, not
                // a preference; the core would refuse the profile at start.
                Some(true) if tunnelled => {
                    return Err(LinkError::Unsupported(
                        "Shadowsocks plugin transports carry TCP only; udp=1 cannot be honoured"
                            .into(),
                    ));
                }
                Some(udp) => udp,
                // Recorded rather than assumed: the profile has to say which
                // carriage it uses, because the answer changed with the plugin.
                None => !tunnelled,
            },
            transport,
            tls: plugin_tls,
            outline_prefix,
            obfs,
        }),
    })
}

/// Outline `prefix=`, decoded the way the Outline SDK decodes it.
///
/// The query value is percent-decoded into text and then read one **character**
/// per byte: every code point must be U+0000..=U+00FF and contributes its low
/// byte. That is `parseStringPrefix` in `outline-sdk/x/configurl`, and it is why
/// a TLS-looking prefix is written `%16%03%01` while a high byte such as 0xA8
/// travels as the UTF-8 of U+00A8 (`%C2%A8`) rather than as a raw `%A8`.
fn outline_prefix(value: &str) -> Result<Vec<u8>, LinkError> {
    value
        .chars()
        .map(|character| {
            u8::try_from(character as u32).map_err(|_| {
                LinkError::Invalid(
                    "Outline prefix character is out of range: every character must be U+0000..=U+00FF"
                        .into(),
                )
            })
        })
        .collect()
}

/// What a recognised SIP003 `plugin=` string resolves to.
struct ShadowsocksPlugin {
    transport: StreamTransportConfig,
    tls: TlsConfig,
    obfs: Option<SimpleObfsConfig>,
    dropped: Vec<DroppedOption>,
}

impl ShadowsocksPlugin {
    fn none() -> Self {
        Self {
            transport: StreamTransportConfig::Raw,
            tls: TlsConfig::default(),
            obfs: None,
            dropped: Vec::new(),
        }
    }
}

/// SIP003 `plugin=` option string.
///
/// Two plugins are carriers rather than protocols and are therefore expressed
/// natively instead of by launching a subprocess: `v2ray-plugin` in WebSocket
/// mode is the same WebSocket carrier VLESS and VMess already use, and
/// `simple-obfs` is one HTTP request or one fake ClientHello in front of the
/// same Shadowsocks stream. Every other plugin stays refused: this core does
/// not spawn helper binaries, and a plugin silently dropped would put plain
/// Shadowsocks on a port expecting a tunnel.
fn shadowsocks_plugin(query: &HashMap<String, String>) -> Result<ShadowsocksPlugin, LinkError> {
    let Some(spec) = query.get("plugin").filter(|value| !value.is_empty()) else {
        return Ok(ShadowsocksPlugin::none());
    };
    let mut parts = spec.split(';');
    let name = parts.next().unwrap_or_default().trim();
    match name {
        "v2ray-plugin" => shadowsocks_v2ray_plugin(parts),
        // `obfs-local` is the binary the reference ships; `simple-obfs` is the
        // name the same plugin is written under in most subscriptions.
        "obfs-local" | "simple-obfs" => shadowsocks_simple_obfs(parts),
        other => Err(LinkError::Unsupported(format!(
            "Shadowsocks SIP003 plugin {other}"
        ))),
    }
}

fn shadowsocks_v2ray_plugin<'a>(
    parts: impl Iterator<Item = &'a str>,
) -> Result<ShadowsocksPlugin, LinkError> {
    let mut mode = "websocket".to_owned();
    let mut tls = false;
    let mut path = "/".to_owned();
    let mut host: Option<String> = None;
    for option in parts {
        let option = option.trim();
        if option.is_empty() {
            continue;
        }
        let (key, value) = match option.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim().to_owned()),
            None => (option, String::new()),
        };
        match key {
            "mode" => mode = value,
            "tls" => tls = true,
            "path" => path = value,
            "host" => host = Some(value),
            // Present and harmless only when off; a live mux changes the framing.
            "mux" if value == "0" => {}
            // Client-side noise that never reaches the wire.
            "loglevel" => {}
            other => {
                return Err(LinkError::Unsupported(format!(
                    "v2ray-plugin option {other} is not implemented"
                )));
            }
        }
    }
    if mode != "websocket" {
        return Err(LinkError::Unsupported(format!(
            "v2ray-plugin mode {mode} is not implemented"
        )));
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    let tls = if tls {
        TlsConfig {
            enabled: true,
            server_name: host.clone(),
            ..TlsConfig::default()
        }
    } else {
        TlsConfig::default()
    };
    Ok(ShadowsocksPlugin {
        transport: StreamTransportConfig::Websocket {
            path,
            host,
            headers: Default::default(),
        },
        tls,
        obfs: None,
        dropped: Vec::new(),
    })
}

/// `plugin=obfs-local;obfs=http;obfs-host=…[;obfs-uri=…][;http-method=…]`
/// or `plugin=obfs-local;obfs=tls;obfs-host=…`.
///
/// `obfs-host` has no default here on purpose. The reference plugin falls back
/// to `cloudfront.net`, which is a value the server matches against — guessing
/// it would produce a profile that looks imported and cannot connect.
fn shadowsocks_simple_obfs<'a>(
    parts: impl Iterator<Item = &'a str>,
) -> Result<ShadowsocksPlugin, LinkError> {
    let mut mode: Option<String> = None;
    let mut host: Option<String> = None;
    let mut uri: Option<String> = None;
    let mut method: Option<String> = None;
    let mut dropped = Vec::new();
    for option in parts {
        let option = option.trim();
        if option.is_empty() {
            continue;
        }
        let (key, value) = match option.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim().to_owned()),
            None => (option, String::new()),
        };
        match key {
            "obfs" => mode = Some(value),
            "obfs-host" => host = Some(value),
            "obfs-uri" => uri = Some(value),
            "http-method" => method = Some(value),
            // Socket options of the plugin process. They change how the bytes
            // travel, never which bytes they are, so the profile still connects
            // to the same server in the same disguise.
            "fast-open" | "mptcp" => dropped.push(DroppedOption {
                option: key.to_owned(),
                reason: "the core opens its own protected socket and does not take \
                         connection options from a plugin string"
                    .to_owned(),
            }),
            "t" | "timeout" | "v" | "verbose" => {}
            other => {
                return Err(LinkError::Unsupported(format!(
                    "simple-obfs option {other} is not implemented"
                )));
            }
        }
    }
    match mode.as_deref() {
        Some("http" | "tls") => {}
        Some(other) => {
            return Err(LinkError::Unsupported(format!(
                "simple-obfs mode {other} is not implemented"
            )));
        }
        None => {
            return Err(LinkError::Invalid(
                "simple-obfs needs obfs=http or obfs=tls".into(),
            ));
        }
    }
    let host = host.filter(|host| !host.is_empty()).ok_or_else(|| {
        LinkError::Invalid("simple-obfs needs an obfs-host the server agrees on".into())
    })?;
    let obfs = match mode.as_deref() {
        Some("http") => SimpleObfsConfig::Http {
            host,
            uri: uri
                .filter(|uri| !uri.is_empty())
                .unwrap_or_else(|| "/".into()),
            method: method
                .filter(|method| !method.is_empty())
                .unwrap_or_else(|| "GET".into()),
        },
        Some("tls") => {
            // Neither reaches the wire in TLS mode, and accepting them would
            // mean quietly ignoring something the profile asked for.
            if uri.is_some() || method.is_some() {
                return Err(LinkError::Invalid(
                    "simple-obfs obfs-uri and http-method belong to obfs=http".into(),
                ));
            }
            SimpleObfsConfig::Tls { host }
        }
        _ => unreachable!("the mode was checked before the host"),
    };
    Ok(ShadowsocksPlugin {
        transport: StreamTransportConfig::Raw,
        tls: TlsConfig::default(),
        obfs: Some(obfs),
        dropped,
    })
}

fn endpoint(url: &Url) -> Result<(String, u16), LinkError> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| LinkError::Invalid("missing server host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| LinkError::Invalid("missing server port".into()))?;
    Ok((host.to_owned(), port))
}

fn credential(url: &Url) -> Result<String, LinkError> {
    if url.password().is_some() {
        return Err(LinkError::Invalid(
            "credential must be one percent-encoded URI userinfo value".into(),
        ));
    }
    let credential = decode_component(url.username())?;
    if credential.is_empty() {
        Err(LinkError::Invalid("missing credential".into()))
    } else {
        Ok(credential)
    }
}

fn query(url: &Url) -> Result<HashMap<String, String>, LinkError> {
    let mut result = HashMap::new();
    for (key, value) in url.query_pairs() {
        let key = key.to_ascii_lowercase();
        if result.insert(key.clone(), value.into_owned()).is_some() {
            return Err(LinkError::Invalid(format!("duplicate query option {key}")));
        }
    }
    Ok(result)
}

fn reject_unknown_options(
    query: &HashMap<String, String>,
    allowed: &[&str],
) -> Result<(), LinkError> {
    let mut unknown: Vec<_> = query
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .collect();
    unknown.sort_unstable();
    if let Some(option) = unknown.first() {
        Err(LinkError::Unsupported(format!(
            "unknown query option {option}"
        )))
    } else {
        Ok(())
    }
}

fn require_noop(
    query: &HashMap<String, String>,
    option: &str,
    accepted: &[&str],
) -> Result<(), LinkError> {
    if query
        .get(option)
        .is_some_and(|value| !accepted.contains(&value.as_str()))
    {
        Err(LinkError::Unsupported(format!(
            "{option} value is not implemented"
        )))
    } else {
        Ok(())
    }
}

fn require_disabled(query: &HashMap<String, String>, option: &str) -> Result<(), LinkError> {
    if query
        .get(option)
        .map(|value| parse_bool(value))
        .transpose()?
        .unwrap_or(false)
    {
        Err(LinkError::Unsupported(format!(
            "{option}=true is not implemented"
        )))
    } else {
        Ok(())
    }
}

fn tls_config(query: &HashMap<String, String>, enabled: bool) -> Result<TlsConfig, LinkError> {
    Ok(TlsConfig {
        enabled,
        server_name: query.get("sni").or_else(|| query.get("peer")).cloned(),
        insecure: aliased_bool(query, &["insecure", "allowinsecure", "skip-cert-verify"])?
            .unwrap_or(false),
        pinned_spki_sha256: query
            .get("pin")
            .or_else(|| query.get("pinned_spki_sha256"))
            .cloned(),
        alpn: query
            .get("alpn")
            .map(|value| {
                value
                    .split(',')
                    .filter(|part| !part.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        // Version and curve pinning arrive in the engine config, not in a share
        // link: no link format carries them.
        ..TlsConfig::default()
    })
}

fn aliased_bool(
    query: &HashMap<String, String>,
    aliases: &[&str],
) -> Result<Option<bool>, LinkError> {
    let mut values = aliases
        .iter()
        .filter_map(|alias| query.get(*alias).map(|value| (*alias, value)));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(LinkError::Invalid(
            "duplicate aliases for one boolean option".into(),
        ));
    }
    parse_bool(value).map(Some)
}

fn server_ip(query: &HashMap<String, String>) -> Result<Option<IpAddr>, LinkError> {
    query
        .get("server_ip")
        .map(|value| {
            value
                .parse()
                .map_err(|_| LinkError::Invalid("server_ip is not an IP address".into()))
        })
        .transpose()
}

fn integer(query: &HashMap<String, String>, key: &str) -> Result<Option<u32>, LinkError> {
    query
        .get(key)
        .map(|value| {
            value
                .parse()
                .map_err(|_| LinkError::Invalid(format!("{key} is not an integer")))
        })
        .transpose()
}

fn parse_bool(value: &str) -> Result<bool, LinkError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(LinkError::Invalid("option value is not a boolean".into())),
    }
}

fn profile_name(url: &Url) -> Result<Option<String>, LinkError> {
    url.fragment()
        .map(decode_component)
        .transpose()
        .map(|name| name.filter(|name| !name.is_empty()))
}

fn decode_component(value: &str) -> Result<String, LinkError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| LinkError::Invalid("URI component is not UTF-8".into()))
}

fn decode_base64_text(value: &str) -> Result<String, LinkError> {
    let decoded = decode_base64_bytes(value)
        .ok_or_else(|| LinkError::Invalid("invalid Shadowsocks base64".into()))?;
    String::from_utf8(decoded)
        .map_err(|_| LinkError::Invalid("Shadowsocks credentials are not UTF-8".into()))
}

fn decode_base64_bytes(value: &str) -> Option<Vec<u8>> {
    [
        URL_SAFE_NO_PAD.decode(value),
        URL_SAFE.decode(value),
        STANDARD_NO_PAD.decode(value),
        STANDARD.decode(value),
    ]
    .into_iter()
    .find_map(Result::ok)
}

fn decode_subscription_body(value: &str) -> Result<String, LinkError> {
    let value = value.trim_start_matches('\u{feff}').trim();
    if value.contains("://") {
        return Ok(value.to_owned());
    }
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let decoded = [
        URL_SAFE_NO_PAD.decode(&compact),
        URL_SAFE.decode(&compact),
        STANDARD_NO_PAD.decode(&compact),
        STANDARD.decode(&compact),
    ]
    .into_iter()
    .find_map(Result::ok)
    .ok_or_else(|| LinkError::Subscription("body is neither URI text nor base64".into()))?;
    String::from_utf8(decoded)
        .map_err(|_| LinkError::Subscription("decoded body is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SANITIZED_SERVER_SUBSCRIPTION: &str = concat!(
        "vless://d0cf0001-0000-4000-8000-000000000000@edge.example:8443",
        "?type=tcp&security=none&encryption=none&fp=chrome",
        "&headerType=none&mux=false&spx=%2F#VLESS%20TCP\n",
        "hysteria2://integration-password@edge.example:8444",
        "?sni=edge.example#Hysteria2\n",
    );

    #[test]
    fn imports_four_supported_schemes() {
        let links = [
            "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp#vless",
            "hysteria2://secret@example.com:8443/?sni=example.com&insecure=1#hy2",
            "trojan://secret@example.com:443?type=tcp&sni=example.com#trojan",
            "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:8388#outline",
        ];
        for link in links {
            assert!(import_link(link).is_ok(), "{link}");
        }
    }

    #[test]
    fn imports_socks_http_and_naive() {
        let OutboundConfig::Socks(socks) = import_link("socks5://user:pass@10.0.0.5:1080#lan")
            .unwrap()
            .outbound
        else {
            panic!("profile must be SOCKS");
        };
        assert_eq!(socks.port, 1080);
        assert_eq!(socks.username.as_deref(), Some("user"));
        assert_eq!(socks.password.as_ref().unwrap().expose(), "pass");

        let OutboundConfig::Http(http) =
            import_link("https://user:pass@proxy.example:8443?sni=proxy.example#edge")
                .unwrap()
                .outbound
        else {
            panic!("profile must be an HTTP proxy");
        };
        assert!(
            http.tls.enabled,
            "https:// is the only thing that says the hop is encrypted"
        );

        let OutboundConfig::Http(plain) =
            import_link("http://proxy.example:3128").unwrap().outbound
        else {
            panic!("profile must be an HTTP proxy");
        };
        assert!(!plain.tls.enabled);
        assert_eq!(plain.username, None);

        let OutboundConfig::Naive(naive) =
            import_link("naive+https://user:pass@edge.example:443#naive")
                .unwrap()
                .outbound
        else {
            panic!("profile must be Naive");
        };
        assert!(naive.tls.enabled);
        assert_eq!(naive.tls.alpn, vec!["h2".to_owned()]);
        assert!(
            naive.padding,
            "padding is on unless the link switches it off"
        );
    }

    #[test]
    fn imports_the_documented_anytls_uri_without_leaking_the_password() {
        let link = "anytls://outer-secret@edge.example/?sni=front.example&insecure=1#AnyTLS%20edge";
        let imported = import_link(link).unwrap();
        let OutboundConfig::AnyTls(config) = &imported.outbound else {
            panic!("profile must be AnyTLS");
        };
        assert_eq!(config.server, "edge.example");
        assert_eq!(config.port, 443);
        assert_eq!(config.password.expose(), "outer-secret");
        assert_eq!(config.tls.server_name.as_deref(), Some("front.example"));
        assert!(config.tls.insecure);
        assert_eq!(imported.name.as_deref(), Some("AnyTLS edge"));
        assert!(!format!("{imported:?}").contains("outer-secret"));
        assert_eq!(
            inspect_link_shape(link).unwrap(),
            ProfileShape {
                scheme: ProfileScheme::AnyTls,
                transport: ProfileTransport::Raw,
                security: ProfileSecurity::Tls,
                flow: ProfileFlow::None,
            }
        );
    }

    #[test]
    fn anytls_link_parser_rejects_undocumented_effectful_options() {
        assert!(matches!(
            import_link("anytls://secret@edge.example/?sni=front.example&fp=chrome"),
            Err(LinkError::Unsupported(_))
        ));
        assert!(matches!(
            import_link("anytls://@edge.example/"),
            Err(LinkError::Invalid(_))
        ));
        assert!(import_link("shadowtls://secret@edge.example:443").is_err());
    }

    const WG_PRIVATE: &str = "l40T7xeXzdV13X8f%2F1IjcRR0wbrACb0bebRqcN01mbQ%3D";
    const WG_PUBLIC: &str = "%2F94rCPHnchHT%2FrfGYWR3oBaNKtGcelLi4ainYamMiTc%3D";

    #[test]
    fn imports_a_wireguard_link_with_the_fields_the_app_emits() {
        let link = format!(
            "wireguard://{WG_PRIVATE}@edge.example:51821?publickey={WG_PUBLIC}\
             &address=10.8.0.2%2F32&allowed_ips=0.0.0.0%2F0&mtu=1420&keepalive=25\
             &reserved=1%2C2%2C3#wg"
        );
        let OutboundConfig::Wireguard(config) = import_link(&link).unwrap().outbound else {
            panic!("profile must be WireGuard");
        };
        assert_eq!(config.port, 51821);
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.persistent_keepalive_s, Some(25));
        assert_eq!(config.address.len(), 1);
        assert_eq!(config.allowed_ips.len(), 1);
        assert_eq!(
            config.reserved,
            Some([1, 2, 3]),
            "a provider's client id must survive import, or the peer drops us"
        );
    }

    #[test]
    fn a_wireguard_link_defaults_the_port_and_the_full_route() {
        let link = format!(
            "wireguard://{WG_PRIVATE}@edge.example?publickey={WG_PUBLIC}&address=10.8.0.2%2F32"
        );
        let OutboundConfig::Wireguard(config) = import_link(&link).unwrap().outbound else {
            panic!("profile must be WireGuard");
        };
        assert_eq!(config.port, 51820);
        assert_eq!(
            config.allowed_ips.len(),
            2,
            "an omitted allowed-ips means the full route in this link format"
        );
        assert_eq!(config.reserved, None);
    }

    #[test]
    fn a_wireguard_link_fails_closed_on_what_the_core_cannot_honour() {
        // Reserved is three bytes; padding a shorter list would send an
        // identifier the profile never asked for.
        let short = format!(
            "wireguard://{WG_PRIVATE}@edge.example:51820?publickey={WG_PUBLIC}&address=10.8.0.2%2F32&reserved=1%2C2"
        );
        assert!(import_link(&short).is_err());

        let no_key = "wireguard://key@edge.example:51820?address=10.8.0.2%2F32";
        assert!(import_link(no_key).is_err());
    }

    #[test]
    fn a_wireguard_dns_parameter_costs_a_note_not_the_server() {
        // The defect this exists for: the owner's subscription carries exactly
        // one wireguard:// server, it carries dns=, and refusing the parameter
        // meant refusing the only WireGuard server there is.
        let link = format!(
            "wireguard://{WG_PRIVATE}@edge.example:51820?publickey={WG_PUBLIC}&address=10.8.0.2%2F32&dns=1.1.1.1"
        );
        let imported = import_link(&link).expect("the server must import");
        assert!(matches!(imported.outbound, OutboundConfig::Wireguard(_),));
        assert_eq!(imported.dropped.len(), 1);
        assert_eq!(imported.dropped[0].option, "dns");
        assert!(
            !imported.dropped[0].reason.contains("1.1.1.1"),
            "the note is meant to be loggable, so it must not echo the value"
        );

        // And a link without it says nothing, so a note always means something.
        let plain = format!(
            "wireguard://{WG_PRIVATE}@edge.example:51820?publickey={WG_PUBLIC}&address=10.8.0.2%2F32"
        );
        assert!(import_link(&plain).unwrap().dropped.is_empty());

        // The same rule reaches the file form.
        let conf = import_wireguard_conf(&WG_CONF.replace("MTU = 1280", "DNS = 1.1.1.1")).unwrap();
        assert_eq!(conf.dropped.len(), 1);
        assert_eq!(conf.dropped[0].option, "dns");
    }

    #[test]
    fn plain_proxy_links_fail_closed_on_ambiguity() {
        // Half a credential pair would import as an anonymous proxy that looks
        // configured.
        assert!(import_link("socks5://user@10.0.0.5:1080").is_err());
        // SOCKS4 has neither auth nor domain addressing; importing it as SOCKS5
        // would be a different protocol under the same name.
        assert!(import_link("socks4://10.0.0.5:1080").is_err());
        // A subscription URL is also `https://` — it must not become a proxy.
        assert!(import_link("https://sub.example.com/api/v1?token=abc").is_err());
        assert!(import_link("https://sub.example.com:443/api/v1").is_err());
        // Naive is TLS-only; the bare scheme does not say so.
        assert!(import_link("naive://user:pass@edge.example:443").is_err());
        // A malformed separator must fail as text, never index into the middle of a UTF-8 scalar.
        assert!(import_link("naive+https:/ˌedge.example:443").is_err());
    }

    #[test]
    fn a_naive_link_can_only_disable_padding_explicitly() {
        let OutboundConfig::Naive(config) =
            import_link("naive+https://user:pass@edge.example:443?padding=0")
                .unwrap()
                .outbound
        else {
            panic!("profile must be Naive");
        };
        assert!(
            !config.padding,
            "an explicit opt-out is allowed; a silent one is not"
        );
    }

    #[test]
    fn imports_modern_vmess_aead_raw_and_websocket() {
        let raw_document = r#"{"v":"2","ps":"VMess raw","add":"edge.example","port":"443","id":"d0cf0001-0000-4000-8000-000000000000","aid":"0","scy":"auto","net":"tcp","type":"none","tls":""}"#;
        let raw = format!("vmess://{}", STANDARD.encode(raw_document));
        let imported = import_link(&raw).unwrap();
        let OutboundConfig::Vmess(config) = imported.outbound else {
            panic!("profile must be VMess");
        };
        assert_eq!(config.cipher, VmessCipher::Auto);
        assert_eq!(config.alter_id, 0);
        assert!(matches!(config.transport, StreamTransportConfig::Raw));
        assert!(!config.tls.enabled);

        let ws_document = r#"{"v":"2","add":"edge.example","port":443,"id":"d0cf0001-0000-4000-8000-000000000000","aid":0,"scy":"aes-128-gcm","net":"ws","type":"none","host":"front.example","path":"/vmess","tls":"tls","sni":"tls.example","alpn":"h2,http/1.1"}"#;
        let ws = format!("vmess://{}", URL_SAFE_NO_PAD.encode(ws_document));
        let imported = import_link(&ws).unwrap();
        let OutboundConfig::Vmess(config) = imported.outbound else {
            panic!("profile must be VMess");
        };
        assert_eq!(config.cipher, VmessCipher::Aes128Gcm);
        assert!(matches!(
            config.transport,
            StreamTransportConfig::Websocket {
                ref path,
                host: Some(ref host),
                ..
            } if path == "/vmess" && host == "front.example"
        ));
        assert!(config.tls.enabled);
        assert_eq!(config.tls.server_name.as_deref(), Some("tls.example"));
    }

    #[test]
    fn imports_vless_reality_without_exposing_client_identifiers() {
        let link = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@edge.example:443",
            "?type=tcp&security=reality&encryption=none&sni=www.example.com",
            "&pbk=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "&sid=0123456789abcdef&fp=chrome&spx=%2Fprivate-fallback#Reality"
        );
        let imported = import_link(link).unwrap();
        let OutboundConfig::Vless(vless) = &imported.outbound else {
            panic!("profile must be VLESS");
        };
        assert!(!vless.tls.enabled);
        let reality = vless.reality.as_ref().expect("Reality must be present");
        assert_eq!(reality.server_name, "www.example.com");
        assert_eq!(reality.fingerprint, RealityFingerprint::Chrome133);
        assert_eq!(reality.short_id.expose(), "0123456789abcdef");
        assert_eq!(
            inspect_link_shape(link).unwrap(),
            ProfileShape {
                scheme: ProfileScheme::Vless,
                transport: ProfileTransport::Raw,
                security: ProfileSecurity::Reality,
                flow: ProfileFlow::None,
            }
        );
        let debug = format!("{imported:?}");
        assert!(!debug.contains(reality.public_key.expose()));
        assert!(!debug.contains(reality.short_id.expose()));
        assert!(!debug.contains("private-fallback"));
    }

    #[test]
    fn rejects_incomplete_or_unsupported_vless_reality_options() {
        let base = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@edge.example:443",
            "?type=tcp&security=reality&encryption=none&sni=www.example.com",
            "&pbk=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        );
        assert!(import_link(&format!("{base}&sid=abc")).is_err());
        assert!(matches!(
            import_link(&format!("{base}&fp=firefox")),
            Err(LinkError::Unsupported(_))
        ));
        assert!(matches!(
            import_link(&base.replace("&pbk=", "&missing=")),
            Err(LinkError::Unsupported(_)) | Err(LinkError::Invalid(_))
        ));
        assert!(matches!(
            import_link(&base.replace("type=tcp", "type=ws")),
            Err(LinkError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_legacy_or_effectful_vmess_options_without_leaking_uuid() {
        let private_uuid = "c1b2498a-e5b7-4bd6-8f58-f312a49f6ecb";
        for extra in [
            r#""aid":"64","scy":"auto","net":"tcp","type":"none","tls":"""#,
            r#""aid":"0","scy":"auto","net":"grpc","type":"none","tls":"tls""#,
            r#""aid":"0","scy":"auto","net":"tcp","type":"none","tls":"","mux":true"#,
        ] {
            let document = format!(
                r#"{{"v":"2","add":"edge.example","port":"443","id":"{private_uuid}",{extra}}}"#
            );
            let link = format!("vmess://{}", STANDARD.encode(document));
            let error = import_link(&link).unwrap_err().to_string();
            assert!(!error.contains(private_uuid));
            assert!(error.contains("not implemented") || error.contains("alterId"));
        }
    }

    #[test]
    fn imports_hysteria2_salamander_without_exposing_its_key() {
        let key = "salamander-key-must-stay-secret";
        let link = format!(
            "hy2://auth@example.com:443?obfs=salamander&obfs-password={key}&sni=example.com"
        );
        let imported = import_link(&link).unwrap();
        let OutboundConfig::Hysteria2(config) = &imported.outbound else {
            panic!("profile must be Hysteria2");
        };
        let Some(Hysteria2ObfsConfig::Salamander { password }) = &config.obfs else {
            panic!("Salamander must be configured");
        };
        assert_eq!(password.expose(), key);
        assert!(!format!("{imported:?}").contains(key));
    }

    #[test]
    fn rejects_incomplete_or_unimplemented_hysteria2_obfs() {
        assert!(matches!(
            import_link("hy2://auth@example.com:443?obfs=salamander"),
            Err(LinkError::Invalid(_))
        ));
        assert!(matches!(
            import_link("hy2://auth@example.com:443?obfs-password=secret"),
            Err(LinkError::Invalid(_))
        ));
        assert!(matches!(
            import_link("hy2://auth@example.com:443?obfs=gecko&obfs-password=secret"),
            Err(LinkError::Unsupported(_))
        ));
    }

    #[test]
    fn imports_shadowsocks_2022_and_its_websocket_plugin() {
        let credentials = URL_SAFE_NO_PAD.encode("2022-blake3-aes-128-gcm:base64-key");
        let link = format!("ss://{credentials}@127.0.0.1:8388?udp=true");
        let imported = import_link(&link).unwrap();
        let OutboundConfig::Shadowsocks(plain) = imported.outbound else {
            panic!("profile must be Shadowsocks");
        };
        assert_eq!(plain.transport, StreamTransportConfig::Raw);
        assert!(plain.udp);

        // v2ray-plugin in WebSocket mode is the carrier this core already has.
        let plugin = format!(
            "ss://{credentials}@127.0.0.1:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dcdn.example%3Bpath%3D%2Fws"
        );
        let OutboundConfig::Shadowsocks(tunnelled) = import_link(&plugin).unwrap().outbound else {
            panic!("profile must be Shadowsocks");
        };
        assert_eq!(
            tunnelled.transport,
            StreamTransportConfig::Websocket {
                path: "/ws".into(),
                host: Some("cdn.example".into()),
                headers: Default::default(),
            }
        );
        assert!(tunnelled.tls.enabled);
        assert_eq!(tunnelled.tls.server_name.as_deref(), Some("cdn.example"));
        assert!(
            !tunnelled.udp,
            "the plugin carries TCP only, and the profile has to say so"
        );

        // Everything else stays refused: this core does not spawn helper
        // binaries, and a dropped plugin puts plain Shadowsocks on a port that
        // is expecting a tunnel.
        for spec in [
            "kcptun",
            "obfs-local%3Bobfs%3Dquic",
            "obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com%3Bfailover%3D1",
            "v2ray-plugin%3Bmode%3Dquic",
            "v2ray-plugin%3Bmux%3D8",
        ] {
            assert!(
                matches!(
                    import_link(&format!("ss://{credentials}@127.0.0.1:8388?plugin={spec}")),
                    Err(LinkError::Unsupported(_))
                ),
                "{spec} must be refused"
            );
        }
        // And asking for UDP over a TCP-only carrier is a contradiction.
        assert!(matches!(
            import_link(&format!(
                "ss://{credentials}@127.0.0.1:8388?plugin=v2ray-plugin&udp=1"
            )),
            Err(LinkError::Unsupported(_))
        ));
    }

    fn shadowsocks(link: &str) -> ShadowsocksConfig {
        let credentials = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:hunter2");
        let OutboundConfig::Shadowsocks(config) =
            import_link(&format!("ss://{credentials}@127.0.0.1:8388{link}"))
                .unwrap()
                .outbound
        else {
            panic!("profile must be Shadowsocks");
        };
        config
    }

    #[test]
    fn imports_the_outline_prefix_one_character_per_byte() {
        // The example Outline documents for a TLS-looking prefix on port 443.
        let config = shadowsocks("/?outline=1&prefix=%16%03%01%00%C2%A8%01%01");
        assert_eq!(
            config.outline_prefix.as_deref(),
            Some(&[0x16, 0x03, 0x01, 0x00, 0xa8, 0x01, 0x01][..]),
            "U+00A8 travels as its UTF-8 and lands as one byte"
        );
        // A printable prefix is the same rule with nothing to escape.
        assert_eq!(
            shadowsocks("/?prefix=POST%20").outline_prefix.as_deref(),
            Some(&b"POST "[..])
        );
        // Absent and empty both mean "no prefix", never "prefix of nothing".
        assert_eq!(shadowsocks("").outline_prefix, None);
        assert_eq!(shadowsocks("/?prefix=").outline_prefix, None);
    }

    #[test]
    fn refuses_an_outline_prefix_that_is_not_bytes() {
        // Anything above U+00FF has no one-byte meaning, and guessing an
        // encoding for it would put bytes on the wire the provider never wrote.
        for prefix in ["%E2%9C%93", "%FF"] {
            let credentials = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:hunter2");
            assert!(
                matches!(
                    import_link(&format!(
                        "ss://{credentials}@127.0.0.1:8388/?prefix={prefix}"
                    )),
                    Err(LinkError::Invalid(_))
                ),
                "{prefix} must be refused"
            );
        }
    }

    #[test]
    fn imports_both_simple_obfs_modes() {
        let http = shadowsocks(
            "/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com%3Bobfs-uri%3D%2Fmail",
        );
        assert_eq!(
            http.obfs,
            Some(SimpleObfsConfig::Http {
                host: "www.bing.com".into(),
                uri: "/mail".into(),
                method: "GET".into(),
            })
        );
        assert!(
            !http.udp,
            "simple-obfs has no datagram mode, and the profile has to say so"
        );
        assert_eq!(http.transport, StreamTransportConfig::Raw);
        assert!(!http.tls.enabled);

        // `simple-obfs` is the same plugin under the name subscriptions use.
        let tls = shadowsocks("/?plugin=simple-obfs%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com");
        assert_eq!(
            tls.obfs,
            Some(SimpleObfsConfig::Tls {
                host: "www.bing.com".into()
            })
        );
    }

    #[test]
    fn simple_obfs_refuses_what_it_cannot_carry_out() {
        let credentials = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:hunter2");
        let refused = |plugin: &str| {
            import_link(&format!(
                "ss://{credentials}@127.0.0.1:8388/?plugin={plugin}"
            ))
        };
        // A host the server matches on cannot be invented.
        assert!(matches!(
            refused("obfs-local%3Bobfs%3Dhttp"),
            Err(LinkError::Invalid(_))
        ));
        // Neither can a mode.
        assert!(matches!(
            refused("obfs-local%3Bobfs-host%3Dwww.bing.com"),
            Err(LinkError::Invalid(_))
        ));
        // Options that belong to the other mode are refused, not ignored.
        assert!(matches!(
            refused("obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com%3Bobfs-uri%3D%2Fmail"),
            Err(LinkError::Invalid(_))
        ));
        // UDP over a TCP-only plugin is a contradiction, not a preference.
        assert!(matches!(
            import_link(&format!(
                "ss://{credentials}@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com&udp=1"
            )),
            Err(LinkError::Unsupported(_))
        ));
    }

    #[test]
    fn simple_obfs_socket_options_are_reported_rather_than_obeyed() {
        let credentials = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:hunter2");
        let imported = import_link(&format!(
            "ss://{credentials}@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dwww.bing.com%3Bfast-open"
        ))
        .unwrap();
        assert_eq!(
            imported
                .dropped
                .iter()
                .map(|dropped| dropped.option.as_str())
                .collect::<Vec<_>>(),
            vec!["fast-open"]
        );
    }

    #[test]
    fn rejects_incomplete_vless_reality_instead_of_silently_downgrading() {
        let link = "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443?security=reality";
        assert!(matches!(import_link(link), Err(LinkError::Invalid(_))));
    }

    #[test]
    fn imports_vless_websocket_transport_without_downgrading_to_raw() {
        let link = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443",
            "?security=tls&type=ws&path=%2Fproxy%3Fmode%3Dtest&host=front.example"
        );
        let imported = import_link(link).unwrap();
        let OutboundConfig::Vless(config) = imported.outbound else {
            panic!("profile must be VLESS");
        };
        assert!(matches!(
            config.transport,
            StreamTransportConfig::Websocket {
                ref path,
                host: Some(ref host),
                ..
            } if path == "/proxy?mode=test" && host == "front.example"
        ));
        assert!(config.tls.enabled);
    }

    #[test]
    fn imports_vless_xudp_packet_encoding() {
        let link = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443",
            "?security=tls&type=tcp&packetEncoding=xudp"
        );
        let imported = import_link(link).unwrap();
        let OutboundConfig::Vless(config) = imported.outbound else {
            panic!("profile must be VLESS");
        };
        assert_eq!(config.packet_encoding, PacketEncoding::Xudp);
    }

    #[test]
    fn vless_packet_encoding_defaults_to_plain_and_rejects_unknown_values() {
        let base = "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443?type=tcp";
        let imported = import_link(base).unwrap();
        let OutboundConfig::Vless(config) = imported.outbound else {
            panic!("profile must be VLESS");
        };
        assert_eq!(config.packet_encoding, PacketEncoding::None);
        let OutboundConfig::Vless(config) =
            import_link(&format!("{base}&packetEncoding=packetaddr"))
                .unwrap()
                .outbound
        else {
            panic!("profile must be VLESS");
        };
        assert_eq!(config.packet_encoding, PacketEncoding::Packetaddr);
        // An encoding we do not speak must fail closed, never fall back to plain.
        assert!(matches!(
            import_link(&format!("{base}&packetEncoding=stream")),
            Err(LinkError::Unsupported(_))
        ));
    }

    #[test]
    fn a_vision_link_imports_with_xudp_because_that_is_what_vision_does_to_udp() {
        let link = "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443\
             ?type=tcp&security=tls&sni=example.com&flow=xtls-rprx-vision";
        let OutboundConfig::Vless(config) = import_link(link).unwrap().outbound else {
            panic!("profile must be VLESS");
        };
        assert_eq!(config.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(
            config.packet_encoding,
            PacketEncoding::Xudp,
            "the profile has to record the carriage it will actually use"
        );
    }

    #[test]
    fn vision_refuses_the_flows_and_carriage_it_cannot_honour() {
        let base = "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443\
             ?type=tcp&security=tls&sni=example.com";
        // The -udp443 suffix is a promise about UDP/443 this core does not keep.
        assert!(matches!(
            import_link(&format!("{base}&flow=xtls-rprx-vision-udp443")),
            Err(LinkError::Unsupported(_))
        ));
        assert!(matches!(
            import_link(&format!("{base}&flow=xtls-rprx-origin")),
            Err(LinkError::Unsupported(_))
        ));
        // An explicit packetEncoding=none contradicts Vision instead of being
        // quietly promoted.
        assert!(matches!(
            import_link(&format!("{base}&flow=xtls-rprx-vision&packetEncoding=none")),
            Err(LinkError::Unsupported(_))
        ));
        // Vision has no defined shape over a WebSocket carrier.
        assert!(matches!(
            import_link(
                "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443\
                 ?type=ws&security=tls&sni=example.com&path=/x&flow=xtls-rprx-vision"
            ),
            Err(LinkError::Unsupported(_))
        ));
    }

    #[test]
    fn hysteria2_port_hopping_imports_as_ranges_or_fails_loudly() {
        let base = "hysteria2://secret@example.com:443?sni=example.com";
        let OutboundConfig::Hysteria2(config) =
            import_link(&format!("{base}&mport=20000-50000,8443&hopInterval=45"))
                .unwrap()
                .outbound
        else {
            panic!("profile must be Hysteria2");
        };
        assert_eq!(
            config.server_ports,
            vec![
                Hysteria2PortRange {
                    start: 20000,
                    end: 50000
                },
                Hysteria2PortRange {
                    start: 8443,
                    end: 8443
                }
            ]
        );
        assert_eq!(config.hop_interval_ms, 45_000);

        // A link with no hopping stays a single-port profile on the core's own
        // default dwell time.
        let OutboundConfig::Hysteria2(plain) = import_link(base).unwrap().outbound else {
            panic!("profile must be Hysteria2");
        };
        assert!(plain.server_ports.is_empty());
        assert_eq!(plain.hop_interval_ms, DEFAULT_HYSTERIA2_HOP_INTERVAL_MS);

        // Importing an unparsable range as "just port 443" would hand the user
        // the port their ISP is already throttling.
        for bad in ["50000-20000", "0-100", "20000-", "not-a-range"] {
            assert!(
                matches!(
                    import_link(&format!("{base}&mport={bad}")),
                    Err(LinkError::Invalid(_))
                ),
                "{bad} must be refused"
            );
        }
    }

    const WG_CONF: &str = "\
[Interface]
PrivateKey = ERERERERERERERERERERERERERERERERERERERERERE=
Address = 10.8.0.2/32, fd00::2/128
MTU = 1280

[Peer]
PublicKey = IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
";

    #[test]
    fn a_wg_quick_conf_imports_as_the_tunnel_the_provider_issued() {
        let OutboundConfig::Wireguard(config) = import_wireguard_conf(WG_CONF).unwrap().outbound
        else {
            panic!("profile must be WireGuard");
        };
        assert_eq!(config.server, "vpn.example.com");
        assert_eq!(config.port, 51820);
        assert_eq!(config.mtu, 1280);
        assert_eq!(config.persistent_keepalive_s, Some(25));
        assert_eq!(config.address.len(), 2);
        assert_eq!(config.allowed_ips.len(), 2);
        assert!(config.amnezia.is_none(), "a plain file must stay plain");
        // Comments, blank lines and the '=' padding of a base64 key all survive.
        assert!(config.private_key.expose().ends_with('='));
    }

    #[test]
    fn an_ipv6_endpoint_and_comments_parse() {
        let conf = WG_CONF.replace(
            "Endpoint = vpn.example.com:51820",
            "Endpoint = [2001:db8::1]:51820 # provider gateway",
        );
        let OutboundConfig::Wireguard(config) = import_wireguard_conf(&conf).unwrap().outbound
        else {
            panic!("profile must be WireGuard");
        };
        assert_eq!(config.server, "2001:db8::1");
        assert_eq!(config.port, 51820);
    }

    #[test]
    fn an_amneziawg_conf_needs_the_whole_obfuscation_block() {
        let full = WG_CONF.replace(
            "MTU = 1280",
            "MTU = 1280\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 20\n\
             H1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890",
        );
        let OutboundConfig::Wireguard(config) = import_wireguard_conf(&full).unwrap().outbound
        else {
            panic!("profile must be WireGuard");
        };
        let amnezia = config.amnezia.expect("the block must be carried through");
        assert_eq!(amnezia.junk_packet_count, 4);
        assert_eq!(amnezia.header_initiation, 1_234_567);

        // Half a block is refused: a peer told S1 but not the headers decodes
        // nothing, and the failure looks like a broken network instead.
        let partial = WG_CONF.replace("MTU = 1280", "MTU = 1280\nJc = 4\nJmin = 40");
        assert!(matches!(
            import_wireguard_conf(&partial),
            Err(LinkError::Invalid(_))
        ));
    }

    #[test]
    fn an_amneziawg_2_0_conf_carries_its_init_packets_and_s3_s4() {
        use foxcore_api::AmneziaInitTag as Tag;

        // The whitespace inside <b 0x…> is the trap: amneziawg-tools handles
        // I1..I5 separately from every other key precisely because a template
        // contains spaces, and upstream's own wg-quick script gets it wrong.
        let conf = WG_CONF.replace(
            "MTU = 1280",
            "MTU = 1280\nS3 = 12\nS4 = 20\nI1 = <b 0xc00000000108><r 32><t>\nI2 = <rd 6>",
        );
        let OutboundConfig::Wireguard(config) = import_wireguard_conf(&conf).unwrap().outbound
        else {
            panic!("profile must be WireGuard");
        };
        let amnezia = config.amnezia.expect("2.0 keys alone are a complete block");
        assert_eq!(amnezia.cookie_junk_size, 12);
        assert_eq!(amnezia.transport_junk_size, 20);
        assert_eq!(amnezia.init_packets.len(), 2);
        assert_eq!(
            amnezia.init_packets[0].tags,
            vec![
                Tag::Bytes {
                    hex: "c00000000108".into()
                },
                Tag::Random { len: 32 },
                Tag::Timestamp,
            ],
            "the space inside the tag must survive the parser"
        );
        assert_eq!(
            amnezia.init_packets[1].tags,
            vec![Tag::RandomDigits { len: 6 }]
        );
        // Everything 1.5 keeps its default rather than being invented.
        assert_eq!(amnezia.junk_packet_count, 0);
        assert_eq!(amnezia.header_initiation, 1);
    }

    #[test]
    fn an_amneziawg_template_is_refused_rather_than_shortened() {
        let with = |line: &str| {
            import_wireguard_conf(&WG_CONF.replace("MTU = 1280", &format!("MTU = 1280\n{line}")))
        };
        // An unknown tag would otherwise vanish and shorten every packet.
        assert!(matches!(
            with("I1 = <b 0xaa><zz 4>"),
            Err(LinkError::Invalid(_))
        ));
        // <c> and <wt> are repeated by secondary sources and do not exist.
        assert!(matches!(with("I1 = <c>"), Err(LinkError::Invalid(_))));
        assert!(matches!(with("I1 = <wt 4>"), Err(LinkError::Invalid(_))));
        // Odd hex is refused, not padded.
        assert!(matches!(with("I1 = <b 0xaaa>"), Err(LinkError::Invalid(_))));
        // An unclosed tag is malformed.
        assert!(matches!(with("I1 = <b 0xaa"), Err(LinkError::Invalid(_))));
        // A template with no tags at all says nothing and is not silently empty.
        assert!(matches!(
            with("I1 = plain text"),
            Err(LinkError::Invalid(_))
        ));
        // Positional keys: a gap is a different send order than renumbering.
        assert!(matches!(
            with("I1 = <r 4>\nI3 = <r 4>"),
            Err(LinkError::Invalid(_))
        ));
        assert!(matches!(with("S4 = 70000"), Err(LinkError::Invalid(_))));
    }

    #[test]
    fn a_conf_refuses_what_it_cannot_carry_out() {
        // Host-side wg-quick directives run shell commands or rewrite the host
        // routing table; this core does neither.
        for line in ["PostUp = iptables -A FORWARD -j ACCEPT", "Table = off"] {
            assert!(
                matches!(
                    import_wireguard_conf(&WG_CONF.replace("MTU = 1280", line)),
                    Err(LinkError::Unsupported(_))
                ),
                "{line} must be refused"
            );
        }
        // An unknown key is a setting we would be dropping.
        assert!(matches!(
            import_wireguard_conf(&WG_CONF.replace("MTU = 1280", "FwMark = 1234")),
            Err(LinkError::Unsupported(_))
        ));
        // The core carries one peer tunnel.
        let two_peers = format!("{WG_CONF}\n[Peer]\nPublicKey = x\nEndpoint = a.example:1\n");
        assert!(matches!(
            import_wireguard_conf(&two_peers),
            Err(LinkError::Unsupported(_))
        ));
        assert!(matches!(
            import_wireguard_conf("PrivateKey = x"),
            Err(LinkError::Invalid(_))
        ));
    }

    #[test]
    fn one_advertising_line_no_longer_costs_the_user_every_server() {
        // The defect this exists for, reproduced from a real subscription: a
        // provider appends its support channel, and strict parsing throws away
        // ten working servers over one line nobody was going to connect to.
        let body = format!(
            "tg://join?domain=example_support\n{SANITIZED_SERVER_SUBSCRIPTION}\nnot-a-link-at-all\n"
        );

        assert!(
            import_subscription(&body).is_err(),
            "the strict import stays strict for callers that need all-or-nothing"
        );

        let imported = import_subscription_partial(&body).expect("the good lines still import");
        assert_eq!(imported.profiles.len(), 2);
        assert_eq!(imported.rejected.len(), 2);
        assert_eq!(imported.rejected[0].index, 1);
        assert_eq!(imported.rejected[0].scheme.as_deref(), Some("tg"));
    }

    #[test]
    fn a_rejection_report_never_carries_the_line_it_rejected() {
        // A subscription line is a credential. This report is the single most
        // likely thing in the crate to reach a log, a bug report or a
        // screenshot, so it must survive being pasted in public.
        let secret =
            "vless://11111111-2222-3333-4444-555555555555@edge.example:443?security=nonsense-value";
        let body = format!("{secret}\n{SANITIZED_SERVER_SUBSCRIPTION}");

        let imported = import_subscription_partial(&body).expect("the good lines still import");
        assert_eq!(imported.rejected.len(), 1);
        let rendered = format!("{:?}", imported.rejected[0]);
        assert!(
            !rendered.contains("11111111-2222-3333-4444-555555555555"),
            "the UUID leaked into the rejection report: {rendered}"
        );
        assert!(
            !rendered.contains("edge.example"),
            "the endpoint leaked into the rejection report: {rendered}"
        );
        assert_eq!(imported.rejected[0].scheme.as_deref(), Some("vless"));
    }

    #[test]
    fn an_invalid_scheme_prefix_never_becomes_a_reported_credential() {
        let secret = "secret-user@example.com";
        let body = format!("{secret}://opaque-value\n{SANITIZED_SERVER_SUBSCRIPTION}");

        let imported = import_subscription_partial(&body).expect("the good lines still import");
        let rejected = imported
            .rejected
            .first()
            .expect("the invalid line is reported");
        assert_eq!(rejected.scheme, None);
        assert_eq!(rejected.reason, "invalid share link");
        assert!(!format!("{rejected:?}").contains(secret));
    }

    #[test]
    fn a_percent_decoded_control_or_transport_value_never_reaches_a_rejection_report() {
        let secret_marker = "private-transport-marker";
        let rejected_link =
            format!("trojan://credential@example.com:443?type=%1F{secret_marker}&security=tls");
        let body = format!("{rejected_link}\n{SANITIZED_SERVER_SUBSCRIPTION}");

        assert!(import_link(&rejected_link).is_err());
        let imported = import_subscription_partial(&body).expect("the good lines still import");
        let rejected = imported.rejected.first().expect("the bad line is reported");
        assert!(!rejected.reason.chars().any(char::is_control));
        assert!(rejected.reason.len() <= 4096);
        assert!(!rejected.reason.contains(secret_marker));
        assert_eq!(rejected.reason, "unsupported share-link option");
    }

    #[test]
    fn a_subscription_with_nothing_usable_is_still_a_failure() {
        // Lenience is per line, not per subscription. Returning an empty
        // success would have the app show a profile list that silently has
        // nothing in it, which reads as "the provider sent nothing".
        let body = "tg://join?domain=a\nhttps://example.invalid/notice\n";
        assert!(matches!(
            import_subscription_partial(body),
            Err(LinkError::Subscription(_))
        ));
    }

    #[test]
    fn imports_sanitized_server_subscription_without_silent_downgrade() {
        let profiles = import_subscription(SANITIZED_SERVER_SUBSCRIPTION).unwrap();
        assert_eq!(profiles.len(), 2);

        let OutboundConfig::Vless(vless) = &profiles[0].outbound else {
            panic!("first server profile must be VLESS");
        };
        assert_eq!(vless.port, 8443);
        assert!(!vless.tls.enabled);
        assert_eq!(vless.uuid.expose().len(), 36);

        let OutboundConfig::Hysteria2(hysteria2) = &profiles[1].outbound else {
            panic!("second server profile must be Hysteria2");
        };
        assert_eq!(hysteria2.port, 8444);
        assert_eq!(hysteria2.tls.server_name.as_deref(), Some("edge.example"));
        assert!(!hysteria2.tls.insecure);
    }

    #[test]
    fn imports_base64_subscription_and_keeps_errors_secret_free() {
        let encoded = STANDARD.encode(SANITIZED_SERVER_SUBSCRIPTION);
        assert_eq!(import_subscription(&encoded).unwrap().len(), 2);

        let credential = "must-never-appear-in-errors";
        let invalid =
            format!("hysteria2://{credential}@example.com:443?unknown_option=unsupported");
        let error = import_subscription(&invalid).unwrap_err().to_string();
        assert!(!error.contains(credential));
        assert!(error.contains("unknown query option"));
    }

    #[test]
    fn rejects_duplicate_or_effectful_ignored_vless_options() {
        let duplicate = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443",
            "?type=tcp&type=tcp"
        );
        assert!(matches!(import_link(duplicate), Err(LinkError::Invalid(_))));

        let mux = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443",
            "?type=tcp&mux=true"
        );
        assert!(matches!(import_link(mux), Err(LinkError::Unsupported(_))));

        let fingerprint = concat!(
            "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443",
            "?type=tcp&security=tls&fp=chrome"
        );
        assert!(matches!(
            import_link(fingerprint),
            Err(LinkError::Unsupported(_))
        ));
    }

    #[test]
    fn inspects_all_subscription_shapes_without_returning_private_fields() {
        let private_host = "private-origin.example";
        let private_uuid = "06f62a2d-7b4f-4a76-b95f-e02ebda6b24a";
        let vmess = STANDARD.encode(format!(
            r#"{{"v":"2","ps":"private label","add":"{private_host}","port":"443","id":"{private_uuid}","net":"ws","path":"/private-path","tls":"tls","sni":"private-sni.example"}}"#
        ));
        let subscription = format!(
            "vless://{private_uuid}@{private_host}:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=private-key\nvmess://{vmess}\nunknown://private-secret"
        );

        let shapes = inspect_subscription(&subscription).unwrap();
        assert_eq!(
            shapes,
            vec![
                ProfileShape {
                    scheme: ProfileScheme::Vless,
                    transport: ProfileTransport::Raw,
                    security: ProfileSecurity::Reality,
                    flow: ProfileFlow::Vision,
                },
                ProfileShape {
                    scheme: ProfileScheme::Vmess,
                    transport: ProfileTransport::Websocket,
                    security: ProfileSecurity::Tls,
                    flow: ProfileFlow::None,
                },
                ProfileShape {
                    scheme: ProfileScheme::Other,
                    transport: ProfileTransport::Other,
                    security: ProfileSecurity::Other,
                    flow: ProfileFlow::Other,
                },
            ]
        );
        let labels = shapes
            .into_iter()
            .map(ProfileShape::label)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(labels, "vless/raw/reality/vision,vmess/ws/tls,other");
        assert!(!labels.contains(private_host));
        assert!(!labels.contains(private_uuid));
        assert!(!labels.contains("private-path"));
    }

    #[test]
    fn selects_one_supported_profile_around_unsupported_items() {
        let vmess_document = r#"{"v":"2","add":"edge.example","port":"443","id":"d0cf0001-0000-4000-8000-000000000000","aid":"0","scy":"auto","net":"tcp","type":"none","tls":""}"#;
        let subscription = format!(
            "naive+https://private\nvmess://{}\nwireguard://private",
            STANDARD.encode(vmess_document)
        );
        let selected = import_first_profile_by_scheme(&subscription, ProfileScheme::Vmess).unwrap();
        assert!(matches!(selected.outbound, OutboundConfig::Vmess(_)));
    }
    /// SSR is closed, not pending — and "closed" has a shape in code.
    ///
    /// The decision (no AEAD in any mode, MD5 instead of a KDF,
    /// integrity from a truncated CRC32 down to a single byte, and none at all
    /// under `protocol=origin`) is a document,
    /// and documents do not stop anyone. What stops it is that `import_link`
    /// has no arm for `ssr` and therefore refuses the link by name.
    ///
    /// The shape inspector still recognises the scheme, and that is deliberate
    /// rather than a leftover: a subscription that contains an `ssr://` line
    /// stays readable, the line is labelled `shadowsocksr`, and the app can say
    /// "this protocol is not supported" instead of "this subscription is
    /// broken". Recognising is not promising — `juicity`, `mieru`, `snell` and
    /// `brook` sit in the same enum and none of them is implemented either.
    #[test]
    fn an_ssr_link_is_named_but_never_imported() {
        let link = "ssr://ZXhhbXBsZS5jb206ODM4ODphdXRoX2FlczEyOF9tZDU";

        let shape = inspect_link_shape(link).expect("the scheme is recognised");
        assert_eq!(shape.scheme, ProfileScheme::ShadowsocksR);
        assert_eq!(shape.label(), "shadowsocksr");

        // And the only thing that can turn a link into an outbound refuses it.
        assert!(
            matches!(import_link(link), Err(LinkError::Scheme(scheme)) if scheme == "ssr"),
            "importing SSR must fail by name; a fallback to any other outbound \
             would be the silent downgrade the refusal exists to prevent"
        );
    }
}
