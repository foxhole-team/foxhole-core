use super::*;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::SecretString;

/// The only XTLS flow FoxCore implements.
pub const VLESS_FLOW_VISION: &str = "xtls-rprx-vision";

/// Vision is not a bolt-on setting: it changes how the stream is framed, when
/// the socket stops being TLS, and how UDP is carried. Every constraint below is
/// a shape the implementation actually requires, so a profile that does not meet
/// one is refused rather than run with the flow quietly dropped — a server told
/// `flow=xtls-rprx-vision` pads its side no matter what the client then does.
pub(super) fn validate_vless_flow(config: &VlessConfig) -> Result<(), ConfigError> {
    let Some(flow) = config.flow.as_deref() else {
        return Ok(());
    };
    if flow != VLESS_FLOW_VISION {
        return Err(ConfigError::Invalid(format!(
            "unsupported VLESS flow '{flow}'; only '{VLESS_FLOW_VISION}' is implemented"
        )));
    }
    if !matches!(config.transport, StreamTransportConfig::Raw) {
        return Err(ConfigError::Invalid(
            "VLESS Vision requires raw TCP transport".into(),
        ));
    }
    if config.reality.is_none() && !config.tls.enabled {
        return Err(ConfigError::Invalid(
            "VLESS Vision requires REALITY or TLS".into(),
        ));
    }
    if config.reality.is_none() && config.tls.max_version == Some(TlsVersion::Tls12) {
        // The handover exposes the inner records on the wire in place of outer
        // 1.3 records. Under 1.2 that swap is visible, so the reference refuses
        // it too.
        return Err(ConfigError::Invalid(
            "VLESS Vision requires an outer TLS 1.3 handshake".into(),
        ));
    }
    if config.packet_encoding != PacketEncoding::Xudp {
        return Err(ConfigError::Invalid(
            "VLESS Vision carries UDP as XUDP; set packet_encoding=\"xudp\"".into(),
        ));
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessConfig {
    pub server: String,
    pub port: u16,
    /// Optional pre-resolved address. On Android this avoids a bootstrap DNS
    /// lookup after the VPN route is already active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub uuid: SecretString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default)]
    pub transport: StreamTransportConfig,
    /// How UDP is carried to the server. See [`PacketEncoding`].
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
    #[serde(default)]
    pub tls: TlsConfig,
    /// Optional REALITY security layer. It is mutually exclusive with `tls`
    /// and runs over raw TCP only. The ClientHello it writes is built from the
    /// named [`RealityFingerprint`] profile; the set of names is closed and
    /// small, not a generic uTLS surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
}

/// UDP carriage for VLESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PacketEncoding {
    /// Plain UDP-over-stream: the destination lives in the request header, so
    /// each destination needs its own stream and the server sees a symmetric
    /// NAT.
    #[default]
    None,
    /// Mux.Cool sub-connections carrying the destination in every frame. One
    /// stream serves every destination of a session, which is what gives the
    /// full-cone behaviour QUIC and STUN traffic expect.
    Xudp,
    /// A bare address prefix in front of every datagram. Same full-cone result
    /// as [`Self::Xudp`] with far less framing, at one hard cost: the format
    /// registers no address type for a name, so destinations that are still
    /// domains at dial time cannot be carried and are refused.
    Packetaddr,
}

/// Which ClientHello the REALITY transport writes.
///
/// Each variant names a browser build whose hello shape is reproduced from a
/// table: extension order, GREASE slots, key-exchange groups and padding. The
/// list is closed on purpose — a name here is a promise that the bytes were
/// derived from a published capture of that build, so it cannot accept
/// arbitrary uTLS strings the way Xray's `fingerprint=` does.
///
/// `chrome` — the name this field carried when there was only one profile — is
/// still accepted and means [`Self::Chrome133`], so a profile an installed app
/// already saved keeps parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RealityFingerprint {
    /// Chrome 133 on desktop: X25519MLKEM768 first in `supported_groups` and
    /// `key_share`, ALPS at the 0x44cd code point, ECH GREASE, permuted
    /// extensions.
    #[default]
    #[serde(rename = "chrome_133", alias = "chrome")]
    Chrome133,
    /// Chrome 131. Byte-identical to [`Self::Chrome133`] except that
    /// `application_settings` is sent at the older 0x4469 code point, which is
    /// the only thing that moved between the two builds.
    #[serde(rename = "chrome_131")]
    Chrome131,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    pub server_name: String,
    /// X25519 server public key (base64url, 32 decoded bytes). It is redacted
    /// in diagnostics even though it is not cryptographically secret.
    pub public_key: SecretString,
    /// 0..=8-byte client identifier encoded as an even-length hex string.
    #[serde(default)]
    pub short_id: SecretString,
    #[serde(default)]
    pub fingerprint: RealityFingerprint,
    #[serde(default = "default_reality_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    /// Imported crawler path retained for profile round-tripping. FoxCore is
    /// fail-closed and never performs Xray's crawler fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<SecretString>,
}

impl RealityConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        validate_reality_server_name(&self.server_name)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(self.public_key.expose())
            .map_err(|_| {
                ConfigError::Invalid("Reality public_key is not valid base64url".into())
            })?;
        if public_key.len() != 32 {
            return Err(ConfigError::Invalid(
                "Reality public_key must decode to 32 bytes".into(),
            ));
        }
        let short_id = self.short_id.expose();
        if short_id.len() > 16
            || !short_id.len().is_multiple_of(2)
            || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ConfigError::Invalid(
                "Reality short_id must contain an even number of 0..=16 hexadecimal characters"
                    .into(),
            ));
        }
        if !(1_000..=60_000).contains(&self.handshake_timeout_ms) {
            return Err(ConfigError::Invalid(
                "Reality handshake_timeout_ms must be in 1000..=60000".into(),
            ));
        }
        if let Some(spider_x) = &self.spider_x {
            let spider_x = spider_x.expose();
            if spider_x.len() > MAX_REALITY_SPIDER_X_BYTES
                || (!spider_x.is_empty()
                    && (!spider_x.starts_with('/')
                        || !spider_x.is_ascii()
                        || spider_x.bytes().any(|byte| byte.is_ascii_control())))
            {
                return Err(ConfigError::Invalid(
                    "Reality spider_x must be empty or a bounded ASCII origin-form path".into(),
                ));
            }
        }
        Ok(())
    }
}

fn default_reality_handshake_timeout_ms() -> u64 {
    15_000
}

fn validate_reality_server_name(value: &str) -> Result<(), ConfigError> {
    let value = value.trim_end_matches('.');
    if value.is_empty()
        || value.len() > 253
        || value.parse::<IpAddr>().is_ok()
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ConfigError::Invalid(
            "Reality server_name must be an ASCII DNS name".into(),
        ));
    }
    Ok(())
}

/// Modern VMess AEAD client configuration.
///
/// Legacy alter-id authentication is intentionally rejected. The stream
/// carrier is shared with VLESS so raw TCP and bounded WebSocket have exactly
/// the same validation and backpressure policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub uuid: SecretString,
    #[serde(default)]
    pub alter_id: u16,
    #[serde(default)]
    pub cipher: VmessCipher,
    #[serde(default)]
    pub transport: StreamTransportConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VmessCipher {
    #[default]
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}
