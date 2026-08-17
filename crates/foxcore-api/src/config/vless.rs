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
/// Validate the parts of a VLESS profile that are not the carrier.
pub(super) fn validate_vless(config: &VlessConfig) -> Result<(), ConfigError> {
    if let Some(encryption) = &config.encryption {
        let params = super::parse_vless_encryption(encryption.expose())
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        if config.flow.is_some() {
            // Upstream supports XTLS over VLESS Encryption and recommends it,
            // but the handover needs a splice point this layer does not expose
            // yet. Refusing by name beats negotiating a flow we would then fail
            // to honour, which desynchronises the server.
            return Err(ConfigError::Invalid(
                "VLESS Vision over VLESS encryption is not implemented; set flow to none".into(),
            ));
        }
        let _ = params;
    }
    validate_vless_flow(config)
}

fn validate_vless_flow(config: &VlessConfig) -> Result<(), ConfigError> {
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
    /// Optional REALITY security layer. It is mutually exclusive with `tls`,
    /// and stands where `tls` would stand: `transport` is composed above it,
    /// so gRPC and WebSocket work over REALITY as they do over TLS. The
    /// ClientHello it writes is built from the
    /// named [`RealityFingerprint`] profile; the set of names is closed and
    /// small, not a generic uTLS surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
    /// VLESS Encryption: the post-quantum layer that lives *inside* VLESS,
    /// independent of `tls` and `reality`. Holds the `encryption=` value
    /// verbatim, as [`parse_vless_encryption`] accepts it.
    ///
    /// `None` is `encryption=none` — plaintext VLESS inside whatever the
    /// carrier provides. It is a [`SecretString`] because the value embeds the
    /// server's key material; those are public keys, but so is
    /// `RealityConfig::public_key`, which is redacted for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<SecretString>,
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
/// still accepted and means whichever Chrome table is current, so a profile an
/// installed app already saved keeps parsing *and* keeps matching a browser
/// that still ships. Today that is [`Self::Chrome151`]; `firefox` resolves the
/// same way to [`Self::Firefox153`]. A bare name is a promise to look like the
/// current browser, not a pin to one build, and pinning is what the explicit
/// `chrome_133`-style names are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RealityFingerprint {
    /// Chromium 151 on desktop. Chrome 133's hello plus the three ML-DSA
    /// signature algorithms Chromium now offers ahead of the rest, which is
    /// the whole of the difference and all of it lands in JA4_c.
    ///
    /// Transcribed from a first-party capture: uTLS has no table for this
    /// build, so following uTLS here would mean not following the browser.
    #[default]
    #[serde(rename = "chrome_151", alias = "chrome")]
    Chrome151,
    /// Chrome 133 on desktop: X25519MLKEM768 first in `supported_groups` and
    /// `key_share`, ALPS at the 0x44cd code point, ECH GREASE, permuted
    /// extensions.
    ///
    /// Kept because it is the faithful transcription of uTLS'
    /// `HelloChrome_133`, which is what the deployed Xray and sing-box
    /// population still sends. It no longer matches a shipping Chrome.
    #[serde(rename = "chrome_133")]
    Chrome133,
    /// Chrome 131. Byte-identical to [`Self::Chrome133`] except that
    /// `application_settings` is sent at the older 0x4469 code point, which is
    /// the only thing that moved between the two builds.
    #[serde(rename = "chrome_131")]
    Chrome131,
    /// Microsoft Edge 85. sing-box maps `fp=edge` here; uTLS' `HelloEdge_Auto`
    /// is `HelloEdge_85`, not `_106`, which uTLS marks broken.
    #[serde(rename = "edge_85", alias = "edge")]
    Edge85,
    /// Safari 26.3 on macOS. ML-KEM hybrid, zlib certificate compression, no
    /// padding extension, 1.3/1.2 only.
    #[serde(rename = "safari_26_3", alias = "safari")]
    Safari263,
    /// Safari on iOS 14. No ML-KEM, no session ticket, no certificate
    /// compression, and a long TLS 1.2 suite tail including 3DES.
    #[serde(rename = "ios_14", alias = "ios")]
    Ios14,
    /// QQ Browser 11.1. Chromium fork: Chrome's cipher list with the older
    /// `application_settings` code point.
    #[serde(rename = "qq_11_1", alias = "qq")]
    Qq111,
    /// Firefox 153. Firefox 148's hello without cipher 0xc009 and with
    /// `session_ticket` and `psk_key_exchange_modes` added — enough to move
    /// JA4_a, the unhashed half a cheap detector reads first.
    ///
    /// Transcribed from a first-party capture; uTLS has no table for it.
    #[serde(rename = "firefox_153", alias = "firefox")]
    Firefox153,
    /// Firefox 148. No GREASE at all, a P-256 key share alongside the hybrid,
    /// `delegated_credentials` and `record_size_limit`, and a fixed extension
    /// order — Firefox does not permute.
    ///
    /// Kept as the faithful transcription of uTLS' `HelloFirefox_148`. It no
    /// longer matches a shipping Firefox.
    #[serde(rename = "firefox_148")]
    Firefox148,
    /// uTLS' `HelloRandomized` **generator**, not a table.
    ///
    /// The only value here that names no browser. A fresh ClientHello is drawn
    /// for every connection from uTLS' weight vector, inside the closed
    /// vocabulary that generator uses. Two draws that uTLS allows are excluded
    /// because REALITY cannot use them at all — the TLS 1.2 cap and the
    /// P-256-only key share both produce a hello with no `x25519` share for the
    /// server to authenticate against.
    ///
    /// It defeats an exact-match blocklist by construction and costs a stable
    /// JA4: a real browser's JA4 does not move between connections, and this
    /// one does.
    #[serde(rename = "randomized")]
    Randomized,
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
