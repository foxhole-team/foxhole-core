use super::*;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub password: SecretString,
    pub tls: TlsConfig,
    /// Same bounded carrier set as VLESS/VMess. Trojan mandates TLS, so the
    /// transport is layered on top of it.
    #[serde(default)]
    pub transport: StreamTransportConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub method: String,
    pub password: SecretString,
    #[serde(default = "default_true")]
    pub udp: bool,
    /// Stream carrier under the Shadowsocks codec. `Raw` is plain Shadowsocks;
    /// `Websocket`/`HttpUpgrade` is what a SIP003 `v2ray-plugin` tunnel is once
    /// the subprocess is taken out of it.
    #[serde(default)]
    pub transport: StreamTransportConfig,
    /// TLS under the carrier (`v2ray-plugin;tls`).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Outline connection prefix: the leading bytes of the Shadowsocks salt are
    /// replaced by this literal so the first bytes on the wire look like some
    /// other protocol. The salt is public and is not part of the key, so the
    /// only cost is entropy — which is why the length is bounded here and again
    /// against the cipher's salt length when the outbound is built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outline_prefix: Option<Vec<u8>>,
    /// SIP003 `simple-obfs` / `obfs-local` carrier, expressed natively instead
    /// of as a subprocess. Mutually exclusive with the `v2ray-plugin` carrier
    /// above: they are two different plugins and a server runs one of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<SimpleObfsConfig>,
}

/// simple-obfs modes, as the two the reference plugin implements.
///
/// The mode decides the whole framing, so it is a closed enum rather than a
/// string: `http` prepends one HTTP/1.1 request and then relays verbatim,
/// `tls` hides the first payload in a fake ClientHello and wraps everything
/// after it in fake `application_data` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SimpleObfsConfig {
    Http {
        /// `obfs-host`: the `Host:` header and the value the server matches on.
        host: String,
        /// `obfs-uri`: request target of the single obfuscating request.
        #[serde(default = "default_simple_obfs_uri")]
        uri: String,
        /// `http-method`: the server compares the request line against it, so a
        /// mismatch is a closed connection rather than a cosmetic difference.
        #[serde(default = "default_simple_obfs_method")]
        method: String,
    },
    Tls {
        /// `obfs-host`: the SNI of the fake ClientHello.
        host: String,
    },
}

impl SimpleObfsConfig {
    pub fn host(&self) -> &str {
        match self {
            Self::Http { host, .. } | Self::Tls { host } => host,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_authority(self.host())?;
        if let Self::Http { uri, method, .. } = self {
            validate_carrier_path(uri)?;
            if method.is_empty()
                || method.len() > MAX_SIMPLE_OBFS_METHOD_BYTES
                || !method.bytes().all(is_http_token_byte)
            {
                return Err(ConfigError::Invalid(
                    "simple-obfs http-method must be a bounded HTTP token".into(),
                ));
            }
        }
        Ok(())
    }
}

fn default_simple_obfs_uri() -> String {
    "/".to_owned()
}

fn default_simple_obfs_method() -> String {
    "GET".to_owned()
}

const MAX_SIMPLE_OBFS_METHOD_BYTES: usize = 16;

/// Outline documents 16 bytes as the maximum prefix; longer prefixes eat the
/// salt entropy that keeps two connections from sharing a session key.
const MAX_OUTLINE_PREFIX_BYTES: usize = 16;

/// The three Shadowsocks carriers — `v2ray-plugin`, `simple-obfs` and the
/// Outline prefix — do not stack. A server runs one plugin, and the prefix is a
/// property of the raw salt, which a plugin no longer puts first on the wire.
/// Every conflict below is a refusal: silently keeping one of the two and
/// dropping the other is exactly the downgrade this core does not do.
pub(super) fn validate_shadowsocks_carriers(config: &ShadowsocksConfig) -> Result<(), ConfigError> {
    if let Some(obfs) = &config.obfs {
        obfs.validate()?;
        if !matches!(config.transport, StreamTransportConfig::Raw) || config.tls.enabled {
            return Err(ConfigError::Invalid(
                "Shadowsocks simple-obfs and the v2ray-plugin carrier are mutually exclusive"
                    .into(),
            ));
        }
        if config.udp {
            // simple-obfs obfuscates a TCP stream and has no datagram mode at
            // all; the reference plugin never sees the UDP relay.
            return Err(ConfigError::Invalid(
                "Shadowsocks simple-obfs carries TCP only; set udp=false".into(),
            ));
        }
    }
    if let Some(prefix) = &config.outline_prefix {
        if prefix.is_empty() {
            return Err(ConfigError::Invalid(
                "Shadowsocks outline_prefix must not be empty".into(),
            ));
        }
        if prefix.len() > MAX_OUTLINE_PREFIX_BYTES {
            return Err(ConfigError::Invalid(format!(
                "Shadowsocks outline_prefix must be at most {MAX_OUTLINE_PREFIX_BYTES} bytes"
            )));
        }
        if !matches!(config.transport, StreamTransportConfig::Raw)
            || config.tls.enabled
            || config.obfs.is_some()
        {
            return Err(ConfigError::Invalid(
                "Shadowsocks outline_prefix disguises the salt of a raw connection and has no meaning under a plugin carrier"
                    .into(),
            ));
        }
    }
    Ok(())
}
