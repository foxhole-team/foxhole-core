use super::*;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::SecretString;

/// Stream carrier below a proxy codec and above TCP/TLS. This stays generic so
/// VMess/Trojan can reuse the same bounded WebSocket implementation later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StreamTransportConfig {
    #[default]
    Raw,
    Websocket {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, SecretString>,
    },
    /// Plain HTTP/1.1 `Upgrade` carrier (`httpupgrade`): the same
    /// bounded path/host/header surface as WebSocket, but after the `101` the
    /// stream is raw bytes with no RFC 6455 framing.
    HttpUpgrade {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        headers: BTreeMap<String, SecretString>,
    },
    /// gRPC ("gun") carrier over HTTP/2: proxy bytes ride inside a bidirectional
    /// `<service_name>/Tun` (or `/TunMulti`) stream. Requires an HTTP/2 layer —
    /// ALPN `h2` under TLS, or h2c when TLS is disabled.
    Grpc {
        service_name: String,
        #[serde(default)]
        multi_mode: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
    },
    /// v2ray HTTP/2 carrier: the tunnel is the raw request/response body of one
    /// HTTP/2 stream. Requires an HTTP/2 layer (ALPN `h2` under TLS, or h2c).
    Http2 {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        host: Vec<String>,
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(default = "default_http2_method")]
        method: String,
    },
}

impl StreamTransportConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let (path, host, headers) = match self {
            Self::Raw => return Ok(()),
            Self::Grpc {
                service_name,
                multi_mode: _,
                authority,
            } => return validate_grpc(service_name, authority.as_deref()),
            Self::Http2 { host, path, method } => return validate_http2(host, path, method),
            Self::Websocket {
                path,
                host,
                headers,
            }
            | Self::HttpUpgrade {
                path,
                host,
                headers,
            } => (path, host, headers),
        };

        if path.is_empty()
            || path.len() > MAX_WEBSOCKET_PATH_BYTES
            || !path.starts_with('/')
            || !path.is_ascii()
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'#')
        {
            return Err(ConfigError::Invalid(
                "WebSocket path must be a 1..=2048 byte ASCII origin-form path without spaces, fragments or controls"
                    .into(),
            ));
        }
        if host.as_ref().is_some_and(|host| {
            host.is_empty()
                || host.len() > 255
                || host.bytes().any(|byte| {
                    byte.is_ascii_control()
                        || byte.is_ascii_whitespace()
                        || matches!(byte, b'/' | b'?' | b'#' | b'@')
                })
        }) {
            return Err(ConfigError::Invalid(
                "WebSocket host must be a valid bounded HTTP authority".into(),
            ));
        }
        if headers.len() > MAX_WEBSOCKET_HEADERS {
            return Err(ConfigError::Invalid(
                "WebSocket custom headers must contain at most 32 entries".into(),
            ));
        }
        let mut total_bytes = 0usize;
        for (name, value) in headers {
            let value = value.expose();
            let lower = name.to_ascii_lowercase();
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().all(is_http_token_byte)
                || matches!(
                    lower.as_str(),
                    "host"
                        | "connection"
                        | "upgrade"
                        | "sec-websocket-key"
                        | "sec-websocket-version"
                        | "sec-websocket-extensions"
                        | "sec-websocket-protocol"
                )
            {
                return Err(ConfigError::Invalid(format!(
                    "WebSocket custom header name '{name}' is invalid or reserved"
                )));
            }
            if value.len() > 1024
                || !value
                    .bytes()
                    .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
            {
                return Err(ConfigError::Invalid(format!(
                    "WebSocket custom header '{name}' has an invalid value"
                )));
            }
            total_bytes = total_bytes
                .saturating_add(name.len())
                .saturating_add(value.len());
        }
        if total_bytes > MAX_WEBSOCKET_HEADER_BYTES {
            return Err(ConfigError::Invalid(
                "WebSocket custom headers exceed 8192 bytes".into(),
            ));
        }
        Ok(())
    }
}

fn default_websocket_path() -> String {
    "/".into()
}

fn validate_grpc(service_name: &str, authority: Option<&str>) -> Result<(), ConfigError> {
    // service_name becomes the HTTP/2 `:path` prefix; the leading-'/' custom-path
    // form is permitted, so slashes are allowed but spaces/fragments/queries are not.
    if service_name.is_empty()
        || service_name.len() > MAX_WEBSOCKET_PATH_BYTES
        || !service_name.is_ascii()
        || service_name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'#' || byte == b'?')
    {
        return Err(ConfigError::Invalid(
            "gRPC service_name must be a 1..=2048 byte ASCII value without spaces, '#' or '?'"
                .into(),
        ));
    }
    if let Some(authority) = authority {
        validate_authority(authority)?;
    }
    Ok(())
}

fn default_http2_method() -> String {
    "PUT".into()
}

fn validate_http2(hosts: &[String], path: &str, method: &str) -> Result<(), ConfigError> {
    validate_carrier_path(path)?;
    for host in hosts {
        validate_authority(host)?;
    }
    if method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        return Err(ConfigError::Invalid(
            "HTTP/2 method must be 1..=16 uppercase ASCII letters".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_carrier_path(path: &str) -> Result<(), ConfigError> {
    if path.is_empty()
        || path.len() > MAX_WEBSOCKET_PATH_BYTES
        || !path.starts_with('/')
        || !path.is_ascii()
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'#')
    {
        return Err(ConfigError::Invalid(
            "stream transport path must be a 1..=2048 byte ASCII origin-form path without spaces, fragments or controls".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_authority(authority: &str) -> Result<(), ConfigError> {
    if authority.is_empty()
        || authority.len() > 255
        || authority.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'/' | b'?' | b'#' | b'@')
        })
    {
        return Err(ConfigError::Invalid(
            "stream transport host must be a valid bounded HTTP authority".into(),
        ));
    }
    Ok(())
}

pub(super) fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
