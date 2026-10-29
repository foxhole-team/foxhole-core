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
        #[serde(default)]
        service_name: String,
        /// Exact HTTP/2 RPC path, when the source format has literal
        /// path semantics rather than Xray's escaped service-name semantics.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rpc_path: Option<String>,
        #[serde(default)]
        multi_mode: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_agent: Option<String>,
        #[serde(default)]
        idle_timeout_ms: u64,
        #[serde(default = "default_grpc_health_timeout_ms")]
        health_check_timeout_ms: u64,
        #[serde(default)]
        permit_without_stream: bool,
        #[serde(default)]
        initial_windows_size: u32,
    },
    /// Xray XHTTP stream-one over HTTP/2. Other XHTTP modes have a different
    /// wire protocol and are deliberately not represented by this carrier.
    Xhttp {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        #[serde(default = "default_xhttp_mode")]
        mode: String,
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
                rpc_path,
                authority,
                user_agent,
                idle_timeout_ms,
                health_check_timeout_ms,
                initial_windows_size,
                ..
            } => {
                return validate_grpc(
                    service_name,
                    rpc_path.as_deref(),
                    authority.as_deref(),
                    user_agent.as_deref(),
                    *idle_timeout_ms,
                    *health_check_timeout_ms,
                    *initial_windows_size,
                );
            }
            Self::Http2 { host, path, method } => return validate_http2(host, path, method),
            Self::Xhttp { path, host, mode } => {
                if mode != "stream-one" {
                    return Err(ConfigError::Invalid(
                        "XHTTP implements only stream-one over HTTP/2".into(),
                    ));
                }
                validate_carrier_path(path)?;
                if let Some(host) = host {
                    validate_authority(host)?;
                    if !host.is_ascii() {
                        return Err(ConfigError::Invalid("XHTTP host must be ASCII".into()));
                    }
                }
                return Ok(());
            }
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

fn default_xhttp_mode() -> String {
    "stream-one".into()
}

fn default_websocket_path() -> String {
    "/".into()
}

fn default_grpc_health_timeout_ms() -> u64 {
    20_000
}

fn validate_grpc(
    service_name: &str,
    rpc_path: Option<&str>,
    authority: Option<&str>,
    user_agent: Option<&str>,
    idle_timeout_ms: u64,
    health_check_timeout_ms: u64,
    initial_windows_size: u32,
) -> Result<(), ConfigError> {
    // Xray escapes UTF-8 service names before making the HTTP/2 path. The empty
    // name is also a real peer default (//Tun), not an absent configuration.
    if service_name.len() > MAX_WEBSOCKET_PATH_BYTES || service_name.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            "gRPC service_name must be at most 2048 UTF-8 bytes without controls".into(),
        ));
    }
    if let Some(path) = rpc_path {
        validate_grpc_rpc_path(path)?;
    }
    if let Some(authority) = authority {
        // gRPC authority is independent of the TLS/DNS verifier name. A
        // valid maximum-length DNS name plus its port exceeds 255 bytes;
        // other carrier host limits intentionally keep their existing bound.
        if authority.is_empty()
            || authority.len() > 1024
            || !authority.is_ascii()
            || authority.bytes().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'?' | b'#' | b'@')
            })
        {
            return Err(ConfigError::Invalid(
                "gRPC authority must be a bounded ASCII HTTP authority".into(),
            ));
        }
    }
    if let Some(agent) = user_agent
        && (agent.len() > 1024 || agent.bytes().any(|byte| byte < 0x20 || byte == 0x7f))
    {
        return Err(ConfigError::Invalid(
            "gRPC user_agent must be at most 1024 UTF-8 bytes without header controls".into(),
        ));
    }
    if idle_timeout_ms > 86_400_000 || health_check_timeout_ms > 86_400_000 {
        return Err(ConfigError::Invalid(
            "gRPC timeouts must be in 0..=86400000 milliseconds".into(),
        ));
    }
    if initial_windows_size > 0x7fff_ffff {
        return Err(ConfigError::Invalid(
            "gRPC initial_windows_size exceeds the HTTP/2 31-bit window limit".into(),
        ));
    }
    Ok(())
}

fn validate_grpc_rpc_path(path: &str) -> Result<(), ConfigError> {
    // This field is an exact wire path, not a value to URL-decode. A literal
    // percent sign and valid UTF-8 are used by maintained gRPC carriers.
    if path.is_empty()
        || path.len() > 8192
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path.bytes().any(|byte| matches!(byte, b' ' | b'?' | b'#'))
    {
        return Err(ConfigError::Invalid(
            "gRPC rpc_path must be a bounded UTF-8 origin-form path without controls, spaces, query or fragment".into(),
        ));
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

#[cfg(test)]
mod grpc_compatibility_tests {
    use super::*;

    #[test]
    fn xhttp_stream_one_is_bounded_and_other_modes_fail_closed() {
        let transport: StreamTransportConfig =
            serde_json::from_str(r#"{"type":"xhttp","mode":"stream-one","path":"/"}"#)
                .expect("XHTTP stream-one schema");
        transport.validate().unwrap();
        for change in [
            serde_json::json!({"mode":"auto"}),
            serde_json::json!({"mode":"packet-up"}),
            serde_json::json!({"mode":"stream-up"}),
            serde_json::json!({"path":"/bad\r\nInjected"}),
            serde_json::json!({"host":"user@front.example"}),
            serde_json::json!({"path":"/".to_owned() + &"x".repeat(2048)}),
        ] {
            let mut value = serde_json::json!({"type":"xhttp","mode":"stream-one","path":"/"});
            for (key, item) in change.as_object().unwrap() {
                value[key] = item.clone();
            }
            if let Ok(transport) = serde_json::from_value::<StreamTransportConfig>(value) {
                assert!(transport.validate().is_err());
            }
        }
    }

    #[test]
    fn grpc_defaults_allow_an_omitted_empty_service() {
        let transport: StreamTransportConfig =
            serde_json::from_str(r#"{"type":"grpc"}"#).expect("empty service is a peer default");
        transport.validate().unwrap();
        assert!(matches!(
            transport,
            StreamTransportConfig::Grpc { ref service_name, .. } if service_name.is_empty()
        ));
    }

    #[test]
    fn grpc_preserves_exact_path_and_millisecond_tuning() {
        let document = serde_json::json!({
            "type": "grpc", "service_name": "名字/with percent%",
            "rpc_path": "/literal%2Fservice/Tun", "multi_mode": true,
            "authority": "front.example", "user_agent": "FoxHole test peer/1",
            "idle_timeout_ms": 1500, "health_check_timeout_ms": 750,
            "permit_without_stream": true, "initial_windows_size": 131072
        });
        let transport: StreamTransportConfig =
            serde_json::from_value(document.clone()).expect("all effectful gRPC fields are typed");
        transport.validate().unwrap();
        let encoded = serde_json::to_value(transport).unwrap();
        for field in [
            "rpc_path",
            "user_agent",
            "idle_timeout_ms",
            "health_check_timeout_ms",
            "permit_without_stream",
            "initial_windows_size",
        ] {
            assert_eq!(encoded[field], document[field], "lost or rounded {field}");
        }
    }

    #[test]
    fn grpc_exact_rpc_path_preserves_utf8_and_literal_percent_but_refuses_injection() {
        for path in ["/名字%literal/Tun", "//service%2Fname/Tun", "/foo%0A/Tun"] {
            let transport: StreamTransportConfig = serde_json::from_value(serde_json::json!({
                "type": "grpc", "rpc_path": path
            }))
            .unwrap();
            transport.validate().unwrap();
            assert_eq!(serde_json::to_value(transport).unwrap()["rpc_path"], path);
        }
        for path in [
            "https://other.example/Tun",
            "relative",
            "/foo?query",
            "/foo#fragment",
            "/foo\r\nInjected",
            "/foo bar",
        ] {
            let transport: StreamTransportConfig = serde_json::from_value(serde_json::json!({
                "type": "grpc", "rpc_path": path
            }))
            .unwrap();
            assert!(transport.validate().is_err(), "must reject {path:?}");
        }
    }

    #[test]
    fn grpc_typed_tuning_refuses_header_injection_overflow_and_wrong_json_types() {
        for change in [
            serde_json::json!({"user_agent": "safe\r\nAuthorization: synthetic"}),
            serde_json::json!({"idle_timeout_ms": 86_400_001u64}),
            serde_json::json!({"health_check_timeout_ms": 86_400_001u64}),
            serde_json::json!({"initial_windows_size": 2_147_483_648u64}),
            serde_json::json!({"idle_timeout_ms": true}),
            serde_json::json!({"health_check_timeout_ms": 1.5}),
            serde_json::json!({"permit_without_stream": "true"}),
        ] {
            let mut document = serde_json::json!({"type":"grpc"});
            for (key, value) in change.as_object().unwrap() {
                document[key] = value.clone();
            }
            if let Ok(transport) = serde_json::from_value::<StreamTransportConfig>(document) {
                assert!(transport.validate().is_err());
            }
        }
        for window in [0u32, 65_534, 65_535, 2_147_483_647] {
            let transport: StreamTransportConfig = serde_json::from_value(serde_json::json!({
                "type":"grpc", "idle_timeout_ms":86_400_000u64,
                "health_check_timeout_ms":0, "initial_windows_size":window,
                "user_agent":"FoxHole/名字"
            }))
            .unwrap();
            transport.validate().unwrap();
        }
    }

    #[test]
    fn grpc_service_names_can_be_utf8_before_path_escaping() {
        let transport: StreamTransportConfig =
            serde_json::from_str(r#"{"type":"grpc","service_name":"名字/space ?#"}"#).unwrap();
        transport
            .validate()
            .expect("escaped service names cannot inject headers");
    }

    #[test]
    fn grpc_authority_allows_a_maximum_dns_name_and_port_without_changing_other_carriers() {
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(domain.len(), 253);
        let authority = format!("{domain}:65535");
        let transport: StreamTransportConfig = serde_json::from_value(serde_json::json!({
            "type":"grpc", "authority":authority,
        }))
        .unwrap();
        transport.validate().unwrap();
        let legacy: StreamTransportConfig = serde_json::from_value(serde_json::json!({
            "type":"http2", "host":[authority], "path":"/", "method":"POST",
        }))
        .unwrap();
        assert!(
            legacy.validate().is_err(),
            "other carrier authority limits must remain unchanged"
        );
        for authority in [
            "a".repeat(1025),
            "front.example\r\nInjected".into(),
            "名字.example".into(),
        ] {
            let transport: StreamTransportConfig = serde_json::from_value(serde_json::json!({
                "type":"grpc", "authority":authority,
            }))
            .unwrap();
            assert!(transport.validate().is_err());
        }
    }
}
