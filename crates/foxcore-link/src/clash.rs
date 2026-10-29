use base64::Engine as _;
use serde_json::{Map, Value, json};
use url::Url;
use yaml_rust2::parser::{Event, Parser};

use crate::{
    LinkError, MAX_SUBSCRIPTION_PROFILES, RejectedLine, SubscriptionImport, URL_SAFE_NO_PAD,
};

fn invalid() -> LinkError {
    LinkError::Subscription("invalid or unsupported Clash document".into())
}

enum Frame {
    Array(Vec<Value>),
    Object(Map<String, Value>, Option<String>),
}

fn append(stack: &mut [Frame], root: &mut Option<Value>, value: Value) -> Result<(), LinkError> {
    match stack.last_mut() {
        None => {
            if root.is_some() {
                return Err(invalid());
            }
            *root = Some(value);
        }
        Some(Frame::Array(values)) => values.push(value),
        Some(Frame::Object(values, key)) => {
            if let Some(key) = key.take() {
                values.insert(key, value);
            } else {
                let Value::String(next) = value else {
                    return Err(invalid());
                };
                if next.is_empty() || next.chars().count() > 128 || values.contains_key(&next) {
                    return Err(invalid());
                }
                *key = Some(next);
            }
        }
    }
    Ok(())
}

fn bounded_yaml(value: &str) -> Result<Value, LinkError> {
    if value.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let mut parser = Parser::new_from_str(value);
    let mut stack = Vec::new();
    let mut root = None;
    let mut documents = 0;
    for _ in 0..16384 {
        let (event, _) = parser.next_token().map_err(|_| invalid())?;
        let mapping = matches!(event, Event::MappingStart(..));
        match event {
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(invalid());
                }
            }
            Event::Scalar(text, _, anchor, tag) => {
                if anchor != 0
                    || text.chars().count() > 16384
                    || tag.is_some_and(|t| {
                        format!("{}{}", t.handle, t.suffix) != "tag:yaml.org,2002:str"
                    })
                {
                    return Err(invalid());
                }
                append(&mut stack, &mut root, Value::String(text))?;
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() || stack.len() >= 32 {
                    return Err(invalid());
                }
                if mapping {
                    stack.push(Frame::Object(Map::new(), None));
                } else {
                    stack.push(Frame::Array(Vec::new()));
                }
            }
            Event::MappingEnd => {
                let Some(Frame::Object(values, None)) = stack.pop() else {
                    return Err(invalid());
                };
                append(&mut stack, &mut root, Value::Object(values))?;
            }
            Event::SequenceEnd => {
                let Some(Frame::Array(values)) = stack.pop() else {
                    return Err(invalid());
                };
                append(&mut stack, &mut root, Value::Array(values))?;
            }
            Event::StreamEnd => {
                if !stack.is_empty() {
                    return Err(invalid());
                }
                return root.ok_or_else(invalid);
            }
            Event::StreamStart | Event::DocumentEnd => {}
            Event::Nothing | Event::Alias(_) => return Err(invalid()),
        }
    }
    Err(invalid())
}

fn text<'a>(
    node: &'a Map<String, Value>,
    key: &str,
    default: Option<&'a str>,
) -> Result<&'a str, LinkError> {
    match node.get(key) {
        Some(Value::String(value)) => Ok(value),
        None => default.ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

fn boolean(node: &Map<String, Value>, key: &str, default: bool) -> Result<bool, LinkError> {
    match node.get(key) {
        None => Ok(default),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(invalid()),
    }
}

fn only(node: &Map<String, Value>, keys: &[&str]) -> Result<(), LinkError> {
    if node.keys().any(|key| !keys.contains(&key.as_str())) {
        Err(invalid())
    } else {
        Ok(())
    }
}

fn share_link(node: &Map<String, Value>, kind: &str) -> Result<String, LinkError> {
    let mut allowed = vec!["name", "type", "server", "port", "udp"];
    match kind {
        "ss" => allowed.extend(["cipher", "password"]),
        "vless" => allowed.extend([
            "uuid",
            "tls",
            "servername",
            "sni",
            "skip-cert-verify",
            "alpn",
            "client-fingerprint",
            "network",
            "ws-opts",
            "grpc-opts",
            "flow",
            "reality-opts",
            "packet-encoding",
        ]),
        "vmess" => allowed.extend([
            "uuid",
            "alterId",
            "cipher",
            "tls",
            "servername",
            "sni",
            "skip-cert-verify",
            "alpn",
            "client-fingerprint",
            "network",
            "ws-opts",
            "grpc-opts",
        ]),
        "trojan" => allowed.extend([
            "password",
            "tls",
            "servername",
            "sni",
            "skip-cert-verify",
            "alpn",
            "network",
            "ws-opts",
            "grpc-opts",
        ]),
        "anytls" => allowed.extend(["password", "tls", "servername", "sni", "skip-cert-verify"]),
        "hysteria2" | "hy2" => allowed.extend([
            "password",
            "tls",
            "servername",
            "sni",
            "skip-cert-verify",
            "alpn",
            "obfs",
            "obfs-password",
            "up",
            "down",
        ]),
        _ => return Err(invalid()),
    }
    only(node, &allowed)?;
    let server = text(node, "server", None)?;
    let port: u16 = text(node, "port", None)?.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    let name: String = text(node, "name", Some("VPN"))?
        .chars()
        .filter(|v| !v.is_control())
        .take(160)
        .collect();
    let mut uri = Url::parse(&format!("{kind}://placeholder.invalid")).map_err(|_| invalid())?;
    let host = if server.contains(':') {
        format!("[{server}]")
    } else {
        server.to_owned()
    };
    uri.set_host(Some(&host)).map_err(|_| invalid())?;
    uri.set_port(Some(port)).map_err(|_| invalid())?;
    uri.set_fragment(Some(&name));
    if kind == "ss" {
        let auth = URL_SAFE_NO_PAD.encode(format!(
            "{}:{}",
            text(node, "cipher", None)?,
            text(node, "password", None)?
        ));
        uri.set_username(&auth).map_err(|_| invalid())?;
        uri.query_pairs_mut().append_pair(
            "udp",
            if boolean(node, "udp", true)? {
                "true"
            } else {
                "false"
            },
        );
        return Ok(uri.into());
    }
    if !boolean(node, "udp", true)? {
        return Err(invalid());
    }
    let mut params = Map::new();
    if node.contains_key("servername")
        && node.contains_key("sni")
        && node["servername"] != node["sni"]
    {
        return Err(invalid());
    }
    for (source, target) in [
        ("servername", "sni"),
        ("sni", "sni"),
        ("client-fingerprint", "fp"),
        ("flow", "flow"),
        ("packet-encoding", "packetEncoding"),
    ] {
        if node.contains_key(source) {
            params.insert(
                target.into(),
                Value::String(text(node, source, None)?.into()),
            );
        }
    }
    if boolean(node, "skip-cert-verify", false)? {
        params.insert("insecure".into(), Value::String("1".into()));
    }
    if let Some(alpn) = node.get("alpn") {
        let values = alpn.as_array().ok_or_else(invalid)?;
        let values: Vec<_> = values
            .iter()
            .map(|v| v.as_str().ok_or_else(invalid))
            .collect::<Result<_, _>>()?;
        if values.iter().any(|v| {
            v.is_empty() || v.len() > 255 || v.contains(',') || v.chars().any(char::is_control)
        }) {
            return Err(invalid());
        }
        if !values.is_empty() {
            params.insert("alpn".into(), Value::String(values.join(",")));
        }
    }
    let network = text(node, "network", Some("tcp"))?;
    match network {
        "tcp" => {
            if node.contains_key("ws-opts") || node.contains_key("grpc-opts") {
                return Err(invalid());
            }
        }
        "ws" => {
            if node.contains_key("grpc-opts") {
                return Err(invalid());
            }
            params.insert("type".into(), Value::String("ws".into()));
            let empty = Map::new();
            let ws = node
                .get("ws-opts")
                .map(|v| v.as_object().ok_or_else(invalid))
                .transpose()?
                .unwrap_or(&empty);
            only(ws, &["path", "headers"])?;
            params.insert(
                "path".into(),
                Value::String(text(ws, "path", Some("/"))?.into()),
            );
            if let Some(headers) = ws.get("headers") {
                let headers = headers.as_object().ok_or_else(invalid)?;
                if headers.len() > 1 || headers.keys().any(|key| !key.eq_ignore_ascii_case("Host"))
                {
                    return Err(invalid());
                }
                if let Some((_, value)) = headers.iter().next() {
                    params.insert(
                        "host".into(),
                        Value::String(value.as_str().ok_or_else(invalid)?.into()),
                    );
                }
            }
        }
        "grpc" | "gun" => {
            if node.contains_key("ws-opts") {
                return Err(invalid());
            }
            let empty = Map::new();
            let grpc = node
                .get("grpc-opts")
                .map(|value| value.as_object().ok_or_else(invalid))
                .transpose()?
                .unwrap_or(&empty);
            only(
                grpc,
                &["grpc-service-name", "grpc-user-agent", "ping-interval"],
            )?;
            let service = text(grpc, "grpc-service-name", Some("GunService"))?;
            let service = if service.is_empty() {
                "GunService"
            } else {
                service
            };
            let path = if service.starts_with('/') {
                service.to_owned()
            } else {
                format!("/{service}/Tun")
            };
            params.insert("type".into(), Value::String("grpc".into()));
            params.insert("serviceName".into(), Value::String(service.into()));
            // Mihomo's Opaque URL sends this literal path. Passing only the
            // service name through a share link would invoke Xray escaping.
            params.insert("rpc_path".into(), Value::String(path));
            let agent = text(grpc, "grpc-user-agent", Some(""))?;
            let agent = if agent.is_empty() {
                "grpc-go/1.36.0"
            } else {
                agent
            };
            params.insert("user_agent".into(), Value::String(agent.into()));
            let seconds: u64 = text(grpc, "ping-interval", Some("0"))?
                .parse()
                .map_err(|_| invalid())?;
            if seconds > 86_400 {
                return Err(invalid());
            }
            params.insert(
                "idle_timeout_ms".into(),
                Value::String((seconds * 1000).to_string()),
            );
        }
        _ => return Err(invalid()),
    }
    let reality = node
        .get("reality-opts")
        .map(|v| v.as_object().ok_or_else(invalid))
        .transpose()?;
    let tls_default =
        reality.is_some() || matches!(kind, "trojan" | "hysteria2" | "hy2" | "anytls");
    let tls = boolean(node, "tls", tls_default)?;
    if !tls
        && (tls_default
            || [
                "servername",
                "sni",
                "skip-cert-verify",
                "alpn",
                "client-fingerprint",
            ]
            .iter()
            .any(|key| node.contains_key(*key)))
    {
        return Err(invalid());
    }
    if matches!(kind, "vless" | "vmess") {
        params.insert(
            "security".into(),
            Value::String(
                if reality.is_some() {
                    "reality"
                } else if tls {
                    "tls"
                } else {
                    "none"
                }
                .into(),
            ),
        );
    }
    if let Some(reality) = reality {
        only(reality, &["public-key", "short-id"])?;
        params.insert(
            "pbk".into(),
            Value::String(text(reality, "public-key", None)?.into()),
        );
        params.insert(
            "sid".into(),
            Value::String(text(reality, "short-id", Some(""))?.into()),
        );
    }
    if matches!(kind, "hysteria2" | "hy2") {
        for key in ["obfs", "obfs-password"] {
            if node.contains_key(key) {
                params.insert(key.into(), Value::String(text(node, key, None)?.into()));
            }
        }
        for key in ["up", "down"] {
            if node.contains_key(key) {
                let speed: u32 = text(node, key, None)?.parse().map_err(|_| invalid())?;
                if speed > i32::MAX as u32 {
                    return Err(invalid());
                }
                params.insert(format!("{key}mbps"), Value::String(speed.to_string()));
            }
        }
    }
    if kind == "vmess" {
        if text(node, "alterId", Some("0"))? != "0" {
            return Err(invalid());
        }
        let fallback = |key| params.get(key).and_then(Value::as_str).unwrap_or("");
        let grpc = matches!(network, "grpc" | "gun");
        let path = if grpc {
            fallback("serviceName")
        } else {
            params.get("path").and_then(Value::as_str).unwrap_or("/")
        };
        let mut body = json!({"v":"2", "ps":name, "add":server, "port":port.to_string(), "id":text(node,"uuid",None)?, "aid":"0", "scy":text(node,"cipher",Some("auto"))?, "net":if grpc {"grpc"} else {network}, "type":"none", "path":path, "host":fallback("host"), "tls":if tls {"tls"} else {""}, "sni":fallback("sni"), "alpn":fallback("alpn"), "fp":fallback("fp"), "allowInsecure":boolean(node,"skip-cert-verify",false)?});
        if grpc {
            // VMess uses a base64 document instead of a URI. Copy every exact
            // canonical field so the intermediary cannot lose its wire path.
            for field in crate::GRPC_TUNING_OPTIONS {
                if let Some(value) = params.get(*field) {
                    body[*field] = value.clone();
                }
            }
        }
        return Ok(format!(
            "vmess://{}",
            URL_SAFE_NO_PAD.encode(body.to_string())
        ));
    }
    uri.set_username(text(
        node,
        if kind == "vless" { "uuid" } else { "password" },
        None,
    )?)
    .map_err(|_| invalid())?;
    for (key, value) in params {
        uri.query_pairs_mut()
            .append_pair(&key, value.as_str().ok_or_else(invalid)?);
    }
    Ok(uri.into())
}

pub(crate) fn looks_like(value: &str) -> bool {
    value
        .lines()
        .any(|line| line.trim_start().starts_with("proxies:"))
}

pub(crate) fn import_yaml(value: &str) -> Result<SubscriptionImport, LinkError> {
    let root = bounded_yaml(value)?;
    let root = root.as_object().ok_or_else(invalid)?;
    if root.contains_key("proxy-providers") {
        return Err(invalid());
    }
    let nodes = root
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if nodes.is_empty() || nodes.len() > MAX_SUBSCRIPTION_PROFILES {
        return Err(invalid());
    }
    let mut result = SubscriptionImport {
        profiles: Vec::new(),
        rejected: Vec::new(),
    };
    for (index, node) in nodes.iter().enumerate() {
        let node = node.as_object().ok_or_else(invalid)?;
        let kind = text(node, "type", None)?.to_ascii_lowercase();
        if ![
            "ss",
            "vless",
            "vmess",
            "trojan",
            "hysteria2",
            "hy2",
            "anytls",
        ]
        .contains(&kind.as_str())
        {
            result.rejected.push(RejectedLine {
                index: index + 1,
                scheme: Some("unknown".into()),
                reason: "unsupported protocol".into(),
            });
            continue;
        }
        let link = share_link(node, &kind)?;
        result
            .profiles
            .push(crate::import_link(&link).map_err(|_| invalid())?);
    }
    if result.profiles.is_empty() {
        return Err(invalid());
    }
    if root.keys().any(|key| key != "proxies") {
        result.rejected.push(RejectedLine {
            index: 1,
            scheme: Some("clash_settings".into()),
            reason: "client settings are not imported".into(),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::{OutboundConfig, import_subscription, import_subscription_partial};

    const NODES: &str = "proxies:\n - {name: SS, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: 00123, udp: false}\n - {name: HY2, type: hysteria2, server: 1.1.1.1, port: 443, password: synthetic, sni: example.com}";

    #[test]
    fn yaml_nodes_preserve_password_bytes_and_transport_options() {
        let profiles = import_subscription(NODES).unwrap();
        assert_eq!(profiles.len(), 2);
        let OutboundConfig::Shadowsocks(ss) = &profiles[0].outbound else {
            panic!("wrong protocol");
        };
        assert_eq!(ss.password.expose(), "00123");
        assert!(!ss.udp);
        assert!(matches!(profiles[1].outbound, OutboundConfig::Hysteria2(_)));
    }

    #[test]
    fn the_supported_tls_protocols_preserve_their_typed_carriers() {
        let uuid = "11111111-1111-4111-8111-111111111111";
        let body = format!(
            "proxies:\n - {{type: vless, server: 1.1.1.1, port: 443, uuid: {uuid}, tls: true, sni: example.com, network: ws, ws-opts: {{path: /path, headers: {{Host: example.com}}}}}}\n - {{type: vmess, server: 1.1.1.1, port: 443, uuid: {uuid}, tls: true, sni: example.com, network: ws, ws-opts: {{path: /path}}}}\n - {{type: trojan, server: 1.1.1.1, port: 443, password: synthetic, alpn: [h2], network: ws, ws-opts: {{path: /path}}}}\n - {{type: anytls, server: 1.1.1.1, port: 443, password: synthetic, sni: example.com}}"
        );
        let profiles = import_subscription(&body).unwrap();
        assert_eq!(profiles.len(), 4);
        for profile in &profiles[..3] {
            let transport = match &profile.outbound {
                OutboundConfig::Vless(value) => &value.transport,
                OutboundConfig::Vmess(value) => &value.transport,
                OutboundConfig::Trojan(value) => &value.transport,
                _ => panic!("wrong protocol"),
            };
            assert!(
                matches!(transport, foxcore_api::StreamTransportConfig::Websocket { path, .. } if path == "/path")
            );
        }
        assert!(matches!(profiles[3].outbound, OutboundConfig::AnyTls(_)));
    }

    #[test]
    fn ambiguous_tls_and_unrepresentable_fields_are_refused_without_secret_output() {
        let base = "proxies:\n - {type: vless, server: 1.1.1.1, port: 443, uuid: 11111111-1111-4111-8111-111111111111";
        for extra in [
            ", reality-opts: sensitive-fixture}",
            ", tls: false, sni: sensitive-fixture}",
            ", tls: true, sni: first.example, servername: second.example}",
            ", tls: true, alpn: ['h2,http/1.1']}",
            ", network: ws, ws-opts: {headers: {Host: first.example, host: second.example}}}",
        ] {
            let error = import_subscription_partial(&format!("{base}{extra}"))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("sensitive-fixture"));
        }
    }

    #[test]
    fn unsupported_nodes_and_client_policy_are_reported_without_loading_them() {
        let body = format!(
            "rules: [MATCH,DIRECT]\n{NODES}\n - {{type: unsupported, password: sensitive-fixture}}"
        );
        let imported = import_subscription_partial(&body).unwrap();
        assert_eq!(imported.profiles.len(), 2);
        assert_eq!(imported.rejected.len(), 2);
        assert!(!format!("{:?}", imported.rejected).contains("sensitive-fixture"));
        assert!(import_subscription(&body).is_err());
    }

    #[test]
    fn yaml_aliases_tags_duplicate_fields_and_resource_exhaustion_are_refused() {
        for input in [
            "proxies: &nodes [*nodes]".into(),
            "proxies: !!unsafe []".into(),
            NODES.replace("password: 00123", "password: first, password: second"),
            format!("{NODES}\n---\n{NODES}"),
            format!("extra: {}x{}\n{NODES}", "[".repeat(33), "]".repeat(33)),
            format!("{NODES}\nextra: {}", "x".repeat(16385)),
            format!("proxy-providers: {{other: {{url: https://example.com}}}}\n{NODES}"),
        ] {
            assert!(import_subscription_partial(&input).is_err());
        }
    }

    fn grpc_node(kind: &str, options: &str) -> String {
        let credential = if kind == "trojan" {
            "password: synthetic-grpc-auth"
        } else {
            "uuid: 11111111-1111-4111-8111-111111111111"
        };
        format!(
            "proxies:\n - {{type: {kind}, server: edge.example, port: 443, {credential}, tls: true, sni: tls.example, network: grpc{options}}}"
        )
    }

    fn imported_grpc(kind: &str, options: &str) -> serde_json::Value {
        let profiles = import_subscription(&grpc_node(kind, options))
            .expect("maintained Clash gRPC node must import");
        assert_eq!(profiles.len(), 1);
        let (transport, tls) = match &profiles[0].outbound {
            OutboundConfig::Vless(value) => (&value.transport, &value.tls),
            OutboundConfig::Vmess(value) => (&value.transport, &value.tls),
            OutboundConfig::Trojan(value) => (&value.transport, &value.tls),
            _ => panic!("protocol must remain unchanged"),
        };
        assert_eq!(tls.server_name.as_deref(), Some("tls.example"));
        serde_json::to_value(transport).unwrap()
    }

    #[test]
    fn clash_grpc_vless_preserves_mihomo_defaults_raw_path_and_effectful_options() {
        let default = imported_grpc("vless", "");
        assert_eq!(default["service_name"], "GunService");
        assert_eq!(default["rpc_path"], "/GunService/Tun");
        let transport = imported_grpc(
            "vless",
            ", grpc-opts: {grpc-service-name: '名字%raw', grpc-user-agent: 'FoxHole peer/1', ping-interval: 23}",
        );
        assert_eq!(transport["service_name"], "名字%raw");
        assert_eq!(transport["rpc_path"], "/名字%raw/Tun");
        assert_eq!(transport["user_agent"], "FoxHole peer/1");
        assert_eq!(transport["idle_timeout_ms"], 23_000);
    }

    #[test]
    fn clash_grpc_vmess_keeps_its_full_literal_rpc_override_and_user_agent() {
        let transport = imported_grpc(
            "vmess",
            ", grpc-opts: {grpc-service-name: '/名字%raw/method', grpc-user-agent: 'firefox', ping-interval: 7}",
        );
        assert_eq!(transport["service_name"], "/名字%raw/method");
        assert_eq!(transport["rpc_path"], "/名字%raw/method");
        assert_eq!(transport["user_agent"], "firefox");
        assert_eq!(transport["idle_timeout_ms"], 7_000);
        assert_eq!(transport["multi_mode"], false);
    }

    #[test]
    fn clash_grpc_trojan_preserves_empty_service_default_and_zero_ping() {
        let transport = imported_grpc(
            "trojan",
            ", grpc-opts: {grpc-service-name: '', grpc-user-agent: 'golang', ping-interval: 0}",
        );
        assert_eq!(transport["service_name"], "GunService");
        assert_eq!(transport["rpc_path"], "/GunService/Tun");
        assert_eq!(transport["user_agent"], "golang");
        assert_eq!(transport["idle_timeout_ms"], 0);
    }

    #[test]
    fn clash_grpc_raw_user_agent_alias_words_and_empty_default_remain_literal() {
        for (source, expected) in [
            ("firefox", "firefox"),
            ("golang", "golang"),
            ("chrome", "chrome"),
            ("", "grpc-go/1.36.0"),
        ] {
            let transport = imported_grpc(
                "vless",
                &format!(", grpc-opts: {{grpc-user-agent: '{source}'}}"),
            );
            assert_eq!(transport["user_agent"], expected);
        }
    }

    #[test]
    fn clash_grpc_unrepresentable_pool_options_and_ambiguous_paths_remain_refused() {
        for options in [
            ", grpc-opts: {max-connections: 2}",
            ", grpc-opts: {min-streams: 1}",
            ", grpc-opts: {max-streams: 3}",
            ", grpc-opts: {authority: front.example}",
            ", grpc-opts: {mode: multi}",
            ", grpc-opts: {ping-interval: 1.5}",
            ", grpc-opts: {ping-interval: 86401}",
            ", grpc-opts: {grpc-service-name: '/foo?query'}",
            ", grpc-opts: {grpc-service-name: '/foo#fragment'}",
            ", ws-opts: {path: /mixed}",
        ] {
            let error = import_subscription(&grpc_node("vless", options))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("synthetic-grpc-auth"));
        }
    }
}
