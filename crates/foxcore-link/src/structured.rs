use base64::Engine as _;
use serde::Deserialize;
use url::Url;

use crate::{ImportedProfile, LinkError, MAX_SUBSCRIPTION_PROFILES, STANDARD_NO_PAD};

#[derive(Deserialize)]
#[serde(untagged)]
enum Document {
    Sip008(Sip008),
    Outline(Server),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sip008 {
    #[serde(default)]
    version: Option<u32>,
    servers: Vec<Server>,
    #[serde(default, rename = "bytes_used")]
    _bytes_used: Option<u64>,
    #[serde(default, rename = "bytes_remaining")]
    _bytes_remaining: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    server: String,
    server_port: u16,
    method: String,
    password: String,
    #[serde(default, rename = "id")]
    _id: Option<String>,
    #[serde(default)]
    remarks: Option<String>,
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    plugin_opts: Option<String>,
}

pub(crate) fn import_json(value: &str) -> Result<Vec<ImportedProfile>, LinkError> {
    let document: Document = serde_json::from_str(value).map_err(|_| invalid())?;
    let servers = match document {
        Document::Sip008(document) => {
            if document.version.is_some_and(|v| v != 1) {
                return Err(LinkError::Unsupported(
                    "SIP008 version is not supported".into(),
                ));
            }
            document.servers
        }
        Document::Outline(server) => vec![server],
    };
    if servers.is_empty() || servers.len() > MAX_SUBSCRIPTION_PROFILES {
        return Err(invalid());
    }
    servers.into_iter().map(import_server).collect()
}

fn invalid() -> LinkError {
    LinkError::Subscription("invalid structured profile document".into())
}

fn import_server(server: Server) -> Result<ImportedProfile, LinkError> {
    if server.plugin.is_some_and(|v| !v.is_empty())
        || server.plugin_opts.is_some_and(|v| !v.is_empty())
    {
        return Err(LinkError::Unsupported(
            "SIP008/Outline plugins are not supported".into(),
        ));
    }
    if server.server_port == 0 {
        return Err(invalid());
    }
    let host = match server.server.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => server.server.clone(),
    };
    let mut uri = Url::parse("ss://placeholder.invalid").map_err(|_| invalid())?;
    uri.set_host(Some(&host)).map_err(|_| invalid())?;
    uri.set_port(Some(server.server_port))
        .map_err(|_| invalid())?;
    let auth = STANDARD_NO_PAD.encode(format!("{}:{}", server.method, server.password));
    uri.set_username(&auth).map_err(|_| invalid())?;
    let name = server.remarks.unwrap_or(server.server);
    let name: String = name.chars().filter(|v| !v.is_control()).take(160).collect();
    if !name.is_empty() {
        uri.set_fragment(Some(&name));
    }
    crate::import_link(uri.as_str()).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use crate::{OutboundConfig, import_subscription, import_subscription_partial};

    const SERVER: &str = r#"{"remarks":"Reference","server":"1.1.1.1","server_port":8388,"method":"aes-256-gcm","password":"00123"}"#;

    #[test]
    fn sip008_and_outline_json_preserve_the_single_shadowsocks_node() {
        for body in [
            format!(r#"{{"version":1,"servers":[{SERVER}]}}"#),
            SERVER.into(),
        ] {
            let profiles = import_subscription(&body).unwrap();
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].name.as_deref(), Some("Reference"));
            let OutboundConfig::Shadowsocks(node) = &profiles[0].outbound else {
                panic!("expected shadowsocks");
            };
            assert_eq!(node.password.expose(), "00123");
            assert_eq!(node.port, 8388);
            assert_eq!(
                import_subscription_partial(&body).unwrap().profiles,
                profiles
            );
        }
    }

    #[test]
    fn structured_formats_refuse_plugins_versions_duplicate_secrets_and_policy() {
        for body in [
            format!(r#"{{"version":2,"servers":[{SERVER}]}}"#),
            format!(r#"{{"version":1,"servers":[{SERVER}],"outbounds":[]}}"#),
            SERVER.replace(
                "\"password\":\"00123\"",
                "\"password\":\"sensitive-first\",\"password\":\"sensitive-second\"",
            ),
            SERVER.replace(
                "\"password\":\"00123\"",
                "\"password\":\"00123\",\"plugin_opts\":\"tls\"",
            ),
        ] {
            let error = import_subscription(&body).unwrap_err().to_string();
            assert!(!error.contains("sensitive"));
        }
    }

    #[test]
    fn structured_server_count_remains_bounded() {
        let body = format!(
            r#"{{"version":1,"servers":[{}]}}"#,
            std::iter::repeat_n(SERVER, 257)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(import_subscription(&body).is_err());
    }
}
