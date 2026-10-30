use base64::Engine as _;
use serde::Deserialize;
use url::Url;

use crate::{
    ImportedProfile, LinkError, MAX_SUBSCRIPTION_PROFILES, RejectedLine, STANDARD_NO_PAD,
    SubscriptionImport,
};

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
    let result = import_json_partial(value)?;
    if !result.rejected.is_empty() {
        return Err(invalid());
    }
    Ok(result.profiles)
}

pub(crate) fn import_json_partial(value: &str) -> Result<SubscriptionImport, LinkError> {
    // Inspect keys before per-node deserialization: serde_json::Value alone would
    // silently collapse duplicate password fields before the strict Server sees them.
    let document = unique_json(value)?;
    let object = document.as_object().ok_or_else(invalid)?;
    let servers = if object.contains_key("servers") {
        if object.keys().any(|key| {
            !["version", "servers", "bytes_used", "bytes_remaining"].contains(&key.as_str())
        }) {
            return Err(invalid());
        }
        let version: Option<u32> =
            serde_json::from_value(object.get("version").cloned().unwrap_or_default())
                .map_err(|_| invalid())?;
        if version.is_some_and(|v| v != 1) {
            return Err(LinkError::Unsupported(
                "SIP008 version is not supported".into(),
            ));
        }
        for key in ["bytes_used", "bytes_remaining"] {
            serde_json::from_value::<Option<u64>>(object.get(key).cloned().unwrap_or_default())
                .map_err(|_| invalid())?;
        }
        object
            .get("servers")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .ok_or_else(invalid)?
    } else {
        vec![document]
    };
    if servers.is_empty() || servers.len() > MAX_SUBSCRIPTION_PROFILES {
        return Err(invalid());
    }
    let mut result = SubscriptionImport {
        profiles: Vec::new(),
        rejected: Vec::new(),
    };
    for (index, value) in servers.into_iter().enumerate() {
        match serde_json::from_value::<Server>(value)
            .map_err(|_| invalid())
            .and_then(import_server)
        {
            Ok(profile) => result.profiles.push(profile),
            Err(_) => result.rejected.push(RejectedLine {
                index: index + 1,
                scheme: Some("ss".into()),
                reason: "invalid or unsupported structured server".into(),
            }),
        }
    }
    if result.profiles.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}

fn unique_json(value: &str) -> Result<serde_json::Value, LinkError> {
    use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Number, Value};
    use std::fmt;

    struct Seed<'a> {
        depth: usize,
        nodes: &'a mut usize,
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
            if self.depth > 32 || *self.nodes >= 16384 {
                return Err(D::Error::custom("structured document bounds"));
            }
            *self.nodes += 1;
            decoder.deserialize_any(Unique(self))
        }
    }
    struct Unique<'a>(Seed<'a>);
    impl<'de> Visitor<'de> for Unique<'_> {
        type Value = Value;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded unique JSON")
        }
        fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
            Ok(Value::Bool(value))
        }
        fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
            Ok(Value::Number(value.into()))
        }
        fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
            Ok(Value::Number(value.into()))
        }
        fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
            Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| E::custom("invalid number"))
        }
        fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
            Ok(Value::String(value.into()))
        }
        fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
            Ok(Value::String(value))
        }
        fn visit_unit<E: Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element_seed(Seed {
                depth: self.0.depth + 1,
                nodes: &mut *self.0.nodes,
            })? {
                values.push(value);
            }
            Ok(Value::Array(values))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
            let mut values = Map::new();
            while let Some(key) = object.next_key::<String>()? {
                if values.contains_key(&key) || key.len() > 128 {
                    return Err(A::Error::custom("duplicate or invalid key"));
                }
                let value = object.next_value_seed(Seed {
                    depth: self.0.depth + 1,
                    nodes: &mut *self.0.nodes,
                })?;
                values.insert(key, value);
            }
            Ok(Value::Object(values))
        }
    }
    let mut nodes = 0;
    let mut decoder = serde_json::Deserializer::from_str(value);
    let value = Seed {
        depth: 0,
        nodes: &mut nodes,
    }
    .deserialize(&mut decoder)
    .map_err(|_| invalid())?;
    decoder.end().map_err(|_| invalid())?;
    Ok(value)
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
    fn regression_partial_sip008_keeps_valid_nodes_and_indexes_invalid_nodes() {
        let unsupported = SERVER
            .replace("\"00123\"", "\"sensitive-node-secret\"")
            .replace("}", ",\"plugin\":\"obfs\"}");
        let malformed = SERVER.replace("8388", "0");
        let body =
            format!(r#"{{"version":1,"servers":[{SERVER},{unsupported},{malformed},{SERVER}]}}"#);
        let imported = import_subscription_partial(&body).unwrap();
        assert_eq!(imported.profiles.len(), 2);
        assert_eq!(
            imported
                .rejected
                .iter()
                .map(|row| row.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(!format!("{:?}", imported.rejected).contains("sensitive-node-secret"));
        assert!(import_subscription(&body).is_err());
    }

    #[test]
    fn regression_partial_sip008_duplicate_secret_keys_remain_document_fatal() {
        let duplicate = SERVER.replace(
            "\"password\":\"00123\"",
            "\"password\":\"first-secret\",\"password\":\"second-secret\"",
        );
        let body = format!(r#"{{"version":1,"servers":[{SERVER},{duplicate}]}}"#);
        let error = import_subscription_partial(&body).unwrap_err().to_string();
        assert!(!error.contains("secret"));
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
