use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) fn import(profile: &Path, output: &Path) -> Result<&'static str, &'static str> {
    let file = crate::config::private_file(profile)?;
    let mut text = Zeroizing::new(String::new());
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "PROFILE_UNREADABLE")?;
    if text.len() > 1024 * 1024 {
        return Err("PROFILE_TOO_LARGE");
    }
    let raw = text.trim();
    let json = if raw.starts_with('{') {
        Some(serde_json::from_str::<serde_json::Value>(raw).map_err(|_| "PROFILE_INVALID")?)
    } else {
        None
    };
    let config = if json
        .as_ref()
        .is_some_and(|v| v.get("schema_version").is_some())
    {
        crate::config::parse(raw)?
    } else {
        let imported = if json.is_some()
            || raw
                .lines()
                .any(|line| line.trim_start().starts_with("proxies:"))
        {
            let mut profiles =
                foxcore_link::import_subscription(raw).map_err(|_| "PROFILE_INVALID")?;
            if profiles.len() != 1 {
                return Err("SINGLE_PROFILE_REQUIRED");
            }
            Ok(profiles.remove(0))
        } else if raw.starts_with("[Interface]") {
            foxcore_link::import_wireguard_conf(raw)
        } else {
            if raw.contains(['\n', '\r']) {
                return Err("SINGLE_PROFILE_REQUIRED");
            }
            foxcore_link::import_link(raw)
        }
        .map_err(|_| "PROFILE_INVALID")?;
        if !imported.dropped.is_empty() {
            return Err("PROFILE_OPTIONS_UNSUPPORTED");
        }
        let mtu = match &imported.outbound {
            foxcore_api::OutboundConfig::Wireguard(peer) => peer.mtu,
            _ => 1400,
        };
        let body = Zeroizing::new(serde_json::json!({"schema_version":1,"outbound":imported.outbound,"tun":{"ipv4":"198.18.0.1","ipv6":"fdfe:dcba:9876::1","mtu":mtu}}).to_string());
        crate::config::parse(&body)?
    };
    let input = std::fs::canonicalize(profile).map_err(|_| "PROFILE_UNREADABLE")?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|_| "PROFILE_OUTPUT_INVALID")?;
    if parent.join(output.file_name().ok_or("PROFILE_OUTPUT_INVALID")?) == input {
        return Err("PROFILE_OUTPUT_COLLISION");
    }
    #[cfg(target_os = "linux")]
    let _lease = crate::status::lease(output)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&config).map_err(|_| "PROFILE_WRITE_FAILED")?);
    if bytes.len() > 1024 * 1024 {
        return Err("PROFILE_TOO_LARGE");
    }
    crate::status::write_bytes(output, &bytes).map_err(|_| "PROFILE_WRITE_FAILED")?;
    Ok(crate::protocols::name(&config.outbound))
}

#[cfg(all(test, target_os = "linux", feature = "vless"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn structured_outline_and_sip008_are_imported_without_losing_password_bytes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = dir.path().join("in");
        let output = dir.path().join("out");
        let node =
            r#"{"server":"1.1.1.1","server_port":8388,"method":"aes-256-gcm","password":"00123"}"#;
        for body in [
            node.to_owned(),
            format!(r#"{{"version":1,"servers":[{node}]}}"#),
        ] {
            std::fs::write(&input, body).unwrap();
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(import(&input, &output), Ok("shadowsocks"));
            let config = crate::config::read(&output).unwrap();
            let foxcore_api::OutboundConfig::Shadowsocks(peer) = config.outbound else {
                panic!("wrong protocol");
            };
            assert_eq!(peer.password.expose(), "00123");
        }
    }

    #[test]
    fn single_clash_node_can_be_imported_but_a_choice_cannot_be_guessed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = dir.path().join("in");
        let output = dir.path().join("out");
        let node = " - {name: V, type: vless, server: 1.1.1.1, port: 443, uuid: 11111111-1111-4111-8111-111111111111, tls: true, sni: example.com}";
        std::fs::write(&input, format!("proxies:\n{node}")).unwrap();
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(import(&input, &output), Ok("vless"));
        let prior = std::fs::read(&output).unwrap();
        std::fs::write(&input, format!("proxies:\n{node}\n{node}")).unwrap();
        assert_eq!(import(&input, &output), Err("SINGLE_PROFILE_REQUIRED"));
        assert_eq!(std::fs::read(&output).unwrap(), prior);
    }

    #[test]
    fn an_imported_link_is_private_and_passes_the_same_router_admission() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = dir.path().join("in");
        let output = dir.path().join("out");
        std::fs::write(
            &input,
            "vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com",
        )
        .unwrap();
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(import(&input, &output), Ok("vless"));
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(crate::config::read(&output).is_ok());
        assert_eq!(import(&input, &input), Err("PROFILE_OUTPUT_COLLISION"));
    }

    #[test]
    fn ambiguous_multiple_links_are_refused_without_overwriting_existing_output() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = dir.path().join("in");
        let output = dir.path().join("out");
        std::fs::write(&input, "vless://first\nvless://second").unwrap();
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&output, "existing").unwrap();
        assert_eq!(import(&input, &output), Err("SINGLE_PROFILE_REQUIRED"));
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "existing");
    }
}
