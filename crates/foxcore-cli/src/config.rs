use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

use foxcore_api::EngineConfig;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub(crate) fn private_file(path: &Path) -> Result<File, &'static str> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| "PRIVATE_FILE_UNAVAILABLE")?;
    validate_private_file(&file)?;
    Ok(file)
}

pub(crate) fn validate_private_file(file: &File) -> Result<(), &'static str> {
    let metadata = file.metadata().map_err(|_| "PRIVATE_FILE_UNAVAILABLE")?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err("PRIVATE_FILE_INVALID");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("PRIVATE_FILE_PERMISSIONS");
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != crate::linux::current_uid() {
            return Err("PRIVATE_FILE_OWNER");
        }
    }
    Ok(())
}

pub(crate) fn read(path: &Path) -> Result<EngineConfig, &'static str> {
    let file = private_file(path)?;
    let mut body = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|_| "CONFIG_UNREADABLE")?;
    if body.len() as u64 > MAX_CONFIG_BYTES {
        return Err("CONFIG_TOO_LARGE");
    }
    parse(&body)
}

pub(crate) fn parse(body: &str) -> Result<EngineConfig, &'static str> {
    let config = EngineConfig::parse(body).map_err(|_| "CONFIG_INVALID")?;
    if config.runtime.local_guard
        || config.runtime.control_proxy.is_some()
        || !config.runtime.loopback_inbounds.is_empty()
    {
        return Err("VPN_PROFILE_REQUIRED");
    }
    if config.dns.route != foxcore_api::DnsRoute::Primary
        || config.traffic.default_action != foxcore_api::ApplicationRouteAction::Vpn
        || !config.traffic.applications.is_empty()
        || config
            .routes
            .iter()
            .any(|rule| matches!(rule.action, foxcore_api::RouteAction::Direct))
    {
        return Err("ROUTER_POLICY_REQUIRED");
    }
    crate::protocols::require_available(&config.outbound)?;
    for outbound in &config.outbounds {
        crate::protocols::require_available(&outbound.outbound)?;
    }
    Ok(config)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_cannot_block_configuration_loading() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fifo");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: name remains a live NUL-terminated pathname throughout this call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(private_file(&path).unwrap_err(), "PRIVATE_FILE_INVALID");
    }

    #[cfg(feature = "hysteria2")]
    #[test]
    fn router_proof_cannot_be_bypassed_by_a_direct_engine_policy() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let base = serde_json::json!({"schema_version":1,"outbound":{"type":"hysteria2","server":"example.com","port":443,"password":"synthetic","tls":{"enabled":true}},"tun":{"ipv4":"10.9.0.1","mtu":1400}});
        let put = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        put(&base);
        assert!(read(&path).is_ok());
        let mut direct_dns = base.clone();
        direct_dns["dns"] = serde_json::json!({"route":"direct"});
        put(&direct_dns);
        assert_eq!(read(&path).unwrap_err(), "ROUTER_POLICY_REQUIRED");
        let mut direct_default = base;
        direct_default["traffic"] = serde_json::json!({"default_action":"direct"});
        put(&direct_default);
        assert_eq!(read(&path).unwrap_err(), "ROUTER_POLICY_REQUIRED");
    }

    #[test]
    fn public_symlink_and_directory_inputs_are_refused_without_echoing_secrets() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic-secret.json");
        std::fs::write(&path, "synthetic-secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(private_file(&path).unwrap_err(), "PRIVATE_FILE_PERMISSIONS");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert_eq!(private_file(&link).unwrap_err(), "PRIVATE_FILE_UNAVAILABLE");
        assert_eq!(
            private_file(temp.path()).unwrap_err(),
            "PRIVATE_FILE_INVALID"
        );
        assert_eq!(read(&path).unwrap_err(), "CONFIG_INVALID");
    }
}
