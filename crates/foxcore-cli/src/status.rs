use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Running,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {
    pub(crate) schema_version: u32,
    pub(crate) pid: u32,
    pub(crate) process_start: u64,
    pub(crate) tun_fd: i32,
    pub(crate) ifindex: u32,
    pub(crate) interface: String,
    pub(crate) protocol: String,
    pub(crate) generation: u64,
    pub(crate) phase: Phase,
    pub(crate) bytes_up: u64,
    pub(crate) bytes_down: u64,
}

pub(crate) fn read(path: &Path) -> Result<Status, &'static str> {
    read_state(path, false)
}

pub(crate) fn read_recent(path: &Path) -> Result<Status, &'static str> {
    read_state(path, true)
}

fn require_recent(
    modified: std::time::SystemTime,
    now: std::time::SystemTime,
) -> Result<(), &'static str> {
    match now.duration_since(modified) {
        Ok(age) if age <= std::time::Duration::from_secs(5) => Ok(()),
        _ => Err("STATUS_STALE"),
    }
}

fn read_state(path: &Path, recent: bool) -> Result<Status, &'static str> {
    let file = crate::config::private_file(path)?;
    if recent {
        require_recent(
            file.metadata()
                .and_then(|m| m.modified())
                .map_err(|_| "STATUS_UNREADABLE")?,
            std::time::SystemTime::now(),
        )?;
    }
    let mut bytes = Vec::new();
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "STATUS_UNREADABLE")?;
    if bytes.len() > 8192 {
        return Err("STATUS_TOO_LARGE");
    }
    let value: Status = serde_json::from_slice(&bytes).map_err(|_| "STATUS_INVALID")?;
    if value.schema_version != 1
        || value.pid == 0
        || value.process_start == 0
        || value.tun_fd < 0
        || value.ifindex == 0
        || value.generation == 0
        || !crate::args::valid_interface(&value.interface)
        || !(crate::protocols::compiled().contains(&value.protocol.as_str())
            || value.protocol == "selector")
    {
        return Err("STATUS_INVALID");
    }
    Ok(value)
}

pub(crate) fn write(path: &Path, value: &Status) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "STATUS_WRITE_FAILED")?;
    write_bytes(path, &bytes)
}

pub(crate) fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let parent = private_parent(path)?;
    let name = path
        .file_name()
        .ok_or("STATUS_PATH_INVALID")?
        .to_str()
        .ok_or("STATUS_PATH_INVALID")?;
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "STATUS_WRITE_FAILED")?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| "STATUS_WRITE_FAILED")?;
        file.sync_all().map_err(|_| "STATUS_WRITE_FAILED")?;
        std::fs::rename(&temporary, path).map_err(|_| "STATUS_WRITE_FAILED")
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn private_parent(path: &Path) -> Result<&Path, &'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = std::fs::metadata(parent).map_err(|_| "STATUS_PATH_INVALID")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err("STATUS_DIRECTORY_PERMISSIONS");
        }
        #[cfg(target_os = "linux")]
        if metadata.uid() != crate::linux::current_uid() {
            return Err("STATUS_DIRECTORY_OWNER");
        }
    }
    Ok(parent)
}

#[cfg(target_os = "linux")]
pub(crate) fn lease(path: &Path) -> Result<File, &'static str> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = private_parent(path)?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("STATUS_PATH_INVALID")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(parent.join(format!(".{name}.lock")))
        .map_err(|_| "STATUS_LEASE_UNAVAILABLE")?;
    crate::config::validate_private_file(&file)?;
    if file
        .metadata()
        .map_err(|_| "STATUS_LEASE_UNAVAILABLE")?
        .nlink()
        != 1
    {
        return Err("STATUS_LEASE_UNAVAILABLE");
    }
    // SAFETY: the borrowed descriptor remains open until the returned lease is dropped.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("RUNTIME_ALREADY_RUNNING");
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_start(pid: u32) -> Result<u64, &'static str> {
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| "OWNER_UNAVAILABLE")?;
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or("OWNER_UNAVAILABLE")
}

#[cfg(target_os = "linux")]
pub(crate) fn require_owner(value: &Status, interface: &str) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;
    if value.phase != Phase::Running
        || value.interface != interface
        || process_start(value.pid)? != value.process_start
    {
        return Err("TUN_OWNER_MISMATCH");
    }
    let index: u32 = std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
        .map_err(|_| "TUN_UNAVAILABLE")?
        .trim()
        .parse()
        .map_err(|_| "TUN_UNAVAILABLE")?;
    if index != value.ifindex {
        return Err("TUN_OWNER_MISMATCH");
    }
    let current = std::env::current_exe()
        .and_then(std::fs::metadata)
        .map_err(|_| "OWNER_UNAVAILABLE")?;
    let owner =
        std::fs::metadata(format!("/proc/{}/exe", value.pid)).map_err(|_| "OWNER_UNAVAILABLE")?;
    if (current.dev(), current.ino()) != (owner.dev(), owner.ino()) {
        return Err("TUN_OWNER_MISMATCH");
    }
    let info = std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", value.pid, value.tun_fd))
        .map_err(|_| "TUN_OWNER_MISMATCH")?;
    if !info.lines().any(|line| {
        line.strip_prefix("iff:")
            .is_some_and(|name| name.trim() == interface)
    }) {
        return Err("TUN_OWNER_MISMATCH");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn private_temp() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn sample() -> Status {
        Status {
            schema_version: 1,
            pid: std::process::id(),
            process_start: 1,
            tun_fd: 3,
            ifindex: 1,
            interface: "foxhole0".into(),
            protocol: crate::protocols::compiled()
                .first()
                .copied()
                .unwrap_or("selector")
                .into(),
            generation: 1,
            phase: Phase::Running,
            bytes_up: 0,
            bytes_down: 0,
        }
    }

    #[test]
    fn a_state_path_has_one_owner_and_requires_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let temp = private_temp();
        let path = temp.path().join("state.json");
        let owner = lease(&path).unwrap();
        assert_eq!(lease(&path).unwrap_err(), "RUNTIME_ALREADY_RUNNING");
        drop(owner);
        assert!(lease(&path).is_ok());
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(lease(&path).unwrap_err(), "STATUS_DIRECTORY_PERMISSIONS");
        assert_eq!(write(&path, &sample()), Err("STATUS_DIRECTORY_PERMISSIONS"));
    }

    #[test]
    fn stale_or_future_status_cannot_validate_a_tunnel() {
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        assert_eq!(require_recent(now - Duration::from_secs(5), now), Ok(()));
        assert_eq!(
            require_recent(now - Duration::from_secs(6), now),
            Err("STATUS_STALE")
        );
        assert_eq!(
            require_recent(now + Duration::from_secs(1), now),
            Err("STATUS_STALE")
        );
        let temp = private_temp();
        let path = temp.path().join("state.json");
        write(&path, &sample()).unwrap();
        assert_eq!(read_recent(&path), Ok(sample()));
    }

    #[test]
    fn status_refuses_path_like_interfaces_and_zero_generations() {
        let temp = private_temp();
        let path = temp.path().join("state.json");
        let mut state = sample();
        for interface in ["../tun", "", "-4"] {
            state.interface = interface.into();
            write(&path, &state).unwrap();
            assert_eq!(read(&path), Err("STATUS_INVALID"));
        }
        state.interface = "foxhole0".into();
        state.generation = 0;
        write(&path, &state).unwrap();
        assert_eq!(read(&path), Err("STATUS_INVALID"));
    }
    #[test]
    fn recorded_process_owner_matches_the_live_process_start_tick() {
        assert!(process_start(std::process::id()).unwrap() > 0);
        assert!(process_start(u32::MAX).is_err());
    }
}
