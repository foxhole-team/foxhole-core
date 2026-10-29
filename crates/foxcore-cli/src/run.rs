use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use foxcore_dialer::SocketCallbacks;
use foxcore_runtime::{CoreRuntime, StopResult};

pub(crate) async fn run(
    config_path: &Path,
    state_path: &Path,
    interface: &str,
) -> Result<(), &'static str> {
    let config = crate::config::read(config_path)?;
    let _lease = crate::status::lease(state_path)?;
    let config_identity = std::fs::canonicalize(config_path).map_err(|_| "CONFIG_UNAVAILABLE")?;
    let parent = state_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|_| "STATUS_PATH_INVALID")?;
    if parent.join(state_path.file_name().ok_or("STATUS_PATH_INVALID")?) == config_identity {
        return Err("CONFIG_STATE_COLLISION");
    }
    if Path::new("/sys/class/net").join(interface).exists() {
        return Err("INTERFACE_ALREADY_EXISTS");
    }
    let fd = foxcore_tun::open_exclusive_named_fd(interface).map_err(|_| "TUN_CREATE_FAILED")?;
    let tun_fd = fd.as_raw_fd();
    let index: u32 = std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))
        .map_err(|_| "TUN_CREATE_FAILED")?
        .trim()
        .parse()
        .map_err(|_| "TUN_CREATE_FAILED")?;
    let address = format!("{}/32", config.tun.ipv4);
    crate::linux::ip(&["addr", "replace", &address, "dev", interface]).await?;
    if let Some(ipv6) = &config.tun.ipv6 {
        crate::linux::ip(&[
            "-6",
            "addr",
            "replace",
            &format!("{ipv6}/128"),
            "dev",
            interface,
        ])
        .await?;
    }
    crate::linux::ip(&[
        "link",
        "set",
        "dev",
        interface,
        "mtu",
        &config.tun.mtu.to_string(),
        "up",
    ])
    .await?;
    crate::linux::configure_return_path(interface)?;
    let mut entropy = [0; 8];
    getrandom::fill(&mut entropy).map_err(|_| "ENTROPY_UNAVAILABLE")?;
    let generation = u64::from_ne_bytes(entropy).max(1);
    let mut state = crate::status::Status {
        schema_version: 1,
        pid: std::process::id(),
        process_start: crate::status::process_start(std::process::id())?,
        tun_fd,
        ifindex: index,
        interface: interface.into(),
        protocol: crate::protocols::name(&config.outbound).into(),
        generation,
        phase: crate::status::Phase::Running,
        bytes_up: 0,
        bytes_down: 0,
    };
    let runtime = CoreRuntime::start(
        generation,
        config,
        fd,
        SocketCallbacks::protect_only(|fd| {
            crate::linux::mark_socket(fd, crate::args::UPSTREAM_MARK).is_ok()
        })
        .with_host_resolver(crate::bootstrap::resolve),
    )
    .map_err(|_| "RUNTIME_START_FAILED")?;
    let result = serve(&runtime, state_path, &mut state).await;
    let stopped = runtime.stop();
    if stopped == StopResult::TimedOut {
        runtime.force_kill();
    }
    state.phase = crate::status::Phase::Stopped;
    let _ = crate::status::write(state_path, &state);
    if stopped == StopResult::TimedOut {
        Err("RUNTIME_STOP_TIMEOUT")
    } else {
        result
    }
}

async fn serve(
    runtime: &CoreRuntime,
    state_path: &Path,
    state: &mut crate::status::Status,
) -> Result<(), &'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = terminate.recv() => return Ok(()),
            _ = interrupt.recv() => return Ok(()),
            _ = timer.tick() => {
                let snapshot: serde_json::Value = serde_json::from_str(&runtime.snapshot_json()).map_err(|_| "STATUS_UNAVAILABLE")?;
                if snapshot.get("last_error").is_some_and(|v| !v.is_null()) {
                    return Err("RUNTIME_FAILED");
                }
                crate::status::require_owner(state, &state.interface)?;
                state.bytes_up = snapshot.get("bytes_up").and_then(|v| v.as_u64()).unwrap_or(0);
                state.bytes_down = snapshot.get("bytes_down").and_then(|v| v.as_u64()).unwrap_or(0);
                crate::status::write(state_path, state)?;
            }
        }
    }
}
