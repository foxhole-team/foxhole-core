use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

pub(crate) fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointers or preconditions and changes no state.
    unsafe { libc::geteuid() }
}

pub(crate) fn mark_socket(fd: RawFd, mark: u32) -> io::Result<()> {
    // SAFETY: the caller keeps fd open; mark is readable for its exact native size during this call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_ref(&mark).cast(),
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn bind_device(fd: RawFd, interface: &str) -> io::Result<()> {
    let interface = CString::new(interface).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: the caller keeps fd open; the NUL-terminated name remains alive for this synchronous call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface.as_ptr().cast(),
            interface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn configure_return_path(interface: &str) -> Result<(), &'static str> {
    let path = format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter");
    let current = std::fs::read_to_string(&path).map_err(|_| "TUN_RETURN_PATH_FAILED")?;
    // Policy-routed replies arrive through the owned TUN despite the WAN's main default route.
    if current.trim() != "2" {
        std::fs::write(path, "2\n").map_err(|_| "TUN_RETURN_PATH_FAILED")?;
    }
    Ok(())
}

pub(crate) async fn ip(args: &[&str]) -> Result<(), &'static str> {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new("ip")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "INTERFACE_COMMAND_TIMEOUT")?
    .map_err(|_| "INTERFACE_COMMAND_FAILED")?;
    if result.status.success() {
        Ok(())
    } else {
        Err("INTERFACE_COMMAND_FAILED")
    }
}
