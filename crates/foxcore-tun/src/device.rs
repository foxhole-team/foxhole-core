//! Non-blocking TUN I/O and the crate's only OS-facing unsafe boundary.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
// _IOW('T', 202, int) on Linux — bind a /dev/net/tun fd to an interface.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Linux `struct ifreq` layout used by `ioctl(TUNSETIFF)`.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: i16,
    _pad: [u8; 22],
}

/// A `/dev/net/tun` (or VpnService) fd wrapped for async packet I/O.
///
/// **The device does not own the descriptor.** It borrows it for as long as the
/// runtime is alive, and closing it is the caller's job — see
/// [`TunDevice::from_owned_fd`] for why the ownership sits where it does.
pub struct TunDevice {
    inner: AsyncFd<Borrowed>,
    _live: LiveDevice,
}

/// A descriptor the Tokio task borrows but cannot close.
struct Borrowed(RawFd);

/// Process-wide count readable after the Tokio runtime has stopped.
static LIVE_DEVICES: AtomicUsize = AtomicUsize::new(0);

struct LiveDevice;

impl LiveDevice {
    fn new() -> Self {
        LIVE_DEVICES.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for LiveDevice {
    fn drop(&mut self) {
        LIVE_DEVICES.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Sole TUN owner, retained outside Tokio until the runtime is down.
pub struct TunFdOwner(OwnedFd);

impl TunFdOwner {
    /// The descriptor, for diagnostics that need to name it.
    pub fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Return the number of live wrappers for baseline-relative shutdown checks.
pub fn live_devices() -> usize {
    LIVE_DEVICES.load(Ordering::Acquire)
}

/// Wait without a runtime until the live-device count returns to `baseline`.
pub fn wait_for_devices_released(baseline: usize, budget: std::time::Duration) -> bool {
    const POLL: std::time::Duration = std::time::Duration::from_millis(2);
    let deadline = std::time::Instant::now() + budget;
    loop {
        if LIVE_DEVICES.load(Ordering::Acquire) <= baseline {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

impl AsRawFd for Borrowed {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl TunDevice {
    /// Wrap a configured descriptor while returning ownership to the caller.
    /// Call inside Tokio and retain the owner until the runtime is fully down.
    pub fn from_owned_fd(owned: OwnedFd) -> io::Result<(Self, TunFdOwner)> {
        Self::from_owned(owned)
    }

    /// Attach to a persistent Linux TUN device by name (host/container test path).
    pub fn open_named(name: &str) -> io::Result<(Self, TunFdOwner)> {
        Self::from_owned_fd(open_named_fd(name)?)
    }

    fn from_owned(owned: OwnedFd) -> io::Result<(Self, TunFdOwner)> {
        set_nonblocking(owned.as_raw_fd())?;
        let raw = owned.as_raw_fd();
        let device = Self {
            inner: AsyncFd::new(Borrowed(raw))?,
            _live: LiveDevice::new(),
        };
        Ok((device, TunFdOwner(owned)))
    }
}

/// Bind `/dev/net/tun` to an existing `IFF_TUN | IFF_NO_PI` device.
///
/// [`CoreRuntime::start`]: ../../foxcore_runtime/struct.CoreRuntime.html#method.start
pub fn open_named_fd(name: &str) -> io::Result<OwnedFd> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun name too long",
        ));
    }
    // SAFETY: the path is a static NUL-terminated C string.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a new non-negative descriptor owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr = IfReq {
        name: [0u8; libc::IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0u8; 22],
    };
    ifr.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: `ifr` is a live, correctly sized Linux `ifreq`; the fd stays open.
    let rc = unsafe {
        libc::ioctl(
            owned.as_raw_fd(),
            TUNSETIFF as _,
            ifr.as_mut_bytes().as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fcntl` accepts any integer descriptor and touches no Rust memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor remains borrowed and valid for this call.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            // Read into spare capacity and initialize only the bytes returned.
            // SAFETY: we never de-initialise previously initialised bytes; we only write into the
            // uninitialised tail via `read(2)` and then mark exactly `n` bytes initialised.
            let unfilled = unsafe { buf.unfilled_mut() };
            let capacity = unfilled.len();
            let res = guard.try_io(|inner| {
                // SAFETY: the slice provides writable storage for `capacity` bytes and the
                // descriptor remains live for the poll.
                let n = unsafe {
                    libc::read(inner.as_raw_fd(), unfilled.as_mut_ptr().cast(), capacity)
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                // Defend the `assume_init` bound even though `read(2)` guarantees it.
                if n as usize > capacity {
                    return Err(io::Error::other(
                        "the TUN device reported reading more bytes than it was given",
                    ));
                }
                Ok(n as usize)
            });
            match res {
                Ok(Ok(n)) => {
                    // SAFETY: `read` initialized `n <= capacity` bytes above.
                    unsafe { buf.assume_init(n) };
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            let res = guard.try_io(|inner| {
                // SAFETY: `buf` is readable for its length and the descriptor is live.
                let n = unsafe { libc::write(inner.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
