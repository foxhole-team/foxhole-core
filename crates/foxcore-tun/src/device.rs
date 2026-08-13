//! TUN device as an async byte stream of IP packets.
//!
//! This is the one place the data-plane touches the OS. Two entry points, same wrapper:
//!   * [`TunDevice::from_owned_fd`] — Android: `VpnService.Builder.establish()` hands us a
//!     ready fd (routes/DNS/MTU already applied by Kotlin). We only read/write packets.
//!     It takes an `OwnedFd`, not a number, so ownership is a type here and not a comment;
//!     validating the descriptor the app passed is the JNI boundary's job and it does it
//!     (`foxcore-android`, `take_tun_fd`).
//!   * [`TunDevice::open_named`] — Linux host: attach to a persistent `IFF_TUN | IFF_NO_PI`
//!     device by name (created out-of-band). Used for the host/container e2e test.
//!
//! The device is put in non-blocking mode and driven through tokio's [`AsyncFd`], so it
//! behaves like any other `AsyncRead + AsyncWrite` and plugs straight into `ipstack`.
//!
//! This module is the only OS-facing unsafe boundary in the TUN crate.

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

/// The Linux `struct ifreq` we hand to `ioctl(TUNSETIFF)`: a 16-byte interface name followed by
/// the flags `short`, padded out to the kernel's 40-byte `sizeof(struct ifreq)`. Only the name
/// and flags are read for this ioctl; the trailing union bytes stay zero. Using a zerocopy
/// `#[repr(C)]` struct removes the hand-written `[0u8; 40]` and offset arithmetic while keeping
/// the exact field placement the kernel expects (`ifr_flags` is native-endian).
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

/// A descriptor this device uses but will not close.
///
/// `AsyncFd` needs something that can hand it a raw fd; it must not be an
/// `OwnedFd`, because the device ends up inside a Tokio task and a task is not
/// a place a VPN's tunnel descriptor can be left. Aborting a task only
/// schedules its drop, and `Runtime::shutdown_timeout` leaks one it cannot
/// finish — so the fd would be closed by nobody, and on a Pixel that is exactly
/// what happened: `device_released=false` after a full 1753 ms of shutdown,
/// with the app then seeing a tunnel it was told had come down and killing its
/// own process to be sure.
struct Borrowed(RawFd);

/// How many `TunDevice`s exist in this process right now.
///
/// The stop path needs an answer to "is the descriptor actually gone", and it
/// needs it without asking the executor. The device is owned by a Tokio task;
/// aborting that task only schedules its drop, and `Runtime::shutdown_timeout`
/// leaks a task caught mid-poll, so "the runtime is down" is not the same
/// statement as "the fd is closed". On a Pixel the difference showed as a stop
/// that reported success while the duplicate descriptor was still open, which
/// the app reads as a leaked tunnel and answers by killing its own process.
///
/// A counter rather than a channel because it must be readable from a plain
/// thread with no runtime left to poll.
static LIVE_DEVICES: AtomicUsize = AtomicUsize::new(0);

/// Increments on construction, decrements on drop. Separate from `TunDevice` so
/// the decrement cannot be lost to a partially-constructed device.
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

/// The one thing that closes the TUN descriptor.
///
/// Held by the thread that owns the generation, dropped after the Tokio runtime
/// is fully down. Splitting it from [`TunDevice`] is what makes "the runtime is
/// down" and "the fd is closed" the same statement again.
pub struct TunFdOwner(OwnedFd);

impl TunFdOwner {
    /// The descriptor, for diagnostics that need to name it.
    pub fn raw(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// How many `TunDevice`s are alive right now.
///
/// Read before a generation creates its device, so its own release can be
/// waited for relative to that baseline. Waiting for zero instead would make
/// one leaked device from an earlier generation condemn every generation after
/// it — a stop that is actually clean reporting that it is not.
pub fn live_devices() -> usize {
    LIVE_DEVICES.load(Ordering::Acquire)
}

/// Wait, without a runtime, until the device count is back to `baseline`.
///
/// Returns `true` if it got there. `false` means the caller must not report a
/// clean release: something still holds the descriptor, and saying otherwise is
/// what makes the app trust a tunnel that is still up.
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
    /// Wrap an already-configured TUN descriptor, and hand its closing back.
    ///
    /// Must be called from inside a Tokio runtime context. The returned
    /// [`TunFdOwner`] is the only thing that closes the descriptor, and it is
    /// deliberately *not* part of the device: the device is moved into a Tokio
    /// task, and a task can be abandoned by `Runtime::shutdown_timeout` without
    /// ever being dropped. Keep the owner on the thread that shuts the runtime
    /// down, and drop it after — at that point no task will be polled again, so
    /// nothing can still be using the fd.
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

/// Open `/dev/net/tun` and bind it to an existing device, returning the raw
/// descriptor rather than a wrapped device.
///
/// [`TunDevice::open_named`] wraps this. It is separate because the production
/// entry point the app uses is [`CoreRuntime::start`], which takes an `OwnedFd`
/// — a host harness that wants to exercise *that* path, and not just the flow
/// engine underneath it, needs the descriptor and not the wrapper. Keeping the
/// ioctl in one place means both callers get the same `IFF_TUN | IFF_NO_PI`
/// device.
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
            // Read straight into the uninitialised tail of the buffer. The previous
            // `initialize_unfilled()` zeroed the whole unfilled region on *every* packet read —
            // a memset on the hottest path in the data plane. `read(2)` only ever writes the
            // bytes it returns, so we init exactly `n` afterwards.
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
                // `assume_init(n)` below is only sound while `n` really is a
                // count of bytes `read` wrote, and `read(2)` returning more
                // than it was given is the one way that stops being true. The
                // kernel's contract says it cannot; this branch already
                // compares `n` against zero, so making the second half of that
                // contract a check instead of an assumption costs one
                // integer comparison per packet.
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
