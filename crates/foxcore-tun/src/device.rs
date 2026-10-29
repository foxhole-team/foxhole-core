//! Non-blocking TUN I/O and the crate's only OS-facing unsafe boundary.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_TUN_EXCL: i16 = 0x8000u16 as i16;
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
/// The external [`TunFdOwner`] owns the descriptor. Dropping that owner revokes
/// this device's registration and wakes pending I/O before closing the fd.
pub struct TunDevice {
    registration: Arc<Mutex<Registration>>,
    _live: LiveDevice,
}

struct Registration {
    io: Option<AsyncFd<Borrowed>>,
    reader: Option<Waker>,
    writer: Option<Waker>,
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

/// Sole TUN owner, normally retained outside Tokio until the runtime is down.
pub struct TunFdOwner {
    fd: OwnedFd,
    registration: Arc<Mutex<Registration>>,
}

impl TunFdOwner {
    /// The descriptor, for diagnostics that need to name it.
    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for TunFdOwner {
    fn drop(&mut self) {
        let (io, reader, writer) = {
            // A panicking poll must not leave a live registration on a closed fd.
            let mut state = self.registration.lock().unwrap_or_else(|e| e.into_inner());
            (state.io.take(), state.reader.take(), state.writer.take())
        };
        // Deregistration and wakers can enter Tokio; do both outside our lock.
        // The owned fd remains open until this destructor returns.
        drop(io);
        if let Some(reader) = reader {
            reader.wake();
        }
        if let Some(writer) = writer {
            writer.wake();
        }
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
    /// Call inside Tokio. Retain the owner for the duration of packet I/O;
    /// dropping it early makes subsequent reads and writes return `BrokenPipe`.
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
        // SAFETY: the sole owner keeps `raw` open. Its destructor takes and
        // drops this registration under the same lock used for all fd I/O,
        // before `OwnedFd` can close it. The device never drops it independently.
        let io = unsafe { AsyncFd::register(Borrowed(raw))? };
        let registration = Arc::new(Mutex::new(Registration {
            io: Some(io),
            reader: None,
            writer: None,
        }));
        let device = Self {
            registration: registration.clone(),
            _live: LiveDevice::new(),
        };
        Ok((
            device,
            TunFdOwner {
                fd: owned,
                registration,
            },
        ))
    }
}

/// Bind `/dev/net/tun` to an existing `IFF_TUN | IFF_NO_PI` device.
///
/// [`CoreRuntime::start`]: ../../foxcore_runtime/struct.CoreRuntime.html#method.start
pub fn open_named_fd(name: &str) -> io::Result<OwnedFd> {
    open_with_flags(name, IFF_TUN | IFF_NO_PI)
}

/// Create a named Linux TUN, atomically refusing an existing interface.
pub fn open_exclusive_named_fd(name: &str) -> io::Result<OwnedFd> {
    open_with_flags(name, IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL)
}

fn open_with_flags(name: &str, flags: i16) -> io::Result<OwnedFd> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun name too long",
        ));
    }
    // SAFETY: the path is a static NUL-terminated C string.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a new non-negative descriptor owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr = IfReq {
        name: [0u8; libc::IFNAMSIZ],
        flags,
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
        let next = cx.waker().clone();
        let mut state = self.registration.lock().unwrap_or_else(|e| e.into_inner());
        let previous = if state.io.is_some() {
            state.reader.replace(next)
        } else {
            Some(next)
        };
        let result = (|| {
            let Some(io) = state.io.as_ref() else {
                return Poll::Ready(Err(revoked()));
            };
            loop {
                let mut guard = ready!(io.poll_read_ready(cx))?;
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
        })();
        drop(state);
        drop(previous);
        result
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let next = cx.waker().clone();
        let mut state = self.registration.lock().unwrap_or_else(|e| e.into_inner());
        let previous = if state.io.is_some() {
            state.writer.replace(next)
        } else {
            Some(next)
        };
        let result = (|| {
            let Some(io) = state.io.as_ref() else {
                return Poll::Ready(Err(revoked()));
            };
            loop {
                let mut guard = ready!(io.poll_write_ready(cx))?;
                let res = guard.try_io(|inner| {
                    // SAFETY: `buf` is readable for its length and the descriptor is live.
                    let n =
                        unsafe { libc::write(inner.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
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
        })();
        drop(state);
        drop(previous);
        result
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn revoked() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "TUN descriptor owner was dropped",
    )
}

#[cfg(test)]
mod registration_lifetime_tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn fd_is_open(fd: RawFd) -> bool {
        // SAFETY: F_GETFD accepts any integer descriptor and touches no Rust memory.
        unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
    }

    #[test]
    fn poisoned_registration_still_revokes_before_close() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let (socket, _peer) = UnixStream::pair().unwrap();
        let (mut device, owner) = {
            let _entered = runtime.enter();
            TunDevice::from_owned_fd(OwnedFd::from(socket)).unwrap()
        };
        let raw = owner.raw();
        let registration = device.registration.clone();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = registration.lock().unwrap();
            panic!("intentional registration-state poison");
        }));
        assert!(poisoned.is_err());
        assert!(fd_is_open(raw));

        drop(owner);
        assert!(!fd_is_open(raw));
        {
            let state = registration
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert!(state.io.is_none() && state.reader.is_none() && state.writer.is_none());
        }
        // Check revocation before polling: neither branch may access the closed fd.
        let mut context = Context::from_waker(Waker::noop());
        let mut storage = [0u8; 1];
        let mut buffer = ReadBuf::new(&mut storage);
        let read = Pin::new(&mut device).poll_read(&mut context, &mut buffer);
        assert!(
            matches!(read, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        let write = Pin::new(&mut device).poll_write(&mut context, b"x");
        assert!(
            matches!(write, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn owner_drop_waits_for_the_registration_borrow() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let (socket, _peer) = UnixStream::pair().unwrap();
        let (device, owner) = {
            let _entered = runtime.enter();
            TunDevice::from_owned_fd(OwnedFd::from(socket)).unwrap()
        };
        let raw = owner.raw();
        let registration = device.registration.clone();
        let held = registration.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let dropper = std::thread::spawn(move || {
            let _ = started_tx.send(());
            drop(owner);
            let _ = done_tx.send(());
        });
        let started = started_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        let still_open = fd_is_open(raw);
        let finished_while_borrowed = done_rx.try_recv().is_ok();
        drop(held);
        let finished = done_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        if finished {
            dropper.join().unwrap();
        }
        assert!(started && still_open && !finished_while_borrowed && finished);
        assert!(!fd_is_open(raw));
        assert!(registration.lock().unwrap().io.is_none());
        drop(device);
    }
}
