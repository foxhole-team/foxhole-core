use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use foxcore_tun::TunDevice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn is_open(fd: RawFd) -> bool {
    // SAFETY: F_GETFD accepts an arbitrary descriptor and touches no Rust memory.
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_the_owner_revokes_the_registered_device() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let (mut device, owner) = TunDevice::from_owned_fd(OwnedFd::from(socket)).unwrap();
    let raw = owner.raw();

    drop(owner);
    assert!(
        !is_open(raw),
        "the external owner must close its descriptor"
    );
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_millis(200), device.read(&mut byte))
        .await
        .expect("a revoked registration must not wait for readiness");
    assert_eq!(read.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(
        device.write(b"x").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    drop(device);
}

#[test]
fn a_retained_device_does_not_delay_close_after_runtime_shutdown() {
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

    drop(runtime);
    drop(owner);
    assert!(
        !is_open(raw),
        "shutdown must not leave the TUN descriptor open"
    );
    drop(device);
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_the_owner_wakes_a_pending_reader() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let (mut device, owner) = TunDevice::from_owned_fd(OwnedFd::from(socket)).unwrap();
    let mut reader = tokio::spawn(async move {
        let mut byte = [0];
        device.read(&mut byte).await
    });
    tokio::task::yield_now().await;

    drop(owner);
    let result = tokio::time::timeout(Duration::from_millis(200), &mut reader).await;
    if result.is_err() {
        reader.abort();
        let _ = reader.await;
        panic!("revoking the descriptor must wake its pending reader");
    }
    assert_eq!(
        result.unwrap().unwrap().unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_the_owner_wakes_a_pending_writer() {
    let (mut socket, _peer) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    let bytes = [0; 65536];
    let mut full = false;
    for _ in 0..128 {
        match std::io::Write::write(&mut socket, &bytes) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                full = true;
                break;
            }
            Err(error) => panic!("could not fill the test socket: {error}"),
        }
    }
    assert!(full, "the test must reach backpressure before registration");
    let (mut device, owner) = TunDevice::from_owned_fd(OwnedFd::from(socket)).unwrap();
    let mut writer = tokio::spawn(async move { device.write(b"x").await });
    tokio::task::yield_now().await;

    std::thread::spawn(move || drop(owner)).join().unwrap();
    let result = tokio::time::timeout(Duration::from_millis(200), &mut writer).await;
    if result.is_err() {
        writer.abort();
        let _ = writer.await;
        panic!("revoking the descriptor must wake its pending writer");
    }
    assert_eq!(
        result.unwrap().unwrap().unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_the_device_keeps_the_external_owner_open() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let (device, owner) = TunDevice::from_owned_fd(OwnedFd::from(socket)).unwrap();
    let raw = owner.raw();

    drop(device);
    assert!(
        is_open(raw),
        "the external owner controls shutdown close timing"
    );
    drop(owner);
    assert!(
        !is_open(raw),
        "the final external owner drop must close the descriptor"
    );
}
