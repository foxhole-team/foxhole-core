use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{BufferPool, copy_bidirectional_pooled};

/// A stream that fails the first time it is read and swallows every write.
///
/// Stands in for the outbound the backlog guard fails: the relay must surface
/// that error even though the other direction is perfectly healthy and parked.
struct FailsOnRead(io::ErrorKind);

impl AsyncRead for FailsOnRead {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(self.0, "scripted relay failure")))
    }
}

impl AsyncWrite for FailsOnRead {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A writer that never accepts a byte and never wakes anyone.
struct NeverWrites;

impl AsyncRead for NeverWrites {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for NeverWrites {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn both_directions_carry_their_bytes_and_the_half_close_is_forwarded() {
    let pool = BufferPool::new(4 * 1024, 8);
    let (mut left, mut left_peer) = tokio::io::duplex(4 * 1024);
    let (mut right, mut right_peer) = tokio::io::duplex(4 * 1024);

    let relay = copy_bidirectional_pooled(&pool, &mut left, &mut right);
    let peers = async {
        left_peer.write_all(b"request").await.unwrap();
        left_peer.shutdown().await.unwrap();

        // `read_to_end` only returns because the relay shut the far writer down
        // when its reader hit EOF. A relay that forwarded the bytes but not the
        // end of stream would hang here, which is the whole point of the assert.
        let mut forwarded = Vec::new();
        right_peer.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, b"request");

        right_peer.write_all(b"response").await.unwrap();
        right_peer.shutdown().await.unwrap();

        let mut returned = Vec::new();
        left_peer.read_to_end(&mut returned).await.unwrap();
        assert_eq!(returned, b"response");
    };

    let (moved, ()) = tokio::join!(relay, peers);
    assert_eq!(moved.unwrap(), (7, 8));
}

#[tokio::test]
async fn a_finished_relay_gives_both_buffers_back() {
    let pool = BufferPool::new(1024, 8);
    let (mut left, left_peer) = tokio::io::duplex(1024);
    let (mut right, right_peer) = tokio::io::duplex(1024);
    drop(left_peer);
    drop(right_peer);

    copy_bidirectional_pooled(&pool, &mut left, &mut right)
        .await
        .unwrap();
    assert_eq!(pool.idle(), 2, "one buffer per direction, both returned");
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_relay_gives_both_buffers_back() {
    let pool = BufferPool::new(1024, 8);
    // Kept alive: a dropped peer would end the copy on its own and prove
    // nothing about cancellation.
    let (mut left, _left_peer) = tokio::io::duplex(1024);
    let (mut right, _right_peer) = tokio::io::duplex(1024);

    // The timeout is the cancellation: it drops the relay future while both
    // directions are parked, which is what a kill switch, a revoked policy and
    // an idle reclaim all do to a live relay.
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        copy_bidirectional_pooled(&pool, &mut left, &mut right),
    )
    .await;

    assert!(
        outcome.is_err(),
        "the relay was supposed to still be running"
    );
    assert_eq!(pool.idle(), 2, "cancellation must not lose the buffers");
}

#[tokio::test(start_paused = true)]
async fn a_failing_direction_ends_the_relay_without_waiting_for_the_other() {
    let pool = BufferPool::new(1024, 8);
    let mut failing = FailsOnRead(io::ErrorKind::BrokenPipe);
    let mut silent = NeverWrites;

    // No timeout wrapper on purpose: if the error did not end the copy, this
    // test hangs rather than reporting a wrong error, and a hang is the honest
    // signal — the TUN engine's stall diagnosis depends on exactly this
    // promptness.
    let error = copy_bidirectional_pooled(&pool, &mut failing, &mut silent)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(pool.idle(), 2, "a failed relay returns its buffers too");
}

#[tokio::test]
async fn the_pool_hands_back_the_size_it_was_built_with() {
    let pool = BufferPool::new(64 * 1024, 2);
    let mut lease = pool.lease();
    assert_eq!(lease.bytes_mut().len(), 64 * 1024);
    assert_eq!(pool.idle(), 0, "a leased buffer is not idle");
    drop(lease);
    assert_eq!(pool.idle(), 1);
}

#[tokio::test]
async fn the_idle_cap_is_a_ceiling_on_what_stays_resident() {
    let pool = BufferPool::new(16, 1);
    let first = pool.lease();
    let second = pool.lease();
    drop(first);
    drop(second);
    assert_eq!(pool.idle(), 1, "the second buffer is dropped, not kept");

    // And the pool still works once it is over its cap: the next lease takes
    // the parked buffer and the one after it allocates.
    let reused = pool.lease();
    assert_eq!(pool.idle(), 0);
    drop(reused);
}

#[tokio::test]
async fn a_relay_reuses_the_buffers_a_previous_relay_returned() {
    let pool = BufferPool::new(1024, 8);
    for _ in 0..4 {
        let (mut left, left_peer) = tokio::io::duplex(1024);
        let (mut right, right_peer) = tokio::io::duplex(1024);
        drop(left_peer);
        drop(right_peer);
        copy_bidirectional_pooled(&pool, &mut left, &mut right)
            .await
            .unwrap();
    }
    // Four connections, still two buffers: the allocation happens once, which is
    // the entire claim this crate makes.
    assert_eq!(pool.idle(), 2);
}

#[tokio::test]
async fn a_large_transfer_survives_being_split_across_many_buffer_loads() {
    // Payload larger than the buffer, so the copy loop refills many times and a
    // fence-post error in the top-up path would corrupt or truncate it.
    let payload: Vec<u8> = (0..(64 * 1024_u32)).map(|byte| byte as u8).collect();
    let pool = BufferPool::new(1024, 4);
    let (mut left, mut left_peer) = tokio::io::duplex(4 * 1024);
    let (mut right, mut right_peer) = tokio::io::duplex(4 * 1024);

    let relay = copy_bidirectional_pooled(&pool, &mut left, &mut right);
    let expected = payload.clone();
    let peers = async move {
        let writer = async {
            left_peer.write_all(&payload).await.unwrap();
            left_peer.shutdown().await.unwrap();
        };
        let reader = async {
            let mut got = Vec::new();
            right_peer.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, expected);
            right_peer.shutdown().await.unwrap();
        };
        tokio::join!(writer, reader);
    };

    let (moved, ()) = tokio::join!(relay, peers);
    assert_eq!(moved.unwrap().0, 64 * 1024);
}

#[tokio::test]
async fn an_unrepresentable_buffer_is_an_error_before_stream_io() {
    let pool = BufferPool::new(usize::MAX, 2);
    let mut left = NeverWrites;
    let mut right = NeverWrites;
    let error = copy_bidirectional_pooled(&pool, &mut left, &mut right)
        .await
        .expect_err("buffer capacity must fail before streams are polled");
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(pool.idle(), 0);
}

#[tokio::test]
async fn a_zero_buffer_is_rejected_without_reporting_false_eof() {
    let pool = BufferPool::new(0, 2);
    let (mut left, mut left_peer) = tokio::io::duplex(64);
    let (mut right, mut right_peer) = tokio::io::duplex(64);
    left_peer.write_all(b"must not disappear").await.unwrap();
    left_peer.shutdown().await.unwrap();
    right_peer.shutdown().await.unwrap();
    let error = copy_bidirectional_pooled(&pool, &mut left, &mut right)
        .await
        .expect_err("empty buffer must not turn pending data into success");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[cfg(target_os = "linux")]
#[test]
fn allocation_refusal_in_a_limited_child_does_not_abort_the_relay() {
    const CHILD_MARKER: &str = "FOXHOLE_RELAY_ALLOCATION_CHILD";
    if std::env::var_os(CHILD_MARKER).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let pool = BufferPool::new(128 * 1024 * 1024, 2);
            let mut left = NeverWrites;
            let mut right = NeverWrites;
            let error = copy_bidirectional_pooled(&pool, &mut left, &mut right)
                .await
                .expect_err("a constrained process must reject the buffer allocation");
            assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
            assert_eq!(pool.idle(), 0);
            let healthy = BufferPool::new(1024, 2);
            let (mut a, a_peer) = tokio::io::duplex(1024);
            let (mut b, b_peer) = tokio::io::duplex(1024);
            drop(a_peer);
            drop(b_peer);
            assert_eq!(
                copy_bidirectional_pooled(&healthy, &mut a, &mut b)
                    .await
                    .unwrap(),
                (0, 0)
            );
        });
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("ulimit -v 65536 || exit 97; exec \"$1\" --exact tests::allocation_refusal_in_a_limited_child_does_not_abort_the_relay --nocapture")
        .arg("relay-allocation-child")
        .arg(executable)
        .env(CHILD_MARKER, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bounded child failed: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
