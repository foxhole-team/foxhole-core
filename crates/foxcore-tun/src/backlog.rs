//! Bounds staged outbound writes and detects stalled flows.
//!
//! Volume cannot distinguish a slow socket from a stalled one. Reaching
//! [`ceiling_for`] applies backpressure; only a non-empty backlog with no
//! progress for [`STALL_TIMEOUT`] fails the flow. Healthy writes pass through
//! without a copy.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

/// Maximum no-progress interval while a backlog exists.
pub(crate) const STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-flow staged-write ceiling: four configured relay buffers.
pub(crate) fn ceiling_for(relay_buffer_bytes: usize) -> usize {
    relay_buffer_bytes.saturating_mul(4)
}

/// Error distinguishing a stalled outbound from a network failure.
#[derive(Debug)]
pub(crate) struct OutboundStalled {
    pub(crate) held: usize,
    pub(crate) after: Duration,
}

impl std::fmt::Display for OutboundStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "outbound accepted nothing for {} s while the flow held {} bytes for it",
            self.after.as_secs(),
            self.held
        )
    }
}

impl std::error::Error for OutboundStalled {}

pub(crate) fn is_outbound_stalled(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<OutboundStalled>())
}

/// Buffered writer with a size ceiling and no-progress timeout.
pub(crate) struct BacklogGuard<S> {
    inner: S,
    /// Staged bytes; `sent` indexes the drained prefix.
    pending: Vec<u8>,
    sent: usize,
    ceiling: usize,
    stall_after: Duration,
    /// Last outbound progress or empty-backlog time.
    progress: Instant,
    /// Armed only while a backlog exists.
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S> BacklogGuard<S> {
    pub(crate) fn new(inner: S, ceiling: usize) -> Self {
        Self::with_stall_timeout(inner, ceiling, STALL_TIMEOUT)
    }

    fn with_stall_timeout(inner: S, ceiling: usize, stall_after: Duration) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            sent: 0,
            ceiling,
            stall_after,
            progress: Instant::now(),
            deadline: None,
        }
    }

    fn backlog(&self) -> usize {
        self.pending.len() - self.sent
    }

    fn note_progress(&mut self) {
        self.progress = Instant::now();
    }

    fn hold(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.backlog() == 0 {
            // Start the clock with the backlog, not earlier flow activity.
            self.note_progress();
        }
        // Reclaim the drained prefix before growing.
        if self.sent > 0 {
            self.pending.drain(..self.sent);
            self.sent = 0;
        }
        self.pending.extend_from_slice(bytes);
    }
}

impl<S: AsyncWrite + Unpin> BacklogGuard<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => {
                    self.sent += written;
                    self.note_progress();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.sent = 0;
        self.note_progress();
        self.deadline = None;
        Poll::Ready(Ok(()))
    }

    /// Register the timer that wakes an otherwise silent stalled flow.
    fn poll_stall(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.backlog() == 0 {
            self.deadline = None;
            return None;
        }
        let stall_after = self.stall_after;
        let progress = self.progress;
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(sleep_until(progress + stall_after)));
        if deadline.as_mut().poll(cx).is_pending() {
            return None;
        }
        if self.progress.elapsed() >= stall_after {
            return Some(io::Error::other(OutboundStalled {
                held: self.backlog(),
                after: stall_after,
            }));
        }
        // Re-arm from the most recent progress and register the waker.
        deadline.as_mut().reset(self.progress + stall_after);
        let _ = deadline.as_mut().poll(cx);
        None
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BacklogGuard<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BacklogGuard<S> {
    /// Accept below the ceiling so the upstream stack stays drained.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if me.backlog() == 0 {
            match Pin::new(&mut me.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(0)) if !buf.is_empty() => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) if written == buf.len() => {
                    me.note_progress();
                    return Poll::Ready(Ok(written));
                }
                Poll::Ready(Ok(written)) => {
                    me.note_progress();
                    me.hold(&buf[written..]);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => me.hold(buf),
            }
            return match me.poll_stall(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(buf.len())),
            };
        }
        if let Poll::Ready(Err(error)) = me.drain(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(error) = me.poll_stall(cx) {
            return Poll::Ready(Err(error));
        }
        if me.backlog() >= me.ceiling {
            // The outbound and stall timer have both registered this waker.
            return Poll::Pending;
        }
        me.hold(buf);
        Poll::Ready(Ok(buf.len()))
    }

    /// Flush staged bytes or fail after the no-progress deadline.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => {
                return match me.poll_stall(cx) {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Pending,
                };
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => {
                return match me.poll_stall(cx) {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Pending,
                };
            }
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[derive(Default)]
    struct SinkState {
        accepted: Vec<u8>,
        /// Maximum bytes accepted per poll; zero never progresses.
        per_poll: usize,
        /// Whether to park between polls.
        parks: bool,
        ready: bool,
        once: bool,
        waker: Option<Waker>,
    }

    /// Outbound with test-controlled progress.
    #[derive(Clone, Default)]
    struct Sink {
        state: Arc<Mutex<SinkState>>,
    }

    impl Sink {
        fn with(per_poll: usize, parks: bool) -> Self {
            let sink = Sink::default();
            {
                let mut state = sink.lock();
                state.per_poll = per_poll;
                state.parks = parks;
                state.ready = true;
            }
            sink
        }

        fn unlimited() -> Self {
            Sink::with(usize::MAX, false)
        }

        fn taking(per_poll: usize) -> Self {
            Sink::with(per_poll, true)
        }

        fn stalled() -> Self {
            Sink::with(0, true)
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, SinkState> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn accepted(&self) -> usize {
            self.lock().accepted.len()
        }

        fn resume(&self, per_poll: usize) {
            let waker = {
                let mut state = self.lock();
                state.per_poll = per_poll;
                state.once = false;
                state.ready = true;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn take_once(&self, bytes: usize) {
            self.resume(bytes);
            self.lock().once = true;
        }
    }

    impl AsyncWrite for Sink {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.lock();
            if state.per_poll == 0 {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if state.parks {
                if !state.ready {
                    state.ready = true;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                state.ready = false;
            }
            let take = buf.len().min(state.per_poll);
            state.accepted.extend_from_slice(&buf[..take]);
            if state.once {
                state.once = false;
                state.per_poll = 0;
            }
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Sink {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn an_outbound_that_keeps_up_is_written_through_without_a_copy() {
        let sink = Sink::unlimited();
        let mut guard = BacklogGuard::new(sink.clone(), 64 * 1024);

        for _ in 0..8 {
            guard.write_all(&[7_u8; 4096]).await.unwrap();
            assert_eq!(
                guard.backlog(),
                0,
                "nothing may be held while the outbound is taking it"
            );
        }
        guard.flush().await.unwrap();
        assert_eq!(sink.accepted(), 8 * 4096);
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test(start_paused = true)]
    async fn an_outbound_that_is_only_slower_than_the_writer_is_never_torn_down() {
        let sink = Sink::taking(4096);
        let ceiling = 64 * 1024;
        let mut guard = BacklogGuard::new(sink.clone(), ceiling);

        let offered = 16 * ceiling;
        let chunk = vec![9_u8; 16 * 1024];
        let mut written = 0;
        while written < offered {
            guard
                .write_all(&chunk)
                .await
                .expect("a slow outbound is not a stalled one");
            written += chunk.len();
        }
        guard.flush().await.expect("and the flush must not fail");

        assert_eq!(
            sink.accepted(),
            offered,
            "every offered byte has to reach an outbound that was always making progress"
        );
        assert_eq!(guard.backlog(), 0);
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test(start_paused = true)]
    async fn a_flow_at_its_ceiling_parks_its_writer_instead_of_failing() {
        let sink = Sink::stalled();
        let ceiling = 16 * 1024;
        let mut guard = BacklogGuard::new(sink.clone(), ceiling);

        for _ in 0..4 {
            guard.write_all(&[1_u8; 4096]).await.unwrap();
        }
        assert_eq!(guard.backlog(), ceiling);
        assert_eq!(sink.accepted(), 0, "the outbound took none of it");

        // A full guard waits instead of failing.
        let mut parked = std::pin::pin!(guard.write_all(&[1_u8; 4096]));
        let waited = tokio::time::timeout(STALL_TIMEOUT / 2, &mut parked).await;
        assert!(waited.is_err(), "a full guard parks its writer");

        sink.resume(usize::MAX);
        parked.await.expect("and resumes when the outbound does");
        guard.flush().await.unwrap();
        assert_eq!(sink.accepted(), 5 * 4096, "everything held has to arrive");
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test(start_paused = true)]
    async fn an_outbound_that_accepts_nothing_is_torn_down_once_the_window_passes() {
        let sink = Sink::stalled();
        let mut guard = BacklogGuard::new(sink.clone(), 64 * 1024);
        guard.write_all(&[2_u8; 8192]).await.unwrap();

        let started = Instant::now();
        let early = tokio::time::timeout(STALL_TIMEOUT / 2, guard.flush()).await;
        assert!(
            early.is_err(),
            "half a window of silence is not yet a stalled flow"
        );

        let error = guard.flush().await.unwrap_err();
        assert!(
            is_outbound_stalled(&error),
            "the flow has to fail with its own reason, not as a network error: {error:?}"
        );
        assert!(
            started.elapsed() >= STALL_TIMEOUT,
            "and not before the whole window has passed"
        );
        assert!(
            error.to_string().contains("8192"),
            "the message has to say how much was held: {error}"
        );
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test(start_paused = true)]
    async fn a_backlog_that_never_empties_is_fine_as_long_as_it_keeps_moving() {
        let sink = Sink::stalled();
        let mut guard = BacklogGuard::new(sink.clone(), 64 * 1024);
        guard.write_all(&[4_u8; 8192]).await.unwrap();

        for _ in 0..4 {
            // One byte resets the no-progress clock.
            let waited =
                tokio::time::timeout(STALL_TIMEOUT - Duration::from_secs(1), guard.flush());
            assert!(
                waited.await.is_err(),
                "the flow is holding and moving, so there is no verdict to give"
            );
            sink.take_once(1);
            let waited = tokio::time::timeout(Duration::from_millis(1), guard.flush());
            assert!(waited.await.is_err());
        }

        assert!(
            guard.backlog() > 0,
            "the flow is still holding, and still alive"
        );
        sink.resume(usize::MAX);
        guard
            .flush()
            .await
            .expect("and finishes when the peer does");
        assert_eq!(sink.accepted(), 8192);
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test(start_paused = true)]
    async fn a_flow_that_was_quiet_before_it_stalled_still_gets_its_whole_window() {
        let sink = Sink::stalled();
        let mut guard = BacklogGuard::new(sink.clone(), 64 * 1024);
        // Pre-backlog idle time must not count toward the stall window.
        tokio::time::sleep(STALL_TIMEOUT * 4).await;

        let started = Instant::now();
        guard
            .write_all(&[6_u8; 4096])
            .await
            .expect("holding bytes is not the same as having held them too long");
        let early = tokio::time::timeout(STALL_TIMEOUT / 2, guard.flush()).await;
        assert!(early.is_err(), "the window starts when the backlog does");

        let error = guard.flush().await.unwrap_err();
        assert!(is_outbound_stalled(&error));
        assert!(
            started.elapsed() >= STALL_TIMEOUT,
            "and it is a whole window, measured from the first held byte"
        );
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn writing_straight_to_a_stalled_outbound_reports_nothing_at_all() {
        let sink = Sink::stalled();
        let mut plain = sink.clone();

        let parked = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            plain.write_all(&[1_u8; 4096]),
        )
        .await;

        assert!(
            parked.is_err(),
            "the pre-fix path does not fail here — that is the defect: it waits, \
             and the growth happens somewhere nothing can see it"
        );
        assert_eq!(sink.accepted(), 0);
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn a_backlog_the_outbound_finally_takes_leaves_nothing_behind() {
        let sink = Sink::stalled();
        let mut guard = BacklogGuard::new(sink.clone(), 64 * 1024);

        guard.write_all(&[3_u8; 8192]).await.unwrap();
        assert_eq!(guard.backlog(), 8192);

        sink.resume(usize::MAX);
        guard.flush().await.unwrap();

        assert_eq!(guard.backlog(), 0);
        assert_eq!(
            sink.accepted(),
            8192,
            "everything held has to arrive, and in order"
        );
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn the_copy_loop_that_drives_this_flushes_when_its_reader_goes_quiet() {
        let (mut near, far) = tokio::io::duplex(4096);
        let sink = Sink::stalled();
        let mut guard = BacklogGuard::new(sink.clone(), 64 * 1024);

        let copy = tokio::spawn(async move {
            let mut far = far;
            tokio::io::copy(&mut far, &mut guard).await
        });

        near.write_all(&[5_u8; 2048]).await.unwrap();
        near.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        sink.resume(usize::MAX);
        drop(near);

        let copied = tokio::time::timeout(std::time::Duration::from_secs(5), copy)
            .await
            .expect("the copy must finish once the outbound accepts")
            .unwrap()
            .unwrap();
        assert_eq!(copied, 2048);
        assert_eq!(sink.accepted(), 2048);
    }

    #[test]
    fn the_ceiling_always_clears_one_whole_relay_buffer() {
        for buffer in [4 * 1024_usize, 16 * 1024, 256 * 1024] {
            assert!(
                ceiling_for(buffer) > buffer,
                "a single ordinary write must never trip it"
            );
        }
        assert_eq!(ceiling_for(16 * 1024), 64 * 1024);
    }
}
