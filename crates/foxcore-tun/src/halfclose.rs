//! When the far end of a relay stops sending, and who is told.
//!
//! `copy_bidirectional` returns when **both** directions are finished, and that
//! is the whole of a relayed flow's lifetime: `dispatch_tcp` moves an owned
//! semaphore permit into the task, and the task holds it until `handle_tcp`
//! returns. So a connection whose remote half closes — the server sent FIN, the
//! application has not — leaves the app→remote direction parked on a read that
//! will never come, and the flow keeps:
//!
//! * the outbound's socket, which the kernel shows as `CLOSE_WAIT` because we
//!   received a FIN and never closed our side, and
//! * one of `max_tcp_flows`, which since the flow table gained a hard ceiling is
//!   a slot another connection is refused with an RST for.
//!
//! Measured on the owner's Pixel over thirty minutes with the tunnel up: 77
//! sockets to the proxy endpoint in `CLOSE_WAIT` under the app's uid while
//! `ESTABLISHED` drained from 34 to 5. They did not clear, because the only
//! clock that would ever have ended them is `tcp_idle_timeout_s` — an hour.
//!
//! What this module contributes is the *observation*: a passthrough wrapper that
//! notices the remote's end-of-stream at the moment `copy_bidirectional` does,
//! and trips a token the relay can select on. It deliberately does not decide
//! anything — a half-open connection is legitimate TCP and the application may
//! still have bytes to push — so the decision, and the window, live in
//! `flow::route::stayed_half_closed` beside the idle clock they belong with.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// A stream that reports its reader reaching end-of-stream, and is otherwise
/// exactly the stream it wraps.
///
/// Wrapped *outside* the backlog guard so what it sees is what the relay sees:
/// the guard passes reads straight through, so either position observes the same
/// end-of-stream, and the outer one needs no assumption about that to be true.
///
/// The token is cancelled at most once — `CancellationToken::cancel` is
/// idempotent — and nothing here ever un-trips it. End-of-stream on a TCP read
/// half is final: once the peer's FIN is delivered, no later read can produce
/// data.
pub(crate) struct WatchRemoteEof<S> {
    inner: S,
    eof: CancellationToken,
}

impl<S> WatchRemoteEof<S> {
    pub(crate) fn new(inner: S, eof: CancellationToken) -> Self {
        Self { inner, eof }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WatchRemoteEof<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Both halves of the end-of-stream test, taken before the read: a ready
        // read that filled nothing is only end-of-stream if there was somewhere
        // to put a byte. `copy_bidirectional` never reads into a full buffer,
        // but a wrapper that depends on that is a wrapper that reports a closed
        // peer the first time somebody else uses it.
        let had_room = buf.remaining() > 0;
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && had_room
            && buf.filled().len() == before
            && !self.eof.is_cancelled()
        {
            self.eof.cancel();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WatchRemoteEof<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The plain case: the peer closes, and the token trips on the read that
    /// saw it.
    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn end_of_stream_trips_the_token() {
        let (near, mut far) = tokio::io::duplex(64);
        let eof = CancellationToken::new();
        let mut near = WatchRemoteEof::new(near, eof.clone());

        far.write_all(b"payload").await.expect("write");
        let mut got = [0_u8; 7];
        near.read_exact(&mut got).await.expect("read the payload");
        assert!(
            !eof.is_cancelled(),
            "a read that produced bytes is not an end-of-stream"
        );

        drop(far);
        let read = near.read(&mut got).await.expect("read after the close");
        assert_eq!(read, 0, "the peer is gone");
        assert!(
            eof.is_cancelled(),
            "the relay has to be able to see that the far end closed; without \
             this the flow holds its slot until `tcp_idle_timeout_s`, an hour"
        );
    }

    /// A read into a buffer with no room is not an end-of-stream, and must not
    /// be reported as one.
    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn a_zero_length_read_is_not_an_end_of_stream() {
        let (near, mut far) = tokio::io::duplex(64);
        let eof = CancellationToken::new();
        let mut near = WatchRemoteEof::new(near, eof.clone());

        far.write_all(b"still here").await.expect("write");
        let read = near.read(&mut []).await.expect("read into nothing");
        assert_eq!(read, 0, "there was nowhere to put a byte");
        assert!(
            !eof.is_cancelled(),
            "the far end is up and has data waiting; reporting it closed would \
             reclaim a live flow"
        );
    }
}
