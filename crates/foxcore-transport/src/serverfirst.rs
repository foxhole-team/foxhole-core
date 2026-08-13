//! Unblocking protocols whose request header rides on the first payload write.
//!
//! Trojan and Shadowsocks both put their authentication header and destination
//! address in front of the *first* application write, so that the opening
//! segment has no distinctive size. That is the right thing to do for a
//! client-first protocol, and a deadlock for every protocol where the server
//! speaks first — SSH, SMTP, IMAP, FTP, MySQL, IRC, and any TLS-wrapped variant
//! of those. The client waits for a banner, the proxy waits for a byte to
//! piggyback the header on, and neither ever moves.
//!
//! [`ServerFirstStream`] breaks the cycle at the only point where it is visible:
//! the application asking to *read*. A read on a stream that has never been
//! written issues a zero-length write, which every inner stream here turns into
//! "send the header now, carry no payload", and then flushes it. Nothing changes
//! for a client-first flow: the application's own first write drives the header
//! exactly as before, header and payload still leave in one piece, and the
//! zero-length write is never issued at all.
//!
//! # Why the priming is a state machine and not a `bool`
//!
//! A relay splits the stream and polls the two halves from two tasks. Both
//! halves can therefore reach the inner stream's connect state, and the inner
//! state machines this wraps — `ProxyClientStream` in the `shadowsocks` crate
//! and its Outline twin here — capture the caller's buffer while the connect
//! write is in flight and then report `Ok(buf.len())` for whatever buffer the
//! *next* call happens to bring. Two rules keep that from losing or duplicating
//! application bytes:
//!
//! 1. A write that has begun claims the header. [`Phase::Written`] is set before
//!    the inner stream is touched, so a concurrent read never starts a second,
//!    competing connect.
//! 2. A priming write that returned `Pending` must be finished by whoever polls
//!    next. A write arriving mid-priming completes the *zero-length* call first
//!    and only then submits its own bytes, so the payload can never be absorbed
//!    into a buffer the inner stream already believes it has written.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Neither the application nor this wrapper has touched the inner stream.
    Idle,
    /// A zero-length write was issued from [`ServerFirstStream::poll_read`] and
    /// has not completed. Any other poll has to finish it before doing its own
    /// work.
    Priming,
    /// The inner stream owns the header now: it has either been sent or been
    /// folded into an application write that is under way.
    Written,
}

/// Wraps an outbound stream that emits its request header on the first write.
///
/// See the module documentation: the header is flushed on the first read
/// attempt, so a server-first destination is reachable without giving up the
/// piggybacked header that a client-first destination gets.
pub struct ServerFirstStream<S> {
    inner: S,
    phase: Phase,
}

impl<S> ServerFirstStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            phase: Phase::Idle,
        }
    }
}

impl<S> ServerFirstStream<S>
where
    S: AsyncWrite + Unpin,
{
    /// Drive the zero-length write that makes the inner stream emit its header.
    ///
    /// `Phase::Priming` is set *before* the first inner poll, so a write that
    /// arrives while this is pending knows it has to finish this call rather
    /// than start one of its own.
    fn poll_prime(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.phase = Phase::Priming;
        ready!(Pin::new(&mut self.inner).poll_write(context, &[]))?;
        // The header is inside the inner stream's buffers at this point; on a
        // TLS carrier it is a record that has not been handed to the socket.
        // Without the flush the read still waits for something the peer cannot
        // send, which is the deadlock this type exists to remove.
        ready!(Pin::new(&mut self.inner).poll_flush(context))?;
        self.phase = Phase::Written;
        Poll::Ready(Ok(()))
    }

    /// Finish a priming write that returned `Pending`, if there is one.
    fn poll_finish_priming(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.phase == Phase::Priming {
            ready!(Pin::new(&mut self.inner).poll_write(context, &[]))?;
        }
        self.phase = Phase::Written;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for ServerFirstStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.phase != Phase::Written {
            ready!(this.poll_prime(context))?;
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl<S> AsyncWrite for ServerFirstStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_finish_priming(context))?;
        Pin::new(&mut this.inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_finish_priming(context))?;
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_finish_priming(context))?;
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stand-in for `ProxyClientStream`: it emits `HEAD` in front of whatever
    /// the first write brings, including a write that brings nothing.
    struct HeaderOnFirstWrite {
        inner: tokio::io::DuplexStream,
        sent: bool,
        writes: Arc<AtomicUsize>,
    }

    impl AsyncRead for HeaderOnFirstWrite {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for HeaderOnFirstWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            if !self.sent {
                let mut framed = b"HEAD".to_vec();
                framed.extend_from_slice(buffer);
                ready!(Pin::new(&mut self.inner).poll_write(context, &framed))?;
                self.sent = true;
                return Poll::Ready(Ok(buffer.len()));
            }
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    fn pair() -> (
        ServerFirstStream<HeaderOnFirstWrite>,
        tokio::io::DuplexStream,
        Arc<AtomicUsize>,
    ) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let writes = Arc::new(AtomicUsize::new(0));
        let stream = ServerFirstStream::new(HeaderOnFirstWrite {
            inner: client,
            sent: false,
            writes: writes.clone(),
        });
        (stream, server, writes)
    }

    #[tokio::test]
    async fn a_read_puts_the_header_on_the_wire_and_the_banner_comes_back() {
        let (mut stream, mut server, _) = pair();
        let peer = tokio::spawn(async move {
            let mut head = [0_u8; 4];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, b"HEAD");
            server.write_all(b"220 ready").await.unwrap();
            server
        });

        let mut banner = [0_u8; 9];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"220 ready");
        peer.await.unwrap();
    }

    /// The piggyback is the point of the deferred header, so a client that
    /// writes first must still put header and payload on the wire together.
    #[tokio::test]
    async fn a_client_that_writes_first_still_sends_one_combined_opening_write() {
        let (mut stream, mut server, writes) = pair();
        stream.write_all(b"EHLO").await.unwrap();
        stream.flush().await.unwrap();

        let mut opening = [0_u8; 8];
        server.read_exact(&mut opening).await.unwrap();
        assert_eq!(&opening, b"HEADEHLO");
        assert_eq!(
            writes.load(Ordering::Relaxed),
            1,
            "no empty priming write may be issued once the application has written"
        );
    }

    /// Reads after the header is out must not keep poking the writer.
    #[tokio::test]
    async fn the_header_is_primed_exactly_once() {
        let (mut stream, mut server, writes) = pair();
        let peer = tokio::spawn(async move {
            let mut head = [0_u8; 4];
            server.read_exact(&mut head).await.unwrap();
            server.write_all(b"ab").await.unwrap();
            server.write_all(b"cd").await.unwrap();
            server
        });
        let mut first = [0_u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        let mut second = [0_u8; 2];
        stream.read_exact(&mut second).await.unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(&second, b"cd");
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        peer.await.unwrap();
    }
}
