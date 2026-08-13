//! One HTTP/2 connection per proxy, shared by every CONNECT stream on it.
//!
//! NaiveProxy is HTTP/2 CONNECT, and the whole point of HTTP/2 is that a
//! connection carries many streams. Opening a TCP connection, a TLS handshake
//! and an HTTP/2 preface for *each* flow threw that away: on a phone, a single
//! page load is dozens of flows, each paying a full round-trip stack before its
//! first byte — and each producing a fresh, identically-shaped ClientHello for
//! anyone counting them. The reference client multiplexes; so does this.
//!
//! What the pool has to get right:
//!
//! * **The peer's limit.** `SETTINGS_MAX_CONCURRENT_STREAMS` is the server's
//!   statement about how many streams it will accept. Exceeding it earns a
//!   `REFUSED_STREAM` per flow, so streams are counted here and a connection at
//!   its limit is passed over in favour of another (or a new one).
//! * **GOAWAY.** A server saying "no new streams" is not a server saying "your
//!   existing streams are dead". A connection that is going away is taken out of
//!   the pool so nothing new is put on it, while the streams already running
//!   finish on their own handles.
//! * **Concurrency.** The list of connections is behind a `std::sync::Mutex`
//!   that is never held across an `await` — every operation on it is a counter
//!   read or a `retain`. Connection *setup* is behind a separate async mutex, so
//!   twenty flows arriving at a cold pool open one connection between them
//!   instead of twenty; the pool is re-checked after that mutex is taken, which
//!   is what makes the nineteen others reuse the first one's work.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use foxcore_transport::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Streams to allow before the peer's `SETTINGS` frame has been seen.
///
/// RFC 9113 §6.5.2 makes the setting unlimited when absent, and taking that
/// literally would put every flow of a cold start on a connection the server may
/// be about to say it wants far fewer streams on.
const ASSUMED_MAX_STREAMS: usize = 16;

/// Ceiling on one connection regardless of what the peer advertises.
///
/// A server offering a very large limit is not a reason to funnel everything
/// through a single socket: one stalled connection would then be every flow.
const MAX_STREAMS_PER_CONNECTION: usize = 128;

/// An established connection, with the two facts the pool reads from its driver.
pub(crate) struct Established {
    sender: h2::client::SendRequest<Bytes>,
    limit: Arc<AtomicUsize>,
    retired: Arc<AtomicBool>,
}

/// Drive one HTTP/2 connection's I/O and publish what the pool needs from it.
///
/// Both published values live inside the `Connection`, which this task owns:
/// the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`, and the moment the connection
/// ends for any reason — GOAWAY, stream error, closed socket. Republishing on
/// every poll costs one relaxed store per wakeup and keeps both current without
/// a channel or a second task.
pub(crate) fn establish<T>(
    sender: h2::client::SendRequest<Bytes>,
    mut connection: h2::client::Connection<T, Bytes>,
) -> Established
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limit = Arc::new(AtomicUsize::new(ASSUMED_MAX_STREAMS));
    let retired = Arc::new(AtomicBool::new(false));
    let published = Arc::clone(&limit);
    let closed = Arc::clone(&retired);
    std::mem::drop(tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| {
            let polled = Pin::new(&mut connection).poll(context);
            published.store(
                connection
                    .max_concurrent_send_streams()
                    .clamp(1, MAX_STREAMS_PER_CONNECTION),
                Ordering::Relaxed,
            );
            polled
        })
        .await;
        closed.store(true, Ordering::Release);
    }));
    Established {
        sender,
        limit,
        retired,
    }
}

struct Session {
    sender: h2::client::SendRequest<Bytes>,
    limit: Arc<AtomicUsize>,
    in_flight: AtomicUsize,
    retired: Arc<AtomicBool>,
}

impl Established {
    /// A handle for opening streams on this connection.
    ///
    /// Production reaches a connection through a [`Lease`], which is what keeps
    /// the stream accounting honest; this is for the one-connection composition
    /// the tests drive over a pipe.
    #[cfg(test)]
    pub(crate) fn sender(&self) -> h2::client::SendRequest<Bytes> {
        self.sender.clone()
    }
}

impl Session {
    fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// Claim one of this connection's stream slots, if it has a free one.
    ///
    /// A compare-and-swap rather than a load and a store: two flows arriving
    /// together must not both read the last free slot and take it.
    fn try_lease(self: Arc<Self>) -> Option<Lease> {
        let limit = self.limit.load(Ordering::Relaxed).max(1);
        let mut current = self.in_flight.load(Ordering::Relaxed);
        loop {
            if current >= limit || self.is_retired() {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Lease { session: self }),
                Err(actual) => current = actual,
            }
        }
    }
}

/// One reserved stream slot on a pooled connection.
///
/// Held by the tunnel it was opened for, so the slot comes back exactly when the
/// stream is dropped and not before.
pub(crate) struct Lease {
    session: Arc<Session>,
}

impl Lease {
    pub(crate) fn sender(&self) -> h2::client::SendRequest<Bytes> {
        self.session.sender.clone()
    }

    /// Take this connection out of the pool.
    ///
    /// Used when a CONNECT on it failed at the HTTP/2 level, which means the
    /// connection lost a race with a GOAWAY or died under us. Streams already
    /// running on it are untouched: they hold their own stream handles, and the
    /// connection's driver task lives until the last of them is gone.
    pub(crate) fn retire(&self) {
        self.session.retired.store(true, Ordering::Release);
    }

    /// Bind the lease to the tunnel, so the slot is held for its lifetime.
    pub(crate) fn attach(self, inner: BoxStream) -> BoxStream {
        Box::new(LeasedStream {
            inner,
            _lease: self,
        })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.session.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A tunnel that keeps its connection's stream slot reserved while it lives.
struct LeasedStream {
    inner: BoxStream,
    _lease: Lease,
}

impl AsyncRead for LeasedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for LeasedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Every live connection to one NaiveProxy server.
#[derive(Default)]
pub(crate) struct H2Pool {
    live: Mutex<Vec<Arc<Session>>>,
    /// Held across connection setup only, so a burst of flows on a cold pool
    /// opens one connection rather than one each.
    connecting: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for H2Pool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("H2Pool")
            .field("connections", &self.connection_count())
            .finish()
    }
}

impl H2Pool {
    /// Reserve a stream slot, opening a connection with `connect` if no live one
    /// has room.
    pub(crate) async fn acquire<F, Fut, E>(&self, connect: F) -> Result<Lease, E>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Established, E>>,
    {
        if let Some(lease) = self.reserve() {
            return Ok(lease);
        }
        // Nothing usable. Serialise the setup, then look again: whoever got here
        // first may already have finished, and the second flow through should
        // use that connection rather than open a second one beside it.
        let _connecting = self.connecting.lock().await;
        if let Some(lease) = self.reserve() {
            return Ok(lease);
        }
        let session = Arc::new(Session::from(connect().await?));
        let lease = Arc::clone(&session)
            .try_lease()
            .expect("a connection this call just opened has a free stream slot");
        self.live().push(session);
        Ok(lease)
    }

    pub(crate) fn connection_count(&self) -> usize {
        self.live().len()
    }

    /// Drop connections that are going away and lease a slot on one that is not.
    fn reserve(&self) -> Option<Lease> {
        let mut live = self.live();
        live.retain(|session| !session.is_retired());
        live.iter()
            .find_map(|session| Arc::clone(session).try_lease())
    }

    /// The lock is only ever held for counter reads and a `retain`, never across
    /// an `await`; poisoning is treated as the empty statement it is, because
    /// nothing under it can panic and leave the list half-written.
    fn live(&self) -> std::sync::MutexGuard<'_, Vec<Arc<Session>>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl From<Established> for Session {
    fn from(established: Established) -> Self {
        Self {
            sender: established.sender,
            limit: established.limit,
            in_flight: AtomicUsize::new(0),
            retired: established.retired,
        }
    }
}
