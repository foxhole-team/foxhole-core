//! Bidirectional stream copying with pooled buffers.
//!
//! Every relay in this core is the same shape — two streams, copy until both
//! ends are done — and every one of them used to reach for
//! `tokio::io::copy_bidirectional`, which owns its buffers. That is two fresh,
//! zero-filled allocations per connection, and on the proxy path a connection
//! is a short-lived thing: a `simpleperf` profile of the bare SOCKS harness on
//! a Pixel 7 Pro put `allocate` + `deallocate_small` + `__memset_aarch64` at
//! 11.4 % of cycles, because 6547 connections in 28 seconds meant 838 MiB of
//! freshly zeroed memory that was never read before being written over.
//!
//! The second half of the same finding was the buffer *size*: tokio defaults to
//! 8 KiB where sing-box's `sing` library copies through 64 KiB, which charged
//! FoxCore eight times the syscalls per byte on an identical transfer. Size is
//! the caller's decision here — the LAN proxy, the onion splice and the TUN flow
//! engine have different memory budgets — so it is a property of the pool rather
//! than of this function.
//!
//! Two things this deliberately does *not* change, because the callers depend on
//! them:
//!
//! * **Semantics are tokio's.** An error in either direction ends the whole copy
//!   at once, each direction shuts the writer down when its reader reaches EOF,
//!   and the copy returns only when both directions are finished. The TUN flow
//!   engine reads its stall diagnosis out of that error
//!   (`foxcore-tun/src/backlog.rs`), and a version that joined both halves
//!   instead would hold a stalled flow open until the *other* direction also
//!   ended — which is exactly the reclaim bug the backlog guard exists to fix.
//! * **Buffers come back on cancellation.** A lease is an RAII guard, so the
//!   buffer is returned when the session ends, when it fails, and when the task
//!   is dropped mid-copy — which for a relay is the common case, not the rare
//!   one: the kill switch, a policy revocation and an idle reclaim all cancel a
//!   relay task while it is parked inside this function.

#![forbid(unsafe_code)]

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bounded free list of equally sized relay buffers.
///
/// The pool is a cache of *idle* buffers, not a limit on live ones: an empty
/// pool allocates, and a full pool drops what is handed back. So `max_idle`
/// bounds the memory a burst of connections leaves resident afterwards, and
/// nothing else — concurrency is bounded by the session limits the callers
/// already enforce.
///
/// Buffers are handed out at exactly `buffer_bytes`, which is why the size lives
/// here: a single process-wide pool of one size would either give the TUN engine
/// buffers four times larger than its backlog ceiling assumes, or give the LAN
/// proxy a size the phone's Wi-Fi peers do not need. Each caller owns a pool
/// sized and capped for its own budget, and states the arithmetic where it
/// declares it.
pub struct BufferPool {
    buffer_bytes: usize,
    max_idle: usize,
    idle: Mutex<Vec<Box<[u8]>>>,
}

impl BufferPool {
    /// A pool that hands out `buffer_bytes` buffers and keeps at most `max_idle`
    /// of them resident between uses.
    ///
    /// `const` so a listener can declare its pool as a `static` and never think
    /// about who owns it.
    pub const fn new(buffer_bytes: usize, max_idle: usize) -> Self {
        Self {
            buffer_bytes,
            max_idle,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Take one buffer, allocating only if the pool is empty.
    pub fn lease(&self) -> BufferLease<'_> {
        let buffer = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_else(|| vec![0_u8; self.buffer_bytes].into_boxed_slice());
        BufferLease {
            pool: self,
            buffer: Some(buffer),
        }
    }

    /// How many buffers are currently parked. Test observability only — a relay
    /// has no reason to ask.
    pub fn idle(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn give_back(&self, buffer: Box<[u8]>) {
        // A buffer of the wrong size can only come from a caller that shared a
        // lease between pools; dropping it is cheaper than reasoning about it,
        // and it cannot happen through this crate's own API.
        if buffer.len() != self.buffer_bytes {
            return;
        }
        // The poison branch matters here and not much anywhere else: this runs
        // in `Drop`, and a panic in `Drop` while another panic is unwinding
        // aborts the process. A relay whose peer happened to be holding this
        // lock when an unrelated task panicked must not be the thing that turns
        // one panic into a crash.
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < self.max_idle {
            idle.push(buffer);
        }
    }
}

/// One borrowed buffer. Returned to its pool on drop, including the drop that a
/// cancelled task performs.
pub struct BufferLease<'pool> {
    pool: &'pool BufferPool,
    /// `Option` only so `Drop` can take the buffer out; it is `Some` for the
    /// whole life of the lease.
    buffer: Option<Box<[u8]>>,
}

impl BufferLease<'_> {
    /// The bytes, for a caller that wants to copy through them directly.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut().expect("lease holds its buffer")
    }
}

impl Drop for BufferLease<'_> {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.give_back(buffer);
        }
    }
}

/// Copy in both directions until both are finished, through two pooled buffers.
///
/// Drop-in for `tokio::io::copy_bidirectional_with_sizes`, including the return
/// value (`(a → b, b → a)` byte counts) and the error behaviour; see this
/// module's header for what that means and why it is not negotiable.
pub async fn copy_bidirectional_pooled<A, B>(
    pool: &BufferPool,
    a: &mut A,
    b: &mut B,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut uplink = pool.lease();
    let mut downlink = pool.lease();
    let mut a_to_b = Transfer::default();
    let mut b_to_a = Transfer::default();

    poll_fn(|context| {
        let forward = a_to_b.poll(context, uplink.bytes_mut(), a, b)?;
        let backward = b_to_a.poll(context, downlink.bytes_mut(), b, a)?;
        // Both are polled before either is awaited on, so a direction that is
        // still running never starves the one that just finished.
        let forward = ready!(forward);
        let backward = ready!(backward);
        Poll::Ready(Ok((forward, backward)))
    })
    .await
}

/// One direction: copy until EOF, then shut the writer down, then stay done.
///
/// The shutdown is a state of its own rather than a step at the end of the copy
/// because `poll_shutdown` may return `Pending`, and a direction that treated a
/// pending shutdown as "finished" would hand the peer a half-open socket it
/// never learns about.
enum Transfer {
    Running(Copy),
    ShuttingDown(u64),
    Done(u64),
}

impl Default for Transfer {
    fn default() -> Self {
        Self::Running(Copy::default())
    }
}

impl Transfer {
    fn poll<R, W>(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            match self {
                Self::Running(copy) => {
                    let moved = ready!(copy.poll(
                        context,
                        buffer,
                        Pin::new(&mut *reader),
                        Pin::new(&mut *writer)
                    ))?;
                    *self = Self::ShuttingDown(moved);
                }
                Self::ShuttingDown(moved) => {
                    ready!(Pin::new(&mut *writer).poll_shutdown(context))?;
                    *self = Self::Done(*moved);
                }
                Self::Done(moved) => return Poll::Ready(Ok(*moved)),
            }
        }
    }
}

/// Where one direction is inside the borrowed buffer.
///
/// The buffer is not held here: it belongs to the lease, and passing it in per
/// poll is what lets the pool own the memory while this owns only the progress.
#[derive(Default)]
struct Copy {
    /// Next byte to write out.
    position: usize,
    /// One past the last byte read in.
    filled: usize,
    moved: u64,
    read_done: bool,
    /// Set by a write, cleared by a flush. Without it a writer that buffers
    /// internally can deadlock against a reader that is waiting for the bytes
    /// still sitting in that buffer.
    needs_flush: bool,
}

impl Copy {
    fn poll<R, W>(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            if self.position == self.filled && !self.read_done {
                self.position = 0;
                self.filled = 0;
                match self.fill(context, buffer, reader.as_mut()) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        if self.needs_flush {
                            ready!(writer.as_mut().poll_flush(context))?;
                            self.needs_flush = false;
                        }
                        return Poll::Pending;
                    }
                }
            }

            while self.position < self.filled {
                let written = match writer
                    .as_mut()
                    .poll_write(context, &buffer[self.position..self.filled])
                {
                    Poll::Pending => {
                        // The writer is full and we are about to yield anyway,
                        // so top the buffer up while there is nothing else to
                        // do — the next wakeup then has a full buffer to write
                        // instead of a syscall's worth.
                        if !self.read_done && self.filled < buffer.len() {
                            ready!(self.fill(context, buffer, reader.as_mut()))?;
                        }
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => result?,
                };
                if written == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "relay writer accepted zero bytes",
                    )));
                }
                self.position += written;
                self.moved += written as u64;
                self.needs_flush = true;
            }

            if self.position == self.filled && self.read_done {
                ready!(writer.as_mut().poll_flush(context))?;
                return Poll::Ready(Ok(self.moved));
            }
        }
    }

    /// Read on top of whatever is already in the buffer.
    ///
    /// Appending rather than overwriting is what makes the top-up above legal:
    /// the bytes between `position` and `filled` have not been written yet.
    fn fill<R>(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
        reader: Pin<&mut R>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
    {
        let mut read = ReadBuf::new(buffer);
        read.set_filled(self.filled);
        let result = reader.poll_read(context, &mut read);
        if let Poll::Ready(Ok(())) = result {
            let filled = read.filled().len();
            // A read that added nothing is end of stream. Comparing against the
            // previous mark rather than against zero is what makes that true
            // after a top-up as well.
            self.read_done = self.filled == filled;
            self.filled = filled;
        }
        result
    }
}

#[cfg(test)]
mod tests;
