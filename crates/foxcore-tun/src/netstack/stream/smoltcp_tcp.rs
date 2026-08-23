use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
use tokio_util::sync::PollSender;

use crate::netstack::packet::NetworkTuple;

const DEFAULT_READ_BUFFER_SIZE: usize = 16 * 1024;
const DEFAULT_WRITE_BUFFER_SIZE: u32 = 16 * 1024;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Fox-owned TCP buffer and final-state policy around smoltcp.
///
/// smoltcp owns retransmission. Every buffer below is charged before a SYN is
/// accepted; `handshake_timeout` bounds an unpublished reservation and
/// `two_msl` controls when the actor releases a completed flow slot.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub two_msl: Duration,
    pub handshake_timeout: Duration,
    pub max_unacked_bytes: u32,
    pub read_buffer_size: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            two_msl: Duration::from_secs(2),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_unacked_bytes: DEFAULT_WRITE_BUFFER_SIZE,
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
        }
    }
}

pub(crate) struct TcpControl {
    tuple: NetworkTuple,
    commands: mpsc::Sender<NetworkTuple>,
    scheduled: AtomicBool,
    reset_requested: AtomicBool,
    close_requested: AtomicBool,
    dropped: AtomicBool,
    closed: AtomicBool,
    queued_write_bytes: AtomicUsize,
    socket_read_bytes: AtomicUsize,
    application_read_bytes: AtomicUsize,
    flush_waker: Mutex<Option<Waker>>,
    shutdown_waker: Mutex<Option<Waker>>,
}

impl TcpControl {
    pub(crate) fn new(tuple: NetworkTuple, commands: mpsc::Sender<NetworkTuple>) -> Arc<Self> {
        Arc::new(Self {
            tuple,
            commands,
            scheduled: AtomicBool::new(false),
            reset_requested: AtomicBool::new(false),
            close_requested: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            queued_write_bytes: AtomicUsize::new(0),
            socket_read_bytes: AtomicUsize::new(0),
            application_read_bytes: AtomicUsize::new(0),
            flush_waker: Mutex::new(None),
            shutdown_waker: Mutex::new(None),
        })
    }

    pub(crate) fn schedule(&self) {
        if !self.scheduled.swap(true, Ordering::AcqRel)
            && self.commands.try_send(self.tuple).is_err()
        {
            self.dropped.store(true, Ordering::Release);
            self.closed.store(true, Ordering::Release);
            self.wake_waiters();
        }
    }

    pub(crate) fn begin_service(&self) {
        self.scheduled.store(false, Ordering::Release);
    }

    pub(crate) fn reset_requested(&self) -> bool {
        self.reset_requested.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn close_requested(&self) -> bool {
        self.close_requested.load(Ordering::Acquire)
    }

    pub(crate) fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Acquire)
    }

    pub(crate) fn add_queued_write_bytes(&self, bytes: usize) {
        self.queued_write_bytes.fetch_add(bytes, Ordering::AcqRel);
    }

    pub(crate) fn consume_queued_write_bytes(&self, bytes: usize) {
        let previous = self.queued_write_bytes.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
        if previous == bytes {
            self.flush_waker
                .lock()
                .take()
                .map(Waker::wake)
                .unwrap_or(());
        }
    }

    pub(crate) fn queued_write_bytes(&self) -> usize {
        self.queued_write_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn set_socket_read_bytes(&self, bytes: usize) {
        self.socket_read_bytes.store(bytes, Ordering::Release);
    }

    pub(crate) fn add_application_read_bytes(&self, bytes: usize) {
        self.application_read_bytes
            .fetch_add(bytes, Ordering::AcqRel);
    }

    fn consume_application_read_bytes(&self, bytes: usize) {
        let previous = self
            .application_read_bytes
            .fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.socket_read_bytes.store(0, Ordering::Release);
        self.wake_waiters();
    }

    fn wake_waiters(&self) {
        self.flush_waker
            .lock()
            .take()
            .map(Waker::wake)
            .unwrap_or(());
        self.shutdown_waker
            .lock()
            .take()
            .map(Waker::wake)
            .unwrap_or(());
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn buffered_bytes(&self) -> usize {
        self.socket_read_bytes
            .load(Ordering::Acquire)
            .saturating_add(self.application_read_bytes.load(Ordering::Acquire))
    }
}

/// The asynchronous side of one smoltcp socket.
///
/// Both application-facing channels hold one MTU-sized chunk. The smoltcp
/// buffers remain the TCP windows; the extra chunk is counted explicitly so a
/// reader that stops cannot silently double the advertised receive budget.
pub struct TcpFlow {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_current: Vec<u8>,
    read_offset: usize,
    write_tx: PollSender<Vec<u8>>,
    write_chunk_bytes: usize,
    control: Arc<TcpControl>,
}

impl std::fmt::Debug for TcpFlow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpFlow")
            .field("buffered_bytes", &self.buffered_bytes())
            .finish_non_exhaustive()
    }
}

impl TcpFlow {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        read_rx: mpsc::Receiver<Vec<u8>>,
        write_tx: mpsc::Sender<Vec<u8>>,
        write_chunk_bytes: usize,
        control: Arc<TcpControl>,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            read_rx,
            read_current: Vec::new(),
            read_offset: 0,
            write_tx: PollSender::new(write_tx),
            write_chunk_bytes: write_chunk_bytes.max(1),
            control,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn buffered_bytes(&self) -> usize {
        self.control.buffered_bytes()
    }

    pub fn reset(&mut self) {
        if !self.control.is_closed() {
            self.control.reset_requested.store(true, Ordering::Release);
            self.control.schedule();
        }
    }

    fn consume_current(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_offset >= self.read_current.len() || buf.remaining() == 0 {
            return false;
        }
        let length = buf
            .remaining()
            .min(self.read_current.len() - self.read_offset);
        buf.put_slice(&self.read_current[self.read_offset..self.read_offset + length]);
        self.read_offset += length;
        self.control.consume_application_read_bytes(length);
        if self.read_offset == self.read_current.len() {
            self.read_current.clear();
            self.read_offset = 0;
            self.control.schedule();
        }
        true
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.consume_current(buf) {
            return Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                self.read_current = bytes;
                self.read_offset = 0;
                let _ = self.consume_current(buf);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.control.is_closed() || self.control.dropped() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP connection closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let length = buf.len().min(self.write_chunk_bytes);
                let bytes = buf[..length].to_vec();
                self.control.add_queued_write_bytes(length);
                if self.write_tx.send_item(bytes).is_err() {
                    self.control.consume_queued_write_bytes(length);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TCP actor is gone",
                    )));
                }
                self.control.schedule();
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP actor is gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.queued_write_bytes() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.control.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP connection closed before queued bytes were accepted",
            )));
        }
        self.control.flush_waker.lock().replace(cx.waker().clone());
        if self.control.queued_write_bytes() == 0 {
            self.control.flush_waker.lock().take();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.is_closed() {
            return Poll::Ready(Ok(()));
        }
        self.control.close_requested.store(true, Ordering::Release);
        self.control
            .shutdown_waker
            .lock()
            .replace(cx.waker().clone());
        self.control.schedule();
        if self.control.is_closed() {
            self.control.shutdown_waker.lock().take();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        if !self.control.is_closed() {
            self.control.dropped.store(true, Ordering::Release);
            self.control.schedule();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    type StreamFixture = (
        TcpFlow,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
        Arc<TcpControl>,
        mpsc::Receiver<NetworkTuple>,
    );

    fn stream() -> StreamFixture {
        let tuple = NetworkTuple::new(
            "10.0.0.2:40000".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            true,
        );
        let (commands, command_rx) = mpsc::channel(1);
        let control = TcpControl::new(tuple, commands);
        let (read_tx, read_rx) = mpsc::channel(1);
        let (write_tx, write_rx) = mpsc::channel(1);
        (
            TcpFlow::new(
                tuple.src,
                tuple.dst,
                read_rx,
                write_tx,
                1400,
                control.clone(),
            ),
            read_tx,
            write_rx,
            control,
            command_rx,
        )
    }

    #[tokio::test]
    async fn one_application_chunk_is_counted_until_it_is_read() {
        let (mut stream, read_tx, _write_rx, control, _commands) = stream();
        control.add_application_read_bytes(4);
        read_tx.send(vec![1, 2, 3, 4]).await.unwrap();
        assert_eq!(stream.buffered_bytes(), 4);

        let mut first = [0_u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [1, 2]);
        assert_eq!(stream.buffered_bytes(), 2);

        let mut second = [0_u8; 2];
        stream.read_exact(&mut second).await.unwrap();
        assert_eq!(second, [3, 4]);
        assert_eq!(stream.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn write_backpressure_is_one_bounded_chunk() {
        let (mut stream, _read_tx, mut write_rx, control, _commands) = stream();
        let data = vec![7_u8; 4096];
        assert_eq!(stream.write(&data).await.unwrap(), 1400);
        assert_eq!(control.queued_write_bytes(), 1400);
        assert_eq!(write_rx.recv().await.unwrap().len(), 1400);
        control.consume_queued_write_bytes(1400);
        stream.flush().await.unwrap();
    }

    #[test]
    fn shutdown_waits_for_the_actor_to_close_the_socket() {
        let (mut stream, _read_tx, _write_rx, control, _commands) = stream();
        let mut shutdown = Box::pin(tokio::io::AsyncWriteExt::shutdown(&mut stream));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(shutdown.as_mut().poll(&mut cx), Poll::Pending));
        control.close();
        assert!(matches!(
            shutdown.as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn repeated_wakes_schedule_at_most_one_bounded_command() {
        let (_stream, _read_tx, _write_rx, control, mut commands) = stream();
        control.schedule();
        control.schedule();

        assert_eq!(commands.try_recv().unwrap(), control.tuple);
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
