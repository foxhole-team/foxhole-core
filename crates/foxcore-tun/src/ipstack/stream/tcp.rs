use super::seqnum::SeqNum;
use crate::ipstack::redacted;
use crate::ipstack::{
    PacketReceiver, PacketSender, TTL,
    error::IpStackError,
    packet::{
        IpHeader, NetworkPacket, NetworkTuple, TransportHeader,
        tcp_flags::{ACK, FIN, PSH, RST, SYN},
        tcp_header_flags, tcp_header_fmt,
    },
    stream::tcb::{
        MAX_COUNT_FOR_DUP_ACK, MAX_RETRANSMIT_COUNT, MAX_UNACK, PacketType, READ_BUFFER_SIZE, RTO,
        Tcb, TcpState,
    },
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, TcpHeader, TcpOptionElement};
use parking_lot::Mutex;
use std::{
    io::ErrorKind::{BrokenPipe, ConnectionRefused, InvalidInput, UnexpectedEof},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// 2 * MSL (Maximum Segment Lifetime) is the maximum time a TCP connection can be in the TIME_WAIT state.
const TWO_MSL: Duration = Duration::from_secs(2);

const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const LAST_ACK_MAX_RETRIES: usize = 3;
const LAST_ACK_TIMEOUT: Duration = Duration::from_millis(500);

/// TCP configuration
///
/// # The session timeout that is not here
///
/// Upstream had a `timeout` field, sixty seconds by default, armed and checked
/// inside [`IpStackTcpStream::poll_read`]. It is gone, and this is the one
/// deletion in this fork that is a bug fix rather than a design change.
///
/// The original timer was not the safety net it looked like: a relay whose far
/// end stops accepting is parked in its *write*
/// direction, `poll_read` is not called, and the timer is never re-armed. What
/// the device found is the other half, and it is worse: on a flow that *is*
/// being read — every ordinary flow — the timer is armed on each poll and
/// therefore fires at sixty seconds of silence, and the stack answers its own
/// question with an RST. A push channel whose only liveness is a TCP keepalive
/// never reaches `poll_read` at all, because the stack answers keepalives
/// itself, so sixty seconds is exactly how long a messenger's connection
/// through this core survived. The reset arrived as `ErrorKind::TimedOut`,
/// which `flow.rs::is_ordinary_end` counts as a normal end, so
/// `flow_idle_timeouts` stayed at zero and nothing anywhere named it.
///
/// So the timer fired only where it must not and never where it was wanted.
/// What replaces it is what was already there: every session's lifetime is
/// bounded by the [`IpStackTcpStream`] the engine owns, and the engine's own
/// TCP idle window — `RuntimeConfig::tcp_idle_timeout_s`, an hour by default —
/// measures bytes in either direction, counts what it closes as
/// `flow_idle_timeouts`, and closes towards the application with a FIN. One
/// timeout, one counter, one configurable window.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// Maximum number of retries for sending the last ACK in the LAST_ACK state. Default is 3.
    pub last_ack_max_retries: usize,
    /// Timeout for the last ACK in the LAST_ACK state. Default is 500ms.
    pub last_ack_timeout: Duration,
    /// Timeout for the CLOSE_WAIT state. Default is 5 seconds.
    pub close_wait_timeout: Duration,
    /// Timeout for the TIME_WAIT state. Default is 2 seconds.
    pub two_msl: Duration,
    /// Maximum number of unacknowledged bytes allowed in the send buffer.
    pub max_unacked_bytes: u32,
    /// Size of the read buffer for incoming data.
    pub read_buffer_size: usize,
    /// Maximum number of duplicate ACKs before triggering fast retransmission.
    pub max_count_for_dup_ack: usize,
    /// Retransmission timeout duration.
    pub rto: std::time::Duration,
    /// Maximum number of retransmissions before giving up.
    pub max_retransmit_count: usize,
    /// TCP options
    pub options: Option<Vec<TcpOptions>>,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum TcpOptions {
    /// Maximum segment size (MSS) for TCP connections.
    MaximumSegmentSize(u16),
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            last_ack_max_retries: LAST_ACK_MAX_RETRIES,
            last_ack_timeout: LAST_ACK_TIMEOUT,
            close_wait_timeout: CLOSE_WAIT_TIMEOUT,
            two_msl: TWO_MSL,
            max_unacked_bytes: MAX_UNACK,
            read_buffer_size: READ_BUFFER_SIZE,
            max_count_for_dup_ack: MAX_COUNT_FOR_DUP_ACK,
            rto: RTO,
            max_retransmit_count: MAX_RETRANSMIT_COUNT,
            options: Default::default(),
        }
    }
}

#[derive(Debug)]
enum Shutdown {
    None,
    Pending(Waker),
    Ready,
}

impl Shutdown {
    fn pending(&mut self, w: Waker) {
        *self = Shutdown::Pending(w);
    }
    fn ready(&mut self) {
        if let Shutdown::Pending(w) = self {
            w.wake_by_ref();
        }
        *self = Shutdown::Ready;
    }

    // Just for comparison purpose
    fn fake_clone(&self) -> Shutdown {
        match self {
            Shutdown::None => Shutdown::None,
            Shutdown::Pending(_) => Shutdown::Pending(Waker::noop().clone()),
            Shutdown::Ready => Shutdown::Ready,
        }
    }
}

impl std::fmt::Display for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shutdown::None => write!(f, "None"),
            Shutdown::Pending(_) => write!(f, "Pending"),
            Shutdown::Ready => write!(f, "Ready"),
        }
    }
}

static SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

type TcbPtr = Arc<Mutex<Tcb>>;

/// A TCP stream in the IP stack.
///
/// This type represents a TCP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. It handles TCP state management, flow control,
/// and retransmission automatically.
///
#[derive(Debug)]
pub struct IpStackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: Option<PacketReceiver>,
    up_packet_sender: PacketSender,
    tcb: TcbPtr,
    shutdown: Arc<Mutex<Shutdown>>,
    write_notify: Arc<Mutex<Option<Waker>>>,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    data_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    read_notify: Arc<Mutex<Option<Waker>>>,
    task_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    exit_notifier: Option<tokio::sync::mpsc::Sender<()>>,
    temp_read_buffer: Vec<u8>,
    config: Arc<TcpConfig>,
}

impl IpStackTcpStream {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp: TcpHeader,
        up_packet_sender: PacketSender,
        mtu: u16,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
        config: Arc<TcpConfig>,
    ) -> Result<IpStackTcpStream, IpStackError> {
        let mut tcb = Tcb::new(
            SeqNum(tcp.sequence_number),
            mtu,
            config.max_unacked_bytes,
            config.read_buffer_size,
            config.max_count_for_dup_ack,
            config.rto,
            config.max_retransmit_count,
        );
        let tuple = NetworkTuple::new(src_addr, dst_addr, true);
        if !tcp.syn {
            if !tcp.rst
                && let Err(err) = write_packet_to_device(
                    &up_packet_sender,
                    tuple,
                    &mut tcb,
                    None,
                    ACK | RST,
                    None,
                    None,
                )
            {
                log::warn!("Error sending RST/ACK packet: {err}");
            }
            let info = format!("Invalid TCP packet: {tuple} {}", tcp_header_fmt(&tcp));
            return Err(IpStackError::IoError(std::io::Error::new(
                ConnectionRefused,
                info,
            )));
        }

        let (stream_sender, stream_receiver) =
            tokio::sync::mpsc::unbounded_channel::<NetworkPacket>();
        let (data_tx, data_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        let mut stream = IpStackTcpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver: Some(stream_receiver),
            up_packet_sender,
            tcb: Arc::new(Mutex::new(tcb.clone())),
            shutdown: Arc::new(Mutex::new(Shutdown::None)),
            write_notify: Arc::new(Mutex::new(None)),
            destroy_messenger,
            data_tx,
            data_rx,
            read_notify: Arc::new(Mutex::new(None)),
            task_handle: None,
            exit_notifier: None,
            temp_read_buffer: Vec::new(),
            config,
        };

        let sessions = SESSION_COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .saturating_add(1);
        let (seq, ack, state) = { (tcb.get_seq().0, tcb.get_ack().0, tcb.get_state()) };
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::debug!("{tuple} {state:?}: {l_info} session begins, total TCP sessions: {sessions}");

        stream.spawn_tasks()?;
        Ok(stream)
    }

    pub(crate) fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple::new(self.src_addr, self.dst_addr, true)
    }

    /// Returns the local socket address of the TCP connection.
    ///
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the TCP connection.
    ///
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    /// Bytes this flow is holding for a reader that has not taken them.
    ///
    /// The whole of it: segments still out of order, segments already
    /// sequenced and queued towards `poll_read`, and the tail of a segment too
    /// large for the last caller's buffer. This is the quantity the advertised
    /// window is the complement of, and the one a memory measurement has to be
    /// able to ask about — bounded by `read_buffer_size` plus at most the one
    /// segment that was in flight when the window closed.
    pub fn buffered_bytes(&self) -> usize {
        let tcb = self.tcb.lock();
        tcb.get_unordered_packets_total_len() + tcb.get_unread_len() + self.temp_read_buffer.len()
    }

    /// Refuse this session outright, the way a closed port refuses.
    ///
    /// The graceful answer is `FlowEngine::close_towards_app`, and every path
    /// that *decided something* about a flow uses it: unattributable, blocked
    /// by policy, undiallable. Those are answers, and a FIN is what an answer
    /// looks like.
    ///
    /// This is the other case, and it is not an answer at all — the core has no
    /// slot and will never look at the flow. A FIN there would be a lie in two
    /// directions: to the application, whose `connect()` returns successfully
    /// and whose first `read` returns end-of-stream, so a browser reports an
    /// empty reply rather than a refusal; and to this process, because a close
    /// is a handshake and the refused flow would hold a task for up to
    /// `CLIENT_CLOSE_TIMEOUT` waiting for an ACK it is not owed. An RST makes
    /// `connect()` fail with `ECONNREFUSED` at once, which is what "we are
    /// full" means, and costs one packet.
    ///
    /// `<SEQ=SND.NXT><CTL=RST,ACK>`: the sequence number the peer is expecting
    /// next, so the reset is inside its receive window and survives the RFC
    /// 5961 §3.2 check that exists to make blind resets hard. The ACK bit and
    /// the acknowledgement number are set for the same reason Linux sets them
    /// on an active reset — a bare RST from a synchronized connection is the
    /// shape a middlebox is most willing to discard.
    ///
    /// Idempotent, and silent on a session that has already finished: the
    /// engine may reset a flow whose peer reset it first.
    pub fn reset(&mut self) {
        let network_tuple = self.network_tuple();
        let mut tcb = self.tcb.lock();
        if tcb.get_state() == TcpState::Closed {
            return;
        }
        if let Err(error) = write_packet_to_device(
            &self.up_packet_sender,
            network_tuple,
            &mut tcb,
            None,
            ACK | RST,
            None,
            None,
        ) {
            log::warn!("{} reset not sent: {error}", redacted(&network_tuple));
        }
        tcb.change_state(TcpState::Closed);
        drop(tcb);
        // The session task is parked on its packet channel and would otherwise
        // only notice the state change when the peer sent something. `Drop`
        // signals it, so waking it here would be redundant — but the *reader*
        // and the *writer* may be parked on this stream inside the engine, and
        // nothing else will wake them now that the state is Closed.
        self.read_notify
            .lock()
            .take()
            .map(|waker| waker.wake())
            .unwrap_or(());
        self.write_notify
            .lock()
            .take()
            .map(|waker| waker.wake())
            .unwrap_or(());
        self.shutdown.lock().ready();
    }
}

/// Answer a segment for a connection that does not exist and will not be
/// opened.
///
/// The other reset in this file, and the one with no state behind it:
/// [`IpStackTcpStream::reset`] ends a session that exists, this refuses one
/// before any exists. It is what the stack owes a SYN it has no room to accept
/// — the alternative is silence, and silence costs the peer its whole SYN
/// retransmission schedule (Linux: 1, 3, 7, 15, 31 s before `ETIMEDOUT`)
/// instead of one round trip.
///
/// RFC 9293 §3.10.7.1, the CLOSED case, both arms:
///
/// * a segment carrying ACK is answered `<SEQ=SEG.ACK><CTL=RST>`;
/// * one without is answered `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`,
///   where SEG.LEN counts the SYN and the FIN as one byte each.
///
/// A reset is never sent in reply to a reset, which is the rule that keeps two
/// full stacks from resetting each other forever.
///
/// Allocates nothing beyond the packet itself and touches no table: a flood of
/// connection attempts against a full stack has to cost a bounded amount of
/// work per packet, or the refusal is the denial of service.
pub(crate) fn refuse_with_reset(
    up_packet_sender: &PacketSender,
    local: SocketAddr,
    peer: SocketAddr,
    header: &TcpHeader,
    payload_len: usize,
) -> std::io::Result<()> {
    if header.rst {
        return Ok(());
    }
    let (seq, ack, flags) = if header.ack {
        (header.acknowledgment_number, 0, RST)
    } else {
        // Saturating rather than `as`: the length comes off a packet an
        // untrusted peer sent, and while a tun read cannot produce more than an
        // MTU, nothing in *this* function's signature says so. The worst a
        // saturated value can do is name an acknowledgement the peer discards.
        let consumed = u32::try_from(payload_len)
            .unwrap_or(u32::MAX)
            .saturating_add(u32::from(header.syn))
            .saturating_add(u32::from(header.fin));
        (0, header.sequence_number.wrapping_add(consumed), ACK | RST)
    };
    // A reset carries no data and offers no window, so there is no receive
    // buffer to describe and nothing for `calculate_payload_max_len` to clamp.
    let packet = create_raw_packet(
        local,
        peer,
        |_, _| 0,
        flags,
        TTL,
        seq,
        ack,
        0,
        Vec::new(),
        None,
    )?;
    up_packet_sender
        .send(packet)
        .map_err(|e| std::io::Error::new(UnexpectedEof, e))?;
    Ok(())
}

impl IpStackTcpStream {
    /// Give the window back the space a caller just took, and tell the peer if
    /// that reopened a window it believes is shut.
    ///
    /// This is the half of backpressure that is easy to forget: closing the
    /// window is what stops a sender, and *this* is what starts it again. With
    /// only the first half a flow whose reader caught up would sit until the
    /// peer's persist timer fired, which on Linux backs off to a minute.
    ///
    /// Called on both `poll_read` paths, because both hand bytes to a caller —
    /// the one that dequeues a segment and the one that drains the remainder of
    /// a segment too big for the caller's buffer. Counting only the first would
    /// free the window for bytes still sitting in `temp_read_buffer`.
    fn release_read_window(&mut self, taken: usize) -> std::io::Result<()> {
        if taken == 0 {
            return Ok(());
        }
        let network_tuple = self.network_tuple();
        let mut tcb = self.tcb.lock();
        tcb.note_consumed(taken);
        if tcb.get_state() != TcpState::Closed && tcb.window_update_due() {
            write_packet_to_device(
                &self.up_packet_sender,
                network_tuple,
                &mut tcb,
                None,
                ACK,
                None,
                None,
            )?;
        }
        Ok(())
    }
}

impl AsyncRead for IpStackTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // if there is data in the temp buffer, read it first
        if !self.temp_read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.temp_read_buffer.len());
            buf.put_slice(&self.temp_read_buffer[..len]);
            self.temp_read_buffer.drain(..len); // remove the read data from the temp buffer
            self.release_read_window(len)?;
            return Poll::Ready(Ok(()));
        }

        let state = self.tcb.lock().get_state();
        if state == TcpState::Closed {
            self.shutdown.lock().ready();
            self.write_notify
                .lock()
                .take()
                .map(|w| w.wake_by_ref())
                .unwrap_or(());
            return Poll::Ready(Ok(()));
        }

        // No session timeout is checked here. There used to be one, sixty
        // seconds, and it killed live connections rather than dead ones — see
        // [`TcpConfig`].

        // read data from channel
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let capacity = buf.remaining();
                let taken = if capacity >= data.len() {
                    buf.put_slice(&data);
                    data.len()
                } else {
                    // if `buf` is not enough, put the remaining data into the temp buffer
                    buf.put_slice(&data[..capacity]);
                    self.temp_read_buffer.extend_from_slice(&data[capacity..]);
                    // Only what the caller actually got. The tail is still held
                    // by this stream, so it still occupies the window.
                    capacity
                };
                self.release_read_window(taken)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => {
                self.read_notify.lock().replace(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for IpStackTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let nt = self.network_tuple();

        let mut tcb = self.tcb.lock();
        let state = tcb.get_state();
        let send_window = tcb.get_send_window();
        let is_full = tcb.is_send_buffer_full();

        if state == TcpState::Closed {
            self.shutdown.lock().ready();
            self.read_notify
                .lock()
                .take()
                .map(|w| w.wake_by_ref())
                .unwrap_or(());
            return Poll::Ready(Err(std::io::Error::new(
                BrokenPipe,
                "TCP connection closed",
            )));
        }

        if send_window == 0 || is_full {
            self.write_notify.lock().replace(cx.waker().clone());
            let info = format!("current send window: {send_window}, send buffer full: {is_full}");
            log::trace!(
                "{nt} {state:?}: [poll_write] {info}, waiting for the other side to send ACK..."
            );
            return Poll::Pending;
        }

        let sender = &self.up_packet_sender;
        let payload_len = write_packet_to_device(
            sender,
            nt,
            &mut tcb,
            None,
            ACK | PSH,
            None,
            Some(buf.to_vec()),
        )?;
        tcb.add_inflight_packet(buf[..payload_len].to_vec())?;

        // Per `poll_write`; the allocation used to happen whether or not trace
        // was on.
        if log::log_enabled!(log::Level::Trace) {
            let (state, seq, ack) = (tcb.get_state(), tcb.get_seq(), tcb.get_ack());
            let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
            log::trace!(
                "{nt} {state:?}: [poll_write] {l_info} upstream data written to device, len = {payload_len}"
            );
        }

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let shutdown = { self.shutdown.lock().fake_clone() };
        let (nt, state, seq, is_ready) = {
            let tcb = self.tcb.lock();
            let is_ready = tcb.get_inflight_packets_total_len() == 0;
            (
                self.network_tuple(),
                tcb.get_state(),
                tcb.get_seq(),
                is_ready,
            )
        };
        log::trace!(
            "{nt} {state:?}: [poll_shutdown] seq = {seq}, ready = {is_ready}, shutdown {shutdown}",
        );
        if state == TcpState::Closed {
            return Poll::Ready(Ok(()));
        }
        match shutdown {
            Shutdown::None => {
                if is_ready && state == TcpState::Established {
                    let mut tcb = self.tcb.lock();
                    send_fin_n_change_state_to_fin_wait1(
                        "[poll_shutdown]",
                        nt,
                        &self.up_packet_sender,
                        &mut tcb,
                    )?;
                }
                self.shutdown.lock().pending(cx.waker().clone());
                Poll::Pending
            }
            Shutdown::Pending(_) => {
                if is_ready && state == TcpState::Established {
                    let mut tcb = self.tcb.lock();
                    send_fin_n_change_state_to_fin_wait1(
                        "[poll_shutdown]",
                        nt,
                        &self.up_packet_sender,
                        &mut tcb,
                    )?;
                }
                Poll::Pending
            }
            Shutdown::Ready => Poll::Ready(Ok(())),
        }
    }
}

fn send_fin_n_change_state_to_fin_wait1(
    hint: &str,
    nt: NetworkTuple,
    sender: &PacketSender,
    tcb: &mut Tcb,
) -> std::io::Result<()> {
    let state = tcb.get_state();
    if !(tcb.get_inflight_packets_total_len() == 0 && state == TcpState::Established) {
        log::debug!(
            "{nt} {state:?}: {hint} session is not in a valid state to send FIN, skipping..."
        );
        return Ok(());
    }

    log::debug!("{nt} {state:?}: {hint} actively send a farewell packet to the other side...");
    write_packet_to_device(sender, nt, tcb, None, ACK | FIN, None, None)?;
    tcb.increase_seq();
    tcb.change_state(TcpState::FinWait1);
    let state = tcb.get_state();
    log::debug!("{nt} {state:?}: {hint} now in {state:?} state");

    Ok(())
}

impl Drop for IpStackTcpStream {
    fn drop(&mut self) {
        let (nt, state) = (self.network_tuple(), self.tcb.lock().get_state());
        log::trace!("{nt} {state:?}: [drop] session dropping, ========================= ");
        if let Some(task_handle) = self.task_handle.take() {
            if !task_handle.is_finished() {
                // `try_current`, not `current`. `current` panics when there is no
                // runtime on this thread, and this is a `Drop`: a panic here
                // during unwinding is a double panic, which is an abort of the
                // whole process — and `catch_unwind` at the JNI boundary cannot
                // catch an abort. `IpStack::drop` drops the accept queue, which
                // still holds un-accepted `IpStackStream::Tcp` values, so the
                // no-runtime case is reachable rather than theoretical.
                //
                // Without a runtime there is nothing to wait on anyway: the
                // task's own runtime is gone, so the handle is abandoned, which
                // is what dropping it already means.
                //
                // The flavor is checked for the same reason: `block_in_place`
                // itself panics on a current-thread runtime, which is what the
                // tests build.
                match tokio::runtime::Handle::try_current() {
                    Ok(handle)
                        if handle.runtime_flavor()
                            == tokio::runtime::RuntimeFlavor::MultiThread =>
                    {
                        if let Some(notifier) = self.exit_notifier.take() {
                            _ = tokio::task::block_in_place(|| handle.block_on(notifier.send(())));
                        }
                        // synchronously wait for the task to finish
                        _ = tokio::task::block_in_place(|| handle.block_on(task_handle));
                    }
                    Ok(_) => {
                        // A current-thread runtime cannot block here without
                        // deadlocking on itself. Tell the task to stop and let
                        // it; dropping the handle detaches rather than cancels.
                        if let Some(notifier) = self.exit_notifier.take() {
                            _ = notifier.try_send(());
                        }
                        log::trace!("{nt} {state:?}: [drop] current-thread runtime, not blocking");
                    }
                    Err(_) => {
                        log::trace!(
                            "{nt} {state:?}: [drop] no runtime on this thread, not waiting"
                        );
                    }
                }
            } else {
                log::trace!(
                    "{nt} {state:?}: [drop] task already finished, no need to wait exiting"
                );
            }
        }
        let sessions = SESSION_COUNTER
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            .saturating_sub(1);
        log::debug!("{nt} {state:?}: [drop] session dropped, total TCP sessions: {sessions}");
    }
}

impl IpStackTcpStream {
    fn spawn_tasks(&mut self) -> std::io::Result<()> {
        let network_tuple = self.network_tuple();

        // task: data receiving and processing
        let tcb = self.tcb.clone();
        let stream_receiver = self.stream_receiver.take().ok_or_else(|| {
            std::io::Error::new(InvalidInput, "TCP stream receive task was already started")
        })?;
        let up_packet_sender = self.up_packet_sender.clone();
        let shutdown = self.shutdown.clone();
        let write_notify = self.write_notify.clone();
        let read_notify = self.read_notify.clone();
        // Kept for after the loop. A session that has ended has to wake
        // whoever was waiting on it, and until this fork it woke only
        // `shutdown`: a reader parked in `poll_read` when the peer's FIN
        // arrived was never polled again, so the end of the stream reached it
        // as a hang rather than as `Ok(0)`. Nothing in the loop wakes it on the
        // way out either — the exit paths break out of the `match` and out of
        // the loop without touching a waker.
        let closing_read_notify = self.read_notify.clone();
        let closing_write_notify = self.write_notify.clone();
        let data_tx = self.data_tx.clone();
        let destroy_messenger = self.destroy_messenger.take();

        let (exit_task_notifier, exit_monitor) = tokio::sync::mpsc::channel::<()>(10);
        let exit_notifier = exit_task_notifier.clone();
        let config = self.config.clone();
        self.exit_notifier = Some(exit_task_notifier);

        let task_handle = tokio::spawn(async move {
            let v = tcp_main_logic_loop(
                tcb,
                config,
                stream_receiver,
                up_packet_sender,
                exit_notifier,
                network_tuple,
                write_notify,
                read_notify,
                data_tx,
                exit_monitor,
            )
            .await;
            if let Err(e) = &v {
                log::warn!("{} task error: {e}", redacted(&network_tuple));
            }
            _ = destroy_messenger.map(|m| m.send(())).unwrap_or(Ok(()));
            log::trace!("{network_tuple} task completed, destroy messenger sent successfully");
            closing_read_notify
                .lock()
                .take()
                .map(|waker| waker.wake())
                .unwrap_or(());
            closing_write_notify
                .lock()
                .take()
                .map(|waker| waker.wake())
                .unwrap_or(());
            shutdown.lock().ready();
            log::trace!("{network_tuple} shutdown ready ==========");
            v
        });
        self.task_handle = Some(task_handle);
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_main_logic_loop(
    tcb: TcbPtr,
    config: Arc<TcpConfig>,
    mut stream_receiver: PacketReceiver,
    up_packet_sender: PacketSender,
    exit_notifier: tokio::sync::mpsc::Sender<()>,
    network_tuple: NetworkTuple,
    write_notify: Arc<Mutex<Option<Waker>>>,
    read_notify: Arc<Mutex<Option<Waker>>>,
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    mut exit_monitor: tokio::sync::mpsc::Receiver<()>,
) -> std::io::Result<()> {
    {
        let mut tcb = tcb.lock();

        let state = tcb.get_state();
        if state != TcpState::Listen {
            log::warn!(
                "{} {state:?}: invalid TCP state, not in Listen",
                redacted(&network_tuple)
            );
            return Ok::<(), std::io::Error>(());
        }

        tcb.increase_ack();
        let (seq, ack) = (tcb.get_seq().0, tcb.get_ack().0);
        let l_info = format!("local {{ seq: {seq}, ack: {ack} }}");
        log::trace!("{network_tuple} {state:?}: {l_info} session begins");
        write_packet_to_device(
            &up_packet_sender,
            network_tuple,
            &mut tcb,
            config.options.as_ref(),
            ACK | SYN,
            None,
            None,
        )?;
        tcb.increase_seq();
        tcb.change_state(TcpState::SynReceived);
        let state = tcb.get_state();
        log::trace!("{network_tuple} {state:?}: session now in {state:?} state");
    }

    let tcb_clone = tcb.clone();

    async fn task_wait_to_close(
        tcb: TcbPtr,
        exit_notifier: tokio::sync::mpsc::Sender<()>,
        nt: NetworkTuple,
        two_msl: Duration,
    ) {
        tokio::time::sleep(two_msl).await;
        {
            let mut tcb = tcb.lock();
            tcb.change_state(TcpState::Closed);
            let state = tcb.get_state();
            log::debug!("{nt} {state:?}: [task_wait_to_close] session closed after {two_msl:?}");
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    async fn task_last_ack(
        tcb: TcbPtr,
        exit_notifier: tokio::sync::mpsc::Sender<()>,
        nt: NetworkTuple,
        pkt_sdr: PacketSender,
        last_ack_timeout: Duration,
        last_ack_max_retries: usize,
    ) {
        let hint = "[task_last_ack]";
        for idx in 1..=last_ack_max_retries {
            let state = { tcb.lock().get_state() };
            if state == TcpState::Closed {
                log::debug!("{nt} {state:?}: {hint} session closed, exiting 1...");
                return;
            }

            tokio::time::sleep(last_ack_timeout).await;

            {
                let mut tcb = tcb.lock();
                let state = tcb.get_state();
                if state == TcpState::Closed {
                    log::debug!("{nt} {state:?}: {hint} session closed, exiting 2...");
                    return;
                }
                log::debug!(
                    "{nt} {state:?}: {hint} timer expired, resending ACK|FIN (retry {idx}/{last_ack_max_retries})"
                );
                _ = write_packet_to_device(&pkt_sdr, nt, &mut tcb, None, ACK | FIN, None, None);
            }
        }
        {
            let mut tcb = tcb.lock();
            tcb.change_state(TcpState::Closed);
            let state = tcb.get_state();
            log::warn!(
                "{} {state:?}: {hint} max retries reached, closing session",
                redacted(&nt)
            );
        }
        exit_notifier.send(()).await.unwrap_or(());
    }

    async fn task_timed_out_for_close_wait(
        tcb: TcbPtr,
        exit_notifier: tokio::sync::mpsc::Sender<()>,
        nt: NetworkTuple,
        up_packet_sender: PacketSender,
        close_wait_timeout: Duration,
        last_ack_timeout: Duration,
        last_ack_max_retries: usize,
    ) -> std::io::Result<()> {
        tokio::time::sleep(close_wait_timeout).await; // Wait CLOSE_WAIT_TIMEOUT for upstream
        let tcb_clone = tcb.clone();
        let mut tcb = tcb.lock();
        let state = tcb.get_state();
        if state != TcpState::CloseWait {
            return Ok(());
        }
        log::warn!("{} {state:?}: upstream timeout, forcing FIN", redacted(&nt));
        write_packet_to_device(&up_packet_sender, nt, &mut tcb, None, ACK | FIN, None, None)?;
        tcb.increase_seq();
        tcb.change_state(TcpState::LastAck);
        let new_state = tcb.get_state();
        log::debug!("{nt} {state:?}: Forced transition to {new_state:?}");

        // Here we set a timer to wait for the last ACK from the other side.
        tokio::spawn(task_last_ack(
            tcb_clone,
            exit_notifier,
            nt,
            up_packet_sender,
            last_ack_timeout,
            last_ack_max_retries,
        ));

        Ok::<(), std::io::Error>(())
    }

    loop {
        let exit_notifier = exit_notifier.clone();

        let network_packet = tokio::select! {
            _ = exit_monitor.recv() => {
                log::debug!("{network_tuple} task exited due to exit signal");
                break;
            }
            network_packet = stream_receiver.recv() => network_packet,
        };

        let Some(mut network_packet) = network_packet else {
            let state = { tcb.lock().get_state() };
            log::debug!(
                "{network_tuple} {state:?}: session closed unexpectedly by pipe broken, exiting task"
            );
            tcb.lock().change_state(TcpState::Closed);
            write_notify
                .lock()
                .take()
                .map(|w| w.wake_by_ref())
                .unwrap_or(());
            read_notify
                .lock()
                .take()
                .map(|w| w.wake_by_ref())
                .unwrap_or(());
            break;
        };

        let payload = network_packet.payload.take().unwrap_or_default();
        let TransportHeader::Tcp(tcp_header) = network_packet.transport_header() else {
            log::warn!("{} invalid TCP packet", redacted(&network_tuple));
            continue;
        };
        let flags = tcp_header_flags(tcp_header);
        let incoming_ack: SeqNum = tcp_header.acknowledgment_number.into();
        let incoming_seq: SeqNum = tcp_header.sequence_number.into();
        let incoming_win = tcp_header.window_size;

        let mut tcb = tcb.lock();

        let state = tcb.get_state();
        if state == TcpState::Closed {
            log::debug!("{network_tuple} {state:?}: session finished, exiting task...");
            break;
        }

        if flags & RST == RST {
            tcb.change_state(TcpState::Closed);
            continue;
        }

        tcb.update_duplicate_ack_count(incoming_ack);

        tcb.update_inflight_packet_queue(incoming_ack);

        for packet in tcb.collect_timed_out_inflight_packets() {
            let (seq, count) = (packet.seq, packet.retransmit_count);
            log::debug!(
                "{network_tuple} inflight packet retransmission timeout: {seq:?}, retransmit_count: {count}",
            );
            write_packet_to_device(
                &up_packet_sender,
                network_tuple,
                &mut tcb,
                None,
                ACK | PSH,
                Some(seq),
                Some(packet.payload),
            )?;
        }

        let pkt_type = tcb.check_pkt_type(tcp_header, &payload);

        let state = tcb.get_state();
        let len = payload.len();
        // Built behind the level check, because macro arguments are evaluated
        // before the macro is. `tcp_header_fmt` builds a String out of eight
        // pushes and a `format!`, and the local-state line builds another —
        // three allocations per inbound packet, in release builds, producing
        // text that is dropped because trace is off.
        let trace = log::log_enabled!(log::Level::Trace);
        let l_info = if trace {
            let (seq, ack) = (tcb.get_seq(), tcb.get_ack());
            format!("local {{ seq: {seq}, ack: {ack} }}")
        } else {
            String::new()
        };
        if trace {
            let info = tcp_header_fmt(tcp_header);
            log::trace!("{network_tuple} {state:?}: {l_info} {info}, {pkt_type:?}, len = {len}");
        }
        if pkt_type == PacketType::Invalid {
            continue;
        }

        match state {
            TcpState::SynReceived => {
                if flags & ACK == ACK {
                    if len > 0 {
                        receive_segment(
                            &up_packet_sender,
                            &mut tcb,
                            network_tuple,
                            incoming_seq,
                            payload,
                            &data_tx,
                            &read_notify,
                        )?;
                    }
                    tcb.change_state(TcpState::Established);
                }
            }
            TcpState::Established => {
                if flags == ACK {
                    match pkt_type {
                        PacketType::WindowUpdate => {
                            write_notify
                                .lock()
                                .take()
                                .map(|w| w.wake_by_ref())
                                .unwrap_or(());
                        }
                        PacketType::KeepAlive => {
                            write_packet_to_device(
                                &up_packet_sender,
                                network_tuple,
                                &mut tcb,
                                None,
                                ACK,
                                None,
                                None,
                            )?;
                        }
                        PacketType::RetransmissionRequest => {
                            if let Some(packet) = tcb.find_inflight_packet(incoming_ack) {
                                let (s, p) = (packet.seq, packet.payload.clone());
                                log::debug!(
                                    "{network_tuple} {state:?}: {l_info}, {pkt_type:?}, retransmission request, seq = {s}, len = {}",
                                    p.len()
                                );
                                write_packet_to_device(
                                    &up_packet_sender,
                                    network_tuple,
                                    &mut tcb,
                                    None,
                                    ACK | PSH,
                                    Some(s),
                                    Some(p),
                                )?;
                            }
                        }
                        PacketType::NewPacket => {
                            receive_segment(
                                &up_packet_sender,
                                &mut tcb,
                                network_tuple,
                                incoming_seq,
                                payload,
                                &data_tx,
                                &read_notify,
                            )?;
                            write_notify
                                .lock()
                                .take()
                                .map(|w| w.wake_by_ref())
                                .unwrap_or(());
                        }
                        PacketType::Ack => {
                            write_notify
                                .lock()
                                .take()
                                .map(|w| w.wake_by_ref())
                                .unwrap_or(());
                        }
                        PacketType::Invalid => {}
                    }
                } else if flags == (ACK | FIN) {
                    // The other side is closing the connection, we need to send an ACK and change state to CloseWait
                    tcb.increase_ack();
                    write_packet_to_device(
                        &up_packet_sender,
                        network_tuple,
                        &mut tcb,
                        None,
                        ACK,
                        None,
                        None,
                    )?;
                    tcb.change_state(TcpState::CloseWait);

                    let s = tcb.get_state();
                    let len = tcb.get_inflight_packets_total_len();
                    if len == 0 {
                        // All upstream data sent, proceed to LastAck
                        log::trace!(
                            "{network_tuple} {s:?}: {l_info}, {pkt_type:?}, closed by the other side, no upstream data"
                        );

                        // Here we don't wait, just send FIN to the other side and change state to LastAck directly,
                        write_packet_to_device(
                            &up_packet_sender,
                            network_tuple,
                            &mut tcb,
                            None,
                            ACK | FIN,
                            None,
                            None,
                        )?;
                        tcb.increase_seq();
                        tcb.change_state(TcpState::LastAck);

                        let s = tcb.get_state();
                        log::trace!(
                            "{network_tuple} {s:?}: {l_info}, {pkt_type:?}, wait the last ack from the other side"
                        );

                        // Here we set a timer to wait for the last ACK from the other side.
                        // If the timer expires, we send an ACK|FIN packet to the other side again and wait anthoer timeout
                        // till the retries reach the limit, and then close the session forcibly.
                        let up = up_packet_sender.clone();
                        tokio::spawn(task_last_ack(
                            tcb_clone.clone(),
                            exit_notifier,
                            network_tuple,
                            up,
                            config.last_ack_timeout,
                            config.last_ack_max_retries,
                        ));
                    } else {
                        // Upstream data pending, wake write_notify and wait
                        write_notify
                            .lock()
                            .take()
                            .map(|w| w.wake_by_ref())
                            .unwrap_or(());
                        log::debug!(
                            "{network_tuple} {state:?}: Waiting for upstream data to complete, inflight packets: {len}",
                        );

                        // Spawn a timeout task to force FIN if upstream is unresponsive
                        let tcb = tcb_clone.clone();
                        let up = up_packet_sender.clone();
                        tokio::spawn(task_timed_out_for_close_wait(
                            tcb,
                            exit_notifier,
                            network_tuple,
                            up,
                            config.close_wait_timeout,
                            config.last_ack_timeout,
                            config.last_ack_max_retries,
                        ));
                    }
                } else if flags == (ACK | PSH) && pkt_type == PacketType::NewPacket {
                    if !payload.is_empty() && tcb.get_ack() == incoming_seq {
                        receive_segment(
                            &up_packet_sender,
                            &mut tcb,
                            network_tuple,
                            incoming_seq,
                            payload,
                            &data_tx,
                            &read_notify,
                        )?;
                    }
                } else {
                    // unnormal case, we do nothing here
                    log::trace!(
                        "{network_tuple} {state:?}: {l_info}, {pkt_type:?}, unnormal case, we do nothing here"
                    );
                }
            }
            TcpState::CloseWait => {
                if flags & ACK == ACK && tcb.get_inflight_packets_total_len() == 0 {
                    write_packet_to_device(
                        &up_packet_sender,
                        network_tuple,
                        &mut tcb,
                        None,
                        ACK | FIN,
                        None,
                        None,
                    )?;
                    tcb.increase_seq();
                    tcb.change_state(TcpState::LastAck);
                    let new_state = tcb.get_state();
                    log::trace!(
                        "{network_tuple} {state:?}: Received ACK|FIN, transitioned to {new_state:?}"
                    );

                    // Here we set a timer to wait for the last ACK from the other side.
                    // If the timer expires, we send an ACK|FIN packet to the other side again and wait anthoer timeout
                    // till the retries reach the limit, and then close the session forcibly.
                    let up = up_packet_sender.clone();
                    tokio::spawn(task_last_ack(
                        tcb_clone.clone(),
                        exit_notifier,
                        network_tuple,
                        up,
                        config.last_ack_timeout,
                        config.last_ack_max_retries,
                    ));
                } else {
                    write_notify
                        .lock()
                        .take()
                        .map(|w| w.wake_by_ref())
                        .unwrap_or(());
                }
            }
            TcpState::LastAck => {
                if flags & ACK == ACK {
                    tcb.change_state(TcpState::Closed);
                    tokio::spawn(async move {
                        if let Err(e) = exit_notifier.send(()).await {
                            log::debug!("exit_notifier send failed: {e}");
                        }
                    });
                    let new_state = tcb.get_state();
                    log::trace!(
                        "{network_tuple} {state:?}: Received final ACK, transitioned to {new_state:?}"
                    );
                }
            }
            TcpState::FinWait1 => {
                if flags & (ACK | FIN) == (ACK | FIN) && len == 0 {
                    // If the received packet is an ACK with FIN, we need to send an ACK and change state to TimeWait directly, not to FinWait2
                    tcb.increase_ack();
                    write_packet_to_device(
                        &up_packet_sender,
                        network_tuple,
                        &mut tcb,
                        None,
                        ACK,
                        None,
                        None,
                    )?;
                    tcb.change_state(TcpState::TimeWait);

                    tokio::spawn(task_wait_to_close(
                        tcb_clone.clone(),
                        exit_notifier,
                        network_tuple,
                        config.two_msl,
                    ));
                    let new_state = tcb.get_state();
                    log::trace!(
                        "{network_tuple} {state:?}: Final ACK|FIN received too early, transitioned to {new_state:?} directly"
                    );
                } else if flags & ACK == ACK {
                    tcb.change_state(TcpState::FinWait2);
                    if len > 0 {
                        // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                        receive_segment(
                            &up_packet_sender,
                            &mut tcb,
                            network_tuple,
                            incoming_seq,
                            payload,
                            &data_tx,
                            &read_notify,
                        )?;
                        write_notify
                            .lock()
                            .take()
                            .map(|w| w.wake_by_ref())
                            .unwrap_or(());
                    }
                    let new_state = tcb.get_state();
                    log::trace!(
                        "{network_tuple} {state:?}: Received ACK, transitioned to {new_state:?}"
                    );
                } else {
                    // unnormal case, we do nothing here
                    log::trace!(
                        "{network_tuple} {state:?}: Some unnormal case, we do nothing here"
                    );
                }
            }
            TcpState::FinWait2 => {
                if flags & (ACK | FIN) == (ACK | FIN) && len == 0 {
                    tcb.increase_ack();
                    write_packet_to_device(
                        &up_packet_sender,
                        network_tuple,
                        &mut tcb,
                        None,
                        ACK,
                        None,
                        None,
                    )?;
                    tcb.change_state(TcpState::TimeWait);
                    tokio::spawn(task_wait_to_close(
                        tcb_clone.clone(),
                        exit_notifier,
                        network_tuple,
                        config.two_msl,
                    ));
                    let new_state = tcb.get_state();
                    log::trace!(
                        "{network_tuple} {state:?}: Received final ACK|FIN, transitioned to {new_state:?}"
                    );
                } else if flags & ACK == ACK && len == 0 {
                    // unnormal case, we do nothing here
                    let l_ack = tcb.get_ack();
                    if incoming_seq < l_ack {
                        log::trace!(
                            "{network_tuple} {state:?}: Ignoring duplicate ACK, seq {incoming_seq}, expected {l_ack}"
                        );
                    }
                } else if flags & ACK == ACK && len > 0 {
                    if pkt_type == PacketType::KeepAlive {
                        write_packet_to_device(
                            &up_packet_sender,
                            network_tuple,
                            &mut tcb,
                            None,
                            ACK,
                            None,
                            None,
                        )?;
                    } else {
                        // if the other side is still sending data, we need to deal with it like PacketStatus::NewPacket
                        receive_segment(
                            &up_packet_sender,
                            &mut tcb,
                            network_tuple,
                            incoming_seq,
                            payload,
                            &data_tx,
                            &read_notify,
                        )?;
                        write_notify
                            .lock()
                            .take()
                            .map(|w| w.wake_by_ref())
                            .unwrap_or(());
                    }
                    if flags & FIN == FIN {
                        tcb.change_state(TcpState::TimeWait);
                        tokio::spawn(task_wait_to_close(
                            tcb_clone.clone(),
                            exit_notifier,
                            network_tuple,
                            config.two_msl,
                        ));
                        let new_state = tcb.get_state();
                        log::trace!(
                            "{network_tuple} {state:?}: Received final ACK|FIN, transitioned to {new_state:?}"
                        );
                    }
                } else {
                    // unnormal case, we do nothing here
                    log::trace!(
                        "{network_tuple} {state:?}: Some unnormal case, we do nothing here"
                    );
                }
            }
            TcpState::TimeWait if flags & (ACK | FIN) == (ACK | FIN) => {
                write_packet_to_device(
                    &up_packet_sender,
                    network_tuple,
                    &mut tcb,
                    None,
                    ACK,
                    None,
                    None,
                )?;
                // wait to timeout, can't call `tcb.change_state(TcpState::Closed);` to change state here
                // now we need to wait for the timeout to reach...
            }
            _ => {}
        } // end of match state

        tcb.update_last_received_ack(incoming_ack);
        tcb.update_send_window(incoming_win);
    } // end of loop
    Ok::<(), std::io::Error>(())
}

/// Take one data segment off the wire: into the receive buffer if the window
/// has room for it, and answered either way.
///
/// The two halves used to be written out at each of the five call sites, and
/// separating them is now a defect rather than a style: a segment the window
/// refuses still has to produce an ACK, because the segment a full receiver is
/// most likely to see is a **zero-window probe** — one byte the peer sends
/// precisely to ask what the window is now. Dropping it in silence leaves that
/// peer doubling its persist timer against a receiver that may already have
/// drained.
#[allow(clippy::too_many_arguments)]
fn receive_segment(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    seq: SeqNum,
    payload: Vec<u8>,
    data_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    read_notify: &Arc<Mutex<Option<Waker>>>,
) -> std::io::Result<()> {
    if !tcb.add_unordered_packet(seq, payload) {
        if tcb.get_state() != TcpState::Closed {
            write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
        }
        return Ok(());
    }
    extract_data_n_write_upstream(up_packet_sender, tcb, network_tuple, data_tx, read_notify)
}

fn extract_data_n_write_upstream(
    up_packet_sender: &PacketSender,
    tcb: &mut Tcb,
    network_tuple: NetworkTuple,
    data_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    read_notify: &Arc<Mutex<Option<Waker>>>,
) -> std::io::Result<()> {
    let state = tcb.get_state();
    // Built only when someone is listening; this runs on every received
    // segment, and the `format!` was unconditional.
    let l_info = || {
        let (seq, ack) = (tcb.get_seq(), tcb.get_ack());
        format!("local {{ seq: {seq}, ack: {ack} }}")
    };
    if state == TcpState::Closed {
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                "{network_tuple} {state:?}: {} session closed, exiting \"data extraction task\"...",
                l_info()
            );
        }
        return Ok(());
    }
    let l_info = if log::log_enabled!(log::Level::Trace) {
        l_info()
    } else {
        String::new()
    };

    if let Some(data) = tcb.consume_unordered_packets(8192) {
        let hint = if state == TcpState::Established {
            "normally"
        } else {
            "still"
        };
        log::trace!(
            "{network_tuple} {state:?}: {l_info} {hint} receiving data, len = {}",
            data.len()
        );
        data_tx
            .send(data)
            .map_err(|e| std::io::Error::new(BrokenPipe, e))?;
        read_notify
            .lock()
            .take()
            .map(|w| w.wake_by_ref())
            .unwrap_or(());
        write_packet_to_device(up_packet_sender, network_tuple, tcb, None, ACK, None, None)?;
    }
    Ok(())
}

/// Send a TCP packet to the downstream device, with the specified flags, sequence number, and payload.
/// The returned value is the length of the `payload` sent, it may be shorter than the length of the incoming parameter `payload`.
///
/// # The floor that was here
///
/// Upstream advertised `get_recv_window().max(get_mtu())`. That floor is the
/// second half of why this stack could not push back: even with an honest
/// occupancy count the smallest window it could offer was one whole segment, so
/// a sender facing a full receiver sent one segment per round trip instead of
/// stopping. Through a tun a round trip is microseconds, which makes a floor of
/// one MTU a multiplier rather than a bound — measured at 512 KiB delivered into
/// a stream nobody read, with `read_buffer_size` set to one byte.
///
/// A zero window is the only thing in TCP that means "stop", so this says zero
/// when it means zero. The peer then runs its persist timer and probes, and
/// [`Tcb::window_update_due`] is what ends the probing.
pub(crate) fn write_packet_to_device(
    up_packet_sender: &PacketSender,
    tuple: NetworkTuple,
    tcb: &mut Tcb,
    options: Option<&Vec<TcpOptions>>,
    flags: u8,
    seq: Option<SeqNum>,
    payload: Option<Vec<u8>>,
) -> std::io::Result<usize> {
    use std::io::Error;
    let seq = seq.unwrap_or(tcb.get_seq()).0;
    let (ack, window_size) = (tcb.get_ack().0, tcb.get_recv_window());
    tcb.note_advertised_window(window_size);
    let (src, dst) = (tuple.dst, tuple.src); // Note: The address is reversed here
    let calc = |ip_header_len: usize, tcp_header_len: usize| {
        tcb.calculate_payload_max_len(ip_header_len, tcp_header_len)
    };
    let packet = create_raw_packet(
        src,
        dst,
        calc,
        flags,
        TTL,
        seq,
        ack,
        window_size,
        payload.unwrap_or_default(),
        options,
    )?;
    let len = packet.payload.as_ref().map(|p| p.len()).unwrap_or(0);
    up_packet_sender
        .send(packet)
        .map_err(|e| Error::new(UnexpectedEof, e))?;
    Ok(len)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_raw_packet(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    calculate_payload_max_len: impl Fn(usize, usize) -> usize,
    flags: u8,
    ttl: u8,
    seq: u32,
    ack: u32,
    win: u16,
    mut payload: Vec<u8>,
    options: Option<&Vec<TcpOptions>>,
) -> std::io::Result<NetworkPacket> {
    let mut tcp_header = etherparse::TcpHeader::new(src_addr.port(), dst_addr.port(), seq, win);
    tcp_header.acknowledgment_number = ack;
    tcp_header.syn = flags & SYN != 0;
    tcp_header.ack = flags & ACK != 0;
    tcp_header.rst = flags & RST != 0;
    tcp_header.fin = flags & FIN != 0;
    tcp_header.psh = flags & PSH != 0;

    if let Some(opts) = options {
        let mut tcp_options = Vec::new();
        for opt in opts {
            match opt {
                TcpOptions::MaximumSegmentSize(mss) => {
                    tcp_options.push(TcpOptionElement::MaximumSegmentSize(*mss))
                }
            }
        }
        tcp_header
            .set_options(&tcp_options)
            .map_err(|e| std::io::Error::new(InvalidInput, e))?;
    }
    let ip_header = match (src_addr.ip(), dst_addr.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::TCP, src.octets(), dst.octets())
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            ip_h.set_payload_len(payload.len() + tcp_header.header_len())
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
            ip_h.dont_fragment = true;
            IpHeader::Ipv4(ip_h)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let mut ip_h = etherparse::Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: 0,
                next_header: IpNumber::TCP,
                hop_limit: ttl,
                source: src.octets(),
                destination: dst.octets(),
            };
            let payload_len = calculate_payload_max_len(ip_h.header_len(), tcp_header.header_len());
            payload.truncate(payload_len);
            let len = payload.len() + tcp_header.header_len();
            ip_h.set_payload_length(len)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;

            IpHeader::Ipv6(ip_h)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IP version mismatch",
            ));
        }
    };

    match ip_header {
        IpHeader::Ipv4(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv4(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
        IpHeader::Ipv6(ref ip_header) => {
            tcp_header.checksum = tcp_header
                .calc_checksum_ipv6(ip_header, &payload)
                .map_err(|e| std::io::Error::new(InvalidInput, e))?;
        }
    }
    Ok(NetworkPacket {
        ip: ip_header,
        transport: TransportHeader::Tcp(tcp_header),
        payload: Some(payload),
    })
}
