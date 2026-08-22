//! Bounded userspace network stack for the TUN data plane.
//!
//! TCP is owned by one Tokio actor around smoltcp. The actor reserves the
//! accept slot and the complete per-flow memory charge before handing an
//! untrusted SYN to smoltcp, uses bounded packet queues on both sides of the
//! synchronous `Device` API, and is the only owner of the `Interface`,
//! `SocketSet` and tuple map. UDP remains a Fox-owned five-tuple demultiplexer:
//! its datagram queues are bounded and counted, while DNS stays in the flow
//! engine where policy is available.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use self::packet::NetworkPacket;

mod actor;
mod error;
mod packet;
mod stream;

pub use self::error::{Result, StackError};
pub use self::stream::{DatagramFlow, StackFlow, TcpConfig, TcpFlow, UnknownTransport};
pub use etherparse::IpNumber;

/// Exercise the packet adapter from the out-of-workspace fuzz harness.
///
/// This is feature-gated so the shipping library does not expose an extra API.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_packet(bytes: &[u8]) -> bool {
    let Ok(packet) = NetworkPacket::parse(bytes) else {
        return false;
    };
    let Ok(reparsed) = NetworkPacket::parse(bytes) else {
        panic!("the same packet was accepted and then refused");
    };

    assert_eq!(packet.network_tuple(), reparsed.network_tuple());
    assert_eq!(
        packet.reverse_network_tuple(),
        reparsed.reverse_network_tuple()
    );
    assert_eq!(packet.ttl(), reparsed.ttl());
    assert_eq!(packet.payload, reparsed.payload);
    assert_eq!(packet.src_addr().is_ipv4(), packet.dst_addr().is_ipv4());
    assert!(
        packet
            .payload
            .as_ref()
            .is_none_or(|payload| payload.len() <= bytes.len())
    );
    true
}

#[derive(Clone, Debug)]
pub(crate) struct RawPacketSender(mpsc::Sender<NetworkPacket>);

impl RawPacketSender {
    pub(crate) fn new(sender: mpsc::Sender<NetworkPacket>) -> Self {
        Self(sender)
    }

    pub(crate) fn send(&self, packet: NetworkPacket) -> std::io::Result<()> {
        match self.0.try_send(packet) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "raw response queue is full",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "raw response queue is closed",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UdpPacketSender {
    sender: mpsc::Sender<NetworkPacket>,
    dropped: Arc<AtomicU64>,
}

impl UdpPacketSender {
    pub(crate) fn new(sender: mpsc::Sender<NetworkPacket>, dropped: Arc<AtomicU64>) -> Self {
        Self { sender, dropped }
    }

    pub(crate) fn send(&self, packet: NetworkPacket) -> SessionPacketDelivery {
        match self.sender.try_send(packet) {
            Ok(()) => SessionPacketDelivery::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                SessionPacketDelivery::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(_)) => SessionPacketDelivery::Closed,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SessionPacketSender(UdpPacketSender);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionPacketDelivery {
    Delivered,
    Dropped,
    Closed,
}

impl SessionPacketSender {
    pub(crate) fn udp(sender: mpsc::Sender<NetworkPacket>, dropped: Arc<AtomicU64>) -> Self {
        Self(UdpPacketSender::new(sender, dropped))
    }

    pub(crate) fn send(&self, packet: NetworkPacket) -> SessionPacketDelivery {
        self.0.send(packet)
    }
}

#[cfg(unix)]
const TTL: u8 = 64;
#[cfg(windows)]
const TTL: u8 = 128;

#[cfg(unix)]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "espidf"
))]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "espidf"
))]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x0a];
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

const MIN_MTU: u16 = 1280;
const DEFAULT_MAX_SESSIONS: usize = 1024 + 512;
const STACK_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
pub(crate) const TCP_SESSION_CEILING: usize = 32_768;
pub(crate) const UDP_SESSION_QUEUE_DEPTH: usize = 32;
pub(crate) const UDP_DEVICE_QUEUE_DEPTH: usize = 256;
const ACCEPT_QUEUE_CEILING: usize = 256;

fn accept_queue_depth(max_sessions: usize) -> usize {
    max_sessions.clamp(1, ACCEPT_QUEUE_CEILING)
}

#[non_exhaustive]
pub struct StackConfig {
    pub mtu: u16,
    pub packet_information: bool,
    pub tcp_config: Arc<TcpConfig>,
    pub udp_timeout: Duration,
    pub max_sessions: usize,
    pub(crate) max_tcp_sessions: usize,
    pub(crate) report_tcp_refusals: bool,
    pub(crate) udp_queue_drops: Arc<AtomicU64>,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            mtu: MIN_MTU,
            packet_information: false,
            tcp_config: Arc::new(TcpConfig::default()),
            udp_timeout: Duration::from_secs(30),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_tcp_sessions: DEFAULT_MAX_SESSIONS,
            report_tcp_refusals: false,
            udp_queue_drops: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl StackConfig {
    pub fn with_tcp_config(&mut self, config: TcpConfig) -> &mut Self {
        self.tcp_config = Arc::new(config);
        self
    }

    pub fn udp_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.udp_timeout = timeout;
        self
    }

    pub fn max_sessions(&mut self, max_sessions: usize) -> &mut Self {
        self.max_sessions = max_sessions.max(1);
        self
    }

    pub(crate) fn udp_queue_drop_counter(&mut self, counter: Arc<AtomicU64>) -> &mut Self {
        self.udp_queue_drops = counter;
        self
    }

    pub(crate) fn max_tcp_sessions(&mut self, max_tcp_sessions: usize) -> &mut Self {
        self.max_tcp_sessions = max_tcp_sessions.clamp(1, TCP_SESSION_CEILING);
        self
    }

    pub(crate) fn report_tcp_refusals(&mut self, report: bool) -> &mut Self {
        self.report_tcp_refusals = report;
        self
    }

    pub fn mtu(&mut self, mtu: u16) -> Result<&mut Self, StackError> {
        if mtu < MIN_MTU {
            return Err(StackError::InvalidMtuSize(mtu));
        }
        self.mtu = mtu;
        Ok(self)
    }

    pub fn mtu_unchecked(&mut self, mtu: u16) -> &mut Self {
        self.mtu = mtu;
        self
    }

    pub fn packet_information(&mut self, packet_information: bool) -> &mut Self {
        self.packet_information = packet_information;
        self
    }
}

pub struct FlowStack {
    accept_receiver: mpsc::Receiver<StackFlow>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<Result<()>>>,
}

impl FlowStack {
    pub fn new<Device>(config: StackConfig, device: Device) -> Self
    where
        Device: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (accept_sender, accept_receiver) =
            mpsc::channel(accept_queue_depth(config.max_sessions));
        let (shutdown, handle) = actor::run(config, device, accept_sender);
        Self {
            accept_receiver,
            shutdown: Some(shutdown),
            handle: Some(handle),
        }
    }

    pub async fn accept(&mut self) -> Result<StackFlow, StackError> {
        if let Some(flow) = self.accept_receiver.recv().await {
            return Ok(flow);
        }
        let Some(handle) = self.handle.take() else {
            return Err(StackError::AcceptError);
        };
        match handle.await {
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => Err(StackError::AcceptError),
            Err(error) => Err(StackError::IoError(std::io::Error::other(format!(
                "netstack actor failed: {error}"
            )))),
        }
    }

    /// Stop and join the actor before the engine releases its TUN generation.
    pub async fn shutdown(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(mut handle) = self.handle.take() else {
            return;
        };
        if tokio::time::timeout(STACK_SHUTDOWN_GRACE, &mut handle)
            .await
            .is_err()
        {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for FlowStack {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingWriterDevice {
        packet: Option<Vec<u8>>,
    }

    impl AsyncRead for FailingWriterDevice {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let Some(packet) = self.packet.take() else {
                return std::task::Poll::Pending;
            };
            buffer.put_slice(&packet);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FailingWriterDevice {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected writer failure",
            )))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn raw_response_queue_refuses_one_packet_past_its_bound() {
        let (sender, mut receiver) = mpsc::channel(1);
        let sender = RawPacketSender::new(sender);
        let packet = NetworkPacket {
            ip: packet::IpHeader::Ipv4(
                etherparse::Ipv4Header::new(0, 64, IpNumber::ICMP, [10, 0, 0, 1], [10, 0, 0, 2])
                    .unwrap(),
            ),
            transport: packet::TransportHeader::Unknown,
            payload: None,
        };

        sender.send(packet.clone()).unwrap();
        assert_eq!(
            sender.send(packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(receiver.recv().await.is_some());
    }

    #[tokio::test]
    async fn fatal_device_error_reaches_the_acceptor() {
        let (device, peer) = tokio::io::duplex(1280);
        drop(peer);
        let mut stack = FlowStack::new(StackConfig::default(), device);

        let result = tokio::time::timeout(Duration::from_secs(1), stack.accept())
            .await
            .expect("the closed device must wake the acceptor");
        let Err(error) = result else {
            panic!("the closed device was accepted as a flow");
        };
        let StackError::IoError(error) = error else {
            panic!("the actor hid its device error behind {error}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn fatal_writer_error_reaches_the_acceptor() {
        use tokio::io::AsyncWriteExt;

        let builder =
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [192, 0, 2, 1], TTL).udp(40_000, 53);
        let mut packet = Vec::new();
        builder
            .write(&mut packet, b"query")
            .expect("build UDP packet");
        let device = FailingWriterDevice {
            packet: Some(packet),
        };
        let mut stack = FlowStack::new(StackConfig::default(), device);

        let accepted = tokio::time::timeout(Duration::from_secs(1), stack.accept())
            .await
            .expect("the packet must reach the stack")
            .expect("accept UDP flow");
        let StackFlow::Udp(mut flow) = accepted else {
            panic!("a UDP packet produced a different flow type");
        };
        flow.write_all(b"answer")
            .await
            .expect("queue the UDP answer");

        let result = tokio::time::timeout(Duration::from_secs(1), stack.accept())
            .await
            .expect("the broken writer must wake the acceptor");
        let Err(StackError::IoError(error)) = result else {
            panic!("the actor hid its writer error");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn shutdown_joins_the_actor_and_its_writer() {
        let (device, mut peer) = tokio::io::duplex(1280);
        let mut stack = FlowStack::new(StackConfig::default(), device);

        stack.shutdown().await;

        use tokio::io::AsyncReadExt;
        let mut byte = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
                .await
                .expect("the joined stack must release its device")
                .expect("read the released peer"),
            0
        );
    }

    #[test]
    fn tcp_session_limit_cannot_exceed_its_command_queue() {
        let mut config = StackConfig::default();
        config.max_tcp_sessions(usize::MAX);
        assert_eq!(config.max_tcp_sessions, TCP_SESSION_CEILING);
    }
}
