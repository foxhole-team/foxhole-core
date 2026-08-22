use std::{
    collections::{HashMap, VecDeque},
    io,
};

use smoltcp::{
    iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle,
        SocketSet,
    },
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    time::Instant as SmolInstant,
    wire::HardwareAddress,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};

use super::{
    RawPacketSender, SessionPacketSender, StackConfig, StackError, StackFlow, TCP_SESSION_CEILING,
    UDP_DEVICE_QUEUE_DEPTH, UdpPacketSender,
    packet::{NetworkPacket, NetworkTuple, TransportHeader},
    stream::{DatagramFlow, TcpConfig, TcpControl, TcpFlow, UdpStreamConfig, UnknownTransport},
};

const PACKET_QUEUE_DEPTH: usize = 256;
const TCP_COMMANDS_PER_TICK: usize = 64;
const TCP_PACKETS_PER_TICK: usize = 32;
const TCP_EGRESS_POLLS_PER_TICK: usize = 32;
const TCP_FLOWS_PER_TICK: usize = 64;
const TCP_MEMORY_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const MAX_TUN_READ_ERRORS: u32 = 8;
const _: () = {
    assert!(PACKET_QUEUE_DEPTH <= super::ACCEPT_QUEUE_CEILING);
    assert!(TCP_MEMORY_BUDGET_BYTES <= 64 * 1024 * 1024);
    assert!(TCP_SESSION_CEILING <= 32_768);
};

struct IngressPacket {
    bytes: Vec<u8>,
    tuple: NetworkTuple,
}

struct PacketDevice {
    ingress: VecDeque<IngressPacket>,
    egress: VecDeque<Vec<u8>>,
    last_ingress_tuple: Option<NetworkTuple>,
    mtu: usize,
}

impl PacketDevice {
    fn new(mtu: usize) -> Self {
        Self {
            ingress: VecDeque::with_capacity(PACKET_QUEUE_DEPTH),
            egress: VecDeque::with_capacity(PACKET_QUEUE_DEPTH),
            last_ingress_tuple: None,
            mtu,
        }
    }

    fn can_enqueue_ingress(&self) -> bool {
        self.ingress.len() < PACKET_QUEUE_DEPTH
    }

    fn enqueue_ingress(&mut self, bytes: Vec<u8>, tuple: NetworkTuple) -> io::Result<()> {
        if bytes.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet exceeds configured MTU",
            ));
        }
        if !self.can_enqueue_ingress() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "smoltcp ingress queue is full",
            ));
        }
        self.ingress.push_back(IngressPacket { bytes, tuple });
        Ok(())
    }

    fn can_enqueue_egress(&self) -> bool {
        self.egress.len() < PACKET_QUEUE_DEPTH
    }

    fn enqueue_egress(&mut self, packet: Vec<u8>) -> io::Result<()> {
        if !self.can_enqueue_egress() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "netstack egress queue is full",
            ));
        }
        self.egress.push_back(packet);
        Ok(())
    }

    fn take_last_ingress_tuple(&mut self) -> Option<NetworkTuple> {
        self.last_ingress_tuple.take()
    }
}

struct PacketRxToken(Vec<u8>);

impl RxToken for PacketRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct PacketTxToken<'a> {
    egress: &'a mut VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TxToken for PacketTxToken<'_> {
    fn consume<R, F>(self, length: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(length <= self.mtu, "smoltcp emitted a packet above the MTU");
        let mut packet = vec![0; length];
        let result = f(&mut packet);
        self.egress.push_back(packet);
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a>
        = PacketRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.can_enqueue_egress() {
            return None;
        }
        let packet = self.ingress.pop_front()?;
        self.last_ingress_tuple = Some(packet.tuple);
        Some((
            PacketRxToken(packet.bytes),
            PacketTxToken {
                egress: &mut self.egress,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if !self.can_enqueue_egress() {
            return None;
        }
        Some(PacketTxToken {
            egress: &mut self.egress,
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(PACKET_QUEUE_DEPTH);
        capabilities
    }
}

struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
}

struct TcpSession {
    handle: SocketHandle,
    control: std::sync::Arc<TcpControl>,
    to_application: Option<mpsc::Sender<Vec<u8>>>,
    from_application: mpsc::Receiver<Vec<u8>>,
    pending_write: Option<PendingWrite>,
    stream: Option<TcpFlow>,
    accept_permit: Option<mpsc::OwnedPermit<StackFlow>>,
    memory_bytes: usize,
    published: bool,
    admitted_at: std::time::Instant,
    time_wait_since: Option<std::time::Instant>,
}

impl Drop for TcpSession {
    fn drop(&mut self) {
        self.control.close();
    }
}

struct AbortOnDrop(Option<JoinHandle<()>>);

impl AbortOnDrop {
    async fn abort_and_join(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

pub(super) fn run<DeviceT>(
    config: StackConfig,
    device: DeviceT,
    accept_sender: mpsc::Sender<StackFlow>,
) -> (oneshot::Sender<()>, JoinHandle<super::Result<()>>)
where
    DeviceT: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    (
        shutdown_tx,
        tokio::spawn(run_inner(config, device, accept_sender, shutdown_rx)),
    )
}

async fn run_inner<DeviceT>(
    config: StackConfig,
    device: DeviceT,
    accept_sender: mpsc::Sender<StackFlow>,
    mut shutdown: oneshot::Receiver<()>,
) -> super::Result<()>
where
    DeviceT: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = tokio::io::split(device);
    let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_DEPTH);
    let (writer_error_tx, mut writer_error_rx) = mpsc::channel::<io::Error>(1);
    let writer_task = tokio::spawn(write_packets(
        writer,
        writer_rx,
        writer_error_tx,
        config.packet_information,
    ));
    let mut writer_guard = AbortOnDrop(Some(writer_task));

    let mut packet_device = PacketDevice::new(usize::from(config.mtu));
    let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
    let mut random_seed = [0_u8; 8];
    getrandom::fill(&mut random_seed)
        .map_err(|_| io::Error::other("operating system RNG failed for TCP seed"))?;
    interface_config.random_seed = u64::from_ne_bytes(random_seed);
    let mut interface = Interface::new(interface_config, &mut packet_device, SmolInstant::ZERO);
    interface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_flows = HashMap::<NetworkTuple, TcpSession>::new();
    let mut tcp_memory_bytes = 0_usize;

    let mut udp_sessions = HashMap::<NetworkTuple, SessionPacketSender>::new();
    let mut session_tasks = JoinSet::<NetworkTuple>::new();

    let command_queue_depth = config.max_tcp_sessions;
    let (tcp_command_tx, mut tcp_command_rx) = mpsc::channel::<NetworkTuple>(command_queue_depth);
    let (raw_up_tx, mut raw_up_rx) = mpsc::channel::<NetworkPacket>(PACKET_QUEUE_DEPTH);
    let raw_up_tx = RawPacketSender::new(raw_up_tx);
    let (udp_up_tx, mut udp_up_rx) = mpsc::channel::<NetworkPacket>(UDP_DEVICE_QUEUE_DEPTH);
    let udp_up_tx = UdpPacketSender::new(udp_up_tx, config.udp_queue_drops.clone());

    let offset = usize::from(config.packet_information && cfg!(unix)) * 4;
    let mut read_buffer = vec![0_u8; usize::from(config.mtu) + offset];
    let mut read_errors = 0_u32;
    let mut scan_tcp = false;
    let mut tcp_scan_queue = VecDeque::<NetworkTuple>::new();
    let mut next_tcp_deadline = None::<std::time::Instant>;

    let result = async {
        loop {
            match shutdown.try_recv() {
                Ok(()) | Err(oneshot::error::TryRecvError::Closed) => return Ok(()),
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            match writer_error_rx.try_recv() {
                Ok(error) => return Err(StackError::IoError(error)),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(writer_gone());
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            if next_tcp_deadline.is_some_and(|deadline| deadline <= std::time::Instant::now()) {
                next_tcp_deadline = None;
                scan_tcp = true;
            }
            let mut did_work = false;

            for _ in 0..PACKET_QUEUE_DEPTH {
                let Some(packet) = packet_device.egress.pop_front() else {
                    break;
                };
                match writer_tx.try_send(packet) {
                    Ok(()) => did_work = true,
                    Err(mpsc::error::TrySendError::Full(packet)) => {
                        packet_device.egress.push_front(packet);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(StackError::IoError(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "netstack writer is gone",
                        )));
                    }
                }
            }

            for _ in 0..TCP_COMMANDS_PER_TICK {
                let Ok(tuple) = tcp_command_rx.try_recv() else {
                    break;
                };
                if let Some(flow) = tcp_flows.get(&tuple) {
                    flow.control.begin_service();
                }
                service_and_reap_tcp_flow(
                    tuple,
                    &mut tcp_flows,
                    &mut sockets,
                    &mut tcp_memory_bytes,
                    &mut next_tcp_deadline,
                    config.mtu,
                    config.tcp_config.as_ref(),
                );
                did_work = true;
            }

            for _ in 0..PACKET_QUEUE_DEPTH {
                let Some(result) = session_tasks.try_join_next() else {
                    break;
                };
                if let Ok(tuple) = result {
                    udp_sessions.remove(&tuple);
                }
                did_work = true;
            }

            while packet_device.can_enqueue_egress() {
                let packet = match udp_up_rx.try_recv() {
                    Ok(packet) => packet,
                    Err(_) => break,
                };
                enqueue_network_packet(packet, &mut packet_device)?;
                did_work = true;
            }

            while packet_device.can_enqueue_egress() {
                let packet = match raw_up_rx.try_recv() {
                    Ok(packet) => packet,
                    Err(_) => break,
                };
                enqueue_network_packet(packet, &mut packet_device)?;
                did_work = true;
            }

            let now = SmolInstant::from(std::time::Instant::now());
            interface.poll_maintenance(now);
            for _ in 0..TCP_PACKETS_PER_TICK {
                if !packet_device.can_enqueue_egress() {
                    break;
                }
                let result = interface.poll_ingress_single(now, &mut packet_device, &mut sockets);
                if result == PollIngressSingleResult::None {
                    break;
                }
                if let Some(tuple) = packet_device.take_last_ingress_tuple() {
                    service_and_reap_tcp_flow(
                        tuple,
                        &mut tcp_flows,
                        &mut sockets,
                        &mut tcp_memory_bytes,
                        &mut next_tcp_deadline,
                        config.mtu,
                        config.tcp_config.as_ref(),
                    );
                }
                did_work = true;
            }

            for _ in 0..TCP_EGRESS_POLLS_PER_TICK {
                if !packet_device.can_enqueue_egress() {
                    break;
                }
                let before = packet_device.egress.len();
                let result = interface.poll_egress(now, &mut packet_device, &mut sockets);
                scan_tcp |= result == PollResult::SocketStateChanged;
                if packet_device.egress.len() == before && result == PollResult::None {
                    break;
                }
                did_work = true;
            }

            if scan_tcp && tcp_scan_queue.is_empty() {
                tcp_scan_queue.extend(tcp_flows.keys().copied());
                scan_tcp = false;
            }
            for _ in 0..TCP_FLOWS_PER_TICK {
                let Some(tuple) = tcp_scan_queue.pop_front() else {
                    break;
                };
                service_and_reap_tcp_flow(
                    tuple,
                    &mut tcp_flows,
                    &mut sockets,
                    &mut tcp_memory_bytes,
                    &mut next_tcp_deadline,
                    config.mtu,
                    config.tcp_config.as_ref(),
                );
                did_work = true;
            }

            if did_work {
                tokio::task::yield_now().await;
                continue;
            }

            let now = SmolInstant::from(std::time::Instant::now());
            let mut delay = if packet_device.can_enqueue_egress() {
                interface
                    .poll_at(now, &sockets)
                    .map(|deadline| {
                        std::time::Duration::from_millis(
                            deadline
                                .total_millis()
                                .saturating_sub(now.total_millis())
                                .max(0) as u64,
                        )
                    })
                    .unwrap_or(std::time::Duration::from_secs(60))
            } else {
                std::time::Duration::from_secs(60)
            };
            if let Some(deadline) = next_tcp_deadline {
                delay = delay.min(deadline.saturating_duration_since(std::time::Instant::now()));
            }
            let timer = tokio::time::sleep(delay);
            tokio::pin!(timer);

            tokio::select! {
                biased;

                _ = &mut shutdown => return Ok(()),
                error = writer_error_rx.recv() => {
                    return Err(error.map_or_else(writer_gone, StackError::IoError));
                }
                permit = writer_tx.reserve(), if !packet_device.egress.is_empty() => {
                    let permit = permit.map_err(|_| {
                        StackError::IoError(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "netstack writer is gone",
                        ))
                    })?;
                    if let Some(packet) = packet_device.egress.pop_front() {
                        permit.send(packet);
                    }
                }
                read = reader.read(&mut read_buffer), if packet_device.can_enqueue_ingress() => {
                    let length = match read {
                        Ok(0) => {
                            return Err(StackError::IoError(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "tun device closed",
                            )));
                        }
                        Ok(length) => {
                            read_errors = 0;
                            length
                        }
                        Err(error) => {
                            read_errors = read_errors.saturating_add(1);
                            log::warn!(
                                "tun read failed ({read_errors}/{MAX_TUN_READ_ERRORS}): {error}"
                            );
                            if read_errors >= MAX_TUN_READ_ERRORS {
                                return Err(StackError::IoError(error));
                            }
                            continue;
                        }
                    };
                    let Some(packet) = read_buffer.get(offset..length) else {
                        log::warn!("short tun read: {length} bytes with a {offset}-byte header");
                        continue;
                    };
                    process_ingress_packet(
                        packet,
                        &config,
                        &accept_sender,
                        &tcp_command_tx,
                        &mut tcp_flows,
                        &mut tcp_memory_bytes,
                        &mut sockets,
                        &mut packet_device,
                        &mut udp_sessions,
                        &mut session_tasks,
                        &raw_up_tx,
                        &udp_up_tx,
                    )?;
                }
                Some(tuple) = tcp_command_rx.recv() => {
                    if let Some(flow) = tcp_flows.get(&tuple) {
                        flow.control.begin_service();
                    }
                    service_and_reap_tcp_flow(
                        tuple,
                        &mut tcp_flows,
                        &mut sockets,
                        &mut tcp_memory_bytes,
                        &mut next_tcp_deadline,
                        config.mtu,
                        config.tcp_config.as_ref(),
                    );
                }
                Some(packet) = udp_up_rx.recv(), if packet_device.can_enqueue_egress() => {
                    enqueue_network_packet(packet, &mut packet_device)?;
                }
                Some(packet) = raw_up_rx.recv(), if packet_device.can_enqueue_egress() => {
                    enqueue_network_packet(packet, &mut packet_device)?;
                }
                Some(result) = session_tasks.join_next(), if !session_tasks.is_empty() => {
                    if let Ok(tuple) = result {
                        udp_sessions.remove(&tuple);
                    }
                }
                _ = &mut timer => {
                    scan_tcp = true;
                }
                else => return Ok(()),
            }
        }
    }
    .await;
    writer_guard.abort_and_join().await;
    result
}

fn writer_gone() -> StackError {
    StackError::IoError(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "netstack writer exited without reporting an I/O error",
    ))
}

#[allow(clippy::too_many_arguments)]
fn process_ingress_packet(
    bytes: &[u8],
    config: &StackConfig,
    accept_sender: &mpsc::Sender<StackFlow>,
    tcp_command_tx: &mpsc::Sender<NetworkTuple>,
    tcp_flows: &mut HashMap<NetworkTuple, TcpSession>,
    tcp_memory_bytes: &mut usize,
    sockets: &mut SocketSet<'static>,
    packet_device: &mut PacketDevice,
    udp_sessions: &mut HashMap<NetworkTuple, SessionPacketSender>,
    session_tasks: &mut JoinSet<NetworkTuple>,
    raw_up_tx: &RawPacketSender,
    udp_up_tx: &UdpPacketSender,
) -> super::Result<()> {
    let packet = match NetworkPacket::parse(bytes) {
        Ok(packet) => packet,
        Err(_) => {
            if let Ok(permit) = accept_sender.try_reserve() {
                permit.send(StackFlow::UnknownNetwork(bytes.to_vec()));
            }
            return Ok(());
        }
    };

    let tuple = packet.network_tuple();
    match packet.transport_header() {
        TransportHeader::Tcp(header) => {
            if !tcp_flows.contains_key(&tuple)
                && header.syn
                && !header.ack
                && !header.rst
                && !header.fin
            {
                let sessions_full =
                    tcp_flows.len().saturating_add(udp_sessions.len()) >= config.max_sessions;
                let admitted = if sessions_full {
                    false
                } else {
                    admit_tcp_flow(
                        tuple,
                        config,
                        accept_sender,
                        tcp_command_tx,
                        tcp_flows,
                        tcp_memory_bytes,
                        sockets,
                    )?
                };
                if !admitted {
                    report_tcp_refusal(config, accept_sender, tuple);
                }
            }
            packet_device.enqueue_ingress(bytes.to_vec(), tuple)?;
        }
        TransportHeader::Udp(_) => {
            if let Some(sender) = udp_sessions.get(&tuple) {
                let _ = sender.send(packet);
                return Ok(());
            }
            if tcp_flows.len().saturating_add(udp_sessions.len()) >= config.max_sessions {
                return Ok(());
            }
            let Ok(permit) = accept_sender.try_reserve() else {
                return Ok(());
            };
            let (destroy_tx, destroy_rx) = tokio::sync::oneshot::channel();
            let stream = DatagramFlow::new(
                tuple.src,
                tuple.dst,
                packet.payload.unwrap_or_default(),
                udp_up_tx.clone(),
                UdpStreamConfig {
                    mtu: config.mtu,
                    timeout_interval: config.udp_timeout,
                    queue_drops: config.udp_queue_drops.clone(),
                },
                Some(destroy_tx),
            );
            let sender = stream.stream_sender();
            session_tasks.spawn(async move {
                let _ = destroy_rx.await;
                tuple
            });
            udp_sessions.insert(tuple, sender);
            permit.send(StackFlow::Udp(stream));
        }
        TransportHeader::Unknown => {
            let Ok(permit) = accept_sender.try_reserve() else {
                return Ok(());
            };
            permit.send(StackFlow::UnknownTransport(UnknownTransport::new(
                packet.src_addr().ip(),
                packet.dst_addr().ip(),
                packet.payload.unwrap_or_default(),
                &packet.ip,
                config.mtu,
                raw_up_tx.clone(),
            )));
        }
    }
    Ok(())
}

fn admit_tcp_flow(
    tuple: NetworkTuple,
    config: &StackConfig,
    accept_sender: &mpsc::Sender<StackFlow>,
    tcp_command_tx: &mpsc::Sender<NetworkTuple>,
    tcp_flows: &mut HashMap<NetworkTuple, TcpSession>,
    tcp_memory_bytes: &mut usize,
    sockets: &mut SocketSet<'static>,
) -> super::Result<bool> {
    if tcp_flows.len() >= config.max_tcp_sessions {
        return Ok(false);
    }
    let receive_bytes = receive_buffer_bytes(tuple, config);
    let transmit_bytes = usize::try_from(config.tcp_config.max_unacked_bytes)
        .unwrap_or(usize::MAX)
        .max(1);
    let application_chunk_bytes = usize::from(config.mtu).max(1);
    let memory_bytes = receive_bytes
        .saturating_add(transmit_bytes)
        .saturating_add(application_chunk_bytes.saturating_mul(2));
    if memory_bytes > TCP_MEMORY_BUDGET_BYTES.saturating_sub(*tcp_memory_bytes) {
        return Ok(false);
    }
    let Ok(accept_permit) = accept_sender.clone().try_reserve_owned() else {
        return Ok(false);
    };

    let mut socket = TcpSocket::new(
        TcpSocketBuffer::new(vec![0; receive_bytes]),
        TcpSocketBuffer::new(vec![0; transmit_bytes]),
    );
    socket.set_congestion_control(CongestionControl::Reno);
    socket.set_nagle_enabled(false);
    socket
        .listen(tuple.dst)
        .map_err(|error| StackError::IoError(io::Error::other(error.to_string())))?;
    let handle = sockets.add(socket);

    let (to_application, read_rx) = mpsc::channel(1);
    let (write_tx, from_application) = mpsc::channel(1);
    let control = TcpControl::new(tuple, tcp_command_tx.clone());
    let stream = TcpFlow::new(
        tuple.src,
        tuple.dst,
        read_rx,
        write_tx,
        application_chunk_bytes,
        control.clone(),
    );
    tcp_flows.insert(
        tuple,
        TcpSession {
            handle,
            control,
            to_application: Some(to_application),
            from_application,
            pending_write: None,
            stream: Some(stream),
            accept_permit: Some(accept_permit),
            memory_bytes,
            published: false,
            admitted_at: std::time::Instant::now(),
            time_wait_since: None,
        },
    );
    *tcp_memory_bytes = tcp_memory_bytes.saturating_add(memory_bytes);
    Ok(true)
}

fn report_tcp_refusal(
    config: &StackConfig,
    accept_sender: &mpsc::Sender<StackFlow>,
    tuple: NetworkTuple,
) {
    if !config.report_tcp_refusals {
        return;
    }
    if let Ok(permit) = accept_sender.try_reserve() {
        permit.send(StackFlow::TcpRefused {
            local: tuple.src,
            peer: tuple.dst,
        });
    }
}

fn receive_buffer_bytes(tuple: NetworkTuple, config: &StackConfig) -> usize {
    let ip_header = if tuple.src.is_ipv4() { 20 } else { 40 };
    let maximum_segment = usize::from(config.mtu)
        .saturating_sub(ip_header + 20)
        .max(1);
    let requested = config.tcp_config.read_buffer_size.max(maximum_segment);
    // smoltcp intentionally does not implement silly-window avoidance. A
    // remainder smaller than one segment would otherwise be advertised as a
    // permanently non-zero window that a conventional full-MSS sender cannot
    // use. Charge and allocate the largest whole-segment window no larger than
    // requested; the legacy one-byte test remains useful through the one-MSS
    // floor, without reopening an unbounded channel above the socket.
    (requested / maximum_segment).max(1) * maximum_segment
}

fn service_and_reap_tcp_flow(
    tuple: NetworkTuple,
    tcp_flows: &mut HashMap<NetworkTuple, TcpSession>,
    sockets: &mut SocketSet<'static>,
    tcp_memory_bytes: &mut usize,
    next_tcp_deadline: &mut Option<std::time::Instant>,
    mtu: u16,
    tcp_config: &TcpConfig,
) {
    if service_tcp_flow(tuple, tcp_flows, sockets, mtu, tcp_config) {
        let Some(flow) = tcp_flows.remove(&tuple) else {
            return;
        };
        let _ = sockets.remove(flow.handle);
        *tcp_memory_bytes = tcp_memory_bytes.saturating_sub(flow.memory_bytes);
        return;
    }
    let deadline = tcp_flows.get(&tuple).and_then(|flow| {
        let time_wait = flow
            .time_wait_since
            .and_then(|started| started.checked_add(tcp_config.two_msl));
        let half_open = (!flow.published)
            .then(|| flow.admitted_at.checked_add(tcp_config.handshake_timeout))
            .flatten();
        match (time_wait, half_open) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    });
    if let Some(deadline) = deadline {
        *next_tcp_deadline = Some(match *next_tcp_deadline {
            Some(current) => current.min(deadline),
            None => deadline,
        });
    }
}

fn service_tcp_flow(
    tuple: NetworkTuple,
    tcp_flows: &mut HashMap<NetworkTuple, TcpSession>,
    sockets: &mut SocketSet<'static>,
    mtu: u16,
    tcp_config: &TcpConfig,
) -> bool {
    let Some(flow) = tcp_flows.get_mut(&tuple) else {
        return false;
    };
    let socket = sockets.get_mut::<TcpSocket<'static>>(flow.handle);

    let handshake_expired = !flow.published
        && socket.state() != TcpState::Established
        && flow.admitted_at.elapsed() >= tcp_config.handshake_timeout;
    if flow.control.reset_requested() || flow.control.dropped() || handshake_expired {
        socket.abort();
    }

    if socket.state() == TcpState::Established
        && !flow.published
        && let (Some(permit), Some(stream)) = (flow.accept_permit.take(), flow.stream.take())
    {
        permit.send(StackFlow::Tcp(stream));
        flow.published = true;
    }

    let receive_chunk = usize::from(mtu).max(1);
    if socket.can_recv()
        && let Some(sender) = flow.to_application.as_ref()
    {
        match sender.try_reserve() {
            Ok(permit) => {
                let mut bytes = vec![0_u8; socket.recv_queue().min(receive_chunk)];
                if let Ok(length) = socket.recv_slice(&mut bytes) {
                    bytes.truncate(length);
                    if !bytes.is_empty() {
                        flow.control.add_application_read_bytes(bytes.len());
                        permit.send(bytes);
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(())) => socket.abort(),
            Err(mpsc::error::TrySendError::Full(())) => {}
        }
    }

    for _ in 0..4 {
        if !socket.can_send() {
            break;
        }
        if flow.pending_write.is_none() {
            match flow.from_application.try_recv() {
                Ok(bytes) => {
                    flow.pending_write = Some(PendingWrite { bytes, offset: 0 });
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        let Some(pending) = flow.pending_write.as_mut() else {
            break;
        };
        match socket.send_slice(&pending.bytes[pending.offset..]) {
            Ok(0) => break,
            Ok(length) => {
                pending.offset += length;
                flow.control.consume_queued_write_bytes(length);
                if pending.offset == pending.bytes.len() {
                    flow.pending_write = None;
                }
            }
            Err(_) => {
                socket.abort();
                break;
            }
        }
    }

    if flow.control.close_requested()
        && flow.control.queued_write_bytes() == 0
        && flow.pending_write.is_none()
    {
        socket.close();
    }

    if socket.state() == TcpState::TimeWait && flow.time_wait_since.is_none() {
        flow.time_wait_since = Some(std::time::Instant::now());
    }

    if flow.published && !socket.may_recv() && socket.recv_queue() == 0 {
        flow.to_application.take();
    }
    flow.control.set_socket_read_bytes(socket.recv_queue());
    let reset_finished = matches!(socket.state(), TcpState::Closed | TcpState::Listen)
        && socket.remote_endpoint().is_none();
    let time_wait_finished = flow
        .time_wait_since
        .is_some_and(|started| started.elapsed() >= tcp_config.two_msl);
    reset_finished || time_wait_finished
}

fn enqueue_network_packet(packet: NetworkPacket, device: &mut PacketDevice) -> super::Result<()> {
    let mut bytes = Vec::with_capacity(device.mtu);
    packet.write_to(&mut bytes)?;
    device.enqueue_egress(bytes)?;
    Ok(())
}

async fn write_packets<Writer>(
    mut writer: Writer,
    mut packets: mpsc::Receiver<Vec<u8>>,
    errors: mpsc::Sender<io::Error>,
    packet_information: bool,
) where
    Writer: AsyncWrite + Unpin,
{
    while let Some(packet) = packets.recv().await {
        let result = if packet_information && cfg!(unix) {
            write_packet_with_information(&mut writer, &packet).await
        } else {
            writer.write_all(&packet).await
        };
        if let Err(error) = result {
            let _ = errors.send(error).await;
            return;
        }
    }
}

async fn write_packet_with_information<Writer>(writer: &mut Writer, packet: &[u8]) -> io::Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    #[cfg(unix)]
    {
        let protocol = match packet.first().map(|byte| byte >> 4) {
            Some(4) => super::TUN_PROTO_IP4,
            Some(6) => super::TUN_PROTO_IP6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netstack emitted a non-IP packet",
                ));
            }
        };
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&super::TUN_FLAGS);
        framed.extend_from_slice(&protocol);
        framed.extend_from_slice(packet);
        writer.write_all(&framed).await
    }
    #[cfg(not(unix))]
    {
        writer.write_all(packet).await
    }
}
