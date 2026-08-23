//! Executable contract for transparent TCP accept over smoltcp.
//!
//! The isolated harness proves the one non-public seam the production actor depends on:
//! inspect a SYN, add an exact-destination listening socket, then give that same
//! packet to `Interface` without consuming it while egress is full.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
};

use etherparse::{
    IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, NetSlice, SlicedPacket, TcpHeader,
    TransportSlice,
};
use smoltcp::{
    iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, SocketHandle, SocketSet,
    },
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    time::{Duration, Instant},
    wire::HardwareAddress,
};

const TCP_RX_BUFFER_BYTES: usize = 16 * 1024;
const TCP_TX_BUFFER_BYTES: usize = 16 * 1024;
const TCP_SOCKET_BUFFER_BYTES: usize = TCP_RX_BUFFER_BYTES + TCP_TX_BUFFER_BYTES;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpTuple {
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
struct ParsedTcp {
    tuple: TcpTuple,
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
}

impl ParsedTcp {
    fn is_initial_syn(self) -> bool {
        self.syn && !self.ack && !self.rst && !self.fin
    }
}

fn parse_tcp(packet: &[u8]) -> Option<ParsedTcp> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    let tcp = match sliced.transport? {
        TransportSlice::Tcp(tcp) => tcp.to_header(),
        _ => return None,
    };
    let (src_ip, dst_ip) = match sliced.net? {
        NetSlice::Ipv4(ip) => {
            let header = ip.header().to_header();
            (header.source.into(), header.destination.into())
        }
        NetSlice::Ipv6(ip) => {
            let header = ip.header().to_header();
            (
                header.source_addr().into(),
                header.destination_addr().into(),
            )
        }
        NetSlice::Arp(_) => return None,
    };
    Some(ParsedTcp {
        tuple: TcpTuple {
            src: SocketAddr::new(src_ip, tcp.source_port),
            dst: SocketAddr::new(dst_ip, tcp.destination_port),
        },
        syn: tcp.syn,
        ack: tcp.ack,
        rst: tcp.rst,
        fin: tcp.fin,
    })
}

struct PacketDevice {
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    ingress_capacity: usize,
    egress_capacity: usize,
    mtu: usize,
}

impl PacketDevice {
    fn new(mtu: usize, ingress_capacity: usize, egress_capacity: usize) -> Self {
        assert!(ingress_capacity > 0);
        assert!(egress_capacity > 0);
        Self {
            ingress: VecDeque::with_capacity(ingress_capacity),
            egress: VecDeque::with_capacity(egress_capacity),
            ingress_capacity,
            egress_capacity,
            mtu,
        }
    }

    fn enqueue(&mut self, packet: Vec<u8>) -> Result<(), Vec<u8>> {
        if packet.len() > self.mtu || self.ingress.len() >= self.ingress_capacity {
            return Err(packet);
        }
        self.ingress.push_back(packet);
        Ok(())
    }

    fn dequeue_egress(&mut self) -> Option<Vec<u8>> {
        self.egress.pop_front()
    }

    fn ingress_len(&self) -> usize {
        self.ingress.len()
    }

    fn egress_len(&self) -> usize {
        self.egress.len()
    }

    fn prefill_egress(&mut self) {
        assert!(self.egress.len() < self.egress_capacity);
        self.egress.push_back(vec![0]);
    }

    fn has_egress_capacity(&self) -> bool {
        self.egress.len() < self.egress_capacity
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
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= self.mtu);
        let mut packet = vec![0; len];
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

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.has_egress_capacity() {
            return None;
        }
        let packet = self.ingress.pop_front()?;
        Some((
            PacketRxToken(packet),
            PacketTxToken {
                egress: &mut self.egress,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.has_egress_capacity().then_some(PacketTxToken {
            egress: &mut self.egress,
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

struct TransparentHarness {
    interface: Interface,
    sockets: SocketSet<'static>,
    device: PacketDevice,
    flows: HashMap<TcpTuple, SocketHandle>,
    max_flows: usize,
    memory_budget: usize,
    allocated_buffer_bytes: usize,
    now_ms: i64,
}

impl TransparentHarness {
    fn new(max_flows: usize, memory_budget: usize, egress_capacity: usize) -> Self {
        let mut device = PacketDevice::new(1400, 8, egress_capacity);
        let mut config = InterfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = 0x5a17_2026;
        let mut interface = Interface::new(config, &mut device, Instant::ZERO);
        interface.set_any_ip(true);
        Self {
            interface,
            sockets: SocketSet::new(Vec::new()),
            device,
            flows: HashMap::new(),
            max_flows,
            memory_budget,
            allocated_buffer_bytes: 0,
            now_ms: 0,
        }
    }

    fn inject(&mut self, packet: Vec<u8>) -> Option<SocketHandle> {
        let parsed = parse_tcp(&packet).expect("test packet must be TCP");
        let handle = self.flows.get(&parsed.tuple).copied().or_else(|| {
            if !parsed.is_initial_syn()
                || self.flows.len() >= self.max_flows
                || TCP_SOCKET_BUFFER_BYTES
                    > self
                        .memory_budget
                        .saturating_sub(self.allocated_buffer_bytes)
            {
                return None;
            }

            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0; TCP_RX_BUFFER_BYTES]),
                TcpSocketBuffer::new(vec![0; TCP_TX_BUFFER_BYTES]),
            );
            socket.set_congestion_control(CongestionControl::Reno);
            socket.set_timeout(Some(Duration::from_secs(60)));
            socket
                .listen(parsed.tuple.dst)
                .expect("exact transparent listen endpoint");
            let handle = self.sockets.add(socket);
            self.flows.insert(parsed.tuple, handle);
            self.allocated_buffer_bytes += TCP_SOCKET_BUFFER_BYTES;
            Some(handle)
        });

        self.device
            .enqueue(packet)
            .expect("bounded test ingress has capacity");
        self.pump_one();
        handle
    }

    fn pump_one(&mut self) -> PollIngressSingleResult {
        self.now_ms += 1;
        let now = Instant::from_millis(self.now_ms);
        self.interface.poll_maintenance(now);
        let result = self
            .interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        let _ = self
            .interface
            .poll_egress(now, &mut self.device, &mut self.sockets);
        result
    }

    fn state(&self, handle: SocketHandle) -> TcpState {
        self.sockets.get::<TcpSocket<'static>>(handle).state()
    }
}

#[derive(Debug)]
struct SeenTcp {
    tuple: TcpTuple,
    sequence: u32,
    acknowledgement: u32,
    syn: bool,
    ack: bool,
    rst: bool,
}

fn seen_tcp(packet: &[u8]) -> SeenTcp {
    let parsed = SlicedPacket::from_ip(packet).expect("emitted IP packet");
    let tcp = match parsed.transport.expect("emitted transport") {
        TransportSlice::Tcp(tcp) => tcp.to_header(),
        _ => panic!("emitted packet is not TCP"),
    };
    let parsed_tcp = parse_tcp(packet).expect("emitted TCP tuple");
    SeenTcp {
        tuple: parsed_tcp.tuple,
        sequence: tcp.sequence_number,
        acknowledgement: tcp.acknowledgment_number,
        syn: tcp.syn,
        ack: tcp.ack,
        rst: tcp.rst,
    }
}

fn tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    flags: u8,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const PSH: u8 = 0x08;
    const ACK: u8 = 0x10;
    const FIN: u8 = 0x01;

    let mut tcp = TcpHeader::new(src.port(), dst.port(), sequence, u16::MAX);
    tcp.acknowledgment_number = acknowledgement;
    tcp.syn = flags & SYN != 0;
    tcp.rst = flags & RST != 0;
    tcp.psh = flags & PSH != 0;
    tcp.ack = flags & ACK != 0;
    tcp.fin = flags & FIN != 0;

    let mut packet = Vec::new();
    match (src.ip(), dst.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut ip = Ipv4Header::new(
                (tcp.header_len() + payload.len()) as u16,
                64,
                IpNumber::TCP,
                src.octets(),
                dst.octets(),
            )
            .expect("IPv4 payload length");
            ip.dont_fragment = true;
            tcp.checksum = tcp
                .calc_checksum_ipv4(&ip, payload)
                .expect("IPv4 TCP checksum");
            ip.write(&mut packet).expect("write IPv4 header");
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Ipv6FlowLabel::ZERO,
                payload_length: (tcp.header_len() + payload.len()) as u16,
                next_header: IpNumber::TCP,
                hop_limit: 64,
                source: src.octets(),
                destination: dst.octets(),
            };
            tcp.checksum = tcp
                .calc_checksum_ipv6(&ip, payload)
                .expect("IPv6 TCP checksum");
            ip.write(&mut packet).expect("write IPv6 header");
        }
        _ => panic!("IP version mismatch"),
    }
    tcp.write(&mut packet).expect("write TCP header");
    packet.extend_from_slice(payload);
    packet
}

fn completes_handshake(client: SocketAddr, server: SocketAddr) {
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    let mut harness = TransparentHarness::new(4, 4 * TCP_SOCKET_BUFFER_BYTES, 4);
    let client_sequence = 0x1020_3040;
    let handle = harness
        .inject(tcp_packet(client, server, SYN, client_sequence, 0, &[]))
        .expect("SYN must reserve one socket");

    assert_eq!(harness.allocated_buffer_bytes, TCP_SOCKET_BUFFER_BYTES);
    assert_eq!(harness.state(handle), TcpState::SynReceived);
    let reply = seen_tcp(
        &harness
            .device
            .dequeue_egress()
            .expect("SYN must produce SYN-ACK"),
    );
    assert_eq!(reply.tuple.src, server);
    assert_eq!(reply.tuple.dst, client);
    assert!(reply.syn && reply.ack && !reply.rst);
    assert_eq!(reply.acknowledgement, client_sequence.wrapping_add(1));

    let ack = tcp_packet(
        client,
        server,
        ACK,
        client_sequence.wrapping_add(1),
        reply.sequence.wrapping_add(1),
        &[],
    );
    assert_eq!(harness.inject(ack), Some(handle));
    assert_eq!(harness.state(handle), TcpState::Established);
}

#[test]
fn arbitrary_ipv4_destination_can_be_accepted_transparently() {
    completes_handshake(
        "10.0.0.2:49152".parse().unwrap(),
        "203.0.113.77:443".parse().unwrap(),
    );
}

#[test]
fn arbitrary_ipv6_destination_can_be_accepted_transparently() {
    completes_handshake(
        "[fd00::2]:49152".parse().unwrap(),
        "[2001:db8:42::77]:443".parse().unwrap(),
    );
}

#[test]
fn retransmitted_syn_reuses_the_reserved_socket() {
    const SYN: u8 = 0x02;
    let client = "10.0.0.2:49152".parse().unwrap();
    let server = "198.51.100.8:8443".parse().unwrap();
    let syn = tcp_packet(client, server, SYN, 700, 0, &[]);
    let mut harness = TransparentHarness::new(2, 2 * TCP_SOCKET_BUFFER_BYTES, 2);
    let handle = harness.inject(syn.clone()).unwrap();
    let _ = harness.device.dequeue_egress().unwrap();

    assert_eq!(harness.inject(syn), Some(handle));
    assert_eq!(harness.flows.len(), 1);
    assert_eq!(harness.allocated_buffer_bytes, TCP_SOCKET_BUFFER_BYTES);
    harness.now_ms += 1_000;
    let _ = harness.pump_one();
    let retransmit = seen_tcp(&harness.device.dequeue_egress().expect("repeated SYN-ACK"));
    assert!(retransmit.syn && retransmit.ack && !retransmit.rst);
}

#[test]
fn exhausted_admission_is_reset_without_allocating_a_socket() {
    const SYN: u8 = 0x02;
    let client = "10.0.0.2:49152".parse().unwrap();
    let server = "192.0.2.9:443".parse().unwrap();
    let mut harness = TransparentHarness::new(4, 0, 2);

    assert!(
        harness
            .inject(tcp_packet(client, server, SYN, 900, 0, &[]))
            .is_none()
    );
    assert!(harness.flows.is_empty());
    assert_eq!(harness.allocated_buffer_bytes, 0);
    let refusal = seen_tcp(&harness.device.dequeue_egress().expect("RST refusal"));
    assert!(refusal.rst && refusal.ack && !refusal.syn);
    assert_eq!(refusal.acknowledgement, 901);
}

#[test]
fn full_egress_keeps_the_syn_in_ingress_until_a_slot_exists() {
    const SYN: u8 = 0x02;
    let client = "10.0.0.2:49152".parse().unwrap();
    let server = "203.0.113.1:443".parse().unwrap();
    let mut harness = TransparentHarness::new(1, TCP_SOCKET_BUFFER_BYTES, 1);
    harness.device.prefill_egress();

    let handle = harness
        .inject(tcp_packet(client, server, SYN, 1_000, 0, &[]))
        .expect("socket admission is independent of writer progress");
    assert_eq!(harness.device.ingress_len(), 1);
    assert_eq!(harness.device.egress_len(), 1);
    assert_eq!(harness.state(handle), TcpState::Listen);

    let _ = harness.device.dequeue_egress().expect("remove blocker");
    assert!(matches!(
        harness.pump_one(),
        PollIngressSingleResult::SocketStateChanged
    ));
    assert_eq!(harness.device.ingress_len(), 0);
    assert_eq!(harness.state(handle), TcpState::SynReceived);
    let reply = seen_tcp(&harness.device.dequeue_egress().expect("deferred SYN-ACK"));
    assert!(reply.syn && reply.ack && !reply.rst);
}

#[test]
fn packet_device_ingress_is_bounded_exactly() {
    let mut device = PacketDevice::new(1400, 2, 1);
    assert!(device.enqueue(vec![0; 40]).is_ok());
    assert!(device.enqueue(vec![0; 40]).is_ok());
    assert!(device.enqueue(vec![0; 40]).is_err());
    assert_eq!(device.ingress_len(), 2);
}
