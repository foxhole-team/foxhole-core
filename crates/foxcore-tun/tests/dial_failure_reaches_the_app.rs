//! What the app sees when the flow it opened cannot be dialled.
//!
//! The netem lab asked a question no unit test had: a destination that refuses,
//! or that is behind a black hole, produces `dial_errors` in the core's
//! counters — but what reaches the application? The measured answer was
//! *nothing*. `curl` through the tunnel completed its connect in 0.6 ms and then
//! sat there until its own `--max-time` fired twelve seconds later, because the
//! userspace stack had already answered the SYN and the core abandoned the
//! session without telling the other end.
//!
//! `ipstack 1.0.0` does not close on drop: `impl Drop for IpStackTcpStream`
//! tears down the session task and sends no FIN and no RST. So a flow the core
//! gave up on stays, from the app's side, an established connection that will
//! never answer — the exact shape of "the app hangs" rather than "connection
//! refused".
//!
//! This drives the real engine over a duplex device, sends one SYN for a port
//! that is closed, and asks for the close to come back. It is written against
//! the packet, not against a counter, because the counter was already right.

use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

use foxcore_api::{DnsConfig, EventSink, FlowAttributor, RouteAction, RuntimeConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_tun::{
    ConnectionTracker, FlowEngine, FlowEngineContext, FlowMetrics, FlowPolicyStore, FlowSnapshot,
    TunDevice,
};
use tokio_util::sync::CancellationToken;

const IPV4_HEADER: usize = 20;
const TCP_HEADER: usize = 20;
const PROTOCOL_TCP: u8 = 6;
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const CLIENT_PORT: u16 = 49_152;

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;

/// RFC 1071, written out rather than reused from the production path so the
/// packet this test injects is checked by different arithmetic than the one the
/// core uses to read it.
fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(u16::from_be_bytes([last, 0]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4/TCP segment with no payload and no options.
fn segment(destination_port: u16, flags: u8, sequence: u32, acknowledgement: u32) -> Vec<u8> {
    let total = (IPV4_HEADER + TCP_HEADER) as u16;
    let mut ip = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x01,
        0x40,
        0x00,
        64,
        PROTOCOL_TCP,
        0x00,
        0x00,
    ];
    ip.extend_from_slice(&CLIENT.octets());
    ip.extend_from_slice(&SERVER.octets());
    let header_checksum = internet_checksum(&[&ip]);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let mut tcp = Vec::with_capacity(TCP_HEADER);
    tcp.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    tcp.extend_from_slice(&destination_port.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&acknowledgement.to_be_bytes());
    // Data offset 5 words, no options.
    tcp.push(0x50);
    tcp.push(flags);
    tcp.extend_from_slice(&65_535_u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]); // checksum, filled below
    tcp.extend_from_slice(&[0, 0]); // urgent pointer

    let pseudo = {
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&CLIENT.octets());
        pseudo.extend_from_slice(&SERVER.octets());
        pseudo.push(0);
        pseudo.push(PROTOCOL_TCP);
        pseudo.extend_from_slice(&(TCP_HEADER as u16).to_be_bytes());
        pseudo
    };
    let tcp_checksum = internet_checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    ip.extend_from_slice(&tcp);
    ip
}

/// Flags and sequence number of a TCP segment addressed to our client port.
///
/// The sequence number matters: the stack picks a random ISN, and an ACK that
/// does not name it leaves the session short of `Established` — which is the
/// one state `ipstack`'s `poll_shutdown` will send a FIN from. A test that
/// hard-codes the acknowledgement passes or fails on the stack's choice of
/// starting number rather than on the behaviour under test.
fn tcp_for_client(packet: &[u8]) -> Option<(u8, u32)> {
    if packet.len() < IPV4_HEADER + TCP_HEADER || packet[0] >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if packet[9] != PROTOCOL_TCP || packet.len() < header_length + TCP_HEADER {
        return None;
    }
    let tcp = &packet[header_length..];
    let destination_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let sequence = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    (destination_port == CLIENT_PORT).then_some((tcp[13], sequence))
}

/// A port nobody is listening on.
///
/// Bound and released rather than picked as a constant: a hard-coded port is a
/// test that passes until the day something on the machine happens to hold it,
/// and then fails for a reason that has nothing to do with the core.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind((SERVER, 0)).expect("bind a port to release it");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

fn engine(metrics: Arc<FlowMetrics>) -> FlowEngine {
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            EventSink::none(),
        )
        .expect("policy"),
    );
    FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics,
        events: EventSink::none(),
        packet_tunnel: false,
        connections: Arc::new(ConnectionTracker::default()),
    })
}

/// A dial that fails has to close the session it was opened for.
///
/// Multi-thread on purpose: `ipstack`'s `Drop` blocks on its session task
/// through `block_in_place`, which is not available on a current-thread
/// runtime — the same property that makes abandoning a stream more expensive
/// than closing it.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_whose_dial_fails_is_closed_towards_the_app() {
    let metrics = Arc::new(FlowMetrics::default());
    let engine = engine(metrics.clone());
    // A datagram socketpair, not a pipe: the device the engine reads is a
    // packet boundary per read, and a stream would hand it two segments glued
    // together the first time the timing was unlucky.
    let (app, device) = UnixDatagram::pair().expect("socketpair");
    app.set_nonblocking(true).expect("nonblocking");
    let app = tokio::net::UnixDatagram::from_std(app).expect("register the app side");
    let (device, _tun_fd_owner) =
        TunDevice::from_owned_fd(OwnedFd::from(device)).expect("wrap the device side");
    let cancel = CancellationToken::new();
    let engine_cancel = cancel.clone();
    let running = tokio::spawn(async move { engine.run(device, 1500, engine_cancel).await });

    let port = closed_port();
    app.send(&segment(port, FLAG_SYN, 1_000, 0))
        .await
        .expect("inject the SYN");

    // The handshake, then the close. Only the second is in question: the stack
    // answers the SYN before the core has dialled anything, which is exactly why
    // an abandoned dial is invisible to the app.
    let mut saw_syn_ack = false;
    let mut saw_close = false;
    let mut buffer = [0_u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline && !saw_close {
        let read = match tokio::time::timeout_at(deadline, app.recv(&mut buffer)).await {
            Ok(Ok(read)) if read != 0 => read,
            _ => break,
        };
        let Some((flags, sequence)) = tcp_for_client(&buffer[..read]) else {
            continue;
        };
        if flags & FLAG_SYN != 0 && flags & FLAG_ACK != 0 {
            saw_syn_ack = true;
            // Complete the handshake so the session is Established and the core
            // reaches its dial; a half-open session would prove nothing.
            app.send(&segment(port, FLAG_ACK, 1_001, sequence.wrapping_add(1)))
                .await
                .expect("finish the handshake");
        }
        if flags & (FLAG_FIN | FLAG_RST) != 0 {
            saw_close = true;
        }
    }

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), running).await;

    assert!(saw_syn_ack, "the stack must answer the SYN");
    let snapshot: FlowSnapshot = metrics.snapshot();
    assert_eq!(
        snapshot.dial_errors, 1,
        "the dial to a closed port must have failed"
    );
    assert!(
        saw_close,
        "a flow the core gave up on must be closed towards the app; without it the \
         application sees an established connection that never answers, and waits for \
         its own timeout instead of a refusal"
    );
}
