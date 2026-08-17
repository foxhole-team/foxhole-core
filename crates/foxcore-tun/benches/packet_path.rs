//! Per-packet cost of the two data paths that carry every byte the app sends:
//! the L3 WireGuard path and the userspace stack hop.
//!
//! These are baselines, not fixes. Each one is written to allocate and copy
//! exactly the way the production caller does, so the number can be quoted
//! against a later change; where a path is private and cannot be called from a
//! benchmark crate, the benchmark reproduces the exact statement and says so.
//!
//! `flow_key_from_packet` is here as the control. It is already allocation-free,
//! so it is what the rest of the per-packet work should be compared against.

#![forbid(unsafe_code)]

use std::hint::black_box;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use foxcore_tun::{FlowKey, PacketArena, StackDevice};
use proto_wireguard::amnezia::AmneziaParams;
use proto_wireguard::message::Initiation;
use proto_wireguard::noise::test_support::Responder;
use proto_wireguard::noise::{Key, TransportKeys, public_key};
use proto_wireguard::session::TransportSession;
use proto_wireguard::tunnel::{Entropy, PeerSettings, PeerTimers, PeerTunnel};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Inner packet sizes: a bare ACK-sized frame and a full one behind a 1500-byte
/// MTU. The allocation counts do not change with size; the copy costs do.
const SIZES: [usize; 2] = [64, 1420];

const CLIENT_STATIC: Key = [7_u8; 32];
const SERVER_STATIC: Key = [9_u8; 32];
const SERVER_EPHEMERAL: Key = [11_u8; 32];

/// Deterministic filler. Benchmarks must not have the OS RNG in the measured
/// loop, and the handshake this drives happens once during setup anyway.
struct CountingEntropy(u8);

impl Entropy for CountingEntropy {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), proto_wireguard::WireguardError> {
        for byte in buffer {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

/// A well-formed IPv4/UDP packet of exactly `total` bytes.
fn ipv4_udp_packet(total: usize) -> Vec<u8> {
    assert!(total >= 28);
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
    packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
    packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((total - 20) as u16).to_be_bytes());
    packet
}

/// A well-formed IPv6/TCP packet of exactly `total` bytes.
fn ipv6_tcp_packet(total: usize) -> Vec<u8> {
    assert!(total >= 60);
    let mut packet = vec![0_u8; total];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet[24..40].copy_from_slice(&[
        0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
    ]);
    packet[40..42].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
    packet
}

/// What `PacketTunnelRelay::run` hands `receive_datagram` as its output: the
/// buffer the decrypted packet will be sent to the tun in. Reproduced here
/// because the relay's own copy of it is private.
struct ArenaSink<'a> {
    arena: &'a mut PacketArena,
    packet: BytesMut,
}

impl<'a> ArenaSink<'a> {
    fn new(arena: &'a mut PacketArena) -> Self {
        Self {
            arena,
            packet: BytesMut::new(),
        }
    }

    fn into_packet(self) -> BytesMut {
        self.packet
    }
}

impl proto_wireguard::tunnel::PacketOut for ArenaSink<'_> {
    fn put_packet(&mut self, packet: &[u8]) {
        self.packet = self.arena.copy_in(packet);
    }
}

/// A tunnel with a live session, plus the peer session that decrypts what it
/// sends and seals what it should receive.
///
/// The handshake runs here rather than inside the measured loop: it is a
/// once-per-two-minutes cost and would drown the per-packet number it is meant
/// to establish.
fn live_tunnel() -> (PeerTunnel, TransportSession) {
    let settings = PeerSettings {
        private_key: CLIENT_STATIC,
        peer_public_key: public_key(&SERVER_STATIC).unwrap(),
        preshared_key: None,
        amnezia: AmneziaParams::default(),
        persistent_keepalive_s: None,
        reserved: [0, 0, 0],
        init_packets: Vec::new(),
        timers: PeerTimers::default(),
    };
    let mut tunnel = PeerTunnel::new(settings, Box::new(CountingEntropy(0))).unwrap();
    tunnel.send_packet(&ipv4_udp_packet(64), 0).unwrap();

    let mut initiation_bytes = Vec::new();
    assert!(tunnel.poll_transmit(&mut initiation_bytes).is_some());
    let initiation = Initiation::decode(&initiation_bytes).unwrap();
    let responder = Responder::new(&SERVER_STATIC, [0; 32]).unwrap();
    let (response, server_send, server_receive) = responder
        .respond(&initiation, &SERVER_EPHEMERAL, 0xABCD)
        .unwrap();

    let mut datagram = response.encode().to_vec();
    let mut out = Vec::new();
    tunnel.receive_datagram(&mut datagram, 0, &mut out).unwrap();
    // The packet that started the handshake is now sealed and queued; drain it
    // so the measured loop starts from an empty transmit queue.
    let mut drained = Vec::new();
    while tunnel.poll_transmit(&mut drained).is_some() {}

    let peer = TransportSession::new(TransportKeys {
        send: server_send,
        receive: server_receive,
        sender_index: 0xABCD,
        receiver_index: initiation.sender_index,
    });
    (tunnel, peer)
}

/// The whole outbound L3 path for one packet: `send_packet` seals it (padded
/// copy plus the AEAD's own `Vec`), obfuscates it, and `poll_transmit` moves
/// that out.
///
/// Three arms, one per allocation that used to be on this path.
///
/// `send_packet` used to take the packet by value and the relay therefore had to
/// own a fresh `Vec` for every packet it read off the tun.
/// `owned_packet_per_send` is that caller — the clone stands for the allocation
/// `read_tun` was making — and `borrowed_packet` is the one that hands over a
/// slice of a buffer it keeps. The gap between them is the allocation the
/// signature change removed, and it is the same removal `tun_read_hand_off`
/// measures from the other end: they are two views of one saving, not two
/// savings.
///
/// `fresh_datagram_buffer` is the other end of the same connection, and it
/// reproduces the *old* `poll_transmit` exactly rather than describing it.
/// `poll_transmit` used to assign, which dropped whatever buffer the caller was
/// holding, so the next `seal` allocated a replacement — one malloc and one free
/// per packet, forever. It now swaps and recycles, so a caller that keeps its
/// buffer (`borrowed_packet`) cycles a fixed pair. A caller that hands in a
/// *fresh empty* `Vec` each time gives the tunnel nothing worth recycling, which
/// puts the allocator back in the loop precisely as the old code did. The gap
/// between those two arms is the saving, measured inside one run.
fn wireguard_outbound(c: &mut Criterion) {
    let mut group = c.benchmark_group("wireguard_outbound");
    for size in SIZES {
        let packet = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("send_packet_and_poll_transmit/{size}b"), |b| {
            let (mut tunnel, _peer) = live_tunnel();
            let mut datagram = Vec::new();
            b.iter(|| {
                let owned = black_box(packet.clone());
                tunnel.send_packet(&owned, 0).unwrap();
                while tunnel.poll_transmit(&mut datagram).is_some() {
                    black_box(&datagram);
                }
            });
        });
        group.bench_function(format!("borrowed_packet/{size}b"), |b| {
            let (mut tunnel, _peer) = live_tunnel();
            let mut datagram = Vec::new();
            b.iter(|| {
                tunnel.send_packet(black_box(&packet), 0).unwrap();
                while tunnel.poll_transmit(&mut datagram).is_some() {
                    black_box(&datagram);
                }
            });
        });
        group.bench_function(format!("fresh_datagram_buffer/{size}b"), |b| {
            let (mut tunnel, _peer) = live_tunnel();
            b.iter(|| {
                tunnel.send_packet(black_box(&packet), 0).unwrap();
                // The old shape: the caller's buffer is not carried between
                // packets, so nothing usable comes back to the tunnel and every
                // `seal` allocates. The `Vec` this arm drops at the end of the
                // iteration is the free the old `poll_transmit` performed.
                let mut datagram = Vec::new();
                while tunnel.poll_transmit(&mut datagram).is_some() {
                    black_box(&datagram);
                }
            });
        });
    }
    group.finish();
}

/// The inbound L3 path, in the three shapes that matter.
///
/// `PacketTunnelRelay::run` used to hand the decrypted packet onward with
/// `std::mem::take`, which left the buffer at zero capacity so the next packet's
/// `out.extend_from_slice` regrew it from nothing — one allocation per packet.
/// `receive_datagram_retained_buffer` is the same call with the buffer left in
/// place: not a fix, but the floor that says what the `mem::take` line was
/// worth. `receive_datagram_into_arena` is what the relay does now — the
/// decrypted packet is written straight into the chunk it will be sent to the
/// tun in, so it is handed on without either the allocation or a second copy.
fn wireguard_inbound(c: &mut Criterion) {
    let mut group = c.benchmark_group("wireguard_inbound");
    for size in SIZES {
        let packet = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("receive_datagram_into_arena/{size}b"), |b| {
            let (mut tunnel, mut peer) = live_tunnel();
            let mut arena = PacketArena::new(2048);
            b.iter_batched(
                || {
                    let mut sealed = Vec::new();
                    peer.seal(&packet, &mut sealed).unwrap();
                    sealed
                },
                |mut sealed| {
                    let mut sink = ArenaSink::new(&mut arena);
                    tunnel
                        .receive_datagram(black_box(&mut sealed), 0, &mut sink)
                        .unwrap();
                    black_box(sink.into_packet())
                },
                BatchSize::PerIteration,
            );
        });

        group.bench_function(format!("receive_datagram_then_mem_take/{size}b"), |b| {
            let (mut tunnel, mut peer) = live_tunnel();
            let mut decrypted = Vec::new();
            b.iter_batched(
                || {
                    // A fresh datagram per iteration: `receive_datagram`
                    // decrypts in place and the replay window refuses a counter
                    // twice.
                    let mut sealed = Vec::new();
                    peer.seal(&packet, &mut sealed).unwrap();
                    sealed
                },
                |mut sealed| {
                    decrypted.clear();
                    tunnel
                        .receive_datagram(black_box(&mut sealed), 0, &mut decrypted)
                        .unwrap();
                    black_box(std::mem::take(&mut decrypted))
                },
                // Per iteration, not per batch: a batch of 1420-byte datagrams
                // is megabytes of cold memory and would measure the cache miss
                // rather than the path. Both variants pay the same timer
                // overhead, so the gap between them stays honest.
                BatchSize::PerIteration,
            );
        });

        group.bench_function(format!("receive_datagram_retained_buffer/{size}b"), |b| {
            let (mut tunnel, mut peer) = live_tunnel();
            let mut decrypted = Vec::new();
            b.iter_batched(
                || {
                    let mut sealed = Vec::new();
                    peer.seal(&packet, &mut sealed).unwrap();
                    sealed
                },
                |mut sealed| {
                    decrypted.clear();
                    tunnel
                        .receive_datagram(black_box(&mut sealed), 0, &mut decrypted)
                        .unwrap();
                    black_box(decrypted.len())
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// One packet through the userspace stack hop, end to end.
///
/// Three copies, in the order the packet meets them: the tun reader's, then
/// `StackDevice::poll_read` copying into the stack's buffer, then the device's
/// own on the way back to the tun writer. All three are still copies; two of
/// them used to allocate as well.
///
/// `one_packet_three_copies` is the shape before the change — a `Vec` channel,
/// `buffer[..length].to_vec()` standing for the tun reader, and `buf.to_vec()`
/// where the device wrote back. `StackDevice` no longer has that shape, so
/// those two statements are reproduced here rather than called; everything
/// around them — the same `PollSender`, the same `poll_recv`, the same buffer
/// sizes — is shared with the arm below so the gap is only the allocations.
///
/// `arena_backed` is the current path: the real `StackDevice`, fed the way
/// `classify` feeds it. The producing line pays one copy in both arms
/// (`to_vec` before, `copy_in` now), which is one copy more than the real tun
/// reader pays — it reads straight into the arena. So this is the floor of the
/// saving, and `tun_read_hand_off` measures the rest of it.
fn stack_hop(c: &mut Criterion) {
    let mut group = c.benchmark_group("stack_hop");
    let waker = Waker::noop();
    for size in SIZES {
        let tun_buffer = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("one_packet_three_copies/{size}b"), |b| {
            let (to_stack, mut stack_inbox) = mpsc::channel::<Vec<u8>>(4);
            let (tun_writer, mut tun_outbox) = mpsc::channel::<Vec<u8>>(4);
            let mut outbox = tokio_util::sync::PollSender::new(tun_writer);
            let mut stack_buffer = vec![0_u8; 2048];
            b.iter(|| {
                let mut cx = Context::from_waker(waker);
                to_stack
                    .try_send(black_box(&tun_buffer[..size]).to_vec())
                    .unwrap();

                // `StackDevice::poll_read`, as it was and still is.
                let mut read = ReadBuf::new(&mut stack_buffer);
                let Poll::Ready(Some(packet)) = stack_inbox.poll_recv(&mut cx) else {
                    unreachable!("a packet was just queued for the stack")
                };
                let length = packet.len().min(read.remaining());
                read.put_slice(&packet[..length]);
                drop(packet);

                // `StackDevice::poll_write`, as it was: a fresh `Vec` per
                // packet for the tun writer.
                let Poll::Ready(Ok(())) = outbox.poll_reserve(&mut cx) else {
                    unreachable!("the tun writer channel has room")
                };
                outbox.send_item(read.filled()[..length].to_vec()).unwrap();
                black_box(tun_outbox.try_recv().unwrap());
            });
        });

        group.bench_function(format!("arena_backed/{size}b"), |b| {
            let (to_stack, stack_inbox) = mpsc::channel::<BytesMut>(4);
            let (tun_writer, mut tun_outbox) = mpsc::channel::<BytesMut>(4);
            let mut device = StackDevice::new(stack_inbox, tun_writer, 1500);
            let mut reads = PacketArena::new(1464);
            let mut stack_buffer = vec![0_u8; 2048];
            b.iter(|| {
                let mut cx = Context::from_waker(waker);
                to_stack
                    .try_send(reads.copy_in(black_box(&tun_buffer[..size])))
                    .unwrap();

                let mut read = ReadBuf::new(&mut stack_buffer);
                let Poll::Ready(Ok(())) = Pin::new(&mut device).poll_read(&mut cx, &mut read)
                else {
                    unreachable!("a packet was just queued for the stack")
                };
                let length = read.filled().len();

                let Poll::Ready(Ok(written)) =
                    Pin::new(&mut device).poll_write(&mut cx, &read.filled()[..length])
                else {
                    unreachable!("the tun writer channel has room")
                };
                black_box(written);
                black_box(tun_outbox.try_recv().unwrap());
            });
        });
    }
    group.finish();
}

/// The tun reader's copy on its own: `buffer[..length].to_vec()` before the
/// channel send. `read_tun` is private and needs a real descriptor, so this is
/// that one statement rather than a call into it.
fn tun_read_to_vec(c: &mut Criterion) {
    let mut group = c.benchmark_group("tun_read_to_vec");
    for size in SIZES {
        let buffer = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}b"), |b| {
            b.iter(|| black_box(black_box(&buffer[..size]).to_vec()));
        });
    }
    group.finish();
}

/// A descriptor that answers every read with the same packet. It copies into
/// whatever buffer it is handed, which is what the kernel does on a real tun
/// read — so both arms below pay that copy exactly once and the gap between
/// them is only what the reader adds on top of it.
struct OnePacket<'a>(&'a [u8]);

impl AsyncRead for OnePacket<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let length = self.0.len().min(buf.remaining());
        buf.put_slice(&self.0[..length]);
        Poll::Ready(Ok(()))
    }
}

/// What one packet costs between the tun descriptor and the classifier.
///
/// `reused_buffer_then_to_vec` is what `read_tun` did: read into a buffer it
/// keeps, then allocate and copy `buffer[..length].to_vec()` for the channel —
/// so the packet is copied twice, once by the kernel and once again for the
/// hand-off. `arena` is what it does now: the descriptor writes straight into
/// the chunk the packet travels in, and the split off it costs a refcount
/// rather than an allocation.
///
/// Both arms drive the same descriptor and the same channel, in the same run,
/// and both go through a pinned future — `AsyncReadExt::read` on one side,
/// `PacketArena::read_packet` on the other — because `read_tun` awaits one in
/// either world and polling the descriptor directly on one side only would
/// charge that machinery to the arena alone.
fn tun_read_hand_off(c: &mut Criterion) {
    let mut group = c.benchmark_group("tun_read_hand_off");
    let waker = Waker::noop();
    for size in SIZES {
        let packet = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("reused_buffer_then_to_vec/{size}b"), |b| {
            let mut reader = OnePacket(&packet);
            let (to_ingress, mut from_tun) = mpsc::channel::<Vec<u8>>(4);
            let mut buffer = vec![0_u8; 1464];
            b.iter(|| {
                let mut cx = Context::from_waker(waker);
                let read = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer);
                let mut read = std::pin::pin!(read);
                let Poll::Ready(Ok(length)) = read.as_mut().poll(&mut cx) else {
                    unreachable!("this descriptor is always ready")
                };
                to_ingress.try_send(buffer[..length].to_vec()).unwrap();
                black_box(from_tun.try_recv().unwrap());
            });
        });

        group.bench_function(format!("arena/{size}b"), |b| {
            let mut reader = OnePacket(&packet);
            let (to_ingress, mut from_tun) = mpsc::channel::<BytesMut>(4);
            let mut arena = PacketArena::new(1464);
            b.iter(|| {
                let mut cx = Context::from_waker(waker);
                let read = arena.read_packet(&mut reader);
                let mut read = std::pin::pin!(read);
                let Poll::Ready(Ok(Some(packet))) = read.as_mut().poll(&mut cx) else {
                    unreachable!("this descriptor is always ready")
                };
                to_ingress.try_send(packet).unwrap();
                black_box(from_tun.try_recv().unwrap());
            });
        });
    }
    group.finish();
}

/// The control: parsing the 5-tuple out of a packet allocates nothing and reads
/// a fixed number of header bytes. Everything above is measured against this.
fn flow_key_from_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("flow_key_from_packet");
    let ipv4 = ipv4_udp_packet(1420);
    let ipv6 = ipv6_tcp_packet(1420);
    group.bench_function("ipv4_udp", |b| {
        b.iter(|| black_box(FlowKey::from_packet(black_box(&ipv4))));
    });
    group.bench_function("ipv6_tcp", |b| {
        b.iter(|| black_box(FlowKey::from_packet(black_box(&ipv6))));
    });
    group.finish();
}

criterion_group!(
    benches,
    wireguard_outbound,
    wireguard_inbound,
    stack_hop,
    tun_read_to_vec,
    tun_read_hand_off,
    flow_key_from_packet
);
criterion_main!(benches);
