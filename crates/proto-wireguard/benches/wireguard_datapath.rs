//! Per-packet cost of the WireGuard transforms.
//!
//! These exist because the project claims speed and had no number attached to
//! that claim, which makes any later "this is faster" unfalsifiable. Nothing
//! here is tuned or fixed — the numbers are the baseline a change has to beat,
//! and they are recorded with the machine they came from.
//!
//! Each benchmark is written to allocate exactly the way the production caller
//! does. `session_seal` takes a fresh `Vec` per packet because
//! `PeerTunnel::flush_pending` does; measuring it against a reused buffer would
//! quietly benchmark a change nobody has made yet.

#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use proto_wireguard::amnezia::{AmneziaParams, HeaderRange};
use proto_wireguard::message::{TRANSPORT_HEADER_LEN, TYPE_TRANSPORT};
use proto_wireguard::noise::TransportKeys;
use proto_wireguard::session::TransportSession;

/// Inner packet sizes: a bare ACK-sized frame and a full one behind a 1500-byte
/// MTU. The allocation counts are the same; the copy costs are not, and a
/// baseline taken at one size only would hide that.
const SIZES: [usize; 2] = [64, 1420];

/// Two sessions keyed so that what one seals the other opens.
fn session_pair() -> (TransportSession, TransportSession) {
    let client = TransportKeys {
        send: [0x11; 32],
        receive: [0x22; 32],
        sender_index: 1,
        receiver_index: 2,
    };
    let server = TransportKeys {
        send: [0x22; 32],
        receive: [0x11; 32],
        sender_index: 2,
        receiver_index: 1,
    };
    (TransportSession::new(client), TransportSession::new(server))
}

/// A well-formed IPv4/UDP packet of exactly `total` bytes. `ip_packet_len` reads
/// the header to find the payload inside WireGuard's padding, so a packet whose
/// declared length is wrong is dropped rather than measured.
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

/// A transport frame as it leaves `TransportSession::seal`, for the obfuscation
/// benchmarks that need one without paying for the AEAD.
fn transport_frame(payload: usize) -> Vec<u8> {
    let mut frame = vec![0_u8; TRANSPORT_HEADER_LEN + payload];
    frame[0] = TYPE_TRANSPORT;
    frame[4..8].copy_from_slice(&0xABCD_u32.to_le_bytes());
    frame
}

fn tuned_params() -> AmneziaParams {
    AmneziaParams {
        junk_packet_count: 4,
        junk_min_size: 10,
        junk_max_size: 50,
        init_junk_size: 20,
        response_junk_size: 15,
        cookie_junk_size: 0,
        transport_junk_size: 0,
        header_initiation: HeaderRange::single(0x1000_0001),
        header_response: HeaderRange::single(0x2000_0002),
        header_cookie: HeaderRange::single(0x3000_0003),
        header_transport: HeaderRange::single(0x4000_0004),
    }
}

/// `AmneziaParams::obfuscate` on a transport frame, allocating against reusing.
///
/// The vanilla arms are here for completeness only: the send path stopped
/// calling this on vanilla profiles when `obfuscate_owned` gained its
/// short-circuit, so what they measure is the cost that path *avoids*.
///
/// The tuned arms are the live ones. An obfuscated profile cannot transform in
/// place — the junk prefix changes the length — so the output has to go
/// somewhere, and the only question is whether that somewhere is a fresh
/// allocation per packet (`owned_output`) or a buffer the tunnel keeps
/// (`reused_output`). The gap between the pair is what `obfuscate_into` removed.
fn amnezia_obfuscate(c: &mut Criterion) {
    let mut group = c.benchmark_group("amnezia_obfuscate");
    for size in SIZES {
        let frame = transport_frame(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("vanilla_owned_output/{size}b"), |b| {
            let params = AmneziaParams::default();
            b.iter(|| black_box(params.obfuscate(black_box(&frame), |_| {}).unwrap()));
        });
        group.bench_function(format!("vanilla_reused_output/{size}b"), |b| {
            let params = AmneziaParams::default();
            let mut out = Vec::new();
            b.iter(|| {
                params
                    .obfuscate_into(black_box(&frame), &mut out, |_| {})
                    .unwrap();
                black_box(&out);
            });
        });
        group.bench_function(format!("tuned_owned_output/{size}b"), |b| {
            let params = tuned_params();
            b.iter(|| {
                black_box(
                    params
                        .obfuscate(black_box(&frame), |junk| junk.fill(0x9A))
                        .unwrap(),
                )
            });
        });
        group.bench_function(format!("tuned_reused_output/{size}b"), |b| {
            let params = tuned_params();
            let mut out = Vec::new();
            b.iter(|| {
                params
                    .obfuscate_into(black_box(&frame), &mut out, |junk| junk.fill(0x9A))
                    .unwrap();
                black_box(&out);
            });
        });
    }
    group.finish();
}

/// The inbound half of the same header swap. Vanilla parameters skip it
/// entirely in `PeerTunnel::receive_datagram`, so only the tuned case is real
/// work on the wire.
///
/// Two arms with the same name they had before and after: `copied_out` builds a
/// fresh `Vec` the way this used to, `in_place` returns a view into the datagram
/// the receive path already owns. The transform drops a fixed prefix and
/// rewrites four bytes, so the copy was the whole cost, and it was charged on
/// every received packet of an obfuscated tunnel.
fn amnezia_deobfuscate_transport(c: &mut Criterion) {
    let mut group = c.benchmark_group("amnezia_deobfuscate_transport");
    let params = tuned_params();
    for size in SIZES {
        let on_wire = params.obfuscate(&transport_frame(size), |_| {}).unwrap();
        let junk = params.transport_junk_size as usize;
        group.throughput(Throughput::Bytes(size as u64));
        // Both arms take a fresh datagram from `setup`, which criterion does not
        // time. The in-place transform overwrites the custom header, so the same
        // buffer cannot be deobfuscated twice — and giving the copying arm a
        // different harness would have measured the harness.
        group.bench_function(format!("copied_out/{size}b"), |b| {
            b.iter_batched(
                || on_wire.clone(),
                |wire| {
                    let mut out = wire[junk..].to_vec();
                    out[..4].copy_from_slice(&[TYPE_TRANSPORT, 0, 0, 0]);
                    black_box(out)
                },
                BatchSize::PerIteration,
            );
        });
        group.bench_function(format!("in_place/{size}b"), |b| {
            b.iter_batched_ref(
                || on_wire.clone(),
                |wire| black_box(params.deobfuscate_transport(wire).unwrap().len()),
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Sealing one IP packet: the padded copy, the AEAD's own output `Vec`, and the
/// fresh destination `Vec` the tunnel hands in per packet.
fn session_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_seal");
    for size in SIZES {
        let packet = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("fresh_output_vec/{size}b"), |b| {
            let (mut client, _server) = session_pair();
            b.iter(|| {
                let mut sealed = Vec::new();
                client.seal(black_box(&packet), &mut sealed).unwrap();
                black_box(sealed)
            });
        });
    }
    group.finish();
}

/// Opening one transport datagram. This one decrypts in place and returns a
/// borrow, so it is the shape the outbound path does not have — worth having a
/// number for, because it is the comparison a fix will be judged against.
fn session_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_open");
    for size in SIZES {
        let packet = ipv4_udp_packet(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("in_place/{size}b"), |b| {
            let (mut client, mut server) = session_pair();
            b.iter_batched(
                || {
                    // A fresh datagram per iteration, because `open` mutates it
                    // and the replay window refuses a counter twice.
                    let mut sealed = Vec::new();
                    client.seal(&packet, &mut sealed).unwrap();
                    sealed
                },
                |mut sealed| black_box(server.open(black_box(&mut sealed)).unwrap().len()),
                // Per iteration, not per batch: a batch of 1420-byte datagrams
                // is megabytes of cold memory and would measure the cache miss
                // rather than the AEAD. The cost is one timer call per
                // iteration, which is under a percent here.
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    amnezia_obfuscate,
    amnezia_deobfuscate_transport,
    session_seal,
    session_open
);
criterion_main!(benches);
