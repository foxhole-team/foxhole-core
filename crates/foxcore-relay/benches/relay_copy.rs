//! What the relay's buffer costs, over real loopback sockets.
//!
//! Three arms, always measured back to back in one run, because two effects
//! were confused with each other for a long time and only a paired measurement
//! tells them apart:
//!
//! * `tokio_8k` — `tokio::io::copy_bidirectional`, exactly as the onion
//!   publisher used it: the 8 KiB default, and a fresh pair of zeroed buffers
//!   per connection.
//! * `tokio_64k` — the same allocating shape at sing-box's size. The gap to
//!   `tokio_8k` is the *syscall* saving on its own, and on a short connection
//!   this arm is expected to be the **worst** of the three: 128 KiB zeroed to
//!   move a kilobyte.
//! * `pooled_64k` — this crate. The gap to `tokio_64k` is the *allocation*
//!   saving on its own.
//!
//! Two workloads, because the two savings live at different ends. `bulk` moves
//! four mebibytes through one connection, where the buffer size decides how many
//! `read`/`write` pairs the kernel is asked for. `churn` moves a kilobyte
//! through a fresh connection, which is the proxy path's real shape — the
//! profile that started this work counted 6547 connections in 28 seconds — and
//! is where the per-connection allocation is the whole cost.
//!
//! Cross-run comparison on the development machine is worthless; these arms are
//! written to be compared with each other inside a single run, never against a
//! saved baseline.

#![forbid(unsafe_code)]

use std::hint::black_box;
use std::net::SocketAddr;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use foxcore_relay::{BufferPool, copy_bidirectional_pooled};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

const KIB: usize = 1024;

/// Big enough that the buffer size decides the syscall count rather than the
/// connection setup doing it.
const BULK_BYTES: usize = 4 * 1024 * KIB;
/// One request-sized payload, which is what most proxied connections are.
const CHURN_BYTES: usize = KIB;

/// Accepts forever; every accepted socket is written `up` bytes, half-closed,
/// and then drained. This is the client side of the relay under test.
async fn client_side(listener: TcpListener, up: usize) {
    let payload = vec![0x5A_u8; up];
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let payload = payload.clone();
        tokio::spawn(async move {
            socket.set_nodelay(true).ok();
            let write = async {
                socket.write_all(&payload).await.ok();
                socket.shutdown().await.ok();
            };
            write.await;
            let mut sink = Vec::new();
            socket.read_to_end(&mut sink).await.ok();
        });
    }
}

/// Accepts forever; drains each socket and answers with `down` bytes. This is
/// the upstream the relay dials.
async fn origin_side(listener: TcpListener, down: usize) {
    let payload = vec![0xA5_u8; down];
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let payload = payload.clone();
        tokio::spawn(async move {
            socket.set_nodelay(true).ok();
            let mut sink = Vec::new();
            socket.read_to_end(&mut sink).await.ok();
            socket.write_all(&payload).await.ok();
            socket.shutdown().await.ok();
        });
    }
}

struct Lab {
    runtime: Runtime,
    client: SocketAddr,
    origin: SocketAddr,
}

impl Lab {
    fn start(up: usize, down: usize) -> Self {
        let runtime = Runtime::new().expect("bench runtime");
        let (client, origin) = runtime.block_on(async move {
            let client_listener = TcpListener::bind("127.0.0.1:0").await.expect("client bind");
            let origin_listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
            let client = client_listener.local_addr().expect("client addr");
            let origin = origin_listener.local_addr().expect("origin addr");
            tokio::spawn(client_side(client_listener, up));
            tokio::spawn(origin_side(origin_listener, down));
            (client, origin)
        });
        Self {
            runtime,
            client,
            origin,
        }
    }

    /// One proxied connection: dial both sides, then relay with `copy`.
    ///
    /// The two dials are inside the measured region on purpose — they are the
    /// same in every arm, and leaving them out would inflate the difference
    /// between arms by removing a cost every real connection pays.
    fn one_connection<F, C>(&self, copy: C)
    where
        C: Fn(TcpStream, TcpStream) -> F,
        F: std::future::Future<Output = ()>,
    {
        self.runtime.block_on(async {
            let (client, origin) = tokio::join!(
                TcpStream::connect(self.client),
                TcpStream::connect(self.origin)
            );
            let client = client.expect("client dial");
            let origin = origin.expect("origin dial");
            client.set_nodelay(true).ok();
            origin.set_nodelay(true).ok();
            copy(client, origin).await;
        });
    }

    /// `count` proxied connections at once, all finished before returning.
    ///
    /// Spawned rather than joined in place, so they land on the runtime's
    /// worker threads and actually contend — a `join_all` on one task would
    /// interleave them on one core and measure nothing about a shared lock.
    fn concurrent<F, C>(&self, count: usize, copy: C)
    where
        C: Fn(TcpStream, TcpStream) -> F + Copy + Send + 'static,
        F: std::future::Future<Output = ()> + Send,
    {
        self.runtime.block_on(async {
            let mut relays = Vec::with_capacity(count);
            for _ in 0..count {
                let client_addr = self.client;
                let origin_addr = self.origin;
                relays.push(tokio::spawn(async move {
                    let (client, origin) = tokio::join!(
                        TcpStream::connect(client_addr),
                        TcpStream::connect(origin_addr)
                    );
                    let client = client.expect("client dial");
                    let origin = origin.expect("origin dial");
                    client.set_nodelay(true).ok();
                    origin.set_nodelay(true).ok();
                    copy(client, origin).await;
                }));
            }
            for relay in relays {
                relay.await.expect("relay task");
            }
        });
    }
}

/// Cap a group that opens a socket pair per iteration.
///
/// Not a tuning knob — a hard limit of the machine. Every iteration burns two
/// ephemeral ports for the length of `TIME_WAIT` (30 s on this host), and the
/// range is about sixteen thousand. At criterion's defaults the churn arms ran
/// ten thousand iterations each and the third one died on
/// `AddrNotAvailable` — a benchmark that exhausts the port table measures the
/// port table.
///
/// The cost is wider confidence intervals, and at the default they are wide
/// enough that the socket arms overlap. That is deliberate: a full
/// `cargo bench -p foxcore-relay` has to *finish*, and the sharp numbers are
/// taken one group at a time, which is what the range is actually big enough
/// for:
///
/// ```text
/// RELAY_BENCH_SAMPLES=100 cargo bench -p foxcore-relay --bench relay_copy -- relay_churn
/// # wait ~45 s for TIME_WAIT to drain, then
/// RELAY_BENCH_SAMPLES=60  cargo bench -p foxcore-relay --bench relay_copy -- relay_parallel
/// ```
fn bounded_by_ephemeral_ports(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    let samples = std::env::var("RELAY_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10)
        .max(10);
    group.sample_size(samples);
    // The window, not the sample count, is what decides how many connections are
    // opened: criterion fills `measurement_time` with iterations and then splits
    // them into samples. So the sample count can be raised for tighter intervals
    // without touching the port budget, and these two numbers are the budget.
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(500));
}

fn arms(c: &mut Criterion, name: &str, up: usize, down: usize) {
    let lab = Lab::start(up, down);
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Bytes((up + down) as u64));
    // `bulk` moves four mebibytes per connection, so criterion's own estimate
    // already keeps it to a few hundred; only the short-connection workload
    // needs the ceiling.
    if up + down <= 64 * KIB {
        bounded_by_ephemeral_ports(&mut group);
    }

    group.bench_function("tokio_8k", |b| {
        b.iter(|| {
            lab.one_connection(|mut client, mut origin| async move {
                let moved = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
                black_box(moved.ok());
            })
        });
    });

    group.bench_function("tokio_64k", |b| {
        b.iter(|| {
            lab.one_connection(|mut client, mut origin| async move {
                let moved = tokio::io::copy_bidirectional_with_sizes(
                    &mut client,
                    &mut origin,
                    64 * KIB,
                    64 * KIB,
                )
                .await;
                black_box(moved.ok());
            })
        });
    });

    // Four idle buffers is more than this single-connection loop can use; the
    // arm is measuring a warm pool, which is what a running relay has.
    let pool = BufferPool::new(64 * KIB, 4);
    let pool = &pool;
    group.bench_function("pooled_64k", |b| {
        b.iter(|| {
            lab.one_connection(move |mut client, mut origin| async move {
                let moved = copy_bidirectional_pooled(pool, &mut client, &mut origin).await;
                black_box(moved.ok());
            })
        });
    });

    group.finish();
}

fn bulk(c: &mut Criterion) {
    arms(c, "relay_bulk", BULK_BYTES, 0);
}

fn churn(c: &mut Criterion) {
    arms(c, "relay_churn", CHURN_BYTES, CHURN_BYTES);
}

/// Concurrent connections, because the pool has a lock and the arms above
/// cannot see it.
///
/// One `Mutex<Vec<..>>` is shared by every relay that draws on a pool — up to
/// `max_tcp_flows` of them in the TUN engine. The critical section is a `pop` or
/// a `push`, but "it is short" is an argument, not a measurement, and the
/// remaining sing-box gap was localised at *medium
/// concurrency* — which is exactly where a new shared lock would hide. Eight
/// connections at once is the shape of that measurement (`direct` c8).
///
/// The arms are the same three. If pooling were contending, `pooled_64k` would
/// close on or fall behind `tokio_64k` here while staying ahead in `relay_churn`.
fn parallel(c: &mut Criterion) {
    const CONCURRENCY: usize = 8;

    let lab = Lab::start(CHURN_BYTES, CHURN_BYTES);
    let mut group = c.benchmark_group("relay_parallel");
    group.throughput(Throughput::Bytes((CONCURRENCY * 2 * CHURN_BYTES) as u64));
    // Sixteen ephemeral ports per iteration here, so the ceiling matters more
    // than anywhere else.
    bounded_by_ephemeral_ports(&mut group);

    group.bench_function("tokio_8k", |b| {
        b.iter(|| {
            lab.concurrent(CONCURRENCY, |mut client, mut origin| async move {
                let moved = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
                black_box(moved.ok());
            })
        });
    });
    group.bench_function("tokio_64k", |b| {
        b.iter(|| {
            lab.concurrent(CONCURRENCY, |mut client, mut origin| async move {
                let moved = tokio::io::copy_bidirectional_with_sizes(
                    &mut client,
                    &mut origin,
                    64 * KIB,
                    64 * KIB,
                )
                .await;
                black_box(moved.ok());
            })
        });
    });

    // Two per concurrent relay, so a saturated run never has to allocate — the
    // same arithmetic the onion publisher's pool uses.
    //
    // Leaked to `'static` because the relays are spawned tasks, which is also
    // how the LAN proxy and the onion publisher hold theirs: a `static` pool.
    // The bench process ends a few seconds later, so this is a lifetime, not a
    // leak.
    let pool: &'static BufferPool = Box::leak(Box::new(BufferPool::new(64 * KIB, 2 * CONCURRENCY)));
    group.bench_function("pooled_64k", |b| {
        b.iter(|| {
            lab.concurrent(CONCURRENCY, move |mut client, mut origin| async move {
                let moved = copy_bidirectional_pooled(pool, &mut client, &mut origin).await;
                black_box(moved.ok());
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bulk, churn, parallel);
criterion_main!(benches);
