#![deny(clippy::undocumented_unsafe_blocks)]

//! Does a generation give back the memory it took?
//!
//! A device soak reported the app's native heap drifting upward across
//! connect/disconnect cycles, but a phone cannot answer this question: the same
//! process draws a map, decodes screenshots, resolves geoip and restarts a
//! second daemon, and its allocator is free to hold freed pages rather than
//! return them. All of that moves `Native Heap Alloc` by megabytes in both
//! directions, which is exactly what the soak showed — up 11 MB one cycle, down
//! 11 MB the next.
//!
//! So the measurement happens here instead, where the only thing running is the
//! runtime itself and the number is live bytes rather than resident pages: a
//! counting allocator that adds on every allocation and subtracts on every free.
//! What survives a stop shows up as a difference that does not come back, and
//! nothing else can contribute to it.
//!
//! The ceiling is per generation and deliberately loose. This is not a budget
//! for how much a generation may allocate — it may allocate freely — it is the
//! claim that what it allocates is *returned*, with room for the one-time caches
//! (rustls roots, a lazily built table) that fill once and then stay flat. A
//! real per-generation leak is unbounded and crosses any ceiling as the count
//! rises; that is why the assertion is on the slope across measured generations
//! rather than on a single high-water mark.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use foxcore_api::EngineConfig;
use foxcore_dialer::SocketCallbacks;
use foxcore_runtime::{CoreRuntime, StopResult};

/// Live bytes: incremented on allocation, decremented on free.
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards to `System` with the same pointer and layout it
// was given, so the underlying allocator sees exactly the sequence it would
// without this wrapper. The counters are plain atomics and cannot affect it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards the caller's `GlobalAlloc` contract unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwards the caller's pointer and layout unchanged.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards the caller's `GlobalAlloc` contract unchanged.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwards the caller's pointer, layout, and size unchanged.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Generations run before the baseline is taken, so one-time caches are already
/// paid for and do not read as a leak.
const WARMUP: u64 = 4;

/// Generations measured against that baseline.
const MEASURED: u64 = 12;

/// Per measured generation. A generation's own working set is hundreds of
/// kilobytes; the device saw ~5 MB per cycle. Anything that holds even a tenth
/// of that per generation is a leak worth a name.
const PER_GENERATION_CEILING: usize = 512 * 1024;

fn offline_profile(ipv4: &str) -> EngineConfig {
    let json = format!(
        r#"{{
            "schema_version": 1,
            "outbound": {{
                "type": "vless",
                "server": "bootstrap.invalid",
                "port": 443,
                "server_ip": "203.0.113.7",
                "uuid": "d0cf0001-0000-4000-8000-000000000000"
            }},
            "tun": {{ "mtu": 1400, "ipv4": "{ipv4}" }}
        }}"#
    );
    EngineConfig::parse(&json).expect("a fixed, valid offline profile")
}

/// Distinct flows pushed through each generation.
///
/// A generation that only starts and stops exercises the plumbing and nothing
/// else, and the device cycles this is chasing carried minutes of traffic. Per
/// flow the core builds a routing decision, a traffic-map entry and an
/// accounting record — the structures that grow with a session and therefore
/// the ones a stop has to release.
const FLOWS_PER_GENERATION: u16 = 256;

/// A minimal IPv4/UDP datagram from the tun's own address. Distinct source
/// ports and destinations make each one a separate flow rather than a repeat.
fn udp_packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 77, 0, 1]);
    // 198.51.100.0/24 is TEST-NET-2: no packet can leave the harness for it.
    packet[16..20].copy_from_slice(&[198, 51, 100, (sequence % 254) as u8 + 1]);
    packet[20..22].copy_from_slice(&(40_000_u16.wrapping_add(sequence)).to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet
}

/// One whole generation: start, let the engine reach its loop, stop, and drop
/// everything the harness owns. The peer socket is dropped here too — held
/// across generations it would be the harness's own leak.
fn one_generation(generation: u64) {
    let (tun, mut peer) = UnixStream::pair().expect("a socket pair stands in for the TUN");
    let runtime = CoreRuntime::start(
        generation,
        offline_profile("10.77.0.1"),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .expect("an offline profile starts");

    // Touch the paths a real session touches, so a per-session structure that is
    // built lazily is actually built before the stop that should release it.
    for sequence in 0..FLOWS_PER_GENERATION {
        if peer.write_all(&udp_packet(sequence)).is_err() {
            break;
        }
    }
    std::thread::sleep(Duration::from_millis(150));

    let _ = runtime.snapshot_json();
    let _ = runtime.traffic_map_json();
    let _ = runtime.drain_events(16);
    runtime.network_changed_with_handle(generation);

    assert_eq!(
        runtime.stop(),
        StopResult::Stopped,
        "generation {generation} must stop cleanly, or this measures a wedged \
         worker rather than a leak"
    );
    drop(runtime);
    drop(peer);
}

#[test]
fn a_generation_returns_the_memory_it_took() {
    for generation in 0..WARMUP {
        one_generation(generation);
    }

    // The worker thread is joined by `stop`, but the allocator sees frees from
    // whichever thread runs a destructor last. A short settle keeps that from
    // landing on the wrong side of the baseline.
    std::thread::sleep(Duration::from_millis(250));
    let baseline = LIVE.load(Ordering::Relaxed);

    for generation in WARMUP..WARMUP + MEASURED {
        one_generation(generation);
    }

    std::thread::sleep(Duration::from_millis(250));
    let after = LIVE.load(Ordering::Relaxed);

    let growth = after.saturating_sub(baseline);
    let per_generation = growth / MEASURED as usize;

    assert!(
        per_generation < PER_GENERATION_CEILING,
        "each generation kept {per_generation} bytes that it never gave back \
         ({growth} bytes across {MEASURED} generations: {baseline} -> {after}). \
         A generation may allocate what it likes, but a stop has to return it."
    );
}
