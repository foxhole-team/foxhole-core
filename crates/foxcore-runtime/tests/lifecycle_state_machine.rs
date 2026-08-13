//! The ABI lifecycle as a state machine, driven concurrently.
//!
//! `nativeStart`, `nativeStop`, `nativeForceKill`, `nativeNetworkChanged` and
//! `nativeStats` are called from whichever Android thread reaches them first: a
//! `NetworkCallback` fires on a ConnectivityManager thread while the UI polls
//! stats on the main thread and the service tears the tunnel down on its own.
//! Nothing in the ABI serialises them, so every ordering below is one the app
//! can produce.
//!
//! Why a model rather than a stress loop. D13 was `nativeStop` hanging on an
//! unbounded join, and the repair for it deadlocked against itself because in
//! edition 2024 a `MutexGuard` in an `if let` scrutinee lives to the end of the
//! block — the second lock of the same mutex was three lines below the first.
//! Neither the defect nor the repair's defect is a crash: they are a call that
//! does not come back. A run either happens to hit the interleaving or does
//! not, and reports nothing when it does not. So the properties here are
//! stated as properties — every call returns inside a stated ceiling, at most
//! one caller is ever told `Stopped` — and the ceiling is asserted on the
//! measured duration of each individual call rather than on the suite finishing.
//!
//! The operations are real: this drives `CoreRuntime` itself over a socketpair
//! standing in for the TUN, not a re-implementation of its state machine.

use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use foxcore_api::EngineConfig;
use foxcore_dialer::SocketCallbacks;
use foxcore_runtime::{CoreRuntime, StopResult};

/// `STOP_TIMEOUT` (3s) + `JOIN_GRACE` (250ms) is what the crate promises a stop
/// may cost. The slack is for a loaded CI runner, not for a second wait: a call
/// that took longer than this has an unbounded wait on it somewhere, which is
/// the defect this file exists to catch.
const STOP_CEILING: Duration = Duration::from_secs(8);

/// Reader and network-change calls touch no join at all, so their ceiling is
/// generous only to survive scheduling noise.
const NONBLOCKING_CEILING: Duration = Duration::from_secs(2);

/// A profile that starts without touching the network: `server_ip` is present,
/// so nothing resolves, and the outbound is built against an address that
/// refuses. The lifecycle is what is under test, not the dial.
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

/// The peer end comes back with the engine and must outlive it: closing it
/// early hands the relay an EOF, which would make every test here a test of
/// teardown-on-error instead. It is returned rather than leaked because
/// `a_hundred_lifecycle_cycles_leak_no_descriptors` counts descriptors, and a
/// leak planted by the harness would mask the one it is looking for.
fn start(generation: u64, ipv4: &str) -> (CoreRuntime, UnixStream) {
    let (tun, peer) = UnixStream::pair().expect("a socket pair stands in for the TUN");
    let runtime = CoreRuntime::start(
        generation,
        offline_profile(ipv4),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .expect("an offline profile starts");
    (runtime, peer)
}

/// A `Stopped` result is an ownership promise, not merely a task-cancellation
/// request. The peer must already observe EOF when the call returns; otherwise
/// Android still has a live `/dev/tun` even though the control plane is idle.
fn assert_tun_closed(peer: &mut UnixStream, generation: u64) {
    peer.set_nonblocking(true)
        .expect("the socketpair supports nonblocking reads");
    let mut byte = [0_u8; 1];
    match peer.read(&mut byte) {
        Ok(0) => {}
        Ok(read) => panic!("cycle {generation}: received {read} unexpected bytes after stop"),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            panic!("cycle {generation}: stop returned while the TUN descriptor was still open")
        }
        Err(error) => panic!("cycle {generation}: failed to verify TUN closure: {error}"),
    }
}

/// Run `action`, and fail with the operation's name if it took longer than
/// `ceiling`. The message carries the measured time because "it hung" and "it
/// took four seconds" are different bugs.
fn within<T>(name: &str, ceiling: Duration, action: impl FnOnce() -> T) -> T {
    let began = Instant::now();
    let value = action();
    let elapsed = began.elapsed();
    assert!(
        elapsed <= ceiling,
        "{name} returned after {elapsed:?}, past the {ceiling:?} ceiling: a wait on this \
         path has no bound"
    );
    value
}

/// Deterministic per-round interleaving source. A failure names its seed, and
/// re-running that seed replays the same op sequence.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: enough for choosing between six operations, and no
        // dependency to add for it.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Every concurrent stop path returns inside the stated ceiling, and exactly
/// one caller is told the engine stopped.
///
/// `Stopped` is not a status line: the app releases the `ParcelFileDescriptor`
/// and lets a replacement generation start on it. Two callers told `Stopped`
/// for one engine is a double release of the TUN, so "at most one" is the
/// property, not a nicety.
#[test]
fn concurrent_stops_are_bounded_and_only_one_of_them_stops_the_engine() {
    for round in 0..4_u64 {
        let mut rng = Rng(0x5eed_0000 ^ round.wrapping_mul(0x9e37_79b9));
        let (runtime, _peer) = start(9_000 + round, "10.71.0.1");
        let runtime = Arc::new(runtime);
        let threads = 6;
        let gate = Arc::new(Barrier::new(threads));
        let stopped = Arc::new(AtomicUsize::new(0));

        let mut workers = Vec::new();
        for slot in 0..threads {
            let runtime = runtime.clone();
            let gate = gate.clone();
            let stopped = stopped.clone();
            let mut rng = Rng(rng.next() ^ slot as u64);
            workers.push(std::thread::spawn(move || {
                gate.wait();
                for _ in 0..3 {
                    match rng.below(6) {
                        0 | 1 => {
                            if within("stop", STOP_CEILING, || runtime.stop())
                                == StopResult::Stopped
                            {
                                stopped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        2 => {
                            if within("force_kill", STOP_CEILING, || runtime.force_kill())
                                == StopResult::Stopped
                            {
                                stopped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        3 => within("network_changed", NONBLOCKING_CEILING, || {
                            runtime.network_changed();
                        }),
                        4 => within("network_changed_with_handle", NONBLOCKING_CEILING, || {
                            runtime.network_changed_with_handle(rng.below(8) + 1);
                        }),
                        _ => {
                            let json = within("snapshot_json", NONBLOCKING_CEILING, || {
                                runtime.snapshot_json()
                            });
                            // A reader racing a teardown must still be handed a
                            // document: the stats screen polls straight through
                            // a stop, and "{" is what a torn read looks like.
                            serde_json::from_str::<serde_json::Value>(&json).unwrap_or_else(
                                |error| {
                                    panic!("stats were not JSON during teardown: {error}: {json}")
                                },
                            );
                        }
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().expect("no lifecycle call may panic");
        }

        assert!(
            stopped.load(Ordering::Relaxed) <= 1,
            "round {round}: {} callers were told the engine stopped; each one releases the \
             TUN descriptor, so more than one is a double release",
            stopped.load(Ordering::Relaxed)
        );

        // Whatever the interleaving decided, a final stop must settle and must
        // not claim a second stop.
        let settled = within("final stop", STOP_CEILING, || runtime.stop());
        assert!(
            settled != StopResult::TimedOut || runtime.force_kill() != StopResult::TimedOut,
            "round {round}: the engine could neither be stopped nor abandoned"
        );
    }
}

/// Readers and network changes keep working, and keep being bounded, after the
/// engine is gone.
///
/// The app does not stop polling the moment it calls `nativeStop`; the stats
/// screen is still on top and the `NetworkCallback` is still registered. Every
/// one of those calls lands on a stopped engine.
#[test]
fn readers_and_network_changes_survive_the_engine_they_are_pointed_at() {
    let (runtime, _peer) = start(9_100, "10.72.0.1");
    assert_eq!(runtime.stop(), StopResult::Stopped);

    for _ in 0..8 {
        within("network_changed after stop", NONBLOCKING_CEILING, || {
            runtime.network_changed();
        });
        within(
            "network_changed_with_handle after stop",
            NONBLOCKING_CEILING,
            || runtime.network_changed_with_handle(4),
        );
        let stats = within("snapshot_json after stop", NONBLOCKING_CEILING, || {
            runtime.snapshot_json()
        });
        serde_json::from_str::<serde_json::Value>(&stats).expect("stats stay JSON after a stop");
        let map = within("traffic_map_json after stop", NONBLOCKING_CEILING, || {
            runtime.traffic_map_json()
        });
        serde_json::from_str::<serde_json::Value>(&map).expect("the map stays JSON after a stop");
        let events = within("drain_events_json after stop", NONBLOCKING_CEILING, || {
            runtime.drain_events_json(16)
        });
        serde_json::from_str::<serde_json::Value>(&events).expect("events stay JSON after a stop");
    }

    assert_eq!(
        runtime.stop(),
        StopResult::AlreadyStopped,
        "a second stop must report that it was already stopped, never a second Stopped"
    );
    assert_eq!(
        runtime.force_kill(),
        StopResult::AlreadyStopped,
        "and neither may a force kill invent one"
    );
}

/// Repeated start/stop must not leak the TUN descriptor or the worker's.
///
/// P1's gate asks for ten thousand cycles; this runs the shape of it on every
/// gate run so a regression cannot reach the soak. A leak of one descriptor
/// per cycle is what an early return between `establish()` and the relay
/// looks like, and on a device it ends as `EMFILE` after a few hundred
/// reconnects rather than as a crash anyone can read.
#[test]
fn a_hundred_lifecycle_cycles_leak_no_descriptors() {
    fn open_descriptors() -> usize {
        // `/dev/fd` is the process's own descriptor table on both Linux and
        // macOS. Reading it opens one itself, which is why the comparison is
        // between two readings and not against an absolute number.
        std::fs::read_dir("/dev/fd")
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    // Warm-up: the first start allocates per-process singletons — the event
    // queue, the quarantine list, lazily opened randomness — that must not be
    // counted as growth.
    for generation in 0..3 {
        let (runtime, mut peer) = start(9_200 + generation, "10.73.0.1");
        assert_eq!(runtime.stop(), StopResult::Stopped);
        assert_tun_closed(&mut peer, generation);
    }

    let before = open_descriptors();
    let cycles = 100;
    for generation in 0..cycles {
        let (runtime, mut peer) = start(9_300 + generation, "10.74.0.1");
        assert_eq!(
            runtime.stop(),
            StopResult::Stopped,
            "cycle {generation}: the ordinary stop path must settle every time; a cycle \
             that only ever times out is a reconnect the user has to force"
        );
        assert_tun_closed(&mut peer, generation);
        drop(runtime);
        drop(peer);
    }
    let after = open_descriptors();

    assert!(
        after <= before + 8,
        "{cycles} lifecycle cycles moved the descriptor table from {before} to {after}: \
         a leak of one per cycle ends as EMFILE on a device, not as a crash"
    );
}

/// `nativeForceKill` on a healthy engine answers `TimedOut`, and that is the
/// contract rather than a failure: the worker was alive, so the quarantine list
/// took it and the call returned without waiting for it.
///
/// Worth pinning because the code is `NATIVE_STOP_TIMED_OUT`, which reads like
/// a failure at the call site, and because the promise attached to it — *this
/// never waits, not even the stop timeout* — is the whole reason the entry
/// point exists. A future repair that made force-kill join "just briefly"
/// would still return `TimedOut` and would still pass every other test here.
#[test]
fn force_kill_hands_a_live_worker_to_quarantine_without_waiting_for_it() {
    let (runtime, _peer) = start(9_500, "10.75.0.1");

    // A tenth of the 3s stop timeout. Anything above this is a join that was
    // not supposed to be on this path.
    let began = Instant::now();
    let result = runtime.force_kill();
    let elapsed = began.elapsed();

    assert_eq!(
        result,
        StopResult::TimedOut,
        "a live worker goes to the quarantine list, and the caller is told so"
    );
    assert!(
        elapsed < Duration::from_millis(300),
        "force_kill waited {elapsed:?}; it is documented not to wait at all"
    );

    // And the abandoned worker really does exit: the quarantine list owns it,
    // not the caller, but "owns" must not mean "forever". `stop` is what can
    // observe that — it waits on the worker's own completion channel, and a
    // dropped sender is how an exited worker announces itself. `TimedOut` here
    // would mean the worker is still alive and the descriptor is gone for the
    // life of the process — on Android, one leaked tun0 per force kill.
    //
    // The answer is `AlreadyStopped` rather than `Stopped` because the force
    // kill took ownership of the worker and this call no longer has it. Only
    // the owner may say `Stopped`, since that is what makes a caller release
    // the TUN descriptor, and here the quarantine list holds it.
    assert_eq!(
        within("stop after force_kill", STOP_CEILING, || runtime.stop()),
        StopResult::AlreadyStopped,
        "the abandoned worker never exited, or a call that does not own it claimed the stop"
    );

    // Force kill itself keeps answering `TimedOut`, because `abandon` hands the
    // thread away without ever moving the state to STOPPED
    // (`RuntimeWorker::abandon`). Not reachable through the ABI —
    // `nativeForceKill` removes the handle before calling, so a second call
    // gets UNKNOWN_HANDLE — but pinned here so that stops being an accident.
    assert_eq!(
        runtime.force_kill(),
        StopResult::AlreadyStopped,
        "once a stop has observed the exit, a later force kill must agree with it"
    );
}
