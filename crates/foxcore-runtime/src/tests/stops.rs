use super::*;

/// The default policy is the behaviour the core always had: no hold, no
/// token, and no control-plane thread waking the phone up.
#[test]
fn the_default_policy_neither_holds_nor_starts_a_watch() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        53,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();

    runtime.network_changed_with_handle(9);
    assert!(runtime.continuity_state().held_lanes.is_empty());
    assert!(runtime.drain_events(16).events.is_empty());

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// D13, exactly. On the device `nativeStop` sat in `futex_wait_queue_me`
/// for over three minutes with a three-second timeout, after a half-hour
/// session. The worker signals `done` when the engine loop returns, and the
/// runtime was dropped afterwards as the closure unwound — so the bounded
/// `recv_timeout` succeeded and the `join()` behind it, which had no
/// ceiling, inherited the whole wait.
///
/// Ten short start/stop cycles cannot produce this and never did: the
/// worker has nothing wedged to unwind. What produces it is a worker that
/// says it finished and then does not, so that is what this builds.
#[test]
fn a_worker_that_reports_done_and_then_wedges_still_returns_from_stop() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let thread = std::thread::spawn(move || {
        // "The engine loop returned."
        let _ = done_tx.send(());
        // ... and now the runtime drop waits on a platform call.
        let _ = release_rx.recv();
    });
    let worker = RuntimeWorker::new(thread, done_rx);

    let started = Instant::now();
    assert_eq!(
        worker.stop(Duration::from_millis(200), || {}),
        StopResult::TimedOut,
        "a stop that cannot join must say so rather than block"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the whole point is that this returns: took {:?}",
        started.elapsed()
    );
    assert!(
        lock(&worker.thread).is_some(),
        "a timed-out stop still owns the worker, so a retry can finish it"
    );

    release_tx.send(()).unwrap();
    let mut outcome = StopResult::TimedOut;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && outcome == StopResult::TimedOut {
        outcome = worker.stop(Duration::from_millis(200), || {
            panic!("cancellation must be requested once, not on every retry")
        });
    }
    assert_eq!(outcome, StopResult::Stopped);
    assert_eq!(
        worker.stop(Duration::ZERO, || unreachable!()),
        StopResult::AlreadyStopped
    );
}

/// The wait the worker used to inherit. `Runtime::drop` blocks for running
/// blocking tasks — attribution is a platform call and cannot be cancelled
/// — so the worker takes its own ceiling instead.
#[test]
fn shutting_the_worker_runtime_down_does_not_wait_for_a_wedged_platform_call() {
    let runtime = build_runtime(&RuntimeConfig::default()).unwrap();
    let (_release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    for _ in 0..RuntimeConfig::default().max_blocking_threads {
        let release_rx = release_rx.clone();
        // Abandoned exactly as the attribution timeout abandons its task:
        // the handle is dropped, the work is not.
        drop(runtime.spawn_blocking(move || {
            let _ = lock(&release_rx).recv();
        }));
    }
    std::thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    shutdown_worker_runtime(runtime);

    assert!(
        started.elapsed() < STOP_TIMEOUT,
        "the shutdown must fit inside the stop budget, took {:?}",
        started.elapsed()
    );
}

/// Force kill exists for the case `stop` reports `TimedOut` and the app is
/// going away regardless. It must not block on the data plane at all.
/// A force kill removes the handle from the registry, so the `Arc` it was
/// called through is usually the last one — and dropping it called straight
/// back into `stop`, which sat on the completion channel for the whole
/// `STOP_TIMEOUT`. Three seconds on the service thread, inside the one call
/// documented never to wait for the worker. Invisible to the existing
/// tests, which drive `RuntimeWorker` directly and never drop a
/// `CoreRuntime` that owns a wedged one.
#[test]
fn dropping_the_handle_a_force_kill_emptied_does_not_wait_for_the_worker() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let thread = std::thread::spawn(move || {
        let _ = release_rx.recv();
        let _ = done_tx.send(());
    });
    let worker = RuntimeWorker::new(thread, done_rx);
    assert_eq!(worker.abandon(), StopResult::TimedOut);

    // What `Drop` now checks before it considers waiting.
    let started = Instant::now();
    let owned_elsewhere = lock(&worker.thread).is_none();
    assert!(owned_elsewhere, "the quarantine list should own it");
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "the check itself must be free, took {:?}",
        started.elapsed()
    );

    // And the wait it skips is the expensive one: asking to stop an
    // abandoned worker still blocks, which is why only the destructor may
    // skip it.
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        reap_quarantined_workers();
        if lock(QUARANTINED_WORKERS.get_or_init(|| Mutex::new(Vec::new()))).is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the quarantined worker never exited");
}

#[test]
fn force_kill_returns_immediately_and_leaves_a_wedged_worker_owned() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let thread = std::thread::spawn(move || {
        let _ = release_rx.recv();
        let _ = done_tx.send(());
    });
    let worker = RuntimeWorker::new(thread, done_rx);

    let started = Instant::now();
    assert_eq!(worker.abandon(), StopResult::TimedOut);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "force kill must not wait for the worker, took {:?}",
        started.elapsed()
    );
    assert!(
        lock(&worker.thread).is_none(),
        "the quarantine list owns it now, not this handle"
    );

    // The quarantine keeps ownership until the worker really exits, which
    // is what stops a replacement generation from racing it.
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        reap_quarantined_workers();
        if lock(QUARANTINED_WORKERS.get_or_init(|| Mutex::new(Vec::new()))).is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("a released worker must eventually be reaped");
}

/// Force kill exists for exactly one situation — a stop that is wedged —
/// and so that is the situation it has to be measured in.
///
/// `nativeForceKill` promises it "never waits, not even the stop timeout".
/// A force kill that serialised against the stop it was called to rescue
/// would keep every other property in this file and still be useless: the
/// app calls it precisely because `nativeStop` has not come back, so
/// queueing behind that call is queueing behind the whole `STOP_TIMEOUT`.
///
/// The worker here never signals completion and never exits, so the stop is
/// wedged for real rather than merely slow, and the stop's own
/// cancellation callback is what says the lock is held and the wait has
/// begun.
#[test]
fn force_kill_does_not_queue_behind_a_stop_that_is_still_waiting() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let thread = std::thread::spawn(move || {
        let _ = release_rx.recv();
        let _ = done_tx.send(());
    });
    let worker = Arc::new(RuntimeWorker::new(thread, done_rx));

    let (waiting_tx, waiting_rx) = mpsc::sync_channel::<()>(1);
    let stopping = {
        let worker = worker.clone();
        std::thread::spawn(move || {
            worker.stop(STOP_TIMEOUT, move || {
                // Called with `stop_lock` held, immediately before the wait.
                waiting_tx.send(()).expect("the test thread is listening");
            })
        })
    };
    waiting_rx
        .recv()
        .expect("the stop reached its wait and is holding the lock");

    let started = Instant::now();
    let result = worker.abandon();
    let elapsed = started.elapsed();

    assert_eq!(
        result,
        StopResult::TimedOut,
        "a live worker goes to the quarantine list"
    );
    assert!(
        elapsed < Duration::from_millis(250),
        "force kill took {elapsed:?} while a stop was waiting out its {STOP_TIMEOUT:?}: it \
             queued behind the call it exists to rescue"
    );

    // Let the worker finish, so the stop's own wait completes and it has to
    // answer for a worker it no longer owns. It did stop — the completion
    // channel says so — but the force kill took ownership, and `Stopped` is
    // what makes a caller release the TUN descriptor.
    release_tx.send(()).expect("the worker is still listening");
    assert_eq!(
        stopping.join().expect("the stop thread does not panic"),
        StopResult::AlreadyStopped,
        "a stop whose worker was taken from it must not also claim Stopped: each Stopped \
             releases the TUN descriptor, and two releases of one descriptor is the bug this \
             answer exists to avoid"
    );

    // Best effort, and not asserted: the quarantine list is process-wide and
    // other tests are using it. Ownership of a released worker ending is
    // pinned by `force_kill_returns_immediately_and_leaves_a_wedged_worker_owned`.
    for _ in 0..64 {
        reap_quarantined_workers();
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A full engine, stopped after work has been abandoned on its blocking
/// pool — the shape a long session leaves behind. The budget is the
/// contract: `nativeStop` answers, one way or the other.
#[test]
fn stopping_an_engine_with_abandoned_platform_work_answers_within_its_budget() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        61,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();

    // Wedge the whole blocking pool, the way a ConnectivityManager that has
    // stopped answering does after half an hour.
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    for _ in 0..RuntimeConfig::default().max_blocking_threads {
        let release_rx = release_rx.clone();
        drop(runtime.tokio_handle.spawn_blocking(move || {
            let _ = lock(&release_rx).recv();
        }));
    }
    std::thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    let result = runtime.stop();
    let elapsed = started.elapsed();

    assert!(
        elapsed < STOP_TIMEOUT + RUNTIME_SHUTDOWN_GRACE + JOIN_GRACE + Duration::from_secs(1),
        "stop must answer inside its own budget, took {elapsed:?}"
    );
    assert!(
        matches!(result, StopResult::Stopped | StopResult::TimedOut),
        "and it must say which, got {result:?}"
    );
    let _ = release_tx.send(());
    let _ = release_tx.send(());
}

/// D11: turning Tor or I2P on in a reload threw the same bare
/// `IllegalStateException` as a malformed policy, so the app could not tell
/// "this library has no Tor" — permanent, retire the switch — from "the
/// policy I just built is wrong" or from "someone reloaded first". The live
/// tunnel survived all three, which made the missing diagnosis the whole
/// defect.
#[test]
fn a_refused_reload_says_which_refusal_it_was_and_changes_nothing() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        71,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();
    let revision = runtime.policy_revision();

    let with_traffic = |traffic: TrafficPolicyConfig, dns: DnsConfig| PolicyConfig {
        expected_revision: None,
        dns,
        routes: Vec::new(),
        traffic,
    };

    // No Tor outbound in this profile, and no Tor feature in this build.
    let tor_on = TrafficPolicyConfig {
        tor_enabled: Some(true),
        ..Default::default()
    };
    let refusal = runtime
        .reload_policy(with_traffic(tor_on, DnsConfig::default()))
        .expect_err("a Tor switch with no Tor must be refused");
    assert_eq!(refusal.refusal, PolicyRefusal::TorUnavailable);
    assert_eq!(refusal.code(), 3);

    let i2p_on = TrafficPolicyConfig {
        i2p_enabled: Some(true),
        ..Default::default()
    };
    assert_eq!(
        runtime
            .reload_policy(with_traffic(i2p_on, DnsConfig::default()))
            .expect_err("an I2P switch with no I2P must be refused")
            .refusal,
        PolicyRefusal::I2pUnavailable,
        "and it must not be reported as the Tor one: the screens differ"
    );

    // A different shape of wrong, which must not look the same.
    let unknown_outbound = PolicyConfig {
        expected_revision: None,
        dns: DnsConfig::default(),
        routes: vec![foxcore_api::RouteRule {
            uid: None,
            package: None,
            exact_domains: Vec::new(),
            domain_suffixes: Vec::new(),
            cidrs: Vec::new(),
            ports: Vec::new(),
            network: None,
            transport: None,
            action: RouteAction::Outbound(OutboundId("nowhere".into())),
            expires_at_ms: None,
        }],
        traffic: TrafficPolicyConfig::default(),
    };
    assert_eq!(
        runtime
            .reload_policy(unknown_outbound)
            .expect_err("a route to nowhere must be refused")
            .refusal,
        PolicyRefusal::UnknownOutbound
    );

    // A retry, which is a different answer again.
    runtime
        .reload_policy(PolicyConfig {
            expected_revision: Some(revision),
            dns: DnsConfig::default(),
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .unwrap();
    assert_eq!(
        runtime
            .reload_policy(PolicyConfig {
                expected_revision: Some(revision),
                dns: DnsConfig::default(),
                routes: Vec::new(),
                traffic: TrafficPolicyConfig::default(),
            })
            .expect_err("a stale expected_revision must be refused")
            .refusal,
        PolicyRefusal::RevisionConflict
    );

    // Every refusal is distinct across the boundary, or the app is back to
    // one shrug for every cause.
    let codes = [
        PolicyRefusal::Invalid,
        PolicyRefusal::UnknownOutbound,
        PolicyRefusal::TorUnavailable,
        PolicyRefusal::I2pUnavailable,
        PolicyRefusal::OverlayRequiresFakeIp,
        PolicyRefusal::IdentityUnavailable,
        PolicyRefusal::RevisionConflict,
    ]
    .map(|refusal| refusal as u8);
    let mut seen = codes.to_vec();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), codes.len());
    assert!(
        seen.iter().all(|code| *code > 0),
        "zero means 'not running'"
    );

    assert_eq!(runtime.stop(), StopResult::Stopped);
}
