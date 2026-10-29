use super::*;
use std::io::Read;
use std::sync::atomic::AtomicU8;

fn config() -> EngineConfig {
    EngineConfig::parse(
        r#"{"schema_version":1,"outbound":{"type":"direct"},"tun":{"mtu":1400,"ipv4":"10.77.0.1"},"dns":{"mode":"fake_ip","advertise":"10.77.0.1"},"runtime":{"local_guard":true}}"#,
    )
    .unwrap()
}

fn policy() -> Arc<foxcore_tun::FlowPolicyStore> {
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    Arc::new(
        foxcore_tun::FlowPolicyStore::new(
            1,
            foxcore_route::RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
            Arc::new(OutboundRegistry::single(direct.clone())),
            direct,
            Arc::new(foxcore_tun::FlowMetrics::default()),
            foxcore_api::EventSink::none(),
        )
        .unwrap(),
    )
}

#[test]
fn dns_continuation_refuses_running_and_stopping_until_clean_join() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        release_rx.recv().unwrap();
        done_tx.send(()).unwrap();
    });
    let worker = RuntimeWorker::new(thread, done_rx);
    let continuation = DnsContinuation {
        policy: policy(),
        stop_fence: worker.dns_stop_fence.clone(),
        packet_tunnel: false,
    };
    for stopping in [false, true] {
        if stopping {
            assert_eq!(
                worker.stop(Duration::from_millis(5), || {}),
                StopResult::TimedOut
            );
        }
        let (tun, _) = UnixStream::pair().unwrap();
        let result = CoreRuntime::start_with_dns_continuation(
            100,
            config(),
            OwnedFd::from(tun),
            SocketCallbacks::none(),
            Some(continuation.clone()),
        );
        match result {
            Ok(runtime) => {
                let _ = runtime.stop();
                panic!("unfinished predecessor accepted");
            }
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        }
    }
    release_tx.send(()).unwrap();
    assert_eq!(
        worker.stop(Duration::from_secs(1), || unreachable!()),
        StopResult::Stopped
    );
    assert!(continuation.is_ready());
    assert!(continuation.dns_for_start(false).is_ok());
}

#[test]
fn revoked_dns_continuation_clones_cannot_be_revived_by_clean_stop() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        release_rx.recv().unwrap();
        done_tx.send(()).unwrap();
    });
    let worker = RuntimeWorker::new(thread, done_rx);
    let continuation = DnsContinuation {
        policy: policy(),
        stop_fence: worker.dns_stop_fence.clone(),
        packet_tunnel: false,
    };
    let cloned = continuation.clone();
    continuation.revoke();
    release_tx.send(()).unwrap();
    assert_eq!(
        worker.stop(Duration::from_secs(1), || {}),
        StopResult::Stopped
    );
    assert!(!cloned.is_ready());
    assert_eq!(
        cloned.dns_for_start(false).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn forced_worker_stop_permanently_revokes_its_dns_fence() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        done_tx.send(()).unwrap();
    });
    let worker = RuntimeWorker::new(thread, done_rx);
    let continuation = DnsContinuation {
        policy: policy(),
        stop_fence: worker.dns_stop_fence.clone(),
        packet_tunnel: false,
    };
    assert_eq!(
        worker.stop(Duration::from_secs(1), || {}),
        StopResult::Stopped
    );
    assert!(continuation.is_ready());
    worker.abandon();
    assert!(!continuation.is_ready());
}

#[test]
fn retained_dns_continuation_does_not_own_the_native_descriptor() {
    let (tun, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let runtime =
        CoreRuntime::start(101, config(), OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    let continuation = runtime.dns_continuation();
    assert_eq!(runtime.stop(), StopResult::Stopped);
    drop(runtime);
    assert!(continuation.is_ready());
    assert_eq!(
        peer.read(&mut [0_u8; 1]).unwrap(),
        0,
        "continuation retained the TUN endpoint"
    );
}

#[test]
fn flow_dns_continuation_cannot_enter_a_packet_tunnel_even_after_policy_became_real_ip() {
    let source = policy();
    source
        .reload(
            None,
            foxcore_route::RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig {
                mode: foxcore_api::DnsMode::FakeIp,
                ..Default::default()
            },
        )
        .unwrap();
    source
        .reload(
            None,
            foxcore_route::RouteTable::compile(Vec::new(), RouteAction::Direct),
            DnsConfig::default(),
        )
        .unwrap();
    let continuation = DnsContinuation {
        policy: source,
        stop_fence: Arc::new(AtomicU8::new(WORKER_STOPPED)),
        packet_tunnel: false,
    };
    assert_eq!(
        continuation.dns_for_start(true).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    let packet = DnsContinuation {
        policy: policy(),
        stop_fence: Arc::new(AtomicU8::new(WORKER_STOPPED)),
        packet_tunnel: true,
    };
    assert!(packet.dns_for_start(true).is_ok());
}

#[test]
fn dns_continuation_reads_latest_policy_after_pre_stop_capture() {
    let (master, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        102,
        config(),
        OwnedFd::from(master.try_clone().unwrap()),
        SocketCallbacks::none(),
    )
    .unwrap();
    let continuation = runtime.dns_continuation();
    let initial = runtime.policy.dns_for_continuation();
    runtime
        .reload_policy(PolicyConfig {
            expected_revision: Some(1),
            dns: config().dns,
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .unwrap();
    let latest = runtime.policy.dns_for_continuation();
    assert!(!Arc::ptr_eq(&initial, &latest));
    let query = [
        0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c',
        b'o', b'm', 0, 0, 1, 0, 1,
    ];
    let cfg = config().dns;
    let answer = latest
        .fake_response(&query, cfg.fake_ipv4_pool, cfg.fake_ipv6_pool, 300)
        .unwrap();
    let bytes = &answer[answer.len() - 4..];
    let address = IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
    latest.observe_response(&answer);
    assert!(initial.reverse_domain(address).is_none());
    assert_eq!(runtime.stop(), StopResult::Stopped);
    let successor = CoreRuntime::start_with_dns_continuation(
        103,
        config(),
        OwnedFd::from(master.try_clone().unwrap()),
        SocketCallbacks::none(),
        Some(continuation),
    )
    .unwrap();
    assert_eq!(
        successor
            .policy
            .dns_for_continuation()
            .reverse_domain(address)
            .as_deref(),
        Some("example.com")
    );
    assert_eq!(successor.stop(), StopResult::Stopped);
}

#[cfg(feature = "wireguard")]
#[test]
fn dns_continuation_revoked_during_start_retires_the_unpublished_worker() {
    let continuation = DnsContinuation {
        policy: policy(),
        stop_fence: Arc::new(AtomicU8::new(WORKER_STOPPED)),
        packet_tunnel: true,
    };
    let peer_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let cfg = packet_tunnel_engine_config(peer_socket.local_addr().unwrap());
    let (tun, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Arc::new(Mutex::new(release_rx));
    let callbacks = SocketCallbacks::protect_only(move |_| {
        entered_tx.send(()).unwrap();
        release_rx.lock().unwrap().recv().unwrap();
        true
    });
    let starting = {
        let cloned = continuation.clone();
        std::thread::spawn(move || {
            CoreRuntime::start_with_dns_continuation(
                104,
                cfg,
                OwnedFd::from(tun),
                callbacks,
                Some(cloned),
            )
        })
    };
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    continuation.revoke();
    release_tx.send(()).unwrap();
    match starting.join().unwrap() {
        Ok(runtime) => {
            let _ = runtime.stop();
            panic!("revoked successor was published");
        }
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
    }
    assert_eq!(
        peer.read(&mut [0_u8; 1]).unwrap(),
        0,
        "unpublished successor retained its native descriptor"
    );
}

#[test]
fn quarantined_dns_cleanup_is_typed_and_retains_descriptor_ownership() {
    let (tun, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let owner = tun;
        release_rx.recv().unwrap();
        drop(owner);
        let _ = done_tx.send(());
    });
    let worker = RuntimeWorker::new(thread, done_rx);
    let continuation = DnsContinuation {
        policy: policy(),
        stop_fence: worker.dns_stop_fence.clone(),
        packet_tunnel: false,
    };
    assert_eq!(
        worker.stop(Duration::from_millis(5), || {}),
        StopResult::TimedOut
    );
    let forced = worker.abandon();
    assert_eq!(forced, StopResult::TimedOut);
    let error = io::Error::new(
        io::ErrorKind::TimedOut,
        DnsContinuationCleanupError { force_stop: forced },
    );
    assert_eq!(
        dns_continuation_cleanup_result(&error),
        Some(StopResult::TimedOut)
    );
    assert!(!continuation.is_ready());
    drop(worker);
    let pending = peer.read(&mut [0_u8; 1]).unwrap_err().kind();
    assert!(matches!(
        pending,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    release_tx.send(()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(peer.read(&mut [0_u8; 1]).unwrap(), 0);
    reap_quarantined_workers();
}
