use super::*;

#[test]
fn a_timed_out_stop_keeps_the_worker_owned_and_can_be_retried() {
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let _ = release_rx.recv();
        let _ = done_tx.send(());
    });
    let worker = RuntimeWorker::new(thread, done_rx);
    let mut stop_requests = 0;

    assert_eq!(
        worker.stop(Duration::from_millis(10), || stop_requests += 1),
        StopResult::TimedOut
    );
    assert_eq!(stop_requests, 1);
    assert_eq!(worker.state.load(Ordering::Acquire), WORKER_STOPPING);
    assert!(
        lock(&worker.thread).is_some(),
        "a timeout must not detach the worker"
    );

    release_tx.send(()).unwrap();
    assert_eq!(
        worker.stop(Duration::from_secs(1), || {
            panic!("a retry must not request cancellation twice")
        }),
        StopResult::Stopped
    );
    assert!(lock(&worker.thread).is_none());
    assert_eq!(
        worker.stop(Duration::ZERO, || unreachable!()),
        StopResult::AlreadyStopped
    );
}

#[test]
fn runtime_start_stop_is_owned_and_idempotent() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let tun_fd = OwnedFd::from(tun);
    let config = EngineConfig {
        schema_version: foxcore_api::SCHEMA_VERSION,
        outbound: OutboundConfig::Vless(VlessConfig {
            server: "bootstrap.invalid".into(),
            port: 443,
            server_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            uuid: SecretString::new("d0cf0001-0000-4000-8000-000000000000"),
            flow: None,
            transport: StreamTransportConfig::Raw,
            packet_encoding: foxcore_api::PacketEncoding::None,
            tls: TlsConfig::default(),
            reality: None,
            encryption: None,
        }),
        outbounds: Vec::new(),
        tun: TunConfig {
            mtu: 1400,
            ipv4: "10.77.0.1".into(),
            ipv6: None,
        },
        dns: DnsConfig::default(),
        runtime: RuntimeConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig::default(),
    };

    let (identity_tun, _identity_peer) = UnixStream::pair().unwrap();
    let mut identity_config = config.clone();
    identity_config.routes.push(foxcore_api::RouteRule {
        uid: Some(10_123),
        package: None,
        exact_domains: Vec::new(),
        domain_suffixes: Vec::new(),
        cidrs: Vec::new(),
        ports: Vec::new(),
        network: None,
        transport: None,
        action: RouteAction::Block,
        expires_at_ms: None,
    });
    let identity_error = match CoreRuntime::start(
        41,
        identity_config,
        OwnedFd::from(identity_tun),
        SocketCallbacks::none(),
    ) {
        Ok(runtime) => {
            let _ = runtime.stop();
            panic!("identity policy started without a platform attributor");
        }
        Err(error) => error,
    };
    assert_eq!(identity_error.kind(), io::ErrorKind::Unsupported);

    let runtime = CoreRuntime::start(42, config, tun_fd, SocketCallbacks::none()).unwrap();
    assert_eq!(runtime.generation(), 42);
    assert_eq!(runtime.policy_revision(), 1);
    assert!(runtime.snapshot_json().contains("\"generation\":42"));
    assert_eq!(
        runtime
            .reload_policy(PolicyConfig {
                expected_revision: Some(1),
                dns: DnsConfig::default(),
                routes: Vec::new(),
                traffic: TrafficPolicyConfig::default(),
            })
            .unwrap(),
        2
    );
    let stale = runtime
        .reload_policy(PolicyConfig {
            expected_revision: Some(1),
            dns: DnsConfig::default(),
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .unwrap_err();
    assert_eq!(stale.refusal, PolicyRefusal::RevisionConflict);
    assert!(runtime.snapshot_json().contains("\"policy_revision\":2"));

    // The remainder of D11. The code is what the app switches on, and seven
    // of the eight are enough on their own; `-1` is not, because it covers
    // a truncated write and a field this schema removed in one value. What
    // the JNI returns is a `jlong` and cannot carry words, so the words
    // have to survive the call that produced them.
    let invalid = runtime
        .reload_policy(PolicyConfig {
            expected_revision: None,
            dns: DnsConfig {
                blocklist: foxcore_api::DnsBlocklistConfig {
                    suffixes: vec!["ads.example".into()],
                    ..Default::default()
                },
                ..DnsConfig::default()
            },
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .unwrap_err();
    assert_eq!(invalid.refusal, PolicyRefusal::Invalid);
    let detail = runtime
        .last_policy_error()
        .expect("a refused reload has to leave its reason behind");
    assert!(
        detail.contains("dns.advertise"),
        "the field that was wrong is the whole diagnosis: {detail}"
    );
    // Cleared by the next reload that works, so a reading taken later can
    // never be a stale reason for a policy that is live.
    runtime
        .reload_policy(PolicyConfig {
            expected_revision: None,
            dns: DnsConfig::default(),
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .expect("a valid policy still applies");
    assert_eq!(runtime.last_policy_error(), None);
    // The parse failure never reaches `reload_policy` — there is no
    // `PolicyConfig` yet — and it is the commonest `-1` there is, so the
    // JNI records it through the same door.
    runtime.record_policy_error("invalid JSON: expected `,` at line 3 column 9");
    assert!(
        runtime
            .last_policy_error()
            .is_some_and(|detail| detail.contains("line 3")),
        "a document that did not parse is a different bug from one that did"
    );

    let components = runtime.component_manager();
    let web_app = WebAppConfig {
        id: ComponentId::new("web:runtime-liveness").unwrap(),
        origin: "https://runtime.example".into(),
        route: ComponentRoute::Vpn,
        notifications_enabled: true,
    };
    components.register_web_app(web_app.clone()).unwrap();
    let lease = components
        .acquire(&web_app.id, LeasePurpose::WebNavigation)
        .unwrap();
    assert!(
        components
            .authorize(&lease, ComponentOperation::Navigation)
            .is_ok()
    );
    assert_eq!(runtime.stop(), StopResult::Stopped);
    assert_eq!(
        components.authorize(&lease, ComponentOperation::Navigation),
        Err(ComponentError::RuntimeUnavailable)
    );
    assert_eq!(runtime.stop(), StopResult::AlreadyStopped);
}

/// The defect this pass exists to close, at the level it was found.
///
/// Three device-acceptance runs were lost to `Arti bootstrap failed: problem
/// with filesystem permissions`, and on each of them the engine did
/// not start *at all* — no tun, no VPN lane, no I2P lane, no direct lane —
/// because the outbound builds were collected with `?`. The message was
/// fixed at the time and the isolation defect underneath it was not.
///
/// Tor stands in for itself here: this build does not carry the `tor`
/// feature, so the profile below fails to build deterministically and
/// offline, which is the same start-time failure with none of Arti's
/// weight.
#[test]
fn an_outbound_that_cannot_be_built_leaves_the_engine_and_the_other_lanes_running() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let config = EngineConfig {
        schema_version: foxcore_api::SCHEMA_VERSION,
        outbound: OutboundConfig::Vless(VlessConfig {
            server: "bootstrap.invalid".into(),
            port: 443,
            server_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            uuid: SecretString::new("d0cf0001-0000-4000-8000-000000000000"),
            flow: None,
            transport: StreamTransportConfig::Raw,
            packet_encoding: foxcore_api::PacketEncoding::None,
            tls: TlsConfig::default(),
            reality: None,
            encryption: None,
        }),
        outbounds: vec![NamedOutboundConfig {
            id: OutboundId("tor".into()),
            outbound: tor_profile(),
        }],
        tun: TunConfig {
            mtu: 1400,
            ipv4: "10.77.0.3".into(),
            ipv6: None,
        },
        dns: DnsConfig::default(),
        runtime: RuntimeConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig::default(),
    };

    // The assertion the old code could not pass: it returned `Err` here.
    let runtime =
        CoreRuntime::start(61, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();

    let unavailable = runtime.unavailable_outbounds();
    assert_eq!(unavailable.len(), 1, "only the lane that failed is down");
    assert_eq!(unavailable[0].id, "tor");
    assert_eq!(
        unavailable[0].kind, "tor",
        "a lane that failed to build is still the lane the profile asked for"
    );
    // Which failure this is depends on whether the Tor lane is compiled in,
    // and that stopped being a property of this crate alone the day `tor`
    // became a default feature of `foxcore-android`: a workspace test build
    // unifies it on, `cargo test -p foxcore-runtime` leaves it off, and the
    // same source produces `Internal` in one and `Unsupported` in the
    // other. Both are deterministic — `tor_profile()` points at
    // `/nonexistent/state`, so a compiled-in Arti fails to build its state
    // directory every time, and an absent one refuses the profile outright
    // — so the expectation is selected rather than loosened. Loosening it
    // to "either" would give up the distinction between a lane this build
    // cannot carry and a lane that broke.
    let expected = if cfg!(feature = "tor") {
        foxcore_api::UnavailableReason::Internal
    } else {
        foxcore_api::UnavailableReason::Unsupported
    };
    assert_eq!(unavailable[0].reason, expected);
    assert_eq!(unavailable[0].attempts, 1);

    // Visible without asking a second question, and visible in the stream
    // as well as in the poll: a lane that is down and silent is the failure
    // mode this core has already paid for three times.
    let snapshot = runtime.snapshot_json();
    assert!(
        snapshot.contains(r#""unavailable":[{"id":"tor""#),
        "{snapshot}"
    );
    let events = runtime.drain_events_json(16);
    assert!(events.contains("outbound_unavailable"), "{events}");
    let expected_json = if cfg!(feature = "tor") {
        r#""reason":"internal""#
    } else {
        r#""reason":"unsupported""#
    };
    assert!(events.contains(expected_json), "{events}");

    // And the reason code is not decoration: it decides whether the lane is
    // ever tried again. A protocol that is not in the build never becomes
    // available, so retrying it is a busy wait on a phone — zero attempts.
    // An `Internal` failure is a different claim: something went wrong that
    // might not be wrong later, so the lane is retried. Here it will fail
    // again, because the directory it names cannot exist, and the lane
    // stays down — which is the behaviour under test either way.
    let expected_retries = usize::from(cfg!(feature = "tor"));
    assert_eq!(runtime.retry_unavailable_outbounds(), expected_retries);
    runtime.network_changed_with_handle(7);
    assert_eq!(runtime.unavailable_outbounds().len(), 1);

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

#[test]
fn a_switched_off_tor_lane_is_never_bootstrapped() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let config = EngineConfig {
        schema_version: foxcore_api::SCHEMA_VERSION,
        outbound: OutboundConfig::Vless(VlessConfig {
            server: "bootstrap.invalid".into(),
            port: 443,
            server_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            uuid: SecretString::new("d0cf0001-0000-4000-8000-000000000000"),
            flow: None,
            transport: StreamTransportConfig::Raw,
            packet_encoding: foxcore_api::PacketEncoding::None,
            tls: TlsConfig::default(),
            reality: None,
            encryption: None,
        }),
        outbounds: vec![NamedOutboundConfig {
            id: OutboundId("tor".into()),
            outbound: tor_profile(),
        }],
        tun: TunConfig {
            mtu: 1400,
            ipv4: "10.77.0.4".into(),
            ipv6: None,
        },
        dns: DnsConfig::default(),
        runtime: RuntimeConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig {
            tor_enabled: Some(false),
            ..Default::default()
        },
    };

    let runtime =
        CoreRuntime::start(62, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();

    let unavailable = runtime.unavailable_outbounds();
    assert_eq!(unavailable.len(), 1);
    assert_eq!(unavailable[0].id, "tor");
    assert_eq!(
        unavailable[0].kind, "tor",
        "the entry stays, or .onion would refuse as 'no Tor outbound' instead of 'the overlay is off'"
    );
    assert_eq!(
        unavailable[0].reason,
        foxcore_api::UnavailableReason::Disabled,
        "and it is reported as switched off rather than as any kind of failure"
    );
    assert_eq!(unavailable[0].attempts, 0, "nothing was ever attempted");
    assert!(
        runtime.outbounds.tor().is_some(),
        "the .onion gate reads this: Some() is what makes the refusal say 'disabled by the \
         active traffic policy' rather than 'requires a registered Tor outbound'"
    );

    let events = runtime.drain_events_json(16);
    assert!(!events.contains("outbound_unavailable"), "{events}");
    let snapshot = runtime.snapshot_json();
    assert!(snapshot.contains(r#""reason":"disabled""#), "{snapshot}");

    assert_eq!(runtime.retry_unavailable_outbounds(), 0);
    runtime.network_changed_with_handle(7);
    let after = runtime.unavailable_outbounds();
    assert_eq!(after.len(), 1);
    assert_eq!(
        after[0].attempts, 0,
        "a network change must not resurrect a lane the user switched off"
    );
    assert_eq!(after[0].reason, foxcore_api::UnavailableReason::Disabled);

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

#[cfg(feature = "wireguard")]
#[test]
fn a_packet_tunnel_generation_refuses_a_reload_that_turns_on_fake_ip() {
    // Held open for the life of the test so the peer port exists and the
    // handshake this runtime starts sending is dropped rather than bounced.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = peer.local_addr().unwrap();
    let (tun, _peer_end) = UnixStream::pair().unwrap();
    let config = packet_tunnel_engine_config(endpoint);

    let runtime =
        CoreRuntime::start(51, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    let error = runtime
        .reload_policy(PolicyConfig {
            expected_revision: Some(1),
            dns: DnsConfig {
                mode: foxcore_api::DnsMode::FakeIp,
                ..DnsConfig::default()
            },
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .expect_err("this policy would black-hole every clearnet flow");
    assert_eq!(error.refusal, PolicyRefusal::PacketTunnelRejectsFakeIp);
    assert!(
        error.message.contains("fake_ip") && error.message.contains("packet tunnel"),
        "the refusal has to name both sides: {}",
        error.message
    );
    assert_eq!(
        runtime.policy_revision(),
        1,
        "a refused reload must not have replaced anything"
    );
    assert_eq!(
        runtime
            .reload_policy(PolicyConfig {
                expected_revision: Some(1),
                dns: DnsConfig::default(),
                routes: Vec::new(),
                traffic: TrafficPolicyConfig::default(),
            })
            .expect("everything else about this reload is ordinary"),
        2
    );
    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The same reload hole for the other thing the DNS block asks of the
/// primary outbound, and the one nobody has to opt into: `dns.route`
/// defaults to `primary`, so a policy that merely turns on an upstream asks
/// for it. A running generation's outbound is fixed, so start-time
/// validation cannot see this arrive — and what arrives is a resolver whose
/// every lookup goes out on the clearnet placeholder standing in for the
/// tunnel, in full view of the network the tunnel was there to hide from.
#[cfg(feature = "wireguard")]
#[test]
fn a_packet_tunnel_generation_refuses_a_reload_that_resolves_through_the_primary() {
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let endpoint = peer.local_addr().unwrap();
    let (tun, _peer_end) = UnixStream::pair().unwrap();

    let runtime = CoreRuntime::start(
        52,
        packet_tunnel_engine_config(endpoint),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();
    let intercepting = DnsConfig {
        upstreams: vec![foxcore_api::DnsUpstream::Udp {
            address: "1.1.1.1:53".into(),
        }],
        ..DnsConfig::default()
    };
    assert_eq!(
        intercepting.route,
        DnsRoute::Primary,
        "this test is only meaningful while `primary` is what a policy gets \
             without asking for it"
    );

    let error = runtime
        .reload_policy(PolicyConfig {
            expected_revision: Some(1),
            dns: intercepting.clone(),
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .expect_err("this policy would resolve every name outside the tunnel");
    assert_eq!(error.refusal, PolicyRefusal::PacketTunnelRejectsPrimaryDns);
    assert_eq!(
        runtime.policy_revision(),
        1,
        "a refused reload must not have replaced anything"
    );

    // Naming the direct route is a choice the document made, and it stays
    // available: the refusal is about the route nobody selected.
    assert_eq!(
        runtime
            .reload_policy(PolicyConfig {
                expected_revision: Some(1),
                dns: DnsConfig {
                    route: DnsRoute::Direct,
                    ..intercepting
                },
                routes: Vec::new(),
                traffic: TrafficPolicyConfig::default(),
            })
            .expect("an explicitly direct resolver is a different question"),
        2
    );
    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The shape the Android app actually emits: every node wrapped in one
/// group, and the group as the primary outbound. Before `selector` existed
/// this config could not start at all.
#[test]
fn a_selector_profile_starts_and_reports_config_applied() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let config = EngineConfig {
        schema_version: foxcore_api::SCHEMA_VERSION,
        outbound: OutboundConfig::Selector(foxcore_api::SelectorConfig {
            members: vec![
                vless_member("node-a", [203, 0, 113, 7]),
                vless_member("node-b", [203, 0, 113, 8]),
            ],
            default: Some(OutboundId("node-b".into())),
            member_timeout_ms: None,
            probe: None,
        }),
        outbounds: Vec::new(),
        tun: TunConfig {
            mtu: 1400,
            ipv4: "10.77.0.1".into(),
            ipv6: None,
        },
        dns: DnsConfig::default(),
        runtime: RuntimeConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig::default(),
    };
    config
        .validate()
        .expect("the app's own shape must validate");

    let runtime =
        CoreRuntime::start(43, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    assert!(
        runtime.drain_events(16).events.is_empty(),
        "nothing has happened yet, so the audit stream must be empty"
    );

    // D3: the app could not tell which member failover landed on. The
    // stats document and the traffic map both have to name it, because the
    // two screens that ask are different screens.
    let stats: serde_json::Value = serde_json::from_str(&runtime.snapshot_json()).unwrap();
    assert_eq!(stats["selectors"][0]["tag"], "default");
    assert_eq!(stats["selectors"][0]["active"], "node-b");
    let map: serde_json::Value = serde_json::from_str(&runtime.traffic_map_json()).unwrap();
    assert_eq!(map["selectors"][0]["active"], "node-b");
    assert_eq!(
        map["lanes"].as_array().map(Vec::len),
        Some(4),
        "every lane is reported, so an empty one reads as zero rather than as missing"
    );
    assert_eq!(map["lanes"][0]["lane"], "vpn");
    assert_eq!(map["dns"]["allowed"], 0);
    assert_eq!(map["connections"].as_array().map(Vec::len), Some(0));

    let revision = runtime
        .reload_policy(PolicyConfig {
            expected_revision: Some(1),
            dns: DnsConfig::default(),
            routes: Vec::new(),
            traffic: TrafficPolicyConfig::default(),
        })
        .unwrap();
    let drain = runtime.drain_events(16);
    assert_eq!(drain.dropped, 0);
    assert_eq!(
        drain.events,
        vec![CoreEvent::ConfigApplied {
            revision,
            previous_revision: revision - 1,
        }]
    );

    // A rejected reload must not appear in the audit trail as an applied one.
    let _ = runtime.reload_policy(PolicyConfig {
        expected_revision: Some(1),
        dns: DnsConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig::default(),
    });
    assert!(
        runtime.drain_events(16).events.is_empty(),
        "a refused reload is not a config change"
    );

    assert_eq!(runtime.stop(), StopResult::Stopped);
}
