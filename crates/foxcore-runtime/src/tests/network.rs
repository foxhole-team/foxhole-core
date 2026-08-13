use super::*;

#[test]
fn control_proxy_is_ready_before_start_returns_and_closes_with_the_runtime() {
    use std::io::{Read as _, Write as _};

    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.runtime.control_proxy = Some(ControlProxyConfig {
        http_port: port,
        username: "foxhole-runtime".into(),
        password: SecretString::new("process-local-secret"),
    });
    config.validate().expect("control proxy config");

    let runtime =
        CoreRuntime::start(44, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    let mut client = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .expect("listener must be ready when start returns");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 407"), "{response}");

    assert_eq!(runtime.stop(), StopResult::Stopped);
    assert!(
        std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
        "the control listener must not outlive its root runtime"
    );
}

/// The LAN ingress from the outside: confirm, start, read the status the app
/// draws, lose the network, stop.
///
/// The status document is the whole point of the test. The component has been
/// able to do this for some time; what did not exist was a way for the app to
/// start it or to see what it was doing, so the screen drew a saved toggle as
/// though it were live state. Each assertion below is one thing that toggle got
/// wrong: it said "on" for a network nobody confirmed, it said "on" with no
/// address to point a laptop at, and it kept saying "on" after the Wi-Fi moved
/// and the listener had gone.
#[test]
fn a_lan_proxy_is_started_owned_and_reported_as_it_actually_is() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        61,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();

    let status = |runtime: &CoreRuntime| -> serde_json::Value {
        serde_json::from_str(&runtime.lan_proxy_status_json()).expect("a well-formed document")
    };
    let binding = NetworkBinding {
        network_handle: 9,
        interface_name: "wlan0".into(),
        local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ssid_hash: Some([5_u8; 32]),
        transport: LanTransport::Wifi,
        generation: runtime.generation(),
    };
    let config = || LanProxyConfig {
        id: ComponentId::new("runtime:lan-proxy").unwrap(),
        preset: LanProxyPreset::Vpn,
        socks_port: port,
        http_port: 0,
        credentials: LanCredentials::new("laptop", b"correct horse".to_vec()).unwrap(),
    };

    // Nothing started: a well-formed document rather than nothing at all.
    assert_eq!(status(&runtime)["state"], "stopped");
    assert!(status(&runtime)["preset"].is_null());
    assert!(status(&runtime)["last_error"].is_null());

    // A network nobody confirmed binds nothing, and says why in the one place
    // the screen reads.
    assert_eq!(
        runtime.install_lan_proxy(config(), binding.clone()),
        Err(ComponentError::LanNetworkNotConfirmed)
    );
    assert_eq!(status(&runtime)["state"], "stopped");
    assert!(
        !status(&runtime)["last_error"].is_null(),
        "a refusal the user can act on must not be silent"
    );

    runtime
        .component_manager()
        .confirm_lan_network(&binding)
        .unwrap();
    runtime
        .install_lan_proxy(config(), binding.clone())
        .unwrap();

    let running = status(&runtime);
    assert_eq!(running["state"], "ready");
    assert_eq!(
        running["socks_address"],
        format!("{}:{port}", Ipv4Addr::LOCALHOST)
    );
    assert!(
        running["http_address"].is_null(),
        "a protocol that was not offered has no address"
    );
    assert_eq!(running["preset"], "vpn");
    assert_eq!(running["network_handle"], 9);
    assert!(
        running["last_error"].is_null(),
        "a start that worked must clear the previous refusal"
    );
    assert!(
        std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "the status says ready, so something has to be listening"
    );

    // The Wi-Fi moved. Rule 4: the listeners close and the credentials are
    // invalidated — no exception for a continuity hold, and no silent rebind.
    runtime.network_changed();
    assert_eq!(
        status(&runtime)["state"],
        "network_lost",
        "\"the proxy you started is gone\" and \"you never started one\" are \
         different sentences"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
        assert!(
            Instant::now() < deadline,
            "the listener outlived its network"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // The same network can be started again once it is confirmed: the identity
    // has to have come back with the handle that was torn down.
    runtime.install_lan_proxy(config(), binding).unwrap();
    assert_eq!(status(&runtime)["state"], "ready");

    assert_eq!(runtime.stop(), StopResult::Stopped);
    assert_eq!(
        status(&runtime)["state"],
        "stopped",
        "no listener may outlive its root runtime"
    );
    assert!(
        std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
        "the LAN listener must go down with the engine"
    );
}

/// The transition, not the config: a network change with
/// `seamless_network_switch` off must suspend traffic, publish a token, and
/// resume only when that exact token comes back.
#[test]
fn a_network_switch_the_user_disallowed_holds_traffic_until_it_is_confirmed() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.traffic = manual_continuity(0);

    let runtime =
        CoreRuntime::start(51, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    assert!(runtime.continuity_state().held_lanes.is_empty());

    runtime.network_changed_with_handle(7);

    let state = runtime.continuity_state();
    assert_eq!(
        state.held_lanes,
        vec!["vpn", "tor", "i2p", "direct"],
        "the network moved under every lane, so every lane is suspended"
    );
    assert_eq!(
        state.interruption,
        Some(ContinuityInterruption::NetworkSwitch)
    );
    let token = state.pending_token.expect("a hold must be answerable");
    let drain = runtime.drain_events(16);
    assert_eq!(
        drain.events,
        vec![CoreEvent::ConfirmationRequired {
            interruption: ContinuityInterruption::NetworkSwitch,
            token,
            expires_in_ms: None,
        }],
        "the default hold has no deadline, so there is none to report and none to expire"
    );
    let snapshot: serde_json::Value = serde_json::from_str(&runtime.snapshot_json()).unwrap();
    assert_eq!(snapshot["continuity"]["interruption"], "network_switch");

    assert_eq!(
        runtime.confirm_continuity(token.wrapping_add(1)),
        ConfirmResult::StaleToken
    );
    assert!(
        !runtime.continuity_state().held_lanes.is_empty(),
        "a token this core never minted must not release anything"
    );

    assert_eq!(runtime.confirm_continuity(token), ConfirmResult::Confirmed);
    assert!(runtime.continuity_state().held_lanes.is_empty());
    assert_eq!(
        runtime.confirm_continuity(token),
        ConfirmResult::NothingPending
    );
    assert!(
        runtime.snapshot_json().find("continuity").is_none(),
        "a resolved hold leaves no row that permanently reads 'nothing is wrong'"
    );

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The packet tunnel's socket obeys the same flag as everything else.
///
/// `seamless_network_switch` off means a network change is an explicit
/// reconnect the user has to approve, and "the lanes are held but the
/// tunnel quietly moved to the new network anyway" is exactly the silent
/// half of a repair the flag exists to forbid. So the epoch the relay
/// watches must not move until the confirmation arrives — and then it must.
///
/// Asserted on the signal rather than on a live relay because this profile
/// has no packet tunnel: the question here is whether the runtime raises
/// the signal at all, and `relay.rs` proves what happens when it does.
#[test]
fn a_held_network_switch_leaves_the_packet_tunnel_where_it_was() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.traffic = manual_continuity(0);

    let runtime =
        CoreRuntime::start(55, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    assert_eq!(*runtime.network_epoch.borrow(), 0);

    runtime.network_changed_with_handle(7);
    assert_eq!(
        *runtime.network_epoch.borrow(),
        0,
        "a held switch must not send the relay looking for a new socket"
    );
    assert_eq!(
        runtime.dialer.network_handle(),
        0,
        "and must not bind anything to the network it has not been allowed to use"
    );

    let token = runtime
        .continuity_state()
        .pending_token
        .expect("a hold must be answerable");
    assert_eq!(runtime.confirm_continuity(token), ConfirmResult::Confirmed);
    assert_eq!(
        *runtime.network_epoch.borrow(),
        1,
        "confirmation is what performs the switch, and it performs all of it"
    );
    assert_eq!(runtime.dialer.network_handle(), 7);

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The default: the core is allowed to heal itself, so the relay is told
/// once per change and no confirmation is raised.
#[test]
fn a_permitted_network_switch_tells_the_relay_immediately() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        56,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();

    runtime.network_changed_with_handle(7);
    runtime.network_changed();

    assert_eq!(
        *runtime.network_epoch.borrow(),
        2,
        "a counter, not a flag: two changes in a row must both reach a relay \
             that was mid-rebind for the first"
    );
    assert!(runtime.continuity_state().pending_token.is_none());

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The defect reproduced by device acceptance. The hold blocked
/// traffic honestly for its whole life and then, at the deadline, stopped
/// the engine — which on Android takes `tun0` down, and the next flow
/// carried the fingerprint of a device with no tunnel at all. A hold that
/// ends in clearnet is the exact outcome the flag is switched off to
/// prevent, so the deadline must leave the tunnel and every held lane
/// exactly where they were.
#[test]
fn an_unanswered_confirmation_never_resolves_into_having_no_tunnel() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.traffic = manual_continuity(1_000);
    config.validate().expect("the shortest allowed deadline");

    let runtime =
        CoreRuntime::start(54, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    runtime.network_changed();
    let token = runtime
        .continuity_state()
        .pending_token
        .expect("a hold must be answerable");

    // The deadline is one second; wait for the watch to reach it rather
    // than for a fixed sleep to be long enough.
    let give_up = Instant::now() + Duration::from_secs(15);
    while Instant::now() < give_up && !runtime.continuity_state().expired {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        runtime.continuity_state().expired,
        "the deadline must be noticed, or this test is measuring nothing"
    );

    assert!(
        !runtime.cancel.is_cancelled(),
        "a hold that ran out of time must not end by taking the tunnel down"
    );
    assert!(runtime.availability.load(Ordering::Acquire));
    assert_eq!(
        runtime.continuity_state().held_lanes,
        vec!["vpn", "tor", "i2p", "direct"],
        "every lane stays refused, so the next flow cannot go around the tunnel"
    );
    assert_eq!(
        runtime.continuity_state().pending_token,
        Some(token),
        "the question is still open and still answerable with the same token"
    );
    assert_eq!(runtime.confirm_continuity(token), ConfirmResult::Confirmed);

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The other half of the same defect: around the deadline the device's
/// event drain reported `count=0`. Protection changing state is not a thing
/// an app should have to discover by polling `connected`.
#[test]
fn a_deadline_that_passes_is_reported_once_and_only_once() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.traffic = manual_continuity(1_000);
    config.validate().expect("the shortest allowed deadline");

    let runtime =
        CoreRuntime::start(55, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    runtime.network_changed();
    let token = runtime
        .continuity_state()
        .pending_token
        .expect("a hold must be answerable");

    let give_up = Instant::now() + Duration::from_secs(15);
    while Instant::now() < give_up && !runtime.continuity_state().expired {
        std::thread::sleep(Duration::from_millis(25));
    }

    let drain = runtime.drain_events(16);
    assert_eq!(drain.dropped, 0);
    assert_eq!(
        drain.events,
        vec![
            CoreEvent::ConfirmationRequired {
                interruption: ContinuityInterruption::NetworkSwitch,
                token,
                expires_in_ms: Some(1_000),
            },
            CoreEvent::ConfirmationExpired {
                interruption: ContinuityInterruption::NetworkSwitch,
                token,
            },
        ]
    );

    // A spent deadline is spent: a watch that wakes again must not
    // re-announce it, or a hold left overnight becomes a stream of them.
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(runtime.drain_events(16).events.is_empty());

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The engine survives its own deadline, and the config that used to end it
/// is refused before a runtime is ever built.
///
/// Two halves, and the order matters. First the door: a policy naming
/// `confirmation_timeout_action` does not parse, so an app that still asks
/// for a timed stop learns it at reload time with the field named, rather
/// than by a preference that silently did nothing. Then the behaviour: with
/// the shortest deadline the validator allows, the watch fires, publishes,
/// and leaves the engine running.
#[test]
fn a_deadline_cannot_stop_the_engine_and_the_config_that_asked_it_to_is_refused() {
    let refused = PolicyConfig::parse(
        r#"{"traffic":{"continuity":{"seamless_network_switch":false,
                "confirmation_timeout_ms":1000,
                "confirmation_timeout_action":"stop_engine_leaving_network_open"}}}"#,
    )
    .expect_err("the timed stop must be unreachable from a config, not merely unused");
    assert!(
        refused.to_string().contains("confirmation_timeout_action"),
        "the app has to be told which field to drop, got: {refused}"
    );

    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.traffic = manual_continuity(1_000);
    config.validate().expect("the shortest allowed deadline");

    let runtime =
        CoreRuntime::start(52, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    runtime.network_changed();
    let token = runtime
        .continuity_state()
        .pending_token
        .expect("a hold must be answerable");

    let give_up = Instant::now() + Duration::from_secs(15);
    while Instant::now() < give_up && !runtime.continuity_state().expired {
        std::thread::sleep(Duration::from_millis(25));
    }

    assert!(
        runtime.continuity_state().expired,
        "the deadline has to actually fire, or the rest of this proves nothing"
    );
    assert!(
        !runtime.cancel.is_cancelled(),
        "the engine outlives the deadline: this is the defect the removal closes"
    );
    assert!(
        runtime.availability.load(Ordering::Acquire),
        "and it is still available, not a half-torn engine holding descriptors"
    );
    assert_eq!(
        runtime.drain_events(16).events.last(),
        Some(&CoreEvent::ConfirmationExpired {
            interruption: ContinuityInterruption::NetworkSwitch,
            token,
        }),
        "the pause is reported; that is the whole of what the deadline does"
    );
    assert!(
        !runtime.continuity_state().held_lanes.is_empty(),
        "and every lane the hold suspended is still suspended"
    );

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

// ---------------------------------------------------------- loopback inbounds

fn inbound_config(name: &str, upstream: LoopbackUpstream) -> LoopbackInboundConfig {
    LoopbackInboundConfig {
        name: name.to_owned(),
        // Ephemeral: the point of the status document is that the app reads the
        // port back rather than reserving one and hoping.
        http_port: 0,
        username: Some(format!("user-{name}")),
        password: Some(SecretString::new(format!("secret-{name}"))),
        upstream,
        max_sessions: 4,
    }
}

fn inbound_rows(runtime: &CoreRuntime) -> Vec<serde_json::Value> {
    let document: serde_json::Value =
        serde_json::from_str(&runtime.loopback_inbounds_json()).expect("a well-formed document");
    document["inbounds"].as_array().cloned().unwrap_or_default()
}

/// The address a web app is pointed at comes from the core, not from the config.
///
/// Two inbounds on ephemeral ports, each with its own credentials and its own
/// upstream. Everything the Kotlin side needs to build a `Proxy` is in this one
/// document, which is the whole contract: a saved port number would be a guess,
/// and the failure mode of a wrong guess on Android is a web app that silently
/// uses the system network.
#[test]
fn named_inbounds_report_the_ports_they_actually_bound() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.runtime.loopback_inbounds = vec![
        inbound_config("webapp.a", LoopbackUpstream::Profile),
        inbound_config("webapp.b", LoopbackUpstream::Direct),
    ];
    config.validate().expect("two distinct named inbounds");

    let runtime =
        CoreRuntime::start(70, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    let rows = inbound_rows(&runtime);
    assert_eq!(rows.len(), 2, "{rows:?}");

    let mut ports = Vec::new();
    for (row, upstream) in rows.iter().zip(["profile", "direct"]) {
        assert_eq!(row["upstream"], upstream, "{row:?}");
        assert_eq!(row["state"], "ready", "{row:?}");
        let address = row["http_address"].as_str().expect("a bound address");
        let (host, port) = address.rsplit_once(':').expect("host:port");
        assert_eq!(
            host, "127.0.0.1",
            "the bind address is the core's and is never configurable"
        );
        let port: u16 = port.parse().unwrap();
        assert_ne!(port, 0, "an ephemeral port must be reported, not echoed");
        ports.push(port);
    }
    assert_ne!(ports[0], ports[1], "two inbounds, two listeners");

    assert_eq!(runtime.stop(), StopResult::Stopped);
    for port in ports {
        assert!(
            std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err(),
            "a named inbound must not outlive its root runtime"
        );
    }
}

/// Authentication is mandatory, and one inbound's credentials do not open
/// another's.
///
/// Every one of these listeners is on `127.0.0.1`, where every app on the phone
/// can reach every port. The credential is the only separator there is; without
/// this the labels on the ports mean nothing.
#[test]
fn a_named_inbound_requires_its_own_credentials() {
    use std::io::{Read as _, Write as _};

    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.runtime.loopback_inbounds = vec![
        inbound_config("webapp.a", LoopbackUpstream::Direct),
        inbound_config("webapp.b", LoopbackUpstream::Direct),
    ];
    config.validate().unwrap();

    let runtime =
        CoreRuntime::start(71, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    let rows = inbound_rows(&runtime);
    let address = rows[0]["http_address"].as_str().unwrap().to_owned();

    let request = |head: String| -> String {
        let mut client = std::net::TcpStream::connect(&address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(head.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = client.read_to_string(&mut response);
        response
    };

    use base64::Engine as _;
    let encode = |value: &str| base64::engine::general_purpose::STANDARD.encode(value);

    let anonymous =
        request("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_owned());
    assert!(
        anonymous.starts_with("HTTP/1.1 407"),
        "authentication is not optional and not configurable, got {anonymous}"
    );

    let neighbour = request(format!(
        "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
        encode("user-webapp.b:secret-webapp.b")
    ));
    assert!(
        neighbour.starts_with("HTTP/1.1 407"),
        "the neighbouring inbound's credentials must not open this one, got {neighbour}"
    );

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// An inbound whose upstream this generation does not have refuses the whole
/// start, and leaves nothing listening.
///
/// The profile here is VLESS with no Tor outbound, so a `tor` inbound has no
/// lane to take. The failure that matters is not the error — it is that no
/// socket is left behind: a listener that answered and then could not serve is a
/// web app labelled Tor whose requests go somewhere else.
#[test]
fn a_named_inbound_without_its_upstream_refuses_the_start_rather_than_leaking() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    let mut tor = inbound_config("webapp.tor", LoopbackUpstream::Tor);
    tor.http_port = port;
    config.runtime.loopback_inbounds = vec![tor];
    config
        .validate()
        .expect("the config is well formed; what is missing is the lane");

    let started = CoreRuntime::start(72, config, OwnedFd::from(tun), SocketCallbacks::none());
    let Err(refused) = started else {
        panic!("a tor inbound on a profile with no tor outbound must not start");
    };
    assert!(
        refused.to_string().contains("named loopback inbound"),
        "the app has to be told which part refused, got: {refused}"
    );
    assert!(
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "nothing may be left listening after a refused inbound"
    );
}

/// The cap holds, and it holds on the live path as well as in the validator.
///
/// `MAX_LOOPBACK_INBOUNDS` is enforced twice on purpose: the config validator
/// catches a profile that asks for too many, and this catches an app that adds
/// them one at a time through the JNI call, which the validator never sees.
#[test]
fn the_named_inbound_cap_holds_on_the_live_path() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        73,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();

    for index in 0..MAX_LOOPBACK_INBOUNDS {
        runtime
            .install_loopback_inbound(&inbound_config(
                &format!("webapp.{index}"),
                LoopbackUpstream::Direct,
            ))
            .unwrap_or_else(|error| panic!("inbound {index} must bind: {error}"));
    }
    assert_eq!(
        inbound_rows(&runtime).len(),
        MAX_LOOPBACK_INBOUNDS,
        "every inbound under the cap must actually be listening"
    );

    assert_eq!(
        runtime
            .install_loopback_inbound(&inbound_config("webapp.over", LoopbackUpstream::Direct))
            .err(),
        Some(ComponentError::Capacity),
        "the cap is a ceiling, not a suggestion"
    );
    // A name already in use is refused too, and refusing it is what keeps the
    // status document a one-to-one map from name to port.
    assert_eq!(
        runtime
            .install_loopback_inbound(&inbound_config("webapp.0", LoopbackUpstream::Direct))
            .err(),
        Some(ComponentError::AlreadyExists)
    );

    // Removing one frees both the slot and the name.
    assert!(runtime.remove_loopback_inbound("webapp.0"));
    assert!(!runtime.remove_loopback_inbound("webapp.0"));
    runtime
        .install_loopback_inbound(&inbound_config("webapp.0", LoopbackUpstream::Direct))
        .expect("a removed name is free again");

    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// The credential rule holds on the live path, not only in the validator.
///
/// `EngineConfig::validate` sees a whole list at once; this call sees one
/// inbound arriving on a running engine, which is the path a web app being
/// created actually takes. If the rule lived only in the validator, the JNI call
/// would be the way around the one thing that makes these listeners separate —
/// they are all on `127.0.0.1`, where any app on the device reaches any port, so
/// a shared credential is a shared upstream.
#[test]
fn a_live_named_inbound_may_not_reuse_another_inbounds_credentials() {
    let (tun, _peer) = UnixStream::pair().unwrap();
    let mut config = vless_engine_config();
    config.runtime.control_proxy = Some(ControlProxyConfig {
        http_port: {
            let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            port
        },
        username: "foxhole-runtime".into(),
        password: SecretString::new("process-local-secret"),
    });
    config.validate().unwrap();

    let runtime =
        CoreRuntime::start(75, config, OwnedFd::from(tun), SocketCallbacks::none()).unwrap();
    runtime
        .install_loopback_inbound(&inbound_config("webapp.a", LoopbackUpstream::Direct))
        .expect("the first inbound has credentials nobody else holds");

    // Same username, fresh password.
    let mut same_user = inbound_config("webapp.b", LoopbackUpstream::Direct);
    same_user.username = Some("user-webapp.a".into());
    assert_eq!(
        runtime.install_loopback_inbound(&same_user).err(),
        Some(ComponentError::AlreadyExists),
        "a repeated username is a second door with the same key"
    );

    // Fresh username, same password.
    let mut same_password = inbound_config("webapp.c", LoopbackUpstream::Direct);
    same_password.password = Some(SecretString::new("secret-webapp.a"));
    assert_eq!(
        runtime.install_loopback_inbound(&same_password).err(),
        Some(ComponentError::AlreadyExists),
        "a repeated password is the same key under another name"
    );

    // And the control proxy is not a special case: it is the same kind of
    // listener on the same interface.
    let mut control = inbound_config("webapp.d", LoopbackUpstream::Direct);
    control.password = Some(SecretString::new("process-local-secret"));
    assert_eq!(
        runtime.install_loopback_inbound(&control).err(),
        Some(ComponentError::AlreadyExists),
        "the control proxy's credentials must not open a web app's inbound either"
    );

    assert_eq!(
        inbound_rows(&runtime).len(),
        1,
        "a refused inbound must not appear in the document the app reads"
    );
    assert_eq!(runtime.stop(), StopResult::Stopped);
}

/// A `tor` inbound added while the engine is up is refused by the same rule the
/// start path uses, with nothing left bound.
#[test]
fn a_live_named_inbound_without_its_upstream_refuses_and_binds_nothing() {
    let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);

    let (tun, _peer) = UnixStream::pair().unwrap();
    let runtime = CoreRuntime::start(
        74,
        vless_engine_config(),
        OwnedFd::from(tun),
        SocketCallbacks::none(),
    )
    .unwrap();

    let mut tor = inbound_config("webapp.tor", LoopbackUpstream::Tor);
    tor.http_port = port;
    assert_eq!(
        runtime.install_loopback_inbound(&tor).err(),
        Some(ComponentError::RuntimeUnavailable),
        "there is no tor lane in this profile and there is no substitute for one"
    );
    assert!(
        inbound_rows(&runtime).is_empty(),
        "a refused inbound must not appear in the document the app reads"
    );
    assert!(
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "nothing may be left listening after a refused inbound"
    );

    assert_eq!(runtime.stop(), StopResult::Stopped);
}
