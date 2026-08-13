use super::*;
use std::io;
use std::os::fd::OwnedFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use foxcore_api::{ContinuityInterruption, EngineConfig, FlowAttributor, OutboundId, RouteAction};
use foxcore_dialer::{ProtectedDialer, SocketCallbacks};
use foxcore_outbound::{InterruptionSink, Outbound};
use foxcore_route::RouteTable;
use foxcore_tun::{
    ContinuityGate, FlowEngine, FlowEngineContext, FlowMetrics, FlowPolicyStore, TrafficMap,
    TunDevice,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

impl CoreRuntime {
    pub fn start(
        generation: u64,
        config: EngineConfig,
        tun_fd: OwnedFd,
        callbacks: SocketCallbacks,
    ) -> io::Result<Self> {
        Self::start_on_network_with_attributor(
            generation,
            config,
            tun_fd,
            callbacks,
            0,
            FlowAttributor::none(),
        )
    }

    pub fn start_on_network(
        generation: u64,
        config: EngineConfig,
        tun_fd: OwnedFd,
        callbacks: SocketCallbacks,
        network_handle: u64,
    ) -> io::Result<Self> {
        Self::start_on_network_with_attributor(
            generation,
            config,
            tun_fd,
            callbacks,
            network_handle,
            FlowAttributor::none(),
        )
    }

    pub fn start_on_network_with_attributor(
        generation: u64,
        config: EngineConfig,
        tun_fd: OwnedFd,
        callbacks: SocketCallbacks,
        network_handle: u64,
        attributor: FlowAttributor,
    ) -> io::Result<Self> {
        Self::start_on_network_with_attributor_and_rule_sets(
            generation,
            config,
            tun_fd,
            callbacks,
            network_handle,
            attributor,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_on_network_with_attributor_and_rule_sets(
        generation: u64,
        config: EngineConfig,
        tun_fd: OwnedFd,
        callbacks: SocketCallbacks,
        network_handle: u64,
        attributor: FlowAttributor,
        rule_sets: Vec<RuleSetBundle>,
    ) -> io::Result<Self> {
        Self::start_on_network_with_attributor_and_trusted_rule_sets(
            generation,
            config,
            tun_fd,
            callbacks,
            network_handle,
            attributor,
            rule_sets,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_on_network_with_attributor_and_trusted_rule_sets(
        generation: u64,
        config: EngineConfig,
        tun_fd: OwnedFd,
        callbacks: SocketCallbacks,
        network_handle: u64,
        attributor: FlowAttributor,
        rule_sets: Vec<RuleSetBundle>,
        trusted_rule_sets: Vec<TrustedRuleSetBundle>,
    ) -> io::Result<Self> {
        let attribution_available = attributor.is_available();
        if !attribution_available
            && (config
                .routes
                .iter()
                .any(|rule| rule.uid.is_some() || rule.package.is_some())
                || config.traffic.requires_identity())
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UID/package routes require a platform flow attributor",
            ));
        }
        reap_quarantined_workers();
        let worker_lease = ProcessWorkerLease::acquire()?;
        let startup_wait = startup_wait(&config);
        // Read before the config is moved into the worker; the answer cannot
        // change for the life of this generation, because swapping the primary
        // outbound needs a new one.
        let packet_tunnel = config.outbound.is_packet_tunnel();
        let runtime_config = config.runtime.clone();
        let control_proxy_config = runtime_config.control_proxy.clone();
        let loopback_inbound_configs = runtime_config.loopback_inbounds.clone();
        // Read out before the config is moved into the worker: a rebuild of a
        // lane that was not there at start gets the same budget as the build at
        // start did.
        let handshake_timeout_ms = runtime_config.handshake_timeout_ms;
        let dialer = ProtectedDialer::new(
            callbacks,
            Duration::from_millis(runtime_config.connect_timeout_ms),
        );
        dialer.set_network_handle(network_handle);
        let cancel = CancellationToken::new();
        let metrics = Arc::new(FlowMetrics::default());
        let connections = Arc::new(TrafficMap::default());
        let events = Arc::new(EventQueue::new(DEFAULT_EVENT_CAPACITY));
        // Built before the worker so the handle and the engine share one gate:
        // the app confirms through the handle, the flow path reads the hold.
        let continuity = Arc::new(ContinuityGate::new(
            config.traffic.continuity,
            events.sink(),
        ));
        // Started here rather than at the first stop, so the phase marks of a
        // generation are all on one clock that predates it.
        stop_diagnostics::arm_clock();
        // Same reason as the clock: the marks have to describe this generation
        // and not the one before it.
        foxcore_tun::enginephase::reset();
        let last_error = Arc::new(Mutex::new(None));
        let availability = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let retained_attributor = attributor.clone();
        // Created out here, before the worker, so the handle owns the sender
        // for the whole life of the generation. A relay whose signal could
        // close would see `changed()` resolve forever and spin.
        let (network_epoch, thread_network_epoch) = watch::channel(0_u64);
        // Only the L3 relay reads it, and a build without `wireguard` has no
        // relay to read it.
        #[cfg(not(feature = "wireguard"))]
        let _ = thread_network_epoch;

        let thread_cancel = cancel.clone();
        let thread_dialer = dialer.clone();
        let thread_metrics = metrics.clone();
        let thread_connections = connections.clone();
        let thread_events = events.clone();
        let thread_continuity = continuity.clone();
        let thread_error = last_error.clone();
        let thread_availability = availability.clone();
        let thread = std::thread::Builder::new()
            .name(format!("foxcore-{generation}"))
            .spawn(move || {
                let _availability_guard = WorkerAvailabilityGuard(thread_availability.clone());
                let _worker_lease = worker_lease;
                // Read before this generation opens its own device, so the
                // release barrier below waits for *this* device and is not
                // held hostage by one an earlier generation leaked.
                let device_baseline = foxcore_tun::live_devices();
                let runtime = match build_runtime(&runtime_config) {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let message = format!("build Tokio runtime: {error}");
                        set_error(&thread_error, message.clone());
                        let _ = ready_tx.send(Err(message));
                        let _ = done_tx.send(());
                        return;
                    }
                };
                // Sent out with readiness so the handle can spawn LAN listeners
                // on the root runtime's executor. A component with its own
                // executor would be a second place threads are owned.
                let tokio_handle = runtime.handle().clone();
                // Built here rather than inside `block_on`, so the thing that
                // closes the descriptor stays on this thread while the device
                // itself goes into the task. `AsyncFd` needs a runtime context
                // to register with the reactor, which `enter` provides without
                // moving anything into the executor.
                let device_and_owner = {
                    let _context = runtime.enter();
                    TunDevice::from_owned_fd(tun_fd)
                };
                let (device, tun_fd_owner) = match device_and_owner {
                    Ok(pair) => pair,
                    Err(error) => {
                        let message = format!("open TUN descriptor: {error}");
                        set_error(&thread_error, message.clone());
                        let _ = ready_tx.send(Err(message));
                        shutdown_worker_runtime(runtime);
                        let _ = done_tx.send(());
                        return;
                    }
                };
                // Caught, not allowed to unwind. The release order below is the
                // whole safety property of this thread, and a panic anywhere
                // inside the engine future — building an outbound, compiling a
                // policy, the accept loop itself — would skip all of it and
                // instead drop the locals in reverse declaration order: the
                // descriptor owner first, **while the runtime is still up and
                // its workers are still polling tasks that hold that fd**. The
                // number is free the instant it closes, so the next `socket()`
                // in any surviving task takes it and the tun writer starts
                // writing IP packets into somebody else's connection. Then the
                // runtime would be dropped through `Runtime::drop`, which has no
                // ceiling, instead of `shutdown_timeout`.
                //
                // The profile unwinds (`panic = "unwind"`), precisely so the JNI
                // boundary can catch. This is the same boundary, one level in.
                let panic_error = thread_error.clone();
                let engine_outcome = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(async move {
                        let EngineConfig {
                            outbound,
                            outbounds: named_outbounds,
                            tun,
                            runtime,
                            routes,
                            dns,
                            traffic,
                            ..
                        } = config;
                        let continuity_sink: InterruptionSink = {
                            let gate = thread_continuity.clone();
                            Arc::new(move |interruption| gate.permit(interruption))
                        };
                        let outbound_result = create_outbound_registry(
                            outbound,
                            named_outbounds,
                            thread_dialer.clone(),
                            runtime.handshake_timeout_ms,
                            &thread_events.sink(),
                            &continuity_sink,
                            &tun,
                        )
                        .await;
                        let (outbounds, packet_tunnel) = match outbound_result {
                            Ok((outbounds, packet_tunnel)) => (Arc::new(outbounds), packet_tunnel),
                            Err(error) => {
                                let message = format!("initialize outbounds: {error}");
                                set_error(&thread_error, message.clone());
                                let _ = ready_tx.send(Err(message));
                                return;
                            }
                        };
                        // A primary that could not be built is the one unavailable
                        // lane that may, by the user's own setting, take another
                        // one with it. `split_tunnel_on_vpn_failure` — on by
                        // default — means "keep the direct lane running when the
                        // VPN dies"; a user who turned it off asked for no clearnet
                        // while the tunnel is down, and a tunnel that never came up
                        // is the strongest form of down. With the flag on this call
                        // does nothing at all, which is the four-lane case: VPN
                        // apps blocked, Tor, I2P and direct apps carrying traffic.
                        if matches!(
                            outbounds.default().as_ref(),
                            Outbound::Deferred(deferred) if !deferred.is_available()
                        ) {
                            let _ = thread_continuity.interrupt(ContinuityInterruption::VpnFailure);
                        }
                        let direct = Arc::new(Outbound::direct(thread_dialer));
                        let (tor_enabled, i2p_enabled) =
                            resolve_network_gates(&traffic, &outbounds);
                        let route_table = RouteTable::compile_with_traffic(
                            routes,
                            RouteAction::Outbound(OutboundId("default".into())),
                            traffic,
                            tor_enabled,
                            i2p_enabled,
                        );
                        let policy = match FlowPolicyStore::new_with_trusted_rule_sets(
                            generation,
                            route_table,
                            dns,
                            outbounds.clone(),
                            direct.clone(),
                            thread_metrics.clone(),
                            thread_events.sink(),
                            rule_sets,
                            trusted_rule_sets,
                        ) {
                            Ok(policy) => Arc::new(policy),
                            Err(error) => {
                                let message = format!("initialize DNS policy: {error}");
                                set_error(&thread_error, message.clone());
                                let _ = ready_tx.send(Err(message));
                                return;
                            }
                        };
                        let engine = FlowEngine::new(FlowEngineContext {
                            outbounds: outbounds.clone(),
                            direct,
                            policy: policy.clone(),
                            attributor,
                            runtime,
                            metrics: thread_metrics.clone(),
                            events: thread_events.sink(),
                            packet_tunnel: packet_tunnel.is_some(),
                            connections: thread_connections.clone(),
                        })
                        .with_continuity(thread_continuity);
                        // The peer socket is bound before readiness is reported:
                        // a tunnel that cannot reach its endpoint is a failed start,
                        // not a tunnel that quietly carries nothing.
                        #[cfg(feature = "wireguard")]
                        let relay = match packet_tunnel {
                            Some(tunnel) => {
                                match foxcore_tun::PacketTunnelRelay::connect(
                                    &tunnel,
                                    &tun_addresses(&tun),
                                    thread_metrics.clone(),
                                )
                                .await
                                {
                                    Ok(relay) => {
                                        Some(relay.with_network_signal(thread_network_epoch))
                                    }
                                    Err(error) => {
                                        let message = format!("connect packet tunnel: {error}");
                                        set_error(&thread_error, message.clone());
                                        let _ = ready_tx.send(Err(message));
                                        return;
                                    }
                                }
                            }
                            None => None,
                        };
                        thread_availability.store(true, Ordering::Release);
                        if ready_tx
                            .send(Ok((outbounds, policy, tokio_handle)))
                            .is_err()
                        {
                            return;
                        }
                        #[cfg(feature = "wireguard")]
                        let result = match relay {
                            Some(relay) => {
                                engine
                                    .run_with_packet_tunnel(device, tun.mtu, relay, thread_cancel)
                                    .await
                            }
                            None => engine.run(device, tun.mtu, thread_cancel).await,
                        };
                        #[cfg(not(feature = "wireguard"))]
                        let result = engine.run(device, tun.mtu, thread_cancel).await;
                        if let Err(error) = result {
                            set_error(&thread_error, format!("flow engine: {error}"));
                        }
                        thread_metrics.set_connected(false);
                    })
                }));
                if let Err(panic) = engine_outcome {
                    set_error(
                        &panic_error,
                        format!("flow engine panicked: {}", panic_text(&panic)),
                    );
                }
                // The two marks that split a stop timeout in half. Between them
                // lies everything the engine loop had to unwind; after the
                // second lies everything Tokio had to wait for.
                stop_diagnostics::engine_returned();
                // Before the signal, not after it. `done` used to mean "the
                // engine loop returned", and the runtime was then dropped as
                // the closure unwound — so `stop` saw success and blocked in a
                // join that had no ceiling. It now means "everything I own is
                // released or abandoned", which is what the caller reads it as.
                shutdown_worker_runtime(runtime);
                // Here, and only here. The runtime is down, so no task will be
                // polled again and nothing can still be reading the descriptor;
                // dropping the owner closes it whether or not the task that was
                // using it survived `shutdown_timeout`. That is the whole point
                // of the owner living on this thread: "the runtime is down" and
                // "the fd is closed" became the same statement again.
                drop(tun_fd_owner);
                // The wrapper's own release is still waited for, because the app
                // asks about the descriptor and a `TunDevice` that outlives this
                // means a task is still holding the reactor registration. Waited
                // for on a plain thread with no runtime left, so nothing here
                // can be starved by the executor that just failed to finish.
                let released =
                    foxcore_tun::wait_for_devices_released(device_baseline, DEVICE_RELEASE_BUDGET);
                stop_diagnostics::device_released(released);
                stop_diagnostics::shutdown_done();
                let _ = done_tx.send(());
            })
            .map_err(|error| io::Error::other(format!("spawn FoxCore thread: {error}")))?;

        match ready_rx.recv_timeout(startup_wait) {
            Ok(Ok((outbounds, policy, tokio_handle))) => {
                let lease_provider: Arc<dyn RuntimeLeaseProvider> =
                    Arc::new(RootRuntimeLeaseProvider {
                        availability: availability.clone(),
                        tor_available: outbounds.tor().is_some(),
                    });
                let components = ComponentManager::new(lease_provider.clone());
                let runtime = Self {
                    generation,
                    tokio_handle,
                    cancel,
                    dialer,
                    handshake_timeout_ms,
                    outbounds,
                    policy,
                    packet_tunnel,
                    attributor: retained_attributor,
                    attribution_available,
                    metrics,
                    connections,
                    events,
                    last_error,
                    last_policy_error: Mutex::new(None),
                    components,
                    control_proxy: Mutex::new(None),
                    control_proxy_credentials: Mutex::new(None),
                    loopback_inbounds: Mutex::new(Vec::new()),
                    lan_proxy: Mutex::new(None),
                    last_lan_error: Mutex::new(None),
                    availability,
                    continuity,
                    deferred_network: Mutex::new(None),
                    network_epoch,
                    continuity_watch: Mutex::new(None),
                    lease_provider,
                    share: Mutex::new(None),
                    worker: RuntimeWorker::new(thread, done_rx),
                };
                runtime
                    .start_control_proxy(control_proxy_config)
                    .map_err(|error| {
                        io::Error::other(format!("start runtime control proxy: {error}"))
                    })?;
                // After the control proxy and before the generation is handed
                // out: an inbound that will not bind fails the *start*, rather
                // than leaving an app pointed at a port that answers nothing.
                runtime
                    .start_loopback_inbounds(&loopback_inbound_configs)
                    .map_err(|error| {
                        io::Error::other(format!("start named loopback inbound: {error}"))
                    })?;
                runtime.start_continuity_watch();
                Ok(runtime)
            }
            Ok(Err(message)) => {
                let _ = thread.join();
                Err(io::Error::other(message))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "FoxCore thread exited before initialization",
                ))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancel.cancel();
                match done_rx.recv_timeout(STOP_TIMEOUT) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = thread.join();
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        quarantine_worker(thread);
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "FoxCore initialization timed out",
                ))
            }
        }
    }
}
