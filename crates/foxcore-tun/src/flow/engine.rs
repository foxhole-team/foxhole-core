use super::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::ipstack::{IpStack, IpStackStream, IpStackTcpStream};
use foxcore_api::{BlockReason, CoreEvent, FlowContext, IpTransport, RouteAction};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use foxcore_trafficmap::{CountingStream, FlowLane, FlowRoute};

use crate::continuity::ContinuityGate;
use crate::{TunDevice, is_i2p, is_onion};

/// How many relay buffers stay resident between flows.
///
/// A byte budget, not a flow count. `max_tcp_flows` defaults to 1024, so a pool
/// sized to hold every flow's pair would keep 32 MiB parked at the default
/// buffer size — against a core whose whole resident set is single-digit
/// megabytes. One mebibyte of cache absorbs the churn of the
/// concurrency a phone actually reaches; past that a flow allocates its buffer
/// exactly as it did before, so the ceiling costs latency on a burst and never
/// correctness.
///
/// The floor of eight keeps the pool useful at the largest configurable buffer
/// (256 KiB), where one mebibyte would otherwise buy four buffers — two
/// simultaneous flows — and the pool would spend its life empty.
fn idle_relay_buffers(relay_buffer_bytes: usize) -> usize {
    const IDLE_BUDGET: usize = 1024 * 1024;
    (IDLE_BUDGET / relay_buffer_bytes.max(1)).max(8)
}

impl FlowEngine {
    pub fn new(context: FlowEngineContext) -> Self {
        let FlowEngineContext {
            outbounds,
            direct,
            policy,
            attributor,
            runtime,
            metrics,
            events,
            packet_tunnel,
            connections,
        } = context;
        Self {
            generation: policy.generation,
            outbounds,
            direct,
            policy,
            attributor,
            tcp_slots: Arc::new(Semaphore::new(runtime.max_tcp_flows)),
            udp_slots: Arc::new(Semaphore::new(runtime.max_udp_flows)),
            attribution_slots: Arc::new(Semaphore::new(runtime.max_attribution_tasks)),
            relay_pool: Arc::new(foxcore_relay::BufferPool::new(
                runtime.relay_buffer_bytes,
                idle_relay_buffers(runtime.relay_buffer_bytes),
            )),
            runtime,
            metrics,
            events: events.clone(),
            packet_tunnel,
            connections,
            shutdown: CancellationToken::new(),
            continuity: Arc::new(ContinuityGate::new(
                foxcore_api::ContinuityConfig::default(),
                events,
            )),
        }
    }

    /// Bind this engine to the runtime's continuity gate.
    ///
    /// A builder rather than a context field so an engine assembled without one
    /// keeps the behaviour it had: the default gate always permits, so nothing
    /// is ever held.
    pub fn with_continuity(mut self, continuity: Arc<ContinuityGate>) -> Self {
        self.continuity = continuity;
        self
    }

    /// Record a refused flow. Blocking is a cold path, but the event is only built
    /// when a sink is installed so the common case costs nothing.
    pub(crate) fn emit_block(
        &self,
        reason: BlockReason,
        transport: IpTransport,
        context: &FlowContext,
    ) {
        self.events.emit_with(|| CoreEvent::Blocked {
            reason,
            transport,
            destination: context.destination.clone(),
            uid: context.uid,
            package: context.package.clone(),
        });
    }

    /// Count and report a flow refused because the transport's slots are all
    /// taken.
    ///
    /// [`BlockReason::FlowLimit`] has existed since the API was written and
    /// `RuntimeConfig`'s own documentation says that exhausting the flow table
    /// "raises `BlockReason::FlowLimit` and is counted" — the sentence that
    /// justifies choosing `tcp_idle_timeout_s` the way it is chosen, on the
    /// grounds that the ceiling is *visible* if it ever bites. It was not: no
    /// call site in the tree emitted it, so the only trace a full table left
    /// was one counter with no name attached, and the application's own view of
    /// the flow was a connection that opened and then said nothing.
    ///
    /// The context is built behind the sink check because building it means a
    /// reverse lookup and two clones, and this runs on a path that is by
    /// definition already under pressure.
    pub(crate) fn refuse_for_flow_limit(
        &self,
        transport: IpTransport,
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
    ) {
        self.metrics.reject_flow();
        if !self.events.is_enabled() {
            return;
        }
        let policy = self.policy.current.load();
        let context = context_for(self.generation, transport, source, destination, &policy.dns);
        self.emit_block(BlockReason::FlowLimit, transport, &context);
    }

    pub async fn run(
        mut self,
        device: TunDevice,
        mtu: u16,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        self.shutdown = cancel.clone();
        let stack = build_stack(device, mtu, &self.runtime, &self.metrics)?;
        self.accept_loop(stack, cancel).await
    }

    /// Run with an L3 packet tunnel beside the userspace stack.
    ///
    /// The tun is read once and every packet is classified *before* anything
    /// terminates it: flows the policy sends to the primary outbound stay at L3
    /// and are sealed by the tunnel, everything else — direct, Tor, I2P, DNS —
    /// reaches the stack exactly as before. There is no second TCP stack in
    /// either path.
    ///
    /// One task owns the tun for writing. Two sources feed it (the tunnel's
    /// decrypted packets and the stack's replies), and letting them write to the
    /// descriptor independently would interleave two packets into one write.
    #[cfg(feature = "wireguard")]
    pub async fn run_with_packet_tunnel(
        mut self,
        device: TunDevice,
        mtu: u16,
        relay: crate::relay::PacketTunnelRelay,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        use crate::ingress::{IngressChannels, StackDevice, classify};
        use crate::split::PacketSplitter;

        self.shutdown = cancel.clone();

        let (reader, writer) = tokio::io::split(device);
        let (to_ingress, from_tun) = tokio::sync::mpsc::channel(PACKET_QUEUE);
        let (to_tunnel, tunnel_inbox) = tokio::sync::mpsc::channel(PACKET_QUEUE);
        let (to_stack, stack_inbox) = tokio::sync::mpsc::channel(PACKET_QUEUE);
        let (to_writer, write_inbox) = tokio::sync::mpsc::channel(PACKET_QUEUE);

        // Every task is explicitly aborted and joined below: merely dropping
        // a JoinSet schedules cancellation but can return while its reader and
        // writer still own the two halves of the tun.
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(read_tun(reader, to_ingress, mtu, cancel.clone()));
        tasks.spawn(write_tun(
            writer,
            write_inbox,
            self.metrics.clone(),
            cancel.clone(),
        ));

        let engine = self.clone();
        tasks.spawn(classify(
            from_tun,
            PacketSplitter::new(
                self.runtime.max_tcp_flows + self.runtime.max_udp_flows,
                self.runtime.idle_timeout_s.saturating_mul(1_000),
            ),
            move |key| {
                let engine = engine.clone();
                async move {
                    // Read before deciding, not after: a snapshot installed
                    // while the owner lookup is in flight must void the answer
                    // it produced. Deciding again costs one Binder call; not
                    // deciding again costs a flow that keeps its old route
                    // through the reload that was supposed to end it.
                    let policy_revoked = engine.policy.current.load().revocation.clone();
                    engine.decide_packet(key).await.voided_by(policy_revoked)
                }
            },
            IngressChannels {
                to_tunnel,
                to_stack,
                metrics: self.metrics.clone(),
                accounting: self.connections.tunnel().clone(),
            },
            cancel.clone(),
        ));

        let relay_cancel = cancel.clone();
        let relay_writer = to_writer.clone();
        let relay = relay
            .with_accounting(self.connections.tunnel().clone())
            .with_events(self.events.clone());
        tasks.spawn(async move {
            let _ = relay.run(tunnel_inbox, relay_writer, relay_cancel).await;
        });

        let stack = build_stack(
            StackDevice::new(stack_inbox, to_writer, mtu),
            mtu,
            &self.runtime,
            &self.metrics,
        )?;
        let result = self.accept_loop(stack, cancel).await;
        tasks.shutdown().await;
        result
    }

    async fn accept_loop(&self, mut stack: IpStack, cancel: CancellationToken) -> io::Result<()> {
        self.metrics.set_connected(true);
        crate::enginephase::mark(crate::enginephase::PHASE_RUNNING);
        let result = loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    break Ok(());
                }
                accepted = stack.accept() => {
                    match accepted {
                        Ok(stream) => self.dispatch(stream, cancel.clone()),
                        Err(error) => break Err(io::Error::other(error.to_string())),
                    }
                }
            }
        };
        crate::enginephase::mark(crate::enginephase::PHASE_LOOP_EXITED);
        stack.shutdown();
        crate::enginephase::mark(crate::enginephase::PHASE_STACK_SHUTDOWN);
        self.metrics.set_connected(false);
        crate::enginephase::mark(crate::enginephase::PHASE_ENGINE_RETURNING);
        result
    }

    /// Decide where one flow's packets go, before anything terminates them.
    ///
    /// Everything the stack would refuse is refused here too, and for the same
    /// reasons — the packet path is not a way around the firewall. What it adds
    /// is the one case the stack cannot serve: a flow bound for the primary
    /// outbound when that outbound is an L3 tunnel.
    #[cfg(feature = "wireguard")]
    pub(super) async fn decide_packet(
        &self,
        key: crate::split::FlowKey,
    ) -> crate::split::PacketDecision {
        use crate::split::{PacketDecision, PacketRoute};

        let policy = self.policy.current.load();
        if policy.routes.kill_switch() {
            return PacketDecision::new(PacketRoute::Block);
        }
        let transport = match key.protocol {
            IP_PROTOCOL_TCP => IpTransport::Tcp,
            IP_PROTOCOL_UDP => IpTransport::Udp,
            // A protocol with no ports cannot be attributed and has no stream
            // semantics. It goes to the stack, where the ICMP responder and its
            // own kill-switch gate already live.
            _ => return PacketDecision::new(PacketRoute::Stack),
        };
        let source = std::net::SocketAddr::new(key.source, key.source_port);
        let destination = std::net::SocketAddr::new(key.destination, key.destination_port);
        let mut context = context_for(self.generation, transport, source, destination, &policy.dns);
        if !self
            .attribute_context(&mut context, source, destination, &policy.routes, transport)
            .await
        {
            self.metrics.attribution_error();
            self.metrics.block_flow();
            self.emit_block(BlockReason::Unattributed, transport, &context);
            return PacketDecision::new(PacketRoute::Block);
        }
        // DNS is terminated by the interceptor, which lives on the stack side.
        // A query sealed straight into the tunnel would skip the blocklist, the
        // overlay gates and fake-IP in one step.
        if context.destination.port == 53 && policy.dns_proxy.is_some() {
            return PacketDecision::new(PacketRoute::Stack);
        }
        // The same question over a transport the gate above cannot read. Sent
        // to the stack rather than blocked here, because a dropped packet and a
        // closed connection are not the same answer to the prober: Android
        // bounds the DoT connect at 127 s by default, so a black hole costs the
        // device that long before it falls back, while a refusal on the stack
        // side costs a round trip. `handle_tcp` is where it is refused and
        // named (D14).
        if policy.dns_proxy.is_some()
            && policy
                .dns_config
                .bypasses_interceptor(key.destination, key.destination_port)
        {
            return PacketDecision::new(PacketRoute::Stack);
        }
        // Overlay destinations are reached by name through a stream proxy; they
        // have no meaning as raw IP packets on a peer's allowed-ips.
        if is_onion(&context.destination.host) || is_i2p(&context.destination.host) {
            return PacketDecision::new(PacketRoute::Stack);
        }
        match policy.routes.decide(&context) {
            RouteAction::Block => {
                self.metrics.block_flow();
                self.emit_block(BlockReason::Policy, transport, &context);
                PacketDecision::new(PacketRoute::Block)
            }
            RouteAction::Outbound(id) if is_primary_outbound(&id.0) => {
                // The last point that can still tell the two apart. Above this
                // arm a fake address is harmless — the stack terminates the
                // flow and `context.destination` is already the name again —
                // and overlay flows have been sent there several lines up. What
                // arrives here is a clearnet name that was answered out of the
                // fake-IP pool and is now about to be sealed as an IP packet,
                // destination and all, for a peer that has no route to it.
                //
                // Refusing costs this flow. Sealing it costs the flow *and* the
                // evidence: on device the packet was translated, sealed, sent,
                // counted by both the lane and the metrics, and the connection
                // died in a twenty-second timeout with nothing refused anywhere
                // during device acceptance. A start-time refusal keeps this unreachable in
                // a runtime the app configured; this keeps it true whatever
                // reaches the data plane.
                if policy.dns_config.synthesizes(key.destination) {
                    self.metrics.block_flow();
                    self.emit_block(BlockReason::TunnelFakeIpUnroutable, transport, &context);
                    return PacketDecision::new(PacketRoute::Block);
                }
                // The row is opened here, at the one point that knows both the
                // owning app and that this flow stays at L3. Its handle lives
                // in the split's decision, so the row and the decision expire
                // together.
                let flow = self.connections.open(
                    transport,
                    context.destination.host.clone(),
                    context.destination.port,
                    FlowRoute::new(FlowLane::Vpn, "wireguard").with_outbound_id(id.0.clone()),
                    context.packages.clone(),
                    context.uid,
                );
                if context.packages.is_empty() {
                    self.attribute_for_telemetry(
                        flow.flow().clone(),
                        transport,
                        source,
                        destination,
                    );
                }
                PacketDecision::with_flow(
                    PacketRoute::Tunnel,
                    flow.bind_packet_flow(foxcore_trafficmap::PacketKey::from(key)),
                )
            }
            _ => PacketDecision::new(PacketRoute::Stack),
        }
    }

    fn dispatch(&self, stream: IpStackStream, cancel: CancellationToken) {
        match stream {
            IpStackStream::Tcp(stream) => self.dispatch_tcp(stream, cancel),
            IpStackStream::Udp(stream) => self.dispatch_udp(stream, cancel),
            IpStackStream::UnknownTransport(stream) => {
                // The local ICMP responder answers without going through `decide`,
                // so the global kill switch has to be checked here as well.
                if self.policy.current.load().routes.kill_switch() {
                    self.metrics.block_flow();
                } else {
                    answer_icmp(stream);
                }
            }
            IpStackStream::UnknownNetwork(_) => self.metrics.flow_error(),
        }
    }

    /// End a session towards the application instead of dropping it.
    ///
    /// `ipstack 1.0.0` sends nothing when a stream is dropped — `impl Drop for
    /// IpStackTcpStream` tears down the session task and emits neither FIN nor
    /// RST. The userspace stack has already answered the SYN by the time the
    /// core decides it cannot carry the flow, so an abandoned session leaves the
    /// application holding a connection that is established and will never
    /// answer. Measured through the tunnel: `curl` to a closed port completed
    /// its connect in 0.6 ms and then sat until its own twelve-second timeout —
    /// "the app hangs" where the truth was "there is nowhere to send this".
    ///
    /// Every path that gives up on a flow after the stack accepted it goes
    /// through here: unattributable, refused by policy, and undiallable. The
    /// three are different reasons and the counters keep them apart; what the
    /// app is owed is the same in all three.
    ///
    /// Bounded, because a close is a handshake and the peer that has to answer
    /// it is the application. A client that never ACKs the FIN must not hold
    /// this task — and the flow slot under it — open.
    async fn close_towards_app(stream: &mut IpStackTcpStream) {
        let _ = tokio::time::timeout(CLIENT_CLOSE_TIMEOUT, stream.shutdown()).await;
    }

    /// The same close, with a reset behind it for the application that will not
    /// finish the handshake.
    ///
    /// Used where the core is reclaiming a session it has already half-closed —
    /// the remote sent FIN, `copy_bidirectional` passed that on as a FIN to the
    /// application, and the application has neither closed nor written since.
    /// `shutdown` on such a stream cannot complete, because `ipstack`'s
    /// `poll_shutdown` stays `Pending` until the session reaches `Closed` and
    /// only the application's own FIN takes it there. Waiting the bounded two
    /// seconds and then *dropping* would leave that application writing into a
    /// hole: `impl Drop for IpStackTcpStream` sends neither FIN nor RST, which
    /// is the silence `cba1e8a` spent four fixes removing from the other
    /// abandonment paths.
    ///
    /// So the graceful attempt is made first — an application that is simply
    /// slow gets the orderly end it is owed — and a reset follows only when it
    /// was not taken. Nothing of a live direction is lost by the reset: the
    /// window that got us here is thirty seconds in which this flow moved not
    /// one byte in either direction.
    async fn close_or_reset_towards_app(stream: &mut IpStackTcpStream) {
        if tokio::time::timeout(CLIENT_CLOSE_TIMEOUT, stream.shutdown())
            .await
            .is_err()
        {
            stream.reset();
        }
    }

    fn dispatch_tcp(&self, mut stream: IpStackTcpStream, cancel: CancellationToken) {
        let Ok(permit) = self.tcp_slots.clone().try_acquire_owned() else {
            // The fifth abandonment path, and the last one. `cba1e8a` found
            // four ways a flow could be given up on after the stack had already
            // answered its SYN, and closed all four with `close_towards_app`.
            // This one was not among them because it is not a decision *about*
            // the flow — the flow is never looked at — so it dropped the stream
            // here, and `impl Drop for IpStackTcpStream` sends neither FIN nor
            // RST. What the application got was `connect()` succeeding in
            // microseconds followed by silence until its own timeout, which is
            // the exact symptom that made a working fail-closed core read as a
            // broken tunnel every time it was measured.
            //
            // Refused before the stack accepts wherever that is possible: the
            // stack's session table is capped at `max_tcp_flows +
            // max_udp_flows` (see `build_stack`), so a device that keeps
            // opening connections is answered with a reset by the stack itself,
            // with no session ever built. This arm is what remains after that —
            // the caps are per-transport here and shared there, so a TCP-only
            // burst can exhaust these slots while the table still has room. The
            // answer on the wire is the same either way.
            self.refuse_for_flow_limit(IpTransport::Tcp, stream.local_addr(), stream.peer_addr());
            stream.reset();
            return;
        };
        let engine = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            engine.handle_tcp(stream, cancel).await;
        });
    }

    async fn handle_tcp(&self, mut stream: IpStackTcpStream, cancel: CancellationToken) {
        let source = stream.local_addr();
        let destination = stream.peer_addr();
        let policy = self.policy.current.load();
        let mut context = context_for(
            self.generation,
            IpTransport::Tcp,
            source,
            destination,
            &policy.dns,
        );
        if !self
            .attribute_context(
                &mut context,
                source,
                destination,
                &policy.routes,
                IpTransport::Tcp,
            )
            .await
        {
            self.metrics.attribution_error();
            self.metrics.block_flow();
            self.emit_block(BlockReason::Unattributed, context.transport, &context);
            Self::close_towards_app(&mut stream).await;
            return;
        }
        if context.destination.port == 53 && policy.dns_proxy.is_some() {
            let metrics = self.metrics.clone();
            let policy = self.policy.clone();
            metrics.open_tcp();
            serve_dns_tcp(&mut stream, policy, context, &metrics, cancel).await;
            metrics.close_flow();
            return;
        }
        // The one place the DNS filter could be walked around without breaking
        // anything visible: the resolver we advertised, asked on 853 instead of
        // 53. Refused in band and at once — the stack has already answered the
        // SYN, so `shutdown` reaches the prober as a close on the connection it
        // was about to speak TLS on, and Android's opportunistic mode falls
        // back to plain DNS, which the branch above filters; device acceptance
        // reproduced this exact fallback.
        if policy.dns_proxy.is_some()
            && policy
                .dns_config
                .bypasses_interceptor(destination.ip(), destination.port())
        {
            self.metrics.dns_encrypted_bypass();
            self.metrics.block_flow();
            self.emit_block(BlockReason::DnsEncryptedBypass, IpTransport::Tcp, &context);
            Self::close_towards_app(&mut stream).await;
            return;
        }
        let SelectedRoute { outbound, route } = match self.select_route(&context, &policy.routes) {
            Ok(selected) => selected,
            Err(reason) => {
                self.metrics.block_flow();
                self.emit_block(reason, context.transport, &context);
                Self::close_towards_app(&mut stream).await;
                return;
            }
        };
        let metrics = self.metrics.clone();
        let relay_buffer = self.runtime.relay_buffer_bytes;
        let relay_pool = self.relay_pool.clone();
        // `tcp_idle_timeout_s`, not `idle_timeout_s`: this window is answering
        // a question about an *established* connection whose keepalives the
        // stack absorbs, and the UDP field's five minutes sit below every
        // keepalive interval that exists.
        let idle_timeout = Duration::from_secs(self.runtime.tcp_idle_timeout_s);
        // The narrower window, for the flow whose far end has already gone. See
        // `HALF_CLOSED_TIMEOUT` for why it is a different question from the one
        // above and why it is not answered by shortening that answer. Clamped so
        // a profile asking for a short idle window never ends up more patient
        // with a dead peer than with a live silent one.
        let half_closed_timeout = HALF_CLOSED_TIMEOUT.min(idle_timeout);
        let lane = route.lane;
        // Cloned before the policy guard is dropped: this flow belongs to the
        // snapshot it was decided under, and that is what a later reload
        // revokes.
        let policy_revoked = policy.revocation.clone();
        metrics.open_tcp();
        let destination = context.destination.clone();
        let tracked = self.connections.open(
            IpTransport::Tcp,
            destination.host.clone(),
            destination.port,
            route,
            context.packages.clone(),
            context.uid,
        );
        if context.packages.is_empty() {
            self.attribute_for_telemetry(
                tracked.flow().clone(),
                IpTransport::Tcp,
                source,
                stream.peer_addr(),
            );
        }
        // The same counters the traffic map reads, and the only view this task
        // has of whether its relay is carrying anything.
        let live = tracked.flow().clone();
        // This flow's own stop signal, beside the snapshot's. They are the same
        // mechanism at two scopes: the one above ends every flow that belongs
        // to a policy which has been replaced, this one ends exactly this flow
        // because something named it. Both mean the flow is over now, and both
        // are answered the same way below, which is the point — a user who
        // blocks one app and a user who arms the kill switch are owed the same
        // thing by the connections they are stopping.
        let flow_revoked = live.revocation();
        match outbound.connect_stream(&context, destination).await {
            Ok(remote) => {
                // Counting the remote side, not the tun side: the numbers have
                // to move while a long transfer runs, and `copy_bidirectional`
                // only reports when it returns.
                let remote = CountingStream::new(remote, tracked.flow().clone())
                    .with_totals(metrics.clone());
                // Outside the counter, so the bytes counted are the ones the
                // outbound actually took rather than the ones we accepted on
                // its behalf. Inside is where the userspace stack's missing
                // backpressure would otherwise become an unbounded heap: see
                // `backlog`.
                let remote = crate::backlog::BacklogGuard::new(
                    remote,
                    crate::backlog::ceiling_for(relay_buffer),
                );
                // Outermost, so what it observes is exactly the end-of-stream
                // the relay observes. This is the only thing in the flow that
                // can tell "the far end is quiet" from "the far end is gone",
                // and the whole of the difference between a thirty-second
                // reclaim and an hour-long one.
                let remote_eof = CancellationToken::new();
                let mut remote = crate::halfclose::WatchRemoteEof::new(remote, remote_eof.clone());
                // Pooled, because a flow used to allocate and zero two relay
                // buffers on arrival and hand them back on departure — per
                // flow, on a path whose flows are mostly short. The size is
                // unchanged: `ceiling_for` above derives this flow's backlog
                // ceiling from the same number, and the pool moves only where
                // the bytes come from. Cancellation is the normal ending here
                // (kill switch, revocation, idle reclaim), and the lease is
                // returned from `Drop`, so every one of those paths gives the
                // buffers back.
                let relay =
                    foxcore_relay::copy_bidirectional_pooled(&relay_pool, &mut stream, &mut remote);
                // Decided after the relay future is dropped, because that is
                // what releases the borrow on `stream` that closing needs.
                let mut idled = false;
                let mut half_closed = false;
                let mut failed = false;
                let mut revoked = false;
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    // Arming the kill switch has to reach flows that are
                    // already running, or "everything is off" is only true of
                    // connections nobody had opened yet.
                    _ = policy_revoked.cancelled() => revoked = true,
                    // The same requirement one app at a time. `revoke_flows`
                    // is what the user's "block this now" reaches, and what a
                    // quarantine of a newly installed app reaches; a policy
                    // reload deliberately does *not*, because a reordered
                    // routing rule must not kill a download.
                    _ = flow_revoked.cancelled() => revoked = true,
                    // The only thing that ever ended a TCP relay was the flow
                    // itself ending. A far end that goes away without saying so
                    // leaves the relay parked on both sides forever, holding
                    // one of `max_tcp_flows` slots that nothing returns.
                    _ = stayed_idle(&live, idle_timeout) => idled = true,
                    // And the same slot, taken by the far more common way of
                    // holding one: the far end sent FIN and the application
                    // never closed. `copy_bidirectional` returns when *both*
                    // directions are done, so that flow is charged to the table
                    // — and to a `CLOSE_WAIT` socket — until the hour above
                    // expires. On device that was 77 of them in thirty minutes,
                    // none of which cleared. A half-open connection that is
                    // still carrying data moves the counters this watches and is
                    // never reached by it.
                    _ = stayed_half_closed(&remote_eof, &live, half_closed_timeout) => {
                        half_closed = true;
                    }
                    // Bytes are counted by the stream as they pass, not from
                    // this return value: it never arrives on either branch
                    // above, and the kill switch makes those branches common.
                    result = relay => {
                        if let Err(error) = result {
                            // Whatever ended it, the session towards the app is
                            // still open and `ipstack` will not close it on
                            // drop. This is the fourth of the four abandonment
                            // paths `cba1e8a` found, and the only one that was
                            // not reachable from the test that proved the other
                            // three.
                            failed = true;
                            // Counted apart from `flow_errors` and reported
                            // with its own reason: this is the core refusing,
                            // not the network failing, and folding a correct
                            // fail-closed refusal into a connectivity counter
                            // is what made D7 read as a broken tunnel.
                            if crate::backlog::is_outbound_stalled(&error) {
                                metrics.flow_backlog_exceeded();
                                self.emit_block(
                                    BlockReason::FlowBacklogExceeded,
                                    IpTransport::Tcp,
                                    &context,
                                );
                            } else if !is_ordinary_end(&error) {
                                metrics.flow_error();
                            }
                        }
                    }
                }
                if idled {
                    metrics.flow_idle_timeout();
                }
                if half_closed {
                    metrics.flow_half_closed_timeout();
                }
                // A revoked flow is reset, not closed, and this was the last
                // place in the core where a torn-down connection still said
                // nothing at all. Until now `revoked.cancelled()` fell straight
                // through this block with `idled` and `failed` both false, so
                // arming the kill switch tore the relay down and left the
                // application holding a connection that would never answer —
                // the same silence `dispatch_tcp` was fixed for, on the path
                // where it matters most. "Everything is off" that reaches the
                // user as a hang is not a kill switch anyone can trust.
                //
                // A reset rather than a FIN for the same reason a refusal gets
                // one: a graceful close says the connection ended normally, and
                // an application that is being *stopped* should see it fail.
                // It also costs nothing — no handshake, no waiting for an ACK
                // the peer owes us — which is what makes revoking a thousand
                // flows at once safe to do from a button.
                if revoked {
                    metrics.revoke_flow();
                    stream.reset();
                } else if half_closed {
                    // Not the plain close the two below get. This session has
                    // already been half-closed towards the application by the
                    // relay, so `shutdown` can only complete if the application
                    // answers with its own FIN — and an application that has
                    // done nothing for thirty seconds is exactly the one that
                    // will not. See `close_or_reset_towards_app`.
                    Self::close_or_reset_towards_app(&mut stream).await;
                } else if idled || failed {
                    Self::close_towards_app(&mut stream).await;
                }
            }
            Err(_) => {
                metrics.dial_error();
                self.report_dial_failure(lane);
                Self::close_towards_app(&mut stream).await;
            }
        }
        metrics.close_flow();
    }
}
