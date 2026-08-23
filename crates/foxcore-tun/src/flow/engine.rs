use super::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::netstack::{FlowStack, StackFlow, TcpFlow};
#[cfg(feature = "wireguard")]
use foxcore_api::RouteAction;
use foxcore_api::{BlockReason, CoreEvent, FlowContext, IpTransport};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use foxcore_trafficmap::CountingStream;
#[cfg(feature = "wireguard")]
use foxcore_trafficmap::{FlowLane, FlowRoute};

use crate::TunDevice;
use crate::continuity::ContinuityGate;
#[cfg(feature = "wireguard")]
use crate::{is_i2p, is_onion};

/// Keep at most 1 MiB idle, with a floor useful at the largest configured buffer.
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

    /// Count and report a flow refused because its transport slots are full.
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

        // Join all tasks before releasing either half of the TUN.
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
                    // A policy replaced during attribution invalidates the decision.
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

    async fn accept_loop(&self, mut stack: FlowStack, cancel: CancellationToken) -> io::Result<()> {
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
                        Err(error) => break Err(error.into()),
                    }
                }
            }
        };
        crate::enginephase::mark(crate::enginephase::PHASE_LOOP_EXITED);
        stack.shutdown().await;
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
            // Portless protocols are handled by the stack's ICMP/kill-switch path.
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
        // Intercepted DNS must remain on the stack side.
        if context.destination.port == 53 && policy.dns_proxy.is_some() {
            return PacketDecision::new(PacketRoute::Stack);
        }
        // Refuse encrypted-DNS bypasses in band on the stack; dropping here
        // would leave Android waiting for its connect timeout.
        if policy.dns_proxy.is_some()
            && policy
                .dns_config
                .bypasses_interceptor(key.destination, key.destination_port)
        {
            return PacketDecision::new(PacketRoute::Stack);
        }
        // Overlay names have no raw-IP route through the packet tunnel.
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
                // A peer cannot route synthetic DNS addresses; enforce the
                // startup invariant again at the final L3 boundary.
                if policy.dns_config.synthesizes(key.destination) {
                    self.metrics.block_flow();
                    self.emit_block(BlockReason::TunnelFakeIpUnroutable, transport, &context);
                    return PacketDecision::new(PacketRoute::Block);
                }
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

    fn dispatch(&self, stream: StackFlow, cancel: CancellationToken) {
        match stream {
            StackFlow::Tcp(stream) => self.dispatch_tcp(stream, cancel),
            StackFlow::TcpRefused { local, peer } => {
                self.refuse_for_flow_limit(IpTransport::Tcp, local, peer);
            }
            StackFlow::Udp(stream) => self.dispatch_udp(stream, cancel),
            StackFlow::UnknownTransport(stream) => {
                // ICMP bypasses `decide`, so enforce the kill switch here.
                if self.policy.current.load().routes.kill_switch() {
                    self.metrics.block_flow();
                } else {
                    answer_icmp(stream);
                }
            }
            StackFlow::UnknownNetwork(_) => self.metrics.flow_error(),
        }
    }

    /// Close an accepted session in band, without letting a missing ACK retain its slot.
    async fn close_towards_app(stream: &mut TcpFlow) {
        let _ = tokio::time::timeout(CLIENT_CLOSE_TIMEOUT, stream.shutdown()).await;
    }

    /// Gracefully close a half-closed session, then reset if its peer never answers.
    async fn close_or_reset_towards_app(stream: &mut TcpFlow) {
        if tokio::time::timeout(CLIENT_CLOSE_TIMEOUT, stream.shutdown())
            .await
            .is_err()
        {
            stream.reset();
        }
    }

    fn dispatch_tcp(&self, mut stream: TcpFlow, cancel: CancellationToken) {
        let Ok(permit) = self.tcp_slots.clone().try_acquire_owned() else {
            // The stack has a shared cap; this enforces the narrower TCP cap.
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

    async fn handle_tcp(&self, mut stream: TcpFlow, cancel: CancellationToken) {
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
        // Refuse bypasses in band so Android can fall back to filtered DNS.
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
        let idle_timeout = Duration::from_secs(self.runtime.tcp_idle_timeout_s);
        // Never retain a dead peer longer than a live but idle one.
        let half_closed_timeout = HALF_CLOSED_TIMEOUT.min(idle_timeout);
        let lane = route.lane;
        // Bind the flow to the policy snapshot that selected it.
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
        let live = tracked.flow().clone();
        let flow_revoked = live.revocation();
        match outbound.connect_stream(&context, destination).await {
            Ok(remote) => {
                let remote = CountingStream::new(remote, tracked.flow().clone())
                    .with_totals(metrics.clone());
                // Keep backpressure outside accounting so only delivered bytes count.
                let remote = crate::backlog::BacklogGuard::new(
                    remote,
                    crate::backlog::ceiling_for(relay_buffer),
                );
                let remote_eof = CancellationToken::new();
                let mut remote = crate::halfclose::WatchRemoteEof::new(remote, remote_eof.clone());
                let relay =
                    foxcore_relay::copy_bidirectional_pooled(&relay_pool, &mut stream, &mut remote);
                // Decide after the relay future releases its borrow on `stream`.
                let mut idled = false;
                let mut half_closed = false;
                let mut failed = false;
                let mut revoked = false;
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = policy_revoked.cancelled() => revoked = true,
                    _ = flow_revoked.cancelled() => revoked = true,
                    _ = stayed_idle(&live, idle_timeout) => idled = true,
                    _ = stayed_half_closed(&remote_eof, &live, half_closed_timeout) => {
                        half_closed = true;
                    }
                    result = relay => {
                        if let Err(error) = result {
                            failed = true;
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
                // Revocation is a failure, so reset rather than reporting a clean EOF.
                if revoked {
                    metrics.revoke_flow();
                    stream.reset();
                } else if half_closed {
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
