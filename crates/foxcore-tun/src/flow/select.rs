use super::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::netstack::DatagramFlow;
use foxcore_api::{BlockReason, FlowContext, IpTransport, RouteAction};
use foxcore_outbound::Outbound;
use foxcore_route::RouteTable;
use foxcore_transport::Datagram;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use foxcore_trafficmap::{FlowLane, FlowRoute};

use crate::{is_i2p, is_onion};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DatagramSendOutcome {
    Sent,
    Failed,
    Cancelled,
    Revoked,
}

/// Send with backpressure while keeping every teardown signal observable.
async fn send_datagram_until_stopped(
    session: &foxcore_transport::BoxDatagramSession,
    datagram: Datagram,
    cancel: &CancellationToken,
    policy_revoked: &CancellationToken,
    flow_revoked: &CancellationToken,
) -> DatagramSendOutcome {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => DatagramSendOutcome::Cancelled,
        _ = policy_revoked.cancelled() => DatagramSendOutcome::Revoked,
        _ = flow_revoked.cancelled() => DatagramSendOutcome::Revoked,
        result = session.send(datagram) => match result {
            Ok(()) => DatagramSendOutcome::Sent,
            Err(_) => DatagramSendOutcome::Failed,
        },
    }
}

impl FlowEngine {
    /// Report the data plane's authoritative VPN-lane failure.
    pub(crate) fn report_dial_failure(&self, lane: FlowLane) {
        if lane == FlowLane::Vpn {
            let _ = self
                .continuity
                .interrupt(foxcore_api::ContinuityInterruption::VpnFailure);
        }
    }

    pub(crate) fn dispatch_udp(&self, stream: DatagramFlow, cancel: CancellationToken) {
        let Ok(permit) = self.udp_slots.clone().try_acquire_owned() else {
            // UDP has no accepted connection to reset; drop and record the refusal.
            self.refuse_for_flow_limit(IpTransport::Udp, stream.local_addr(), stream.peer_addr());
            return;
        };
        let engine = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            engine.handle_udp(stream, cancel).await;
        });
    }

    async fn handle_udp(&self, mut stream: DatagramFlow, cancel: CancellationToken) {
        let source = stream.local_addr();
        let destination = stream.peer_addr();
        let policy = self.policy.current.load();
        let mut context = context_for(
            self.generation,
            IpTransport::Udp,
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
                IpTransport::Udp,
            )
            .await
        {
            self.metrics.attribution_error();
            self.metrics.block_flow();
            self.emit_block(BlockReason::Unattributed, context.transport, &context);
            return;
        }
        if context.destination.port == 53 && policy.dns_proxy.is_some() {
            let metrics = self.metrics.clone();
            let policy = self.policy.clone();
            metrics.open_udp();
            serve_dns_udp(&mut stream, policy, context, &metrics, cancel).await;
            metrics.close_flow();
            return;
        }
        // Port 853 must not bypass filtering over QUIC either.
        if policy.dns_proxy.is_some()
            && policy
                .dns_config
                .bypasses_interceptor(destination.ip(), destination.port())
        {
            self.metrics.dns_encrypted_bypass();
            self.metrics.block_flow();
            self.emit_block(BlockReason::DnsEncryptedBypass, IpTransport::Udp, &context);
            return;
        }
        let SelectedRoute { outbound, route } = match self.select_route(&context, &policy.routes) {
            Ok(selected) => selected,
            Err(reason) => {
                self.metrics.block_flow();
                self.emit_block(reason, context.transport, &context);
                return;
            }
        };
        let metrics = self.metrics.clone();
        let dns = policy.dns.clone();
        let lane = route.lane;
        let policy_revoked = policy.revocation.clone();
        metrics.open_udp();
        let tracked = self.connections.open(
            IpTransport::Udp,
            context.destination.host.clone(),
            context.destination.port,
            route,
            context.packages.clone(),
            context.uid,
        );
        if context.packages.is_empty() {
            self.attribute_for_telemetry(
                tracked.flow().clone(),
                IpTransport::Udp,
                source,
                stream.peer_addr(),
            );
        }
        let flow_revoked = tracked.flow().revocation();
        if let Some(session) = self.open_datagram(&outbound, &context, lane).await {
            // TUN datagrams cannot exceed the link payload.
            let mut buffer = vec![0_u8; stream.max_payload()];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = policy_revoked.cancelled() => {
                        metrics.revoke_flow();
                        break;
                    }
                    _ = flow_revoked.cancelled() => {
                        metrics.revoke_flow();
                        break;
                    }
                    read = stream.read(&mut buffer) => {
                        let Ok(length) = read else {
                            metrics.flow_error();
                            break;
                        };
                        if length == 0 {
                            break;
                        }
                        let datagram = Datagram::new(
                            context.destination.clone(),
                            bytes::Bytes::copy_from_slice(&buffer[..length]),
                        );
                        match send_datagram_until_stopped(
                            &session,
                            datagram,
                            &cancel,
                            &policy_revoked,
                            &flow_revoked,
                        ).await {
                            DatagramSendOutcome::Sent => {}
                            DatagramSendOutcome::Failed => {
                                metrics.flow_error();
                                break;
                            }
                            DatagramSendOutcome::Cancelled => break,
                            DatagramSendOutcome::Revoked => {
                                metrics.revoke_flow();
                                break;
                            }
                        }
                        metrics.add_up(length as u64);
                        tracked.add_up(length as u64);
                    }
                    received = session.recv() => {
                        let Ok(datagram) = received else {
                            metrics.flow_error();
                            break;
                        };
                        if context.destination.port == 53 {
                            dns.observe_response(&datagram.payload);
                        }
                        if stream.write_all(&datagram.payload).await.is_err() {
                            metrics.flow_error();
                            break;
                        }
                        metrics.add_down(datagram.payload.len() as u64);
                        tracked.add_down(datagram.payload.len() as u64);
                    }
                }
            }
        }
        metrics.close_flow();
    }

    /// Open a datagram session, distinguishing unsupported UDP from dial failure.
    pub(super) async fn open_datagram(
        &self,
        outbound: &Outbound,
        context: &FlowContext,
        lane: FlowLane,
    ) -> Option<foxcore_transport::BoxDatagramSession> {
        match outbound.connect_datagram(context).await {
            Ok(session) => Some(session),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                self.metrics.udp_unsupported();
                self.metrics.block_flow();
                self.emit_block(BlockReason::UdpUnsupported, IpTransport::Udp, context);
                None
            }
            Err(_) => {
                self.metrics.dial_error();
                self.report_dial_failure(lane);
                None
            }
        }
    }

    pub(crate) async fn attribute_context(
        &self,
        context: &mut FlowContext,
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
        routes: &RouteTable,
        transport: IpTransport,
    ) -> bool {
        if !routes.requires_identity() {
            return true;
        }
        if !self.attributor.is_available() {
            return false;
        }
        let Some(identity) = self.resolve_identity(transport, source, destination).await else {
            return false;
        };
        if routes.requires_package() && identity.packages.is_empty() {
            return false;
        }
        context.uid = Some(identity.uid);
        context.package = identity.packages.first().cloned();
        context.packages = identity.packages;
        context.signing_digest = identity.signing_digest;
        true
    }

    /// Run one bounded platform lookup; the inner deadline also bounds orphaned
    /// `spawn_blocking` work after the async timeout drops its join handle.
    async fn resolve_identity(
        &self,
        transport: IpTransport,
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
    ) -> Option<foxcore_api::FlowIdentity> {
        let timeout = Duration::from_millis(self.runtime.attribution_timeout_ms);
        let attributor = self.attributor.clone();
        let slots = self.attribution_slots.clone();
        let shutdown = self.shutdown.clone();
        let deadline = tokio::time::Instant::now() + timeout;
        let resolved = tokio::time::timeout(timeout, async move {
            let permit = slots.acquire_owned().await.ok()?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                if shutdown.is_cancelled() || tokio::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                attributor.resolve(transport, source, destination)
            })
            .await
            .ok()
        })
        .await;
        let Ok(Some(Ok(Some(mut identity)))) = resolved else {
            return None;
        };
        identity.packages.retain(|package| {
            !package.trim().is_empty()
                && package.len() <= 255
                && !package.chars().any(char::is_control)
        });
        identity.packages.sort_unstable();
        identity.packages.dedup();
        identity.packages.truncate(32);
        Some(identity)
    }

    /// Resolve ownership after routing so telemetry never delays a flow.
    pub(crate) fn attribute_for_telemetry(
        &self,
        flow: Arc<foxcore_trafficmap::LiveFlow>,
        transport: IpTransport,
        source: std::net::SocketAddr,
        destination: std::net::SocketAddr,
    ) {
        if !self.attributor.is_available() {
            return;
        }
        let engine = self.clone();
        tokio::spawn(async move {
            if let Some(identity) = engine
                .resolve_identity(transport, source, destination)
                .await
            {
                flow.set_identity(Some(identity.uid), identity.packages);
            }
        });
    }

    /// Select the outbound and snapshot the exact route used for telemetry.
    pub(crate) fn select_route(
        &self,
        context: &FlowContext,
        routes: &RouteTable,
    ) -> Result<SelectedRoute, BlockReason> {
        let Some(outbound) = self.select_outbound(context, routes) else {
            return Err(if routes.kill_switch() {
                BlockReason::KillSwitch
            } else {
                BlockReason::Policy
            });
        };
        // A missing lane is a fail-closed refusal, not a network dial failure.
        if let Outbound::Deferred(deferred) = outbound.as_ref()
            && !deferred.is_available()
        {
            deferred.note_refusal();
            return Err(BlockReason::LaneUnavailable);
        }
        let lane = if is_onion(&context.destination.host) {
            FlowLane::Tor
        } else if is_i2p(&context.destination.host) {
            FlowLane::I2p
        } else {
            match routes.decide(context) {
                RouteAction::Direct => FlowLane::Direct,
                RouteAction::Tor => FlowLane::Tor,
                RouteAction::I2p => FlowLane::I2p,
                RouteAction::Block | RouteAction::Outbound(_) => FlowLane::Vpn,
            }
        };
        // Held lanes never downgrade to another route.
        if self.continuity.is_held(lane) {
            return Err(BlockReason::ContinuityHeld);
        }
        let mut route = FlowRoute::new(lane, outbound.kind().name());
        if let RouteAction::Outbound(id) = &routes.decide(context) {
            route = route.with_outbound_id(id.0.clone());
        }
        if let Outbound::Selector(selector) = outbound.as_ref() {
            route = route.with_member(selector.active_id());
        }
        Ok(SelectedRoute { outbound, route })
    }

    pub(super) fn select_outbound(
        &self,
        context: &FlowContext,
        routes: &RouteTable,
    ) -> Option<Arc<Outbound>> {
        let action = routes.decide(context);
        if matches!(action, RouteAction::Block) {
            return None;
        }
        if is_onion(&context.destination.host) {
            return routes
                .tor_enabled()
                .then(|| self.outbounds.tor().cloned())
                .flatten();
        }
        if is_i2p(&context.destination.host) {
            return routes
                .i2p_enabled()
                .then(|| self.outbounds.i2p().cloned())
                .flatten();
        }
        match action {
            RouteAction::Direct => Some(self.direct.clone()),
            RouteAction::Block => None,
            RouteAction::Tor => self.outbounds.tor().cloned(),
            RouteAction::I2p => self.outbounds.i2p().cloned(),
            // A stream reaching an L3 primary after reload must fail closed.
            RouteAction::Outbound(id) if self.packet_tunnel && is_primary_outbound(&id.0) => None,
            RouteAction::Outbound(id) => self
                .outbounds
                .get(&id.0)
                .filter(|outbound| outbound_allowed(outbound, routes))
                .cloned(),
        }
    }
}

#[cfg(test)]
mod send_tests {
    use std::time::Duration;

    use bytes::Bytes;
    use foxcore_api::Destination;
    use foxcore_transport::{Datagram, datagram_channel};
    use tokio_util::sync::CancellationToken;

    use super::{DatagramSendOutcome, send_datagram_until_stopped};

    #[derive(Clone, Copy)]
    enum Stop {
        Generation,
        Policy,
        Flow,
    }

    async fn assert_blocked_send_stops(stop: Stop) {
        let destination = Destination::new("resolver.example", 53);
        let (session, _io) = datagram_channel(1);
        session
            .send(Datagram::new(
                destination.clone(),
                Bytes::from_static(b"fills the outbound queue"),
            ))
            .await
            .expect("fill the one-slot queue");

        let cancel = CancellationToken::new();
        let policy = CancellationToken::new();
        let flow = CancellationToken::new();
        let task = tokio::spawn({
            let session = session.clone();
            let cancel = cancel.clone();
            let policy = policy.clone();
            let flow = flow.clone();
            async move {
                send_datagram_until_stopped(
                    &session,
                    Datagram::new(destination, Bytes::from_static(b"must not stay parked")),
                    &cancel,
                    &policy,
                    &flow,
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "the regression needs a send that is genuinely applying backpressure"
        );

        match stop {
            Stop::Generation => cancel.cancel(),
            Stop::Policy => policy.cancel(),
            Stop::Flow => flow.cancel(),
        }
        let outcome = tokio::time::timeout(Duration::from_millis(250), task)
            .await
            .expect("a stop signal must cancel a blocked UDP send")
            .expect("send task must not panic");
        let expected = match stop {
            Stop::Generation => DatagramSendOutcome::Cancelled,
            Stop::Policy | Stop::Flow => DatagramSendOutcome::Revoked,
        };
        assert_eq!(outcome, expected);
    }

    #[tokio::test]
    async fn a_blocked_udp_send_observes_generation_policy_and_flow_stop() {
        for stop in [Stop::Generation, Stop::Policy, Stop::Flow] {
            assert_blocked_send_stops(stop).await;
        }
    }
}
