use super::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::ipstack::IpStackUdpStream;
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

/// Wait for the outbound to accept one datagram without making teardown wait
/// for the outbound too.
///
/// `DatagramSession::send` is allowed to apply backpressure. That is useful,
/// but awaiting it directly inside the stream-read branch hid all three stop
/// signals in the outer `select!`: a full protocol queue could keep a revoked
/// app or an entire stopped generation alive indefinitely. Dropping the send
/// future is the session contract's cancellation mechanism.
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
    /// A dial the VPN lane could not complete.
    ///
    /// This is the data plane's only view of "the tunnel is down": the session
    /// itself lives inside the outbound. With `split_tunnel_on_vpn_failure`
    /// off, that is the moment the direct lane has to go down with it, because
    /// the reason to turn the flag off is to not have clearnet traffic continue
    /// while the tunnel is dead. With it on — the default — nothing happens
    /// here at all, and per-app `direct` rules keep working exactly as before.
    pub(crate) fn report_dial_failure(&self, lane: FlowLane) {
        if lane == FlowLane::Vpn {
            let _ = self
                .continuity
                .interrupt(foxcore_api::ContinuityInterruption::VpnFailure);
        }
    }

    pub(crate) fn dispatch_udp(&self, stream: IpStackUdpStream, cancel: CancellationToken) {
        let Ok(permit) = self.udp_slots.clone().try_acquire_owned() else {
            // The TCP arm of this — `dispatch_tcp` — owes the application a
            // reset, because the stack answered a SYN on its behalf and the
            // application is holding a connection. There is no equivalent debt
            // here: a datagram was never accepted, so the honest answer is to
            // drop it, and dropping is also the only answer that costs nothing.
            //
            // What this must *not* do is grow. The stream is dropped without
            // being read, which runs `IpStackUdpStream`'s destroy messenger and
            // takes the session straight back out of the stack's table; no
            // permit is held, no relay task is spawned, no row is opened in the
            // traffic map. The refusal is counted and named instead, which is
            // the only trace a dropped datagram can honestly leave.
            self.refuse_for_flow_limit(IpTransport::Udp, stream.local_addr(), stream.peer_addr());
            return;
        };
        let engine = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            engine.handle_udp(stream, cancel).await;
        });
    }

    async fn handle_udp(&self, mut stream: IpStackUdpStream, cancel: CancellationToken) {
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
        // The datagram half of the same gate: 853 is DNS over QUIC as well as
        // DNS over TLS. Android's Private DNS probe is the TCP one, so this arm
        // is not what closes D14 — it is what keeps the guarantee a statement
        // about the question rather than about the transport that carried it.
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
        // This flow's own stop signal, beside the snapshot's — see the TCP arm
        // in `handle_tcp` for why there are two and why they mean the same
        // thing.
        let flow_revoked = tracked.flow().revocation();
        if let Some(session) = self.open_datagram(&outbound, &context, lane).await {
            // Sized to what the link can actually deliver, not to the largest
            // number a UDP length field can hold. Datagrams reach this stream
            // from tun packets, so the ceiling is the MTU less both headers —
            // 1372 bytes at the Android MTU of 1400. The old 64 KiB was 47×
            // that, per flow, and `max_udp_flows` is 512: about 32 MB of
            // resident memory that could never be filled.
            let mut buffer = vec![0_u8; stream.max_payload()];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    // A datagram flow has no reset to send — there is no
                    // connection state at the far end to tear down — so what a
                    // revocation owes it is to stop carrying traffic and to
                    // give the resources back. Breaking here does both: the
                    // outbound session is dropped with this scope, and
                    // `stream` is dropped when `handle_udp` returns, which
                    // fires `IpStackUdpStream`'s destroy messenger and takes
                    // the session straight out of the stack's table.
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

    /// Open the datagram session for a UDP flow, telling the two failure modes
    /// apart.
    ///
    /// An outbound that cannot carry this flow as datagrams — HTTP CONNECT and
    /// Naive have no UDP at all, and Vision on UDP/443 and Shadowsocks over a
    /// stream transport refuse the individual flow — is answering correctly for
    /// this profile, permanently. Counting that as a dial error
    /// made a working fail-closed core look like a network fault and kept the
    /// refusal out of the audit trail entirely (D7, found on device); a UI
    /// watching `dial_errors` climb has no way to tell "your proxy is
    /// unreachable" from "this proxy has no UDP, by design".
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

    /// One bounded platform lookup, shared by routing and by telemetry.
    ///
    /// The deadline is carried into the blocking closure because
    /// `tokio::time::timeout` cancels the *future*, not the blocking task
    /// underneath it: dropping the join handle abandons the work, it does not
    /// stop it. On a two-thread blocking pool that is how a long session leaves
    /// a queue of platform calls nobody will read, and shutting the runtime
    /// down then runs every one of them — which is how `nativeStop` came to
    /// hang for minutes after half an hour of traffic (D13). A task that
    /// reaches the front of the queue after its caller gave up, or after the
    /// generation ended, does nothing and returns.
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

    /// Find out who owns a flow that is already running, for the map alone.
    ///
    /// Per-app bytes are a product requirement, and they used to depend on the
    /// policy happening to need identity for *routing*: with no per-app rules
    /// nothing resolved, and every snapshot reported zero packages (D12).
    ///
    /// Resolving it here rather than inline is the difference between a feature
    /// and a regression — inline would put a platform round trip in front of
    /// every connection's first byte. Late is fine: totals are computed from
    /// the row's owner at snapshot and at close, so a package that lands a few
    /// milliseconds after the flow opens still accounts for all of its bytes.
    /// Failure is fine too; this never decides anything.
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

    /// Which outbound carries this flow, and by which route.
    ///
    /// The route is recorded here rather than derived later because this is the
    /// only place that knows all three parts of it at once: the lane the policy
    /// chose, the protocol that ended up carrying it, and — for a group — the
    /// member the selector was on at this instant. Reading the member back off
    /// the selector when a screen renders would report the server the group has
    /// since failed over to, not the one that moved these bytes.
    pub(crate) fn select_route(
        &self,
        context: &FlowContext,
        routes: &RouteTable,
    ) -> Result<SelectedRoute, BlockReason> {
        let Some(outbound) = self.select_outbound(context, routes) else {
            // A kill-switch block is reported distinctly: the operator needs to
            // see "everything is off" rather than a pile of per-flow denials.
            return Err(if routes.kill_switch() {
                BlockReason::KillSwitch
            } else {
                BlockReason::Policy
            });
        };
        // An outbound that could not be built refuses its own flows here,
        // before anything is dialled and before any other lane is consulted.
        //
        // Refusing rather than dialling keeps the failure honest in two ways.
        // The flow is not counted as a dial error — that counter is about the
        // network, and this is the core declining to carry traffic it has
        // nothing to carry it with (the D7 lesson). And no dial failure means
        // no `VpnFailure` interruption from this path, so an overlay that never
        // built cannot suspend a lane that is working. What it must never do is
        // answer the flow from somewhere else: a VPN that failed to build and
        // whose apps quietly went out clearnet is the outcome the whole
        // isolation contract exists to prevent.
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
                // Block never reaches here: `select_outbound` returned None.
                RouteAction::Block | RouteAction::Outbound(_) => FlowLane::Vpn,
            }
        };
        // Held lanes refuse before anything is dialled. Never a downgrade to
        // another lane: a suspended VPN whose flows quietly went out direct is
        // the exact outcome turning the flag off exists to prevent.
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
            // Returned above; refusing rather than asserting, because this runs
            // per flow and a panic aborts the process in release.
            RouteAction::Block => None,
            RouteAction::Tor => self.outbounds.tor().cloned(),
            RouteAction::I2p => self.outbounds.i2p().cloned(),
            // The primary is an L3 tunnel in packet-tunnel mode, so it is not in
            // the registry at all and the entry under this id is a placeholder.
            // A stream flow that reached the stack with this action lost a race
            // with a policy reload; answering it from the registry would put the
            // traffic on the open network. Refusing is the only safe answer.
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
