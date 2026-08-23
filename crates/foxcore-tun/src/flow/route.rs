use super::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::netstack::{DatagramFlow, FlowStack, StackConfig, TcpFlow, UnknownTransport};
use foxcore_api::{
    BlockReason, CoreEvent, Destination, FlowContext, IpTransport, RouteAction, RuntimeConfig,
};
use foxcore_dns::{DnsCache, servfail_response, truncated_response};
use foxcore_outbound::{Outbound, OutboundKind};
use foxcore_route::RouteTable;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use foxcore_trafficmap::{FlowRoute, LiveFlow};

#[cfg(feature = "wireguard")]
use crate::TunDevice;
use crate::{FlowMetrics, echo_reply_v4};

/// An outbound together with the route the traffic map will record for it.
pub(crate) struct SelectedRoute {
    pub(crate) outbound: Arc<Outbound>,
    pub(crate) route: FlowRoute,
}

/// Whether an I/O error represents ordinary flow termination rather than failure.
pub(crate) fn is_ordinary_end(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
    )
}

/// Resolve after `idle` without relay-visible traffic; stack-handled keepalives
/// intentionally do not count as activity.
pub(crate) async fn stayed_idle(flow: &LiveFlow, idle: Duration) {
    stayed_quiet(flow, idle, (idle / 4).max(Duration::from_secs(1))).await;
}

/// Resolve after remote EOF followed by `window` without relay-visible traffic.
pub(crate) async fn stayed_half_closed(
    remote_eof: &CancellationToken,
    flow: &LiveFlow,
    window: Duration,
) {
    remote_eof.cancelled().await;
    stayed_quiet(flow, window, HALF_CLOSED_STEP.min(window)).await;
}

const HALF_CLOSED_STEP: Duration = Duration::from_secs(1);

async fn stayed_quiet(flow: &LiveFlow, window: Duration, step: Duration) {
    let step = step.max(Duration::from_millis(1));
    let moved = |flow: &LiveFlow| flow.bytes_up().saturating_add(flow.bytes_down());
    let mut seen = moved(flow);
    let mut still = Duration::ZERO;
    loop {
        tokio::time::sleep(step).await;
        let now = moved(flow);
        if now == seen {
            still = still.saturating_add(step);
            if still >= window {
                return;
            }
        } else {
            seen = now;
            still = Duration::ZERO;
        }
    }
}

pub(crate) fn outbound_allowed(outbound: &Outbound, routes: &RouteTable) -> bool {
    match outbound.kind() {
        OutboundKind::Tor => routes.tor_enabled(),
        OutboundKind::I2p => routes.i2p_enabled(),
        _ => true,
    }
}

pub(crate) async fn serve_dns_tcp(
    stream: &mut TcpFlow,
    policy: Arc<FlowPolicyStore>,
    context: FlowContext,
    metrics: &FlowMetrics,
    cancel: CancellationToken,
) {
    loop {
        let length = tokio::select! {
            _ = cancel.cancelled() => return,
            length = stream.read_u16() => match length {
                Ok(length) => usize::from(length),
                Err(_) => return,
            }
        };
        if length < 12 {
            metrics.flow_error();
            return;
        }
        let mut query = vec![0_u8; length];
        let read = tokio::select! {
            _ = cancel.cancelled() => return,
            read = stream.read_exact(&mut query) => read,
        };
        if read.is_err() {
            return;
        }
        metrics.add_up(length as u64);
        let response = tokio::select! {
            _ = cancel.cancelled() => return,
            response = exchange_dns(&policy, &context, &query, metrics) => {
                response.or_else(|| servfail_response(&query))
            }
        };
        let Some(response) = response else {
            metrics.flow_error();
            return;
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            metrics.flow_error();
            return;
        };
        let write = tokio::select! {
            _ = cancel.cancelled() => return,
            write = async {
                stream.write_u16(response_len).await?;
                stream.write_all(&response).await?;
                stream.flush().await
            } => write,
        };
        if write.is_err() {
            return;
        }
        metrics.add_down(response.len() as u64);
    }
}

pub(crate) async fn serve_dns_udp(
    stream: &mut DatagramFlow,
    policy: Arc<FlowPolicyStore>,
    context: FlowContext,
    metrics: &FlowMetrics,
    cancel: CancellationToken,
) {
    let mut buffer = vec![0_u8; stream.max_payload()];
    loop {
        let length = tokio::select! {
            _ = cancel.cancelled() => return,
            read = stream.read(&mut buffer) => match read {
                Ok(0) | Err(_) => return,
                Ok(length) => length,
            }
        };
        let query = &buffer[..length];
        metrics.add_up(length as u64);
        let response = tokio::select! {
            _ = cancel.cancelled() => return,
            response = exchange_dns(&policy, &context, query, metrics) => {
                response.or_else(|| servfail_response(query))
            }
        };
        let Some(response) = response else {
            metrics.flow_error();
            continue;
        };
        // RFC 1035 requires oversized UDP answers to advertise truncation.
        let response = if response.len() > stream.max_payload() {
            match truncated_response(query) {
                Some(truncated) => {
                    metrics.dns_truncated();
                    truncated
                }
                None => {
                    metrics.flow_error();
                    continue;
                }
            }
        } else {
            response
        };
        let write = tokio::select! {
            _ = cancel.cancelled() => return,
            write = stream.write_all(&response) => write,
        };
        if write.is_err() {
            return;
        }
        metrics.add_down(response.len() as u64);
    }
}

pub(super) async fn exchange_dns(
    policy: &FlowPolicyStore,
    context: &FlowContext,
    query: &[u8],
    metrics: &FlowMetrics,
) -> Option<Vec<u8>> {
    let current = policy.current.load();
    // Report DNS policy refusals through the same audit surface as other flows.
    let unattributed = (current.routes.requires_uid() && context.uid.is_none())
        || (current.routes.requires_package() && context.packages.is_empty());
    let reason = if unattributed {
        Some(BlockReason::Unattributed)
    } else if matches!(current.routes.decide(context), RouteAction::Block) {
        Some(if current.routes.kill_switch() {
            BlockReason::KillSwitch
        } else {
            BlockReason::Policy
        })
    } else {
        None
    };
    if let Some(reason) = reason {
        if unattributed {
            metrics.attribution_error();
        }
        metrics.block_flow();
        policy.events.emit_with(|| CoreEvent::Blocked {
            reason,
            transport: context.transport,
            destination: context.destination.clone(),
            uid: context.uid,
            package: context.package.clone(),
        });
        return None;
    }
    let proxy = current.dns_proxy.clone()?;
    drop(current);
    proxy
        .exchange_for_identity(
            query,
            context.package.as_deref(),
            context.packages.as_slice(),
        )
        .await
        .ok()
}

/// Read packets directly into arena buffers from the single TUN reader.
#[cfg(feature = "wireguard")]
pub(crate) async fn read_tun(
    mut reader: tokio::io::ReadHalf<TunDevice>,
    to_ingress: tokio::sync::mpsc::Sender<bytes::BytesMut>,
    mtu: u16,
    cancel: CancellationToken,
) {
    let mut arena =
        crate::arena::PacketArena::new(usize::from(mtu).saturating_add(TUN_READ_HEADROOM));
    loop {
        let read = tokio::select! {
            _ = cancel.cancelled() => return,
            read = arena.read_packet(&mut reader) => read,
        };
        let Ok(Some(packet)) = read else { return };
        if to_ingress.send(packet).await.is_err() {
            return;
        }
    }
}

/// Serialize packets from both producers through the single TUN writer.
#[cfg(feature = "wireguard")]
pub(crate) async fn write_tun(
    mut writer: tokio::io::WriteHalf<TunDevice>,
    mut inbox: tokio::sync::mpsc::Receiver<bytes::BytesMut>,
    metrics: Arc<FlowMetrics>,
    cancel: CancellationToken,
) {
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => return,
            packet = inbox.recv() => match packet {
                Some(packet) => packet,
                None => return,
            },
        };
        match writer.write(&packet).await {
            Ok(written) if written == packet.len() => {}
            // A short TUN write cannot be resumed as another packet.
            Ok(_) => metrics.flow_error(),
            Err(_) => return,
        }
    }
}

/// Build one generation's stack with a shared cap equal to both transport caps.
pub(crate) fn build_stack<D>(
    device: D,
    mtu: u16,
    runtime: &RuntimeConfig,
    metrics: &FlowMetrics,
) -> io::Result<FlowStack>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut config = StackConfig::default();
    config
        .mtu(mtu)
        .map_err(|error| io::Error::other(error.to_string()))?;
    config
        .packet_information(false)
        .udp_timeout(Duration::from_secs(runtime.idle_timeout_s))
        .max_sessions(runtime.max_tcp_flows.saturating_add(runtime.max_udp_flows))
        .max_tcp_sessions(runtime.max_tcp_flows)
        .report_tcp_refusals(true)
        .udp_queue_drop_counter(metrics.udp_queue_drop_counter());
    Ok(FlowStack::new(config, device))
}

pub(crate) fn context_for(
    generation: u64,
    transport: IpTransport,
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    dns: &DnsCache,
) -> FlowContext {
    let fake_domain = dns.fake_domain(destination.ip());
    let domain_hint = fake_domain
        .clone()
        .or_else(|| dns.reverse_domain(destination.ip()));
    let destination = match fake_domain {
        Some(domain) => Destination::new(domain, destination.port()),
        None => Destination::new(destination.ip().to_string(), destination.port()),
    };
    let mut context = FlowContext::new(generation, transport, destination);
    context.source = Some(source);
    context.domain_hint = domain_hint;
    context
}

pub(crate) fn answer_icmp(unknown: UnknownTransport) {
    if u8::from(unknown.ip_protocol()) != IP_PROTOCOL_ICMP {
        return;
    }
    if let Some(reply) = echo_reply_v4(unknown.payload()) {
        let _ = unknown.send(reply);
    }
}
