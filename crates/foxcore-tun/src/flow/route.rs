use super::*;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::ipstack::{
    IpStack, IpStackConfig, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport,
};
use foxcore_api::{
    BlockReason, CoreEvent, Destination, FlowContext, IpTransport, RouteAction, RuntimeConfig,
};
use foxcore_dns::{DnsCache, servfail_response, truncated_response};
use foxcore_outbound::{Outbound, OutboundKind};
use foxcore_route::RouteTable;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use foxcore_trafficmap::{FlowRoute, LiveFlow};

use crate::{FlowMetrics, echo_reply_v4};
// Only `read_tun`/`write_tun` name the device here, and both are the packet
// tunnel's halves. Imported unconditionally this was a warning in every build
// without the feature — which is every build whose whole point is that the
// feature is off, so the one configuration that most needs to compile cleanly
// was the one that did not.
#[cfg(feature = "wireguard")]
use crate::TunDevice;

/// An outbound together with the route the traffic map will record for it.
pub(crate) struct SelectedRoute {
    pub(crate) outbound: Arc<Outbound>,
    pub(crate) route: FlowRoute,
}

/// Whether an I/O error is how this flow was always going to end.
///
/// A peer that resets, a tun stream the platform closed, an idle datagram
/// session timing out: these are terminations, not failures. Counting them as
/// errors put `flow_errors` at 114 of 124 flows on a device where every one of
/// 27 probes succeeded (D9) — a number that says "something is badly wrong"
/// about a core that was working. A real failure still counts, because the
/// whole value of the counter is that it means something when it moves.
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

/// Resolves once a live flow has passed no bytes in either direction for
/// `idle`.
///
/// This is the TCP relay's only timeout, and until it existed there was none at
/// all. `idle_timeout_s` reached the stack's UDP sessions and the split table
/// and stopped there — and it stays there: what arrives here is
/// `tcp_idle_timeout_s`, whose whole reason for existing is the last paragraph
/// below. `ipstack`'s own 60-second TCP timer is armed inside
/// `poll_read`, so a relay parked in its *write* direction — which is exactly
/// what a far end that stops accepting produces — never re-arms it. Measured
/// with a black hole applied to established flows: eleven of them sat unchanged
/// for the last 91 seconds of the run, and `max_tcp_flows` is 1024.
///
/// Sampled rather than instrumented, because the counters
/// [`foxcore_trafficmap::CountingStream`] already keeps for the traffic map say
/// exactly what is wanted — bytes the outbound actually took and actually
/// returned — and adding a second set of them to the hot path to answer a
/// question asked once a minute would be the wrong trade. A busy flow pays one
/// atomic load per quarter-window; an idle one pays a timer.
///
/// What this deliberately does *not* count as activity is a TCP keepalive from
/// the application. The stack answers those itself and the relay never sees
/// them, so a connection whose only liveness is an empty ACK will be closed
/// here. That is a property of the *value*, not of this mechanism — and it is
/// why the value is [`foxcore_api::RuntimeConfig::tcp_idle_timeout_s`] rather
/// than the UDP window it started out sharing: at five minutes this closed push
/// channels, which are the connections most likely to be silent and alive.
pub(crate) async fn stayed_idle(flow: &LiveFlow, idle: Duration) {
    stayed_quiet(flow, idle, (idle / 4).max(Duration::from_secs(1))).await;
}

/// Resolves once the flow's **remote half has closed** and it has carried
/// nothing for `window` since.
///
/// The other half of the same mechanism, asking a narrower question, and the
/// reason it is worth asking separately is in [`HALF_CLOSED_TIMEOUT`]: a relay
/// ends when `copy_bidirectional` returns, `copy_bidirectional` returns when
/// *both* directions are finished, and a far end that sent FIN finishes one of
/// them. The other waits on an application that may never write again — and for
/// as long as it waits the flow holds a `CLOSE_WAIT` socket and one of
/// `max_tcp_flows`, with only the hour-long idle clock underneath it.
///
/// Sampled against the same counters [`stayed_idle`] reads, and for the same
/// reason. What differs is the step: the idle clock takes a quarter of an hour's
/// window because nothing is waiting on its resolution, while this one is
/// bounded by a number small enough that a quarter of it would be a visible
/// share of the answer. One second is exact to within a second and costs at most
/// thirty wakeups over the whole remaining life of a flow that is, by
/// construction, doing nothing.
///
/// Nothing here decides that a half-open flow is dead — a flow still pushing
/// bytes moves the counter and resets the window, exactly as a live silent
/// connection would with the idle clock.
pub(crate) async fn stayed_half_closed(
    remote_eof: &CancellationToken,
    flow: &LiveFlow,
    window: Duration,
) {
    remote_eof.cancelled().await;
    stayed_quiet(flow, window, HALF_CLOSED_STEP.min(window)).await;
}

/// How often [`stayed_half_closed`] looks. See its documentation for why this is
/// not a fraction of the window the way [`stayed_idle`]'s step is.
const HALF_CLOSED_STEP: Duration = Duration::from_secs(1);

/// Resolves once `flow` has passed no bytes in either direction for `window`,
/// looking every `step`.
///
/// The shared body of [`stayed_idle`] and [`stayed_half_closed`], which differ
/// only in when they start and how long they wait. Why it samples rather than
/// instruments is on [`stayed_idle`].
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
    stream: &mut IpStackTcpStream,
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
    stream: &mut IpStackUdpStream,
    policy: Arc<FlowPolicyStore>,
    context: FlowContext,
    metrics: &FlowMetrics,
    cancel: CancellationToken,
) {
    // Same ceiling as the plain UDP path: a query arrives in one tun packet.
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
        // An answer larger than one datagram is answered with the truncation
        // bit instead, which is what RFC 1035 defines and what the TCP side of
        // this same interceptor exists to serve. The stack used to accept the
        // oversized write and put the tail on the wire as a second datagram,
        // so a DNSSEC-signed or large TXT lookup failed and nothing counted it.
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
    // A refused DNS query is a refused flow and has to be counted and reported
    // like one. Returning `None` in silence left the app with `blocked_flows`
    // at zero, `dns_queries` at zero and an empty event stream while every
    // lookup failed — the firewall working and looking broken (found on
    // device).
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

/// Read whole packets off the tun and hand them to the classifier.
///
/// Split out from the stack so exactly one task owns the read side: two readers
/// on a tun descriptor would each get a different subset of the packets, which
/// is indistinguishable from packet loss and impossible to debug.
///
/// The descriptor is read straight into the buffer the packet travels in, so
/// nothing on this path copies. It used to read into a buffer it kept and copy
/// `buffer[..length].to_vec()` into a fresh allocation for the channel, once per
/// packet the device moves; see [`PacketArena`].
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
        // A read error or EOF means the descriptor is gone; the generation is
        // over and there is nothing left to classify.
        let Ok(Some(packet)) = read else { return };
        if to_ingress.send(packet).await.is_err() {
            return;
        }
    }
}

/// The single writer. Both the tunnel and the stack feed this queue, so a
/// packet is never interleaved with another halfway through a write.
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
            // A tun writes a whole packet or nothing. A short write means the
            // rest of this packet is lost, and continuing would send the
            // remainder as if it were a new one.
            Ok(_) => metrics.flow_error(),
            Err(_) => return,
        }
    }
}

/// The stack for one generation, sized from the same numbers the engine is.
///
/// `max_sessions` is `max_tcp_flows + max_udp_flows` and not a constant of its
/// own, so the two limits cannot drift apart:
///
/// * larger, and the stack would hold sessions the engine has no slot for. Each
///   one costs a task, a TCB and a receive buffer for a flow that can only ever
///   be refused, which is the memory the cap exists to bound.
/// * smaller, and the stack would refuse SYNs the engine had room to serve —
///   a working connection turned away by an accounting mistake.
///
/// It is the same sum `PacketSplitter` is already built with on the L3 path
/// (see `run_with_packet_tunnel`), for the same reason: it is how many flows
/// this core can have at once, whichever plane carries them.
///
/// The engine still keeps its own refusal in `dispatch_tcp`, because these caps
/// are not interchangeable — the engine's are per-transport and this one is
/// shared, so a burst of one transport can fill the table while the other's
/// slots are free.
pub(crate) fn build_stack<D>(
    device: D,
    mtu: u16,
    runtime: &RuntimeConfig,
    metrics: &FlowMetrics,
) -> io::Result<IpStack>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut config = IpStackConfig::default();
    config
        .mtu(mtu)
        .map_err(|error| io::Error::other(error.to_string()))?;
    config
        .packet_information(false)
        .udp_timeout(Duration::from_secs(runtime.idle_timeout_s))
        .max_sessions(runtime.max_tcp_flows.saturating_add(runtime.max_udp_flows))
        .udp_queue_drop_counter(metrics.udp_queue_drop_counter());
    Ok(IpStack::new(config, device))
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

pub(crate) fn answer_icmp(unknown: IpStackUnknownTransport) {
    if u8::from(unknown.ip_protocol()) != IP_PROTOCOL_ICMP {
        return;
    }
    if let Some(reply) = echo_reply_v4(unknown.payload()) {
        let _ = unknown.send(reply);
    }
}
