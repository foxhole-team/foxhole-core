//! Hysteria2 port hopping below Quinn's QUIC packet layer.
//!
//! The server listens on (or redirects) a whole range of UDP ports, and the
//! client keeps moving between them so no single port carries the connection
//! long enough to be throttled or blocked. The QUIC connection itself does not
//! notice: connection IDs, not addresses, are what identify it.
//!
//! Two rewrites make that invisible to Quinn, which would otherwise treat a
//! changed peer address as path migration and a reply from an unexpected port as
//! an off-path packet:
//!
//! * outgoing datagrams go to the currently chosen port rather than the one the
//!   endpoint was told to connect to;
//! * incoming datagrams are reported as coming *from* that original address.
//!
//! Deviation from the reference client, stated because it is visible on the
//! wire: upstream also rebinds its local socket on every hop, so the source port
//! moves too. FoxCore keeps one socket. On Android every UDP socket has to be
//! handed to `VpnService.protect()` before it sends anything, and an unprotected
//! datagram routes back into our own TUN; rebinding mid-connection would put
//! that guarantee in the middle of a hot path. The destination port — the one
//! the middlebox is filtering on — still moves.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};

/// Ports to hop between, and how long to stay on each.
#[derive(Debug, Clone)]
pub(crate) struct HopPlan {
    /// Every port the server answers on, expanded from the configured ranges.
    pub(crate) ports: Arc<[u16]>,
    pub(crate) interval: Duration,
}

/// Runtime adapter that wraps whatever socket the inner runtime produces.
///
/// Composes with [`crate::obfs::SalamanderRuntime`]: obfuscation rewrites the
/// datagram body, hopping rewrites its address, and neither needs to know about
/// the other.
pub(crate) struct PortHopRuntime {
    inner: Arc<dyn Runtime>,
    plan: HopPlan,
    /// The address the endpoint was told to connect to. Every received datagram
    /// is reported as coming from here.
    canonical: SocketAddr,
}

impl PortHopRuntime {
    pub(crate) fn new(inner: Arc<dyn Runtime>, plan: HopPlan, canonical: SocketAddr) -> Self {
        Self {
            inner,
            plan,
            canonical,
        }
    }
}

impl fmt::Debug for PortHopRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortHopRuntime")
            .field("ports", &self.plan.ports.len())
            .field("interval", &self.plan.interval)
            .finish_non_exhaustive()
    }
}

impl Runtime for PortHopRuntime {
    fn new_timer(&self, deadline: Instant) -> std::pin::Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(deadline)
    }

    fn spawn(&self, future: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future);
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = self.inner.wrap_udp_socket(socket)?;
        Ok(Arc::new(PortHopSocket::new(
            inner,
            self.plan.clone(),
            self.canonical,
        )?))
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

struct HopState {
    port: u16,
    next_hop: Instant,
}

struct PortHopSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    plan: HopPlan,
    canonical: SocketAddr,
    state: Mutex<HopState>,
}

impl PortHopSocket {
    fn new(
        inner: Arc<dyn AsyncUdpSocket>,
        plan: HopPlan,
        canonical: SocketAddr,
    ) -> io::Result<Self> {
        let port = pick(&plan.ports)?;
        let next_hop = Instant::now() + plan.interval;
        Ok(Self {
            inner,
            plan,
            canonical,
            state: Mutex::new(HopState { port, next_hop }),
        })
    }

    /// The port this datagram goes to, rotating when the dwell time is up.
    ///
    /// Hopping is driven by sends rather than by a timer task: an idle
    /// connection has nothing to hide, and a background task would have to
    /// outlive the socket it mutates.
    fn destination(&self) -> SocketAddr {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if now >= state.next_hop {
            // A failed OS RNG must not stall the connection; staying on the
            // current port is a worse hiding place, not a broken one.
            if let Ok(port) = pick(&self.plan.ports) {
                state.port = port;
            }
            state.next_hop = now + self.plan.interval;
        }
        SocketAddr::new(self.canonical.ip(), state.port)
    }
}

impl fmt::Debug for PortHopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortHopSocket")
            .field("inner", &self.inner)
            .field("ports", &self.plan.ports.len())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for PortHopSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(&Transmit {
            destination: self.destination(),
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let received = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(received)) => received,
        };
        for entry in meta.iter_mut().take(received) {
            // Report the address the connection was established on. Quinn would
            // otherwise see every reply as coming from an unknown peer and drop
            // it, or treat it as a migration attempt.
            if entry.addr.ip() == self.canonical.ip() {
                entry.addr = self.canonical;
            }
        }
        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

/// Uniform choice over the port set.
fn pick(ports: &[u16]) -> io::Result<u16> {
    if ports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port hopping needs at least one port",
        ));
    }
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("operating system RNG failed"))?;
    let index = usize::try_from(u64::from_be_bytes(bytes) % ports.len() as u64)
        .map_err(|_| io::Error::other("port index does not fit the platform word"))?;
    Ok(ports[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn plan(ports: Vec<u16>, interval: Duration) -> HopPlan {
        HopPlan {
            ports: ports.into(),
            interval,
        }
    }

    fn canonical() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 443)
    }

    #[test]
    fn an_empty_port_set_is_refused_rather_than_silently_pinned() {
        assert!(pick(&[]).is_err());
    }

    #[test]
    fn every_choice_comes_from_the_configured_set() {
        let ports = [20000_u16, 20001, 45000];
        for _ in 0..200 {
            assert!(ports.contains(&pick(&ports).unwrap()));
        }
    }

    #[tokio::test]
    async fn the_destination_port_moves_but_the_host_never_does() {
        let socket = PortHopSocket {
            inner: quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            plan: plan((30000..30064).collect(), Duration::from_millis(0)),
            canonical: canonical(),
            state: Mutex::new(HopState {
                port: 30000,
                next_hop: Instant::now(),
            }),
        };

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let destination = socket.destination();
            assert_eq!(
                destination.ip(),
                canonical().ip(),
                "hopping moves the port, never the host"
            );
            seen.insert(destination.port());
        }
        assert!(
            seen.len() > 1,
            "a zero dwell time must actually rotate, saw {seen:?}"
        );
    }

    #[tokio::test]
    async fn the_port_holds_still_for_the_dwell_time() {
        let socket = PortHopSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            plan((30000..30064).collect(), Duration::from_secs(3600)),
            canonical(),
        )
        .unwrap();

        let first = socket.destination();
        for _ in 0..64 {
            assert_eq!(
                socket.destination(),
                first,
                "a datagram must not pick a new port on every send"
            );
        }
    }
}
