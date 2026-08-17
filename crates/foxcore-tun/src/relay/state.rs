use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use foxcore_api::{BlockReason, CoreEvent, Destination, EventSink, IpTransport};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::PacketTunnelOutbound;
use foxcore_trafficmap::PacketAccounting;
use proto_wireguard::tunnel::{PacketOut, PeerTunnel};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::arena::PacketArena;
use crate::l3::{AddressTranslator, TranslationRefusal};
use crate::metrics::FlowMetrics;
use crate::split::FlowKey;

/// Largest datagram the socket will ever hand back. WireGuard adds 32 bytes to
/// the inner packet, so this covers any MTU a tun can have.
pub(crate) const MAX_DATAGRAM: usize = 65_535;

/// How much of a chunk one decrypted packet is sized against.
///
/// The inner packet is bounded by the tun's MTU, which the relay is never told —
/// it only ever sees sealed datagrams. Two kilobytes covers every MTU a tun on
/// a phone is configured with and leaves room above the 1500 an Ethernet-sized
/// one uses, at 16 KiB of resident memory for the whole relay. It is a sizing
/// hint and not a limit: `copy_in` keeps every byte it is handed, so a larger
/// packet is carried whole and merely costs its own chunk.
pub(crate) const DECRYPTED_PACKET_HINT: usize = 2_048;

/// The decrypted packet, written straight into the buffer that goes to the tun.
///
/// `receive_datagram` used to fill a `Vec` the relay then handed on with
/// `mem::take`, which left that buffer at zero capacity so the next packet
/// allocated a new one — one allocation per packet, forever. Writing into the
/// arena instead is the same single copy the `Vec` was doing, with nothing
/// allocated around it.
pub(crate) struct ArenaPacket<'a> {
    arena: &'a mut PacketArena,
    packet: BytesMut,
}

impl<'a> ArenaPacket<'a> {
    pub(crate) fn new(arena: &'a mut PacketArena) -> Self {
        Self {
            arena,
            packet: BytesMut::new(),
        }
    }

    /// The packet, or an empty one if the datagram carried none. Only read after
    /// [`Received::Packet`], which is the case that wrote it.
    pub(crate) fn into_packet(self) -> BytesMut {
        self.packet
    }
}

impl PacketOut for ArenaPacket<'_> {
    fn put_packet(&mut self, packet: &[u8]) {
        self.packet = self.arena.copy_in(packet);
    }
}

/// Floor on the relay's sleep between timer passes.
///
/// This used to be the whole timer: a fixed one-second `interval`, on the
/// reasoning that it "costs nothing while idle". On a phone it costs the thing
/// that matters most — 86 400 wakeups a day, each one pulling the CPU out of
/// deep idle for a `tick` that almost always has nothing to do, against a
/// tunnel whose shortest real deadline is the 25-second keepalive. WireGuard is
/// silent by design when nothing is moving; the timer above it was not.
///
/// The relay now sleeps until [`proto_wireguard::tunnel::PeerTunnel::next_deadline_ms`]
/// says there is work. This value survives as the *floor* on that sleep, which
/// is what makes the change unable to regress: the relay can never wake more
/// often than the old tick did, whatever the state machine reports.
pub(crate) const TICK: Duration = Duration::from_secs(1);

/// Ceiling on the relay's sleep when no deadline is pending at all.
///
/// Reached only with no session, no handshake and no keepalive — a tunnel that
/// has never carried anything. `tick` is a no-op in that state and every event
/// that could change it (a packet, a datagram, a network change, cancellation)
/// is its own arm of the `select!`, so the sleep is a backstop rather than the
/// mechanism. `REKEY_AFTER_TIME` is the protocol's own longest interval, which
/// makes it the honest bound.
pub(crate) const MAX_IDLE_TICK: Duration =
    Duration::from_millis(proto_wireguard::tunnel::REKEY_AFTER_TIME_MS);

/// First retry delay for a socket rebind, and the base it doubles from.
///
/// A rebind is a resolve, a bind, a `protect()` and a connect. Retrying that
/// every second is what an offline phone used to do all night — 28 800 attempts
/// between putting it down and picking it up, every one of them certain to fail
/// while there is no route. Backing off is safe here precisely because the
/// retry is not how the outage ends: connectivity coming back is a network
/// signal, and that is its own arm of the `select!` which resets this to the
/// base the moment it fires.
pub(crate) const REBIND_BACKOFF_MIN: Duration = Duration::from_secs(1);

/// Ceiling on the rebind backoff. Long enough to matter overnight, short enough
/// that a network whose signal never arrives is still retried on its own.
pub(crate) const REBIND_BACKOFF_MAX: Duration = Duration::from_secs(60);

// This ladder doubles and is deliberately **not** jittered, unlike
// `foxcore_transport::backoff::ReconnectBackoff`. The two look alike and are
// not the same problem.
//
// A server reconnect is jittered for two reasons: a population that lost the
// same server would otherwise dial back in the same instant, and a fixed ladder
// is a timing fingerprint of the client. Neither applies here.
//
//   * This is a *local* socket rebind — resolve, `bind`, `protect`, `connect`.
//     A failed attempt with no route produces no traffic at the server, so
//     there is no herd to spread.
//   * The outage does not end by retrying. It ends when the platform reports a
//     network change, which is its own arm of the `select!` and resets this to
//     `REBIND_BACKOFF_MIN` at once. That signal arrives when each device's
//     radio reattaches, which is already unsynchronised across a population.
//     The retry ladder is only the fallback for a signal that never comes.
//
// And jitter would actively cost here. Decorrelated jitter draws
// `uniform(min, prev * 3)`, whose expected value sits well below the ceiling:
// with `min = 1s` and `max = 60s` a phone with no route all night would average
// roughly 30 s between attempts instead of the flat 60 s this ladder pins to —
// about twice the wakeups, in exactly the overnight-idle case the backoff was
// added to fix. Spreading a herd that does not exist, at the price of doubling
// the battery cost of the scenario that motivated the code, is the wrong trade.

/// How long the relay may send into silence before it says so.
///
/// Four `REKEY_TIMEOUT` windows. By then four whole handshake attempts have gone
/// out and not one authenticated byte has come back, which is no longer "the
/// peer is starting up" — it is a tunnel that is down. Shorter would report a
/// slow handshake; longer would let a dead tunnel run a battery flat while every
/// counter reads healthy, which is exactly what happened (D15).
/// Measured on a Pixel 7 Pro: at 4 x REKEY_TIMEOUT (20 s) this fires once per keepalive cycle on a
/// perfectly healthy tunnel — a `persistent_keepalive_s` of 25 is common and 25 > 20, so the app
/// painted a working tunnel as unresponsive 25-29 times per 15 minutes.
///
/// This is now the *floor* and the margin, not the whole window: see
/// [`peer_silence_window`], which adds the profile's own keepalive on top.
pub(crate) const PEER_SILENCE: Duration =
    Duration::from_millis(6 * proto_wireguard::tunnel::REKEY_TIMEOUT_MS);

/// How long this peer may go unheard before the relay calls it unresponsive.
///
/// [`PEER_SILENCE`] alone was the whole window, on the reasoning that 30 s
/// "clears the longest keepalive a profile can ask for". It does not — it clears
/// exactly the 25 s that was measured, and nothing above it. `PersistentKeepalive`
/// is a `u16` and providers do ship 45 and 60.
///
/// The arithmetic that matters: on an idle-but-healthy tunnel nothing crosses
/// except keepalives. We send one every `K` seconds; the peer answers with its
/// own about `KEEPALIVE_TIMEOUT` later (WireGuard §6.5), and in between the relay
/// has heard nothing at all. So the gap since the last authenticated datagram
/// reaches very nearly `K` once per cycle, with `sent_since_heard` set — which is
/// the exact condition the report fires on. At `K = 60` a fixed 30 s window
/// reports a working tunnel as unresponsive once a minute: the same D15 shape the
/// widening was meant to remove, moved up one keepalive interval.
///
/// So the window is one keepalive plus the margin. The cost is that a genuinely
/// dead tunnel on a 25 s profile is now named at 55 s rather than 30 s; the
/// report is a diagnosis and not a fail-closed action, and four handshake
/// attempts have still long since gone unanswered by then. A profile with no
/// keepalive is unchanged, because there is no cycle to clear.
pub(crate) fn peer_silence_window(keepalive_s: Option<u16>) -> Duration {
    PEER_SILENCE.saturating_add(Duration::from_secs(u64::from(keepalive_s.unwrap_or(0))))
}

/// Receive errors in a row before the relay stops trusting the socket.
///
/// A connected UDP socket reports the peer's ICMP errors on the receive side and
/// one of those is routine. A run of them is a socket on a network that no
/// longer routes — and it is also a spin, because tokio returns a non-
/// `WouldBlock` error without clearing the registration's readiness, so the
/// receive arm is ready again the instant the relay loops. Dropping the socket
/// after a bounded run turns an unbounded busy-loop into the outage it actually
/// is: fail-closed, counted, reported, and retried by the existing tick.
pub(crate) const MAX_RECEIVE_ERRORS: u32 = 8;

/// Everything needed to build another socket for the same peer.
///
/// Kept because the first socket is not the last one: a phone moving from Wi-Fi
/// to mobile leaves the relay holding a descriptor bound to an interface that
/// no longer routes, and the only repair is a new socket through the same
/// dialer — which is also what re-runs `protect()` and the bind to the new
/// Android `Network`.
pub(crate) struct PeerEndpoint {
    dialer: ProtectedDialer,
    host: String,
    port: u16,
    /// A pinned address from the profile. Present on the Android bootstrap
    /// path, where there is no route to a resolver yet, and it makes a rebind
    /// free: no lookup, just bind, protect and connect.
    pinned: Option<IpAddr>,
}

impl PeerEndpoint {
    pub(crate) fn of(outbound: &PacketTunnelOutbound) -> Self {
        let endpoint = outbound.endpoint();
        Self {
            dialer: outbound.dialer().clone(),
            host: endpoint.host.clone(),
            port: endpoint.port,
            pinned: endpoint.ip,
        }
    }

    /// Bind, protect and connect a socket for the network the dialer now names,
    /// returning it with the address it reached.
    ///
    /// `connect_udp` runs `protect()` and the bind to the current network handle
    /// *before* connecting and before any datagram crosses: a WireGuard socket
    /// that skipped that ordering is routed back into the tun the engine serves,
    /// and what looks like a rebind is a leak. The address comes back because a
    /// tun packet addressed to it is the relay's own output returning — sealing
    /// it would make the core amplify a routing loop (D15) — and after a rebind
    /// with an unpinned host it is not the address the profile named.
    pub(crate) async fn open(&self) -> io::Result<(UdpSocket, SocketAddr)> {
        match self.pinned {
            Some(ip) => {
                let address = SocketAddr::new(ip, self.port);
                Ok((self.dialer.connect_udp(address).await?, address))
            }
            None => {
                self.dialer
                    .connect_udp_server_with_address(&self.host, self.port, None)
                    .await
            }
        }
    }
}

/// One peer's data path: state machine, protected socket, address translation.
pub struct PacketTunnelRelay {
    pub(super) tunnel: PeerTunnel,
    pub(super) socket: UdpSocket,
    pub(super) endpoint: PeerEndpoint,
    /// Lets the packet path recognise its own output: a tun packet addressed
    /// here is a datagram this relay sent that the platform routed back in.
    pub(super) peer: SocketAddr,
    /// Bumped by the runtime on every network change it may act on. A watch,
    /// not a callback: the rebind must happen on the relay's own task —
    /// rebinding from the caller's thread would `.await` inside a JNI upcall,
    /// and no second owner can swap the socket under a live `select!`.
    pub(crate) network: watch::Receiver<u64>,
    /// Keeps `network` from seeing a dropped sender: a closed watch resolves
    /// `changed()` immediately and spins the relay loop.
    pub(crate) network_keepalive: Option<watch::Sender<u64>>,
    pub(super) translator: AddressTranslator,
    pub(super) started: Instant,
    /// L3 traffic never touches the userspace stack, so nothing else counts it.
    /// Without this a live tunnel reports zero bytes and the app draws it idle.
    pub(super) metrics: Arc<FlowMetrics>,
    /// Per-flow attribution for the same bytes — which the platform cannot
    /// answer while the VPN is up (D4).
    pub(crate) accounting: Arc<PacketAccounting>,
    /// Where a refused packet is reported, once per cause: the condition is
    /// static until the config changes, and per-packet records would bury it.
    pub(crate) events: EventSink,
}

/// How often the routing loop is allowed to say so again.
///
/// The first version of this said it once and never again, which is a report
/// about the moment the condition started rather than about the condition. On
/// device the two are not the same thing: the loop outlived a move to mobile
/// and a move back to Wi-Fi, `tunnel_routing_loops` reached 44, and the
/// application — which reads the event stream, not the counters — drained
/// nothing at all for the whole device scenario. A screen that opens
/// after the first packet, an app that starts draining later, a reconciliation
/// against a rising counter: all three see silence, and silence here reads as
/// "not happening".
///
/// A minute, and the flood argument still holds by four orders of magnitude:
/// the condition the ceiling exists for moved ~17 MB/s, tens of thousands of
/// packets per second, and this permits one record.
const LOOP_REPORT_INTERVAL_MS: u64 = 60_000;

/// Reports an untranslatable packet the first time each cause appears.
#[derive(Default)]
pub(crate) struct RefusalReporter {
    mismatch: std::sync::atomic::AtomicBool,
    unmapped: std::sync::atomic::AtomicBool,
    /// The relay-clock millisecond at which the routing loop may be reported
    /// again. Zero — the default — is "now", so the first looped packet always
    /// produces a record.
    loop_report_after_ms: std::sync::atomic::AtomicU64,
}

impl RefusalReporter {
    pub(crate) fn report(&self, events: &EventSink, refusal: TranslationRefusal, packet: &[u8]) {
        let (reason, seen) = match refusal {
            TranslationRefusal::ForeignAddress => {
                (BlockReason::TunnelAddressMismatch, &self.mismatch)
            }
            TranslationRefusal::NoMappingForFamily => {
                (BlockReason::TunnelFamilyUnmapped, &self.unmapped)
            }
            // A packet the tun should never have produced. Not a configuration
            // problem, and not worth a record per occurrence.
            TranslationRefusal::Malformed => return,
        };
        if seen.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let (transport, destination) = match FlowKey::from_packet(packet) {
            Some(key) => (
                if key.protocol == 17 {
                    IpTransport::Udp
                } else {
                    IpTransport::Tcp
                },
                Destination::new(key.destination.to_string(), key.destination_port),
            ),
            None => (IpTransport::Tcp, Destination::new("", 0)),
        };
        events.emit_with(|| CoreEvent::Blocked {
            reason,
            transport,
            destination,
            uid: None,
            package: None,
        });
    }

    /// Report the tunnel's own output arriving back on the tun.
    ///
    /// Rate-limited rather than latched, unlike the two above. Those name a
    /// *configuration* — the tun carries an address this peer cannot, and that
    /// is true from start to stop — so one record says all there is. This one
    /// names a platform state that comes and goes with the socket underneath
    /// it, and while it holds it is a packet flood: a record per occurrence
    /// would be a second denial of service, and a record per generation is a
    /// report nobody who looked afterwards could see: device acceptance saw
    /// the counter reach 44 while `nativeDrainEvents` returned nothing.
    pub(crate) fn report_loop(&self, events: &EventSink, peer: SocketAddr, now_ms: u64) {
        // Relaxed and read-then-write without a compare: the only caller is the
        // relay's own loop, on one task.
        let after = self
            .loop_report_after_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if now_ms < after {
            return;
        }
        self.loop_report_after_ms.store(
            now_ms.saturating_add(LOOP_REPORT_INTERVAL_MS),
            std::sync::atomic::Ordering::Relaxed,
        );
        events.emit_with(|| CoreEvent::Blocked {
            reason: BlockReason::TunnelRoutingLoop,
            transport: IpTransport::Udp,
            destination: Destination::new(peer.ip().to_string(), peer.port()),
            uid: None,
            package: None,
        });
    }
}

/// Whether this IP packet is one of this relay's own datagrams, routed back into
/// the tun instead of out to the network.
///
/// Matched on the full UDP tuple half — address *and* port — rather than the
/// address alone, so a user reaching the VPN server on any other port is
/// untouched. Nothing else can produce this shape: the peer endpoint is where
/// only the relay's protected socket sends, and a packet arriving from the tun
/// for it has already been round-tripped through the platform's routing table.
pub(crate) fn is_own_datagram(packet: &[u8], peer: SocketAddr) -> bool {
    let Some(key) = FlowKey::from_packet(packet) else {
        return false;
    };
    key.protocol == 17 && key.destination == peer.ip() && key.destination_port == peer.port()
}
