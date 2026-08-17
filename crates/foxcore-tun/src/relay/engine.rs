use super::*;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use foxcore_api::{BlockReason, CoreEvent, Destination, EventSink, IpTransport};
use foxcore_outbound::PacketTunnelOutbound;
use foxcore_trafficmap::{PacketAccounting, PacketKey};
use proto_wireguard::tunnel::{OsEntropy, PeerTunnel, Queued, Received};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::arena::PacketArena;
use crate::l3::AddressTranslator;
use crate::metrics::FlowMetrics;
use crate::split::FlowKey;

impl PacketTunnelRelay {
    /// Bind and connect the protected socket for this peer.
    ///
    /// `tun_addresses` are the addresses the Kotlin side put on the tun; they
    /// are paired by family with the addresses the peer assigned.
    pub async fn connect(
        outbound: &PacketTunnelOutbound,
        tun_addresses: &[IpAddr],
        metrics: Arc<FlowMetrics>,
    ) -> io::Result<Self> {
        // Before the socket. Every address family the tun advertises must have
        // somewhere to go, not merely one of them.
        //
        // The weaker check — "at least one family maps" — is what let D10 live:
        // a v4-only profile on a dual-stack tun passes it, carries v4 correctly,
        // and black-holes every v6 packet. That reads as a working tunnel right
        // up until an application uses it, because happy-eyeballs tries v6
        // first: the DNS lookup goes out over v4 and is answered by the
        // interceptor, the SYN goes out over v6 and disappears. Meanwhile
        // Android has been talking ICMPv6 to nobody since the interface came up.
        //
        // The app decides which way to resolve it — stop advertising the family,
        // or use a profile that carries it — but it has to be told, and a
        // refusal at start is the only way to say so before traffic is lost.
        let pairs = address_pairs(outbound, tun_addresses);
        let translator = AddressTranslator::new(pairs.clone());
        let unmapped: Vec<String> = tun_addresses
            .iter()
            .filter(|tun| !pairs.iter().any(|(mapped, _)| mapped == *tun))
            .map(ToString::to_string)
            .collect();
        if !unmapped.is_empty() {
            let assigned: Vec<String> = outbound
                .interface()
                .iter()
                .map(|network| network.addr().to_string())
                .collect();
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the tun carries [{}] that this packet tunnel cannot: the peer \
                     assigned [{}]. Remove the unmapped address from the tun config, \
                     or use a profile that carries that family — advertising it and \
                     dropping its packets looks like a working tunnel with no internet",
                    unmapped.join(", "),
                    assigned.join(", ")
                ),
            ));
        }
        let endpoint = PeerEndpoint::of(outbound);
        let (socket, peer) = endpoint.open().await?;
        let tunnel = PeerTunnel::new(outbound.settings().clone(), Box::new(OsEntropy))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let (keepalive, network) = watch::channel(0);
        Ok(Self {
            tunnel,
            socket,
            endpoint,
            peer,
            network,
            network_keepalive: Some(keepalive),
            translator,
            started: Instant::now(),
            metrics,
            accounting: Arc::new(PacketAccounting::default()),
            events: EventSink::none(),
        })
    }

    /// Report untranslatable packets to the engine's audit stream.
    pub fn with_events(mut self, events: EventSink) -> Self {
        self.events = events;
        self
    }

    /// Rebind the peer socket whenever this counter moves.
    ///
    /// Separate from [`PacketTunnelRelay::connect`] because the signal belongs
    /// to the runtime, not to the profile: it is the same event that rebinds
    /// the proxy dialer, and a harness exercising only the wire behaviour has
    /// no network to change.
    pub fn with_network_signal(mut self, network: watch::Receiver<u64>) -> Self {
        self.network = network;
        self.network_keepalive = None;
        self
    }

    /// Attribute this peer's packets to the flows the split registered.
    ///
    /// Separate from [`PacketTunnelRelay::connect`] so a harness that only
    /// wants the wire behaviour does not have to build a traffic map.
    pub fn with_accounting(mut self, accounting: Arc<PacketAccounting>) -> Self {
        self.accounting = accounting;
        self
    }

    /// Drive the peer until cancelled. `from_tun` carries IP packets the tun
    /// read, `to_tun` the decrypted packets to write back.
    pub async fn run(
        self,
        mut from_tun: mpsc::Receiver<BytesMut>,
        to_tun: mpsc::Sender<BytesMut>,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        // Destructured so the socket and the state machine can be borrowed
        // independently inside `select!`.
        let Self {
            mut tunnel,
            socket,
            endpoint,
            mut peer,
            mut network,
            network_keepalive,
            translator,
            started,
            metrics,
            accounting,
            events,
        } = self;
        let _network_keepalive = network_keepalive;
        let refusals = RefusalReporter::default();
        let mut inbound = vec![0_u8; MAX_DATAGRAM];
        let mut decrypted_arena = PacketArena::new(DECRYPTED_PACKET_HINT);
        // How long the relay may sleep before its next timer pass. Recomputed
        // at the top of every iteration from what the state machine actually
        // has pending, rather than a fixed tick — see `TICK`.
        let mut rebind_backoff = REBIND_BACKOFF_MIN;
        // Pinned outside the loop, and reset rather than recreated, because the
        // timer has to stay *armed* while another arm is being served. A
        // `sleep` built inside the `select!` is dropped the moment any other
        // branch wins, which leaves the relay with no registered timer for as
        // long as that branch's body runs — the `Interval` this replaced kept
        // its registration across iterations, and the liveness deadline depends
        // on that being true.
        let timer = tokio::time::sleep(TICK);
        tokio::pin!(timer);
        // `None` is the fail-closed state: the network moved and no protected
        // socket could be built for the new one. Packets are dropped and
        // counted while it holds, and every tick retries.
        let mut socket = Some(socket);
        // Stops selecting on a watch whose sender is gone. Without this the
        // arm resolves immediately, forever, and the relay spins a core.
        let mut network_signalled = true;
        let mut offline_reported = false;
        // Consecutive errors from the peer socket. Bounded rather than ignored:
        // see `MAX_RECEIVE_ERRORS`.
        let mut receive_errors = 0_u32;
        // The liveness question, kept as two facts rather than one: when the
        // peer last authenticated something, and whether anything of ours has
        // left the socket since. Both are needed — a tunnel nobody is using is
        // silent and healthy, and a tunnel that has been sending into silence
        // for four handshake windows is neither.
        let mut heard_ms = 0_u64;
        let mut sent_since_heard = false;
        let mut silence_reported = false;
        // Derived from the profile, not a constant: an idle-but-healthy tunnel
        // is unheard for one keepalive interval at a time. See
        // `peer_silence_window`.
        let peer_silence = peer_silence_window(tunnel.persistent_keepalive_s());

        loop {
            // The three things that can want a timer, resolved to one sleep.
            //
            // Anything else that could change the tunnel's state — a packet, a
            // datagram, a network change, cancellation — is its own arm below
            // and wakes the loop on its own, so nothing here has to be polled
            // for. Clamped into `TICK..=MAX_IDLE_TICK`: the floor is what makes
            // this unable to wake more often than the fixed tick it replaces,
            // and it also keeps a deadline that is already past from spinning.
            let now = elapsed_ms(started);
            let mut wake = tunnel
                .next_deadline_ms()
                .map(|deadline| deadline.saturating_sub(now))
                .unwrap_or(MAX_IDLE_TICK.as_millis() as u64);
            if socket.is_none() {
                wake = wake.min(rebind_backoff.as_millis() as u64);
            }
            // The silence window is measured from the last thing the peer
            // authenticated, and `heard_ms` starts at zero — so the deadline
            // exists from the moment the relay does, and not only once
            // something has gone out. Arming it on `sent_since_heard` instead
            // made the report's timing depend on when the loop happened to
            // wake next, which is exactly the property D15 needs it not to
            // have. `sent_since_heard` still decides whether it is *reported*;
            // it has no business deciding whether the relay is awake to ask.
            // Only while it is still ahead. A stale deadline is not a deadline:
            // once the window has passed, either this pass reports (the tick
            // arm below asks) or nothing ever will, because `sent_since_heard`
            // is false and only traffic can set it. Clamping on it regardless
            // pinned `wake` at the `TICK` floor for the rest of the tunnel's
            // life on the one profile with no keepalive to move `heard_ms` —
            // 1 Hz forever, which is the exact cost this loop was rewritten to
            // remove, reintroduced on the quietest path there is.
            let silence_due = heard_ms.saturating_add(peer_silence.as_millis() as u64);
            if !silence_reported && silence_due > now {
                wake = wake.min(silence_due.saturating_sub(now));
            }
            let wake = Duration::from_millis(wake).clamp(TICK, MAX_IDLE_TICK);
            timer.as_mut().reset(Instant::now() + wake);

            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                changed = network.changed(), if network_signalled => {
                    if changed.is_err() {
                        network_signalled = false;
                        continue;
                    }
                    // Dropped before the replacement is built, not after. The
                    // old descriptor is bound to an interface that no longer
                    // routes; keeping it as a fallback is exactly the bug —
                    // it accepts every send and delivers nothing, which is
                    // indistinguishable from a working tunnel from inside.
                    socket = None;
                    // A different network is a fresh reason to try at once:
                    // whatever the backoff had grown to was earned against the
                    // network that just went away. This is what keeps the
                    // backoff from ever delaying a recovery.
                    rebind_backoff = REBIND_BACKOFF_MIN;
                    // Cancellation is polled *during* the rebind, not only
                    // between them. `rebind` resolves the peer under
                    // `connect_timeout_ms`, which defaults to 10 s — more than
                    // three times the whole stop budget. With a hostname peer
                    // and no route (aeroplane mode is the ordinary case), a
                    // stop issued mid-resolve waited out the resolver, and the
                    // failure then looked identical to "the loop never saw
                    // cancellation" when in fact it never asked.
                    let rebound = tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        rebound = rebind(&endpoint, &mut tunnel, started, &metrics) => rebound,
                    };
                    match rebound {
                        Some((fresh, address)) => {
                            socket = Some(fresh);
                            peer = address;
                            offline_reported = false;
                            receive_errors = 0;
                            sent_since_heard |=
                                flush(&mut tunnel, socket.as_ref(), &metrics).await;
                        }
                        None => report_offline(&events, &mut offline_reported),
                    }
                }
                packet = from_tun.recv() => {
                    let Some(mut packet) = packet else { return Ok(()) };
                    // Before anything else, because this one is not the user's
                    // traffic at all: a datagram addressed to our own peer
                    // endpoint is something this relay already sent, which the
                    // platform routed back into the tun instead of out to the
                    // network. Sealing it adds a WireGuard header and sends it
                    // round again — one packet becomes an unbounded stream that
                    // never leaves the device, costs a whole core, and bills the
                    // user for every lap (D15: ~2.9 GB counted against 479 bytes
                    // the OS had actually sent). The core cannot repair a
                    // `protect()` that did not take; it can refuse to be the
                    // amplifier and name what it refused.
                    if is_own_datagram(&packet, peer) {
                        metrics.tunnel_routing_loop();
                        refusals.report_loop(&events, peer, elapsed_ms(started));
                        continue;
                    }
                    // A packet the translator refuses is not this tunnel's
                    // traffic. Dropping it is the whole point: forwarding it
                    // untranslated would put the tun's address on the wire.
                    // Saying so is the other half — this used to be the one
                    // place in the L3 path where a user's packet vanished with
                    // no counter, no event and no log (D10).
                    if let Err(refusal) = translator.to_tunnel_checked(&mut packet) {
                        metrics.tunnel_untranslated_up();
                        refusals.report(&events, refusal, &packet);
                        continue;
                    }
                    // Fail-closed while the tunnel has no socket. Sealing this
                    // into the state machine's queue instead would hide the
                    // outage: the counters would say the packet was carried and
                    // it would sit in memory until a rebind that may never come.
                    if socket.is_none() {
                        metrics.tunnel_offline_packet();
                        report_offline(&events, &mut offline_reported);
                        continue;
                    }
                    // The next place a packet could vanish quietly. Refusing to
                    // seal is ordinary while a handshake is in flight — the
                    // peer has no session yet — but a count that never stops
                    // rising is a tunnel that will never carry anything, and
                    // that is indistinguishable from a working one without
                    // this.
                    //
                    // `Held` is *not* an error and not counted as one: the
                    // packet is waiting for a session that may well arrive. It
                    // is also not carried, which is why nothing is added to
                    // `bytes_up` here — that happens in `flush`, when the socket
                    // has accepted the datagram the packet ended up in. Counting
                    // at this line instead is what made a tunnel that sent 8
                    // packets report 2.9 GB (D15).
                    match tunnel.send_packet(&packet, elapsed_ms(started)) {
                        Err(_) => {
                            metrics.tunnel_unsealed();
                            continue;
                        }
                        // The oldest held packet was dropped to make room. The
                        // queue is bounded on purpose, but the drop used to be
                        // silent, which is the D10 shape.
                        Ok(Queued::HeldDisplacing) => metrics.tunnel_queue_dropped(),
                        Ok(Queued::Held | Queued::Sealed) => {}
                    }
                    sent_since_heard |= flush(&mut tunnel, socket.as_ref(), &metrics).await;
                }
                result = recv_from(socket.as_ref(), &mut inbound), if socket.is_some() => {
                    // A connected UDP socket surfaces ICMP port-unreachable as a
                    // receive error. That is routine while a peer is starting up
                    // and must never take the relay down.
                    //
                    // It must not be discarded either, which is what a bare
                    // `continue` here did. `async_io` returns anything that is
                    // not `WouldBlock` without clearing the registration's
                    // readiness, so this arm is ready again the instant the loop
                    // comes round: on a network that keeps producing errors the
                    // relay spun a whole core with `bytes_down` flat and every
                    // health counter at zero. A bounded run of them is treated
                    // as what it is — a socket on a network that no longer
                    // routes — and the tunnel is closed fail-closed until a
                    // rebind succeeds.
                    let length = match result {
                        Ok(length) => {
                            receive_errors = 0;
                            length
                        }
                        Err(_) => {
                            metrics.tunnel_receive_error();
                            receive_errors = receive_errors.saturating_add(1);
                            if receive_errors >= MAX_RECEIVE_ERRORS {
                                receive_errors = 0;
                                socket = None;
                                report_offline(&events, &mut offline_reported);
                            }
                            continue;
                        }
                    };
                    let mut received = ArenaPacket::new(&mut decrypted_arena);
                    match tunnel.receive_datagram(&mut inbound[..length], elapsed_ms(started), &mut received) {
                        Ok(Received::Packet) => {
                            let mut decrypted = received.into_packet();
                            if let Err(refusal) = translator.to_tun_checked(&mut decrypted) {
                                metrics.tunnel_untranslated_down();
                                refusals.report(&events, refusal, &decrypted);
                            } else {
                                metrics.add_down(decrypted.len() as u64);
                                // The tuple is read after translation, so it is
                                // the tun-side one the split bound the flow to.
                                if let Some(key) = FlowKey::from_packet(&decrypted) {
                                    accounting
                                        .count_down(&PacketKey::from(key), decrypted.len() as u64);
                                }
                                if to_tun.send(decrypted).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        // Keepalives and handshake messages carry nothing for the
                        // tun; forged or stale datagrams are dropped in silence.
                        Ok(Received::None) => {}
                        Err(_) => {
                            // Not proof of life: a forged, replayed or junk
                            // datagram is exactly what an unresponsive peer's
                            // network is full of, and treating it as an answer
                            // would let anything on the path silence the
                            // liveness report below.
                            //
                            // But what the flush puts on the wire still counts.
                            // Dropping this return value was the one asymmetry
                            // in the silence bookkeeping: a datagram that fails
                            // to decrypt can still push a retry out — the tunnel
                            // may be mid-handshake — and the report below only
                            // fires once something has gone out since the peer
                            // was last heard. So a tunnel whose entire inbound
                            // stream was undecryptable sent into silence without
                            // ever being able to say so.
                            sent_since_heard |=
                                flush(&mut tunnel, socket.as_ref(), &metrics).await;
                            continue;
                        }
                    }
                    // Authenticated. Whatever it carried, the peer is there, so
                    // the silence clock restarts from here — including anything
                    // the reply itself puts on the wire.
                    heard_ms = elapsed_ms(started);
                    silence_reported = false;
                    sent_since_heard = flush(&mut tunnel, socket.as_ref(), &metrics).await;
                }
                _ = timer.as_mut() => {
                    // The retry, on a backoff rather than every second. A
                    // rebind that failed because the new interface was not up
                    // yet is retried a second later; one that keeps failing
                    // because there is no network at all doubles out to
                    // `REBIND_BACKOFF_MAX`, because repeating a resolve and a
                    // bind every second against no route all night is pure
                    // battery. The network-change arm above resets it, so
                    // connectivity returning is still acted on at once.
                    let retried = if socket.is_none() {
                        // Same reason as the network-change branch above.
                        tokio::select! {
                            _ = cancel.cancelled() => return Ok(()),
                            rebound = rebind(&endpoint, &mut tunnel, started, &metrics) => rebound,
                        }
                    } else {
                        None
                    };
                    if let Some((fresh, address)) = retried {
                        socket = Some(fresh);
                        peer = address;
                        offline_reported = false;
                        rebind_backoff = REBIND_BACKOFF_MIN;
                    } else if socket.is_none() {
                        rebind_backoff =
                            (rebind_backoff * 2).min(REBIND_BACKOFF_MAX);
                    }
                    let _ = tunnel.tick(elapsed_ms(started));
                    sent_since_heard |= flush(&mut tunnel, socket.as_ref(), &metrics).await;
                    // The signal the whole class was missing. Handshakes,
                    // keepalives and rekeys all go out through the line above,
                    // so a tunnel that is producing them and hearing nothing
                    // back is a tunnel that is down — and every other counter on
                    // this path reads healthy while it happens, which is what
                    // made a whole device window inconclusive (D15). Reported
                    // once per silent stretch, and cleared the moment the peer
                    // authenticates anything.
                    if sent_since_heard
                        && !silence_reported
                        && elapsed_ms(started).saturating_sub(heard_ms)
                            >= peer_silence.as_millis() as u64
                    {
                        silence_reported = true;
                        metrics.tunnel_peer_silent();
                        events.emit_with(|| CoreEvent::Blocked {
                            reason: BlockReason::TunnelPeerUnresponsive,
                            transport: IpTransport::Udp,
                            destination: Destination::new(peer.ip().to_string(), peer.port()),
                            uid: None,
                            package: None,
                        });
                    }
                }
            }
        }
    }
}

/// Hand every datagram the state machine produced to the socket.
///
/// Send errors do not propagate — WireGuard is built to lose datagrams and the
/// retry timers already cover an unreachable peer — but they are counted. A
/// socket that refuses every send looks exactly like a peer that never answers,
/// and the difference is the whole diagnosis.
///
/// With no socket the queue is drained into the counter rather than held: the
/// datagrams were sealed for a network that is gone, and keeping them would
/// grow without bound while the tunnel is closed.
///
/// This is also the only place a byte may be counted as sent. `bytes_up` used to
/// be written where the state machine *accepted* a packet, which is a different
/// event: without a session that packet is only held, and on a network that
/// carries nothing it is then dropped out of the queue to make room for the
/// next. The counter claimed ~2.9 GB against the 479 bytes the operating system
/// had actually sent (D15). What is counted here is the inner packet the
/// datagram carries — not the datagram, whose extra 32 bytes are framing the
/// user never sent — and only after the socket accepted it.
///
/// Returns whether anything left, which is what makes "sending into silence"
/// distinguishable from "idle".
async fn flush(tunnel: &mut PeerTunnel, socket: Option<&UdpSocket>, metrics: &FlowMetrics) -> bool {
    let mut datagram = Vec::new();
    let mut sent = false;
    while let Some(payload) = tunnel.poll_transmit(&mut datagram) {
        match socket {
            Some(socket) if socket.send(&datagram).await.is_ok() => {
                sent = true;
                if payload > 0 {
                    metrics.add_up(payload as u64);
                }
            }
            _ => metrics.tunnel_socket_error(),
        }
    }
    sent
}

/// Wait for a datagram, or never, when there is no socket to wait on.
///
/// The `if socket.is_some()` guard on the `select!` arm already stops this
/// being polled while closed; the `pending` branch is what makes the type work
/// out, and it is unreachable in practice.
async fn recv_from(socket: Option<&UdpSocket>, buffer: &mut [u8]) -> io::Result<usize> {
    match socket {
        Some(socket) => socket.recv(buffer).await,
        None => std::future::pending().await,
    }
}

/// Build a socket for the network the dialer now names and tell the peer about
/// it.
///
/// Returns `None` when no protected socket could be made, which leaves the
/// relay closed. That is the required trade: `connect_udp` is where `protect()`
/// and the bind to the Android `Network` happen, so a socket this function
/// declined to produce is a socket that would have carried the user's packets
/// outside the tunnel.
///
/// The peer session is not touched. WireGuard sets a peer's endpoint from the
/// source address of the last authenticated datagram, so the keys, the nonces
/// and the byte counters all survive the move — roaming is a protocol feature,
/// not a reconnect — and the announcement below is what makes the peer start
/// using the new address for the downstream direction.
async fn rebind(
    endpoint: &PeerEndpoint,
    tunnel: &mut PeerTunnel,
    started: Instant,
    metrics: &FlowMetrics,
) -> Option<(UdpSocket, SocketAddr)> {
    let Ok((socket, address)) = endpoint.open().await else {
        metrics.tunnel_rebind_failure();
        return None;
    };
    metrics.tunnel_rebind();
    let _ = tunnel.announce_endpoint(elapsed_ms(started));
    Some((socket, address))
}

/// Say the tunnel is closed, once per outage.
///
/// The condition is static until a rebind succeeds, and a record per dropped
/// packet would bury it — the same reason [`RefusalReporter`] reports each
/// translation cause once.
fn report_offline(events: &EventSink, reported: &mut bool) {
    if std::mem::replace(reported, true) {
        return;
    }
    events.emit_with(|| CoreEvent::Blocked {
        reason: BlockReason::TunnelSocketUnavailable,
        transport: IpTransport::Udp,
        destination: Destination::new("", 0),
        uid: None,
        package: None,
    });
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Pair each tun address with the tunnel address of the same family.
fn address_pairs(
    outbound: &PacketTunnelOutbound,
    tun_addresses: &[IpAddr],
) -> Vec<(IpAddr, IpAddr)> {
    tun_addresses
        .iter()
        .filter_map(|tun| {
            outbound
                .interface()
                .iter()
                .map(|network| network.addr())
                .find(|assigned| assigned.is_ipv4() == tun.is_ipv4())
                .map(|assigned| (*tun, assigned))
        })
        .collect()
}
