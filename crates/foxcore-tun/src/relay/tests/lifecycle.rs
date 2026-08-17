use super::datapath::{establish, wait_for};
use super::*;
use crate::metrics::FlowMetrics;
use foxcore_api::{BlockReason, CoreEvent, EventSink};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The other trigger: a profile with no address of the tun's family at all
/// can translate nothing, so the engine refuses rather than dropping
/// everything.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_tunnel_with_no_common_address_family_refuses_to_start() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();

    let error = PacketTunnelRelay::connect(
        &outbound(endpoint),
        // The profile in `outbound()` assigns only IPv4.
        &[IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
        Arc::new(FlowMetrics::default()),
    )
    .await
    .err()
    .expect("a tunnel that can translate nothing must not start");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let message = error.to_string();
    assert!(
        message.contains("cannot") && message.contains("assigned"),
        "the error has to say what disagrees with what: {message}"
    );
}

/// D15, first half, reproduced without a device: a tunnel whose handshake
/// never completes billed the user for every packet it was handed.
///
/// `PeerTunnel::send_packet` returns `Ok` for a packet it merely *held* —
/// there is no session to seal it with — and for a packet it dropped out of
/// its own bounded queue to make room for a newer one. The relay read that
/// `Ok` as "carried" and added the packet's length to `bytes_up` at the same
/// line. On the device that produced ~84 MB every five seconds against
/// 479 bytes the operating system had actually sent, with `connected=true`,
/// `dial_errors=0`, `sock_err=0` and every other health counter at zero.
///
/// The peer here binds a socket and never answers it, which is exactly the
/// device's condition: the datagrams are accepted by the socket, the
/// handshake goes unanswered, and not one user packet can leave.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_tunnel_with_no_session_bills_nothing_and_says_what_it_dropped() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let metrics = Arc::new(FlowMetrics::default());
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("the relay should bind and connect its socket");

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, mut tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    // Comfortably more than the state machine may hold, so the queue has to
    // start dropping — which is the second silent loss on this path.
    let offered = proto_wireguard::tunnel::MAX_PENDING_PACKETS * 3;
    for _ in 0..offered {
        to_relay.send(ip_packet(TUN_V4, REMOTE_V4)).await.unwrap();
    }
    wait_for(&metrics, |snapshot| {
        snapshot.tunnel_queue_dropped as usize
            >= offered - proto_wireguard::tunnel::MAX_PENDING_PACKETS
    })
    .await;

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.bytes_up, 0,
        "not one packet was sealed, so not one byte may be billed: the peer \
             never answered the handshake"
    );
    assert_eq!(
        snapshot.tunnel_queue_dropped as usize,
        offered - proto_wireguard::tunnel::MAX_PENDING_PACKETS,
        "every packet the bounded queue threw away has to be counted, not \
             dropped in silence"
    );
    assert_eq!(
        snapshot.tunnel_socket_errors, 0,
        "the socket accepted everything it was given"
    );
    assert!(tun_inbox.try_recv().is_err());

    cancel.cancel();
    let _ = task.await;
}

/// The other half of the same claim: once the session is up, the counter has
/// to move again — and by the inner packet's length, not the datagram's.
///
/// Without this the fix above could be "never count anything", which would
/// draw a working tunnel as idle (D4, also found on device).
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_session_that_comes_up_bills_the_packet_and_not_the_wireguard_framing() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let metrics = Arc::new(FlowMetrics::default());
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("the relay should bind and connect its socket");

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, _tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    let mut buffer = [0_u8; 2048];
    let (_session, _client) = establish(&peer, &to_relay, &mut buffer).await;
    let packet = ip_packet(TUN_V4, REMOTE_V4);
    wait_for(&metrics, |snapshot| {
        snapshot.bytes_up >= packet.len() as u64
    })
    .await;

    assert_eq!(
        metrics.snapshot().bytes_up,
        packet.len() as u64,
        "the held packet is billed exactly once, at its own length: the 32 \
             bytes WireGuard adds are framing the user did not send"
    );

    cancel.cancel();
    let _ = task.await;
}

/// D15, second half: the tunnel's own datagram arriving back on the tun.
///
/// This is the only mechanism consistent with what the device showed — a
/// core at 103%, `bytes_up` climbing by ~17 MB/s, and the operating system
/// reporting 8 packets sent. A WireGuard socket that `protect()` did not
/// take out of the tun it is serving has its datagrams routed straight back
/// in; the relay used to translate them, seal them and send them round
/// again, so one packet became an unbounded stream that never left the
/// device and every lap was billed to the user.
///
/// Nothing about it was visible: the source is the tun's own address, so the
/// translator accepts it; the socket accepts every send, so `sock_err` stays
/// zero; and no counter on the path counts laps.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn the_tunnels_own_datagram_coming_back_on_the_tun_is_refused_and_named() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("the relay should bind and connect its socket")
            .with_events(sink);

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, _tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    let mut buffer = [0_u8; 2048];
    let (mut session, _client) = establish(&peer, &to_relay, &mut buffer).await;
    let established = metrics.snapshot().bytes_up;

    // What the platform hands back when the peer socket was not taken out of
    // the tun: a UDP packet from the tun's own address to the peer endpoint.
    let mut looped = ip_packet(TUN_V4, endpoint.ip().to_string().parse().unwrap());
    looped[22..24].copy_from_slice(&endpoint.port().to_be_bytes());
    for _ in 0..4 {
        to_relay.send(looped.clone()).await.unwrap();
    }
    wait_for(&metrics, |snapshot| snapshot.tunnel_routing_loops >= 4).await;

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.tunnel_routing_loops, 4,
        "a datagram addressed to our own peer endpoint is our output coming \
             back, and every lap has to be counted"
    );
    assert_eq!(
        snapshot.bytes_up, established,
        "and not one lap may be billed to the user: this traffic never \
             reaches the network at all"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buffer))
            .await
            .is_err(),
        "sealing it would send it round again, which is the amplifier"
    );
    // The session is untouched: a routing loop is not a reason to rekey.
    to_relay.send(ip_packet(TUN_V4, REMOTE_V4)).await.unwrap();
    let (len, _) = recv(&peer, &mut buffer).await;
    assert!(session.open(&mut buffer[..len]).is_ok());

    let events = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        events.len(),
        1,
        "the condition is a packet flood, so a record per packet would be a \
             second denial of service: {events:?}"
    );
    assert!(
        matches!(
            &events[0],
            CoreEvent::Blocked {
                reason: BlockReason::TunnelRoutingLoop,
                ..
            }
        ),
        "the reason has to name the loop, not just say 'blocked': {events:?}"
    );

    cancel.cancel();
    let _ = task.await;
}

/// The other half of that ceiling: a loop that is still happening has to
/// still be sayable.
///
/// Reported once per generation, the record is about the moment the
/// condition started rather than about the condition, and every consumer
/// that arrives afterwards sees an empty stream. On device that is exactly
/// what happened — the loop survived Wi-Fi → mobile → Wi-Fi,
/// `tunnel_routing_loops` reached 44, and `nativeDrainEvents` returned
/// `EVENTS count=0` for the whole device scenario. An
/// application that reads events and not counters could not learn the
/// cause at any point after the first packet.
///
/// The clock is tokio's, so the window passes without the test waiting a
/// minute for it.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(start_paused = true)]
async fn a_loop_that_is_still_happening_is_still_reported() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("the relay should bind and connect its socket")
            .with_events(sink);

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, _tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    let mut looped = ip_packet(TUN_V4, endpoint.ip().to_string().parse().unwrap());
    looped[22..24].copy_from_slice(&endpoint.port().to_be_bytes());

    to_relay.send(looped.clone()).await.unwrap();
    wait_for(&metrics, |snapshot| snapshot.tunnel_routing_loops >= 1).await;
    let count = |recorded: &Arc<std::sync::Mutex<Vec<CoreEvent>>>| {
        recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    };
    assert_eq!(count(&recorded), 1, "the first packet always says so");

    // Still inside the window: the flood ceiling holds.
    tokio::time::sleep(Duration::from_secs(30)).await;
    to_relay.send(looped.clone()).await.unwrap();
    wait_for(&metrics, |snapshot| snapshot.tunnel_routing_loops >= 2).await;
    assert_eq!(
        count(&recorded),
        1,
        "a record per packet is what the ceiling exists to prevent"
    );

    // Past it: the condition is still true, and an application that started
    // listening a minute ago has a right to hear it.
    tokio::time::sleep(Duration::from_secs(31)).await;
    to_relay.send(looped.clone()).await.unwrap();
    wait_for(&metrics, |snapshot| snapshot.tunnel_routing_loops >= 3).await;
    let events = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        events.len(),
        2,
        "a loop that outlived two network changes reported itself once, and \
             the app drained nothing: {events:?}"
    );
    assert!(
        events.iter().all(|event| matches!(
            event,
            CoreEvent::Blocked {
                reason: BlockReason::TunnelRoutingLoop,
                ..
            }
        )),
        "{events:?}"
    );

    cancel.cancel();
    let _ = task.await;
}

/// D15, third part: a tunnel that has been sending and has heard nothing
/// back has to say so.
///
/// Four handshake attempts left this relay and not one authenticated byte
/// came back. Every counter that exists says the tunnel is healthy —
/// `connected`, `dial_errors`, `sock_err`, `rebind_fail`, `offline_pkts`,
/// `untrans_up` were all zero on the device while exactly this held — and
/// the app drew a working tunnel. The peer state machine already knows: the
/// handshake is never answered and the keepalive never returns.
///
/// The clock is tokio's, so four `REKEY_TIMEOUT` windows pass in a paused
/// runtime rather than in twenty seconds of test time.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(start_paused = true)]
async fn a_peer_that_answers_nothing_while_we_send_is_reported_not_drawn_as_healthy() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("the relay should bind and connect its socket")
            .with_events(sink);

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, _tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    // One packet is enough to start the handshake; the peer never answers.
    to_relay.send(ip_packet(TUN_V4, REMOTE_V4)).await.unwrap();
    // Derived from the constant rather than hardcoded: PEER_SILENCE has to clear the longest
    // keepalive a profile can ask for, so pinning a literal here made the window untunable.
    tokio::time::sleep(crate::relay::state::PEER_SILENCE + Duration::from_secs(5)).await;

    assert_eq!(
        metrics.snapshot().tunnel_peer_silences,
        1,
        "a tunnel sending into silence past PEER_SILENCE is down, \
             and reporting it once is the difference between a diagnosis and a \
             screen that says everything is fine"
    );
    let events = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        events.iter().any(|event| matches!(
            event,
            CoreEvent::Blocked {
                reason: BlockReason::TunnelPeerUnresponsive,
                ..
            }
        )),
        "and it has to be named, not left to a counter nobody polls: {events:?}"
    );

    cancel.cancel();
    let _ = task.await;
}

/// The window the report above measures against has to clear the profile's own
/// keepalive, because an idle-but-healthy tunnel is unheard for exactly one
/// keepalive interval at a time.
///
/// The fixed 30 s constant cleared the 25 s that was measured on device and
/// nothing above it. `PersistentKeepalive` is a `u16`; providers ship 45 and 60,
/// and at 60 the relay reported a working tunnel as unresponsive once a minute —
/// the same shape the constant was widened to remove, one keepalive up.
#[test]
fn the_silence_window_clears_the_profiles_own_keepalive() {
    use crate::relay::state::{PEER_SILENCE, peer_silence_window};

    // No keepalive is no cycle to clear, so the floor stands unchanged. This is
    // the shape every test above runs with.
    assert_eq!(peer_silence_window(None), PEER_SILENCE);
    assert_eq!(peer_silence_window(Some(0)), PEER_SILENCE);

    for keepalive in [10_u16, 25, 45, 60, 300, u16::MAX] {
        assert!(
            peer_silence_window(Some(keepalive)) > Duration::from_secs(u64::from(keepalive)),
            "a healthy tunnel with a {keepalive} s keepalive must not be called unresponsive"
        );
    }
}
