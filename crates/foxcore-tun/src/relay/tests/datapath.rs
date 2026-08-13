use super::*;
use crate::metrics::FlowMetrics;
use bytes::BytesMut;
use foxcore_api::{BlockReason, CoreEvent, EventSink};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_tun_packet_reaches_the_peer_sealed_and_translated_and_the_reply_comes_back() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();

    let metrics = Arc::new(FlowMetrics::default());
    // The row the split would have opened for this flow. Without it the
    // tunnel's bytes exist only as a global total and no screen can say
    // which app is using the tunnel (D4).
    let map = Arc::new(foxcore_trafficmap::TrafficMap::default());
    let uplink_key =
        foxcore_trafficmap::PacketKey::new(IpAddr::V4(TUN_V4), 0, IpAddr::V4(REMOTE_V4), 0, 17);
    let tracked = map
        .open(
            foxcore_api::IpTransport::Udp,
            REMOTE_V4.to_string(),
            0,
            foxcore_trafficmap::FlowRoute::new(foxcore_trafficmap::FlowLane::Vpn, "wireguard"),
            vec!["com.example".to_owned()],
            Some(10_123),
        )
        .bind_packet_flow(uplink_key);
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("the relay should bind and connect its socket")
            .with_accounting(map.tunnel().clone());

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, mut tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    let outbound_packet = ip_packet(TUN_V4, REMOTE_V4);
    to_relay.send(outbound_packet.clone()).await.unwrap();

    // 1. The first thing on the wire is a handshake, never the packet.
    let mut buffer = [0_u8; 2048];
    let (len, client_addr) = recv(&peer, &mut buffer).await;
    assert_eq!(message_type(&buffer[..len]), Some(TYPE_INITIATION));
    let initiation = Initiation::decode(&buffer[..len]).unwrap();

    let responder = Responder::new(&SERVER_STATIC, [0; 32]).unwrap();
    let (response, server_send, server_receive) = responder
        .respond(&initiation, &SERVER_EPHEMERAL, 0xABCD)
        .unwrap();
    peer.send_to(&response.encode(), client_addr).await.unwrap();

    let mut session = TransportSession::new(TransportKeys {
        send: server_send,
        receive: server_receive,
        sender_index: 0xABCD,
        receiver_index: initiation.sender_index,
    });

    // 2. The held packet arrives sealed, with the tun address rewritten to
    //    the address the peer assigned.
    let (len, _) = recv(&peer, &mut buffer).await;
    let plaintext = session.open(&mut buffer[..len]).unwrap();
    let length = ip_packet_len(plaintext).expect("a sealed IP packet");
    assert_eq!(
        &plaintext[12..16],
        &TUNNEL_V4.octets(),
        "the peer must see the address it assigned, not the tun's"
    );
    assert_eq!(&plaintext[16..20], &REMOTE_V4.octets());
    assert_eq!(length, outbound_packet.len());

    // 3. A reply is decrypted and restored to the tun address.
    let mut reply = Vec::new();
    session
        .seal(&ip_packet(REMOTE_V4, TUNNEL_V4), &mut reply)
        .unwrap();
    peer.send_to(&reply, client_addr).await.unwrap();

    let delivered = tokio::time::timeout(Duration::from_secs(5), tun_inbox.recv())
        .await
        .expect("the decrypted reply should reach the tun")
        .expect("the relay should still be running");
    assert_eq!(
        &delivered[16..20],
        &TUN_V4.octets(),
        "the tun only accepts packets addressed to its own address"
    );
    assert_eq!(&delivered[12..16], &REMOTE_V4.octets());

    // A live L3 tunnel that reports zero bytes is drawn as idle by the app;
    // nothing else on this path counts them.
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.bytes_up, outbound_packet.len() as u64);
    assert_eq!(
        snapshot.bytes_down, 28,
        "the decrypted inner packet is what the user received"
    );
    // And the same bytes, attributed. The uplink is counted by the split,
    // which this test does not run, so only the reply lands here.
    let map_snapshot = map.snapshot();
    assert_eq!(map_snapshot.connections[0].bytes_down, 28);
    assert_eq!(map_snapshot.packages[0].package, "com.example");
    assert_eq!(map_snapshot.packages[0].bytes_down, 28);
    drop(tracked);

    cancel.cancel();
    task.await.unwrap().unwrap();
}

/// D10, reproduced without a device. The tun carries an address the engine
/// was not configured with — Kotlin's `addAddress()` and `EngineConfig.tun`
/// disagreeing, which the core cannot observe directly — so the translator
/// refuses every outbound packet.
///
/// Every existing test in this file stays green through that, because their
/// address pairs agree by construction. That is exactly why this shipped:
/// the failure is invisible to the wire tests, and on the device it looked
/// like a live tunnel. Handshakes and keepalives come from `PeerTunnel` and
/// go out through `flush`, bypassing translation entirely, so bytes move;
/// DNS is answered by the interceptor on the stack side, so names resolve;
/// and not one TCP connection can be established.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_tun_address_the_engine_does_not_know_is_counted_and_reported_not_dropped_in_silence() {
    const OTHER_TUN_V4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

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

    // The engine believes the tun is TUN_V4. The platform actually put
    // OTHER_TUN_V4 on it, so every packet arrives with a source the
    // translator will not map.
    let relay =
        PacketTunnelRelay::connect(&outbound(endpoint), &[IpAddr::V4(TUN_V4)], metrics.clone())
            .await
            .expect("a translator with a usable pair still starts")
            .with_events(sink);

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, mut tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    for _ in 0..3 {
        to_relay
            .send(ip_packet(OTHER_TUN_V4, REMOTE_V4))
            .await
            .unwrap();
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && metrics.snapshot().tunnel_untranslated_up < 3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.tunnel_untranslated_up, 3,
        "a tunnel losing every packet must not be indistinguishable from a working one"
    );
    assert_eq!(
        snapshot.bytes_up, 0,
        "and it must not claim it carried them"
    );
    assert!(
        tun_inbox.try_recv().is_err(),
        "nothing reaches the peer, which is the symptom that was reported"
    );

    let events = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        events.len(),
        1,
        "the cause is static, so it is reported once rather than per packet: {events:?}"
    );
    assert!(
        matches!(
            &events[0],
            CoreEvent::Blocked {
                reason: BlockReason::TunnelAddressMismatch,
                ..
            }
        ),
        "the reason has to name the mismatch, not just say 'blocked': {events:?}"
    );

    cancel.cancel();
    let _ = task.await;
}

/// The configuration D10 turned out to be, caught before a single packet is
/// lost: a v4-only profile on a dual-stack tun.
///
/// This one *does* map a family, so the old "at least one pair" check let it
/// through — and it then carried v4 correctly while black-holing every v6
/// packet, which is a working tunnel with no internet as soon as
/// happy-eyeballs prefers v6.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_tun_family_the_tunnel_cannot_carry_refuses_to_start() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();

    let error = PacketTunnelRelay::connect(
        &outbound(endpoint),
        // Exactly the owner's shape: the tun advertises both, the profile
        // in `outbound()` assigns only IPv4.
        &[
            IpAddr::V4(TUN_V4),
            IpAddr::V6("fd00::2".parse::<std::net::Ipv6Addr>().unwrap()),
        ],
        Arc::new(FlowMetrics::default()),
    )
    .await
    .err()
    .expect("a family with nowhere to go must not start silently");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let message = error.to_string();
    assert!(
        message.contains("fd00::2"),
        "the error must name the address that has nowhere to go: {message}"
    );
    assert!(
        !message.contains(&TUN_V4.to_string()),
        "and must not blame the family that is fine: {message}"
    );
}

/// Wait for the relay to reach a state, rather than for a sleep to be long
/// enough. The relay runs on its own task, so every assertion about what it
/// did has to be ordered against it explicitly or it is a race that passes
/// on an idle machine.
pub(super) async fn wait_for(
    metrics: &FlowMetrics,
    reached: impl Fn(&crate::FlowSnapshot) -> bool,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && !reached(&metrics.snapshot()) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        reached(&metrics.snapshot()),
        "the relay never got there: {:?}",
        metrics.snapshot()
    );
}

/// Bring the peer session up and hand back the server side of it, plus the
/// client address the peer learned. Shared by the roaming tests, which are
/// about what happens *after* this.
pub(super) async fn establish(
    peer: &UdpSocket,
    to_relay: &mpsc::Sender<BytesMut>,
    buffer: &mut [u8; 2048],
) -> (TransportSession, SocketAddr) {
    to_relay.send(ip_packet(TUN_V4, REMOTE_V4)).await.unwrap();

    let (len, client) = recv(peer, buffer).await;
    assert_eq!(message_type(&buffer[..len]), Some(TYPE_INITIATION));
    let initiation = Initiation::decode(&buffer[..len]).unwrap();
    let responder = Responder::new(&SERVER_STATIC, [0; 32]).unwrap();
    let (response, server_send, server_receive) = responder
        .respond(&initiation, &SERVER_EPHEMERAL, 0xABCD)
        .unwrap();
    peer.send_to(&response.encode(), client).await.unwrap();

    let mut session = TransportSession::new(TransportKeys {
        send: server_send,
        receive: server_receive,
        sender_index: 0xABCD,
        receiver_index: initiation.sender_index,
    });
    // The packet that was waiting for the session, now sealed.
    let (len, from) = recv(peer, buffer).await;
    assert_eq!(from, client);
    assert!(session.open(&mut buffer[..len]).is_ok());
    (session, client)
}

/// The defect, reproduced without a device: the relay used to own the one
/// socket `connect` gave it and never build another, so a phone moving from
/// Wi-Fi to mobile left the tunnel on a descriptor bound to an interface
/// that no longer routes.
///
/// What makes it worth a test rather than a patch is the shape of the
/// failure, which is the one that already cost three device runs (D1, D2,
/// D7, D10): the peer state machine keeps producing handshakes and
/// keepalives, `bytes_up` keeps rising, the app draws a live tunnel — and
/// not one user packet arrives. Nothing in the process can tell the
/// difference.
///
/// Two claims are asserted, and they are the two halves of "roaming", not
/// one: the datagram after the change leaves a **different local socket**
/// (so it is on the new network, and `protect`/`bind` ran for it), and the
/// peer opens it with the **same session** (so the keys, the nonces and the
/// byte counters were not thrown away — WireGuard sets a peer's endpoint
/// from the source address of the last authenticated datagram, which is
/// exactly why a rebind must not be a reconnect).
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_network_change_rebinds_the_peer_socket_and_the_session_survives_it() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    let platform = PlatformCalls::unlimited();
    let dialer = platform.dialer();
    dialer.set_network_handle(7);

    let metrics = Arc::new(FlowMetrics::default());
    let (network, network_signal) = tokio::sync::watch::channel(0_u64);
    let relay = PacketTunnelRelay::connect(
        &outbound_through(endpoint, dialer.clone()),
        &[IpAddr::V4(TUN_V4)],
        metrics.clone(),
    )
    .await
    .expect("the relay should bind and connect its socket")
    .with_network_signal(network_signal);

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, mut tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    let mut buffer = [0_u8; 2048];
    let (mut session, wifi) = establish(&peer, &to_relay, &mut buffer).await;

    // Wi-Fi to mobile. The handle is applied before the signal, which is
    // the order `RuntimeHandle::network_changed_with_handle` uses.
    dialer.set_network_handle(9);
    network.send_modify(|epoch| *epoch += 1);

    // The peer hears from the new socket without the tun sending anything.
    // That is not a nicety: until an authenticated datagram arrives from
    // the new address the peer keeps sending downstream traffic to the one
    // that just died, and the tunnel is half dead in a way no counter shows.
    let (len, mobile) = recv(&peer, &mut buffer).await;
    assert_ne!(
        mobile, wifi,
        "the socket must be recreated on the new network, not reused: \
             a datagram from the same local port is the old descriptor"
    );
    assert!(
        session.open(&mut buffer[..len]).is_ok(),
        "roaming must keep the session: rekeying on every Wi-Fi switch \
             would drop every flow the tunnel is carrying"
    );

    assert_eq!(
        platform.taken(),
        vec!["protect:true", "bind:7", "protect:true", "bind:9"],
        "the replacement socket has to be protected and bound to the new \
             network before it carries anything"
    );
    assert_eq!(metrics.snapshot().tunnel_rebinds, 1);

    // And both directions work on the new socket.
    to_relay.send(ip_packet(TUN_V4, REMOTE_V4)).await.unwrap();
    let (len, from) = recv(&peer, &mut buffer).await;
    assert_eq!(from, mobile);
    assert!(session.open(&mut buffer[..len]).is_ok());

    let mut reply = Vec::new();
    session
        .seal(&ip_packet(REMOTE_V4, TUNNEL_V4), &mut reply)
        .unwrap();
    peer.send_to(&reply, mobile).await.unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(5), tun_inbox.recv())
        .await
        .expect("the peer's reply must reach the tun over the new socket")
        .expect("the relay should still be running");
    assert_eq!(&delivered[16..20], &TUN_V4.octets());

    cancel.cancel();
    let _ = task.await;
}

/// The other half of the requirement: a rebind the platform refuses must
/// close the tunnel visibly, not quietly carry on.
///
/// `protect()` is what keeps a WireGuard socket out of the tun the engine
/// is serving. A socket that could not be protected must never carry a
/// byte, so the relay has nowhere to put the user's packets and says so —
/// a counter per dropped packet, one typed event, and a retry every tick.
/// The alternative is not "keep working": the old socket is on a dead
/// interface, and keeping it is the defect above with a clean conscience.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_rebind_the_platform_will_not_protect_closes_the_tunnel_loudly() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = peer.local_addr().unwrap();
    // One protected socket for this engine and no more.
    let platform = PlatformCalls::allowing(1);
    let dialer = platform.dialer();
    dialer.set_network_handle(7);

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
    let (network, network_signal) = tokio::sync::watch::channel(0_u64);
    let relay = PacketTunnelRelay::connect(
        &outbound_through(endpoint, dialer.clone()),
        &[IpAddr::V4(TUN_V4)],
        metrics.clone(),
    )
    .await
    .expect("the first socket is protected, so the engine starts")
    .with_events(sink)
    .with_network_signal(network_signal);

    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, mut tun_inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));

    let mut buffer = [0_u8; 2048];
    let (_session, _wifi) = establish(&peer, &to_relay, &mut buffer).await;

    dialer.set_network_handle(9);
    network.send_modify(|epoch| *epoch += 1);

    // The change has to be *processed* before the tun is offered anything.
    // A packet that raced ahead of the signal leaves on the old socket, and
    // that is correct — it was still the live one at the time — but it would
    // make the assertion below prove nothing.
    wait_for(&metrics, |snapshot| snapshot.tunnel_rebind_failures >= 1).await;

    // Nothing may leave. Not on the refused socket, and not on the old one.
    for _ in 0..3 {
        to_relay.send(ip_packet(TUN_V4, REMOTE_V4)).await.unwrap();
    }
    wait_for(&metrics, |snapshot| snapshot.tunnel_offline_packets >= 3).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), peer.recv_from(&mut buffer))
            .await
            .is_err(),
        "a socket that was never protected must not carry the user's traffic, \
             and neither must the one on the network that went away"
    );

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.tunnel_offline_packets, 3,
        "and every packet it refused has to be counted, not dropped in silence"
    );
    assert_eq!(snapshot.tunnel_rebinds, 0);

    let events = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        events.len(),
        1,
        "the cause holds until a rebind succeeds, so it is reported once per \
             outage rather than once per packet: {events:?}"
    );
    assert!(
        matches!(
            &events[0],
            CoreEvent::Blocked {
                reason: BlockReason::TunnelSocketUnavailable,
                ..
            }
        ),
        "the reason has to name the closed socket, not just say 'blocked': {events:?}"
    );
    assert!(tun_inbox.try_recv().is_err());

    cancel.cancel();
    let _ = task.await;
}
