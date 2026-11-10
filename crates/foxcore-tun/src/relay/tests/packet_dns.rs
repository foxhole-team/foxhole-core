use super::datapath::establish;
use super::*;
use crate::packet_dns::PacketDnsTracker;
use crate::{FlowKey, FlowMetrics};
use etherparse::PacketBuilder;
use foxcore_dns::{DnsCache, DnsIdentity};
use std::net::IpAddr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[cfg_attr(miri, ignore = "requires protected UDP sockets")]
#[tokio::test]
async fn packet_dns_binding_is_learned_after_peer_authentication_and_address_restoration() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tracker = Arc::new(PacketDnsTracker::default());
    let cache = Arc::new(DnsCache::new(32));
    let owner = DnsIdentity::new(10001, vec!["app".into()]);
    let relay = PacketTunnelRelay::connect(
        &outbound(peer.local_addr().unwrap()),
        &[IpAddr::V4(TUN_V4)],
        Arc::new(FlowMetrics::default()),
    )
    .await
    .unwrap()
    .with_packet_dns(tracker.clone());
    let (to_relay, from_tun) = mpsc::channel(8);
    let (to_tun, mut inbox) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let task = tokio::spawn(relay.run(from_tun, to_tun, cancel.clone()));
    let mut buffer = [0u8; 2048];
    let (mut session, client) = establish(&peer, &to_relay, &mut buffer).await;
    let query = [
        0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 3, b'o', b'r', b'g', 0, 0, 1, 0, 1,
    ];
    let resolver = [10, 8, 0, 1];
    let mut request = Vec::new();
    PacketBuilder::ipv4(TUN_V4.octets(), resolver, 64)
        .udp(44000, 53)
        .write(&mut request, &query)
        .unwrap();
    let key = FlowKey::from_packet(&request).unwrap();
    tracker.register(key, owner.clone(), cache.clone(), CancellationToken::new());
    tracker.query(&request);
    to_relay
        .send(BytesMut::from(request.as_slice()))
        .await
        .unwrap();
    let (size, _) = recv(&peer, &mut buffer).await;
    let plaintext = session.open(&mut buffer[..size]).unwrap();
    assert_eq!(&plaintext[12..16], &TUNNEL_V4.octets());
    let mut answer = query.to_vec();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    let mut reply = Vec::new();
    PacketBuilder::ipv4(resolver, TUNNEL_V4.octets(), 64)
        .udp(53, 44000)
        .write(&mut reply, &answer)
        .unwrap();
    let mut sealed = Vec::new();
    session.seal(&reply, &mut sealed).unwrap();
    let mut forged = sealed.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    peer.send_to(&forged, client).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), inbox.recv())
            .await
            .is_err()
    );
    assert!(
        cache
            .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
            .is_none()
    );
    peer.send_to(&sealed, client).await.unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(5), inbox.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&delivered[16..20], &TUN_V4.octets());
    assert_eq!(
        cache
            .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
            .unwrap(),
        ["a.org"]
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}
