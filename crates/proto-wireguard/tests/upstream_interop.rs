use std::net::UdpSocket;
use std::time::{Duration, Instant};

use proto_wireguard::amnezia::{AmneziaParams, HeaderRange};
use proto_wireguard::noise::public_key;
use proto_wireguard::tunnel::{OsEntropy, PeerSettings, PeerTimers, PeerTunnel, Received};

#[test]
#[ignore = "requires the pinned amneziawg-go peer named by FOXCORE_AWG_TEST_PEER"]
fn custom_headers_exchange_real_ip_packets_with_upstream_amnezia() {
    let endpoint = std::env::var("FOXCORE_AWG_TEST_PEER")
        .expect("set FOXCORE_AWG_TEST_PEER to the upstream test peer's UDP endpoint");
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(endpoint).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut tunnel = PeerTunnel::new(
        PeerSettings {
            private_key: [7; 32],
            peer_public_key: public_key(&[9; 32]).unwrap(),
            preshared_key: None,
            amnezia: AmneziaParams {
                init_junk_size: 24,
                response_junk_size: 16,
                random_trailers: std::env::var("FOXCORE_AWG_RANDOM_TRAILERS").as_deref()
                    == Ok("true"),
                header_initiation: HeaderRange::new(0x1111_1100, 0x1111_11ff).unwrap(),
                header_response: HeaderRange::single(0x2222_2222),
                header_cookie: HeaderRange::single(0x3333_3333),
                header_transport: HeaderRange::single(0x4444_4444),
                ..Default::default()
            },
            persistent_keepalive_s: None,
            reserved: [0; 3],
            init_packets: Vec::new(),
            timers: PeerTimers::default(),
        },
        Box::new(OsEntropy),
    )
    .unwrap();
    let mut outbound = vec![0_u8; 28];
    outbound[0] = 0x45;
    outbound[2..4].copy_from_slice(&28_u16.to_be_bytes());
    outbound[8] = 64;
    outbound[9] = 1;
    outbound[12..16].copy_from_slice(&[10, 8, 0, 2]);
    outbound[16..20].copy_from_slice(&[10, 8, 0, 1]);
    outbound[20..28].copy_from_slice(b"FoxCore!");
    tunnel.send_packet(&outbound, 0).unwrap();
    let started = Instant::now();
    let mut outgoing = Vec::new();
    let mut incoming = [0_u8; 2048];
    let mut packet = Vec::new();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "upstream packet exchange timed out"
        );
        while tunnel.poll_transmit(&mut outgoing).is_some() {
            socket.send(&outgoing).unwrap();
        }
        match socket.recv(&mut incoming) {
            Ok(length) => {
                if tunnel
                    .receive_datagram(
                        &mut incoming[..length],
                        started.elapsed().as_millis() as u64,
                        &mut packet,
                    )
                    .unwrap()
                    == Received::Packet
                {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("receive upstream packet: {error}"),
        }
        tunnel.tick(started.elapsed().as_millis() as u64).unwrap();
    }
    assert_eq!(packet.len(), 28);
    assert_eq!(&packet[12..16], &[10, 8, 0, 1]);
    assert_eq!(&packet[16..20], &[10, 8, 0, 2]);
    assert_eq!(&packet[20..], b"FoxCore!");
}
