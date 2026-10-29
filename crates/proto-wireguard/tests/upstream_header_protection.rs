use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use proto_wireguard::amnezia::{AmneziaParams, HeaderRange};
use proto_wireguard::header_protection::HeaderProtectionKey;
use proto_wireguard::noise::public_key;
use proto_wireguard::tunnel::{OsEntropy, PeerSettings, PeerTimers, PeerTunnel, Received};
use serde_json::Value;
use zeroize::Zeroizing;

fn peer_receipt() -> Value {
    let address = std::env::var("FOXCORE_CPA_TEST_RECEIPT").unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(b"GET /receipt HTTP/1.0\r\nHost: synthetic-peer\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (_, json) = response.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(json).unwrap()
}

fn client(addition: Option<HeaderRange>, trailers: bool, s4: u16) -> PeerTunnel {
    let mode = std::env::var("FOXCORE_HPK_PREFIX_MODE").unwrap();
    let key_mode = std::env::var("FOXCORE_HPK_CLIENT_KEY").unwrap();
    let minimal = mode == "minimal" || mode == "vanilla";
    let prefix = if mode == "vanilla" { 0 } else { 12 };
    let bytes = match key_mode.as_str() {
        "correct" => std::array::from_fn(|index| index as u8 + 1),
        "wrong" => [0x77; 32],
        "zero" | "none" => [0; 32],
        _ => panic!("bad synthetic key mode"),
    };
    let configured = PeerSettings {
        private_key: [7; 32],
        peer_public_key: public_key(&[9; 32]).unwrap(),
        preshared_key: None,
        amnezia: AmneziaParams {
            init_junk_size: if minimal { prefix } else { 24 },
            response_junk_size: if minimal { prefix } else { 16 },
            cookie_junk_size: if mode == "legacy" || mode == "vanilla" {
                0
            } else {
                12
            },
            transport_junk_size: s4,
            random_trailers: trailers,
            content_padding_addition: addition,
            header_initiation: if minimal {
                HeaderRange::single(1)
            } else {
                HeaderRange::new(0x1111_1100, 0x1111_11ff).unwrap()
            },
            header_response: HeaderRange::single(if minimal { 2 } else { 0x2222_2222 }),
            header_cookie: HeaderRange::single(if minimal { 3 } else { 0x3333_3333 }),
            header_transport: HeaderRange::single(if minimal { 4 } else { 0x4444_4444 }),
            ..Default::default()
        },
        persistent_keepalive_s: None,
        reserved: [0; 3],
        init_packets: Vec::new(),
        timers: PeerTimers::default(),
    };
    PeerTunnel::new(
        configured
            .with_header_protection_key(HeaderProtectionKey::from_bytes(Zeroizing::new(bytes))),
        Box::new(OsEntropy),
    )
    .unwrap()
}

fn ipv4_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 8, 0, 1]);
    packet[20..].copy_from_slice(b"FoxCore!");
    packet
}

fn exchange(
    tunnel: &mut PeerTunnel,
    socket: &UdpSocket,
    packet: &[u8],
    now_ms: u64,
) -> (Vec<u8>, usize) {
    tunnel.send_packet(packet, now_ms).unwrap();
    let start = Instant::now();
    let mut outgoing = Vec::new();
    let mut incoming = [0_u8; 4096];
    let mut result = Vec::new();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "official HPK peer exchange timed out"
        );
        while tunnel.poll_transmit(&mut outgoing).is_some() {
            socket.send(&outgoing).unwrap();
        }
        match socket.recv(&mut incoming) {
            Ok(length) => {
                let headers: Vec<_> = [0, 16, 23]
                    .into_iter()
                    .map(|offset| {
                        incoming
                            .get(offset..offset + 4)
                            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    })
                    .collect();
                if tunnel
                    .receive_datagram(
                        &mut incoming[..length],
                        now_ms + start.elapsed().as_millis() as u64,
                        &mut result,
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "official synthetic peer datagram failed: {error:?}, length={length}, headers={headers:?}, receipt={}",
                            peer_receipt()
                        )
                    })
                    == Received::Packet
                {
                    return (result, length);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("receive official HPK peer: {error}"),
        }
        tunnel
            .tick(now_ms + start.elapsed().as_millis() as u64)
            .unwrap();
    }
}

fn ipv6_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 60];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
    packet[6] = 59;
    packet[7] = 64;
    packet[8..10].copy_from_slice(&[0xfd, 8]);
    packet[23] = 2;
    packet[24..26].copy_from_slice(&[0xfd, 8]);
    packet[39] = 1;
    packet[40..].fill(0x37);
    packet
}

#[test]
#[ignore = "requires an owned official b5928efb HPK peer with the declared case parameters"]
fn header_protection_exchanges_ipv4_ipv6_and_authenticated_keepalives() {
    let selected: u32 = std::env::var("FOXCORE_CPA_CLIENT_ADDITION")
        .unwrap()
        .parse()
        .unwrap();
    let trailers = std::env::var("FOXCORE_CPA_TRAILERS").as_deref() == Ok("true");
    let s4: u16 = std::env::var("FOXCORE_CPA_S4").unwrap().parse().unwrap();
    let server_addition: u32 = std::env::var("FOXCORE_CPA_SERVER_ADDITION")
        .unwrap()
        .parse()
        .unwrap();
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket
        .connect(std::env::var("FOXCORE_CPA_TEST_PEER").unwrap())
        .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut tunnel = client(Some(HeaderRange::single(selected)), trailers, s4);
    let packet4 = ipv4_packet();
    let (response4, wire4) = exchange(&mut tunnel, &socket, &packet4, 0);
    assert_eq!(&response4[12..16], &packet4[16..20]);
    assert_eq!(&response4[16..20], &packet4[12..16]);
    assert_eq!(&response4[20..], &packet4[20..]);
    let packet6 = ipv6_packet();
    let (response6, wire6) = exchange(&mut tunnel, &socket, &packet6, 100);
    assert_eq!(&response6[8..24], &packet6[24..40]);
    assert_eq!(&response6[24..40], &packet6[8..24]);
    assert_eq!(&response6[40..], &packet6[40..]);
    assert_eq!(response4.len(), packet4.len());
    assert_eq!(response6.len(), packet6.len());
    let expected_wire_bounds = |addition: u32, length: usize| {
        let base = usize::from(s4) + 32 + length;
        let available = 500_usize.saturating_sub(base);
        if addition != 0 {
            let exact = base + u64::from(addition).min(available as u64) as usize;
            (exact, exact)
        } else if trailers {
            (base, base + available.saturating_sub(1))
        } else {
            let exact = base + length.next_multiple_of(16) - length;
            (exact, exact)
        }
    };
    let assert_wire_size = |actual: usize, bounds: (usize, usize)| {
        if bounds.0 == bounds.1 {
            assert_eq!(actual, bounds.0);
        } else {
            assert!(
                (bounds.0..=bounds.1).contains(&actual),
                "transport wire size {actual} must be in {}..={}",
                bounds.0,
                bounds.1
            );
        }
    };
    assert_wire_size(wire4, expected_wire_bounds(server_addition, 28));
    assert_wire_size(wire6, expected_wire_bounds(server_addition, 60));
    let before = peer_receipt();
    let received_lengths = before["inbound_transport"].as_array().unwrap();
    for length in [28, 60] {
        let bounds = expected_wire_bounds(selected, length);
        if bounds.0 == bounds.1 {
            assert!(received_lengths.contains(&Value::from(bounds.0)));
        } else {
            assert!(received_lengths.iter().any(|received| {
                let received = received.as_u64().unwrap() as usize;
                (bounds.0..=bounds.1).contains(&received)
            }));
        }
    }
    tunnel.send_packet(&[], 200).unwrap();
    let mut wire = Vec::new();
    assert_eq!(tunnel.poll_transmit(&mut wire), Some(0));
    assert_wire_size(wire.len(), expected_wire_bounds(selected, 0));
    socket.send(&wire).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let after = loop {
        let receipt = peer_receipt();
        if receipt["authenticated_keepalives"].as_u64().unwrap()
            > before["authenticated_keepalives"].as_u64().unwrap()
        {
            break receipt;
        }
        assert!(
            Instant::now() < deadline,
            "official peer did not authenticate the padded keepalive"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(after["ipv4_echoes"], 1);
    assert_eq!(after["ipv6_echoes"], 1);
    assert_eq!(
        after["content_padding_addition"],
        server_addition.to_string()
    );
    assert_eq!(
        after["header_protection_active"],
        std::env::var("FOXCORE_HPK_SERVER_ACTIVE").unwrap() == "true"
    );
    println!("HPK_PEER_RECEIPT={after}");
}

#[test]
#[ignore = "requires an owned official HPK peer configured with a mismatched declared key policy"]
fn mismatched_header_protection_does_not_deliver_inner_packets() {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket
        .connect(std::env::var("FOXCORE_CPA_TEST_PEER").unwrap())
        .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let s4: u16 = std::env::var("FOXCORE_CPA_S4").unwrap().parse().unwrap();
    let mut tunnel = client(Some(HeaderRange::single(13)), false, s4);
    tunnel.send_packet(&ipv4_packet(), 0).unwrap();
    let mut wire = Vec::new();
    while tunnel.poll_transmit(&mut wire).is_some() {
        socket.send(&wire).unwrap();
    }
    let deadline = Instant::now() + Duration::from_millis(600);
    let mut buffer = [0; 4096];
    let mut output = Vec::new();
    while Instant::now() < deadline {
        match socket.recv(&mut buffer) {
            Ok(size) => {
                let received = tunnel.receive_datagram(&mut buffer[..size], 1, &mut output);
                assert_ne!(received, Ok(Received::Packet));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("synthetic negative peer receive: {error}"),
        }
    }
    assert!(output.is_empty());
    let receipt = peer_receipt();
    assert_eq!(receipt["ipv4_echoes"], 0);
    assert_eq!(receipt["ipv6_echoes"], 0);
    assert_eq!(receipt["authenticated_keepalives"], 0);
    println!("HPK_PEER_NEGATIVE_RECEIPT={receipt}");
}
