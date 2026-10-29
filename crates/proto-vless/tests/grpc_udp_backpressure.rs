use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use foxcore_api::{Destination, OutboundConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::Datagram;
use proto_vless::{VlessOutbound, codec};
use tokio::net::TcpListener;

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut body = vec![0x0a];
    let mut length = payload.len();
    loop {
        let byte = (length & 127) as u8;
        length >>= 7;
        body.push(if length == 0 { byte } else { byte | 128 });
        if length == 0 {
            break;
        }
    }
    body.extend_from_slice(payload);
    let mut framed = vec![0];
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);
    Bytes::from(framed)
}

async fn read_hunk(body: &mut h2::RecvStream, pending: &mut BytesMut) -> Vec<u8> {
    loop {
        if pending.len() >= 5 {
            assert_eq!(pending[0], 0);
            let length = u32::from_be_bytes(pending[1..5].try_into().unwrap()) as usize;
            assert!(length <= 4096, "fixture Hunk bound");
            if pending.len() >= 5 + length {
                pending.advance(5);
                let message = pending.split_to(length);
                assert_eq!(message[0], 0x0a);
                let mut payload_len = 0usize;
                let mut prefix = 1;
                loop {
                    assert!(prefix <= 3);
                    let byte = message[prefix];
                    payload_len |= usize::from(byte & 127) << ((prefix - 1) * 7);
                    prefix += 1;
                    if byte & 128 == 0 {
                        break;
                    }
                }
                assert_eq!(prefix + payload_len, message.len());
                return message[prefix..].to_vec();
            }
        }
        let data = body
            .data()
            .await
            .expect("client stream stayed open")
            .unwrap();
        let size = data.len();
        pending.extend_from_slice(&data);
        // Advertise more capacity after every real H2 DATA fragment. This
        // deliberately requires the sender to drain a buffered first write.
        body.flow_control().release_capacity(size).unwrap();
    }
}

#[tokio::test]
async fn one_supported_vless_udp_datagram_drains_under_h2_backpressure_without_a_second_send() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let destination = Destination::new("127.0.0.1", 19003);
        let expected: Vec<u8> = (0..1024usize).map(|index| ((index * 17) ^ (index >> 3)) as u8).collect();
        let server_destination = destination.clone();
        let server_payload = expected.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::Builder::new().initial_window_size(32)
                .handshake(socket).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/fox/Tun");
            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let mut pending = BytesMut::new();
                let mut uuid = [0x11; 16]; uuid[6] = 0x41; uuid[8] = 0x81;
                let mut expected_header = Vec::new();
                codec::encode_request(&uuid, codec::Command::Udp, &server_destination, None, &mut expected_header).unwrap();
                assert_eq!(read_hunk(&mut body, &mut pending).await, expected_header);
                let response = http::Response::builder().status(200)
                    .header("content-type", "application/grpc").body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                send.send_data(grpc_frame(&[0, 0]), false).unwrap();
                let packet = read_hunk(&mut body, &mut pending).await;
                assert_eq!(u16::from_be_bytes(packet[..2].try_into().unwrap()) as usize, server_payload.len());
                assert_eq!(packet[2..], server_payload);
                send.send_data(grpc_frame(&packet), false).unwrap();
                std::future::pending::<()>().await;
            });
            while connection.accept().await.is_some() {}
            handler.abort();
            let _ = handler.await;
        });
        let link = format!("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:{port}?encryption=none&type=grpc&serviceName=fox");
        let OutboundConfig::Vless(config) = foxcore_link::import_link(&link).unwrap().outbound else { unreachable!() };
        let outbound = VlessOutbound::new(config, ProtectedDialer::host()).await.unwrap();
        let session = outbound.connect_datagram(&destination, None).await.unwrap();
        session.send(Datagram::new(destination.clone(), expected.clone())).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), session.recv()).await;
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), server).await.expect("owned H2 fixture did not close").unwrap();
        let echoed = result.expect("the first datagram must drain without a second send").unwrap();
        assert_eq!(echoed.destination, destination);
        assert_eq!(echoed.payload.as_ref(), expected);
    }).await.expect("bounded backpressure regression did not settle");
}
