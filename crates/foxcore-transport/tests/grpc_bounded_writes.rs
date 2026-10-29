use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use foxcore_api::{StreamTransportConfig, TlsConfig};
use foxcore_transport::establish_stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PEER_MESSAGE_LIMIT: usize = 1024 * 1024;

fn pattern(index: usize) -> u8 {
    ((index * 131 + 17) & 255) as u8
}

// Decode the public Hunk wire format independently of the carrier's decoder.
fn hunk_payload(message: &[u8]) -> &[u8] {
    assert_eq!(message.first(), Some(&0x0a));
    let mut length = 0usize;
    for (index, byte) in message.iter().copied().skip(1).take(5).enumerate() {
        length |= usize::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            let start = index + 2;
            assert_eq!(start + length, message.len(), "one exact protobuf Hunk");
            return &message[start..];
        }
    }
    panic!("invalid bounded protobuf length");
}

async fn large_write_to_bounded_peer(length: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(16 * 1024)
                .initial_connection_window_size(32 * 1024)
                .handshake(server_io)
                .await
                .unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/GunService/Tun");
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let mut handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let mut buffered = BytesMut::new();
                let mut received = 0usize;
                let mut messages = 0usize;
                let mut largest_payload = 0usize;
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    let consumed = data.len();
                    buffered.extend_from_slice(&data);
                    // Release H2 credit before a whole gRPC message arrives;
                    // each message is larger than this peer's stream window.
                    body.flow_control().release_capacity(consumed).unwrap();
                    assert!(buffered.len() <= PEER_MESSAGE_LIMIT + 5 + 16 * 1024);
                    while buffered.len() >= 5 {
                        assert_eq!(buffered[0], 0, "uncompressed gRPC message");
                        let declared =
                            u32::from_be_bytes(buffered[1..5].try_into().unwrap()) as usize;
                        assert!(
                            declared <= PEER_MESSAGE_LIMIT,
                            "bounded peer refuses gRPC message of {declared} bytes"
                        );
                        if buffered.len() < 5 + declared {
                            break;
                        }
                        buffered.advance(5);
                        let message = buffered.split_to(declared);
                        let payload = hunk_payload(&message);
                        assert!(!payload.is_empty());
                        assert!(received + payload.len() <= length);
                        for (index, byte) in payload.iter().copied().enumerate() {
                            assert_eq!(byte, pattern(received + index), "exact ordered delivery");
                        }
                        received += payload.len();
                        messages += 1;
                        largest_payload = largest_payload.max(payload.len());
                    }
                }
                assert!(
                    buffered.is_empty(),
                    "request EOF must finish a whole message"
                );
                assert_eq!(received, length, "request half-close must flush every byte");
                assert!(messages > 1, "one large application write must be split");
                assert!(
                    largest_payload <= 64 * 1024,
                    "bounded outbound Hunk payload"
                );
                // Literal independent wire encoding of Hunk { data: "OK" }.
                send.send_data(
                    Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 2, b'O', b'K']),
                    false,
                )
                .unwrap();
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                send.send_trailers(trailers).unwrap();
            });
            tokio::select! {
                result = &mut handler => {
                    if let Err(error) = result {
                        drop(connection);
                        panic!("bounded peer handler failed: {error}");
                    }
                    // A successful handler queued the ACK and trailers. Keep
                    // driving H2 until the client reads them and closes.
                    while connection.accept().await.is_some() {}
                }
                next = connection.accept() => {
                    assert!(next.is_none(), "one owned RPC per bounded peer");
                    drop(connection);
                    handler.await.unwrap();
                }
            }
        });
        let transport = StreamTransportConfig::Grpc {
            service_name: "GunService".into(),
            rpc_path: None,
            multi_mode: false,
            authority: None,
            user_agent: None,
            idle_timeout_ms: 0,
            health_check_timeout_ms: 20_000,
            permit_without_stream: false,
            initial_windows_size: 0,
        };
        let mut client = establish_stream(
            client_io,
            &TlsConfig::default(),
            &transport,
            "bounded.example",
            443,
        )
        .await
        .unwrap();
        let payload: Vec<u8> = (0..length).map(pattern).collect();
        client
            .write_all(&payload)
            .await
            .expect("large public AsyncWrite must fit the bounded peer");
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"OK");
        assert_eq!(client.read(&mut [0u8; 1]).await.unwrap(), 0);
        drop(client);
        server.await.unwrap();
    })
    .await
    .expect("bounded H2 flow control or request half-close stalled");
}

#[tokio::test]
async fn one_mib_plus_one_application_write_reaches_a_bounded_grpc_peer() {
    large_write_to_bounded_peer(1024 * 1024 + 1).await;
}

#[tokio::test]
async fn eight_mib_application_write_preserves_all_bytes_under_h2_backpressure() {
    large_write_to_bounded_peer(8 * 1024 * 1024 + 31).await;
}
