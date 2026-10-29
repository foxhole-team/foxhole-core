use std::time::Duration;

use foxcore_api::StreamTransportConfig;
use foxcore_transport::wrap_stream_transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn transport() -> StreamTransportConfig {
    serde_json::from_str(
        r#"{"type":"xhttp","host":"front.example","path":"/tunnel?keep=1","mode":"stream-one"}"#,
    )
    .expect("the native schema must represent XHTTP stream-one")
}

#[tokio::test]
async fn xhttp_stream_one_uses_xray_headers_and_raw_bidirectional_data() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().scheme_str(), Some("https"));
            assert_eq!(request.uri().authority().unwrap().as_str(), "front.example");
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/tunnel/?keep=1"
            );
            assert_eq!(request.headers()["content-type"], "application/grpc");
            let referer = request.headers()["referer"].to_str().unwrap();
            let padding = referer
                .strip_prefix("https://front.example/tunnel/?x_padding=")
                .unwrap();
            assert!((100..=1000).contains(&padding.len()));
            assert!(padding.bytes().all(|value| value == b'X'));
            assert!(!request.headers().contains_key("grpc-encoding"));
            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let mut received = Vec::new();
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    body.flow_control().release_capacity(data.len()).unwrap();
                    received.extend_from_slice(&data);
                }
                assert_eq!(received, vec![7; 512 * 1024]);
                send.send_data(bytes::Bytes::from_static(b"raw xhttp response"), true)
                    .unwrap();
            });
            while conn.accept().await.is_some() {}
            handler.await.unwrap();
        });
        let mut client =
            wrap_stream_transport(client_io, &transport(), "endpoint.example", 443, true)
                .await
                .unwrap();
        client.write_all(&vec![7; 512 * 1024]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"raw xhttp response");
        drop(client);
        server.await.unwrap();
    })
    .await
    .expect("XHTTP stream-one stalled");
}

#[tokio::test]
async fn xhttp_rejects_non_200_without_raw_fallback() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let (_, mut respond) = conn.accept().await.unwrap().unwrap();
        respond
            .send_response(
                http::Response::builder().status(403).body(()).unwrap(),
                true,
            )
            .unwrap();
        while conn.accept().await.is_some() {}
    });
    let result =
        wrap_stream_transport(client_io, &transport(), "endpoint.example", 443, true).await;
    assert!(result.is_err());
    server.await.unwrap();
}
