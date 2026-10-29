//! Bounded RFC 6455 carrier for stream-oriented proxy codecs.
//!
//! The proxy sees an ordinary byte stream. An owned relay maps bounded byte
//! chunks to binary WebSocket messages and applies backpressure through a Tokio
//! duplex buffer. Text frames and oversized messages fail closed.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use foxcore_api::StreamTransportConfig;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::client_async_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::HOST;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

use crate::BoxStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;
const RELAY_CHUNK_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_WRITE_BUFFER_BYTES: usize = 512 * 1024;

pub async fn wrap_stream_transport<S>(
    stream: S,
    transport: &StreamTransportConfig,
    server: &str,
    port: u16,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match transport {
        StreamTransportConfig::Raw => Ok(Box::new(stream)),
        StreamTransportConfig::Websocket {
            path,
            host,
            headers,
        } => connect_websocket(stream, path, host.as_deref(), headers, server, port, tls).await,
        StreamTransportConfig::HttpUpgrade {
            path,
            host,
            headers,
        } => {
            crate::httpupgrade::connect_http_upgrade(
                stream,
                path,
                host.as_deref(),
                headers,
                server,
                port,
                tls,
            )
            .await
        }
        StreamTransportConfig::Grpc {
            service_name,
            rpc_path,
            multi_mode,
            authority,
            user_agent,
            idle_timeout_ms,
            health_check_timeout_ms,
            permit_without_stream,
            initial_windows_size,
        } => {
            let default_authority = match server.parse::<std::net::IpAddr>() {
                Ok(address) => std::net::SocketAddr::new(address, port).to_string(),
                Err(_) => server.to_owned(),
            };
            crate::grpc::connect_grpc_with_options(
                stream,
                service_name,
                *multi_mode,
                authority.as_deref(),
                &default_authority,
                tls,
                crate::grpc::GrpcOptions {
                    rpc_path: rpc_path.as_deref(),
                    user_agent: user_agent.as_deref(),
                    idle_timeout_ms: *idle_timeout_ms,
                    health_check_timeout_ms: *health_check_timeout_ms,
                    permit_without_stream: *permit_without_stream,
                    initial_windows_size: *initial_windows_size,
                },
            )
            .await
        }
        StreamTransportConfig::Xhttp { path, host, mode } => {
            if mode != "stream-one" {
                return Err(invalid("XHTTP implements only stream-one over HTTP/2"));
            }
            crate::xhttp::connect_xhttp(stream, path, host.as_deref(), server, tls).await
        }
        StreamTransportConfig::Http2 { host, path, method } => {
            crate::http2::connect_http2(stream, host, path, method, server, tls).await
        }
    }
}

async fn connect_websocket<S>(
    stream: S,
    path: &str,
    host: Option<&str>,
    headers: &std::collections::BTreeMap<String, foxcore_api::SecretString>,
    server: &str,
    port: u16,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let scheme = if tls { "wss" } else { "ws" };
    let uri = format!("{scheme}://{}{path}", authority(server, port, tls));
    let mut request = uri
        .into_client_request()
        .map_err(|error| invalid(format!("invalid WebSocket request: {error}")))?;
    if let Some(host) = host {
        request.headers_mut().insert(
            HOST,
            HeaderValue::from_str(host).map_err(|_| invalid("invalid WebSocket Host header"))?,
        );
    }
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid(format!("invalid WebSocket header name '{name}'")))?;
        let header_value = HeaderValue::from_str(value.expose())
            .map_err(|_| invalid(format!("invalid WebSocket header value for '{name}'")))?;
        request.headers_mut().insert(header_name, header_value);
    }

    let websocket_config = WebSocketConfig::default()
        .read_buffer_size(32 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let (websocket, _) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_async_with_config(request, stream, Some(websocket_config)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket handshake timed out"))?
    .map_err(websocket_io)?;

    let (application, relay) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    // As with the gRPC driver, the returned stream owns its relay. A blocked
    // socket write must not keep the flow alive after its application drops it.
    let relay = tokio::spawn(relay_websocket(websocket, relay));
    Ok(Box::new(WebSocketCarrier { application, relay }))
}

struct WebSocketCarrier {
    application: tokio::io::DuplexStream,
    relay: tokio::task::JoinHandle<()>,
}

impl Drop for WebSocketCarrier {
    fn drop(&mut self) {
        self.relay.abort();
    }
}

impl AsyncRead for WebSocketCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_read(cx, buffer)
    }
}

impl AsyncWrite for WebSocketCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.application).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_shutdown(cx)
    }
}

async fn relay_websocket<S>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    relay: tokio::io::DuplexStream,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut websocket_writer, mut websocket_reader) = websocket.split();
    let (mut local_reader, mut local_writer) = tokio::io::split(relay);
    let mut buffer = vec![0u8; RELAY_CHUNK_BYTES];

    loop {
        tokio::select! {
            read = local_reader.read(&mut buffer) => {
                match read {
                    Ok(0) | Err(_) => {
                        let _ = websocket_writer.send(Message::Close(None)).await;
                        break;
                    }
                    Ok(read) => {
                        if websocket_writer
                            .send(Message::Binary(Bytes::copy_from_slice(&buffer[..read])))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            incoming = websocket_reader.next() => {
                match incoming {
                    Some(Ok(Message::Binary(payload))) => {
                        if local_writer.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if websocket_writer.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        let _ = websocket_writer.send(Message::Close(frame)).await;
                        break;
                    }
                    Some(Ok(Message::Text(_) | Message::Frame(_)))
                    | Some(Err(_))
                    | None => break,
                }
            }
        }
    }
    let _ = local_writer.shutdown().await;
}

fn authority(server: &str, port: u16, tls: bool) -> String {
    let host = match server.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        _ => server.to_owned(),
    };
    if (tls && port == 443) || (!tls && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn websocket_io(error: WebSocketError) -> io::Error {
    io::Error::other(format!("WebSocket handshake failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use foxcore_api::SecretString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::sync::oneshot;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    use super::*;

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's test handshake callback owns ErrorResponse.
    async fn websocket_tls_forces_http1_even_with_default_or_conflicting_profile_alpn() {
        tokio::time::timeout(Duration::from_secs(5), async {
            crate::ensure_process_crypto_provider().unwrap();
            for alpn in [vec![], vec!["h2", "http/1.1"], vec!["h2"]] {
                use base64::Engine as _;
                use foxcore_api::{TlsConfig, TlsFingerprint};
                use sha2::{Digest, Sha256};

                let generated =
                    rcgen::generate_simple_self_signed(vec!["tls.example".into()]).unwrap();
                let certificate = generated.cert.der().clone();
                let mut config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![certificate.clone()],
                        rustls_pki_types::PrivatePkcs8KeyDer::from(
                            generated.signing_key.serialize_der(),
                        )
                        .into(),
                    )
                    .unwrap();
                // A protocol-respecting peer must select h1 before accepting
                // the existing RFC 6455 HTTP/1 Upgrade carrier.
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                let (client_io, server_io) = tokio::io::duplex(128 * 1024);
                let (done_tx, done_rx) = oneshot::channel::<()>();
                let payload = vec![0x57; 257];
                let expected = payload.clone();
                let peer = tokio::spawn(async move {
                    let secured = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                        .accept(server_io)
                        .await
                        .unwrap();
                    assert_eq!(secured.get_ref().1.server_name(), Some("tls.example"));
                    assert_eq!(
                        secured.get_ref().1.alpn_protocol(),
                        Some(b"http/1.1".as_slice()),
                        "HTTP/1 WebSocket must not negotiate h2"
                    );
                    let mut websocket =
                        accept_hdr_async(secured, |request: &Request, response: Response| {
                            assert_eq!(request.uri().path(), "/alpn");
                            assert_eq!(request.headers()["host"], "ws.example");
                            Ok(response)
                        })
                        .await
                        .unwrap();
                    let message = websocket.next().await.unwrap().unwrap();
                    assert_eq!(message.into_data().as_ref(), expected.as_slice());
                    websocket
                        .send(Message::Binary(expected.into()))
                        .await
                        .unwrap();
                    done_rx.await.unwrap();
                });
                let profile_alpn: Vec<String> = alpn.into_iter().map(str::to_owned).collect();
                let tls = TlsConfig {
                    enabled: true,
                    server_name: Some("tls.example".into()),
                    insecure: false,
                    pinned_certificate_sha256: Some(
                        base64::engine::general_purpose::STANDARD
                            .encode(Sha256::digest(certificate.as_ref())),
                    ),
                    fingerprint: Some(TlsFingerprint::Chrome151),
                    alpn: profile_alpn.clone(),
                    ..TlsConfig::default()
                };
                let transport = StreamTransportConfig::Websocket {
                    path: "/alpn".into(),
                    host: Some("ws.example".into()),
                    headers: BTreeMap::new(),
                };
                let mut stream =
                    crate::establish_stream(client_io, &tls, &transport, "origin.example", 443)
                        .await
                        .unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
                let mut echoed = vec![0; payload.len()];
                stream.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
                assert_eq!(tls.alpn, profile_alpn, "the supplied profile is immutable");
                done_tx.send(()).unwrap();
                drop(stream);
                peer.await.unwrap();
            }
        })
        .await
        .expect("TLS WebSocket ALPN fixture did not settle");
    }

    /// A real duplex carrier whose writes can become permanently backpressured
    /// after its standard WebSocket handshake. The signal proves the relay has
    /// reached the blocked write before the application endpoint is dropped.
    struct StalledWriter {
        inner: tokio::io::DuplexStream,
        stall: Arc<AtomicBool>,
        blocked: Option<oneshot::Sender<()>>,
        dropped: Option<oneshot::Sender<()>>,
    }

    impl AsyncRead for StalledWriter {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.stall.load(Ordering::SeqCst) && !buffer.is_empty() {
                if let Some(signal) = self.blocked.take() {
                    let _ = signal.send(());
                }
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_write(cx, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl Drop for StalledWriter {
        fn drop(&mut self) {
            if let Some(signal) = self.dropped.take() {
                let _ = signal.send(());
            }
        }
    }

    #[tokio::test]
    async fn websocket_client_drop_releases_a_carrier_with_a_blocked_writer() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let stall = Arc::new(AtomicBool::new(false));
        let (blocked_tx, blocked_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let carrier = StalledWriter {
            inner: client_io,
            stall: stall.clone(),
            blocked: Some(blocked_tx),
            dropped: Some(dropped_tx),
        };
        let peer = tokio::spawn(async move {
            let websocket = tokio_tungstenite::accept_async(server_io).await.unwrap();
            // Hold the peer alive without consuming data: termination must come
            // from the application endpoint, rather than a peer-side EOF.
            std::future::pending::<()>().await;
            drop(websocket);
        });
        let transport = StreamTransportConfig::Websocket {
            path: "/synthetic".into(),
            host: None,
            headers: BTreeMap::new(),
        };
        let mut application = tokio::time::timeout(
            Duration::from_secs(2),
            wrap_stream_transport(carrier, &transport, "synthetic.example", 80, false),
        )
        .await
        .expect("standard synthetic WebSocket handshake must settle")
        .unwrap();
        stall.store(true, Ordering::SeqCst);
        application
            .write_all(b"bounded-synthetic-payload")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), blocked_rx)
            .await
            .expect("relay must reach the blocked carrier write")
            .unwrap();
        drop(application);
        let released = tokio::time::timeout(Duration::from_secs(1), dropped_rx).await;
        peer.abort();
        let _ = peer.await;
        assert!(
            matches!(released, Ok(Ok(()))),
            "dropping the WebSocket application must release its blocked carrier"
        );
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's test handshake callback owns ErrorResponse.
    async fn websocket_carrier_preserves_bytes_and_custom_handshake() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            let mut websocket =
                accept_hdr_async(server_io, |request: &Request, response: Response| {
                    assert_eq!(request.uri().path_and_query().unwrap(), "/proxy?mode=test");
                    assert_eq!(request.headers()[HOST], "front.example");
                    assert_eq!(request.headers()["x-foxhole-test"], "bounded");
                    Ok(response)
                })
                .await
                .unwrap();

            let message = websocket.next().await.unwrap().unwrap();
            assert_eq!(message.into_data(), b"client bytes".as_slice());
            websocket
                .send(Message::Binary(Bytes::from_static(b"server bytes")))
                .await
                .unwrap();
        });

        let mut headers = BTreeMap::new();
        headers.insert("x-foxhole-test".into(), SecretString::new("bounded"));
        let transport = StreamTransportConfig::Websocket {
            path: "/proxy?mode=test".into(),
            host: Some("front.example".into()),
            headers,
        };
        let mut client = wrap_stream_transport(client_io, &transport, "server.example", 80, false)
            .await
            .unwrap();
        client.write_all(b"client bytes").await.unwrap();
        let mut response = [0u8; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"server bytes");
        drop(client);
        server.await.unwrap();
    }

    #[test]
    fn websocket_authority_brackets_ipv6_and_omits_default_ports() {
        assert_eq!(authority("2001:db8::1", 443, true), "[2001:db8::1]");
        assert_eq!(authority("example.com", 8080, false), "example.com:8080");
    }
}
