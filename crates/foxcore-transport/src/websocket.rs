//! Bounded RFC 6455 carrier for stream-oriented proxy codecs.
//!
//! The proxy sees an ordinary byte stream. A detached relay maps bounded byte
//! chunks to binary WebSocket messages and applies backpressure through a Tokio
//! duplex buffer. Text frames and oversized messages fail closed.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use foxcore_api::StreamTransportConfig;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
            multi_mode,
            authority,
        } => {
            crate::grpc::connect_grpc(
                stream,
                service_name,
                *multi_mode,
                authority.as_deref(),
                server,
                tls,
            )
            .await
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
    // Dropping the JoinHandle intentionally detaches the per-flow relay. It
    // exits when either the WebSocket or the returned duplex stream closes.
    std::mem::drop(tokio::spawn(relay_websocket(websocket, relay)));
    Ok(Box::new(application))
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

    use foxcore_api::SecretString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    use super::*;

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
