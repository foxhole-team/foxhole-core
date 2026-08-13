//! v2ray HTTP/2 carrier: the tunnel is the raw request/response body of one
//! HTTP/2 stream — no gRPC message framing.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;

/// Same budget the TLS, WebSocket and httpupgrade carriers already use.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Open an HTTP/2 body tunnel over `stream` (already HTTP/2-capable: TLS with
/// ALPN `h2`, or plaintext h2c).
///
/// Bounded as a whole, for the reason spelled out on `connect_grpc`: none of
/// the three waits on the server had a deadline, and the flow path around them
/// has none either, so a stalling endpoint leaked a task and a descriptor per
/// attempt until the engine stopped.
pub(crate) async fn connect_http2<S>(
    stream: S,
    hosts: &[String],
    path: &str,
    method: &str,
    server: &str,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_http2_inner(stream, hosts, path, method, server, tls),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 handshake timed out"))?
}

async fn connect_http2_inner<S>(
    stream: S,
    hosts: &[String],
    path: &str,
    method: &str,
    server: &str,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (client, connection) = h2::client::handshake(stream)
        .await
        .map_err(crate::h2io::h2_io)?;
    std::mem::drop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut client = client.ready().await.map_err(crate::h2io::h2_io)?;

    let scheme = if tls { "https" } else { "http" };
    let authority = hosts.first().map(String::as_str).unwrap_or(server);
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|error| invalid(format!("invalid HTTP/2 method: {error}")))?;
    let uri: http::Uri = format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|error| invalid(format!("invalid HTTP/2 uri: {error}")))?;
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .map_err(|error| invalid(format!("invalid HTTP/2 request: {error}")))?;

    let (response, send) = client
        .send_request(request, false)
        .map_err(crate::h2io::h2_io)?;
    let response = response.await.map_err(crate::h2io::h2_io)?;
    if response.status() != http::StatusCode::OK {
        return Err(invalid(format!(
            "HTTP/2 server returned HTTP status {}",
            response.status()
        )));
    }
    Ok(Box::new(Http2Stream::new(send, response.into_body())))
}

/// Adapts one HTTP/2 stream to `AsyncRead`/`AsyncWrite`, carrying raw bytes in
/// the request/response DATA frames (no application framing).
struct Http2Stream {
    send: h2::SendStream<bytes::Bytes>,
    recv: h2::RecvStream,
    write_pending: Option<bytes::Bytes>,
    inbound: bytes::BytesMut,
    recv_eof: bool,
}

impl Http2Stream {
    fn new(send: h2::SendStream<bytes::Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            write_pending: None,
            inbound: bytes::BytesMut::new(),
            recv_eof: false,
        }
    }
}

impl AsyncRead for Http2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use bytes::Buf as _;
        loop {
            if !self.inbound.is_empty() {
                let take = self.inbound.len().min(buf.remaining());
                buf.put_slice(&self.inbound[..take]);
                self.inbound.advance(take);
                return Poll::Ready(Ok(()));
            }
            if self.recv_eof {
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    self.inbound.extend_from_slice(&data);
                    let _ = self.recv.flow_control().release_capacity(len);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(crate::h2io::h2_io(error)));
                }
                Poll::Ready(None) => self.recv_eof = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Http2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = crate::h2io::drive_send(&mut self.send, cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let frame = bytes::Bytes::copy_from_slice(buf);
        if let Some(remaining) = crate::h2io::drive_send(&mut self.send, cx, frame)? {
            self.write_pending = Some(remaining);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = crate::h2io::drive_send(&mut self.send, cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = crate::h2io::drive_send(&mut self.send, cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        self.send
            .send_data(bytes::Bytes::new(), true)
            .map_err(crate::h2io::h2_io)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn http2_body_tunnel_round_trips() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::PUT);
                assert_eq!(request.uri().path(), "/stream");
                let handler = tokio::spawn(async move {
                    let mut body = request.into_body();
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    let mut buf = BytesMut::new();
                    while buf.len() < 12 {
                        let data = body.data().await.unwrap().unwrap();
                        let len = data.len();
                        buf.extend_from_slice(&data);
                        body.flow_control().release_capacity(len).unwrap();
                    }
                    assert_eq!(&buf[..12], b"raw h2 bytes");
                    send.send_data(bytes::Bytes::from_static(b"raw h2 back!"), false)
                        .unwrap();
                    send.send_data(bytes::Bytes::new(), true).unwrap();
                });
                while conn.accept().await.is_some() {}
                handler.await.unwrap();
            });

            let mut client = connect_http2(
                client_io,
                &["cdn.example".to_string()],
                "/stream",
                "PUT",
                "server.example",
                false,
            )
            .await
            .expect("http2 connect");
            client.write_all(b"raw h2 bytes").await.unwrap();
            client.flush().await.unwrap();
            let mut response = [0u8; 12];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"raw h2 back!");
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("http2 round trip did not complete in time");
    }
}
