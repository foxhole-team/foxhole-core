//! gRPC ("gun") carrier over HTTP/2.
//!
//! Proxy bytes ride inside a single bidirectional gRPC streaming RPC
//! (`<service>/Tun` or `/TunMulti`). Each write is wrapped as a length-prefixed
//! gRPC message carrying a protobuf `Hunk { bytes data = 1 }`; the reader
//! reassembles messages across HTTP/2 DATA frames and concatenates every field-1
//! chunk (so single `Hunk` and multi `MultiHunk` decode identically).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;

/// Same budget the TLS, WebSocket and httpupgrade carriers already use.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Encode one payload as a gRPC length-prefixed message wrapping a `Hunk`.
///
/// `0x00` (uncompressed) `| u32be(len(hunk)) | 0x0A | varint(len) | payload`.
fn encode_frame(payload: &[u8]) -> bytes::Bytes {
    let mut hunk = Vec::with_capacity(payload.len() + 6);
    hunk.push(0x0A); // protobuf field 1, wire type 2 (LEN)
    put_varint(&mut hunk, payload.len() as u64);
    hunk.extend_from_slice(payload);

    let mut frame = Vec::with_capacity(hunk.len() + 5);
    frame.push(0x00); // gRPC compression flag: identity
    frame.extend_from_slice(&(hunk.len() as u32).to_be_bytes());
    frame.extend_from_slice(&hunk);
    bytes::Bytes::from(frame)
}

/// Pull one complete gRPC message out of `raw`, returning the concatenation of
/// every `Hunk`/`MultiHunk` field-1 chunk. `Ok(None)` means "need more bytes".
fn try_deframe(raw: &mut bytes::BytesMut) -> io::Result<Option<Vec<u8>>> {
    use bytes::Buf as _;
    if raw.len() < GRPC_PREFIX_LEN {
        return Ok(None);
    }
    if raw[0] != 0x00 {
        return Err(invalid("gRPC compressed messages are not supported"));
    }
    // The declared length is 32 bits and `usize` is 32 bits on armeabi-v7a,
    // which FoxCore ships. Both steps are therefore checked rather than assumed:
    // the conversion, and the addition of the five-byte prefix.
    let declared = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
    let length = usize::try_from(declared)
        .ok()
        .filter(|length| *length <= MAX_GRPC_MESSAGE_BYTES)
        .ok_or_else(|| invalid("gRPC message exceeded the bounded size"))?;
    let framed = GRPC_PREFIX_LEN
        .checked_add(length)
        .ok_or_else(|| invalid("gRPC message length overflows this platform"))?;
    if raw.len() < framed {
        return Ok(None);
    }
    raw.advance(GRPC_PREFIX_LEN);
    let message = raw.split_to(length);
    Ok(Some(parse_hunk(&message)?))
}

/// Concatenate every protobuf field-1 (LEN) chunk in a `Hunk`/`MultiHunk` body.
fn parse_hunk(message: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(message.len());
    let mut index = 0;
    while index < message.len() {
        if message[index] != 0x0A {
            return Err(invalid("unexpected protobuf field in gRPC Hunk"));
        }
        index += 1;
        let (length, consumed) =
            read_varint(&message[index..]).ok_or_else(|| invalid("truncated gRPC Hunk length"))?;
        index += consumed;
        // A protobuf varint is 64 bits wide and `usize` is not, on the 32-bit
        // Android ABI this core ships. `as usize` truncated it, so a chunk that
        // declared 2^32 + n bytes was read as n and the rest of the message was
        // parsed from the middle of a payload.
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| index.checked_add(length))
            .filter(|end| *end <= message.len())
            .ok_or_else(|| invalid("truncated gRPC Hunk payload"))?;
        out.extend_from_slice(&message[index..end]);
        index = end;
    }
    Ok(out)
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }
    None
}

fn build_path(service_name: &str, multi_mode: bool) -> String {
    let method = if multi_mode { "TunMulti" } else { "Tun" };
    let base = service_name.trim_end_matches('/');
    if base.starts_with('/') {
        format!("{base}/{method}")
    } else {
        format!("/{base}/{method}")
    }
}

const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// gRPC's compression flag plus the 32-bit message length.
const GRPC_PREFIX_LEN: usize = 5;
/// Largest application write that still fits one bounded gRPC message.
///
/// The `Hunk` wrapper adds a field tag and a varint, and the length that goes
/// on the wire is 32 bits: a longer write would be truncated by the cast, so it
/// is split instead. `poll_write` reports what it framed and the caller brings
/// the rest.
const MAX_APP_WRITE: usize = MAX_GRPC_MESSAGE_BYTES - 16;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Open a gRPC tunnel over `stream` (which must already be an HTTP/2-capable
/// byte stream: TLS with ALPN `h2`, or plaintext h2c).
///
/// Bounded as a whole. Every step below waits on the server — the HTTP/2
/// handshake, the connection becoming ready, and the response headers — and
/// none of them had a deadline, while TLS, WebSocket and httpupgrade all do.
/// The per-flow connect path has no outer timeout either, so a server that
/// finished TCP and TLS and then said nothing more pinned the flow task, its
/// tun-side socket, the outbound descriptor, the tracked-connection entry and
/// the detached HTTP/2 task — for as long as the engine lived. That is an
/// unbounded descriptor leak reachable by any endpoint that stalls.
pub(crate) async fn connect_grpc<S>(
    stream: S,
    service_name: &str,
    multi_mode: bool,
    authority: Option<&str>,
    server: &str,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_grpc_inner(stream, service_name, multi_mode, authority, server, tls),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC handshake timed out"))?
}

async fn connect_grpc_inner<S>(
    stream: S,
    service_name: &str,
    multi_mode: bool,
    authority: Option<&str>,
    server: &str,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (client, connection) = h2::client::handshake(stream).await.map_err(h2_io)?;
    // A detached task drives HTTP/2 I/O for this stream; it exits when the tunnel closes.
    std::mem::drop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut client = client.ready().await.map_err(h2_io)?;

    let scheme = if tls { "https" } else { "http" };
    let authority = authority.unwrap_or(server);
    let path = build_path(service_name, multi_mode);
    let uri: http::Uri = format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|error| invalid(format!("invalid gRPC uri: {error}")))?;
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .header(http::header::USER_AGENT, "grpc-go/1.62.0")
        .body(())
        .map_err(|error| invalid(format!("invalid gRPC request: {error}")))?;

    let (response, send) = client.send_request(request, false).map_err(h2_io)?;
    let response = response.await.map_err(h2_io)?;
    if response.status() != http::StatusCode::OK {
        return Err(invalid(format!(
            "gRPC server returned HTTP status {}",
            response.status()
        )));
    }
    Ok(Box::new(GrpcStream::new(send, response.into_body())))
}

fn h2_io(error: h2::Error) -> io::Error {
    io::Error::other(format!("gRPC/HTTP2: {error}"))
}

/// Adapts one gRPC bidirectional stream to `AsyncRead`/`AsyncWrite`: writes are
/// framed as `Hunk` messages, reads are de-framed and concatenated.
struct GrpcStream {
    send: h2::SendStream<bytes::Bytes>,
    recv: h2::RecvStream,
    write_pending: Option<bytes::Bytes>,
    inbound: bytes::BytesMut,
    raw: bytes::BytesMut,
    recv_eof: bool,
}

impl GrpcStream {
    fn new(send: h2::SendStream<bytes::Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            write_pending: None,
            inbound: bytes::BytesMut::new(),
            raw: bytes::BytesMut::new(),
            recv_eof: false,
        }
    }

    fn drive_send(
        &mut self,
        cx: &mut Context<'_>,
        frame: bytes::Bytes,
    ) -> io::Result<Option<bytes::Bytes>> {
        crate::h2io::drive_send(&mut self.send, cx, frame)
    }
}

impl AsyncRead for GrpcStream {
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
            if let Some(payload) = try_deframe(&mut self.raw)? {
                self.inbound.extend_from_slice(&payload);
                continue;
            }
            if self.recv_eof {
                // Everything decodable has been handed up by now, so whatever
                // is still in `raw` is the beginning of a message whose rest
                // never arrived. Reporting that as a clean end of stream told
                // the application the peer had finished talking, which is how a
                // connection cut mid-message became a short, plausible-looking
                // answer instead of an error.
                if !self.raw.is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "gRPC stream ended inside a message",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    self.raw.extend_from_slice(&data);
                    // Return the consumed window so the peer may keep sending.
                    let _ = self.recv.flow_control().release_capacity(len);
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_io(error))),
                Poll::Ready(None) => self.recv_eof = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = self.drive_send(cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Bounded before framing: the length prefix is 32 bits, so a longer
        // write would go out with a truncated length and a body the peer cannot
        // parse. `AsyncWrite` allows a short write, and the caller brings the
        // rest.
        let taken = buf.len().min(MAX_APP_WRITE);
        let frame = encode_frame(&buf[..taken]);
        if let Some(remaining) = self.drive_send(cx, frame)? {
            self.write_pending = Some(remaining);
        }
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = self.drive_send(cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = self.drive_send(cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        self.send
            .send_data(bytes::Bytes::new(), true)
            .map_err(h2_io)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn build_path_covers_single_multi_and_custom_forms() {
        assert_eq!(build_path("grpc", false), "/grpc/Tun");
        assert_eq!(build_path("GunService", true), "/GunService/TunMulti");
        assert_eq!(build_path("/full/service", false), "/full/service/Tun");
    }

    #[test]
    fn multi_hunk_message_concatenates_every_chunk() {
        // A MultiHunk with two field-1 chunks must de-frame to their concatenation.
        let mut body = Vec::new();
        for chunk in [b"aa".as_slice(), b"bbb".as_slice()] {
            body.push(0x0A);
            put_varint(&mut body, chunk.len() as u64);
            body.extend_from_slice(chunk);
        }
        let mut frame = vec![0x00];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        let mut raw = BytesMut::from(&frame[..]);
        assert_eq!(try_deframe(&mut raw).unwrap().unwrap(), b"aabbb");
    }

    #[test]
    fn frame_round_trips_through_deframe() {
        let frame = encode_frame(b"hello gun");
        let mut raw = BytesMut::from(&frame[..]);
        assert_eq!(try_deframe(&mut raw).unwrap().unwrap(), b"hello gun");
        assert!(try_deframe(&mut raw).unwrap().is_none());
    }

    /// A length header the platform cannot represent must be refused, not
    /// wrapped into a small one. On a 32-bit target `5 + length` used to be a
    /// wrapping add whose result was smaller than the bytes in hand, which put
    /// `split_to` past the end of the buffer.
    #[test]
    fn an_impossible_message_length_is_refused_rather_than_wrapped() {
        let mut raw = BytesMut::new();
        raw.extend_from_slice(&[0x00]);
        raw.extend_from_slice(&u32::MAX.to_be_bytes());
        raw.extend_from_slice(b"a few bytes");
        let error = try_deframe(&mut raw).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        // And the boundary itself: exactly at the cap is a length that is still
        // waiting for its body, one past it is refused.
        let mut at_limit = BytesMut::new();
        at_limit.extend_from_slice(&[0x00]);
        at_limit.extend_from_slice(&(MAX_GRPC_MESSAGE_BYTES as u32).to_be_bytes());
        assert!(try_deframe(&mut at_limit).unwrap().is_none());

        let mut over_limit = BytesMut::new();
        over_limit.extend_from_slice(&[0x00]);
        over_limit.extend_from_slice(&(MAX_GRPC_MESSAGE_BYTES as u32 + 1).to_be_bytes());
        assert!(try_deframe(&mut over_limit).is_err());
    }

    /// The inner `Hunk` length is a 64-bit varint, and `usize` is 32 bits on the
    /// Android ABI this core ships. Truncating it read a chunk that claimed
    /// `2^32 + n` bytes as one of `n`, and parsed the rest of the message out of
    /// the middle of a payload.
    #[test]
    fn a_hunk_length_that_does_not_fit_the_platform_is_refused() {
        let mut body = vec![0x0A];
        put_varint(&mut body, (1_u64 << 32) + 5);
        body.extend_from_slice(b"short");
        let error = parse_hunk(&body).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// A stream cut in the middle of a message is not the peer saying it has
    /// finished. It was reported as a clean end of stream, so a connection reset
    /// mid-answer reached the application as a short, well-formed-looking reply.
    #[tokio::test]
    async fn a_truncated_message_is_an_error_and_not_a_clean_close() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                // The request body stays alive for the whole test: dropping it
                // resets the stream, which the client would see instead of the
                // truncation under test.
                let handler = tokio::spawn(async move {
                    let _body = request.into_body();
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    // Half a message, then the end of the stream.
                    let whole = encode_frame(b"an answer that never finishes");
                    send.send_data(whole.slice(..12), false).unwrap();
                    send.send_data(bytes::Bytes::new(), true).unwrap();
                    std::future::pending::<()>().await;
                });
                while conn.accept().await.is_some() {}
                handler.abort();
            });

            let mut client = connect_grpc(
                client_io,
                "GunService",
                false,
                None,
                "server.example",
                false,
            )
            .await
            .expect("grpc connect");
            let mut sink = Vec::new();
            let error = client
                .read_to_end(&mut sink)
                .await
                .expect_err("a truncated message must not read as a clean close");
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            assert!(
                sink.is_empty(),
                "no part of an incomplete message may reach the application"
            );
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("the truncation test did not complete in time");
    }

    #[tokio::test]
    async fn grpc_gun_frames_round_trip_over_http2() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::POST);
                assert_eq!(request.uri().path(), "/GunService/Tun");
                assert_eq!(
                    request.headers()[http::header::CONTENT_TYPE],
                    "application/grpc"
                );
                let handler = tokio::spawn(async move {
                    let mut body = request.into_body();
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    let mut raw = BytesMut::new();
                    let payload = loop {
                        if let Some(payload) = try_deframe(&mut raw).unwrap() {
                            break payload;
                        }
                        let data = body.data().await.unwrap().unwrap();
                        let len = data.len();
                        raw.extend_from_slice(&data);
                        body.flow_control().release_capacity(len).unwrap();
                    };
                    assert_eq!(&payload, b"ping over grpc");
                    send.send_data(encode_frame(b"pong over grpc"), false)
                        .unwrap();
                    send.send_data(bytes::Bytes::new(), true).unwrap();
                });
                while conn.accept().await.is_some() {}
                handler.await.unwrap();
            });

            let mut client = connect_grpc(
                client_io,
                "GunService",
                false,
                None,
                "server.example",
                false,
            )
            .await
            .expect("grpc connect");
            client.write_all(b"ping over grpc").await.unwrap();
            client.flush().await.unwrap();
            let mut buf = vec![0u8; 14];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong over grpc");
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("grpc round trip did not complete in time");
    }
}
