//! gRPC ("gun") carrier over HTTP/2.
//!
//! Proxy bytes ride inside a single bidirectional gRPC streaming RPC
//! (`<service>/Tun` or `/TunMulti`). Each write is wrapped as a length-prefixed
//! gRPC message carrying a protobuf `Hunk { bytes data = 1 }`; the reader
//! reassembles messages across HTTP/2 DATA frames and concatenates every field-1
//! chunk (so single `Hunk` and multi `MultiHunk` decode identically).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
        // A uint64 varint has only one value bit left in its tenth byte.
        // Shifting a larger terminal byte would silently discard its high
        // bits, turning an impossible length into a small accepted payload.
        if shift >= 64 || (shift == 63 && byte > 1) {
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
    if !service_name.starts_with('/') {
        let method = if multi_mode { "TunMulti" } else { "Tun" };
        return format!("/{}/{method}", escape_path_segment(service_name));
    }
    let last = service_name.rfind('/').unwrap_or(0);
    let service = &service_name[1..last.max(1)];
    let suffix = &service_name[last + 1..];
    let mut methods = suffix.split('|');
    let single = methods.next().unwrap_or_default();
    let method = if multi_mode {
        methods.next().unwrap_or(single)
    } else {
        single
    };
    let service = service
        .split('/')
        .map(escape_path_segment)
        .collect::<Vec<_>>()
        .join("/");
    format!("/{service}/{}", escape_path_segment(method))
}

// Go net/url.PathEscape for a path segment: '/', ';', ',' and '?' must not
// become path delimiters; UTF-8 and percent signs are escaped byte by byte.
fn escape_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        {
            escaped.push(char::from(byte));
        } else {
            escaped.push('%');
            escaped.push(char::from(HEX[usize::from(byte >> 4)]));
            escaped.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    escaped
}

#[derive(Default)]
pub(crate) struct GrpcOptions<'a> {
    pub rpc_path: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub idle_timeout_ms: u64,
    pub health_check_timeout_ms: u64,
    pub permit_without_stream: bool,
    pub initial_windows_size: u32,
}

fn user_agent(value: Option<&str>) -> Option<&str> {
    match value {
        None => Some("grpc-go/1.62.0"),
        Some("") => None,
        Some(raw) => Some(raw),
    }
}

const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// gRPC's compression flag plus the 32-bit message length.
const GRPC_PREFIX_LEN: usize = 5;
/// Limit outbound frames to 64 KiB, including Hunk and gRPC overhead.
/// Short writes let large application buffers cross peers with smaller message
/// budgets without changing the independent inbound limit.
const MAX_APP_WRITE: usize = 64 * 1024 - 16;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Open a gRPC tunnel over `stream` (which must already be an HTTP/2-capable
/// byte stream: TLS with ALPN `h2`, or plaintext h2c).
///
/// Connection setup has a finite deadline. Response headers are awaited by
/// the owned driver after returning the writable stream, because proxy peers
/// may require the first request message before they can produce a response.
#[cfg(test)]
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
    connect_grpc_with_options(
        stream,
        service_name,
        multi_mode,
        authority,
        server,
        tls,
        GrpcOptions::default(),
    )
    .await
}

pub(crate) async fn connect_grpc_with_options<S>(
    stream: S,
    service_name: &str,
    multi_mode: bool,
    authority: Option<&str>,
    server: &str,
    tls: bool,
    options: GrpcOptions<'_>,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Public carrier dispatch can also receive a directly constructed config;
    // reject values that would panic in h2 or overflow the timer before I/O.
    if options.initial_windows_size > 0x7fff_ffff
        || options.idle_timeout_ms > 86_400_000
        || options.health_check_timeout_ms > 86_400_000
    {
        return Err(invalid("gRPC window or timeout exceeds its bounded range"));
    }
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_grpc_inner(
            stream,
            service_name,
            multi_mode,
            authority,
            server,
            tls,
            options,
        ),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC handshake timed out"))?
}

#[derive(Clone, Copy)]
enum DriverFailure {
    Http2,
    HeadersTimedOut,
    HealthTimedOut,
}
impl DriverFailure {
    fn error(self) -> io::Error {
        match self {
            Self::Http2 => io::Error::other("gRPC/HTTP2 connection failed"),
            Self::HeadersTimedOut => {
                io::Error::new(io::ErrorKind::TimedOut, "gRPC response headers timed out")
            }
            Self::HealthTimedOut => {
                io::Error::new(io::ErrorKind::TimedOut, "gRPC health check timed out")
            }
        }
    }
}

struct DriverGuard(tokio::task::JoinHandle<()>);
impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Activity {
    changed: tokio::sync::Notify,
    stream_active: AtomicBool,
}
impl Activity {
    fn touch(&self) {
        self.changed.notify_one();
    }
}

// Keepalive measures bytes received by HTTP/2, including control frames.
// Application writes and reading already buffered payload cannot postpone it.
struct ObservedIo<S> {
    inner: S,
    activity: Arc<Activity>,
}
impl<S: AsyncRead + Unpin> AsyncRead for ObservedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type HeaderReply = tokio::sync::oneshot::Sender<io::Result<(h2::RecvStream, bool)>>;
struct HeaderJob {
    response: h2::client::ResponseFuture,
    reply: HeaderReply,
}

async fn drive_connection<S>(
    mut connection: h2::client::Connection<S, bytes::Bytes>,
    mut jobs: tokio::sync::oneshot::Receiver<HeaderJob>,
    activity: Arc<Activity>,
    failure: tokio::sync::watch::Sender<Option<DriverFailure>>,
    idle: Option<Duration>,
    health: Duration,
    permit_without_stream: bool,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut ping = connection.ping_pong();
    let mut job: Option<HeaderJob> = None;
    let mut job_received = false;
    let mut headers_deadline: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut idle_deadline = idle.map(|duration| Box::pin(tokio::time::sleep(duration)));
    let mut ping_deadline: Option<Pin<Box<tokio::time::Sleep>>> = None;
    loop {
        tokio::select! {
            result = &mut connection => {
                if result.is_err() || job.is_some() || !job_received {
                    let _ = failure.send(Some(DriverFailure::Http2));
                    if let Some(job) = job.take() { let _ = job.reply.send(Err(DriverFailure::Http2.error())); }
                }
                return;
            }
            received = &mut jobs, if !job_received => {
                job_received = true;
                let Ok(received) = received else { return; };
                job = Some(received);
                headers_deadline = Some(Box::pin(tokio::time::sleep(HANDSHAKE_TIMEOUT)));
            }
            response = async { (&mut job.as_mut().expect("guarded header job").response).await }, if job.is_some() => {
                let job = job.take().expect("guarded header job");
                headers_deadline = None;
                let result = response.map_err(h2_io).and_then(validate_response);
                if job.reply.send(result).is_err() { return; }
            }
            _ = async { headers_deadline.as_mut().expect("guarded deadline").await }, if headers_deadline.is_some() => {
                let _ = failure.send(Some(DriverFailure::HeadersTimedOut));
                if let Some(job) = job.take() { let _ = job.reply.send(Err(DriverFailure::HeadersTimedOut.error())); }
                return;
            }
            _ = activity.changed.notified(), if idle.is_some() => {
                if ping_deadline.is_none() {
                    idle_deadline = idle.map(|duration| Box::pin(tokio::time::sleep(duration)));
                }
            }
            _ = async { idle_deadline.as_mut().expect("guarded idle deadline").await }, if idle_deadline.is_some() && ping_deadline.is_none() => {
                if permit_without_stream || activity.stream_active.load(Ordering::Acquire) {
                    let Some(ping) = ping.as_mut() else { let _ = failure.send(Some(DriverFailure::Http2)); return; };
                    if ping.send_ping(h2::Ping::opaque()).is_err() { let _ = failure.send(Some(DriverFailure::Http2)); return; }
                    ping_deadline = Some(Box::pin(tokio::time::sleep(health)));
                } else {
                    idle_deadline = idle.map(|duration| Box::pin(tokio::time::sleep(duration)));
                }
            }
            pong = futures::future::poll_fn(|cx| ping.as_mut().expect("guarded ping").poll_pong(cx)), if ping_deadline.is_some() => {
                if pong.is_err() { let _ = failure.send(Some(DriverFailure::Http2)); return; }
                ping_deadline = None;
                idle_deadline = idle.map(|duration| Box::pin(tokio::time::sleep(duration)));
            }
            _ = async { ping_deadline.as_mut().expect("guarded ping deadline").await }, if ping_deadline.is_some() => {
                let _ = failure.send(Some(DriverFailure::HealthTimedOut));
                return;
            }
        }
    }
}

fn validate_response(
    response: http::Response<h2::RecvStream>,
) -> io::Result<(h2::RecvStream, bool)> {
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC peer refused the HTTP/2 request",
        ));
    }
    let mime = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !mime
        .is_some_and(|value| value == "application/grpc" || value.starts_with("application/grpc+"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC peer returned an incompatible content type",
        ));
    }
    let status_seen = rpc_status(response.headers())?;
    Ok((response.into_body(), status_seen))
}

fn rpc_status(headers: &http::HeaderMap) -> io::Result<bool> {
    if headers.get_all("grpc-status").iter().count() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC peer returned duplicate RPC status",
        ));
    }
    let Some(value) = headers.get("grpc-status") else {
        return Ok(false);
    };
    let status = value
        .to_str()
        .ok()
        .filter(|value| {
            !value.is_empty() && value.len() <= 2 && value.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value <= 16)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "gRPC peer returned an invalid RPC status",
            )
        })?;
    if status != 0 {
        let kind = if matches!(status, 7 | 16) {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::ConnectionAborted
        };
        return Err(io::Error::new(
            kind,
            format!("gRPC RPC failed with status {status}"),
        ));
    }
    Ok(true)
}

async fn connect_grpc_inner<S>(
    stream: S,
    service_name: &str,
    multi_mode: bool,
    authority: Option<&str>,
    server: &str,
    tls: bool,
    options: GrpcOptions<'_>,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut builder = h2::client::Builder::new();
    builder.max_header_list_size(16 * 1024);
    if options.initial_windows_size >= 65_535 {
        builder.initial_window_size(options.initial_windows_size);
    }
    let activity = Arc::new(Activity {
        changed: tokio::sync::Notify::new(),
        stream_active: AtomicBool::new(true),
    });
    let observed = ObservedIo {
        inner: stream,
        activity: activity.clone(),
    };
    let (client, connection) = builder.handshake(observed).await.map_err(h2_io)?;
    let (failure_tx, failure_rx) = tokio::sync::watch::channel(None);
    let (job_tx, job_rx) = tokio::sync::oneshot::channel();
    // Canonical milliseconds are exact. Xray's format importer applies its
    // own grpc-go minimum; Lite and Mihomo permit shorter positive intervals.
    let idle =
        (options.idle_timeout_ms > 0).then(|| Duration::from_millis(options.idle_timeout_ms));
    let health = Duration::from_millis(if options.health_check_timeout_ms == 0 {
        20_000
    } else {
        options.health_check_timeout_ms
    });
    let guard = DriverGuard(tokio::spawn(drive_connection(
        connection,
        job_rx,
        activity.clone(),
        failure_tx,
        idle,
        health,
        options.permit_without_stream,
    )));
    let mut client = client.ready().await.map_err(h2_io)?;
    let scheme = if tls { "https" } else { "http" };
    let authority = authority.unwrap_or(server);
    let derived = build_path(service_name, multi_mode);
    let path = options.rpc_path.unwrap_or(&derived);
    let uri: http::Uri = format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|_| invalid("invalid gRPC request URI"))?;
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers");
    if let Some(agent) = user_agent(options.user_agent) {
        request = request.header(http::header::USER_AGENT, agent);
    }
    let request = request
        .body(())
        .map_err(|_| invalid("invalid gRPC request headers"))?;
    let (response, send) = client.send_request(request, false).map_err(h2_io)?;
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    job_tx
        .send(HeaderJob {
            response,
            reply: reply_tx,
        })
        .map_err(|_| DriverFailure::Http2.error())?;
    // Do not wait for response headers: a VPN server must receive the protocol
    // header before it can produce them. The owned driver bounds that wait.
    Ok(Box::new(GrpcStream::new(
        send, reply_rx, failure_rx, guard, activity,
    )))
}

fn h2_io(_: h2::Error) -> io::Error {
    io::Error::other("gRPC/HTTP2 exchange failed")
}

/// Adapts one gRPC bidirectional stream to `AsyncRead`/`AsyncWrite`: writes are
/// framed as `Hunk` messages, reads are de-framed and concatenated.
struct GrpcStream {
    _driver: DriverGuard,
    send: h2::SendStream<bytes::Bytes>,
    recv: Option<h2::RecvStream>,
    headers: Option<tokio::sync::oneshot::Receiver<io::Result<(h2::RecvStream, bool)>>>,
    failure: tokio::sync::watch::Receiver<Option<DriverFailure>>,
    activity: Arc<Activity>,
    write_pending: Option<bytes::Bytes>,
    inbound: bytes::BytesMut,
    raw: bytes::BytesMut,
    recv_eof: bool,
    status_seen: bool,
    trailers_checked: bool,
    send_ended: bool,
}

impl GrpcStream {
    fn new(
        send: h2::SendStream<bytes::Bytes>,
        headers: tokio::sync::oneshot::Receiver<io::Result<(h2::RecvStream, bool)>>,
        failure: tokio::sync::watch::Receiver<Option<DriverFailure>>,
        driver: DriverGuard,
        activity: Arc<Activity>,
    ) -> Self {
        Self {
            _driver: driver,
            send,
            recv: None,
            headers: Some(headers),
            failure,
            activity,
            write_pending: None,
            inbound: bytes::BytesMut::new(),
            raw: bytes::BytesMut::new(),
            recv_eof: false,
            status_seen: false,
            trailers_checked: false,
            send_ended: false,
        }
    }

    fn poll_headers(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(failure) = *self.failure.borrow() {
            return Poll::Ready(Err(failure.error()));
        }
        if self.recv.is_some() {
            return Poll::Ready(Ok(()));
        }
        let Some(headers) = self.headers.as_mut() else {
            return Poll::Ready(Err(DriverFailure::Http2.error()));
        };
        match Pin::new(headers).poll(cx) {
            Poll::Ready(Ok(Ok((recv, status_seen)))) => {
                self.headers = None;
                self.recv = Some(recv);
                self.status_seen = status_seen;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Err(error))) => {
                self.headers = None;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(_)) => {
                self.headers = None;
                Poll::Ready(Err(DriverFailure::Http2.error()))
            }
            Poll::Pending => Poll::Pending,
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
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_headers(cx) {
            Poll::Ready(result) => result?,
            Poll::Pending => return Poll::Pending,
        }
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
                if !self.trailers_checked {
                    match self
                        .recv
                        .as_mut()
                        .expect("validated response")
                        .poll_trailers(cx)
                    {
                        Poll::Ready(Ok(trailers)) => {
                            if let Some(trailers) = trailers {
                                self.status_seen |= rpc_status(&trailers)?;
                            }
                            // The official sing-box Lite carrier ends a complete
                            // HTTP/2 body without grpc-status. Explicit RPC status
                            // remains authoritative and is checked above; DATA
                            // truncation and HTTP/2 errors never become clean EOF.
                            self.trailers_checked = true;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(h2_io(error))),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                if self.send_ended {
                    self.activity.stream_active.store(false, Ordering::Release);
                }
                return Poll::Ready(Ok(()));
            }
            match self
                .recv
                .as_mut()
                .expect("validated response")
                .poll_data(cx)
            {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    self.raw.extend_from_slice(&data);
                    // Return the consumed window so the peer may keep sending.
                    self.recv
                        .as_mut()
                        .expect("validated response")
                        .flow_control()
                        .release_capacity(len)
                        .map_err(h2_io)?;
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
        if let Poll::Ready(result) = self.poll_headers(cx) {
            result?;
        }
        if self.send_ended {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC request stream is closed",
            )));
        }
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
        if let Poll::Ready(result) = self.poll_headers(cx) {
            result?;
        }
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = self.drive_send(cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.send_ended {
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(result) = self.poll_headers(cx) {
            result?;
        }
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = self.drive_send(cx, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        self.send
            .send_data(bytes::Bytes::new(), true)
            .map_err(h2_io)?;
        self.send_ended = true;
        if self.recv_eof {
            self.activity.stream_active.store(false, Ordering::Release);
        }
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
        assert_eq!(build_path("/full/service", false), "/full/service");
    }

    #[test]
    fn grpc_paths_preserve_peer_defaults_escaping_and_custom_rpc_names() {
        assert_eq!(build_path("", false), "//Tun");
        assert_eq!(build_path("", true), "//TunMulti");
        assert_eq!(
            build_path("fox/name space?x#", false),
            "/fox%2Fname%20space%3Fx%23/Tun"
        );
        assert_eq!(build_path("名字", false), "/%E5%90%8D%E5%AD%97/Tun");
        assert_eq!(build_path("/full/service", false), "/full/service");
        assert_eq!(build_path("/full/single|multi", false), "/full/single");
        assert_eq!(build_path("/full/single|multi", true), "/full/multi");
        assert_eq!(build_path("/full/service/", false), "/full/service/");
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
    async fn grpc_rpc_error_trailers_are_not_a_clean_eof_or_a_secret_echo() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                let handler = tokio::spawn(async move {
                    let _body = request.into_body();
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", http::HeaderValue::from_static("16"));
                    trailers.insert(
                        "grpc-message",
                        http::HeaderValue::from_static("secret-node-must-not-leak"),
                    );
                    send.send_trailers(trailers).unwrap();
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
            .unwrap();
            let error = client
                .read_to_end(&mut Vec::new())
                .await
                .expect_err("a failed RPC must not appear as an ordinary empty response");
            assert!(!error.to_string().contains("secret-node-must-not-leak"));
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("RPC error test did not settle");
    }

    #[tokio::test]
    async fn grpc_can_send_the_proxy_header_before_response_headers_arrive() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                let handler = tokio::spawn(async move {
                    let mut body = request.into_body();
                    // A real streaming RPC may wait for RecvMsg before it can
                    // send headers or its first reply. The client must be able
                    // to transmit the VPN protocol header in that interval.
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
                    assert_eq!(payload, b"synthetic proxy header");
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(encode_frame(b"accepted"), false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                    send.send_trailers(trailers).unwrap();
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
            .unwrap();
            client.write_all(b"synthetic proxy header").await.unwrap();
            client.flush().await.unwrap();
            let mut reply = [0u8; 8];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"accepted");
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("client and server deadlocked before the first request message");
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
    // Official sing-box Lite finishes HTTP/2 without grpc-status trailers.
    // This is compatible only when every received Hunk is complete.
    async fn lite_eof_result(truncated: bool) -> io::Result<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                let handler = tokio::spawn(async move {
                    let _body = request.into_body();
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    let frame = encode_frame(b"Lite reply");
                    let frame = if truncated { frame.slice(..8) } else { frame };
                    send.send_data(frame, true).unwrap();
                    std::future::pending::<()>().await;
                });
                while conn.accept().await.is_some() {}
                handler.abort();
            });
            let mut client = connect_grpc(client_io, "", false, None, "peer.example", false)
                .await
                .unwrap();
            let mut reply = Vec::new();
            let result = client.read_to_end(&mut reply).await.map(|_| reply);
            drop(client);
            server.await.unwrap();
            result
        })
        .await
        .expect("Lite EOF fixture did not settle")
    }

    #[tokio::test]
    async fn grpc_lite_clean_eof_without_status_preserves_the_complete_reply() {
        assert_eq!(lite_eof_result(false).await.unwrap(), b"Lite reply");
    }

    #[tokio::test]
    async fn grpc_lite_truncated_eof_without_status_is_still_an_error() {
        assert_eq!(
            lite_eof_result(true).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn grpc_drop_terminates_the_owned_h2_driver_while_headers_are_pending() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let accepted = conn.accept().await.unwrap().unwrap();
                accepted_tx.send(()).unwrap();
                // No response headers: cancellation must close the carrier
                // rather than leave its connection task alive for 15 seconds.
                while conn.accept().await.is_some() {}
                drop(accepted);
            });
            let client = connect_grpc(client_io, "fox", false, None, "peer.example", false)
                .await
                .unwrap();
            accepted_rx.await.unwrap();
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("dropping the RPC left its owned driver running");
    }

    async fn wire_frame(peer: &mut tokio::io::DuplexStream) -> (u8, u8, Vec<u8>) {
        let mut header = [0u8; 9];
        peer.read_exact(&mut header).await.unwrap();
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        assert!(length <= 16 * 1024, "unbounded fixture frame");
        let mut body = vec![0; length];
        peer.read_exact(&mut body).await.unwrap();
        (header[3], header[4], body)
    }

    async fn driver_fixture(
        idle: Option<Duration>,
        health: Duration,
    ) -> (
        h2::client::SendRequest<bytes::Bytes>,
        tokio::io::DuplexStream,
        tokio::sync::oneshot::Sender<HeaderJob>,
        tokio::sync::watch::Receiver<Option<DriverFailure>>,
        DriverGuard,
    ) {
        let (client_io, mut peer) = tokio::io::duplex(64 * 1024);
        let (client, connection) = h2::client::handshake(client_io).await.unwrap();
        let activity = Arc::new(Activity {
            changed: tokio::sync::Notify::new(),
            stream_active: AtomicBool::new(true),
        });
        let (job_tx, job_rx) = tokio::sync::oneshot::channel();
        let (failure_tx, failure_rx) = tokio::sync::watch::channel(None);
        let guard = DriverGuard(tokio::spawn(drive_connection(
            connection, job_rx, activity, failure_tx, idle, health, false,
        )));
        let mut preface = [0u8; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let (kind, flags, _) = wire_frame(&mut peer).await;
        assert_eq!((kind, flags), (4, 0));
        // This raw peer controls PING acknowledgements instead of relying on
        // h2::server's automatic acknowledgement, so timeout is observable.
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
        peer.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.unwrap();
        let (kind, flags, _) = wire_frame(&mut peer).await;
        assert_eq!((kind, flags), (4, 1));
        (client, peer, job_tx, failure_rx, guard)
    }

    #[tokio::test]
    async fn grpc_driver_without_idle_settings_sends_no_health_ping() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (_client, mut peer, _job, failure, _guard) =
                driver_fixture(None, Duration::from_millis(250)).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), wire_frame(&mut peer))
                    .await
                    .is_err()
            );
            assert!(failure.borrow().is_none());
        })
        .await
        .expect("disabled timer fixture did not settle");
    }

    #[tokio::test]
    async fn grpc_driver_health_ping_times_out_without_an_ack() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (_client, mut peer, _job, mut failure, _guard) =
                driver_fixture(Some(Duration::from_millis(100)), Duration::from_millis(250)).await;
            let (kind, flags, ping) = wire_frame(&mut peer).await;
            assert_eq!((kind, flags, ping.len()), (6, 0, 8));
            failure.changed().await.unwrap();
            assert!(matches!(
                *failure.borrow(),
                Some(DriverFailure::HealthTimedOut)
            ));
            let mut byte = [0];
            assert_eq!(
                peer.read(&mut byte).await.unwrap(),
                0,
                "failed health check must close owned transport"
            );
        })
        .await
        .expect("health timeout fixture did not settle");
    }

    #[tokio::test]
    async fn grpc_driver_accepts_a_real_ping_ack_and_stays_live() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (_client, mut peer, _job, failure, _guard) =
                driver_fixture(Some(Duration::from_millis(100)), Duration::from_millis(250)).await;
            for _ in 0..3 {
                let (kind, flags, ping) = wire_frame(&mut peer).await;
                assert_eq!((kind, flags, ping.len()), (6, 0, 8));
                peer.write_all(&[0, 0, 8, 6, 1, 0, 0, 0, 0]).await.unwrap();
                peer.write_all(&ping).await.unwrap();
                assert!(failure.borrow().is_none());
            }
        })
        .await
        .expect("ping ACK fixture did not settle");
    }

    struct CaptureIo {
        inner: tokio::io::DuplexStream,
        written: Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl AsyncRead for CaptureIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for CaptureIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
            if let Poll::Ready(Ok(count)) = result {
                let mut written = self.written.lock().unwrap();
                assert!(
                    written.len() + count <= 128 * 1024,
                    "unbounded fixture capture"
                );
                written.extend_from_slice(&bytes[..count]);
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn grpc_exact_utf8_percent_path_authority_user_agent_and_window_reach_h2() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let written = Arc::new(std::sync::Mutex::new(Vec::new()));
            let io = CaptureIo {
                inner: client_io,
                written: written.clone(),
            };
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                assert_eq!(request.uri().path(), "/名字%raw%2Fservice/Tun");
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    "front.example:8443"
                );
                assert_eq!(request.uri().scheme_str(), Some("https"));
                assert_eq!(
                    request.headers()[http::header::USER_AGENT].as_bytes(),
                    "FoxHole/名字".as_bytes()
                );
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let _send = respond.send_response(response, false).unwrap();
                accepted_tx.send(()).unwrap();
                while conn.accept().await.is_some() {}
                drop(request);
            });
            let client = connect_grpc_with_options(
                io,
                "unused",
                false,
                Some("front.example:8443"),
                "origin.example",
                true,
                GrpcOptions {
                    rpc_path: Some("/名字%raw%2Fservice/Tun"),
                    user_agent: Some("FoxHole/名字"),
                    initial_windows_size: 131_072,
                    ..GrpcOptions::default()
                },
            )
            .await
            .unwrap();
            accepted_rx.await.unwrap();
            let wire = written.lock().unwrap().clone();
            assert!(wire.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
            let mut offset = 24;
            let mut window = None;
            while offset + 9 <= wire.len() {
                let length = (usize::from(wire[offset]) << 16)
                    | (usize::from(wire[offset + 1]) << 8)
                    | usize::from(wire[offset + 2]);
                if offset + 9 + length > wire.len() {
                    break;
                }
                if wire[offset + 3] == 4 && wire[offset + 4] == 0 {
                    for entry in wire[offset + 9..offset + 9 + length].chunks_exact(6) {
                        if u16::from_be_bytes([entry[0], entry[1]]) == 4 {
                            window = Some(u32::from_be_bytes(entry[2..6].try_into().unwrap()));
                        }
                    }
                }
                offset += 9 + length;
            }
            assert_eq!(window, Some(131_072));
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("exact option wire fixture did not settle");
    }

    #[test]
    fn grpc_canonical_user_agent_is_raw_and_alias_expansion_is_not_a_runtime_policy() {
        assert_eq!(user_agent(Some("chrome")), Some("chrome"));
        assert_eq!(user_agent(Some("edge")), Some("edge"));
        assert_eq!(user_agent(Some("firefox")), Some("firefox"));
        assert_eq!(user_agent(Some("golang")), Some("golang"));
        assert_eq!(user_agent(None), Some("grpc-go/1.62.0"));
        assert_eq!(user_agent(Some("")), None);
        assert_eq!(
            user_agent(Some("FoxHole custom/名字")),
            Some("FoxHole custom/名字")
        );
    }

    #[tokio::test]
    async fn grpc_direct_carrier_invalid_tuning_fails_before_any_peer_io() {
        for options in [
            GrpcOptions {
                initial_windows_size: u32::MAX,
                ..GrpcOptions::default()
            },
            GrpcOptions {
                idle_timeout_ms: u64::MAX,
                ..GrpcOptions::default()
            },
            GrpcOptions {
                health_check_timeout_ms: u64::MAX,
                ..GrpcOptions::default()
            },
        ] {
            let (client_io, mut peer) = tokio::io::duplex(64 * 1024);
            let error = match connect_grpc_with_options(
                client_io,
                "fox",
                false,
                None,
                "peer.example",
                false,
                options,
            )
            .await
            {
                Err(error) => error,
                Ok(_) => panic!("out-of-range tuning must fail"),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty(), "invalid tuning reached the peer");
        }
    }

    #[tokio::test]
    async fn grpc_pending_response_headers_have_a_finite_deadline() {
        tokio::time::timeout(HANDSHAKE_TIMEOUT + Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server_io).await.unwrap();
                let accepted = conn.accept().await.unwrap().unwrap();
                while conn.accept().await.is_some() {}
                drop(accepted);
            });
            let mut client = connect_grpc(client_io, "fox", false, None, "peer.example", false)
                .await
                .unwrap();
            client.write_all(b"synthetic proxy header").await.unwrap();
            client.flush().await.unwrap();
            let error = client
                .read(&mut [0u8; 1])
                .await
                .expect_err("a silent RPC cannot wait indefinitely");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("response-header deadline did not close its owned carrier");
    }

    #[tokio::test]
    async fn grpc_cancel_during_setup_releases_the_owned_io() {
        let (client_io, mut peer) = tokio::io::duplex(1);
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            connect_grpc(client_io, "fox", false, None, "peer.example", false),
        )
        .await;
        assert!(
            result.is_err(),
            "one-byte non-reading peer must stall the H2 preface"
        );
        let mut sent = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut sent))
            .await
            .expect("setup cancellation retained its transport")
            .unwrap();
        assert!(sent.len() <= 1);
    }

    async fn raw_carrier_fixture(
        options: GrpcOptions<'static>,
    ) -> (BoxStream, tokio::io::DuplexStream) {
        let (client_io, mut peer) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            connect_grpc_with_options(
                client_io,
                "fox",
                false,
                None,
                "peer.example",
                false,
                options,
            )
            .await
            .unwrap()
        });
        let mut preface = [0u8; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let (kind, flags, _) = wire_frame(&mut peer).await;
        assert_eq!((kind, flags), (4, 0));
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
        peer.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.unwrap();
        (client.await.unwrap(), peer)
    }

    async fn next_health_ping(peer: &mut tokio::io::DuplexStream) -> Vec<u8> {
        loop {
            let (kind, flags, body) = wire_frame(peer).await;
            if kind == 6 && flags == 0 {
                assert_eq!(body.len(), 8);
                return body;
            }
        }
    }

    #[tokio::test]
    async fn grpc_precise_short_idle_ping_is_not_postponed_by_outgoing_only_data() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client, mut peer) = raw_carrier_fixture(GrpcOptions {
                idle_timeout_ms: 60,
                health_check_timeout_ms: 120,
                ..GrpcOptions::default()
            })
            .await;
            let (mut reader, mut writer) = tokio::io::split(client);
            let writes = tokio::spawn(async move {
                for _ in 0..100 {
                    if writer.write_all(b"x").await.is_err() || writer.flush().await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            tokio::time::timeout(Duration::from_millis(500), next_health_ping(&mut peer))
                .await
                .expect("outgoing bytes masked a dead peer or canonical milliseconds were clamped");
            assert!(
                !writes.is_finished(),
                "fixture must still be sending when idle PING occurs"
            );
            let error = reader
                .read(&mut [0u8; 1])
                .await
                .expect_err("unacknowledged health PING must fail");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            drop(reader);
            writes.await.unwrap();
        })
        .await
        .expect("outgoing-only health fixture did not settle");
    }

    #[tokio::test]
    async fn grpc_incoming_h2_control_frames_reset_the_read_idle_deadline() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client, mut peer) = raw_carrier_fixture(GrpcOptions {
                idle_timeout_ms: 200,
                health_check_timeout_ms: 250,
                ..GrpcOptions::default()
            })
            .await;
            for value in 0u8..4 {
                peer.write_all(&[0, 0, 8, 6, 0, 0, 0, 0, 0]).await.unwrap();
                peer.write_all(&[value; 8]).await.unwrap();
                let ack = async {
                    loop {
                        let (kind, flags, body) = wire_frame(&mut peer).await;
                        assert!(
                            !(kind == 6 && flags == 0),
                            "inbound control traffic did not postpone read-idle PING"
                        );
                        if kind == 6 && flags == 1 {
                            assert_eq!(body, [value; 8]);
                            break;
                        }
                    }
                };
                tokio::time::timeout(Duration::from_millis(150), ack)
                    .await
                    .expect("incoming PING was not acknowledged");
                tokio::time::sleep(Duration::from_millis(70)).await;
            }
            tokio::time::timeout(Duration::from_millis(400), next_health_ping(&mut peer))
                .await
                .expect("read-idle PING did not resume when incoming frames stopped");
            drop(client);
        })
        .await
        .expect("read-idle activity fixture did not settle");
    }

    #[tokio::test]
    async fn grpc_canonical_alias_words_are_literal_http2_user_agent_values() {
        tokio::time::timeout(Duration::from_secs(3), async {
            for agent in ["firefox", "golang", ""] {
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                let server = tokio::spawn(async move {
                    let mut conn = h2::server::handshake(server_io).await.unwrap();
                    let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                    let actual = request
                        .headers()
                        .get(http::header::USER_AGENT)
                        .map(|value| value.as_bytes());
                    let expected = if agent.is_empty() {
                        None
                    } else {
                        Some(agent.as_bytes())
                    };
                    assert_eq!(actual, expected);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "0")
                        .body(())
                        .unwrap();
                    let _send = respond.send_response(response, true).unwrap();
                    while conn.accept().await.is_some() {}
                    drop(request);
                });
                let mut client = connect_grpc_with_options(
                    client_io,
                    "fox",
                    false,
                    None,
                    "peer.example",
                    false,
                    GrpcOptions {
                        user_agent: Some(agent),
                        ..GrpcOptions::default()
                    },
                )
                .await
                .unwrap();
                client.read_to_end(&mut Vec::new()).await.unwrap();
                drop(client);
                server.await.unwrap();
            }
        })
        .await
        .expect("raw canonical UA fixture did not settle");
    }

    #[test]
    fn grpc_hunk_varint_overflow_is_refused_and_maximum_uint64_is_preserved() {
        let mut maximum = vec![0xff; 9];
        maximum.push(0x01);
        assert_eq!(read_varint(&maximum), Some((u64::MAX, 10)));
        for terminal in [0x02, 0x7f, 0x80, 0xff] {
            let mut overflow = vec![0x80; 9];
            overflow.push(terminal);
            assert_eq!(
                read_varint(&overflow),
                None,
                "tenth byte must contain at most one value bit"
            );
            let mut hunk = vec![0x0a];
            hunk.extend_from_slice(&overflow);
            assert_eq!(
                parse_hunk(&hunk).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
