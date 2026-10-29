//! Xray XHTTP stream-one over HTTP/2, with raw bidirectional DATA bodies.
//! The default Referer padding is required by the peer, even in stream-one.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_CHUNK_BYTES: usize = 16 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct ConnectionTask(tokio::task::JoinHandle<()>);

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn connect_xhttp<S>(
    stream: S,
    path: &str,
    host: Option<&str>,
    server: &str,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_inner(stream, path, host.unwrap_or(server), tls),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "XHTTP handshake timed out"))?
}

async fn connect_inner<S>(
    stream: S,
    path: &str,
    authority: &str,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let authority = if matches!(
        authority.parse::<std::net::IpAddr>(),
        Ok(std::net::IpAddr::V6(_))
    ) {
        format!("[{authority}]")
    } else {
        authority.to_owned()
    };
    let scheme = if tls { "https" } else { "http" };
    let (raw_path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut normalized = raw_path.to_owned();
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    let mut uri = format!("{scheme}://{authority}{normalized}");
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(query);
    }
    let uri: http::Uri = uri.parse().map_err(|_| invalid("invalid XHTTP URI"))?;
    let mut random = [0_u8; 2];
    getrandom::fill(&mut random)
        .map_err(|_| io::Error::other("XHTTP padding entropy unavailable"))?;
    let padding = "X".repeat(100 + usize::from(u16::from_le_bytes(random)) % 901);
    let referer = format!("{scheme}://{authority}{normalized}?x_padding={padding}");
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::REFERER, referer)
        .body(())
        .map_err(|_| invalid("invalid XHTTP request"))?;

    let (client, connection) = h2::client::handshake(stream)
        .await
        .map_err(crate::h2io::h2_io)?;
    let driver = ConnectionTask(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut client = client.ready().await.map_err(crate::h2io::h2_io)?;
    let (response, send) = client
        .send_request(request, false)
        .map_err(crate::h2io::h2_io)?;
    let response = response.await.map_err(crate::h2io::h2_io)?;
    if response.status() != http::StatusCode::OK {
        return Err(invalid("XHTTP peer returned a non-200 status"));
    }
    Ok(Box::new(XhttpStream {
        inner: crate::http2::Http2Stream::new(send, response.into_body()),
        _driver: driver,
    }))
}

struct XhttpStream {
    inner: crate::http2::Http2Stream,
    _driver: ConnectionTask,
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, &buf[..buf.len().min(WRITE_CHUNK_BYTES)])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
