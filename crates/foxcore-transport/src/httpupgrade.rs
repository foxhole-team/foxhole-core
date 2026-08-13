//! Plain HTTP/1.1 `Upgrade` carrier (`httpupgrade`).
//!
//! Borrows the HTTP/1.1 `Upgrade` handshake (and even the literal `Upgrade:
//! websocket` token) to pass CDNs, but after the `101` the connection is a raw
//! bidirectional byte pipe with **no** RFC 6455 framing or masking. Any bytes the
//! server buffers immediately after the response headers are surfaced first.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use foxcore_api::SecretString;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::BoxStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// Run the HTTP/1.1 `Upgrade` handshake over `stream`, then hand back a raw byte
/// carrier. Fails closed unless the server answers `101` with `Connection:
/// upgrade` and `Upgrade: websocket`; it never downgrades to a plain stream.
pub(crate) async fn connect_http_upgrade<S>(
    mut stream: S,
    path: &str,
    host: Option<&str>,
    headers: &BTreeMap<String, SecretString>,
    server: &str,
    port: u16,
    tls: bool,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let host_header = host
        .map(str::to_owned)
        .unwrap_or_else(|| authority(server, port, tls));

    let mut request = String::with_capacity(128);
    request.push_str("GET ");
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(&host_header);
    request.push_str("\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value.expose());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    let (stream, leftover) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut buffer = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            if let Some(position) = find_subsequence(&buffer, b"\r\n\r\n") {
                break position + 4;
            }
            if buffer.len() > MAX_RESPONSE_HEADER_BYTES {
                return Err(invalid("httpupgrade response headers exceeded 16 KiB"));
            }
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(invalid(
                    "httpupgrade server closed before 101 Switching Protocols",
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
        };
        validate_upgrade_response(&buffer[..header_end])?;
        let leftover = buffer.split_off(header_end);
        Ok::<(S, Vec<u8>), io::Error>((stream, leftover))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "httpupgrade handshake timed out"))??;

    Ok(Box::new(HttpUpgradeStream::new(stream, leftover)))
}

fn validate_upgrade_response(head: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(head)
        .map_err(|_| invalid("httpupgrade response headers are not valid UTF-8"))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("101") {
        return Err(invalid(format!(
            "httpupgrade expected 101 Switching Protocols, got '{status}'"
        )));
    }
    let mut connection_upgrade = false;
    let mut upgrade_websocket = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "connection" => {
                connection_upgrade |= value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
            }
            "upgrade" => {
                upgrade_websocket |= value.trim().eq_ignore_ascii_case("websocket");
            }
            _ => {}
        }
    }
    if !connection_upgrade || !upgrade_websocket {
        return Err(invalid(
            "httpupgrade response is missing Connection: upgrade / Upgrade: websocket",
        ));
    }
    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

/// A raw byte carrier that first drains the bytes the server sent right after the
/// `101` response, then delegates to the underlying connection.
struct HttpUpgradeStream<S> {
    inner: S,
    leftover: Vec<u8>,
    offset: usize,
}

impl<S> HttpUpgradeStream<S> {
    fn new(inner: S, leftover: Vec<u8>) -> Self {
        Self {
            inner,
            leftover,
            offset: 0,
        }
    }
}

impl<S> AsyncRead for HttpUpgradeStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.leftover.len() {
            let remaining = &self.leftover[self.offset..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.offset += take;
            if self.offset >= self.leftover.len() {
                self.leftover = Vec::new();
                self.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for HttpUpgradeStream<S>
where
    S: AsyncWrite + Unpin,
{
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use foxcore_api::{SecretString, StreamTransportConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::wrap_stream_transport;

    #[tokio::test]
    async fn http_upgrade_handshakes_then_streams_raw_bytes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let read = server_io.read(&mut tmp).await.unwrap();
                    assert!(read > 0, "client closed before completing the handshake");
                    buf.extend_from_slice(&tmp[..read]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let head = head.split("\r\n\r\n").next().unwrap();
                assert!(head.starts_with("GET /tunnel HTTP/1.1"), "request line: {head}");
                let lower = head.to_ascii_lowercase();
                assert!(lower.contains("\r\nhost: cdn.example"), "missing Host: {head}");
                assert!(lower.contains("\r\nconnection: upgrade"), "missing Connection");
                assert!(lower.contains("\r\nupgrade: websocket"), "missing Upgrade");
                assert!(lower.contains("\r\nx-foxhole-test: bounded"), "missing custom header");
                assert!(
                    !lower.contains("sec-websocket-key"),
                    "httpupgrade must not send a WebSocket key"
                );

                server_io
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
                    )
                    .await
                    .unwrap();

                let mut payload = [0u8; 12];
                server_io.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"client bytes");
                server_io.write_all(b"server bytes").await.unwrap();
            });

            let mut headers = BTreeMap::new();
            headers.insert("x-foxhole-test".to_string(), SecretString::new("bounded"));
            let transport = StreamTransportConfig::HttpUpgrade {
                path: "/tunnel".into(),
                host: Some("cdn.example".into()),
                headers,
            };
            let mut client =
                wrap_stream_transport(client_io, &transport, "server.example", 80, false)
                    .await
                    .expect("http_upgrade handshake");
            client.write_all(b"client bytes").await.unwrap();
            let mut response = [0u8; 12];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"server bytes");
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("http_upgrade handshake did not complete in time");
    }

    #[tokio::test]
    async fn http_upgrade_surfaces_bytes_buffered_with_the_101_response() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let read = server_io.read(&mut tmp).await.unwrap();
                    assert!(read > 0, "client closed before completing the handshake");
                    buf.extend_from_slice(&tmp[..read]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let head = head.split("\r\n\r\n").next().unwrap();
                // host=None with tls+443 derives the authority without a default port.
                assert!(head.contains("\r\nHost: server.example\r\n"), "host header: {head}");
                // The 101 response and the first payload arrive in a single write; the
                // client must surface the payload, not swallow it with the headers.
                server_io
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nearly-server-bytes",
                    )
                    .await
                    .unwrap();
            });

            let transport = StreamTransportConfig::HttpUpgrade {
                path: "/".into(),
                host: None,
                headers: BTreeMap::new(),
            };
            let mut client =
                wrap_stream_transport(client_io, &transport, "server.example", 443, true)
                    .await
                    .expect("http_upgrade handshake");
            let mut response = [0u8; 18];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"early-server-bytes");
            drop(client);
            server.await.unwrap();
        })
        .await
        .expect("http_upgrade leftover drain did not complete in time");
    }
}
