//! A stream that serves already-buffered bytes before touching the socket.
//!
//! A CONNECT response head and the first tunnel bytes routinely arrive in the
//! same TCP segment. Without this the reader would have consumed those bytes
//! into the header buffer and then read from the socket again, silently losing
//! the peer's first payload.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct LeftoverStream<S> {
    inner: S,
    leftover: Bytes,
}

impl<S> LeftoverStream<S> {
    pub(crate) fn new(inner: S, leftover: Bytes) -> Self {
        Self { inner, leftover }
    }
}

impl<S> AsyncRead for LeftoverStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.leftover.is_empty() {
            let take = self.leftover.len().min(buffer.remaining());
            buffer.put_slice(&self.leftover[..take]);
            self.leftover.advance(take);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S> AsyncWrite for LeftoverStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn buffered_bytes_come_first_then_the_socket() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = LeftoverStream::new(client, Bytes::from_static(b"early"));
        server.write_all(b"late").await.unwrap();

        let mut received = [0_u8; 9];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"earlylate");
    }

    #[tokio::test]
    async fn a_short_read_buffer_drains_the_leftover_across_calls() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = LeftoverStream::new(client, Bytes::from_static(b"abcdef"));
        server.write_all(b"gh").await.unwrap();

        let mut first = [0_u8; 2];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"ab");
        let mut rest = [0_u8; 6];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"cdefgh");
    }

    #[tokio::test]
    async fn writes_go_straight_to_the_inner_stream() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = LeftoverStream::new(client, Bytes::new());
        stream.write_all(b"payload").await.unwrap();
        stream.flush().await.unwrap();

        let mut received = [0_u8; 7];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"payload");
    }
}
