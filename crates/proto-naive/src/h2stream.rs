//! `AsyncRead`/`AsyncWrite` over the request/response body of one HTTP/2
//! CONNECT stream.
//!
//! This duplicates `foxcore-transport`'s private `Http2Stream`/`drive_send`.
//! Neither is exported today and neither speaks CONNECT, so the choice was
//! between copying ~120 lines or editing another crate's public surface. See
//! the crate docs for the exports that would let this file disappear.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) fn h2_io(error: h2::Error) -> io::Error {
    io::Error::other(format!("HTTP/2: {error}"))
}

/// Push as much of `frame` into the HTTP/2 send window as capacity allows,
/// returning the not-yet-sent remainder when the window is momentarily full.
fn drive_send(
    send: &mut SendStream<Bytes>,
    context: &mut Context<'_>,
    mut frame: Bytes,
) -> io::Result<Option<Bytes>> {
    send.reserve_capacity(frame.len());
    loop {
        if frame.is_empty() {
            return Ok(None);
        }
        let capacity = send.capacity();
        if capacity == 0 {
            return match send.poll_capacity(context) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => Err(h2_io(error)),
                Poll::Ready(None) => Err(io::Error::other("HTTP/2 send stream closed")),
                Poll::Pending => Ok(Some(frame)),
            };
        }
        let take = capacity.min(frame.len());
        send.send_data(frame.split_to(take), false).map_err(h2_io)?;
    }
}

pub(crate) struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    write_pending: Option<Bytes>,
    inbound: BytesMut,
    recv_eof: bool,
}

impl H2Stream {
    pub(crate) fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            write_pending: None,
            inbound: BytesMut::new(),
            recv_eof: false,
        }
    }

    fn poll_pending(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(frame) = self.write_pending.take()
            && let Some(remaining) = drive_send(&mut self.send, context, frame)?
        {
            self.write_pending = Some(remaining);
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.inbound.is_empty() {
                let take = self.inbound.len().min(buffer.remaining());
                buffer.put_slice(&self.inbound[..take]);
                self.inbound.advance(take);
                return Poll::Ready(Ok(()));
            }
            if self.recv_eof {
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(context) {
                Poll::Ready(Some(Ok(data))) => {
                    let length = data.len();
                    self.inbound.extend_from_slice(&data);
                    // Releasing capacity is what keeps the peer's window open;
                    // skipping it stalls the tunnel after 64 KiB.
                    let _ = self.recv.flow_control().release_capacity(length);
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_io(error))),
                Poll::Ready(None) => self.recv_eof = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_pending.is_some() {
            match self.poll_pending(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let frame = Bytes::copy_from_slice(buffer);
        if let Some(remaining) = drive_send(&mut self.send, context, frame)? {
            self.write_pending = Some(remaining);
        }
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_pending(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending(context) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        self.send.send_data(Bytes::new(), true).map_err(h2_io)?;
        Poll::Ready(Ok(()))
    }
}
