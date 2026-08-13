//! Shared HTTP/2 send-side flow control for the gRPC and HTTP/2 transports.

use std::io;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::SendStream;

pub(crate) fn h2_io(error: h2::Error) -> io::Error {
    io::Error::other(format!("HTTP/2: {error}"))
}

/// Push as much of `frame` into the HTTP/2 send window as capacity allows,
/// returning the not-yet-sent remainder when the window is momentarily full.
pub(crate) fn drive_send(
    send: &mut SendStream<Bytes>,
    cx: &mut Context<'_>,
    mut frame: Bytes,
) -> io::Result<Option<Bytes>> {
    send.reserve_capacity(frame.len());
    loop {
        if frame.is_empty() {
            return Ok(None);
        }
        let capacity = send.capacity();
        if capacity == 0 {
            return match send.poll_capacity(cx) {
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
