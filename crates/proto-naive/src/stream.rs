//! Applies the NaiveProxy padding framing to a byte stream.
//!
//! Sits between the proxied application bytes and the HTTP/2 DATA frames, so
//! one `poll_write` becomes one padded frame — the same "one write, one frame"
//! relationship `NaivePaddingSocket::Write` has in the reference client.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::padding::{FIRST_PADDINGS, PaddingFramer};

/// Inbound scratch. Sized so a maximal frame (3 + 65535 + 255) rarely needs a
/// second round trip through the state machine.
const READ_SCRATCH: usize = 16 * 1024;

/// Source of per-frame padding sizes. Injectable so the wire format can be
/// asserted byte for byte in tests instead of only statistically.
pub(crate) type PaddingSizes = Box<dyn FnMut() -> u8 + Send>;

pub(crate) struct PaddedStream<S> {
    inner: S,
    framer: PaddingFramer,
    /// Encoded-but-not-yet-written frame bytes. Once a frame is built its
    /// payload is owned by this buffer, so the caller must never be told to
    /// resend it.
    pending: BytesMut,
    scratch: Box<[u8]>,
    decoded: BytesMut,
    padding_sizes: PaddingSizes,
}

impl<S> PaddedStream<S> {
    pub(crate) fn new(inner: S, padding_sizes: PaddingSizes) -> Self {
        Self {
            inner,
            framer: PaddingFramer::new(Some(FIRST_PADDINGS)),
            pending: BytesMut::new(),
            scratch: vec![0_u8; READ_SCRATCH].into_boxed_slice(),
            decoded: BytesMut::new(),
            padding_sizes,
        }
    }
}

impl<S> PaddedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_drain(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(context, &self.pending))?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write a NaiveProxy padded frame",
                )));
            }
            self.pending.advance(written);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for PaddedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.decoded.is_empty() {
                let take = this.decoded.len().min(buffer.remaining());
                buffer.put_slice(&this.decoded[..take]);
                this.decoded.advance(take);
                return Poll::Ready(Ok(()));
            }
            // Past the padded prefix every byte is payload, so hand the
            // caller's buffer straight to the transport.
            if this.framer.read_is_raw() {
                return Pin::new(&mut this.inner).poll_read(context, buffer);
            }

            let filled = {
                let mut scratch = ReadBuf::new(&mut this.scratch);
                ready!(Pin::new(&mut this.inner).poll_read(context, &mut scratch))?;
                scratch.filled().len()
            };
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
            // A frame may be pure padding, in which case `decoded` stays empty
            // and the loop reads again rather than reporting a false EOF.
            this.framer.read(&this.scratch[..filled], &mut this.decoded);
        }
    }
}

impl<S> AsyncWrite for PaddedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Drain first: returning `Pending` here is safe precisely because
        // nothing from `buffer` has been consumed yet.
        ready!(this.poll_drain(context))?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.framer.written_frames() >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(context, buffer);
        }

        let padding_size = (this.padding_sizes)();
        let consumed = this.framer.write(buffer, padding_size, &mut this.pending);
        // The frame now owns those bytes; a still-full transport just leaves
        // them in `pending` for the next flush.
        if let Poll::Ready(Err(error)) = this.poll_drain(context) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::padding::FRAME_HEADER_SIZE;

    /// Deterministic padding sizes, so the wire bytes are exact.
    fn fixed(sizes: &'static [u8]) -> PaddingSizes {
        let mut index = 0_usize;
        Box::new(move || {
            let size = sizes[index % sizes.len()];
            index += 1;
            size
        })
    }

    #[tokio::test]
    async fn the_first_eight_writes_are_padded_and_the_ninth_is_not() {
        let (client, mut server) = tokio::io::duplex(256 * 1024);
        let mut stream = PaddedStream::new(client, fixed(&[2]));

        for _ in 0..FIRST_PADDINGS {
            stream.write_all(b"ab").await.unwrap();
        }
        stream.write_all(b"raw").await.unwrap();
        stream.flush().await.unwrap();

        let framed = (FRAME_HEADER_SIZE + 2 + 2) * FIRST_PADDINGS as usize;
        let mut wire = vec![0_u8; framed + 3];
        server.read_exact(&mut wire).await.unwrap();
        for frame in wire[..framed].chunks(FRAME_HEADER_SIZE + 4) {
            assert_eq!(frame, b"\x00\x02\x02ab\x00\x00");
        }
        assert_eq!(&wire[framed..], b"raw");
    }

    #[tokio::test]
    async fn inbound_padding_is_stripped_and_never_surfaces_as_payload() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        framer.write(b"hello ", 40, &mut wire);
        framer.write(b"world", 0, &mut wire);
        server.write_all(&wire).await.unwrap();

        let mut stream = PaddedStream::new(client, fixed(&[0]));
        let mut received = [0_u8; 11];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello world");
    }

    #[tokio::test]
    async fn a_pure_padding_frame_is_not_mistaken_for_end_of_stream() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        framer.write(b"", 64, &mut wire);
        framer.write(b"after", 0, &mut wire);
        server.write_all(&wire).await.unwrap();

        let mut stream = PaddedStream::new(client, fixed(&[0]));
        let mut received = [0_u8; 5];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"after");
    }

    #[tokio::test]
    async fn inbound_framing_stops_after_eight_frames() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        for _ in 0..FIRST_PADDINGS {
            framer.write(b"p", 3, &mut wire);
        }
        wire.extend_from_slice(b"unframed-tail");
        server.write_all(&wire).await.unwrap();

        let mut stream = PaddedStream::new(client, fixed(&[0]));
        let mut received = vec![0_u8; FIRST_PADDINGS as usize + 13];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received.as_slice(), b"ppppppppunframed-tail");
    }

    #[tokio::test]
    async fn a_long_write_is_split_into_frames_that_fit_the_length_field() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let mut stream = PaddedStream::new(client, fixed(&[0]));
        let payload = vec![9_u8; 70_000];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();

        let mut header = [0_u8; 3];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [0xff, 0xff, 0x00]);
        let mut first = vec![0_u8; 65_535];
        server.read_exact(&mut first).await.unwrap();
        server.read_exact(&mut header).await.unwrap();
        // 70_000 - 65_535 == 4_465 == 17 * 256 + 113
        assert_eq!(header, [0x11, 0x71, 0x00]);
    }

    #[tokio::test]
    async fn a_full_round_trip_survives_the_padded_prefix() {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let echo = tokio::spawn(async move {
            let mut server = PaddedStream::new(server, fixed(&[17, 0, 255, 3]));
            let mut buffer = vec![0_u8; 4096];
            loop {
                match server.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if server.write_all(&buffer[..read]).await.is_err() {
                            break;
                        }
                        let _ = server.flush().await;
                    }
                }
            }
        });

        let mut client = PaddedStream::new(client, fixed(&[5, 200, 0, 31]));
        for index in 0..12_u8 {
            let message = vec![index; 64];
            client.write_all(&message).await.unwrap();
            client.flush().await.unwrap();
            let mut echoed = vec![0_u8; 64];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, message);
        }
        drop(client);
        echo.await.unwrap();
    }
}
