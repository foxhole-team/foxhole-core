//! DNS-only h3 I/O adapter. HTTP/3 and QPACK remain in upstream h3. Receive
//! handles stay in place across Pending so STOP_SENDING never dereferences a
//! moved-out stream. All stream reads have a separate bounded wire budget.
//!
//! Send-trait forwarding follows h3-quinn 0.0.10 (MIT); receive ownership and
//! cancellation differ. Original permission notice:
/*
Copyright (c) 2020 h3 authors

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};

const CANCEL: quinn::VarInt = quinn::VarInt::from_u32(0x10c);
const READ_CHUNK_BYTES: usize = 8192;
// Covers the 64 KiB DNS body, 16 KiB headers and trailers, framing and GREASE,
// before h3 can accumulate an attacker-declared unbounded frame.
const MAX_WIRE_BYTES: usize = 128 * 1024;

type BiFuture = Pin<
    Box<
        dyn Future<Output = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>
            + Send,
    >,
>;
type UniFuture =
    Pin<Box<dyn Future<Output = Result<quinn::RecvStream, quinn::ConnectionError>> + Send>>;

pub(super) struct Connection {
    open: OpenStreams,
    incoming_bi: Option<BiFuture>,
    incoming_uni: Option<UniFuture>,
}

pub(super) struct OpenStreams {
    upstream: h3_quinn::OpenStreams,
    raw: quinn::Connection,
    opening_bi: Option<BiFuture>,
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            upstream: self.upstream.clone(),
            raw: self.raw.clone(),
            opening_bi: None,
        }
    }
}

impl Connection {
    pub(super) fn new(raw: quinn::Connection) -> Self {
        let connection = h3_quinn::Connection::new(raw.clone());
        let upstream = quic::Connection::<Bytes>::opener(&connection);
        Self {
            open: OpenStreams {
                upstream,
                raw,
                opening_bi: None,
            },
            incoming_bi: None,
            incoming_uni: None,
        }
    }
}

pub(super) struct RecvStream {
    raw: quinn::RecvStream,
    id: StreamId,
    finished: bool,
    stopped: bool,
    wire_bytes: usize,
}

impl RecvStream {
    fn new(raw: quinn::RecvStream) -> Result<Self, StreamErrorIncoming> {
        let id = u64::from(raw.id())
            .try_into()
            .map_err(|_| internal_stream("invalid QUIC receive stream ID"))?;
        Ok(Self {
            raw,
            id,
            finished: false,
            stopped: false,
            wire_bytes: 0,
        })
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        if !self.finished && !self.stopped {
            let _ = self.raw.stop(CANCEL);
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut buffer = [0; READ_CHUNK_BYTES];
        match self.raw.poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => {
                self.finished = true;
                Poll::Ready(Ok(None))
            }
            Poll::Ready(Ok(length)) => {
                self.wire_bytes = self.wire_bytes.saturating_add(length);
                if self.wire_bytes > MAX_WIRE_BYTES {
                    let _ = self.raw.stop(CANCEL);
                    self.stopped = true;
                    return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                        io::Error::new(
                            io::ErrorKind::FileTooLarge,
                            "DNS HTTP/3 wire response exceeds bounded limit",
                        ),
                    ))));
                }
                Poll::Ready(Ok(Some(Bytes::copy_from_slice(&buffer[..length]))))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(read_error(error))),
        }
    }

    fn stop_sending(&mut self, code: u64) {
        let _ = self
            .raw
            .stop(quinn::VarInt::from_u64(code).unwrap_or(CANCEL));
        self.stopped = true;
    }
    fn recv_id(&self) -> StreamId {
        self.id
    }
}

pub(super) struct BidiStream {
    send: quinn::SendStream,
    receive: RecvStream,
    send_id: StreamId,
    writing: Option<WriteBuf<Bytes>>,
    sent_fin: bool,
    reset: bool,
}

impl BidiStream {
    fn new(
        (send, receive): (quinn::SendStream, quinn::RecvStream),
    ) -> Result<Self, StreamErrorIncoming> {
        let send_id = u64::from(send.id())
            .try_into()
            .map_err(|_| internal_stream("invalid QUIC send stream ID"))?;
        Ok(Self {
            send,
            receive: RecvStream::new(receive)?,
            send_id,
            writing: None,
            sent_fin: false,
            reset: false,
        })
    }
}

impl Drop for BidiStream {
    fn drop(&mut self) {
        if !self.sent_fin && !self.reset {
            let _ = self.send.reset(CANCEL);
        }
    }
}

impl quic::RecvStream for BidiStream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        quic::RecvStream::poll_data(&mut self.receive, cx)
    }
    fn stop_sending(&mut self, code: u64) {
        quic::RecvStream::stop_sending(&mut self.receive, code);
    }
    fn recv_id(&self) -> StreamId {
        self.receive.id
    }
}

impl quic::SendStream<Bytes> for BidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = &mut self.writing {
            while data.has_remaining() {
                match Pin::new(&mut self.send).poll_write(cx, data.chunk()) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(write_error(error))),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(internal_stream(
                            "DNS HTTP/3 write made no progress",
                        )));
                    }
                    Poll::Ready(Ok(length)) => data.advance(length),
                }
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(internal_stream("DNS HTTP/3 sender is not ready"));
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match quic::SendStream::<Bytes>::poll_ready(self, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        match self.send.finish() {
            Ok(()) => {
                self.sent_fin = true;
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(error)))),
        }
    }
    fn reset(&mut self, code: u64) {
        let _ = self
            .send
            .reset(quinn::VarInt::from_u64(code).unwrap_or(CANCEL));
        self.reset = true;
    }
    fn send_id(&self) -> StreamId {
        self.send_id
    }
}

impl quic::OpenStreams<Bytes> for OpenStreams {
    type BidiStream = BidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream, StreamErrorIncoming>> {
        if self.opening_bi.is_none() {
            let connection = self.raw.clone();
            self.opening_bi = Some(Box::pin(async move { connection.open_bi().await }));
        }
        let Some(opening) = self.opening_bi.as_mut() else {
            return Poll::Ready(Err(internal_stream("DNS HTTP/3 stream opener missing")));
        };
        let result = match opening.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.opening_bi = None;
        Poll::Ready(
            result
                .map_err(|error| StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: connection_error(error),
                })
                .and_then(BidiStream::new),
        )
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_send(&mut self.upstream, cx)
    }
    fn close(&mut self, code: Code, reason: &[u8]) {
        quic::OpenStreams::<Bytes>::close(&mut self.upstream, code, reason);
    }
}

impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = BidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.open, cx)
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_send(&mut self.open, cx)
    }
    fn close(&mut self, code: Code, reason: &[u8]) {
        quic::OpenStreams::<Bytes>::close(&mut self.open, code, reason);
    }
}

impl quic::Connection<Bytes> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RecvStream, ConnectionErrorIncoming>> {
        if self.incoming_uni.is_none() {
            let connection = self.open.raw.clone();
            self.incoming_uni = Some(Box::pin(async move { connection.accept_uni().await }));
        }
        let Some(accepting) = self.incoming_uni.as_mut() else {
            return Poll::Ready(Err(ConnectionErrorIncoming::InternalError(
                "DNS HTTP/3 uni receiver missing".into(),
            )));
        };
        let result = match accepting.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.incoming_uni = None;
        Poll::Ready(result.map_err(connection_error).and_then(|stream| {
            RecvStream::new(stream).map_err(|_| {
                ConnectionErrorIncoming::InternalError(
                    "DNS HTTP/3 receive stream ID invalid".into(),
                )
            })
        }))
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<BidiStream, ConnectionErrorIncoming>> {
        if self.incoming_bi.is_none() {
            let connection = self.open.raw.clone();
            self.incoming_bi = Some(Box::pin(async move { connection.accept_bi().await }));
        }
        let Some(accepting) = self.incoming_bi.as_mut() else {
            return Poll::Ready(Err(ConnectionErrorIncoming::InternalError(
                "DNS HTTP/3 bidi receiver missing".into(),
            )));
        };
        let result = match accepting.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.incoming_bi = None;
        Poll::Ready(result.map_err(connection_error).and_then(|streams| {
            BidiStream::new(streams).map_err(|_| {
                ConnectionErrorIncoming::InternalError("DNS HTTP/3 bidi stream ID invalid".into())
            })
        }))
    }
    fn opener(&self) -> OpenStreams {
        self.open.clone()
    }
}

fn internal_stream(message: &'static str) -> StreamErrorIncoming {
    StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: ConnectionErrorIncoming::InternalError(message.into()),
    }
}
fn connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: close.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        error => ConnectionErrorIncoming::Undefined(Arc::new(error)),
    }
}
fn read_error(error: quinn::ReadError) -> StreamErrorIncoming {
    match error {
        quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into(),
        },
        quinn::ReadError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: connection_error(error),
        },
        error => StreamErrorIncoming::Unknown(Box::new(error)),
    }
}
fn write_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into(),
        },
        quinn::WriteError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: connection_error(error),
        },
        error => StreamErrorIncoming::Unknown(Box::new(error)),
    }
}
