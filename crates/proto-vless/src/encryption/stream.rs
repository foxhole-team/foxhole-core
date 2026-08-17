//! The record layer that carries the inner VLESS protocol.
//!
//! Upstream's `CommonConn`. Records look exactly like TLS 1.3 application data
//! — `23 03 03` and a big-endian length — and the header is the AEAD's
//! additional data, so there is no separately encrypted length field the way
//! Shadowsocks 2022 has one. That is where upstream's throughput claim comes
//! from, and it is also why a wrong length simply fails to authenticate instead
//! of being detected separately.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Instant;

use foxcore_transport::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead::{Aead, MAX_RECORD_PLAINTEXT, TAG_LEN, decode_header, encode_header};
use super::crypto::PFS_KEY_LEN;
use super::xor::XorState;

/// A 0-RTT ticket and the forward-secret key it stands for.
#[derive(Clone)]
pub struct CachedSession {
    pub expire: Instant,
    pub pfs_key: [u8; PFS_KEY_LEN],
    pub ticket: [u8; 16],
}

/// Shared across every connection of one outbound, which is what makes 0-RTT
/// possible: the first connection pays for the exchange and the rest reuse it
/// until the server-chosen lifetime runs out.
#[derive(Default)]
pub struct SessionCache {
    inner: Mutex<Option<CachedSession>>,
}

impl SessionCache {
    pub fn get(&self) -> Option<CachedSession> {
        let guard = self.inner.lock().ok()?;
        let session = guard.as_ref()?;
        (Instant::now() < session.expire).then(|| session.clone())
    }

    pub fn store(&self, session: CachedSession) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = Some(session);
        }
    }

    /// Drop the cached session if it is still the one `pfs_key` came from.
    ///
    /// Guarded on identity rather than cleared outright so a connection that
    /// discovers an expired ticket cannot throw away a *newer* session another
    /// connection has meanwhile negotiated.
    pub fn expire_if_matches(&self, pfs_key: &[u8; PFS_KEY_LEN]) {
        if let Ok(mut guard) = self.inner.lock()
            && guard.as_ref().is_some_and(|s| &s.pfs_key == pfs_key)
        {
            *guard = None;
        }
    }
}

enum ReadState {
    /// 0-RTT: the server opens with 16 random bytes that key this direction.
    ServerRandom,
    /// 1-RTT: the server's padding, which it is allowed to send slowly.
    Padding(usize),
    Header,
    Body([u8; 5], usize),
    Serve,
}

pub struct EncryptedStream {
    inner: BoxStream,
    use_aes: bool,
    united_key: Vec<u8>,
    aead: Aead,
    peer_aead: Option<Aead>,
    xor: Option<XorState>,
    /// Prepended to the first record. Upstream insists the handshake prefix and
    /// the first data record leave in a single write, so their combined length
    /// carries no fixed signature.
    pre_write: Option<Vec<u8>>,
    /// Set while this connection is still the 0-RTT gamble; cleared once the
    /// server has answered with something that authenticates.
    zero_rtt: Option<(Arc<SessionCache>, [u8; PFS_KEY_LEN])>,

    out: Vec<u8>,
    out_pos: usize,

    read_state: ReadState,
    read_buf: Vec<u8>,
    read_need: usize,
    plain: Vec<u8>,
    plain_pos: usize,
}

pub struct StreamParts {
    pub inner: BoxStream,
    pub use_aes: bool,
    pub united_key: Vec<u8>,
    pub aead: Aead,
    pub peer_aead: Option<Aead>,
    pub xor: Option<XorState>,
    pub pre_write: Option<Vec<u8>>,
    pub peer_padding: Option<usize>,
    pub zero_rtt: Option<(Arc<SessionCache>, [u8; PFS_KEY_LEN])>,
}

impl EncryptedStream {
    pub fn new(parts: StreamParts) -> Self {
        let read_state = if parts.peer_aead.is_none() {
            ReadState::ServerRandom
        } else if let Some(length) = parts.peer_padding {
            ReadState::Padding(length)
        } else {
            ReadState::Header
        };
        Self {
            inner: parts.inner,
            use_aes: parts.use_aes,
            united_key: parts.united_key,
            aead: parts.aead,
            peer_aead: parts.peer_aead,
            xor: parts.xor,
            pre_write: parts.pre_write,
            zero_rtt: parts.zero_rtt,
            out: Vec::new(),
            out_pos: 0,
            read_state,
            read_buf: Vec::new(),
            read_need: 0,
            plain: Vec::new(),
            plain_pos: 0,
        }
    }

    /// Read until `read_need` bytes are buffered, unmasking each chunk as it
    /// arrives so the keystream advances in wire order.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            read_buf,
            read_need,
            xor,
            ..
        } = self;
        while read_buf.len() < *read_need {
            let start = read_buf.len();
            read_buf.resize(*read_need, 0);
            let mut slot = ReadBuf::new(&mut read_buf[start..]);
            let result = Pin::new(&mut *inner).poll_read(cx, &mut slot);
            let filled = slot.filled().len();
            match result {
                Poll::Pending => {
                    read_buf.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => {
                    read_buf.truncate(start);
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) => {
                    read_buf.truncate(start + filled);
                    if filled == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS encryption stream ended mid-record",
                        )));
                    }
                    if let Some(xor) = xor.as_mut() {
                        xor.unmask_inbound(&mut read_buf[start..start + filled]);
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VLESS encryption stream refused a record",
                    )));
                }
                Poll::Ready(Ok(written)) => self.out_pos += written,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Frame one record and stage it for writing.
    fn frame(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut record = vec![0_u8; 5 + plaintext.len() + TAG_LEN];
        let mut header = [0_u8; 5];
        encode_header(&mut header, plaintext.len() + TAG_LEN);
        record[..5].copy_from_slice(&header);
        record[5..5 + plaintext.len()].copy_from_slice(plaintext);

        // The rekey decision is taken before sealing, because sealing is what
        // advances the counter past the wrap.
        let rekey = self.aead.at_max_nonce();
        let (head, body) = record.split_at_mut(5);
        self.aead.seal_in_place(head, body, plaintext.len())?;
        if rekey {
            self.aead = Aead::new(&record, &self.united_key, self.use_aes);
        }

        if let Some(prefix) = self.pre_write.take() {
            let mut combined = prefix;
            combined.extend_from_slice(&record);
            record = combined;
        }
        if let Some(xor) = self.xor.as_mut() {
            xor.mask_outbound(&mut record);
        }
        debug_assert!(self.out.is_empty());
        self.out = record;
        self.out_pos = 0;
        Ok(())
    }
}

impl AsyncRead for EncryptedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.read_state {
                ReadState::ServerRandom => {
                    this.read_need = 16;
                    ready!(this.poll_fill(cx))?;
                    let mut random = [0_u8; 16];
                    random.copy_from_slice(&this.read_buf);
                    this.read_buf.clear();
                    this.peer_aead = Some(Aead::new(&random, &this.united_key, this.use_aes));
                    if let Some(xor) = this.xor.as_mut() {
                        xor.set_peer_iv(&this.united_key, &random);
                    }
                    this.read_state = ReadState::Header;
                }
                ReadState::Padding(length) => {
                    this.read_need = length;
                    ready!(this.poll_fill(cx))?;
                    let mut padding = std::mem::take(&mut this.read_buf);
                    let peer = this.peer_aead.as_mut().expect("padding implies a peer key");
                    peer.open_in_place(&[], &mut padding)?;
                    this.read_state = ReadState::Header;
                }
                ReadState::Header => {
                    this.read_need = 5;
                    ready!(this.poll_fill(cx))?;
                    let mut header = [0_u8; 5];
                    header.copy_from_slice(&this.read_buf);
                    this.read_buf.clear();
                    let Some(length) = decode_header(&header) else {
                        // A 0-RTT client whose ticket the server no longer
                        // knows is answered with a stream of noise, on purpose:
                        // there is nothing to distinguish and nothing to reply
                        // to. Dropping the cached session turns the caller's
                        // retry into a fresh 1-RTT exchange.
                        if let Some((cache, pfs_key)) = this.zero_rtt.take() {
                            cache.expire_if_matches(&pfs_key);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                "VLESS encryption 0-RTT ticket was not accepted; a new handshake is needed",
                            )));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "VLESS encryption record header is not well formed",
                        )));
                    };
                    // The server has authenticated itself from here on, so the
                    // ticket is good and the gamble is over.
                    this.zero_rtt = None;
                    this.read_state = ReadState::Body(header, length);
                }
                ReadState::Body(header, length) => {
                    this.read_need = length;
                    ready!(this.poll_fill(cx))?;
                    let mut body = std::mem::take(&mut this.read_buf);
                    let peer = this.peer_aead.as_mut().expect("a body implies a peer key");
                    let rekey = peer.at_max_nonce().then(|| {
                        let mut context = Vec::with_capacity(5 + body.len());
                        context.extend_from_slice(&header);
                        context.extend_from_slice(&body);
                        context
                    });
                    let plain_len = peer.open_in_place(&header, &mut body)?;
                    if let Some(context) = rekey {
                        this.peer_aead = Some(Aead::new(&context, &this.united_key, this.use_aes));
                    }
                    body.truncate(plain_len);
                    this.plain = body;
                    this.plain_pos = 0;
                    this.read_state = ReadState::Serve;
                }
                ReadState::Serve => {
                    let available = &this.plain[this.plain_pos..];
                    if available.is_empty() {
                        this.plain.clear();
                        this.plain_pos = 0;
                        this.read_state = ReadState::Header;
                        continue;
                    }
                    let take = available.len().min(buf.remaining());
                    if take == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    buf.put_slice(&available[..take]);
                    this.plain_pos += take;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for EncryptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // One record in flight at a time: a partially written record cannot be
        // interleaved with a new one.
        ready!(this.flush_out(cx))?;
        let take = buf.len().min(MAX_RECORD_PLAINTEXT);
        this.frame(&buf[..take])?;
        match this.flush_out(cx) {
            // Staged but not yet drained; poll_flush will finish it.
            Poll::Pending => Poll::Ready(Ok(take)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_out(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
