//! Hysteria2 Salamander obfuscation below Quinn's QUIC packet layer.
//!
//! Every UDP datagram is encoded independently as `salt[8] || xor(quic_packet,
//! BLAKE2b-256(key || salt))`. The wrapper deliberately disables UDP GSO/GRO at
//! its public boundary: salts are packet-scoped and must never span datagrams.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};
use zeroize::Zeroizing;

const SALT_LEN: usize = 8;

type Blake2b256 = Blake2b<U32>;

/// Runtime adapter that delegates scheduling to Tokio and wraps only UDP I/O.
pub(crate) struct SalamanderRuntime {
    key: Arc<Zeroizing<Vec<u8>>>,
}

impl SalamanderRuntime {
    pub(crate) fn new(key: &str) -> Self {
        Self {
            key: Arc::new(Zeroizing::new(key.as_bytes().to_vec())),
        }
    }
}

impl fmt::Debug for SalamanderRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderRuntime")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Runtime for SalamanderRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Runtime::new_timer(&quinn::TokioRuntime, deadline)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        Runtime::spawn(&quinn::TokioRuntime, future);
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)?;
        Ok(Arc::new(SalamanderSocket::new(inner, self.key.clone())))
    }

    fn now(&self) -> Instant {
        Runtime::now(&quinn::TokioRuntime)
    }
}

struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    key: Arc<Zeroizing<Vec<u8>>>,
    send_buffer: Mutex<Zeroizing<Vec<u8>>>,
    receive_buffers: Mutex<Vec<Vec<u8>>>,
}

impl SalamanderSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>, key: Arc<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            inner,
            key,
            send_buffer: Mutex::new(Zeroizing::new(Vec::new())),
            receive_buffers: Mutex::new(Vec::new()),
        }
    }
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderSocket")
            .field("inner", &self.inner)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander does not accept segmented UDP transmits",
            ));
        }

        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|error| {
            io::Error::other(format!("secure random generation failed: {error}"))
        })?;

        let mut buffer = self
            .send_buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        encode_with_salt(&self.key, &salt, transmit.contents, &mut buffer);
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buffer,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = bufs.len().min(meta.len());
        if count == 0 {
            return Poll::Ready(Ok(0));
        }

        // Quinn sizes its receive buffers for plain QUIC payloads. Salamander
        // adds eight bytes on the wire, so receive into reusable enlarged
        // buffers and compact after removing each packet-local salt.
        let mut receive_buffers = self
            .receive_buffers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        receive_buffers.resize_with(count, Vec::new);
        for (outer, plain) in receive_buffers.iter_mut().zip(bufs.iter()).take(count) {
            outer.resize(plain.len().saturating_add(SALT_LEN), 0);
        }

        let mut outer_iovs: Vec<_> = receive_buffers
            .iter_mut()
            .take(count)
            .map(|buffer| IoSliceMut::new(buffer.as_mut_slice()))
            .collect();
        let received = match self
            .inner
            .poll_recv(cx, &mut outer_iovs, &mut meta[..count])
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(received)) => received,
        };
        drop(outer_iovs);

        for index in 0..received {
            let decoded = decode_segments(
                &self.key,
                &mut receive_buffers[index],
                meta[index].len,
                meta[index].stride,
            );
            match decoded {
                Some((decoded_len, decoded_stride)) if decoded_len <= bufs[index].len() => {
                    bufs[index][..decoded_len]
                        .copy_from_slice(&receive_buffers[index][..decoded_len]);
                    meta[index].len = decoded_len;
                    meta[index].stride = decoded_stride;
                }
                _ => {
                    // Quinn skips zero-length entries. Treat malformed or
                    // truncated datagrams as unauthenticated noise.
                    meta[index].len = 0;
                    meta[index].stride = 1;
                }
            }
        }

        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn encode_with_salt(key: &[u8], salt: &[u8; SALT_LEN], payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(SALT_LEN.saturating_add(payload.len()));
    out.extend_from_slice(salt);
    out.extend_from_slice(payload);
    xor_payload(key, salt, &mut out[SALT_LEN..]);
}

fn decode_segments(
    key: &[u8],
    buffer: &mut [u8],
    encoded_len: usize,
    encoded_stride: usize,
) -> Option<(usize, usize)> {
    if encoded_len == 0
        || encoded_len > buffer.len()
        || encoded_stride < SALT_LEN
        || encoded_stride > encoded_len
    {
        return None;
    }

    let mut read_offset = 0;
    let mut write_offset = 0;
    while read_offset < encoded_len {
        let segment_len = encoded_stride.min(encoded_len - read_offset);
        if segment_len < SALT_LEN {
            return None;
        }
        let salt: [u8; SALT_LEN] = buffer[read_offset..read_offset + SALT_LEN]
            .try_into()
            .ok()?;
        let payload_start = read_offset + SALT_LEN;
        let payload_end = read_offset + segment_len;
        xor_payload(key, &salt, &mut buffer[payload_start..payload_end]);
        buffer.copy_within(payload_start..payload_end, write_offset);
        write_offset += segment_len - SALT_LEN;
        read_offset += segment_len;
    }

    let decoded_stride = if encoded_len <= encoded_stride {
        write_offset
    } else {
        encoded_stride - SALT_LEN
    };
    Some((write_offset, decoded_stride))
}

fn xor_payload(key: &[u8], salt: &[u8; SALT_LEN], payload: &mut [u8]) {
    let mut hasher = Blake2b256::new();
    hasher.update(key);
    hasher.update(salt);
    let digest = hasher.finalize();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= digest[index % digest.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_matches_official_wire_algorithm_vector() {
        let salt = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut encoded = Vec::new();
        encode_with_salt(b"test-key", &salt, b"hello-quic", &mut encoded);
        assert_eq!(hex(&encoded), "0001020304050607a993af144f58c78ed58b");
    }

    #[test]
    fn salamander_round_trip_preserves_packet_boundaries() {
        let key = b"another-key";
        let salt_a = [1; SALT_LEN];
        let salt_b = [2; SALT_LEN];
        let mut first = Vec::new();
        let mut second = Vec::new();
        encode_with_salt(key, &salt_a, b"first", &mut first);
        encode_with_salt(key, &salt_b, b"two", &mut second);

        let stride = first.len();
        second.resize(stride, 0);
        let mut packets = first;
        packets.extend_from_slice(&second);
        let encoded_len = packets.len() - (stride - (SALT_LEN + 3));
        let (decoded_len, decoded_stride) =
            decode_segments(key, &mut packets, encoded_len, stride).unwrap();

        assert_eq!(decoded_stride, 5);
        assert_eq!(decoded_len, 8);
        assert_eq!(&packets[..decoded_len], b"firsttwo");
    }

    #[test]
    fn salamander_discards_truncated_datagrams() {
        let mut packet = [0u8; SALT_LEN - 1];
        let packet_len = packet.len();
        assert_eq!(
            decode_segments(b"key", &mut packet, packet_len, packet_len),
            None
        );
    }

    fn hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
