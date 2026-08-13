//! The memory every packet on the datapath travels in.
//!
//! Each hop between the tun and an outbound used to own a `Vec<u8>` per packet.
//! The reader copied the descriptor's buffer into a fresh one before the channel
//! send, the stack device copied its reply into another, and the WireGuard relay
//! handed its decrypt buffer away with `mem::take` so the next packet regrew one
//! from zero capacity. Three allocations and one avoidable copy on every packet
//! the device moves.
//!
//! A [`PacketArena`] is one allocation that hands out several packets. The tun
//! reader reads *straight into* it, so the packet that reaches the classifier is
//! the bytes the kernel wrote and was never copied at all; the other two sites
//! still copy — their callers hand over a borrowed slice and there is nothing to
//! take ownership of — but they no longer allocate to do it.
//!
//! What that is worth, from `benches/packet_path.rs`: the tun hand-off went
//! 68.0 ns → 53.5 ns for a full 1420-byte
//! packet and is a wash at 64 bytes, where there is barely a copy to save; the
//! whole userspace-stack hop went 161 ns → 133 ns at 1420 bytes and 90 ns →
//! 71 ns at 64. On the WireGuard path the AEAD costs 2.7 µs per full packet and
//! swallows the difference whole — the allocations are removed there for the
//! allocator's sake, not the clock's.
//!
//! # What a packet costs while it is in flight
//!
//! A packet keeps its whole chunk alive, so a consumer that stalls holds more
//! memory than the packets in its queue add up to. The bound is
//! `channel capacity × chunk size`: with [`PACKETS_PER_CHUNK`] at 8 and the
//! 256-deep packet queues, one wedged consumer can pin about 3 MiB where
//! per-packet `Vec`s would have pinned 1.1 MiB. Nothing accumulates beyond that
//! — chunks are freed as their last packet is consumed, and the steady state is
//! one live chunk per producer, refilled in place.

use std::io;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Packets per chunk.
///
/// The trade in the module header, decided: eight is 8× fewer allocations for a
/// worst case a stalled consumer can pin that stays inside a few MiB. Raising it
/// buys progressively less — the copy, not the allocation, was the larger cost —
/// and raises that ceiling in proportion.
const PACKETS_PER_CHUNK: usize = 8;

/// A chunk of memory that hands out whole packets.
///
/// Every packet it returns is a disjoint window on the chunk: `BytesMut` splits
/// do not overlap, so a packet can be rewritten in place — the address
/// translator does exactly that — without touching another packet's bytes.
pub struct PacketArena {
    /// The unhanded-out tail of the current chunk. Empty between packets: each
    /// one is split off whole.
    chunk: BytesMut,
    /// One packet's worth. It bounds a read — a tun delivers one packet per
    /// read and this keeps a reader that does otherwise from handing two on as
    /// one — and it is the unit the chunk is sized in. It does not bound
    /// [`PacketArena::copy_in`], which keeps every byte it is given.
    packet_capacity: usize,
}

impl PacketArena {
    /// An arena whose packets are at most `packet_capacity` bytes.
    ///
    /// Sized by the caller because the ceiling differs by path: the tun reader
    /// adds header room to the MTU, the stack device and the packet-tunnel relay
    /// are bounded by the MTU itself.
    pub fn new(packet_capacity: usize) -> Self {
        // At least one byte, so `chunk_mut` can never be asked for an empty
        // window and a zero-length read can never be mistaken for end of file.
        let packet_capacity = packet_capacity.max(1);
        Self {
            chunk: BytesMut::with_capacity(packet_capacity.saturating_mul(PACKETS_PER_CHUNK)),
            packet_capacity,
        }
    }

    /// Read one packet from `reader` directly into the arena.
    ///
    /// `Ok(None)` is end of file. The read is bounded to one packet's worth,
    /// which is what a tun descriptor delivers anyway and what keeps a reader
    /// that returns more than one packet's bytes from producing a "packet" that
    /// is really two.
    ///
    /// Cancel-safe, which the caller relies on — it is one arm of a `select!`
    /// against the shutdown token. `read_buf` reads nothing when its future is
    /// dropped, and the arena is only split after the read has returned.
    pub async fn read_packet<R>(&mut self, reader: &mut R) -> io::Result<Option<BytesMut>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        debug_assert!(self.chunk.is_empty(), "a packet was left half handed out");
        // Either room in the current chunk or a fresh one; `BytesMut` reclaims
        // this chunk in place once the packets split off it have been consumed,
        // so the steady state allocates nothing.
        self.chunk.reserve(self.packet_capacity);
        let read = {
            let mut window = (&mut self.chunk).limit(self.packet_capacity);
            reader.read_buf(&mut window).await?
        };
        if read == 0 {
            return Ok(None);
        }
        Ok(Some(self.chunk.split_to(read)))
    }

    /// Copy a borrowed packet into the arena.
    ///
    /// For the two hops that are handed a slice they do not own — the stack
    /// device's `poll_write` and the relay's decrypted packet. The copy is the
    /// caller's interface, not this arena's; what goes away is the allocation
    /// that used to come with it.
    pub fn copy_in(&mut self, packet: &[u8]) -> BytesMut {
        debug_assert!(self.chunk.is_empty(), "a packet was left half handed out");
        // `max` rather than the fixed capacity: a caller that hands over more
        // than one packet's worth must still get all of its bytes back, not a
        // silently truncated packet.
        self.chunk.reserve(packet.len().max(self.packet_capacity));
        self.chunk.extend_from_slice(packet);
        self.chunk.split_to(packet.len())
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncRead;

    use super::*;

    /// A reader that answers every read with the next scripted packet, the way a
    /// tun descriptor delivers one packet per read.
    struct Scripted(std::collections::VecDeque<Vec<u8>>);

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if let Some(packet) = self.0.pop_front() {
                let length = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..length]);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn scripted(packets: &[Vec<u8>]) -> Scripted {
        Scripted(packets.iter().cloned().collect())
    }

    /// Drive a future to completion with nothing underneath it.
    ///
    /// These three tests used to be `#[tokio::test]`, and that alone kept them
    /// out of Miri: the attribute builds a runtime with every driver enabled,
    /// the I/O driver opens a `kqueue`, and Miri implements no such syscall —
    /// which aborts the whole test binary on the first one, not just that test.
    ///
    /// Nothing here needs a runtime. `Scripted` answers every `poll_read` with
    /// `Ready`, so what these futures want is somebody to poll them, and a
    /// no-op waker is somebody. That is the entire distance between "the
    /// arena's aliasing is argued in a comment" and "the interpreter checks it
    /// on every run": `packets_from_one_chunk_never_share_bytes` is a claim
    /// about two windows into one allocation, and
    /// `a_consumed_packet_gives_its_room_back` does pointer arithmetic across
    /// them — exactly the two things Miri exists to find and the two things no
    /// assertion can.
    fn poll_to_completion<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            // The scripted reader never yields, so `Pending` means the test
            // grew a real wait and stopped being a unit test. Waiting on a
            // no-op waker would hang instead of saying so.
            std::task::Poll::Pending => {
                panic!("a scripted read parked: this test now needs a real executor")
            }
        }
    }

    #[test]
    fn a_packet_read_into_the_arena_is_the_bytes_the_reader_produced() {
        poll_to_completion(async {
            let mut arena = PacketArena::new(1464);
            let mut reader = scripted(&[vec![1, 2, 3], vec![9; 1400]]);

            let first = arena.read_packet(&mut reader).await.unwrap().unwrap();
            assert_eq!(&first[..], &[1, 2, 3]);
            let second = arena.read_packet(&mut reader).await.unwrap().unwrap();
            assert_eq!(second.len(), 1400);
            assert!(second.iter().all(|byte| *byte == 9));
            assert_eq!(
                arena.read_packet(&mut reader).await.unwrap(),
                None,
                "a reader with nothing left is end of file, not a zero-length packet"
            );
        });
    }

    /// The failure mode a shared chunk makes possible and per-packet `Vec`s did
    /// not: two packets overlapping in the same allocation, so writing one
    /// corrupts the other. Every hop on this path rewrites its packet in
    /// place — the address translator does — so this is the property the whole
    /// arena stands on.
    #[test]
    fn packets_from_one_chunk_never_share_bytes() {
        poll_to_completion(async {
            let mut arena = PacketArena::new(64);
            // More than one chunk's worth, so the wrap to a fresh chunk is
            // covered as well as the splits inside one.
            let scripted_packets: Vec<Vec<u8>> = (0..PACKETS_PER_CHUNK * 3 + 1)
                .map(|index| vec![index as u8; 40])
                .collect();
            let mut reader = scripted(&scripted_packets);

            let mut held = Vec::new();
            for _ in 0..scripted_packets.len() {
                held.push(arena.read_packet(&mut reader).await.unwrap().unwrap());
            }
            // Rewrite every packet in place, then check that no packet lost its
            // bytes to a neighbour.
            for (index, packet) in held.iter_mut().enumerate() {
                packet.fill(index as u8 ^ 0xFF);
            }
            for (index, packet) in held.iter().enumerate() {
                assert!(
                    packet.iter().all(|byte| *byte == index as u8 ^ 0xFF),
                    "packet {index} was written through by another packet's window"
                );
            }
        });
    }

    #[test]
    fn a_read_is_bounded_to_one_packet() {
        poll_to_completion(async {
            let mut arena = PacketArena::new(100);
            // A reader offering more than the ceiling in one read: the tun does
            // not do this, but a chunk that let it would hand two packets on as
            // one.
            let mut reader = scripted(&[vec![7; 4096]]);

            let packet = arena.read_packet(&mut reader).await.unwrap().unwrap();
            assert_eq!(packet.len(), 100);
        });
    }

    #[test]
    fn a_copied_packet_keeps_its_bytes_and_is_not_truncated() {
        let mut arena = PacketArena::new(64);
        let first = arena.copy_in(&[1, 2, 3]);
        let oversized = arena.copy_in(&[5; 4096]);
        let third = arena.copy_in(&[4, 5]);

        assert_eq!(&first[..], &[1, 2, 3]);
        assert_eq!(
            oversized.len(),
            4096,
            "a copy must keep every byte it was given; truncating here would put \
             half a packet on the wire"
        );
        assert_eq!(&third[..], &[4, 5]);
    }

    /// The reason the arena exists, asserted rather than assumed: once a packet
    /// has been consumed its room comes back, so a stream of packets costs one
    /// allocation and not one each. Stated as "every packet lands inside the
    /// first chunk" — if the arena ever went back to allocating per packet, the
    /// addresses would walk out of that range immediately.
    #[test]
    fn a_consumed_packet_gives_its_room_back() {
        const PACKET: usize = 64;
        let mut arena = PacketArena::new(PACKET);
        let first = arena.copy_in(&[1; PACKET]);
        let base = first.as_ptr() as usize;
        drop(first);

        for index in 0..PACKETS_PER_CHUNK * 8 {
            let packet = arena.copy_in(&[2; PACKET]);
            let offset = (packet.as_ptr() as usize).wrapping_sub(base);
            assert!(
                offset < PACKET * PACKETS_PER_CHUNK,
                "packet {index} came out of a second chunk: the arena is \
                 allocating per packet again"
            );
        }
    }

    #[test]
    fn an_empty_copy_is_an_empty_packet() {
        let mut arena = PacketArena::new(64);
        assert!(arena.copy_in(&[]).is_empty());
        assert_eq!(&arena.copy_in(&[8, 9])[..], &[8, 9]);
    }
}
