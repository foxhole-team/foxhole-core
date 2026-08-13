//! Transport sessions: counters, anti-replay and packet sealing.
//!
//! A session is pure state — it never touches a socket or a clock, so the whole
//! replay surface is unit-testable. Expiry by *time* belongs to the tunnel
//! above; expiry by *message count* lives here because only this type knows the
//! counter.

use zeroize::Zeroize;

use crate::WireguardError;
use crate::message::{TAG_LEN, TRANSPORT_HEADER_LEN, parse_transport, write_transport_header};
use crate::noise::{Key, TransportKeys, aead_open, aead_seal_in_place};

/// After this many messages a key must never be used again (WireGuard §6.1).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
/// The point at which a fresh handshake should already be under way.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Transport plaintext is padded to a multiple of 16 bytes so packet lengths
/// leak less about the traffic inside.
const PAD_TO: usize = 16;

const BLOCK_BITS: u64 = 64;
const RING_BLOCKS: usize = 128;
const RING_MASK: u64 = RING_BLOCKS as u64 - 1;
const BLOCK_MASK: u64 = BLOCK_BITS - 1;
/// Counters this far behind the newest one are refused outright.
pub const REPLAY_WINDOW: u64 = (RING_BLOCKS as u64 - 1) * BLOCK_BITS;

/// Sliding-window replay filter.
///
/// The window is a ring of bit blocks rather than a shifted bitmap: an in-order
/// packet then costs one word write instead of moving 128 words, which is what
/// keeps the data path free of per-packet work proportional to the window.
#[derive(Debug)]
pub struct ReplayWindow {
    last: u64,
    ring: [u64; RING_BLOCKS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0; RING_BLOCKS],
        }
    }
}

impl ReplayWindow {
    /// Accept `counter` once. Returns `false` for replays, for counters that
    /// have fallen out of the window, and for counters past the hard limit.
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let mut index = counter >> 6;
        if counter > self.last {
            // Clear the blocks the window just moved over; anything they held
            // is now older than the window and must not be accepted again.
            let current = self.last >> 6;
            let advanced = (index - current).min(RING_BLOCKS as u64);
            for step in 1..=advanced {
                self.ring[((current + step) & RING_MASK) as usize] = 0;
            }
            self.last = counter;
        } else if self.last - counter > REPLAY_WINDOW {
            return false;
        }
        index &= RING_MASK;
        let bit = 1_u64 << (counter & BLOCK_MASK);
        let block = &mut self.ring[index as usize];
        let seen = *block & bit != 0;
        *block |= bit;
        !seen
    }
}

/// A live WireGuard session: one key pair, one counter, one replay window.
pub struct TransportSession {
    send_key: Key,
    receive_key: Key,
    /// Index the peer stamps on packets it sends to us.
    pub local_index: u32,
    /// Index we stamp on packets we send to the peer.
    pub remote_index: u32,
    send_counter: u64,
    replay: ReplayWindow,
}

impl Drop for TransportSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

impl TransportSession {
    pub fn new(keys: TransportKeys) -> Self {
        Self {
            send_key: keys.send,
            receive_key: keys.receive,
            local_index: keys.sender_index,
            remote_index: keys.receiver_index,
            send_counter: 0,
            replay: ReplayWindow::default(),
        }
    }

    /// Counter the next sealed packet will carry.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Place the counter at a value no test could reach by actually sending.
    ///
    /// `REJECT_AFTER_MESSAGES` is within eight kilopackets of `u64::MAX`, so the
    /// limit is only observable if it can be approached directly. `#[cfg(test)]`
    /// keeps this out of every build that ships.
    #[cfg(test)]
    pub(crate) fn set_send_counter(&mut self, counter: u64) {
        self.send_counter = counter;
    }

    /// Whether a rekey is due. The tunnel also rekeys on time.
    pub fn needs_rekey(&self) -> bool {
        self.send_counter >= REKEY_AFTER_MESSAGES
    }

    /// Whether the counter still has room under `REJECT_AFTER_MESSAGES` (§6.1).
    ///
    /// The tunnel asks before sealing so that a spent key produces a handshake
    /// and a held packet, rather than the `SessionExpired` error [`Self::seal`]
    /// would raise once the packet is already past the point of being retried.
    pub fn can_send(&self) -> bool {
        self.send_counter < REJECT_AFTER_MESSAGES
    }

    /// Seal one IP packet into `out`. An empty packet is a keepalive.
    pub fn seal(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), WireguardError> {
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(WireguardError::SessionExpired);
        }
        let counter = self.send_counter;
        self.send_counter += 1;

        // The whole datagram is built in `out`, and the packet is copied exactly
        // once. The previous shape allocated three more buffers on every packet
        // — pad into a copy, encrypt into a second copy, grow that to append the
        // tag — then walked the plaintext once more to wipe the copy it made.
        // Six passes over 1.4 KiB, a thousand times a second, to produce the
        // bytes one pass produces.
        //
        // The wipe went with them: it cleared one of three copies of the same
        // plaintext (the caller's packet and the tunnel's pending queue hold the
        // others and are dropped without zeroing), so it bought no secrecy and
        // cost a full-length volatile write per packet.
        let padded_len = packet.len().next_multiple_of(PAD_TO);
        out.clear();
        out.reserve(TRANSPORT_HEADER_LEN + padded_len + TAG_LEN);
        out.resize(TRANSPORT_HEADER_LEN, 0);
        write_transport_header(self.remote_index, counter, out);
        out.extend_from_slice(packet);
        // Padding must be zero on the wire; this is the only memset left.
        out.resize(TRANSPORT_HEADER_LEN + padded_len, 0);
        let tag = aead_seal_in_place(
            &self.send_key,
            counter,
            &mut out[TRANSPORT_HEADER_LEN..],
            &[],
        )?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Open one transport datagram in place, returning the plaintext.
    ///
    /// The plaintext still carries WireGuard's 16-byte padding; the caller reads
    /// the IP header to find the real length. An empty result is a keepalive.
    pub fn open<'a>(&mut self, datagram: &'a mut [u8]) -> Result<&'a [u8], WireguardError> {
        let (receiver_index, counter, _) = parse_transport(datagram)?;
        if receiver_index != self.local_index {
            return Err(WireguardError::UnexpectedMessage);
        }
        // Authenticate before touching the replay window: an attacker must not
        // be able to burn counters by spraying forged datagrams.
        let length = aead_open(
            &self.receive_key,
            counter,
            &mut datagram[TRANSPORT_HEADER_LEN..],
            &[],
        )?;
        if !self.replay.accept(counter) {
            return Err(WireguardError::Replay);
        }
        Ok(&datagram[TRANSPORT_HEADER_LEN..TRANSPORT_HEADER_LEN + length])
    }
}

/// Length of the IP packet at the front of `plaintext`, ignoring padding.
///
/// Returns `None` for a keepalive or for bytes that are not an IP packet the
/// tunnel should forward — the caller must drop those rather than guess.
pub fn ip_packet_len(plaintext: &[u8]) -> Option<usize> {
    let version = plaintext.first()? >> 4;
    let length = match version {
        4 => u16::from_be_bytes(plaintext.get(2..4)?.try_into().ok()?) as usize,
        6 => 40 + u16::from_be_bytes(plaintext.get(4..6)?.try_into().ok()?) as usize,
        _ => return None,
    };
    // A declared length longer than what arrived means a truncated or lying
    // packet; forwarding it would hand the tun device garbage.
    (length >= 20 && length <= plaintext.len()).then_some(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::TAG_LEN;

    fn pair() -> (TransportSession, TransportSession) {
        let client = TransportKeys {
            send: [0x11; 32],
            receive: [0x22; 32],
            sender_index: 1,
            receiver_index: 2,
        };
        let server = TransportKeys {
            send: [0x22; 32],
            receive: [0x11; 32],
            sender_index: 2,
            receiver_index: 1,
        };
        (TransportSession::new(client), TransportSession::new(server))
    }

    #[test]
    fn a_sealed_packet_opens_on_the_other_side() {
        let (mut client, mut server) = pair();
        let packet = b"\x45\x00\x00\x1c-- an IP packet --";
        let mut datagram = Vec::new();
        client.seal(packet, &mut datagram).unwrap();

        assert_eq!(&datagram[..4], &[4, 0, 0, 0], "transport type");
        let opened = server.open(&mut datagram).unwrap();
        assert_eq!(&opened[..packet.len()], packet);
        assert_eq!(opened.len() % PAD_TO, 0, "plaintext stays padded");
    }

    #[test]
    fn payloads_are_padded_to_sixteen_bytes() {
        let (mut client, mut server) = pair();
        for length in [1_usize, 15, 16, 17, 100] {
            let packet = vec![0x45; length];
            let mut datagram = Vec::new();
            client.seal(&packet, &mut datagram).unwrap();
            let expected = TRANSPORT_HEADER_LEN + length.next_multiple_of(PAD_TO) + TAG_LEN;
            assert_eq!(datagram.len(), expected, "length {length}");
            assert!(server.open(&mut datagram).is_ok());
        }
    }

    #[test]
    fn a_keepalive_is_an_empty_packet() {
        let (mut client, mut server) = pair();
        let mut datagram = Vec::new();
        client.seal(&[], &mut datagram).unwrap();
        assert_eq!(datagram.len(), TRANSPORT_HEADER_LEN + TAG_LEN);
        assert!(server.open(&mut datagram).unwrap().is_empty());
    }

    #[test]
    fn a_replayed_datagram_is_refused() {
        let (mut client, mut server) = pair();
        let mut datagram = Vec::new();
        client
            .seal(b"\x45\x00\x00\x14aaaaaaaaaaaa", &mut datagram)
            .unwrap();
        let replay = datagram.clone();
        assert!(server.open(&mut datagram).is_ok());

        let mut replay = replay;
        assert!(matches!(
            server.open(&mut replay),
            Err(WireguardError::Replay)
        ));
    }

    #[test]
    fn a_datagram_for_another_session_is_refused() {
        let (mut client, mut server) = pair();
        let mut datagram = Vec::new();
        client.seal(b"packet", &mut datagram).unwrap();
        datagram[4..8].copy_from_slice(&99_u32.to_le_bytes());
        assert!(matches!(
            server.open(&mut datagram),
            Err(WireguardError::UnexpectedMessage)
        ));
    }

    #[test]
    fn a_forged_datagram_does_not_consume_a_counter() {
        let (mut client, mut server) = pair();
        let mut datagram = Vec::new();
        client.seal(b"real packet", &mut datagram).unwrap();

        let mut forged = datagram.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        assert!(matches!(
            server.open(&mut forged),
            Err(WireguardError::Decryption)
        ));
        // The genuine packet with the same counter must still be accepted.
        assert!(server.open(&mut datagram).is_ok());
    }

    #[test]
    fn out_of_order_packets_inside_the_window_are_accepted_once() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(0));
        assert!(window.accept(5));
        assert!(window.accept(3), "reordering is normal on the internet");
        assert!(!window.accept(3), "but only once");
        assert!(window.accept(4));
    }

    #[test]
    fn counters_older_than_the_window_are_refused() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(REPLAY_WINDOW + 100));
        assert!(window.accept(REPLAY_WINDOW + 100 - REPLAY_WINDOW));
        assert!(!window.accept(99), "just past the window edge");
        assert!(!window.accept(0));
    }

    #[test]
    fn a_large_jump_clears_the_whole_window() {
        let mut window = ReplayWindow::default();
        for counter in 0..64 {
            assert!(window.accept(counter));
        }
        // Jumping far ahead must not leave stale bits that reject fresh
        // counters landing on the same ring slots.
        assert!(window.accept(1_000_000));
        assert!(window.accept(1_000_001));
        assert!(!window.accept(1_000_000));
    }

    #[test]
    fn the_hard_message_limit_is_enforced() {
        let mut window = ReplayWindow::default();
        assert!(!window.accept(REJECT_AFTER_MESSAGES));
        assert!(!window.accept(u64::MAX));
    }

    #[test]
    fn ip_length_is_read_from_the_header_not_the_padding() {
        let mut ipv4 = vec![0x45, 0, 0, 21];
        ipv4.resize(32, 0);
        assert_eq!(ip_packet_len(&ipv4), Some(21));

        let mut ipv6 = vec![0x60, 0, 0, 0, 0, 8];
        ipv6.resize(64, 0);
        assert_eq!(ip_packet_len(&ipv6), Some(48));

        assert_eq!(ip_packet_len(&[]), None, "keepalive");
        assert_eq!(ip_packet_len(&[0x25, 0, 0, 21]), None, "not IP");
        let mut lying = vec![0x45, 0, 0xFF, 0xFF];
        lying.resize(32, 0);
        assert_eq!(ip_packet_len(&lying), None, "declared longer than received");
    }
}
