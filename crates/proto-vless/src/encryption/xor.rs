//! The `random` appearance mode.
//!
//! `native` and `xorpub` leave every record wearing a TLS 1.3 `23 03 03 len`
//! header. `random` masks those five bytes with AES-256-CTR so the whole
//! connection is indistinguishable from random bytes — upstream measures the
//! cost at six ten-thousandths of the traffic, because only the header is
//! touched and the AEAD body streams past untouched.
//!
//! Upstream models this as a `net.Conn` wrapper. Here it is an in-place
//! transform owned by [`super::stream::EncryptedStream`], which already owns
//! the buffers on both sides and feeds them through in wire order. That avoids
//! a second copy of every record and keeps the keystream position — which
//! advances five bytes at a time, mid-AES-block — in one place.

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};

use super::aead::decode_header_raw;
use super::blake3;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// `NewCTR`: AES-256-CTR keyed by `BLAKE3::derive_key("VLESS", key)`.
///
/// The literal context is what keeps this keystream separate from every AEAD
/// key derived from the same `unitedKey`.
fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let derived = blake3::derive_key(b"VLESS", key);
    Aes256Ctr::new((&derived).into(), iv.into())
}

/// Masks the public key material in `ivAndRelays` for `xorpub` and `random`.
///
/// Keyed by the hop's *own* long-term public key, so a client holding the
/// config can undo it — which is the point: the bytes underneath are a real
/// X25519 public key or ML-KEM ciphertext, and upstream is explicit that this
/// is not an attempt at an indistinguishable encoding.
pub fn mask_relay(nfs_public_key: &[u8], iv: &[u8; 16], relay: &mut [u8]) {
    new_ctr(nfs_public_key, iv).apply_keystream(relay);
}

/// A CTR stream used to bind one relay hop to the next.
pub struct RelayLink(Aes256Ctr);

impl RelayLink {
    pub fn new(nfs_key: &[u8], iv: &[u8; 16]) -> Self {
        Self(new_ctr(nfs_key, iv))
    }

    /// Consumes keystream in the order upstream does: first the 32-byte hash
    /// binding the next hop, then the first 32 bytes of that hop's material.
    pub fn apply(&mut self, bytes: &mut [u8]) {
        self.0.apply_keystream(bytes);
    }
}

/// Header masking state for one direction.
struct Direction {
    ctr: Option<Aes256Ctr>,
    /// Bytes still to pass through untouched — the remainder of a record body,
    /// or a handshake prefix that was written before masking began.
    skip: usize,
    /// Partial header carried across a chunk boundary, in plaintext.
    header: Vec<u8>,
}

impl Direction {
    fn new(ctr: Option<Aes256Ctr>, skip: usize) -> Self {
        Self {
            ctr,
            skip,
            header: Vec::with_capacity(5),
        }
    }
}

/// The masking state for a connection in `random` mode.
pub struct XorState {
    out: Direction,
    inbound: Direction,
}

impl XorState {
    /// `NewXorConn`. `peer_ctr` is `None` for a 0-RTT client, which cannot key
    /// the inbound direction until the server's 16 random bytes arrive.
    pub fn new(
        united_key: &[u8],
        out_iv: &[u8; 16],
        peer_iv: Option<&[u8; 16]>,
        out_skip: usize,
        in_skip: usize,
    ) -> Self {
        Self {
            out: Direction::new(Some(new_ctr(united_key, out_iv)), out_skip),
            inbound: Direction::new(peer_iv.map(|iv| new_ctr(united_key, iv)), in_skip),
        }
    }

    /// Keys the inbound direction once the server's random prefix is known.
    pub fn set_peer_iv(&mut self, united_key: &[u8], peer_iv: &[u8; 16]) {
        self.inbound.ctr = Some(new_ctr(united_key, peer_iv));
    }

    /// Masks the record headers in an outbound chunk, in place.
    pub fn mask_outbound(&mut self, buffer: &mut [u8]) {
        Self::walk(&mut self.out, buffer, true);
    }

    /// Unmasks the record headers in an inbound chunk, in place.
    pub fn unmask_inbound(&mut self, buffer: &mut [u8]) {
        Self::walk(&mut self.inbound, buffer, false);
    }

    /// One pass of upstream's `XorConn.Write`/`Read` loop.
    ///
    /// `outbound` decides the order of the two steps on a whole header: the
    /// writer decodes the plaintext it is about to mask, the reader unmasks
    /// first and decodes what it recovered.
    fn walk(direction: &mut Direction, buffer: &mut [u8], outbound: bool) {
        let mut start = 0_usize;
        loop {
            // `<=` rather than `<`: a chunk that ends exactly on a record
            // boundary leaves the next header for the following chunk.
            if buffer.len() - start <= direction.skip {
                direction.skip -= buffer.len() - start;
                return;
            }
            start += direction.skip;
            direction.skip = 0;

            let Some(ctr) = direction.ctr.as_mut() else {
                // No key yet, which can only happen while the whole chunk is
                // still inside the unkeyed prefix handled above.
                return;
            };
            let need = 5 - direction.header.len();
            if buffer.len() - start < need {
                // Fewer bytes left than the header needs; carry the partial
                // header across the chunk boundary. It is stored in plaintext
                // on both sides, so the two branches differ only in whether
                // masking happens before or after it is recorded.
                let tail = &mut buffer[start..];
                if outbound {
                    direction.header.extend_from_slice(tail);
                    ctr.apply_keystream(tail);
                } else {
                    ctr.apply_keystream(tail);
                    direction.header.extend_from_slice(tail);
                }
                return;
            }
            let slice = &mut buffer[start..start + need];
            if outbound {
                direction.header.extend_from_slice(slice);
                ctr.apply_keystream(slice);
            } else {
                ctr.apply_keystream(slice);
                direction.header.extend_from_slice(slice);
            }
            let mut header = [0_u8; 5];
            header.copy_from_slice(&direction.header);
            direction.header.clear();
            direction.skip = decode_header_raw(&header);
            start += need;
        }
    }
}
