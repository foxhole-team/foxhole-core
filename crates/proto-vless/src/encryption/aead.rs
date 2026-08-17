//! The AEAD layer: BLAKE3-derived keys, an implicit counter nonce, and rekeying
//! when that counter wraps.
//!
//! Two things here are easy to get subtly wrong and both are load-bearing for
//! interoperability:
//!
//! * the nonce is incremented *before* every operation, so the first record on
//!   a key uses `00..01` and never `00..00`;
//! * one message in the handshake — the server's forward-secret public key — is
//!   sealed under the all-`FF` nonce instead, which is what keeps the server's
//!   use of `nfsKey` from colliding with the client's counter on the same key.

use std::io;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use super::blake3;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// The nonce the sender is required to use for a message that must not share
/// the counter sequence.
pub const MAX_NONCE: [u8; NONCE_LEN] = [0xFF; NONCE_LEN];

enum Cipher {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

pub struct Aead {
    cipher: Cipher,
    nonce: [u8; NONCE_LEN],
}

impl Aead {
    /// `NewAEAD`: the working key is `BLAKE3::derive_key(context = ctx, key)`.
    ///
    /// `ctx` is arbitrary binary — an IV, a public key, a whole record — which
    /// is why [`super::blake3`] exists.
    pub fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let derived = blake3::derive_key(ctx, key);
        let cipher = if use_aes {
            Cipher::Aes(Box::new(Aes256Gcm::new((&derived).into())))
        } else {
            Cipher::ChaCha(Box::new(ChaCha20Poly1305::new((&derived).into())))
        };
        Self {
            cipher,
            nonce: [0; NONCE_LEN],
        }
    }

    /// True when the next counter step wraps to zero, which is the point at
    /// which both sides re-derive from the record just processed.
    pub fn at_max_nonce(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn advance(&mut self) -> [u8; NONCE_LEN] {
        for index in (0..NONCE_LEN).rev() {
            self.nonce[index] = self.nonce[index].wrapping_add(1);
            if self.nonce[index] != 0 {
                break;
            }
        }
        self.nonce
    }

    fn seal_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> io::Result<[u8; TAG_LEN]> {
        let tag = match &self.cipher {
            Cipher::Aes(cipher) => cipher
                .encrypt_in_place_detached(nonce.into(), aad, buffer)
                .map_err(|_| io::Error::other("VLESS encryption AES-256-GCM seal failed"))?,
            Cipher::ChaCha(cipher) => cipher
                .encrypt_in_place_detached(nonce.into(), aad, buffer)
                .map_err(|_| io::Error::other("VLESS encryption ChaCha20-Poly1305 seal failed"))?,
        };
        Ok(tag.into())
    }

    /// Seal `plaintext_len` bytes in place at the front of `buffer`, appending
    /// the tag. `buffer` must be exactly `plaintext_len + TAG_LEN` long.
    pub fn seal_in_place(
        &mut self,
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> io::Result<()> {
        let nonce = self.advance();
        self.seal_in_place_with_nonce(&nonce, aad, buffer, plaintext_len)
    }

    pub fn seal_in_place_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> io::Result<()> {
        debug_assert_eq!(buffer.len(), plaintext_len + TAG_LEN);
        let (body, tag_slot) = buffer.split_at_mut(plaintext_len);
        let tag = self.seal_detached(nonce, aad, body)?;
        tag_slot.copy_from_slice(&tag);
        Ok(())
    }

    fn open_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8],
    ) -> io::Result<()> {
        let result = match &self.cipher {
            Cipher::Aes(cipher) => {
                cipher.decrypt_in_place_detached(nonce.into(), aad, body, tag.into())
            }
            Cipher::ChaCha(cipher) => {
                cipher.decrypt_in_place_detached(nonce.into(), aad, body, tag.into())
            }
        };
        result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS encryption AEAD authentication failed",
            )
        })
    }

    /// Open `buffer` in place. On success the plaintext occupies
    /// `buffer[..buffer.len() - TAG_LEN]`.
    pub fn open_in_place(&mut self, aad: &[u8], buffer: &mut [u8]) -> io::Result<usize> {
        let nonce = self.advance();
        self.open_in_place_with_nonce(&nonce, aad, buffer)
    }

    pub fn open_in_place_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        if buffer.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS encryption AEAD message is shorter than its tag",
            ));
        }
        let plaintext_len = buffer.len() - TAG_LEN;
        let (body, tag) = buffer.split_at_mut(plaintext_len);
        self.open_detached(nonce, aad, body, tag)?;
        Ok(plaintext_len)
    }
}

/// TLS 1.3's application-data record header, which every data record wears so
/// that a connection handed over to XTLS looks the same before and after the
/// handover.
pub fn encode_header(header: &mut [u8; 5], length: usize) {
    header[0] = 23;
    header[1] = 3;
    header[2] = 3;
    header[3] = (length >> 8) as u8;
    header[4] = length as u8;
}

/// Smallest record body: an empty payload plus its tag, plus the one byte that
/// upstream's `< 17` bound implies.
pub const MIN_RECORD_BODY: usize = 17;
/// TLS 1.3's maximum record: 16384 plus the 256 bytes RFC 8446 §5.2 allows for
/// expansion.
pub const MAX_RECORD_BODY: usize = 16640;
/// Largest plaintext upstream will put in one record. Chosen so the peer can
/// decrypt straight into the caller's buffer without a second copy.
pub const MAX_RECORD_PLAINTEXT: usize = 8192;

/// `DecodeHeader`'s length *without* the range check. A header whose magic
/// bytes are wrong decodes to zero.
///
/// The masking layer uses this rather than [`decode_header`] because upstream's
/// `XorConn` discards the error and walks on with whatever length came back;
/// diverging here would desynchronise the keystream instead of failing loudly.
pub fn decode_header_raw(header: &[u8; 5]) -> usize {
    if header[0] != 23 || header[1] != 3 || header[2] != 3 {
        return 0;
    }
    (usize::from(header[3]) << 8) | usize::from(header[4])
}

pub fn decode_header(header: &[u8; 5]) -> Option<usize> {
    let length = decode_header_raw(header);
    if !(MIN_RECORD_BODY..=MAX_RECORD_BODY).contains(&length) {
        return None;
    }
    Some(length)
}

pub fn encode_length(length: usize) -> [u8; 2] {
    [(length >> 8) as u8, length as u8]
}
