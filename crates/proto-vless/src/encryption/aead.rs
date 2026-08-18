use std::io;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use super::blake3;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

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

pub fn encode_header(header: &mut [u8; 5], length: usize) {
    header[0] = 23;
    header[1] = 3;
    header[2] = 3;
    header[3] = (length >> 8) as u8;
    header[4] = length as u8;
}

pub const MIN_RECORD_BODY: usize = 17;
pub const MAX_RECORD_BODY: usize = 16640;
pub const MAX_RECORD_PLAINTEXT: usize = 8192;

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
