// VMess AEAD KDF and key derivation are adapted from Shoes, commit
// 386b11532424b8665ee3e46340c6236fb3c47595 (MIT). See THIRD_PARTY_NOTICES.md.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as _};
use aes_gcm::aead::{AeadInPlace, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use md5::{Digest as _, Md5};
use sha2::Sha256;

trait VmessHash: std::fmt::Debug + Send {
    fn fork(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> [u8; 32];
}

#[derive(Clone)]
struct Sha256Hash(Sha256);

impl std::fmt::Debug for Sha256Hash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Sha256Hash(..)")
    }
}

impl VmessHash for Sha256Hash {
    fn fork(&self) -> Box<dyn VmessHash> {
        Box::new(self.clone())
    }

    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.0, data);
    }

    fn finalize(&self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

#[derive(Debug)]
struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
}

impl RecursiveHash {
    fn new(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        debug_assert!(key.len() <= 64);
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for (index, byte) in key.iter().copied().enumerate() {
            inner_pad[index] ^= byte;
            outer_pad[index] ^= byte;
        }
        let mut inner = hash.fork();
        inner.update(&inner_pad);
        Self {
            inner,
            outer: hash,
            inner_pad,
            outer_pad,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn fork(&self) -> Box<dyn VmessHash> {
        Box::new(Self {
            inner: self.inner.fork(),
            outer: self.outer.fork(),
            inner_pad: self.inner_pad,
            outer_pad: self.outer_pad,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&self) -> [u8; 32] {
        let mut outer = self.outer.fork();
        outer.update(&self.outer_pad);
        outer.update(&self.inner.finalize());
        outer.finalize()
    }
}

pub(crate) fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current: Box<dyn VmessHash> = Box::new(RecursiveHash::new(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash(Sha256::new())),
    ));
    for item in path {
        current = Box::new(RecursiveHash::new(item, current));
    }
    current.update(key);
    current.finalize()
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub(crate) fn chacha_key(data: &[u8]) -> [u8; 32] {
    let first = md5(data);
    let second = md5(&first);
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

pub(crate) fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

pub(crate) fn aes128_gcm_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &mut [u8],
) -> Result<[u8; 16], ()> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| ())?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, plaintext)
        .map_err(|_| ())?;
    Ok(tag.into())
}

pub(crate) fn aes128_gcm_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8],
) -> Result<(), ()> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| ())?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            ciphertext,
            Tag::from_slice(tag),
        )
        .map_err(|_| ())
}

pub(crate) fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

/// IEEE CRC-32 used by VMess AuthID (despite some implementations naming it
/// `crc32c`). The tiny bitwise form only processes the 12-byte AuthID prefix.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_hash_vectors_match() {
        assert_eq!(
            hex(&sha256(b"hello")),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(hex(&md5(b"hello")), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(fnv1a(b"hello"), 0x4f9f_2cab);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn vmess_recursive_kdf_is_deterministic_and_domain_separated() {
        let key = [0x11_u8; 16];
        let one = kdf(&key, &[b"VMess Header AEAD Key_Length"]);
        let two = kdf(&key, &[b"VMess Header AEAD Nonce_Length"]);
        assert_ne!(one, two);
        assert_eq!(one, kdf(&key, &[b"VMess Header AEAD Key_Length"]));
        assert_ne!(one, sha256(&key));
    }

    #[test]
    fn chacha_key_matches_vmess_double_md5_layout() {
        let source = [7_u8; 16];
        let key = chacha_key(&source);
        assert_eq!(&key[..16], &md5(&source));
        assert_eq!(&key[16..], &md5(&key[..16]));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
