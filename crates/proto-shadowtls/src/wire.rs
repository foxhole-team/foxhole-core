use std::io;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) const TLS_HANDSHAKE: u8 = 22;
pub(crate) const TLS_APPLICATION_DATA: u8 = 23;
pub(crate) const TLS_ALERT: u8 = 21;
pub(crate) const TLS_LEGACY_VERSION: [u8; 2] = [3, 3];
pub(crate) const MAX_TLS_RECORD: usize = 18 * 1024;
pub(crate) const MAX_DATA_PER_RECORD: usize = 16 * 1024 - 4;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
pub(crate) struct HmacChain(HmacSha1);

impl HmacChain {
    pub(crate) fn new(key: &[u8], initial: &[u8]) -> io::Result<Self> {
        let mut state =
            HmacSha1::new_from_slice(key).map_err(|_| invalid("ShadowTLS HMAC key is invalid"))?;
        state.update(initial);
        Ok(Self(state))
    }

    pub(crate) fn tag_and_advance(&mut self, data: &[u8]) -> [u8; 4] {
        self.0.update(data);
        let digest = self.0.clone().finalize().into_bytes();
        let mut tag = [0_u8; 4];
        tag.copy_from_slice(&digest[..4]);
        self.0.update(&tag);
        tag
    }

    pub(crate) fn verify_and_advance(&mut self, tag: &[u8], data: &[u8]) -> bool {
        if tag.len() != 4 {
            return false;
        }
        let mut candidate = self.clone();
        let expected = candidate.tag_and_advance(data);
        if expected.ct_eq(tag).into() {
            *self = candidate;
            true
        } else {
            false
        }
    }
}

/// Sign the TLS ClientHello legacy session id according to ShadowTLS v3.
pub(crate) fn sign_client_hello(record: &mut [u8], password: &[u8]) -> io::Result<()> {
    validate_record(record)?;
    if record[0] != TLS_HANDSHAKE {
        return Err(invalid("ShadowTLS first TLS record is not a handshake"));
    }
    let payload = &mut record[5..];
    if payload.len() < 4 + 2 + 32 + 1 || payload[0] != 1 {
        return Err(invalid("ShadowTLS first handshake is not ClientHello"));
    }
    let handshake_length =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if handshake_length + 4 > payload.len() {
        return Err(invalid("ShadowTLS ClientHello is truncated"));
    }
    let session_length_offset = 4 + 2 + 32;
    if payload[session_length_offset] != 32 {
        return Err(invalid(
            "ShadowTLS v3 requires a 32-byte TLS legacy session id",
        ));
    }
    let session_start = session_length_offset + 1;
    let signature_start = session_start + 28;
    payload[signature_start..signature_start + 4].fill(0);
    let mut hmac =
        HmacSha1::new_from_slice(password).map_err(|_| invalid("ShadowTLS HMAC key is invalid"))?;
    hmac.update(payload);
    let digest = hmac.finalize().into_bytes();
    payload[signature_start..signature_start + 4].copy_from_slice(&digest[..4]);
    Ok(())
}

pub(crate) fn xor_proof(data: &mut [u8], password: &[u8], random: &[u8; 32]) {
    let mut hash = Sha256::new();
    hash.update(password);
    hash.update(random);
    let mask = hash.finalize();
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
}

pub(crate) fn record_header(kind: u8, payload_length: usize) -> io::Result<[u8; 5]> {
    let length = u16::try_from(payload_length)
        .map_err(|_| invalid("ShadowTLS TLS record exceeds 65535 bytes"))?;
    Ok([
        kind,
        TLS_LEGACY_VERSION[0],
        TLS_LEGACY_VERSION[1],
        (length >> 8) as u8,
        length as u8,
    ])
}

pub(crate) fn validate_record(record: &[u8]) -> io::Result<()> {
    if record.len() < 5 {
        return Err(invalid("ShadowTLS TLS record is truncated"));
    }
    let length = u16::from_be_bytes([record[3], record[4]]) as usize;
    if length > MAX_TLS_RECORD || record.len() != 5 + length {
        return Err(invalid("ShadowTLS TLS record length is invalid"));
    }
    Ok(())
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello() -> Vec<u8> {
        let body_length = 2 + 32 + 1 + 32;
        let mut payload = vec![1, 0, 0, body_length as u8];
        payload.extend_from_slice(&[3, 3]);
        payload.extend_from_slice(&[7_u8; 32]);
        payload.push(32);
        payload.extend_from_slice(&[9_u8; 32]);
        let mut record = record_header(TLS_HANDSHAKE, payload.len())
            .unwrap()
            .to_vec();
        record.extend_from_slice(&payload);
        record
    }

    #[test]
    fn client_hello_signature_is_deterministic_and_localised() {
        let mut first = client_hello();
        let original = first.clone();
        sign_client_hello(&mut first, b"secret").unwrap();
        let mut second = original.clone();
        sign_client_hello(&mut second, b"secret").unwrap();
        assert_eq!(first, second);
        assert_eq!(&first[..72], &original[..72]);
        assert_ne!(&first[72..76], &original[72..76]);
        assert_eq!(&first[72..76], &[0x3e, 0x37, 0x52, 0xa0]);
    }

    #[test]
    fn chained_tags_reject_reorder_and_replay() {
        let mut sender = HmacChain::new(b"password", b"randomC").unwrap();
        let first = sender.tag_and_advance(b"one");
        let second = sender.tag_and_advance(b"two");
        assert_eq!(first, [0x10, 0xee, 0xf8, 0xc6]);
        assert_eq!(second, [0x5c, 0xde, 0xde, 0xb1]);
        let mut receiver = HmacChain::new(b"password", b"randomC").unwrap();
        assert!(!receiver.verify_and_advance(&second, b"two"));
        assert!(receiver.verify_and_advance(&first, b"one"));
        assert!(receiver.verify_and_advance(&second, b"two"));
        assert!(!receiver.verify_and_advance(&first, b"one"));
    }
}
