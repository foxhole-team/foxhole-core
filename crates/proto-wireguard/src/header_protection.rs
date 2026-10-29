use std::fmt;

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::WireguardError;
use crate::amnezia::AmneziaParams;

/// Non-Copy ownership; the key and cipher state are cleared on drop.
#[derive(Clone)]
pub struct HeaderProtectionKey(Zeroizing<[u8; 32]>);

impl ZeroizeOnDrop for HeaderProtectionKey {}

impl fmt::Debug for HeaderProtectionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeaderProtectionKey([REDACTED])")
    }
}

impl HeaderProtectionKey {
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    pub(crate) fn validate_prefixes(&self, params: &AmneziaParams) -> Result<(), WireguardError> {
        if [
            params.init_junk_size,
            params.response_junk_size,
            params.cookie_junk_size,
            params.transport_junk_size,
        ]
        .into_iter()
        .any(|prefix| prefix < 12)
        {
            return Err(WireguardError::InvalidParameters);
        }
        Ok(())
    }

    pub(crate) fn transform(&self, prefix: &[u8], body: &mut [u8]) -> Result<(), WireguardError> {
        let nonce: &[u8; 12] = prefix
            .get(..12)
            .and_then(|nonce| nonce.try_into().ok())
            .ok_or(WireguardError::MalformedMessage)?;
        let mut cipher = ChaCha20::new((&*self.0).into(), nonce.into());
        cipher
            .try_apply_keystream(body)
            .map_err(|_| WireguardError::MalformedMessage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    fn vector(kind: &str) {
        let vectors: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/hpk-b5928efb.json")).unwrap();
        let value = vectors.iter().find(|value| value["kind"] == kind).unwrap();
        let bytes = hex(value["key"].as_str().unwrap());
        let key =
            HeaderProtectionKey::from_bytes(Zeroizing::new(bytes.as_slice().try_into().unwrap()))
                .unwrap();
        let prefix = hex(value["prefix"].as_str().unwrap());
        let original = hex(value["plain"].as_str().unwrap());
        let mut body = original.clone();
        key.transform(&prefix, &mut body).unwrap();
        assert_eq!(
            body,
            hex(value["cipher"].as_str().unwrap()),
            "official {kind} cipher vector"
        );
        key.transform(&prefix, &mut body).unwrap();
        assert_eq!(body, original);
    }
    #[test]
    fn official_initiation_vector() {
        vector("initiation");
    }
    #[test]
    fn official_response_vector() {
        vector("response");
    }
    #[test]
    fn official_cookie_vector() {
        vector("cookie");
    }
    #[test]
    fn official_transport_header_vector() {
        vector("transport");
    }
    #[test]
    fn owned_key_is_redacted_and_zeroizing() {
        fn zeroizes<T: ZeroizeOnDrop>() {}
        zeroizes::<HeaderProtectionKey>();
        assert!(HeaderProtectionKey::from_bytes(Zeroizing::new([0; 32])).is_none());
        let key = HeaderProtectionKey::from_bytes(Zeroizing::new([1; 32])).unwrap();
        assert_eq!(format!("{key:?}"), "HeaderProtectionKey([REDACTED])");
        assert!(key.transform(&[0; 11], &mut [0; 16]).is_err());
    }
}
