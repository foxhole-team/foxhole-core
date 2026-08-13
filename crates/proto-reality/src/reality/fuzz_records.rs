//! The TLS 1.3 record layer, opened to the fuzz harness in `fuzz/`.
//!
//! Compiled only under the `fuzzing` feature, which nothing in the workspace
//! enables. The record layer is where a REALITY server's bytes first become
//! structure — length prefix, AEAD tag, `TLSInnerPlaintext` trailer — and it is
//! private because the only legitimate caller is the reader/writer above it.
//! Reaching it from a fuzz target through `RealityClientConnection` would mean
//! completing an X25519 handshake first, which no fuzzer will ever do by
//! mutation, so the record parser would never be reached at all.

use std::io;

use super::common::{MAX_TLS_CIPHERTEXT_LEN, MAX_TLS_PLAINTEXT_LEN, TLS_RECORD_HEADER_SIZE};
use super::reality_aead::AeadKey;
use super::reality_cipher_suite::CipherSuite;
use super::reality_records::{RecordDecryptor, RecordEncryptor};

/// Largest plaintext one record may carry before fragmentation.
pub const MAX_PLAINTEXT: usize = MAX_TLS_PLAINTEXT_LEN;
/// Largest ciphertext a record header may declare.
pub const MAX_CIPHERTEXT: usize = MAX_TLS_CIPHERTEXT_LEN;
/// `ContentType | ProtocolVersion | Length`.
pub const RECORD_HEADER: usize = TLS_RECORD_HEADER_SIZE;
/// Poly1305/GCM tag appended by the AEAD.
pub const TAG: usize = 16;
/// The three inner content types the decryptor is allowed to return.
pub const ALLOWED_CONTENT_TYPES: [u8; 3] = [
    super::common::CONTENT_TYPE_ALERT,
    super::common::CONTENT_TYPE_HANDSHAKE,
    super::common::CONTENT_TYPE_APPLICATION_DATA,
];

/// The suite the harness pins. One suite is enough: the record framing is
/// suite-independent and the other two only change key and tag sizes.
const SUITE: CipherSuite = CipherSuite::AES_128_GCM_SHA256;

/// Key length `SUITE` requires; a harness that passes anything else gets an
/// error rather than a panic.
pub const KEY_LEN: usize = 16;
/// IV length the nonce construction requires.
pub const IV_LEN: usize = 12;

/// Encrypt `plaintext` into a record stream, exactly as the write side does.
///
/// `plaintext` is cleared on success, which is the contract the writer relies
/// on and therefore part of what the harness asserts.
pub fn encrypt_app_data(
    key: &[u8],
    iv: &[u8],
    seq: &mut u64,
    plaintext: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let key = AeadKey::new(SUITE, key)?;
    RecordEncryptor::new(&key, iv, seq).encrypt_app_data(plaintext, out)
}

/// Decrypt one record in place and return `(content_type, plaintext)`.
///
/// The plaintext is copied out rather than borrowed so the harness does not
/// have to thread the lifetime; the parsing under test is unaffected.
pub fn decrypt_record(
    key: &[u8],
    iv: &[u8],
    seq: &mut u64,
    ciphertext: &mut [u8],
    record_len: u16,
) -> io::Result<(u8, Vec<u8>)> {
    let key = AeadKey::new(SUITE, key)?;
    let (content_type, plaintext) =
        RecordDecryptor::new(&key, iv, seq).decrypt_record_in_place(ciphertext, record_len)?;
    Ok((content_type, plaintext.to_vec()))
}
