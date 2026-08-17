//! The `encryption=` grammar lives in `foxcore-api`.
//!
//! It has to: `foxcore-link` refuses unsupported variants by name at import
//! time and cannot depend on a protocol crate, while this crate needs the same
//! parse to drive the handshake. `foxcore-api` is the only thing both see.
//!
//! The names are prefixed there because that crate has a flat public namespace;
//! they are aliased back to short ones here, where the module already says what
//! they are about.

pub use foxcore_api::{
    VLESS_ENCRYPTION_ML_KEM_768_CIPHERTEXT_LEN as ML_KEM_768_CIPHERTEXT_LEN,
    VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN as ML_KEM_768_ENCAPSULATION_KEY_LEN,
    VLESS_ENCRYPTION_ML_KEM_768_SECRET_LEN as ML_KEM_768_SHARED_SECRET_LEN,
    VLESS_ENCRYPTION_SUITE as SUITE_MLKEM768X25519PLUS,
    VLESS_ENCRYPTION_X25519_KEY_LEN as X25519_LEN, VlessEncryptionError as EncryptionError,
    VlessEncryptionKey as NfsPublicKey, VlessEncryptionMode as XorMode,
    VlessEncryptionPadding as PaddingParams, VlessEncryptionPaddingRange as PaddingRange,
    VlessEncryptionParams as EncryptionParams, parse_vless_encryption as parse_encryption,
    parse_vless_encryption_padding as parse_padding,
};
