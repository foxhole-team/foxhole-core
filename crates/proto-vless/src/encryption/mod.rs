mod aead;
mod blake3;
mod crypto;
mod handshake;
mod params;
mod stream;
mod xor;

pub use crypto::{HandshakeCrypto, LiveCrypto, NfsShare, PfsOffer};
pub use handshake::{ClientInstance, prefer_aes};
pub use params::{
    EncryptionError, EncryptionParams, ML_KEM_768_ENCAPSULATION_KEY_LEN, NfsPublicKey,
    PaddingParams, PaddingRange, SUITE_MLKEM768X25519PLUS, X25519_LEN, XorMode, parse_encryption,
    parse_padding,
};
pub use stream::{EncryptedStream, SessionCache};
