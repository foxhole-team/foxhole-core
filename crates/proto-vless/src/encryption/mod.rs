//! VLESS Encryption — the post-quantum encryption layer that lives *inside*
//! VLESS, independent of TLS or REALITY.
//!
//! Upstream: [XTLS/Xray-core#5067], merged as `proxy/vless/encryption`. This is
//! the **client** half. A server would need the other half; see the report and
//! the notes on `ServerInstance` behaviour scattered through these modules.
//!
//! The layer wraps the transport connection — TCP, TLS, REALITY, WebSocket,
//! whatever the profile composed — and the plaintext VLESS request rides inside
//! it. It is deliberately not coupled to the inner protocol, which is why a
//! record here is just a TLS-shaped AEAD frame.
//!
//! What it buys over Shadowsocks 2022 or VMess, in upstream's framing:
//!
//! * **Client-config security.** The client holds public keys only, so a leaked
//!   profile decrypts neither past nor future traffic.
//! * **Forward secrecy.** `unitedKey = pfsKey ‖ nfsKey`, and `pfsKey` comes from
//!   an ephemeral ML-KEM-768 + X25519 exchange that is itself encrypted — so
//!   recording traffic now and breaking X25519 later is not enough; the server
//!   private key is needed too.
//! * **0-RTT without a clock.** Replay protection is a ticket map plus an
//!   `nfsKey` set on the server, both discarded on a timer, so neither side
//!   needs time synchronisation.
//!
//! [XTLS/Xray-core#5067]: https://github.com/XTLS/Xray-core/pull/5067

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
