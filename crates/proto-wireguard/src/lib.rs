//! WireGuard for FoxCore.
//!
//! This is the L3 half of the core: instead of terminating TCP and re-dialing,
//! it takes whole IP packets, seals them and hands back a UDP payload. The
//! crate owns cryptography and state only — sockets, timers and routing live in
//! the layer above, which keeps the protocol testable without any I/O.

#![forbid(unsafe_code)]

pub mod amnezia;
pub mod initpacket;
pub mod message;
pub mod noise;
pub mod session;
pub mod tunnel;

/// Every way a WireGuard exchange can fail. Errors never carry key material or
/// endpoints so they stay safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireguardError {
    /// A datagram that is not the message type the state machine expected.
    UnexpectedMessage,
    /// Right type, wrong shape — a length the protocol cannot produce.
    MalformedMessage,
    /// AEAD authentication failed: wrong key, replayed nonce or tampering.
    Decryption,
    /// AEAD encryption refused the supplied in-memory buffer.
    Encryption,
    /// A key that is not a valid X25519 scalar or point.
    InvalidKey,
    /// The operating system could not provide cryptographically secure entropy.
    EntropyUnavailable,
    /// A transport datagram whose counter was already accepted.
    Replay,
    /// The session hit the hard message limit and must rekey before sending.
    SessionExpired,
    /// AmneziaWG obfuscation parameters that cannot describe a working session.
    InvalidParameters,
}

impl std::fmt::Display for WireguardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnexpectedMessage => "unexpected WireGuard message",
            Self::MalformedMessage => "malformed WireGuard message",
            Self::Decryption => "WireGuard decryption failed",
            Self::Encryption => "WireGuard encryption failed",
            Self::InvalidKey => "invalid WireGuard key",
            Self::EntropyUnavailable => "operating system entropy unavailable",
            Self::Replay => "replayed WireGuard counter",
            Self::SessionExpired => "WireGuard session reached its message limit",
            Self::InvalidParameters => "invalid AmneziaWG obfuscation parameters",
        })
    }
}

impl std::error::Error for WireguardError {}
