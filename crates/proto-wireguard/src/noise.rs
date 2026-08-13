//! Noise IKpsk2 handshake as WireGuard specialises it.
//!
//! Only the initiator role is built: on Android FoxCore is always the client.
//! The responder appears in tests, where it is the honest way to prove the
//! handshake without a server.
//!
//! Every step follows the WireGuard whitepaper §5.4 in order; the chaining key
//! and transcript hash are threaded through unchanged so a mismatch anywhere
//! surfaces as a failed AEAD rather than a silently weaker session.

use aws_lc_rs::agreement::{PrivateKey, UnparsedPublicKey, X25519, agree};
use blake2::digest::{FixedOutput, KeyInit as BlakeKeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Tag as XChaChaTag, XChaCha20Poly1305};
use zeroize::{Zeroize, Zeroizing};

use subtle::ConstantTimeEq;

use crate::WireguardError;
use crate::message::{INITIATION_MAC1_OFFSET, Initiation, Response, TAG_LEN};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const BLAKE2S_BLOCK_LEN: usize = 64;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const MAC_LEN: usize = 16;
const TIMESTAMP_LEN: usize = 12;

/// TAI64 epoch offset including the ten leap seconds WireGuard bakes in.
const TAI64_OFFSET: u64 = (1_u64 << 62) + 10;

pub type Key = [u8; KEY_LEN];

/// BLAKE2s-256, the protocol's `HASH`.
pub(crate) fn hash(parts: &[&[u8]]) -> Key {
    let mut hasher = Blake2s256::new();
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

/// Keyed BLAKE2s with a 16-byte tag, the protocol's `MAC`.
pub(crate) fn mac(key: &Key, data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <Blake2sMac<blake2::digest::consts::U16> as BlakeKeyInit>::new(key.into());
    Mac::update(&mut mac, data);
    mac.finalize_fixed().into()
}

/// HMAC-BLAKE2s. WireGuard's KDF is HMAC-based, not the keyed BLAKE2s above.
fn hmac(key: &[u8], data: &[&[u8]]) -> Key {
    let mut padded = [0_u8; BLAKE2S_BLOCK_LEN];
    if key.len() > BLAKE2S_BLOCK_LEN {
        padded[..KEY_LEN].copy_from_slice(&hash(&[key]));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = padded;
    let mut outer_pad = padded;
    for (inner, outer) in inner_pad.iter_mut().zip(outer_pad.iter_mut()) {
        *inner ^= 0x36;
        *outer ^= 0x5C;
    }

    let mut inner = Blake2s256::new();
    Digest::update(&mut inner, inner_pad);
    for part in data {
        Digest::update(&mut inner, part);
    }
    let inner: Key = inner.finalize().into();

    let mut outer = Blake2s256::new();
    Digest::update(&mut outer, outer_pad);
    Digest::update(&mut outer, inner);

    padded.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    outer.finalize().into()
}

fn kdf1(chaining_key: &Key, input: &[u8]) -> Key {
    let secret = hmac(chaining_key, &[input]);
    hmac(&secret, &[&[0x01]])
}

fn kdf2(chaining_key: &Key, input: &[u8]) -> (Key, Key) {
    let secret = hmac(chaining_key, &[input]);
    let first = hmac(&secret, &[&[0x01]]);
    let second = hmac(&secret, &[&first, &[0x02]]);
    (first, second)
}

fn kdf3(chaining_key: &Key, input: &[u8]) -> (Key, Key, Key) {
    let secret = hmac(chaining_key, &[input]);
    let first = hmac(&secret, &[&[0x01]]);
    let second = hmac(&secret, &[&first, &[0x02]]);
    let third = hmac(&secret, &[&second, &[0x03]]);
    (first, second, third)
}

/// ChaCha20-Poly1305 with WireGuard's nonce layout: four zero bytes then the
/// counter little-endian.
pub(crate) fn aead_seal(
    key: &Key,
    counter: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, WireguardError> {
    let mut buffer = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buffer.extend_from_slice(plaintext);
    let tag = aead_seal_in_place(key, counter, &mut buffer, aad)?;
    buffer.extend_from_slice(&tag);
    Ok(buffer)
}

/// Encrypt `buffer` where it lies and hand back the tag.
///
/// The data path uses this one. `aead_seal` above allocates a buffer per call
/// and grows it again to append the tag, which is fine for the handful of
/// handshake fields it seals and is not fine once per packet — the transport
/// path builds its whole datagram in one buffer and only needs somewhere to put
/// the sixteen bytes at the end.
pub(crate) fn aead_seal_in_place(
    key: &Key,
    counter: u64,
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<[u8; TAG_LEN], WireguardError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(&nonce(counter).into(), aad, buffer)
        .map_err(|_| WireguardError::Encryption)?;
    let mut bytes = [0_u8; TAG_LEN];
    bytes.copy_from_slice(&tag);
    Ok(bytes)
}

/// Decrypt in place; the returned length is the plaintext length.
pub(crate) fn aead_open(
    key: &Key,
    counter: u64,
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<usize, WireguardError> {
    if buffer.len() < TAG_LEN {
        return Err(WireguardError::MalformedMessage);
    }
    let (data, tag) = buffer.split_at_mut(buffer.len() - TAG_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(&nonce(counter).into(), aad, data, (&*tag).into())
        .map_err(|_| WireguardError::Decryption)?;
    Ok(data.len())
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn dh(private: &PrivateKey, peer: &Key) -> Result<Key, WireguardError> {
    agree(
        private,
        UnparsedPublicKey::new(&X25519, peer),
        WireguardError::InvalidKey,
        |shared| {
            let mut out = [0_u8; KEY_LEN];
            out.copy_from_slice(shared);
            Ok(out)
        },
    )
}

fn private_key(bytes: &Key) -> Result<PrivateKey, WireguardError> {
    PrivateKey::from_private_key(&X25519, bytes).map_err(|_| WireguardError::InvalidKey)
}

/// Public key for a raw X25519 private key, as WireGuard prints it.
pub fn public_key(private: &Key) -> Result<Key, WireguardError> {
    let private = private_key(private)?;
    let public = private
        .compute_public_key()
        .map_err(|_| WireguardError::InvalidKey)?;
    let mut out = [0_u8; KEY_LEN];
    out.copy_from_slice(public.as_ref());
    Ok(out)
}

/// TAI64N timestamp; the responder uses it to reject replayed initiations.
pub fn tai64n(now: std::time::SystemTime) -> [u8; TIMESTAMP_LEN] {
    let since_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut stamp = [0_u8; TIMESTAMP_LEN];
    stamp[..8].copy_from_slice(&(since_epoch.as_secs() + TAI64_OFFSET).to_be_bytes());
    stamp[8..].copy_from_slice(&since_epoch.subsec_nanos().to_be_bytes());
    stamp
}

/// Static identity of this peer plus the remote it talks to.
pub struct StaticIdentity {
    private: PrivateKey,
    pub public: Key,
    pub peer_public: Key,
    pub preshared_key: Key,
}

impl StaticIdentity {
    /// Clear the secrets this identity holds.
    ///
    /// A named method rather than only a `Drop` body so a test can call it: this
    /// crate forbids `unsafe`, so reading a freed allocation to check that the
    /// destructor did its job is not available, and the next best thing is to
    /// prove the wipe itself and that `Drop` is the only caller.
    fn wipe(&mut self) {
        self.preshared_key.zeroize();
    }
}

impl Drop for StaticIdentity {
    /// `PrivateKey` wipes itself; the preshared key is a plain array and would
    /// otherwise be left in whatever memory the allocator hands out next.
    fn drop(&mut self) {
        self.wipe();
    }
}

impl StaticIdentity {
    pub fn new(
        private: &Key,
        peer_public: Key,
        preshared_key: Option<Key>,
    ) -> Result<Self, WireguardError> {
        Ok(Self {
            private: private_key(private)?,
            public: public_key(private)?,
            peer_public,
            // Absent PSK is specified as all zeros, not as "skip the step".
            preshared_key: preshared_key.unwrap_or([0_u8; KEY_LEN]),
        })
    }
}

/// Handshake in flight.
///
/// Deriving the transport keys borrows it rather than consuming it, because the
/// tunnel must be able to *refuse* a response — a forged or corrupted one —
/// without losing the initiation it is still waiting on. Only the tunnel drops
/// the handshake, and only once a response has actually opened.
pub struct Handshake {
    chaining_key: Key,
    hash: Key,
    ephemeral: PrivateKey,
    pub sender_index: u32,
}

impl Handshake {
    /// Clear the secrets carried between the two halves of the handshake.
    /// See [`StaticIdentity::wipe`] for why this is a named method.
    fn wipe(&mut self) {
        self.chaining_key.zeroize();
        self.hash.zeroize();
    }
}

impl Drop for Handshake {
    /// The chaining key is the secret every transport key descends from, so it
    /// must not outlive the handshake in freed memory. `PrivateKey` wipes
    /// itself; the transcript hash is not secret but costs nothing to clear.
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Keys a completed handshake yields.
pub struct TransportKeys {
    pub send: Key,
    pub receive: Key,
    pub sender_index: u32,
    pub receiver_index: u32,
}

impl TransportKeys {
    /// Clear both session keys. See [`StaticIdentity::wipe`].
    fn wipe(&mut self) {
        self.send.zeroize();
        self.receive.zeroize();
    }
}

impl Drop for TransportKeys {
    /// `TransportSession::new` copies these out — `Key` is `Copy` — so without
    /// this the session keys stay readable in the carrier struct's stack slot
    /// for as long as that memory goes unwritten.
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Handshake {
    /// Build the initiation message. `ephemeral_seed` is the raw private key to
    /// use; callers pass fresh randomness, tests pass a fixed value.
    pub fn initiate(
        identity: &StaticIdentity,
        sender_index: u32,
        ephemeral_seed: &Key,
        timestamp: [u8; TIMESTAMP_LEN],
    ) -> Result<(Self, Initiation), WireguardError> {
        let chaining_key = hash(&[CONSTRUCTION]);
        let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
        transcript = hash(&[&transcript, &identity.peer_public]);

        let ephemeral = private_key(ephemeral_seed)?;
        let ephemeral_public = public_key(ephemeral_seed)?;
        // As in `consume_response`: each secret intermediate is wiped when the
        // next one replaces it.
        let mut chaining_key = Zeroizing::new(kdf1(&chaining_key, &ephemeral_public));
        transcript = hash(&[&transcript, &ephemeral_public]);

        let ephemeral_shared = Zeroizing::new(dh(&ephemeral, &identity.peer_public)?);
        let (next, key) = kdf2(&chaining_key, &ephemeral_shared[..]);
        chaining_key = Zeroizing::new(next);
        let key = Zeroizing::new(key);
        let encrypted_static = aead_seal(&key, 0, &identity.public, &transcript)?;
        transcript = hash(&[&transcript, &encrypted_static]);

        let static_shared = Zeroizing::new(dh(&identity.private, &identity.peer_public)?);
        let (next, key) = kdf2(&chaining_key, &static_shared[..]);
        chaining_key = Zeroizing::new(next);
        let key = Zeroizing::new(key);
        let encrypted_timestamp = aead_seal(&key, 0, &timestamp, &transcript)?;
        transcript = hash(&[&transcript, &encrypted_timestamp]);

        let mut initiation = Initiation {
            sender_index,
            ephemeral: ephemeral_public,
            encrypted_static: encrypted_static
                .try_into()
                .map_err(|_| WireguardError::MalformedMessage)?,
            encrypted_timestamp: encrypted_timestamp
                .try_into()
                .map_err(|_| WireguardError::MalformedMessage)?,
            mac1: [0; MAC_LEN],
            mac2: [0; MAC_LEN],
        };
        initiation.mac1 = compute_mac1(
            &identity.peer_public,
            &initiation.encode(),
            INITIATION_MAC1_OFFSET,
        );

        Ok((
            Self {
                chaining_key: *chaining_key,
                hash: transcript,
                ephemeral,
                sender_index,
            },
            initiation,
        ))
    }

    /// Derive the transport keys from the responder's message.
    ///
    /// Takes `&self`: a response that fails to open must leave the handshake
    /// exactly as it was. Consuming it here meant that any datagram which
    /// reached this socket and merely *looked* like a response — 92 bytes with
    /// the right type byte — destroyed the initiation the client was waiting
    /// on, and the peer's real answer then had nothing to complete.
    pub fn consume_response(
        &self,
        identity: &StaticIdentity,
        response: &Response,
    ) -> Result<TransportKeys, WireguardError> {
        if response.receiver_index != self.sender_index {
            return Err(WireguardError::UnexpectedMessage);
        }

        // Every intermediate below is a secret that the transport keys descend
        // from. `Zeroizing` wipes each one as the next assignment drops it, so
        // the chain leaves nothing behind on the stack.
        let mut chaining_key = Zeroizing::new(kdf1(&self.chaining_key, &response.ephemeral));
        let mut transcript = hash(&[&self.hash, &response.ephemeral]);
        let ephemeral_shared = Zeroizing::new(dh(&self.ephemeral, &response.ephemeral)?);
        chaining_key = Zeroizing::new(kdf1(&chaining_key, &ephemeral_shared[..]));
        let static_shared = Zeroizing::new(dh(&identity.private, &response.ephemeral)?);
        chaining_key = Zeroizing::new(kdf1(&chaining_key, &static_shared[..]));

        let (next, tau, key) = kdf3(&chaining_key, &identity.preshared_key);
        chaining_key = Zeroizing::new(next);
        let tau = Zeroizing::new(tau);
        let key = Zeroizing::new(key);
        transcript = hash(&[&transcript, &tau[..]]);

        let mut empty = response.encrypted_empty;
        if aead_open(&key, 0, &mut empty, &transcript)? != 0 {
            return Err(WireguardError::MalformedMessage);
        }

        // Initiator sends with the first key, receives with the second.
        let (send, receive) = kdf2(&chaining_key, &[]);
        Ok(TransportKeys {
            send,
            receive,
            sender_index: self.sender_index,
            receiver_index: response.sender_index,
        })
    }
}

/// `mac1` binds a message to the peer's static public key, so an off-path
/// sender cannot make the responder do handshake work.
pub(crate) fn compute_mac1(peer_public: &Key, encoded: &[u8], offset: usize) -> [u8; MAC_LEN] {
    let key = hash(&[LABEL_MAC1, peer_public]);
    mac(&key, &encoded[..offset])
}

/// Check the `mac1` of a message addressed to *us*.
///
/// The sender keys it with our own static public key, so this is one keyed
/// BLAKE2s over 60 bytes — and it is the only part of a handshake response that
/// can be checked before the two Diffie-Hellman operations and the AEAD open
/// that follow. Verifying it first is what stops an unauthenticated flood from
/// buying an X25519 pair per datagram; a sender that cannot produce it does not
/// know the public key of the peer it claims to be answering.
///
/// Constant time, because a MAC compared with `==` leaks where it first differs.
pub(crate) fn verify_mac1(
    local_public: &Key,
    encoded: &[u8],
    offset: usize,
    claimed: &[u8; MAC_LEN],
) -> bool {
    compute_mac1(local_public, encoded, offset)
        .ct_eq(claimed)
        .into()
}

/// `mac2` proves the sender received the responder's cookie, which proves it can
/// receive at the address it claims (WireGuard §5.3). Zero until a cookie
/// arrives; a loaded responder ignores every message whose `mac2` is zero.
///
/// Keyed with the cookie itself and taken over everything ahead of the field,
/// `mac1` included — so it cannot be lifted off one message onto another.
pub(crate) fn compute_mac2(cookie: &[u8; MAC_LEN], encoded: &[u8], offset: usize) -> [u8; MAC_LEN] {
    // Keyed with the 16-byte cookie as it stands, not padded out to `KEY_LEN`:
    // BLAKE2s takes any key up to 32 bytes and a padded key is a different key,
    // so the peer would compute something else.
    let mut mac = <Blake2sMac<blake2::digest::consts::U16> as BlakeKeyInit>::new_from_slice(cookie)
        .expect("BLAKE2s accepts any key up to 32 bytes");
    Mac::update(&mut mac, &encoded[..offset]);
    mac.finalize_fixed().into()
}

/// Recover the cookie from a responder's cookie reply.
///
/// XChaCha20-Poly1305 under `HASH(LABEL_COOKIE || Spub_responder)`, with the
/// `mac1` of the message that provoked the reply as associated data. That AAD is
/// what makes a cookie reply unusable by anyone who did not send the message it
/// answers: an attacker who copies the reply cannot bind it to a message of
/// their own.
pub(crate) fn open_cookie(
    peer_public: &Key,
    nonce: &[u8; 24],
    encrypted_cookie: &[u8; MAC_LEN + TAG_LEN],
    mac1: &[u8; MAC_LEN],
) -> Result<[u8; MAC_LEN], WireguardError> {
    let key = hash(&[LABEL_COOKIE, peer_public]);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut buffer = [0_u8; MAC_LEN];
    buffer.copy_from_slice(&encrypted_cookie[..MAC_LEN]);
    let tag = XChaChaTag::from_slice(&encrypted_cookie[MAC_LEN..]);
    cipher
        .decrypt_in_place_detached(nonce.into(), mac1, &mut buffer, tag)
        .map_err(|_| WireguardError::Decryption)?;
    Ok(buffer)
}

/// Test-only responder. It lives beside the initiator because it needs the same
/// private KDF/AEAD helpers; the tunnel and the relay above it reuse it to drive
/// a whole session. Gated behind `test-support` so it cannot reach production:
/// FoxCore never serves WireGuard.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use crate::message::{CookieReply, RESPONSE_MAC1_OFFSET};

    pub struct Responder {
        private: PrivateKey,
        public: Key,
        preshared_key: Key,
    }

    impl Responder {
        pub fn new(seed: &Key, preshared_key: Key) -> Result<Self, WireguardError> {
            Ok(Self {
                private: private_key(seed)?,
                public: public_key(seed)?,
                preshared_key,
            })
        }

        pub fn respond(
            &self,
            initiation: &Initiation,
            ephemeral_seed: &Key,
            sender_index: u32,
        ) -> Result<(Response, Key, Key), WireguardError> {
            let chaining_key = hash(&[CONSTRUCTION]);
            let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
            transcript = hash(&[&transcript, &self.public]);

            let chaining_key = kdf1(&chaining_key, &initiation.ephemeral);
            transcript = hash(&[&transcript, &initiation.ephemeral]);

            let (chaining_key, key) =
                kdf2(&chaining_key, &dh(&self.private, &initiation.ephemeral)?);
            let mut peer_static = initiation.encrypted_static;
            let length = aead_open(&key, 0, &mut peer_static, &transcript)?;
            if length != KEY_LEN {
                return Err(WireguardError::MalformedMessage);
            }
            let peer_static = *peer_static
                .first_chunk::<KEY_LEN>()
                .ok_or(WireguardError::MalformedMessage)?;
            transcript = hash(&[&transcript, &initiation.encrypted_static]);

            let (chaining_key, key) = kdf2(&chaining_key, &dh(&self.private, &peer_static)?);
            let mut timestamp = initiation.encrypted_timestamp;
            aead_open(&key, 0, &mut timestamp, &transcript)?;
            transcript = hash(&[&transcript, &initiation.encrypted_timestamp]);

            let ephemeral = private_key(ephemeral_seed)?;
            let ephemeral_public = public_key(ephemeral_seed)?;
            let chaining_key = kdf1(&chaining_key, &ephemeral_public);
            transcript = hash(&[&transcript, &ephemeral_public]);
            let chaining_key = kdf1(&chaining_key, &dh(&ephemeral, &initiation.ephemeral)?);
            let chaining_key = kdf1(&chaining_key, &dh(&ephemeral, &peer_static)?);

            let (chaining_key, tau, key) = kdf3(&chaining_key, &self.preshared_key);
            transcript = hash(&[&transcript, &tau[..]]);
            let encrypted_empty = aead_seal(&key, 0, &[], &transcript)?;
            transcript = hash(&[&transcript, &encrypted_empty]);
            let _ = transcript;

            let mut response = Response {
                sender_index,
                receiver_index: initiation.sender_index,
                ephemeral: ephemeral_public,
                encrypted_empty: encrypted_empty
                    .try_into()
                    .map_err(|_| WireguardError::MalformedMessage)?,
                mac1: [0; MAC_LEN],
                mac2: [0; MAC_LEN],
            };
            response.mac1 = compute_mac1(&peer_static, &response.encode(), RESPONSE_MAC1_OFFSET);

            // Responder receives with the first key and sends with the second.
            let (receive, send) = kdf2(&chaining_key, &[]);
            Ok((response, send, receive))
        }

        /// Answer an initiation the way a loaded responder does (§5.3): a cookie
        /// instead of a response, sealed under this responder's static public
        /// key with the initiation's own `mac1` as associated data.
        ///
        /// Written from the wire format rather than by calling the initiator's
        /// helper, so the test it serves compares two independent readings of
        /// the specification instead of one implementation against itself.
        pub fn issue_cookie(
            &self,
            initiation: &Initiation,
            cookie: [u8; MAC_LEN],
            nonce: [u8; 24],
        ) -> Result<CookieReply, WireguardError> {
            let key = hash(&[LABEL_COOKIE, &self.public]);
            let cipher = XChaCha20Poly1305::new((&key).into());
            let mut sealed = [0_u8; MAC_LEN + TAG_LEN];
            sealed[..MAC_LEN].copy_from_slice(&cookie);
            let (body, tag_slot) = sealed.split_at_mut(MAC_LEN);
            let tag = cipher
                .encrypt_in_place_detached((&nonce).into(), &initiation.mac1, body)
                .map_err(|_| WireguardError::Encryption)?;
            tag_slot.copy_from_slice(&tag);
            Ok(CookieReply {
                receiver_index: initiation.sender_index,
                nonce,
                encrypted_cookie: sealed,
            })
        }

        /// The `mac2` this responder would require of the next initiation.
        pub fn expected_mac2(
            &self,
            cookie: &[u8; MAC_LEN],
            initiation: &Initiation,
        ) -> [u8; MAC_LEN] {
            let mut mac =
                <Blake2sMac<blake2::digest::consts::U16> as BlakeKeyInit>::new_from_slice(cookie)
                    .expect("BLAKE2s accepts any key up to 32 bytes");
            Mac::update(
                &mut mac,
                &initiation.encode()[..crate::message::INITIATION_MAC2_OFFSET],
            );
            mac.finalize_fixed().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::Responder;
    use super::*;

    const CLIENT_STATIC: Key = [0x01; 32];
    const CLIENT_EPHEMERAL: Key = [0x02; 32];
    const SERVER_STATIC: Key = [0x03; 32];
    const SERVER_EPHEMERAL: Key = [0x04; 32];

    fn identity(preshared_key: Option<Key>) -> StaticIdentity {
        StaticIdentity::new(
            &CLIENT_STATIC,
            public_key(&SERVER_STATIC).unwrap(),
            preshared_key,
        )
        .unwrap()
    }

    #[test]
    fn handshake_agrees_on_transport_keys() {
        let identity = identity(None);
        let (handshake, initiation) = Handshake::initiate(
            &identity,
            0x1234_5678,
            &CLIENT_EPHEMERAL,
            tai64n(std::time::UNIX_EPOCH),
        )
        .unwrap();

        let responder = Responder::new(&SERVER_STATIC, [0; KEY_LEN]).unwrap();
        let (response, server_send, server_receive) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 0x9ABC_DEF0)
            .unwrap();

        let keys = handshake.consume_response(&identity, &response).unwrap();
        assert_eq!(keys.send, server_receive, "client send == server receive");
        assert_eq!(keys.receive, server_send, "client receive == server send");
        assert_eq!(keys.sender_index, 0x1234_5678);
        assert_eq!(keys.receiver_index, 0x9ABC_DEF0);
    }

    #[test]
    fn preshared_key_changes_the_session() {
        let plain = identity(None);
        let (handshake, initiation) =
            Handshake::initiate(&plain, 1, &CLIENT_EPHEMERAL, tai64n(std::time::UNIX_EPOCH))
                .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0; KEY_LEN]).unwrap();
        let (response, _, _) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 2)
            .unwrap();
        let without = handshake.consume_response(&plain, &response).unwrap();

        let psk = [0x77; KEY_LEN];
        let keyed = identity(Some(psk));
        let (handshake, initiation) =
            Handshake::initiate(&keyed, 1, &CLIENT_EPHEMERAL, tai64n(std::time::UNIX_EPOCH))
                .unwrap();
        let responder = Responder::new(&SERVER_STATIC, psk).unwrap();
        let (response, _, _) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 2)
            .unwrap();
        let with = handshake.consume_response(&keyed, &response).unwrap();

        assert_ne!(without.send, with.send);
    }

    #[test]
    fn a_mismatched_preshared_key_fails_closed() {
        let identity = identity(Some([0x11; KEY_LEN]));
        let (handshake, initiation) = Handshake::initiate(
            &identity,
            1,
            &CLIENT_EPHEMERAL,
            tai64n(std::time::UNIX_EPOCH),
        )
        .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0x22; KEY_LEN]).unwrap();
        let (response, _, _) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 2)
            .unwrap();
        assert!(matches!(
            handshake.consume_response(&identity, &response),
            Err(WireguardError::Decryption)
        ));
    }

    #[test]
    fn a_response_for_another_handshake_is_refused() {
        let identity = identity(None);
        let (handshake, initiation) = Handshake::initiate(
            &identity,
            7,
            &CLIENT_EPHEMERAL,
            tai64n(std::time::UNIX_EPOCH),
        )
        .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0; KEY_LEN]).unwrap();
        let (mut response, _, _) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 2)
            .unwrap();
        response.receiver_index = 8;
        assert!(matches!(
            handshake.consume_response(&identity, &response),
            Err(WireguardError::UnexpectedMessage)
        ));
    }

    #[test]
    fn initiation_carries_a_mac1_the_peer_can_verify() {
        let identity = identity(None);
        let (_, initiation) = Handshake::initiate(
            &identity,
            1,
            &CLIENT_EPHEMERAL,
            tai64n(std::time::UNIX_EPOCH),
        )
        .unwrap();
        // The peer recomputes mac1 from its own static key and must match; a
        // wrong key must not, which is what makes mac1 a proof-of-knowledge.
        let server_public = public_key(&SERVER_STATIC).unwrap();
        let encoded = initiation.encode();
        assert_eq!(
            compute_mac1(&server_public, &encoded, INITIATION_MAC1_OFFSET),
            initiation.mac1
        );
        assert_ne!(
            compute_mac1(
                &public_key(&CLIENT_STATIC).unwrap(),
                &encoded,
                INITIATION_MAC1_OFFSET
            ),
            initiation.mac1
        );
    }

    /// Every secret this module holds past one function call is wiped when its
    /// owner is dropped.
    ///
    /// `unsafe` is forbidden here, so the destructor cannot be caught reading a
    /// freed allocation. What is checked instead is the whole of what the
    /// destructor does — the wipe itself, on values that demonstrably held key
    /// material first — plus the fact that each type has a destructor at all,
    /// which is the part a later edit is most likely to remove by turning one of
    /// them back into a plain struct.
    #[test]
    fn every_carrier_of_key_material_clears_it_when_dropped() {
        for type_needs_drop in [
            std::mem::needs_drop::<Handshake>(),
            std::mem::needs_drop::<TransportKeys>(),
            std::mem::needs_drop::<StaticIdentity>(),
            std::mem::needs_drop::<crate::session::TransportSession>(),
        ] {
            assert!(type_needs_drop, "a key carrier without a destructor");
        }

        let plain = identity(None);
        let (mut handshake, initiation) =
            Handshake::initiate(&plain, 1, &CLIENT_EPHEMERAL, tai64n(std::time::UNIX_EPOCH))
                .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0; KEY_LEN]).unwrap();
        let (response, _, _) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 2)
            .unwrap();

        let mut keys = handshake.consume_response(&plain, &response).unwrap();
        assert_ne!(keys.send, [0; KEY_LEN], "the test needs a real key to wipe");
        assert_ne!(keys.receive, [0; KEY_LEN]);
        keys.wipe();
        assert_eq!(keys.send, [0; KEY_LEN]);
        assert_eq!(keys.receive, [0; KEY_LEN]);

        assert_ne!(handshake.chaining_key, [0; KEY_LEN]);
        handshake.wipe();
        assert_eq!(handshake.chaining_key, [0; KEY_LEN]);
        assert_eq!(handshake.hash, [0; KEY_LEN]);

        let mut keyed = identity(Some([0x77; KEY_LEN]));
        assert_eq!(keyed.preshared_key, [0x77; KEY_LEN]);
        keyed.wipe();
        assert_eq!(keyed.preshared_key, [0; KEY_LEN]);
    }

    #[test]
    fn tai64n_is_monotonic_and_uses_the_wireguard_epoch() {
        let early = tai64n(std::time::UNIX_EPOCH);
        assert_eq!(
            u64::from_be_bytes(early[..8].try_into().unwrap()),
            TAI64_OFFSET
        );
        let later = tai64n(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1));
        assert!(later > early, "timestamps compare bytewise");
    }

    #[test]
    fn hmac_matches_the_rfc_construction_for_long_keys() {
        // A key longer than the block size must be hashed first; getting this
        // wrong still "works" for short keys and breaks only against real peers.
        let long = [0xAB_u8; 100];
        let expected = hmac(&hash(&[&long]), &[b"data"]);
        assert_eq!(hmac(&long, &[b"data"]), expected);
    }

    #[test]
    fn aead_round_trips_and_rejects_a_tampered_tag() {
        let key = [0x5A; KEY_LEN];
        let mut sealed = aead_seal(&key, 42, b"payload", b"aad").unwrap();
        let mut opened = sealed.clone();
        let length = aead_open(&key, 42, &mut opened, b"aad").unwrap();
        assert_eq!(&opened[..length], b"payload");

        assert!(matches!(
            aead_open(&key, 43, &mut sealed.clone(), b"aad"),
            Err(WireguardError::Decryption)
        ));
        sealed[0] ^= 1;
        assert!(matches!(
            aead_open(&key, 42, &mut sealed, b"aad"),
            Err(WireguardError::Decryption)
        ));
    }
}
