//! The client handshake.
//!
//! Two shapes, and the summary that started this work described them as one
//! four-step flow. They are not:
//!
//! * **1-RTT** — the client sends `ivAndRelays`, an `nfsKey`-encrypted length,
//!   its forward-secret public key and padding; the server answers with its own
//!   forward-secret public key, a ticket and padding. The inner VLESS protocol
//!   then rides ordinary records. There is no ticket sent by the client here and
//!   no 16 random bytes sent by the server.
//! * **0-RTT** — the client skips straight to an `nfsKey`-encrypted length of
//!   32, the cached ticket, and the first record of inner VLESS in the *same*
//!   write. The server's 16 random bytes key the download direction.
//!
//! `nfsKey` is not a pre-shared secret. It is established per connection, by
//! X25519 against the server's long-term public key or by ML-KEM-768
//! encapsulation against its encapsulation key, so a stolen client config
//! decrypts nothing: the config holds public keys only.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use foxcore_transport::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::aead::{Aead, MAX_NONCE, TAG_LEN, encode_length};
use super::blake3;
use super::crypto::{HandshakeCrypto, PFS_ANSWER_LEN, PFS_KEY_LEN, PFS_OFFER_LEN};
use super::params::{EncryptionParams, XorMode};
use super::stream::{CachedSession, EncryptedStream, SessionCache, StreamParts};
use super::xor::{RelayLink, XorState, mask_relay};

/// Encrypted length field: two bytes plus a tag.
const SEALED_LENGTH_LEN: usize = 2 + TAG_LEN;
/// The client's forward-secret block: its length field, then the offer.
const PFS_EXCHANGE_LEN: usize = SEALED_LENGTH_LEN + PFS_OFFER_LEN + TAG_LEN;
/// The server's forward-secret block, which carries no length of its own.
const SERVER_PFS_LEN: usize = PFS_ANSWER_LEN + TAG_LEN;
/// A sealed 16-byte ticket.
const SEALED_TICKET_LEN: usize = 16 + TAG_LEN;

/// Whether to prefer AES-256-GCM over ChaCha20-Poly1305.
///
/// This is a performance choice and *not* a negotiation: upstream's server
/// tries AES first and transparently retries with ChaCha if that fails, so
/// either answer interoperates. Guessing wrong costs the server one extra AEAD
/// attempt on the first 18 bytes of the connection and nothing after that.
pub fn prefer_aes() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// A client's parsed configuration plus the session it shares across
/// connections.
pub struct ClientInstance {
    params: EncryptionParams,
    /// `BLAKE3(nfs public key)` per hop, used to bind each relay to the next.
    hash32s: Vec<[u8; 32]>,
    cache: Arc<SessionCache>,
}

impl ClientInstance {
    pub fn new(params: EncryptionParams) -> Self {
        let hash32s = params
            .nfs_keys
            .iter()
            .map(|key| blake3::hash(key.bytes()))
            .collect();
        Self {
            params,
            hash32s,
            cache: Arc::new(SessionCache::default()),
        }
    }

    pub fn params(&self) -> &EncryptionParams {
        &self.params
    }

    pub async fn handshake(
        &self,
        stream: BoxStream,
        crypto: &mut dyn HandshakeCrypto,
    ) -> io::Result<EncryptedStream> {
        self.handshake_inner(stream, crypto, prefer_aes()).await
    }

    pub async fn handshake_with_cipher(
        &self,
        stream: BoxStream,
        crypto: &mut dyn HandshakeCrypto,
        use_aes: bool,
    ) -> io::Result<EncryptedStream> {
        self.handshake_inner(stream, crypto, use_aes).await
    }

    async fn handshake_inner(
        &self,
        mut stream: BoxStream,
        crypto: &mut dyn HandshakeCrypto,
        use_aes: bool,
    ) -> io::Result<EncryptedStream> {
        let relays_len = self.params.relays_len();
        let iv_and_relays_len = 16 + relays_len;
        let (len_ranges, gap_ranges) = self.params.padding.resolved();

        // `CreatPadding` runs before anything is drawn for the handshake
        // itself, and on both branches, so the randomness stream is consumed in
        // the same order whether or not this connection ends up 0-RTT.
        let mut padding_lens = Vec::with_capacity(len_ranges.len());
        let mut padding_total = 0_usize;
        for range in &len_ranges {
            let length = if range.probability >= crypto.rand_between(0, 100) {
                crypto.rand_between(range.from, range.to) as usize
            } else {
                0
            };
            padding_lens.push(length);
            padding_total += length;
        }
        let mut padding_gaps = Vec::with_capacity(gap_ranges.len());
        for range in &gap_ranges {
            let gap = if range.probability >= crypto.rand_between(0, 100) {
                crypto.rand_between(range.from, range.to)
            } else {
                0
            };
            padding_gaps.push(Duration::from_millis(u64::from(gap)));
        }

        let mut client_hello = vec![0_u8; iv_and_relays_len + PFS_EXCHANGE_LEN + padding_total];
        let mut iv = [0_u8; 16];
        crypto.fill_random(&mut iv)?;
        client_hello[..16].copy_from_slice(&iv);

        // ---- ivAndRelays -------------------------------------------------
        //
        // One hop per configured key. Each hop's material is optionally masked
        // with a keystream its own public key defines, and then bound to the
        // previous hop's `nfsKey`, so a relay cannot be swapped out for another.
        let mut nfs_key = [0_u8; 32];
        let mut cursor = 16;
        let mut link: Option<RelayLink> = None;
        for (index, key) in self.params.nfs_keys.iter().enumerate() {
            let width = key.relay_len();
            let share = crypto.nfs_share(key)?;
            if share.wire.len() != width {
                return Err(io::Error::other(
                    "VLESS encryption relay share has an unexpected length",
                ));
            }
            client_hello[cursor..cursor + width].copy_from_slice(&share.wire);
            nfs_key = share.shared_secret;

            if self.params.xor_mode != XorMode::Native {
                mask_relay(key.bytes(), &iv, &mut client_hello[cursor..cursor + width]);
            }
            if let Some(link) = link.as_mut() {
                link.apply(&mut client_hello[cursor..cursor + 32]);
            }
            if index == self.params.nfs_keys.len() - 1 {
                break;
            }
            let mut next = RelayLink::new(&nfs_key, &iv);
            let hash = self.hash32s[index + 1];
            client_hello[cursor + width..cursor + width + 32].copy_from_slice(&hash);
            next.apply(&mut client_hello[cursor + width..cursor + width + 32]);
            link = Some(next);
            cursor += width + 32;
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key, use_aes);

        // ---- 0-RTT -------------------------------------------------------
        if self.params.zero_rtt
            && let Some(session) = self.cache.get()
        {
            let mut united_key = Vec::with_capacity(PFS_KEY_LEN + 32);
            united_key.extend_from_slice(&session.pfs_key);
            united_key.extend_from_slice(&nfs_key);

            let length_at = iv_and_relays_len;
            let ticket_at = length_at + SEALED_LENGTH_LEN;
            client_hello[length_at..length_at + 2]
                .copy_from_slice(&encode_length(SEALED_TICKET_LEN));
            nfs_aead.seal_in_place(
                &[],
                &mut client_hello[length_at..length_at + SEALED_LENGTH_LEN],
                2,
            )?;
            client_hello[ticket_at..ticket_at + 16].copy_from_slice(&session.ticket);
            nfs_aead.seal_in_place(
                &[],
                &mut client_hello[ticket_at..ticket_at + SEALED_TICKET_LEN],
                16,
            )?;

            let pre_write = client_hello[..ticket_at + SEALED_TICKET_LEN].to_vec();
            let aead = Aead::new(
                &client_hello[ticket_at..ticket_at + SEALED_TICKET_LEN],
                &united_key,
                use_aes,
            );
            let xor = (self.params.xor_mode == XorMode::Random)
                .then(|| XorState::new(&united_key, &iv, None, pre_write.len(), 16));
            return Ok(EncryptedStream::new(StreamParts {
                inner: stream,
                use_aes,
                united_key,
                aead,
                peer_aead: None,
                xor,
                pre_write: Some(pre_write),
                peer_padding: None,
                zero_rtt: Some((Arc::clone(&self.cache), session.pfs_key)),
            }));
        }

        // ---- 1-RTT client hello -----------------------------------------
        let offer = crypto.pfs_offer()?;
        if offer.public_bytes().len() != PFS_OFFER_LEN {
            return Err(io::Error::other(
                "VLESS encryption forward-secret offer has an unexpected length",
            ));
        }
        let exchange_at = iv_and_relays_len;
        client_hello[exchange_at..exchange_at + 2]
            .copy_from_slice(&encode_length(PFS_EXCHANGE_LEN - SEALED_LENGTH_LEN));
        nfs_aead.seal_in_place(
            &[],
            &mut client_hello[exchange_at..exchange_at + SEALED_LENGTH_LEN],
            2,
        )?;
        let offer_at = exchange_at + SEALED_LENGTH_LEN;
        client_hello[offer_at..offer_at + PFS_OFFER_LEN].copy_from_slice(offer.public_bytes());
        nfs_aead.seal_in_place(
            &[],
            &mut client_hello[offer_at..offer_at + PFS_OFFER_LEN + TAG_LEN],
            PFS_OFFER_LEN,
        )?;

        // Padding: a sealed length, then a sealed run of zeros. The plaintext
        // is never read by anyone; only its length is doing work.
        let padding_at = exchange_at + PFS_EXCHANGE_LEN;
        if padding_total < SEALED_LENGTH_LEN + TAG_LEN + 1 {
            return Err(io::Error::other(
                "VLESS encryption padding schedule produced too short a first chunk",
            ));
        }
        client_hello[padding_at..padding_at + 2]
            .copy_from_slice(&encode_length(padding_total - SEALED_LENGTH_LEN));
        nfs_aead.seal_in_place(
            &[],
            &mut client_hello[padding_at..padding_at + SEALED_LENGTH_LEN],
            2,
        )?;
        let body_at = padding_at + SEALED_LENGTH_LEN;
        let body_plain = padding_total - SEALED_LENGTH_LEN - TAG_LEN;
        nfs_aead.seal_in_place(
            &[],
            &mut client_hello[body_at..body_at + body_plain + TAG_LEN],
            body_plain,
        )?;

        // The first chunk carries everything up to and including the first
        // padding run; later chunks are padding alone, spaced by the gaps.
        let mut chunks = padding_lens;
        chunks[0] += iv_and_relays_len + PFS_EXCHANGE_LEN;
        let mut rest = client_hello.as_slice();
        for (index, length) in chunks.iter().enumerate() {
            if *length > 0 {
                stream.write_all(&rest[..*length]).await?;
                stream.flush().await?;
                rest = &rest[*length..];
            }
            if let Some(gap) = padding_gaps.get(index)
                && !gap.is_zero()
            {
                tokio::time::sleep(*gap).await;
            }
        }

        // ---- server hello ------------------------------------------------
        let mut answer = vec![0_u8; SERVER_PFS_LEN];
        stream.read_exact(&mut answer).await?;
        // Sealed under the all-FF nonce so the server's use of nfsKey cannot
        // collide with the client's counter on the same key.
        nfs_aead.open_in_place_with_nonce(&MAX_NONCE, &[], &mut answer)?;
        answer.truncate(PFS_ANSWER_LEN);

        let offer_public = offer.public_bytes().to_vec();
        let pfs_key = offer.derive(&answer)?;
        let mut united_key = Vec::with_capacity(PFS_KEY_LEN + 32);
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(&nfs_key);

        // Each direction is keyed by the public key its *sender* chose, so an
        // attacker cannot reflect one side's stream back at it.
        let aead = Aead::new(&offer_public, &united_key, use_aes);
        let mut peer_aead = Aead::new(&answer, &united_key, use_aes);

        let mut ticket = vec![0_u8; SEALED_TICKET_LEN];
        stream.read_exact(&mut ticket).await?;
        peer_aead.open_in_place(&[], &mut ticket)?;
        ticket.truncate(16);
        // The server states the ticket's lifetime in the ticket's own first two
        // bytes; the client adapts rather than being configured. Zero means the
        // server declines 0-RTT.
        let seconds = u64::from(u16::from_be_bytes([ticket[0], ticket[1]]));
        let mut ticket_bytes = [0_u8; 16];
        ticket_bytes.copy_from_slice(&ticket);
        if self.params.zero_rtt && seconds > 0 {
            self.cache.store(CachedSession {
                expire: Instant::now() + Duration::from_secs(seconds),
                pfs_key,
                ticket: ticket_bytes,
            });
        }

        let mut sealed_padding_len = vec![0_u8; SEALED_LENGTH_LEN];
        stream.read_exact(&mut sealed_padding_len).await?;
        peer_aead.open_in_place(&[], &mut sealed_padding_len)?;
        let peer_padding =
            (usize::from(sealed_padding_len[0]) << 8) | usize::from(sealed_padding_len[1]);

        // The server's padding is deliberately *not* drained here: upstream
        // requires the client to move on so the server can dribble it out
        // alongside real traffic and erase the 1-RTT length signature.
        let xor = (self.params.xor_mode == XorMode::Random)
            .then(|| XorState::new(&united_key, &iv, Some(&ticket_bytes), 0, peer_padding));
        Ok(EncryptedStream::new(StreamParts {
            inner: stream,
            use_aes,
            united_key,
            aead,
            peer_aead: Some(peer_aead),
            xor,
            pre_write: None,
            peer_padding: Some(peer_padding),
            zero_rtt: None,
        }))
    }
}
