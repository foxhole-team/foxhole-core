// Modern VMess AEAD data framing is independently adapted from Shoes, commit
// 386b11532424b8665ee3e46340c6236fb3c47595 (MIT). See THIRD_PARTY_NOTICES.md.

use std::io;

use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce, Tag as AesTag};
use bytes::Bytes;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag};
use foxcore_api::{Destination, VmessCipher};
use foxcore_transport::{BoxStream, Datagram};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::crypto::{aes128_gcm_open, kdf};

const TAG_LEN: usize = 16;
const MAX_PLAINTEXT_CHUNK: usize = 8192;
const MAX_RESPONSE_HEADER_BYTES: usize = 1024;
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

enum DataCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Chacha20Poly1305(ChaCha20Poly1305),
    None,
}

pub(crate) struct DataCryptor {
    cipher: DataCipher,
    iv: Zeroizing<[u8; 16]>,
    next_counter: u16,
}

impl DataCryptor {
    pub(crate) fn new(cipher: VmessCipher, key: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        let cipher = match cipher {
            VmessCipher::Aes128Gcm => DataCipher::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).map_err(|_| invalid_key())?,
            )),
            VmessCipher::Auto | VmessCipher::Chacha20Poly1305 => {
                let key = Zeroizing::new(crate::crypto::chacha_key(key));
                DataCipher::Chacha20Poly1305(
                    ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| invalid_key())?,
                )
            }
            VmessCipher::None => DataCipher::None,
        };
        Ok(Self {
            cipher,
            iv: Zeroizing::new(*iv),
            next_counter: 0,
        })
    }

    fn tag_len(&self) -> usize {
        match self.cipher {
            DataCipher::None => 0,
            DataCipher::Aes128Gcm(_) | DataCipher::Chacha20Poly1305(_) => TAG_LEN,
        }
    }

    /// Chunk nonce: a 16-bit counter over the IV tail.
    ///
    /// The counter must not wrap, and this used to let it, matching the
    /// protocol's own `uint16` generator on purpose. The nonce is
    /// `counter || iv[2..12]` and the key is fixed for the whole connection, so
    /// the chunk after 65535 would be sealed under a nonce an earlier chunk
    /// already used. That is not a weakened property, it is the end of the one
    /// the AEAD exists for: two GCM frames under one nonce recover the
    /// authentication subkey H and make every later frame on the connection
    /// forgeable by anyone on the path, and ChaCha20-Poly1305 gives up the
    /// keystream the same way. `encode_uplink` seals a chunk per `read`, so a
    /// stream reaches this after roughly 90 MB of ordinary traffic — not a
    /// theoretical bound.
    ///
    /// So the stream ends here instead. Parity with v2ray is worth less than
    /// the property being traded for it, and the cost is a reconnect, which is
    /// recoverable; a leaked subkey is not.
    fn nonce(&mut self) -> io::Result<[u8; 12]> {
        let counter = self.next_counter;
        self.next_counter = self.next_counter.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess nonce space exhausted: this connection has used all 65536 chunk \
                 counters and the next chunk would repeat a nonce under the same key",
            )
        })?;
        let mut nonce = [0_u8; 12];
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        Ok(nonce)
    }

    fn seal(&mut self, payload: &mut Vec<u8>) -> io::Result<()> {
        // Taken after the tag-less cipher returns, so a `None` stream — which
        // has no nonce and no property to lose — is not ended at 65536 chunks.
        // This is also where `open` takes it, which keeps the two halves
        // counting the same frames.
        if matches!(self.cipher, DataCipher::None) {
            return Ok(());
        }
        let nonce = self.nonce()?;
        let tag = match &self.cipher {
            DataCipher::Aes128Gcm(cipher) => cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), b"", payload)
                .map(|tag| tag.to_vec()),
            DataCipher::Chacha20Poly1305(cipher) => cipher
                .encrypt_in_place_detached(ChaChaNonce::from_slice(&nonce), b"", payload)
                .map(|tag| tag.to_vec()),
            // Returned above; a per-frame path must not abort the process if
            // that guard ever moves.
            DataCipher::None => return Ok(()),
        }
        .map_err(|_| io::Error::other("VMess data encryption failed"))?;
        payload.extend_from_slice(&tag);
        Ok(())
    }

    fn open(&mut self, payload: &mut Vec<u8>) -> io::Result<()> {
        let tag_len = self.tag_len();
        if payload.len() < tag_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess frame is shorter than its authentication tag",
            ));
        }
        if tag_len == 0 {
            return Ok(());
        }
        let nonce = self.nonce()?;
        let tag_offset = payload.len() - tag_len;
        let tag: [u8; TAG_LEN] = payload[tag_offset..]
            .try_into()
            .map_err(|_| io::Error::other("VMess tag length invariant failed"))?;
        payload.truncate(tag_offset);
        match &self.cipher {
            DataCipher::Aes128Gcm(cipher) => cipher.decrypt_in_place_detached(
                AesNonce::from_slice(&nonce),
                b"",
                payload,
                AesTag::from_slice(&tag),
            ),
            DataCipher::Chacha20Poly1305(cipher) => cipher.decrypt_in_place_detached(
                ChaChaNonce::from_slice(&nonce),
                b"",
                payload,
                ChaChaTag::from_slice(&tag),
            ),
            // The tag-less cipher returns above. Reached only if that guard
            // ever moves; per-frame code must not abort the process over it.
            DataCipher::None => Err(aes_gcm::Error),
        }
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess data authentication failed",
            )
        })
    }
}

pub(crate) struct LengthMask {
    reader: Box<dyn XofReader + Send>,
}

impl LengthMask {
    pub(crate) fn new(iv: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        Self {
            reader: Box::new(shake.finalize_xof()),
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut bytes = [0_u8; 2];
        self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}

pub(crate) async fn verify_response_header<S>(
    stream: &mut S,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    response_authentication: u8,
) -> io::Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut encrypted_length = [0_u8; 2 + TAG_LEN];
    stream.read_exact(&mut encrypted_length).await?;
    let length_key = kdf(response_key, &[b"AEAD Resp Header Len Key"]);
    let length_nonce = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let tag: [u8; TAG_LEN] = encrypted_length[2..]
        .try_into()
        .map_err(|_| io::Error::other("VMess response length tag invariant failed"))?;
    aes128_gcm_open(
        &length_key[..16],
        &length_nonce[..12],
        b"",
        &mut encrypted_length[..2],
        &tag,
    )
    .map_err(|_| invalid_response("response header length authentication failed"))?;
    let content_len = u16::from_be_bytes([encrypted_length[0], encrypted_length[1]]) as usize;
    if !(4..=MAX_RESPONSE_HEADER_BYTES).contains(&content_len) {
        return Err(invalid_response("response header length is outside limits"));
    }

    let mut encrypted_content = vec![0_u8; content_len + TAG_LEN];
    stream.read_exact(&mut encrypted_content).await?;
    let content_key = kdf(response_key, &[b"AEAD Resp Header Key"]);
    let content_nonce = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let tag: [u8; TAG_LEN] = encrypted_content[content_len..]
        .try_into()
        .map_err(|_| io::Error::other("VMess response tag invariant failed"))?;
    encrypted_content.truncate(content_len);
    aes128_gcm_open(
        &content_key[..16],
        &content_nonce[..12],
        b"",
        &mut encrypted_content,
        &tag,
    )
    .map_err(|_| invalid_response("response header authentication failed"))?;

    if encrypted_content[0] != response_authentication {
        return Err(invalid_response("response authentication byte mismatch"));
    }
    // Byte 2 is a command *id*, not a bit field. The only command servers
    // actually send is 0 ("none"); anything else asks the client to change
    // where or as whom it connects, which this core does not do on a server's
    // say-so. Refusing is the fail-closed reading of an instruction we will not
    // carry out.
    if encrypted_content[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VMess server commands (dynamic port, account switch) are not honoured",
        ));
    }
    Ok(())
}

pub(crate) struct DataSession {
    pub(crate) outgoing: DataCryptor,
    pub(crate) incoming: DataCryptor,
    pub(crate) outgoing_mask: LengthMask,
    pub(crate) incoming_mask: LengthMask,
    pub(crate) response_key: Zeroizing<[u8; 16]>,
    pub(crate) response_iv: Zeroizing<[u8; 16]>,
    pub(crate) response_authentication: u8,
}

pub(crate) fn wrap_data_stream(stream: BoxStream, session: DataSession) -> BoxStream {
    let (client, relay) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    let (relay_reader, relay_writer) = tokio::io::split(relay);
    let (server_reader, server_writer) = tokio::io::split(stream);
    tokio::spawn(async move {
        let uplink = encode_uplink(
            relay_reader,
            server_writer,
            session.outgoing,
            session.outgoing_mask,
        );
        let downlink = decode_downlink(
            server_reader,
            relay_writer,
            session.incoming,
            session.incoming_mask,
            session.response_key,
            session.response_iv,
            session.response_authentication,
        );
        tokio::pin!(uplink, downlink);
        tokio::select! {
            _ = &mut downlink => {}
            result = &mut uplink => {
                // A client that shuts its write half is half-closing, not
                // hanging up: the response is still coming. Ending the task
                // here dropped the tail of every request/response exchange
                // written that way.
                if result.is_ok() {
                    let _ = downlink.await;
                }
            }
        }
    });
    Box::new(client)
}

/// Relay one UDP session over a VMess `command = UDP` stream.
///
/// The framing is the same length-prefixed chunk stream TCP uses, but the
/// *boundaries* carry meaning: the protocol's packet transfer type seals each
/// datagram as exactly one chunk, and each chunk read back is exactly one
/// datagram. Reusing the byte-stream path here would coalesce two replies into
/// one packet, which is indistinguishable from a corrupt DNS answer.
pub(crate) async fn relay_datagrams(
    stream: BoxStream,
    destination: Destination,
    session: DataSession,
    uplink: &mut mpsc::Receiver<Datagram>,
    downlink: mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) -> io::Result<()> {
    let DataSession {
        mut outgoing,
        mut incoming,
        mut outgoing_mask,
        mut incoming_mask,
        response_key,
        response_iv,
        response_authentication,
    } = session;
    let (mut wire_reader, mut wire_writer) = tokio::io::split(stream);

    // The two directions run independently on purpose. The response header only
    // gates reading; making the first uplink packet wait for it would hold a DNS
    // query behind a header the server sends in answer to that very request.
    let send = async {
        while let Some(outbound) = uplink.recv().await {
            let mut frame = outbound.payload.to_vec();
            if frame.len() + outgoing.tag_len() > u16::MAX as usize {
                // One oversized datagram must not end the session; the sender
                // simply cannot express it on this carrier.
                continue;
            }
            outgoing.seal(&mut frame)?;
            let length = frame.len() as u16 ^ outgoing_mask.next_u16();
            wire_writer.write_all(&length.to_be_bytes()).await?;
            wire_writer.write_all(&frame).await?;
            wire_writer.flush().await?;
        }
        io::Result::Ok(())
    };

    let receive = async {
        verify_response_header(
            &mut wire_reader,
            &response_key,
            &response_iv,
            response_authentication,
        )
        .await?;
        loop {
            let encoded = wire_reader.read_u16().await?;
            let frame_len = usize::from(encoded ^ incoming_mask.next_u16());
            if frame_len == incoming.tag_len() {
                return io::Result::Ok(());
            }
            if frame_len < incoming.tag_len() {
                return Err(invalid_response("data frame is shorter than its tag"));
            }
            let mut frame = vec![0_u8; frame_len];
            wire_reader.read_exact(&mut frame).await?;
            incoming.open(&mut frame)?;
            if downlink
                .send(Datagram::new(destination.clone(), Bytes::from(frame)))
                .await
                .is_err()
            {
                return io::Result::Ok(());
            }
        }
    };

    tokio::pin!(send, receive);
    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = &mut send => result,
        result = &mut receive => result,
    }
}

async fn encode_uplink<R, W>(
    mut plaintext: R,
    mut wire: W,
    mut cryptor: DataCryptor,
    mut mask: LengthMask,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; MAX_PLAINTEXT_CHUNK];
    loop {
        let read = plaintext.read(&mut buffer).await?;
        let mut frame = buffer[..read].to_vec();
        cryptor.seal(&mut frame)?;
        let frame_len = u16::try_from(frame.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "VMess frame exceeds u16"))?;
        wire.write_all(&(frame_len ^ mask.next_u16()).to_be_bytes())
            .await?;
        wire.write_all(&frame).await?;
        if read == 0 {
            wire.flush().await?;
            wire.shutdown().await?;
            return Ok(());
        }
    }
}

async fn decode_downlink<R, W>(
    mut wire: R,
    mut plaintext: W,
    mut cryptor: DataCryptor,
    mut mask: LengthMask,
    response_key: Zeroizing<[u8; 16]>,
    response_iv: Zeroizing<[u8; 16]>,
    response_authentication: u8,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    verify_response_header(
        &mut wire,
        &response_key,
        &response_iv,
        response_authentication,
    )
    .await?;
    loop {
        let encoded_len = wire.read_u16().await?;
        let frame_len = usize::from(encoded_len ^ mask.next_u16());
        if frame_len == cryptor.tag_len() {
            plaintext.shutdown().await?;
            return Ok(());
        }
        if frame_len < cryptor.tag_len() {
            return Err(invalid_response("data frame is shorter than its tag"));
        }
        let mut frame = vec![0_u8; frame_len];
        wire.read_exact(&mut frame).await?;
        cryptor.open(&mut frame)?;
        if frame.is_empty() {
            return Err(invalid_response("unexpected empty VMess data frame"));
        }
        plaintext.write_all(&frame).await?;
    }
}

fn invalid_key() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid VMess data key length")
}

fn invalid_response(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_and_chacha_frames_roundtrip() {
        for cipher in [
            VmessCipher::Aes128Gcm,
            VmessCipher::Chacha20Poly1305,
            VmessCipher::None,
        ] {
            let key = [9_u8; 16];
            let iv = [7_u8; 16];
            let mut seal = DataCryptor::new(cipher, &key, &iv).unwrap();
            let mut open = DataCryptor::new(cipher, &key, &iv).unwrap();
            let mut payload = b"bounded vmess frame".to_vec();
            seal.seal(&mut payload).unwrap();
            assert_eq!(payload.len(), 19 + seal.tag_len());
            open.open(&mut payload).unwrap();
            assert_eq!(payload, b"bounded vmess frame");
        }
    }

    #[test]
    fn authentication_failure_is_rejected() {
        let key = [9_u8; 16];
        let iv = [7_u8; 16];
        let mut seal = DataCryptor::new(VmessCipher::Aes128Gcm, &key, &iv).unwrap();
        let mut open = DataCryptor::new(VmessCipher::Aes128Gcm, &key, &iv).unwrap();
        let mut payload = b"message".to_vec();
        seal.seal(&mut payload).unwrap();
        payload[0] ^= 1;
        assert!(open.open(&mut payload).is_err());
    }

    /// A VMess connection has one key and a 16-bit chunk counter, and
    /// `encode_uplink` spends one counter per `read` — about 90 MB of ordinary
    /// traffic to the end of the space. The chunk after that would be sealed
    /// under a nonce an earlier chunk already used, which under GCM hands an
    /// observer the authentication subkey and makes the rest of the connection
    /// forgeable. Ending the stream costs a reconnect and nothing else.
    #[test]
    fn a_stream_that_runs_out_of_vmess_chunk_counters_ends_rather_than_repeat_a_nonce() {
        let key = [9_u8; 16];
        let iv = [7_u8; 16];
        let mut cryptor = DataCryptor::new(VmessCipher::Aes128Gcm, &key, &iv).unwrap();
        cryptor.next_counter = u16::MAX - 1;

        let mut last = b"the last chunk in the space".to_vec();
        cryptor
            .seal(&mut last)
            .expect("the counter still has room for this one");

        let mut over = b"one chunk too many".to_vec();
        let error = cryptor
            .seal(&mut over)
            .expect_err("this chunk would reuse the nonce of an earlier one");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("nonce space exhausted"),
            "the reason has to be legible in a log, got: {error}"
        );
        assert_eq!(
            over, b"one chunk too many",
            "a refused chunk must not leave a half-encrypted payload behind"
        );

        // The receiving half counts the same frames and stops at the same point:
        // a peer that kept going past the wrap is not to be followed there.
        let mut opener = DataCryptor::new(VmessCipher::Aes128Gcm, &key, &iv).unwrap();
        opener.next_counter = u16::MAX;
        assert!(opener.open(&mut last).is_err());

        // The tag-less cipher has no nonce and nothing to forfeit, so it is not
        // cut off at the same boundary.
        let mut plaintext = DataCryptor::new(VmessCipher::None, &key, &iv).unwrap();
        plaintext.next_counter = u16::MAX;
        let mut payload = b"unencrypted".to_vec();
        plaintext.seal(&mut payload).unwrap();
        assert_eq!(payload, b"unencrypted");
    }

    #[test]
    fn masks_are_deterministic_but_iv_specific() {
        let mut one = LengthMask::new(&[1_u8; 16]);
        let mut again = LengthMask::new(&[1_u8; 16]);
        let mut other = LengthMask::new(&[2_u8; 16]);
        assert_eq!(one.next_u16(), again.next_u16());
        assert_ne!(one.next_u16(), other.next_u16());
    }
}
