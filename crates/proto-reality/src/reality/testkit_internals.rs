use std::io;

use aws_lc_rs::{
    agreement, digest,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};

use super::common::{HELLO_SESSION_ID_LEN, HELLO_SESSION_ID_OFFSET};
use super::reality_aead::AeadKey;
use super::reality_auth::{derive_auth_key, perform_ecdh};
use super::reality_certificate::generate_hmac_certificate;
use super::reality_cipher_suite::CipherSuite;
use super::reality_records::{RecordDecryptor, RecordEncryptor};
use super::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use super::reality_tls13_messages::{
    construct_certificate, construct_encrypted_extensions, construct_finished,
};

pub use super::common::{CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE};

pub const fn observed_initial_record_version() -> [u8; 2] {
    super::reality_tls13_messages::INITIAL_RECORD_VERSION
}

pub struct ParsedClientHello {
    pub cipher_suite: CipherSuite,
    pub client_x25519: [u8; 32],
    pub session_id: [u8; HELLO_SESSION_ID_LEN],
    pub auth_key: [u8; 32],
}

pub fn record_header(content_type: u8, length: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(5);
    header.push(content_type);
    header.extend_from_slice(&[0x03, 0x03]);
    header.extend_from_slice(&(length as u16).to_be_bytes());
    header
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

pub fn parse_client_hello(
    hello: &[u8],
    server_private: &[u8; 32],
) -> io::Result<ParsedClientHello> {
    if hello.first() != Some(&0x01) {
        return Err(invalid("not a ClientHello"));
    }
    if hello.len() < HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN {
        return Err(invalid("ClientHello is too short"));
    }

    let mut random_salt = [0_u8; 20];
    random_salt.copy_from_slice(&hello[6..26]);

    let mut session_id = [0_u8; HELLO_SESSION_ID_LEN];
    session_id.copy_from_slice(
        &hello[HELLO_SESSION_ID_OFFSET..HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN],
    );

    let mut cursor = HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN;
    let cipher_suites_len = be16(hello, cursor)? as usize;
    let mut offered = Vec::with_capacity(cipher_suites_len / 2);
    for index in 0..cipher_suites_len / 2 {
        offered.push(be16(hello, cursor + 2 + index * 2)?);
    }
    cursor += 2 + cipher_suites_len;
    let compression_len = *hello.get(cursor).ok_or_else(|| invalid("truncated"))? as usize;
    cursor += 1 + compression_len;
    let extensions_len = be16(hello, cursor)? as usize;
    cursor += 2;
    let extensions_end = cursor + extensions_len;
    if extensions_end > hello.len() {
        return Err(invalid("extensions run past the ClientHello"));
    }

    let mut client_x25519 = None;
    while cursor + 4 <= extensions_end {
        let extension_type = be16(hello, cursor)?;
        let body_len = be16(hello, cursor + 2)? as usize;
        let body_start = cursor + 4;
        let body_end = body_start + body_len;
        if body_end > extensions_end {
            return Err(invalid("extension runs past the list"));
        }
        if extension_type == 0x0033 {
            client_x25519 = find_x25519_share(&hello[body_start..body_end])?;
        }
        cursor = body_end;
    }

    let client_x25519 =
        client_x25519.ok_or_else(|| invalid("no x25519 key share in ClientHello"))?;

    let cipher_suite = offered
        .iter()
        .find_map(|id| CipherSuite::from_id(*id))
        .ok_or_else(|| invalid("ClientHello offers no TLS 1.3 cipher suite"))?;

    let shared = perform_ecdh(server_private, &client_x25519)
        .map_err(|_| invalid("REALITY ECDH against the client share failed"))?;
    let auth_key = derive_auth_key(&shared, &random_salt, b"REALITY")
        .map_err(|_| invalid("REALITY auth key derivation failed"))?;

    Ok(ParsedClientHello {
        cipher_suite,
        client_x25519,
        session_id,
        auth_key,
    })
}

fn find_x25519_share(body: &[u8]) -> io::Result<Option<[u8; 32]>> {
    let list_len = be16(body, 0)? as usize;
    let end = (2 + list_len).min(body.len());
    let mut cursor = 2;
    while cursor + 4 <= end {
        let group = be16(body, cursor)?;
        let length = be16(body, cursor + 2)? as usize;
        let data_start = cursor + 4;
        let data_end = data_start + length;
        if data_end > end {
            break;
        }
        if group == 0x001d && length == 32 {
            let mut share = [0_u8; 32];
            share.copy_from_slice(&body[data_start..data_end]);
            return Ok(Some(share));
        }
        cursor = data_end;
    }
    Ok(None)
}

fn be16(bytes: &[u8], at: usize) -> io::Result<u16> {
    let slice = bytes
        .get(at..at + 2)
        .ok_or_else(|| invalid("truncated while reading a length"))?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

pub fn build_server_hello(parsed: &ParsedClientHello) -> io::Result<(Vec<u8>, [u8; 32])> {
    let rng = SystemRandom::new();

    let mut server_random = [0_u8; 32];
    rng.fill(&mut server_random)
        .map_err(|_| io::Error::other("rng"))?;

    let mut ephemeral_private = [0_u8; 32];
    rng.fill(&mut ephemeral_private)
        .map_err(|_| io::Error::other("rng"))?;
    let ephemeral = agreement::PrivateKey::from_private_key(&agreement::X25519, &ephemeral_private)
        .map_err(|_| io::Error::other("ephemeral key"))?;
    let ephemeral_public = ephemeral
        .compute_public_key()
        .map_err(|_| io::Error::other("ephemeral public key"))?;

    let shared_secret = perform_ecdh(&ephemeral_private, &parsed.client_x25519)
        .map_err(|_| io::Error::other("handshake ECDH failed"))?;

    let server_hello = super::reality_tls13_messages::construct_server_hello(
        &server_random,
        &parsed.session_id,
        parsed.cipher_suite.id(),
        ephemeral_public.as_ref(),
    )?;

    Ok((server_hello, shared_secret))
}

pub struct ServerAppKeys {
    cipher_suite: CipherSuite,
    server_key: AeadKey,
    server_iv: Vec<u8>,
    server_seq: u64,
    client_key: AeadKey,
    client_iv: Vec<u8>,
    client_seq: u64,
}

impl ServerAppKeys {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut owned = plaintext.to_vec();
        let mut encryptor =
            RecordEncryptor::new(&self.server_key, &self.server_iv, &mut self.server_seq);
        encryptor.encrypt_app_data(&mut owned, &mut out)?;
        Ok(out)
    }

    pub fn decrypt(&mut self, body: &mut [u8], record_len: u16) -> io::Result<Vec<u8>> {
        let mut decryptor =
            RecordDecryptor::new(&self.client_key, &self.client_iv, &mut self.client_seq);
        let (content_type, plaintext) = decryptor.decrypt_record_in_place(body, record_len)?;
        if content_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(invalid("expected application data from the client"));
        }
        let _ = self.cipher_suite;
        Ok(plaintext.to_vec())
    }
}

pub struct EncryptedFlight {
    pub bytes: Vec<u8>,
    pub keys: ServerAppKeys,
}

pub fn build_encrypted_flight(
    parsed: &ParsedClientHello,
    shared_secret: &[u8; 32],
    mut transcript: digest::Context,
    server_name: &str,
    _client_hello: &[u8],
    _server_hello: &[u8],
) -> io::Result<EncryptedFlight> {
    let cipher_suite = parsed.cipher_suite;
    let server_hello_hash = transcript.clone().finish();

    let keys = derive_handshake_keys(
        cipher_suite,
        shared_secret,
        server_hello_hash.as_ref(),
        server_hello_hash.as_ref(),
    )?;

    let (certificate, signing_key) = generate_hmac_certificate(&parsed.auth_key, server_name)?;
    let encrypted_extensions = construct_encrypted_extensions()?;
    let certificate_message = construct_certificate(certificate)?;

    transcript.update(&encrypted_extensions);
    transcript.update(&certificate_message);
    let cv_transcript = transcript.clone().finish();

    let certificate_verify = build_certificate_verify(&signing_key, cv_transcript.as_ref())?;
    transcript.update(&certificate_verify);
    let finished_transcript = transcript.clone().finish();

    let verify_data = compute_finished_verify_data(
        cipher_suite,
        &keys.server_handshake_traffic_secret,
        finished_transcript.as_ref(),
    )?;
    let finished = construct_finished(&verify_data)?;
    transcript.update(&finished);
    let handshake_hash = transcript.finish();

    let (server_hs_key, server_hs_iv) =
        derive_traffic_keys(&keys.server_handshake_traffic_secret, cipher_suite)?;
    let hs_key = AeadKey::new(cipher_suite, &server_hs_key)?;
    let mut hs_seq = 0_u64;
    let mut bytes = Vec::new();
    for message in [
        &encrypted_extensions,
        &certificate_message,
        &certificate_verify,
        &finished,
    ] {
        let mut encryptor = RecordEncryptor::new(&hs_key, &server_hs_iv, &mut hs_seq);
        encryptor.encrypt_handshake(message, &mut bytes)?;
    }

    let (client_app_secret, server_app_secret) =
        derive_application_secrets(cipher_suite, &keys.master_secret, handshake_hash.as_ref())?;
    let (client_app_key, client_iv) = derive_traffic_keys(&client_app_secret, cipher_suite)?;
    let (server_app_key, server_iv) = derive_traffic_keys(&server_app_secret, cipher_suite)?;

    Ok(EncryptedFlight {
        bytes,
        keys: ServerAppKeys {
            cipher_suite,
            server_key: AeadKey::new(cipher_suite, &server_app_key)?,
            server_iv,
            server_seq: 0,
            client_key: AeadKey::new(cipher_suite, &client_app_key)?,
            client_iv,
            client_seq: 0,
        },
    })
}

fn build_certificate_verify(
    signing_key: &Ed25519KeyPair,
    transcript_hash: &[u8],
) -> io::Result<Vec<u8>> {
    let mut signed = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed.extend_from_slice(&[0x20_u8; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0x00);
    signed.extend_from_slice(transcript_hash);

    let signature = signing_key.sign(&signed);
    let signature = signature.as_ref();

    let body_len = 2 + 2 + signature.len();
    let mut message = Vec::with_capacity(4 + body_len);
    message.push(0x0f);
    message.extend_from_slice(&[
        ((body_len >> 16) & 0xff) as u8,
        ((body_len >> 8) & 0xff) as u8,
        (body_len & 0xff) as u8,
    ]);
    message.extend_from_slice(&0x0807_u16.to_be_bytes());
    message.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    message.extend_from_slice(signature);
    let _ = signing_key.public_key();
    Ok(message)
}
