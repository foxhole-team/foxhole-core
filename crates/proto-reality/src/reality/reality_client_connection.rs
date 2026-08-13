// REALITY client connection with rustls-compatible API

use std::io::{self, Read, Write};

use aws_lc_rs::digest;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CIPHERTEXT_READ_BUF_CAPACITY, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_TYPE_FINISHED, HELLO_SESSION_ID_LEN, HELLO_SESSION_ID_OFFSET, MAX_TLS_CIPHERTEXT_LEN,
    OUTGOING_BUFFER_LIMIT, PLAINTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE,
    TLS_RECORD_HEADER_SIZE,
};
use super::hello_profile::{
    CHROME_ALPN_PROTOCOLS, EchGreaseParams, GreaseValues, HelloSession, RealityHelloProfile,
    TLS_1_3,
};
use super::reality_aead::{AeadKey, decrypt_handshake_message};
use super::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
use super::reality_cipher_suite::CipherSuite;
use super::reality_client_verify::{
    extract_certificate_der, extract_certificate_verify_signature, extract_ed25519_public_key,
    verify_certificate_hmac, verify_certificate_verify_signature,
};
use super::reality_key_exchange::{ClientKeyExchange, NamedGroup, random_x25519_public_key};
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::{RecordDecryptor, RecordEncryptor};
use super::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use super::reality_tls13_messages::{
    construct_client_hello, construct_finished, write_record_header,
};
use super::reality_util::{
    extract_server_cipher_suite, extract_server_key_share, extract_server_selected_group,
    extract_server_selected_version,
};
use crate::slide_buffer::SlideBuffer;

/// The state machine reached a place its own construction says is impossible.
///
/// These used to be `unreachable!()`. Every transition here is driven by a
/// remote server, and the release profile aborts on panic, so an invariant that
/// turns out to be wrong once would end the whole VPN process rather than one
/// connection. Failing the connection is the strictly better answer: the
/// invariant is still asserted by tests, but a mistake costs a dropped
/// handshake instead of a crash the user cannot report.
fn handshake_state_error(expected: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("REALITY connection is not in the state required to process {expected}"),
    )
}

/// Configuration for REALITY client connections
#[derive(Clone)]
pub struct RealityClientConfig {
    /// Server's X25519 public key (32 bytes)
    pub public_key: [u8; 32],
    /// Short ID for authentication (8 bytes)
    pub short_id: [u8; 8],
    /// Server name for SNI
    pub server_name: String,
    /// Which ClientHello to write. The profile owns the cipher suite list, so
    /// there is no second place to say which suites are offered — the set the
    /// hello advertises and the set a ServerHello is checked against are read
    /// off the same table.
    pub hello_profile: RealityHelloProfile,
}

/// Handshake state machine for REALITY client
enum HandshakeState {
    /// ClientHello sent, waiting for ServerHello
    AwaitingServerHello {
        client_hello_bytes: Vec<u8>, // Full ClientHello handshake message (raw bytes for transcript)
        /// Private key exchange material for every group the hello offered.
        /// Zeroizes itself on drop.
        key_exchange: ClientKeyExchange,
        auth_key: [u8; 32], // REALITY authentication key for HMAC verification
    },
    /// ServerHello received, processing encrypted handshake messages
    ProcessingHandshake {
        client_handshake_traffic_secret: Vec<u8>,
        server_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: CipherSuite,
        handshake_transcript_bytes: Vec<u8>, // Accumulated transcript for hash computation
        auth_key: [u8; 32],                  // REALITY authentication key for HMAC verification
        // State for handling multiple encrypted handshake records (separate mode)
        handshake_seq: u64,             // Sequence number for decrypting records
        accumulated_plaintext: Vec<u8>, // Accumulated plaintext across records
        parse_offset: usize,            // First unparsed handshake byte
        messages_found: u8,             // Number of handshake messages found so far
        certificate_verified: bool,     // Whether Certificate HMAC was verified
        ed25519_public_key: Option<[u8; 32]>, // Public key from Certificate for CV verification
        cert_verify_offset: Option<usize>, // Offset of CertificateVerify in accumulated plaintext
        finished_offset: Option<usize>, // Offset of server Finished in accumulated plaintext
    },
    /// Handshake complete, ready for application data
    Complete,
}

impl Drop for HandshakeState {
    fn drop(&mut self) {
        match self {
            Self::AwaitingServerHello {
                client_hello_bytes,
                key_exchange: _,
                auth_key,
            } => {
                client_hello_bytes.zeroize();
                auth_key.zeroize();
            }
            Self::ProcessingHandshake {
                client_handshake_traffic_secret,
                server_handshake_traffic_secret,
                master_secret,
                handshake_transcript_bytes,
                auth_key,
                accumulated_plaintext,
                ed25519_public_key,
                ..
            } => {
                client_handshake_traffic_secret.zeroize();
                server_handshake_traffic_secret.zeroize();
                master_secret.zeroize();
                handshake_transcript_bytes.zeroize();
                auth_key.zeroize();
                accumulated_plaintext.zeroize();
                ed25519_public_key.zeroize();
            }
            Self::Complete => {}
        }
    }
}

/// REALITY client-side connection implementing rustls-compatible API
pub struct RealityClientConnection {
    // Configuration
    config: RealityClientConfig,

    // Handshake state
    handshake_state: HandshakeState,

    // TLS 1.3 application traffic encryption (post-handshake)
    // Keys are cached as AeadKey to avoid per-record key setup overhead
    app_read_key: Option<AeadKey>,
    app_read_iv: Option<Vec<u8>>,
    app_write_key: Option<AeadKey>,
    app_write_iv: Option<Vec<u8>>,
    read_seq: u64,
    write_seq: u64,
    cipher_suite: Option<CipherSuite>,

    // Pre-allocated buffer for TLS read operations (reused across calls)
    tls_read_buffer: Box<[u8]>,

    // Buffers for I/O - using SlideBuffer for efficient zero-alloc operations
    ciphertext_read_buf: SlideBuffer, // Incoming encrypted TLS records
    ciphertext_write_buf: Vec<u8>,    // Outgoing encrypted TLS records
    plaintext_read_buf: SlideBuffer,  // Decrypted application data
    plaintext_write_buf: Vec<u8>,     // Application data to encrypt

    // Connection state flags (mirrors rustls patterns)
    received_close_notify: bool,        // Peer sent close_notify alert
    fatal_error: Option<io::ErrorKind>, // Fatal error occurred, connection unusable
}

impl Drop for RealityClientConnection {
    fn drop(&mut self) {
        self.config.public_key.zeroize();
        self.config.short_id.zeroize();
        self.config.server_name.zeroize();
        self.tls_read_buffer.zeroize();
        self.ciphertext_write_buf.zeroize();
        self.plaintext_write_buf.zeroize();
        self.app_read_iv.zeroize();
        self.app_write_iv.zeroize();
    }
}

impl RealityClientConnection {
    /// Create a new REALITY client connection and generate ClientHello
    pub fn new(config: RealityClientConfig) -> io::Result<Self> {
        // The placeholder state has to hold *some* key material, and generating
        // a throwaway x25519 pair is cheaper than making the field an Option
        // that every later match has to unwrap. It is replaced before `new`
        // returns.
        let placeholder = ClientKeyExchange::generate(&[NamedGroup::X25519])?;
        let mut conn = RealityClientConnection {
            config,
            handshake_state: HandshakeState::AwaitingServerHello {
                client_hello_bytes: Vec::new(),
                key_exchange: placeholder,
                auth_key: [0u8; 32],
            },
            app_read_key: None,
            app_read_iv: None,
            app_write_key: None,
            app_write_iv: None,
            read_seq: 0,
            write_seq: 0,
            cipher_suite: None,
            tls_read_buffer: vec![0_u8; TLS_MAX_RECORD_SIZE].into_boxed_slice(),
            ciphertext_read_buf: SlideBuffer::new(CIPHERTEXT_READ_BUF_CAPACITY),
            ciphertext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            received_close_notify: false,
            fatal_error: None,
        };

        conn.generate_client_hello()?;

        Ok(conn)
    }

    /// Generate and buffer ClientHello
    fn generate_client_hello(&mut self) -> io::Result<()> {
        let mut rng = rand::rng();
        let profile = self.config.hello_profile.table();

        let groups = profile.key_share_groups();
        let key_exchange = ClientKeyExchange::generate(&groups)?;
        let mut key_shares: Vec<(NamedGroup, Vec<u8>)> = Vec::with_capacity(groups.len());
        for group in groups {
            let share = key_exchange.share_bytes(group).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "REALITY key exchange produced no {} share for the hello profile",
                        group.name()
                    ),
                )
            })?;
            key_shares.push((group, share));
        }

        let mut client_random = [0u8; 32];
        rng.fill_bytes(&mut client_random);

        // REALITY's own ECDH: the client's plain x25519 share against the
        // server's REALITY public key. Independent of whichever group TLS ends
        // up negotiating — the server reads this share straight out of the
        // ClientHello, before any of that is decided.
        let shared_secret =
            perform_ecdh(key_exchange.reality_private_key(), &self.config.public_key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Use slice directly from client_random to avoid copying
        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], b"REALITY")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Create session ID with REALITY metadata
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::other("System time error"))?
            .as_secs();

        let mut session_id_plaintext = [0u8; 16];
        session_id_plaintext[0] = 1; // Protocol version major
        session_id_plaintext[1] = 8; // Protocol version minor
        session_id_plaintext[2] = 0; // Protocol version patch
        session_id_plaintext[3] = 0; // Padding byte
        // Timestamp (4 bytes as uint32, in seconds)
        session_id_plaintext[4..8].copy_from_slice(&(timestamp as u32).to_be_bytes());
        // Short ID (8 bytes)
        session_id_plaintext[8..16].copy_from_slice(&self.config.short_id);

        // Create a 32-byte SessionId (16 bytes plaintext + 16 bytes zeros for padding)
        let mut session_id_for_hello = [0u8; HELLO_SESSION_ID_LEN];
        session_id_for_hello[0..16].copy_from_slice(&session_id_plaintext);

        let session = HelloSession {
            client_random: &client_random,
            session_id: &session_id_for_hello,
            server_name: &self.config.server_name,
            alpn_protocols: CHROME_ALPN_PROTOCOLS,
            key_shares: &key_shares,
            grease: GreaseValues::random(&mut rng),
            ech_grease: EchGreaseParams::new(random_x25519_public_key()?, &mut rng),
            permutation_seed: rng.next_u64(),
        };
        let mut client_hello = construct_client_hello(profile, &session)?;

        // Now encrypt the SessionId using the ClientHello with zeroed SessionId as AAD
        // Use slice directly from client_random to avoid copying
        let nonce = &client_random[20..32];

        // Zero the SessionId to form the AAD, which is the same window the
        // server zeroes. `construct_client_hello` has already asserted the
        // constant against the bytes it produced, so this cannot address the
        // wrong 32 bytes without that assertion firing first.
        let session_id_window =
            HELLO_SESSION_ID_OFFSET..HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN;
        client_hello[session_id_window.clone()].fill(0);

        let encrypted_session_id =
            encrypt_session_id(&session_id_plaintext, &auth_key, nonce, &client_hello)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Restore the encrypted SessionId before writing or storing ClientHello.
        // REALITY transcripts use the wire ClientHello, not the zeroed AAD form.
        client_hello[session_id_window].copy_from_slice(&encrypted_session_id);

        let hello_len = u16::try_from(client_hello.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY ClientHello does not fit in one TLS record",
            )
        })?;
        let mut record = write_record_header(CONTENT_TYPE_HANDSHAKE, hello_len);
        record.extend_from_slice(&client_hello);
        self.ciphertext_write_buf.extend_from_slice(&record);

        // Store the wire ClientHello bytes for transcript hashing after ServerHello.
        // At this point client_hello contains the encrypted SessionId.
        self.handshake_state = HandshakeState::AwaitingServerHello {
            client_hello_bytes: client_hello, // Save the actual ClientHello bytes
            key_exchange,
            auth_key, // Save auth_key for HMAC certificate verification
        };

        Ok(())
    }

    /// Read TLS messages from the provided reader into internal buffer
    ///
    /// Uses pre-allocated buffer to avoid allocation on every call.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        if self.ciphertext_read_buf.remaining_capacity() < TLS_MAX_RECORD_SIZE {
            self.ciphertext_read_buf.compact();
        }

        let available = self.ciphertext_read_buf.remaining_capacity();
        if available == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY ciphertext buffer limit exceeded",
            ));
        }
        let n = rd.read(&mut self.tls_read_buffer[..available.min(TLS_MAX_RECORD_SIZE)])?;
        if n > 0 {
            self.ciphertext_read_buf
                .extend_from_slice(&self.tls_read_buffer[..n]);
        }
        Ok(n)
    }

    /// Process buffered packets and advance state machine
    ///
    /// Like rustls, this loops until no more progress can be made, ensuring
    /// that piggybacked application data is processed in the same call.
    pub fn process_new_packets(&mut self) -> io::Result<()> {
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        // RFC 8446: don't process data after close_notify
        if self.received_close_notify {
            return Ok(());
        }

        let result = self.process_new_packets_inner();

        if let Err(ref e) = result {
            match e.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(e.kind());
                }
                _ => {}
            }
        }

        result
    }

    /// Inner implementation of process_new_packets
    fn process_new_packets_inner(&mut self) -> io::Result<()> {
        loop {
            match &self.handshake_state {
                HandshakeState::AwaitingServerHello { .. } => {
                    if !self.process_server_hello()? {
                        break;
                    }
                }
                HandshakeState::ProcessingHandshake { .. } => {
                    if !self.process_encrypted_handshake()? {
                        break;
                    }
                }
                HandshakeState::Complete => {
                    self.process_application_data()?;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process ServerHello
    /// Returns true if a complete record was processed, false if more data needed
    #[inline]
    fn process_server_hello(&mut self) -> io::Result<bool> {
        let HandshakeState::AwaitingServerHello {
            client_hello_bytes,
            key_exchange,
            auth_key,
        } = &self.handshake_state
        else {
            return Err(handshake_state_error("ServerHello"));
        };

        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        if self.ciphertext_read_buf[0] != CONTENT_TYPE_HANDSHAKE
            || self.ciphertext_read_buf.get_u16_be(1) != Some(0x0303)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid REALITY ServerHello record header",
            ));
        }
        let total_record_len = checked_record_len(&self.ciphertext_read_buf)?;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false);
        }

        // Clone fields before consuming buffer
        let client_hello_bytes = client_hello_bytes.clone();
        let auth_key = *auth_key;

        let record: Vec<u8> = self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);
        let server_hello = &record[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header (includes handshake header)

        let profile = self.config.hello_profile.table();
        validate_server_hello(server_hello, &client_hello_bytes)?;

        let cipher_suite_id = extract_server_cipher_suite(server_hello)?;
        let cipher_suite = CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Server selected unsupported cipher suite: 0x{:04x}",
                    cipher_suite_id
                ),
            )
        })?;
        // The offered list and the implemented list are the same table: a suite
        // the profile marks negotiable is one `CipherSuite::from_id` resolves,
        // and `HelloProfile::validate` refused the hello otherwise.
        if !profile
            .negotiable_cipher_suites()
            .iter()
            .any(|suite| suite.id() == cipher_suite_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "server selected cipher suite 0x{cipher_suite_id:04x}, which the \
                     {} hello does not offer as negotiable",
                    profile.name
                ),
            ));
        }

        let server_key_share = extract_server_key_share(server_hello)?;

        // Compute transcript hash using negotiated cipher suite's algorithm
        let mut full_transcript = digest::Context::new(cipher_suite.digest_algorithm());
        full_transcript.update(&client_hello_bytes); // Use actual ClientHello bytes, not hash!
        full_transcript.update(server_hello); // ServerHello already includes handshake header
        let server_hello_hash = full_transcript.finish();
        let server_hello_hash_vec: Vec<u8> = server_hello_hash.as_ref().to_vec();

        let client_hello_hash_vec: Vec<u8> = {
            let mut ctx = digest::Context::new(cipher_suite.digest_algorithm());
            ctx.update(&client_hello_bytes);
            ctx.finish().as_ref().to_vec()
        };

        // 32 bytes for x25519, 64 for X25519MLKEM768. This is the last use of
        // the borrow on the handshake state, so the assignment below is free to
        // replace it.
        let mut tls_shared_secret = key_exchange.complete(&server_key_share)?;

        let hs_keys = derive_handshake_keys(
            cipher_suite,
            &tls_shared_secret,
            &client_hello_hash_vec,
            &server_hello_hash_vec,
        )?;
        tls_shared_secret.zeroize();

        // Use actual bytes (not hashes) for transcript
        let mut transcript_bytes = Vec::new();
        transcript_bytes.extend_from_slice(&client_hello_bytes);
        transcript_bytes.extend_from_slice(server_hello);

        self.handshake_state = HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret,
            server_handshake_traffic_secret: hs_keys.server_handshake_traffic_secret,
            master_secret: hs_keys.master_secret,
            cipher_suite,
            handshake_transcript_bytes: transcript_bytes,
            auth_key, // Pass auth_key for certificate HMAC verification
            // Initialize state for handling multiple encrypted handshake records
            handshake_seq: 0,
            accumulated_plaintext: Vec::new(),
            parse_offset: 0,
            messages_found: 0,
            certificate_verified: false,
            ed25519_public_key: None,
            cert_verify_offset: None,
            finished_offset: None,
        };

        Ok(true)
    }

    /// Process encrypted handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished)
    /// Handles both combined (1 record) and separate (multiple records) modes.
    /// Returns true if a complete record was processed, false if more data needed
    #[inline]
    fn process_encrypted_handshake(&mut self) -> io::Result<bool> {
        let HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_transcript_bytes,
            auth_key,
            handshake_seq,
            accumulated_plaintext,
            parse_offset,
            messages_found,
            certificate_verified,
            ed25519_public_key,
            cert_verify_offset,
            finished_offset,
        } = &self.handshake_state
        else {
            return Err(handshake_state_error("server handshake messages"));
        };

        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(server_handshake_traffic_secret, *cipher_suite)?;

        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_type = self.ciphertext_read_buf[0];
        let tls_version = self
            .ciphertext_read_buf
            .get_u16_be(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?;
        let record_len = self
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;
        if tls_version != 0x0303 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid REALITY TLS record version",
            ));
        }

        let total_record_len = checked_record_len(&self.ciphertext_read_buf)?;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false);
        }

        // Skip ChangeCipherSpec (dummy in TLS 1.3)
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            self.ciphertext_read_buf.consume(total_record_len);
            return Ok(true);
        }

        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected Application Data record, got 0x{:02x}",
                    record_type
                ),
            ));
        }

        // NOW we're committed to processing - clone/copy fields we need to modify
        let client_hs_secret = client_handshake_traffic_secret.clone();
        let server_hs_secret = server_handshake_traffic_secret.clone();
        let master_secret = master_secret.clone();
        let transcript_bytes = handshake_transcript_bytes.clone();
        let mut accumulated_plaintext = accumulated_plaintext.clone();
        let mut parse_offset = *parse_offset;
        let cipher_suite = *cipher_suite;
        let auth_key = *auth_key;
        let mut handshake_seq = *handshake_seq;
        let mut messages_found = *messages_found;
        let mut certificate_verified = *certificate_verified;
        let mut ed25519_public_key = *ed25519_public_key;
        let mut cert_verify_offset = *cert_verify_offset;
        let mut finished_offset = *finished_offset;

        // Copy and extract the encrypted handshake record
        let ciphertext: Vec<u8> =
            self.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);

        // Decrypt using current sequence number
        let plaintext = decrypt_handshake_message(
            cipher_suite,
            &server_hs_key,
            &server_hs_iv,
            handshake_seq,
            &ciphertext,
            record_len as u16,
        )?;

        handshake_seq += 1;

        accumulated_plaintext.extend_from_slice(&plaintext);

        // Continue from the first incomplete message so split TLS records are
        // parsed correctly instead of treating a fragment as a new message.
        while parse_offset < accumulated_plaintext.len() && messages_found < 4 {
            // Each handshake message has: type (1 byte) + length (3 bytes) + data
            if parse_offset + 4 > accumulated_plaintext.len() {
                break; // Incomplete message header, need more data
            }

            let msg_type = accumulated_plaintext[parse_offset];
            let msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[parse_offset + 1],
                accumulated_plaintext[parse_offset + 2],
                accumulated_plaintext[parse_offset + 3],
            ]) as usize;

            if parse_offset + 4 + msg_len > accumulated_plaintext.len() {
                break; // Incomplete message body, need more data
            }

            let expected = match messages_found {
                0 => HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
                1 => HANDSHAKE_TYPE_CERTIFICATE,
                2 => HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
                3 => HANDSHAKE_TYPE_FINISHED,
                // The loop condition bounds this to 0..4, but the bound and the
                // table live in different places; a mismatch must not abort the
                // process.
                _ => return Err(handshake_state_error("server handshake message index")),
            };
            if msg_type != expected {
                // The hello offers `compress_certificate` because Chrome does,
                // and a server may take the offer. RFC 8879 is not implemented
                // here, so say that rather than reporting a message-order bug
                // for a server that did exactly what it was invited to do.
                if msg_type == HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE
                    && expected == HANDSHAKE_TYPE_CERTIFICATE
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "REALITY server compressed its Certificate; this client offers \
                         compress_certificate for fingerprint fidelity but does not implement \
                         RFC 8879",
                    ));
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "REALITY server handshake message order is invalid",
                ));
            }

            // Verify HMAC signature when we encounter the Certificate message
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE {
                let cert_der = extract_certificate_der(
                    &accumulated_plaintext[parse_offset..parse_offset + 4 + msg_len],
                )?;
                verify_certificate_hmac(cert_der, &auth_key)?;
                ed25519_public_key = Some(extract_ed25519_public_key(cert_der)?);
                certificate_verified = true;
            }

            // Record CertificateVerify offset for later verification
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                cert_verify_offset = Some(parse_offset);
            }
            if msg_type == HANDSHAKE_TYPE_FINISHED {
                finished_offset = Some(parse_offset);
            }

            messages_found += 1;
            parse_offset += 4 + msg_len;
        }

        if messages_found < 4 {
            self.handshake_state = HandshakeState::ProcessingHandshake {
                client_handshake_traffic_secret: client_hs_secret,
                server_handshake_traffic_secret: server_hs_secret,
                master_secret,
                cipher_suite,
                handshake_transcript_bytes: transcript_bytes,
                auth_key,
                handshake_seq,
                accumulated_plaintext,
                parse_offset,
                messages_found,
                certificate_verified,
                ed25519_public_key,
                cert_verify_offset,
                finished_offset,
            };
            return Ok(true); // Processed a record, but need more
        }

        // Ensure the Certificate message was present and HMAC verified
        if !certificate_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: Certificate message not received or not verified",
            ));
        }

        // Verify CertificateVerify signature
        let mut cert_verify_verified = false;
        if let (Some(public_key), Some(cv_offset)) = (ed25519_public_key, cert_verify_offset) {
            // Transcript up to (not including) CertificateVerify
            let mut cv_transcript = digest::Context::new(cipher_suite.digest_algorithm());
            cv_transcript.update(&transcript_bytes);
            cv_transcript.update(&accumulated_plaintext[..cv_offset]);
            let cv_transcript_hash = cv_transcript.finish();

            let cv_msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[cv_offset + 1],
                accumulated_plaintext[cv_offset + 2],
                accumulated_plaintext[cv_offset + 3],
            ]) as usize;
            let cv_message = &accumulated_plaintext[cv_offset..cv_offset + 4 + cv_msg_len];
            let signature = extract_certificate_verify_signature(cv_message)?;

            verify_certificate_verify_signature(
                &public_key,
                &signature,
                cv_transcript_hash.as_ref(),
            )?;
            cert_verify_verified = true;
        }

        if !cert_verify_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: CertificateVerify not verified",
            ));
        }

        let finished_offset = finished_offset.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY server Finished message is missing",
            )
        })?;
        if parse_offset != accumulated_plaintext.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected bytes after REALITY server Finished",
            ));
        }
        let finished_len = u32::from_be_bytes([
            0,
            accumulated_plaintext[finished_offset + 1],
            accumulated_plaintext[finished_offset + 2],
            accumulated_plaintext[finished_offset + 3],
        ]) as usize;
        if finished_len != cipher_suite.hash_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY server Finished has an invalid length",
            ));
        }
        let mut server_finished_transcript = digest::Context::new(cipher_suite.digest_algorithm());
        server_finished_transcript.update(&transcript_bytes);
        server_finished_transcript.update(&accumulated_plaintext[..finished_offset]);
        let server_finished_hash = server_finished_transcript.finish();
        let expected_server_finished = compute_finished_verify_data(
            cipher_suite,
            &server_hs_secret,
            server_finished_hash.as_ref(),
        )?;
        let actual_server_finished =
            &accumulated_plaintext[finished_offset + 4..finished_offset + 4 + finished_len];
        if expected_server_finished
            .as_slice()
            .ct_eq(actual_server_finished)
            .unwrap_u8()
            == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY server Finished verification failed",
            ));
        }

        let mut handshake_transcript = digest::Context::new(cipher_suite.digest_algorithm());
        handshake_transcript.update(&transcript_bytes);
        handshake_transcript.update(&accumulated_plaintext);

        let handshake_hash = handshake_transcript.finish();
        let handshake_hash_vec: Vec<u8> = handshake_hash.as_ref().to_vec();

        let client_verify_data =
            compute_finished_verify_data(cipher_suite, &client_hs_secret, &handshake_hash_vec)?;
        let client_finished = construct_finished(&client_verify_data)?;

        let (mut client_hs_key, client_hs_iv) =
            derive_traffic_keys(&client_hs_secret, cipher_suite)?;

        let mut client_hs_seq = 0u64;
        let hs_aead_key = AeadKey::new(cipher_suite, &client_hs_key)?;
        {
            let mut encryptor =
                RecordEncryptor::new(&hs_aead_key, &client_hs_iv, &mut client_hs_seq);
            encryptor.encrypt_handshake(&client_finished, &mut self.ciphertext_write_buf)?;
        }
        client_hs_key.zeroize();

        let (mut client_app_secret, mut server_app_secret) =
            derive_application_secrets(cipher_suite, &master_secret, &handshake_hash_vec)?;

        let (mut client_app_key_bytes, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (mut server_app_key_bytes, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        // Cache AeadKey objects to avoid per-record key setup
        let client_app_key = AeadKey::new(cipher_suite, &client_app_key_bytes)?;
        let server_app_key = AeadKey::new(cipher_suite, &server_app_key_bytes)?;
        client_app_key_bytes.zeroize();
        server_app_key_bytes.zeroize();
        client_app_secret.zeroize();
        server_app_secret.zeroize();

        self.app_read_key = Some(server_app_key);
        self.app_read_iv = Some(server_app_iv);
        self.app_write_key = Some(client_app_key);
        self.app_write_iv = Some(client_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = Some(cipher_suite);
        self.handshake_state = HandshakeState::Complete;

        Ok(true)
    }

    /// Decrypt application data using TLS 1.3 keys
    /// Processes all complete TLS records in the buffer
    #[inline]
    fn process_application_data(&mut self) -> io::Result<()> {
        let (app_read_key, app_read_iv) = match (&self.app_read_key, &self.app_read_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => return Err(handshake_state_error("application traffic keys")),
        };

        while self.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
            let total_record_len = checked_record_len(&self.ciphertext_read_buf)?;
            if self.ciphertext_read_buf.len() < total_record_len {
                break;
            }
            let record_len = total_record_len - TLS_RECORD_HEADER_SIZE;

            // Decrypt in-place: get mutable slice of ciphertext, decrypt, copy plaintext out
            let ciphertext_slice = self
                .ciphertext_read_buf
                .slice_mut(TLS_RECORD_HEADER_SIZE..total_record_len);
            let mut decryptor = RecordDecryptor::new(app_read_key, app_read_iv, &mut self.read_seq);
            let (content_type, plaintext) =
                decryptor.decrypt_record_in_place(ciphertext_slice, record_len as u16)?;

            match content_type {
                CONTENT_TYPE_APPLICATION_DATA => {
                    // Compact plaintext buffer if needed before extending
                    self.plaintext_read_buf.maybe_compact(4096);
                    self.plaintext_read_buf.extend_from_slice(plaintext);
                }
                CONTENT_TYPE_ALERT => {
                    // Parse alert: level (1 byte) + description (1 byte)
                    if plaintext.len() >= 2 {
                        let alert_level = plaintext[0];
                        let alert_desc = plaintext[1];

                        if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                            self.received_close_notify = true;
                            // Per RFC 8446: "Any data received after a closure alert
                            // has been received MUST be ignored."
                            return Ok(());
                        } else if alert_level != ALERT_LEVEL_WARNING {
                            // Fatal alert - connection must be terminated
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                format!("received fatal alert: {}", alert_desc),
                            ));
                        }
                    }
                }
                // CONTENT_TYPE_HANDSHAKE is invalid after handshake complete
                // strip_content_type() validates and returns error for invalid types
                // `strip_content_type` is supposed to have rejected anything
                // else already. Trusting that across a module boundary is how a
                // remote peer gets to end the process.
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "REALITY record carries an unexpected content type",
                    ));
                }
            }

            // Consume the processed record from the buffer (after plaintext borrow ends)
            self.ciphertext_read_buf.consume(total_record_len);
        }

        Ok(())
    }

    /// Get a reader for accessing decrypted plaintext
    pub fn reader(&mut self) -> RealityReader<'_> {
        // SlideBuffer handles compaction internally via maybe_compact()
        // Compact before returning reader if we've consumed significant data
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf, self.received_close_notify)
    }

    /// Get a writer for buffering plaintext to be encrypted
    pub fn writer(&mut self) -> RealityWriter<'_> {
        RealityWriter::new(&mut self.plaintext_write_buf)
    }

    /// Write buffered TLS messages to the provided writer
    ///
    /// Large plaintext is automatically fragmented into multiple TLS records
    /// to comply with the TLS 1.3 record size limit.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        // If handshake not complete, just write buffered handshake data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            let n = wr.write(&self.ciphertext_write_buf)?;
            self.ciphertext_write_buf.drain(..n);
            return Ok(n);
        }

        // Encrypt any pending plaintext (with automatic fragmentation for large data)
        if !self.plaintext_write_buf.is_empty() {
            let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Application keys not available",
                    ));
                }
            };

            let mut encryptor =
                RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
            encryptor.encrypt_app_data(
                &mut self.plaintext_write_buf,
                &mut self.ciphertext_write_buf,
            )?;
        }

        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    /// Check if the connection wants to write data
    pub fn wants_write(&self) -> bool {
        !self.ciphertext_write_buf.is_empty() || !self.plaintext_write_buf.is_empty()
    }

    /// Check if handshake is still in progress
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.handshake_state, HandshakeState::Complete)
    }

    /// Check if the connection wants to read more TLS data
    ///
    /// Returns true if we need more data to make progress (handshake or decryption).
    /// This mirrors rustls::Connection::wants_read().
    pub fn wants_read(&self) -> bool {
        // Don't read more after receiving close_notify (RFC 8446)
        if self.received_close_notify {
            return false;
        }

        // Don't read more if we're in a fatal error state
        if self.fatal_error.is_some() {
            return false;
        }

        // During handshake, we always want to read
        if self.is_handshaking() {
            return true;
        }

        // After handshake, we want to read if:
        // 1. Plaintext buffer is empty (need more application data), OR
        // 2. Ciphertext buffer has incomplete records that need more data
        //
        // Note: If plaintext buffer has data, the caller should consume it first.
        // If ciphertext buffer has complete records, process_new_packets should be called.
        self.plaintext_read_buf.is_empty()
    }

    /// Queue a close notification alert
    pub fn send_close_notify(&mut self) {
        // In TLS 1.3, alerts must be encrypted like application data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            return;
        }

        // Get application keys
        let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => {
                return;
            }
        };

        // Encrypt close_notify alert using RecordEncryptor
        let mut encryptor = RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
        let _ = encryptor.encrypt_close_notify(&mut self.ciphertext_write_buf);
    }
}

fn checked_record_len(buffer: &SlideBuffer) -> io::Result<usize> {
    let record_len = buffer
        .get_u16_be(3)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TLS record header truncated"))?
        as usize;
    if record_len > MAX_TLS_CIPHERTEXT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY TLS record exceeds the TLS 1.3 ciphertext limit",
        ));
    }
    Ok(TLS_RECORD_HEADER_SIZE + record_len)
}

/// RFC 8446 §4.1.3: a ServerHello whose `random` is this value is a
/// HelloRetryRequest wearing a ServerHello's clothes.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn validate_server_hello(server_hello: &[u8], client_hello: &[u8]) -> io::Result<()> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);

    let end = HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN;
    if server_hello.len() < end
        || client_hello.len() < end
        || server_hello[0] != 2
        || server_hello[4..6] != [0x03, 0x03]
    {
        return Err(invalid("invalid REALITY ServerHello".to_owned()));
    }
    let declared =
        u32::from_be_bytes([0, server_hello[1], server_hello[2], server_hello[3]]) as usize;
    if declared != server_hello.len() - 4
        || server_hello[HELLO_SESSION_ID_OFFSET - 1] as usize != HELLO_SESSION_ID_LEN
        || server_hello[HELLO_SESSION_ID_OFFSET..end]
            .ct_eq(&client_hello[HELLO_SESSION_ID_OFFSET..end])
            .unwrap_u8()
            == 0
    {
        return Err(invalid("REALITY ServerHello session is invalid".to_owned()));
    }

    // Lock 1 — HelloRetryRequest. It is a ServerHello with a fixed `random`,
    // and treating it as one would derive handshake keys from a message that
    // carries no key share at all. Chrome would answer it with a second hello
    // for the group the server asked for; this client does not, and says so
    // rather than failing later with something that looks like a parse bug.
    if server_hello[6..38] == HELLO_RETRY_REQUEST_RANDOM {
        return Err(invalid(
            "REALITY server answered with a HelloRetryRequest; this client sends one ClientHello \
             and does not renegotiate the key exchange group"
                .to_owned(),
        ));
    }

    // Lock 2 — the negotiated version. `legacy_version` is 0x0303 in every TLS
    // 1.3 ServerHello *and* in every TLS 1.2 one, so it proves nothing: the
    // real answer is in `supported_versions`. The hello offers TLS 1.2 because
    // Chrome does, which is exactly why a server taking that offer has to be
    // refused here instead of being run through a 1.3-only key schedule.
    match extract_server_selected_version(server_hello)? {
        Some(TLS_1_3) => {}
        Some(version) => {
            return Err(invalid(format!(
                "REALITY server negotiated TLS version 0x{version:04x}; this client implements \
                 TLS 1.3 only"
            )));
        }
        None => {
            return Err(invalid(
                "REALITY server sent no supported_versions extension, which means it did not \
                 negotiate TLS 1.3"
                    .to_owned(),
            ));
        }
    }

    // Lock 3 — the selected group. `supported_groups` names secp256r1 and
    // secp384r1 because Chrome names them; this build sends no share for either
    // and cannot complete one. A server picking one is refused by name.
    let group = extract_server_selected_group(server_hello)?;
    match NamedGroup::from_id(group) {
        Some(named) if named.is_executable() => Ok(()),
        Some(named) => Err(invalid(format!(
            "REALITY server selected key exchange group {}, which this hello names but this \
             build does not execute",
            named.name()
        ))),
        None => Err(invalid(format!(
            "REALITY server selected key exchange group 0x{group:04x}, which was never offered"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::agreement;

    fn server_public_key(private: &[u8; 32]) -> [u8; 32] {
        let key = agreement::PrivateKey::from_private_key(&agreement::X25519, private).unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(key.compute_public_key().unwrap().as_ref());
        public
    }

    fn config() -> RealityClientConfig {
        RealityClientConfig {
            public_key: server_public_key(&[0x42u8; 32]),
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            server_name: "example.com".to_string(),
            hello_profile: RealityHelloProfile::Chrome133,
        }
    }

    fn fresh_connection() -> RealityClientConnection {
        RealityClientConnection::new(config()).unwrap()
    }

    /// A state machine driven by a remote server must fail the connection, not
    /// the process. These paths used to be `unreachable!()`, and the release
    /// profile aborts on panic — so a server that got the handshake out of order
    /// could end the whole VPN rather than its own connection.
    #[test]
    fn a_wrong_handshake_state_is_an_error_rather_than_a_panic() {
        let mut connection = fresh_connection();
        // Fresh connection: application traffic keys do not exist yet.
        let error = connection
            .process_application_data()
            .expect_err("application data before the handshake must not be processed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = connection
            .process_encrypted_handshake()
            .expect_err("encrypted handshake messages are not expected in this state");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn client_hello_transcript_bytes_use_encrypted_session_id() {
        let mut conn = RealityClientConnection::new(config()).unwrap();
        let stored_client_hello = match &conn.handshake_state {
            HandshakeState::AwaitingServerHello {
                client_hello_bytes, ..
            } => client_hello_bytes.clone(),
            _ => panic!("new client must be awaiting ServerHello"),
        };

        let mut wire = Vec::new();
        conn.write_tls(&mut wire).unwrap();

        assert_eq!(&wire[5..], stored_client_hello.as_slice());
        assert_ne!(
            &stored_client_hello
                [HELLO_SESSION_ID_OFFSET..HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN],
            &[0u8; 32],
            "transcript ClientHello must retain encrypted wire SessionId"
        );
    }

    /// The parrot has to reach the wire, not just the table: a hello that is
    /// still the old six-extension literal would pass every profile test and
    /// still be the thing this change exists to remove.
    #[test]
    fn the_hello_a_connection_writes_is_the_profile_hello() {
        let mut conn = RealityClientConnection::new(config()).unwrap();
        let mut wire = Vec::new();
        conn.write_tls(&mut wire).unwrap();
        let hello = &wire[TLS_RECORD_HEADER_SIZE..];

        // 1216 bytes of hybrid key share alone puts it well past the old ~200.
        assert!(hello.len() > 1400, "hello is {} bytes", hello.len());
        assert_eq!(hello[0], 0x01);

        let mut offset = HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN;
        let cipher_suites_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        assert_eq!(cipher_suites_len / 2, 16, "Chrome offers sixteen");
        offset += 2 + cipher_suites_len;
        offset += 1 + hello[offset] as usize; // compression methods
        let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
        offset += 2;
        let end = offset + extensions_len;

        let mut types = Vec::new();
        while offset < end {
            let kind = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
            let length = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
            types.push(kind);
            offset += 4 + length;
        }
        assert_eq!(offset, end);
        for required in [
            0x0000, // server_name
            0x000a, // supported_groups
            0x0033, // key_share
            0x002b, // supported_versions
            0x0010, // ALPN
            0xfe0d, // ECH GREASE
        ] {
            assert!(types.contains(&required), "missing 0x{required:04x}");
        }
    }

    /// Build a ServerHello handshake message with the pieces each lock reads.
    fn server_hello(
        random: [u8; 32],
        session_id: &[u8; 32],
        selected_version: Option<u16>,
        selected_group: Option<u16>,
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(version) = selected_version {
            extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02]);
            extensions.extend_from_slice(&version.to_be_bytes());
        }
        if let Some(group) = selected_group {
            let share = vec![0x11_u8; 32];
            extensions.extend_from_slice(&[0x00, 0x33]);
            extensions.extend_from_slice(&((4 + share.len()) as u16).to_be_bytes());
            extensions.extend_from_slice(&group.to_be_bytes());
            extensions.extend_from_slice(&(share.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&share);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut message = vec![0x02];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn client_hello_with(session_id: &[u8; 32]) -> Vec<u8> {
        let mut hello = vec![0u8; HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN];
        hello[HELLO_SESSION_ID_OFFSET - 1] = HELLO_SESSION_ID_LEN as u8;
        hello[HELLO_SESSION_ID_OFFSET..].copy_from_slice(session_id);
        hello
    }

    /// Three refusals, three messages. One "invalid ServerHello" for all of
    /// them would be a client that cannot tell a server asking for another
    /// group from a server that answered TLS 1.2.
    #[test]
    fn the_three_server_hello_locks_each_refuse_for_their_own_reason() {
        let session_id = [0x5c_u8; 32];
        let client_hello = client_hello_with(&session_id);
        let good_random = [0x01_u8; 32];

        // The baseline this is all measured against: TLS 1.3, x25519.
        validate_server_hello(
            &server_hello(
                good_random,
                &session_id,
                Some(TLS_1_3),
                Some(NamedGroup::X25519.id()),
            ),
            &client_hello,
        )
        .expect("a TLS 1.3 x25519 ServerHello is exactly what this client asked for");
        validate_server_hello(
            &server_hello(
                good_random,
                &session_id,
                Some(TLS_1_3),
                Some(NamedGroup::X25519MlKem768.id()),
            ),
            &client_hello,
        )
        .expect("and so is the hybrid");

        let message = |hello: Vec<u8>| -> String {
            validate_server_hello(&hello, &client_hello)
                .expect_err("this ServerHello must be refused")
                .to_string()
        };

        let hrr = message(server_hello(
            HELLO_RETRY_REQUEST_RANDOM,
            &session_id,
            Some(TLS_1_3),
            Some(NamedGroup::Secp256r1.id()),
        ));
        assert!(hrr.contains("HelloRetryRequest"), "{hrr}");

        let tls12 = message(server_hello(
            good_random,
            &session_id,
            Some(0x0303),
            Some(NamedGroup::X25519.id()),
        ));
        assert!(tls12.contains("TLS version 0x0303"), "{tls12}");

        let no_version = message(server_hello(
            good_random,
            &session_id,
            None,
            Some(NamedGroup::X25519.id()),
        ));
        assert!(no_version.contains("supported_versions"), "{no_version}");

        let named_group = message(server_hello(
            good_random,
            &session_id,
            Some(TLS_1_3),
            Some(NamedGroup::Secp256r1.id()),
        ));
        assert!(named_group.contains("secp256r1"), "{named_group}");

        let unknown_group = message(server_hello(
            good_random,
            &session_id,
            Some(TLS_1_3),
            Some(0x11eb), // SecP256r1MLKEM768: never offered
        ));
        assert!(unknown_group.contains("never offered"), "{unknown_group}");

        // Every message is distinct: that is the whole requirement.
        let all = [hrr, tls12, no_version, named_group, unknown_group];
        let unique: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "{all:?}");
    }

    /// The hello offers `compress_certificate` because Chrome does. A server
    /// that takes the offer gets an answer that names RFC 8879, not a generic
    /// "message order is invalid" that would send someone reading the code.
    #[test]
    fn a_compressed_certificate_is_refused_by_name() {
        // Driven through the real record layer and the real state machine: a
        // test that walked the messages itself would assert that the test can
        // spot a 25, not that the client does.
        let cipher_suite = CipherSuite::AES_128_GCM_SHA256;
        let server_secret = vec![0x33_u8; 32];
        let encrypted_record = |messages: &[u8]| -> Vec<u8> {
            let (key, iv) = derive_traffic_keys(&server_secret, cipher_suite).unwrap();
            let aead = AeadKey::new(cipher_suite, &key).unwrap();
            let mut seq = 0_u64;
            let mut record = Vec::new();
            RecordEncryptor::new(&aead, &iv, &mut seq)
                .encrypt_handshake(messages, &mut record)
                .unwrap();
            record
        };
        let in_handshake = |connection: &mut RealityClientConnection| {
            connection.handshake_state = HandshakeState::ProcessingHandshake {
                client_handshake_traffic_secret: vec![0_u8; 32],
                server_handshake_traffic_secret: server_secret.clone(),
                master_secret: vec![0_u8; 32],
                cipher_suite,
                handshake_transcript_bytes: Vec::new(),
                auth_key: [0_u8; 32],
                handshake_seq: 0,
                accumulated_plaintext: Vec::new(),
                parse_offset: 0,
                messages_found: 0,
                certificate_verified: false,
                ed25519_public_key: None,
                cert_verify_offset: None,
                finished_offset: None,
            };
        };

        // EncryptedExtensions (empty), then a CompressedCertificate where a
        // Certificate belongs.
        let mut messages = vec![HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0];
        messages.extend_from_slice(&[HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE, 0, 0, 1, 0]);

        let mut connection = fresh_connection();
        in_handshake(&mut connection);
        connection
            .read_tls(&mut io::Cursor::new(encrypted_record(&messages)))
            .unwrap();
        let error = connection
            .process_encrypted_handshake()
            .expect_err("RFC 8879 is not implemented");
        assert!(error.to_string().contains("RFC 8879"), "{error}");

        // Any other out-of-order type still gets the generic answer, so the
        // branch above is a named case and not a rename of the whole check.
        let mut wrong = vec![HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0];
        wrong.extend_from_slice(&[HANDSHAKE_TYPE_FINISHED, 0, 0, 1, 0]);
        let mut connection = fresh_connection();
        in_handshake(&mut connection);
        connection
            .read_tls(&mut io::Cursor::new(encrypted_record(&wrong)))
            .unwrap();
        let error = connection
            .process_encrypted_handshake()
            .expect_err("a Finished cannot stand in for a Certificate");
        assert!(error.to_string().contains("message order"), "{error}");
    }
}
