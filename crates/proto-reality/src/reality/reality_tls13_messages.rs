// TLS 1.3 Message Construction
//
// Construct TLS 1.3 handshake messages for REALITY protocol

#[cfg(any(test, feature = "testkit"))]
use super::common::{
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_SERVER_HELLO,
    VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR,
};
use super::common::{
    HANDSHAKE_TYPE_FINISHED, HELLO_SESSION_ID_LEN, HELLO_SESSION_ID_OFFSET, VERSION_TLS_1_0_MAJOR,
    VERSION_TLS_1_0_MINOR,
};
use super::hello_profile::{
    COMPRESSION_METHODS, CipherSuiteSlot, GreaseSlot, HelloProfileData, HelloSession,
    LEGACY_VERSION, extension_order, write_padding,
};
use std::io::Result;

/// Construct ServerHello message
///
/// # Arguments
/// * `server_random` - 32 bytes of server random
/// * `session_id` - Session ID from ClientHello (for compatibility)
/// * `cipher_suite` - Selected cipher suite (e.g., 0x1301)
/// * `key_share_data` - Server's X25519 public key (32 bytes)
#[cfg(any(test, feature = "testkit"))]
pub fn construct_server_hello(
    server_random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    key_share_data: &[u8],
) -> Result<Vec<u8>> {
    let mut server_hello = Vec::new();

    // ServerHello structure:
    // - handshake_type (1 byte) = 2
    // - length (3 bytes)
    // - version (2 bytes) = 0x0303 (TLS 1.2 for compatibility)
    // - random (32 bytes)
    // - session_id_length (1 byte)
    // - session_id (variable)
    // - cipher_suite (2 bytes)
    // - compression_method (1 byte) = 0
    // - extensions_length (2 bytes)
    // - extensions (variable)

    let mut payload = Vec::new();

    // Version: 0x0303 (TLS 1.2 for compatibility)
    payload.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Random (32 bytes)
    payload.extend_from_slice(server_random);

    // Session ID
    payload.push(session_id.len() as u8);
    payload.extend_from_slice(session_id);

    // Cipher suite
    payload.extend_from_slice(&cipher_suite.to_be_bytes());

    // Compression method = 0
    payload.push(0x00);

    // Extensions
    let mut extensions = Vec::new();

    // supported_versions extension (type=43)
    extensions.extend_from_slice(&[0x00, 0x2b]); // type = 43
    extensions.extend_from_slice(&[0x00, 0x02]); // length = 2
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // key_share extension (type=51)
    let key_share_length = 2 + 2 + key_share_data.len(); // group + length + data
    extensions.extend_from_slice(&[0x00, 0x33]); // type = 51
    extensions.extend_from_slice(&(key_share_length as u16).to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x1d]); // group = X25519 (0x001d)
    extensions.extend_from_slice(&(key_share_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key_share_data);

    // Extensions length
    payload.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    payload.extend_from_slice(&extensions);

    // Handshake header
    server_hello.push(HANDSHAKE_TYPE_SERVER_HELLO);

    // Payload length (3 bytes, big-endian)
    let length_bytes = [
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    server_hello.extend_from_slice(&length_bytes);
    server_hello.extend_from_slice(&payload);

    Ok(server_hello)
}

/// Construct EncryptedExtensions message
#[cfg(any(test, feature = "testkit"))]
pub fn construct_encrypted_extensions() -> Result<Vec<u8>> {
    let mut encrypted_extensions = Vec::new();

    // EncryptedExtensions structure:
    // - handshake_type (1 byte) = 8
    // - length (3 bytes)
    // - extensions_length (2 bytes)
    // - extensions (variable, usually empty for minimal setup)

    encrypted_extensions.push(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);

    // Empty extensions for minimal setup
    let extensions_length: u16 = 0;
    let payload_length = 2; // Just the extensions_length field

    // Payload length (3 bytes)
    encrypted_extensions.extend_from_slice(&[0x00, 0x00, payload_length as u8]);

    // Extensions length (2 bytes)
    encrypted_extensions.extend_from_slice(&extensions_length.to_be_bytes());

    Ok(encrypted_extensions)
}

/// Construct Certificate message with HMAC-signed Ed25519 certificate
///
/// # Arguments
/// * `cert` - Certificate from rcgen (takes ownership to avoid allocation)
#[cfg(any(test, feature = "testkit"))]
pub fn construct_certificate(cert: rcgen::Certificate) -> Result<Vec<u8>> {
    let cert_der = cert.der();

    // Certificate structure:
    // - handshake_type (1 byte) = 11
    // - length (3 bytes)
    // - certificate_request_context (1 byte length + data, usually empty)
    // - certificate_list (3 bytes length + entries)
    //   - certificate_entry:
    //     - cert_data (3 bytes length + DER)
    //     - extensions (2 bytes length, usually empty)

    // Pre-calculate sizes to allocate exact capacity
    // cert_list = 3 (len) + cert_der.len() + 2 (extensions)
    let cert_list_len = 3 + cert_der.len() + 2;
    // payload = 1 (context) + 3 (list len) + cert_list_len
    let payload_len = 1 + 3 + cert_list_len;
    // total = 1 (type) + 3 (payload len) + payload_len
    let total_len = 1 + 3 + payload_len;

    let mut certificate = Vec::with_capacity(total_len);

    // Handshake header
    certificate.push(HANDSHAKE_TYPE_CERTIFICATE);

    // Payload length (3 bytes)
    certificate.extend_from_slice(&[
        ((payload_len >> 16) & 0xff) as u8,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
    ]);

    // Certificate request context (empty for server certificates)
    certificate.push(0x00);

    // Certificate list length (3 bytes)
    certificate.extend_from_slice(&[
        ((cert_list_len >> 16) & 0xff) as u8,
        ((cert_list_len >> 8) & 0xff) as u8,
        (cert_list_len & 0xff) as u8,
    ]);

    // Certificate entry - cert data length (3 bytes)
    certificate.extend_from_slice(&[
        ((cert_der.len() >> 16) & 0xff) as u8,
        ((cert_der.len() >> 8) & 0xff) as u8,
        (cert_der.len() & 0xff) as u8,
    ]);

    // Certificate DER data
    certificate.extend_from_slice(cert_der);

    // Extensions (empty)
    certificate.extend_from_slice(&[0x00, 0x00]);

    Ok(certificate)
}

/// Construct Finished message
///
/// # Arguments
/// * `verify_data` - HMAC of handshake transcript (32 bytes for SHA256)
pub fn construct_finished(verify_data: &[u8]) -> Result<Vec<u8>> {
    let mut finished = Vec::new();

    // Finished structure:
    // - handshake_type (1 byte) = 20
    // - length (3 bytes)
    // - verify_data (variable, 32 bytes for SHA256)

    finished.push(HANDSHAKE_TYPE_FINISHED);

    // Payload length (3 bytes)
    finished.extend_from_slice(&[
        ((verify_data.len() >> 16) & 0xff) as u8,
        ((verify_data.len() >> 8) & 0xff) as u8,
        (verify_data.len() & 0xff) as u8,
    ]);

    finished.extend_from_slice(verify_data);

    Ok(finished)
}

/// Construct a TLS 1.3 ClientHello by executing a fingerprint profile.
///
/// Returns handshake message bytes, without the record header.
///
/// The shape is entirely the profile's: cipher suites, extension set, extension
/// order, GREASE placement and padding all come out of the table in
/// [`super::hello_profile`]. Everything this function adds is the framing and
/// the per-connection values the table asks the session for.
///
/// # The session-id window
///
/// REALITY derives its encrypted session id over the ClientHello *with the
/// session id zeroed*, and the server does the same. The window is
/// [`HELLO_SESSION_ID_OFFSET`]`..+`[`HELLO_SESSION_ID_LEN`] and it used to be
/// the literal `39..71` in two files. It is checked here, against the bytes
/// just written, so that changing a field in front of it fails at construction
/// instead of producing an AAD the server cannot reproduce — a failure that
/// would surface as "authentication rejected" and send everyone looking at
/// short ids.
pub fn construct_client_hello(
    profile: &HelloProfileData<'_>,
    session: &HelloSession<'_>,
) -> Result<Vec<u8>> {
    profile.validate()?;

    let mut hello = Vec::with_capacity(2048);

    // ClientHello handshake header: type, then a 24-bit length filled in last.
    hello.push(0x01);
    let length_offset = hello.len();
    hello.extend_from_slice(&[0_u8; 3]);

    hello.extend_from_slice(&LEGACY_VERSION);
    hello.extend_from_slice(session.client_random);

    hello.push(HELLO_SESSION_ID_LEN as u8);
    hello.extend_from_slice(session.session_id);

    let mut cipher_suites = Vec::with_capacity(profile.cipher_suites.len() * 2);
    for slot in profile.cipher_suites {
        let id = match slot {
            CipherSuiteSlot::Grease => session.grease.value(GreaseSlot::Cipher),
            CipherSuiteSlot::Negotiable(id) | CipherSuiteSlot::Decorative(id) => *id,
        };
        cipher_suites.extend_from_slice(&id.to_be_bytes());
    }
    let cipher_suites_len = u16::try_from(cipher_suites.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY hello profile offers more cipher suites than a ClientHello can carry",
        )
    })?;
    hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
    hello.extend_from_slice(&cipher_suites);

    hello.extend_from_slice(COMPRESSION_METHODS);

    let extensions_offset = hello.len();
    hello.extend_from_slice(&[0_u8; 2]);

    let mut extensions = Vec::with_capacity(2048);
    for index in extension_order(profile, session.permutation_seed) {
        profile.extensions[index].encode(session, &mut extensions)?;
    }
    // Padding is last and is a function of everything already written: the
    // handshake header, the body, the two-byte extensions length, and every
    // other extension. `hello` currently holds all of those but the extensions
    // themselves, so this sum is the finished message length without padding.
    let unpadded_len = hello.len() + extensions.len();
    write_padding(&mut extensions, unpadded_len)?;

    let extensions_len = u16::try_from(extensions.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ClientHello extensions exceed 65535 bytes",
        )
    })?;
    hello[extensions_offset..extensions_offset + 2].copy_from_slice(&extensions_len.to_be_bytes());
    hello.extend_from_slice(&extensions);

    let message_length = hello.len() - 4;
    if message_length > 0x00ff_ffff {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY ClientHello exceeds the 24-bit handshake length",
        ));
    }
    hello[length_offset..length_offset + 3]
        .copy_from_slice(&(message_length as u32).to_be_bytes()[1..]);

    assert_session_id_window(&hello, session.session_id)?;

    Ok(hello)
}

/// Check that [`HELLO_SESSION_ID_OFFSET`] still points at the session id.
///
/// Cheap, and the only thing standing between a reordered ClientHello field and
/// a REALITY AAD that silently stops matching the server's.
fn assert_session_id_window(hello: &[u8], session_id: &[u8; HELLO_SESSION_ID_LEN]) -> Result<()> {
    let end = HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN;
    if hello.len() < end
        || hello[HELLO_SESSION_ID_OFFSET - 1] as usize != HELLO_SESSION_ID_LEN
        || &hello[HELLO_SESSION_ID_OFFSET..end] != session_id.as_slice()
    {
        return Err(std::io::Error::other(
            "REALITY ClientHello layout moved the session id away from its constant offset; the \
             REALITY AAD would no longer match the server's",
        ));
    }
    Ok(())
}

/// Write a TLS record header with the pinned legacy record version.
///
/// # Arguments
/// * `record_type` - TLS record type (0x16 for Handshake, 0x17 for ApplicationData)
/// * `version` - `legacy_record_version`; see [`INITIAL_RECORD_VERSION`]
/// * `length` - Length of record payload
pub fn write_record_header(record_type: u8, version: [u8; 2], length: u16) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(record_type);
    header.extend_from_slice(&version);
    header.extend_from_slice(&length.to_be_bytes());
    header
}

pub const INITIAL_RECORD_VERSION: [u8; 2] = [VERSION_TLS_1_0_MAJOR, VERSION_TLS_1_0_MINOR];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::common::CONTENT_TYPE_HANDSHAKE;
    use crate::reality::hello_profile::{
        CHROME_131, CHROME_133, CHROME_ALPN_PROTOCOLS, EchGreaseParams, GreaseValues, is_grease,
    };
    use crate::reality::reality_key_exchange::{ClientKeyExchange, NamedGroup};

    #[test]
    fn test_construct_server_hello() {
        let server_random = [0x42u8; 32];
        let session_id = vec![0x99u8; 32];
        let cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
        let key_share = vec![0xAAu8; 32];

        let result = construct_server_hello(&server_random, &session_id, cipher_suite, &key_share);

        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_SERVER_HELLO);
    }

    #[test]
    fn test_construct_encrypted_extensions() {
        let result = construct_encrypted_extensions();
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);
    }

    #[test]
    fn test_construct_certificate() {
        use crate::reality::reality_certificate::generate_hmac_certificate;
        let auth_key = [0x42u8; 32];
        let (cert, _) = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let result = construct_certificate(cert);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_CERTIFICATE);
    }

    #[test]
    fn test_construct_finished() {
        let verify_data = vec![0xCCu8; 32];
        let result = construct_finished(&verify_data);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_FINISHED);
        assert_eq!(msg.len(), 1 + 3 + 32); // type + length + verify_data
    }

    #[test]
    fn test_write_record_header() {
        let header = write_record_header(CONTENT_TYPE_HANDSHAKE, INITIAL_RECORD_VERSION, 100);
        assert_eq!(header.len(), 5);
        assert_eq!(header[0], 0x16); // Handshake
        assert_eq!(header[1], 0x03);
        assert_eq!(header[2], 0x01);
        assert_eq!(u16::from_be_bytes([header[3], header[4]]), 100);
    }

    #[test]
    fn the_initial_record_version_is_the_one_boringssl_and_utls_send() {
        assert_eq!(INITIAL_RECORD_VERSION, [0x03, 0x01]);
        let header = write_record_header(CONTENT_TYPE_HANDSHAKE, INITIAL_RECORD_VERSION, 512);
        assert_eq!(&header[..3], &[0x16, 0x03, 0x01]);
    }

    /// A ClientHello, parsed back out of the bytes the builder produced.
    ///
    /// Everything below asserts against a re-parse rather than against a
    /// golden blob: the hello is permuted and GREASEd per connection, so a
    /// fixed expected buffer could only be produced by freezing the very
    /// randomness that is the point of the change.
    struct ParsedHello {
        cipher_suites: Vec<u16>,
        session_id: Vec<u8>,
        /// `(type, body)` in wire order.
        extensions: Vec<(u16, Vec<u8>)>,
    }

    impl ParsedHello {
        fn parse(hello: &[u8]) -> Self {
            assert_eq!(hello[0], 0x01, "ClientHello");
            let declared = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
            assert_eq!(declared, hello.len() - 4, "handshake length");

            let mut offset = 1 + 3 + 2 + 32;
            let session_id_len = hello[offset] as usize;
            offset += 1;
            let session_id = hello[offset..offset + session_id_len].to_vec();
            offset += session_id_len;

            let cipher_suites_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
            offset += 2;
            let cipher_suites = hello[offset..offset + cipher_suites_len]
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            offset += cipher_suites_len;

            let compression_len = hello[offset] as usize;
            assert_eq!(&hello[offset..offset + 1 + compression_len], &[0x01, 0x00]);
            offset += 1 + compression_len;

            let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
            offset += 2;
            let extensions_end = offset + extensions_len;
            assert_eq!(extensions_end, hello.len(), "extensions run to the end");

            let mut extensions = Vec::new();
            while offset < extensions_end {
                let extension_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
                let length = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
                offset += 4;
                extensions.push((extension_type, hello[offset..offset + length].to_vec()));
                offset += length;
            }
            assert_eq!(offset, extensions_end);

            Self {
                cipher_suites,
                session_id,
                extensions,
            }
        }

        fn body(&self, extension_type: u16) -> &[u8] {
            self.extensions
                .iter()
                .find(|(candidate, _)| *candidate == extension_type)
                .map(|(_, body)| body.as_slice())
                .unwrap_or_else(|| panic!("no extension 0x{extension_type:04x}"))
        }
    }

    const TEST_SEED: [u8; 5] = [0x00, 0x1f, 0x2c, 0x30, 0x4d];

    fn test_hello(profile: &HelloProfileData<'_>, seed: u64) -> (Vec<u8>, [u8; 32], GreaseValues) {
        let session_id = [0x5c_u8; 32];
        let grease = GreaseValues::from_seed(TEST_SEED);
        let exchange =
            ClientKeyExchange::generate(&profile.key_share_groups()).expect("key material");
        let key_shares: Vec<(NamedGroup, Vec<u8>)> = profile
            .key_share_groups()
            .into_iter()
            .map(|group| (group, exchange.share_bytes(group).expect("a share")))
            .collect();
        let session = HelloSession {
            client_random: &[0x11_u8; 32],
            session_id: &session_id,
            server_name: "www.example.com",
            alpn_protocols: CHROME_ALPN_PROTOCOLS,
            key_shares: &key_shares,
            grease,
            ech_grease: EchGreaseParams::new([0x7e_u8; 32], &mut rand::rng()),
            permutation_seed: seed,
        };
        (
            construct_client_hello(profile, &session).unwrap(),
            session_id,
            grease,
        )
    }

    /// Preserved from the previous, hand-written hello: the eight schemes and
    /// their order are still the ones Chrome sends. What changed is where they
    /// come from — a constant blob in the profile table rather than eight
    /// `extend_from_slice` calls inside the builder.
    #[test]
    fn test_client_hello_signature_algorithms_match_chrome_utls() {
        let (hello, _, _) = test_hello(&CHROME_133, 7);
        let extension = ParsedHello::parse(&hello).body(0x000d).to_vec();
        assert_eq!(u16::from_be_bytes([extension[0], extension[1]]), 16);
        assert_eq!(
            &extension[2..],
            &[
                0x04, 0x03, // ecdsa_secp256r1_sha256
                0x08, 0x04, // rsa_pss_rsae_sha256
                0x04, 0x01, // rsa_pkcs1_sha256
                0x05, 0x03, // ecdsa_secp384r1_sha384
                0x08, 0x05, // rsa_pss_rsae_sha384
                0x05, 0x01, // rsa_pkcs1_sha384
                0x08, 0x06, // rsa_pss_rsae_sha512
                0x06, 0x01, // rsa_pkcs1_sha512
            ]
        );
    }

    #[test]
    fn grease_lands_in_every_slot_chrome_greases() {
        let (hello, _, grease) = test_hello(&CHROME_133, 3);
        let parsed = ParsedHello::parse(&hello);

        assert_eq!(
            parsed.cipher_suites[0],
            grease.value(GreaseSlot::Cipher),
            "cipher_suites[0]"
        );

        let groups = parsed.body(0x000a);
        assert_eq!(
            u16::from_be_bytes([groups[2], groups[3]]),
            grease.value(GreaseSlot::Group),
            "supported_groups[0]"
        );

        let key_share = parsed.body(0x0033);
        assert_eq!(
            u16::from_be_bytes([key_share[2], key_share[3]]),
            grease.value(GreaseSlot::Group),
            "key_share[0] draws the *same* GREASE value as supported_groups: a \
             share for a group that was never advertised is a different animal"
        );
        assert_eq!(
            u16::from_be_bytes([key_share[4], key_share[5]]),
            1,
            "the GREASE key share is one byte, not zero-length"
        );

        let versions = parsed.body(0x002b);
        assert_eq!(
            u16::from_be_bytes([versions[1], versions[2]]),
            grease.value(GreaseSlot::Version),
            "supported_versions[0]"
        );

        let (first_type, first_body) = &parsed.extensions[0];
        let (last_type, last_body) = parsed.extensions.last().unwrap();
        assert_eq!(*first_type, grease.value(GreaseSlot::Extension1));
        assert!(first_body.is_empty(), "the first GREASE extension is empty");
        assert_eq!(*last_type, grease.value(GreaseSlot::Extension2));
        assert_eq!(
            last_body.as_slice(),
            &[0x00],
            "the last GREASE extension carries one zero byte"
        );
        assert_ne!(first_type, last_type);
        for value in [
            parsed.cipher_suites[0],
            *first_type,
            *last_type,
            grease.value(GreaseSlot::Group),
            grease.value(GreaseSlot::Version),
        ] {
            assert!(is_grease(value), "{value:#06x} is not a GREASE point");
        }
    }

    #[test]
    fn the_hello_carries_both_key_shares_at_their_draft_lengths() {
        let (hello, _, _) = test_hello(&CHROME_133, 11);
        let key_share = ParsedHello::parse(&hello).body(0x0033).to_vec();
        let list_len = u16::from_be_bytes([key_share[0], key_share[1]]) as usize;
        assert_eq!(list_len, key_share.len() - 2);

        let mut offset = 2;
        let mut seen = Vec::new();
        while offset < key_share.len() {
            let group = u16::from_be_bytes([key_share[offset], key_share[offset + 1]]);
            let length =
                u16::from_be_bytes([key_share[offset + 2], key_share[offset + 3]]) as usize;
            seen.push((group, length));
            offset += 4 + length;
        }
        assert_eq!(offset, key_share.len());
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[1], (NamedGroup::X25519MlKem768.id(), 1216));
        assert_eq!(seen[2], (NamedGroup::X25519.id(), 32));
    }

    #[test]
    fn the_hello_greases_ech_the_way_chrome_does() {
        // The extension everything else in this transport revolves around. A
        // parrot that omits it differs from real Chrome on exactly the field a
        // censor is most likely to be looking at.
        let (hello, _, _) = test_hello(&CHROME_133, 5);
        let body = ParsedHello::parse(&hello).body(0xfe0d).to_vec();
        assert_eq!(body[0], 0x00, "outer ECHClientHello");
        assert_eq!(u16::from_be_bytes([body[6], body[7]]) as usize, 32);
        assert_eq!(&body[8..40], &[0x7e_u8; 32]);
        let payload_len = u16::from_be_bytes([body[40], body[41]]) as usize;
        assert_eq!(body.len(), 42 + payload_len);
    }

    #[test]
    fn the_session_id_sits_at_the_constant_the_reality_aad_uses() {
        let (hello, session_id, _) = test_hello(&CHROME_133, 13);
        assert_eq!(HELLO_SESSION_ID_OFFSET, 39, "1 + 3 + 2 + 32 + 1");
        assert_eq!(
            &hello[HELLO_SESSION_ID_OFFSET..HELLO_SESSION_ID_OFFSET + HELLO_SESSION_ID_LEN],
            &session_id
        );
        assert_eq!(ParsedHello::parse(&hello).session_id, session_id);

        // And the guard itself refuses a hello whose window moved.
        let mut moved = hello.clone();
        moved[HELLO_SESSION_ID_OFFSET] ^= 0xff;
        assert!(assert_session_id_window(&moved, &session_id).is_err());
    }

    #[test]
    fn the_extension_order_is_permuted_but_the_set_is_not() {
        let mut orders = std::collections::HashSet::new();
        let mut sets = std::collections::HashSet::new();
        for seed in 0..32_u64 {
            let (hello, _, _) = test_hello(&CHROME_133, seed);
            let parsed = ParsedHello::parse(&hello);
            let types: Vec<u16> = parsed.extensions.iter().map(|(kind, _)| *kind).collect();
            let mut sorted = types.clone();
            sorted.sort_unstable();
            assert_eq!(
                sorted.len(),
                sorted
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                "no extension may be sent twice"
            );
            sets.insert(sorted);
            orders.insert(types);
        }
        assert_eq!(sets.len(), 1, "the same extensions every time");
        assert!(orders.len() > 1, "in more than one order");
    }

    #[test]
    fn chrome_131_moves_only_the_application_settings_code_point() {
        let (hello, _, _) = test_hello(&CHROME_131, 2);
        let parsed = ParsedHello::parse(&hello);
        assert_eq!(parsed.body(0x4469), &[0x00, 0x03, 0x02, b'h', b'2']);
        assert!(
            !parsed.extensions.iter().any(|(kind, _)| *kind == 0x44cd),
            "Chrome 131 does not send the new code point"
        );
    }

    #[test]
    fn a_session_missing_a_share_the_profile_names_is_refused() {
        let session_id = [0_u8; 32];
        let session = HelloSession {
            client_random: &[0_u8; 32],
            session_id: &session_id,
            server_name: "www.example.com",
            alpn_protocols: CHROME_ALPN_PROTOCOLS,
            key_shares: &[],
            grease: GreaseValues::from_seed(TEST_SEED),
            ech_grease: EchGreaseParams::new([0_u8; 32], &mut rand::rng()),
            permutation_seed: 0,
        };
        let error = construct_client_hello(&CHROME_133, &session)
            .expect_err("a profile naming a share the session did not generate must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
