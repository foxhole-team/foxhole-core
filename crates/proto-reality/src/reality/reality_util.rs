use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

use super::reality_key_exchange::{
    ML_KEM_768_CIPHERTEXT_LEN, NamedGroup, ServerKeyShare, X25519_LEN,
    X25519MLKEM768_SERVER_SHARE_LEN,
};
use crate::buf_reader::BufReader;

/// Decodes a base64url-encoded public key
pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], std::io::Error> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid base64: {}", e),
        )
    })?;

    if decoded.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid public key length: {} (expected 32)", decoded.len()),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Decodes a hex-encoded short ID with zero-padding
///
/// Short IDs can be 0-16 hex characters (0-8 bytes).
/// If shorter than 16 characters, they are right-padded with zeros.
pub fn decode_short_id(hex: &str) -> Result<[u8; 8], std::io::Error> {
    if hex.len() > 16 || !hex.len().is_multiple_of(2) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Short ID must contain an even number of at most 16 hex characters",
        ));
    }

    // Right-pad with zeros to make 16 chars (compatible with other REALITY clients)
    let padded = format!("{:0<16}", hex);

    let mut short_id = [0u8; 8];
    decode_hex_to_slice(&padded, &mut short_id).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid hex: {}", e),
        )
    })?;

    Ok(short_id)
}

/// Decode hex string to byte slice
fn decode_hex_to_slice(hex: &str, output: &mut [u8]) -> Result<(), &'static str> {
    if hex.len() != output.len() * 2 {
        return Err("Invalid hex length");
    }

    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_value(chunk[0])?;
        let low = hex_char_to_value(chunk[1])?;
        output[i] = (high << 4) | low;
    }

    Ok(())
}

/// Convert hex character to its numeric value
fn hex_char_to_value(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("Invalid hex character"),
    }
}

/// Extracts ClientRandom from ClientHello
///
/// ClientHello structure (simplified):
/// - TLS Header: 5 bytes
/// - Handshake Type: 1 byte
/// - Length: 3 bytes
/// - Protocol Version: 2 bytes
/// - ClientRandom: 32 bytes (starts at offset 11)
#[cfg(test)]
pub fn extract_client_random(client_hello: &[u8]) -> Result<[u8; 32], std::io::Error> {
    const TLS_HEADER_LEN: usize = 5;
    const HANDSHAKE_HEADER_LEN: usize = 4; // type(1) + length(3)
    const PROTOCOL_VERSION_LEN: usize = 2;
    const RANDOM_OFFSET: usize = TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN + PROTOCOL_VERSION_LEN;

    if client_hello.len() < RANDOM_OFFSET + 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello too short to extract random",
        ));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[RANDOM_OFFSET..RANDOM_OFFSET + 32]);
    Ok(random)
}

/// TLS extension code points read out of a ServerHello.
pub const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXTENSION_KEY_SHARE: u16 = 0x0033;

/// Position a `BufReader` at a ServerHello's extension block.
///
/// `server_hello` is the handshake message — type, 24-bit length, body — with
/// the record header already stripped.
fn seek_extensions(server_hello: &[u8]) -> Result<(BufReader<'_>, usize), std::io::Error> {
    let mut reader = BufReader::new(server_hello);

    let _handshake_type = reader.read_u8()?;
    let _handshake_len = reader.read_u24_be()?;
    let _legacy_version = reader.read_u16_be()?;
    reader.skip(32)?; // random
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;
    reader.skip(2)?; // cipher suite
    reader.skip(1)?; // legacy_compression_method

    let extensions_len = reader.read_u16_be()? as usize;
    let extensions_end = reader.position() + extensions_len;
    Ok((reader, extensions_end))
}

/// The body of one ServerHello extension, or `None` when the server did not
/// send it.
pub fn server_hello_extension(
    server_hello: &[u8],
    wanted: u16,
) -> Result<Option<&[u8]>, std::io::Error> {
    let (mut reader, extensions_end) = seek_extensions(server_hello)?;
    while reader.position() < extensions_end {
        let ext_type = reader.read_u16_be()?;
        let ext_len = reader.read_u16_be()? as usize;
        if ext_type == wanted {
            return Ok(Some(reader.read_slice(ext_len)?));
        }
        reader.skip(ext_len)?;
    }
    Ok(None)
}

/// The group the server selected, straight out of its `key_share` extension.
///
/// Separate from [`extract_server_key_share`] because refusing an unexecutable
/// group and failing to parse a share of a group we do execute are two
/// different answers, and the caller says so with two different messages.
pub fn extract_server_selected_group(server_hello: &[u8]) -> Result<u16, std::io::Error> {
    let data = server_hello_extension(server_hello, EXTENSION_KEY_SHARE)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "REALITY ServerHello carries no key_share extension",
        )
    })?;
    BufReader::new(data).read_u16_be()
}

/// The TLS version the server negotiated, from `supported_versions`.
///
/// `None` means the extension is absent, which in TLS 1.3 means the server
/// answered with something older.
pub fn extract_server_selected_version(server_hello: &[u8]) -> Result<Option<u16>, std::io::Error> {
    match server_hello_extension(server_hello, EXTENSION_SUPPORTED_VERSIONS)? {
        Some(data) => BufReader::new(data).read_u16_be().map(Some),
        None => Ok(None),
    }
}

/// Extract the server's key share from a ServerHello handshake message.
pub fn extract_server_key_share(server_hello: &[u8]) -> Result<ServerKeyShare, std::io::Error> {
    let data = server_hello_extension(server_hello, EXTENSION_KEY_SHARE)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "REALITY ServerHello carries no key_share extension",
        )
    })?;
    parse_server_keyshare_extension(data)
}

/// Parse the ServerHello `key_share` body into the group the server chose.
///
/// This used to return a bare `[u8; 32]`, which could only ever describe
/// `x25519`: every other group came back as "X25519 key share not found",
/// which is a parse error for what is really a negotiation outcome.
///
/// Layout: group (2), key_exchange length (2), key_exchange.
fn parse_server_keyshare_extension(data: &[u8]) -> Result<ServerKeyShare, std::io::Error> {
    let mut reader = BufReader::new(data);
    let group = reader.read_u16_be()?;
    let key_len = reader.read_u16_be()? as usize;

    let invalid = |message: String| std::io::Error::new(std::io::ErrorKind::InvalidData, message);

    match NamedGroup::from_id(group) {
        Some(NamedGroup::X25519) => {
            if key_len != X25519_LEN {
                return Err(invalid(format!(
                    "REALITY ServerHello x25519 key share is {key_len} bytes, expected {X25519_LEN}"
                )));
            }
            let mut key = [0_u8; X25519_LEN];
            key.copy_from_slice(reader.read_slice(X25519_LEN)?);
            Ok(ServerKeyShare::X25519(key))
        }
        Some(NamedGroup::X25519MlKem768) => {
            // draft-ietf-tls-ecdhe-mlkem §3.1: ciphertext first, X25519 second.
            if key_len != X25519MLKEM768_SERVER_SHARE_LEN {
                return Err(invalid(format!(
                    "REALITY ServerHello X25519MLKEM768 key share is {key_len} bytes, expected \
                     {X25519MLKEM768_SERVER_SHARE_LEN}"
                )));
            }
            let bytes = reader.read_slice(X25519MLKEM768_SERVER_SHARE_LEN)?;
            let mut ml_kem_ciphertext = Box::new([0_u8; ML_KEM_768_CIPHERTEXT_LEN]);
            ml_kem_ciphertext.copy_from_slice(&bytes[..ML_KEM_768_CIPHERTEXT_LEN]);
            let mut x25519 = [0_u8; X25519_LEN];
            x25519.copy_from_slice(&bytes[ML_KEM_768_CIPHERTEXT_LEN..]);
            Ok(ServerKeyShare::X25519MlKem768 {
                ml_kem_ciphertext,
                x25519,
            })
        }
        Some(other) => Err(invalid(format!(
            "REALITY ServerHello selected {}, which this build names but does not execute",
            other.name()
        ))),
        None => Err(invalid(format!(
            "REALITY ServerHello selected unknown key exchange group 0x{group:04x}"
        ))),
    }
}

/// Extract the cipher suite selected by the server from a ServerHello handshake
/// message. ServerHello carries exactly one.
pub fn extract_server_cipher_suite(server_hello: &[u8]) -> Result<u16, std::io::Error> {
    let mut reader = BufReader::new(server_hello);

    let _handshake_type = reader.read_u8()?;
    let _handshake_len = reader.read_u24_be()?;
    let _legacy_version = reader.read_u16_be()?;
    reader.skip(32)?; // random
    let session_id_len = reader.read_u8()? as usize;
    reader.skip(session_id_len)?;

    reader.read_u16_be()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_short_id() {
        // Full 16-char hex
        let short_id = decode_short_id("0123456789abcdef").unwrap();
        assert_eq!(short_id, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        // Partial hex (should be zero-padded on right)
        let short_id2 = decode_short_id("abcdef").unwrap();
        assert_eq!(short_id2, [0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Empty (all zeros)
        let short_id3 = decode_short_id("").unwrap();
        assert_eq!(short_id3, [0; 8]);

        // Too long should error
        let result = decode_short_id("0123456789abcdef0");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_client_random() {
        // Create a minimal ClientHello with random
        let mut client_hello = vec![0u8; 100];

        // TLS Header
        client_hello[0] = 0x16; // Handshake
        client_hello[1] = 0x03; // Version major
        client_hello[2] = 0x03; // Version minor (TLS 1.2)

        // Handshake header
        client_hello[5] = 0x01; // ClientHello type

        // Protocol version in handshake
        client_hello[9] = 0x03; // Major
        client_hello[10] = 0x03; // Minor

        // ClientRandom starts at offset 11
        for i in 0..32 {
            client_hello[11 + i] = (i + 1) as u8;
        }

        let random = extract_client_random(&client_hello).unwrap();
        for (index, byte) in random.iter().enumerate() {
            assert_eq!(*byte, (index + 1) as u8);
        }
    }

    #[test]
    fn test_decode_public_key() {
        use base64::engine::{Engine as _, general_purpose::URL_SAFE_NO_PAD};

        // Valid 32-byte key
        let key_bytes = [0x42u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(key_bytes);
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(decoded, key_bytes);

        // Invalid length
        let short_key = [0x42u8; 16];
        let encoded_short = URL_SAFE_NO_PAD.encode(short_key);
        assert!(decode_public_key(&encoded_short).is_err());

        // Invalid base64
        assert!(decode_public_key("not-valid-base64!!!").is_err());
    }
}
