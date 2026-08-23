use std::io::{self, Error, ErrorKind};

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub const ALERT_LEVEL_WARNING: u8 = 0x01;
pub const ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

pub const VERSION_TLS_1_2_MAJOR: u8 = 0x03;
pub const VERSION_TLS_1_2_MINOR: u8 = 0x03;

pub const VERSION_TLS_1_0_MAJOR: u8 = 0x03;
pub const VERSION_TLS_1_0_MINOR: u8 = 0x01;

/// Offset of `legacy_session_id` in a hello handshake message (record excluded).
/// Shared by the hello builder and REALITY AAD; construction asserts this layout.
pub const HELLO_SESSION_ID_OFFSET: usize = 1 + 3 + 2 + 32 + 1;

/// REALITY always sends a 32-byte session id: 16 bytes of encrypted metadata
/// plus 16 bytes of tag.
pub const HELLO_SESSION_ID_LEN: usize = 32;

#[cfg(any(test, feature = "testkit"))]
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
/// RFC 8879 `compressed_certificate`. The hello offers `compress_certificate`
/// because Chrome does; this client cannot decompress one, so the type exists
/// here only to be refused by name.
pub const HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE: u8 = 25;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;

// RFC 8446 limits TLS 1.3 ciphertext to 2^14 bytes plus 256 bytes overhead.

/// Maximum TLS 1.3 ciphertext payload size (16,640 bytes)
pub const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 256;

/// RFC 8446 §5.1 maximum plaintext payload for one TLS 1.3 record.
pub const MAX_TLS_PLAINTEXT_LEN: usize = 16384;

/// TLS record header size (ContentType + ProtocolVersion + Length)
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum TLS record size (ciphertext + header)
pub const TLS_MAX_RECORD_SIZE: usize = MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

/// Buffer capacity for ciphertext read (2x TLS max record for safety)
pub const CIPHERTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Buffer capacity for plaintext read
pub const PLAINTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Combined limit for queued plaintext and ciphertext (matches rustls DEFAULT_BUFFER_LIMIT)
pub const OUTGOING_BUFFER_LIMIT: usize = 64 * 1024;

/// Return the TLS 1.3 content type and unpadded length without allocation.
#[inline]
#[cfg(test)]
pub fn strip_content_type_slice(plaintext: &[u8]) -> io::Result<(u8, usize)> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    let content_type = plaintext[plaintext.len() - 1];

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok((content_type, plaintext.len() - 1))
}

/// Remove this implementation's unpadded TLS 1.3 content-type trailer.
#[cfg(test)]
pub fn strip_content_type(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    let (content_type, valid_len) = strip_content_type_slice(plaintext)?;
    plaintext.truncate(valid_len);
    Ok(content_type)
}

/// Remove RFC 8446 §5.4 padding and the TLS 1.3 content-type trailer.
pub fn strip_content_type_with_padding(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    while plaintext.last() == Some(&0) {
        plaintext.pop();
    }

    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"));
    }

    let content_type = plaintext
        .pop()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"))?;

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok(content_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_content_type_app_data() {
        let mut plaintext = vec![0x01, 0x02, 0x03, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_strip_content_type_handshake() {
        let mut plaintext = vec![0xAA, 0xBB, CONTENT_TYPE_HANDSHAKE];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(plaintext, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_strip_content_type_alert() {
        let mut plaintext = vec![0x01, 0x00, CONTENT_TYPE_ALERT];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_ALERT);
        assert_eq!(plaintext, vec![0x01, 0x00]);
    }

    #[test]
    fn test_strip_content_type_preserves_zeros() {
        // Trailing zeros in data should be preserved (not treated as padding)
        let mut plaintext = vec![0x01, 0x00, 0x00, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_strip_content_type_empty() {
        let mut plaintext = Vec::new();
        assert!(strip_content_type(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_content_type_invalid() {
        let mut plaintext = vec![0x01, 0xFF]; // 0xFF is invalid
        assert!(strip_content_type(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_no_padding() {
        let mut plaintext = vec![0x01, 0x02, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02]);
    }

    #[test]
    fn test_strip_with_padding_strips_zeros() {
        // TLS 1.3 format: content || type || padding
        let mut plaintext = vec![0x01, 0x02, CONTENT_TYPE_HANDSHAKE, 0x00, 0x00, 0x00];
        let ct = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(plaintext, vec![0x01, 0x02]);
    }

    #[test]
    fn test_strip_with_padding_empty() {
        let mut plaintext = Vec::new();
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_all_zeros() {
        let mut plaintext = vec![0x00, 0x00, 0x00];
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_invalid_type() {
        let mut plaintext = vec![0x01, 0xFF, 0x00]; // 0xFF with padding
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }
}
