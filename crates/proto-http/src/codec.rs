//! RFC 9110 §9.3.6 / RFC 9112 CONNECT request builder and bounded response
//! parser.
//!
//! The parser is sans-io on purpose: an adversarial proxy controls the response
//! byte stream, so the exact "how many bytes may I buffer" question is decided
//! here and tested here, not inside an async read loop.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::{BufMut, BytesMut};
use foxcore_api::{Destination, SecretString};

use crate::error::HttpProxyError;

/// Hard cap on buffered response headers. A proxy that needs more than this is
/// either broken or trying to make us allocate.
pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Hard cap on header field count, so a flood of 2-byte lines is bounded too.
pub(crate) const MAX_HEADER_FIELDS: usize = 128;

const CRLF: &[u8; 2] = b"\r\n";
const HEADER_END: &[u8; 4] = b"\r\n\r\n";

/// Build the whole `CONNECT` request, including the terminating blank line.
///
/// The returned buffer may hold the `Proxy-Authorization` credentials; the
/// caller is expected to clear it after the write.
pub(crate) fn encode_connect(
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    headers: &BTreeMap<String, SecretString>,
) -> Result<BytesMut, HttpProxyError> {
    let authority = destination.authority();
    // A hostname carrying CR/LF would forge extra request lines.
    check_field_value(&authority, "the CONNECT authority")?;

    let mut out = BytesMut::with_capacity(128 + authority.len());
    out.put_slice(b"CONNECT ");
    out.put_slice(authority.as_bytes());
    out.put_slice(b" HTTP/1.1");
    out.put_slice(CRLF);
    out.put_slice(b"Host: ");
    out.put_slice(authority.as_bytes());
    out.put_slice(CRLF);

    if let Some((username, password)) = credentials {
        // RFC 7617: the userid must not contain a colon, otherwise the split on
        // the server side lands in the wrong place.
        if username.contains(':') {
            return Err(HttpProxyError::IllegalHeader("the proxy username"));
        }
        check_field_value(username, "the proxy username")?;
        check_field_value(password, "the proxy password")?;
        // Base64 is not encryption: both the plaintext pair and its encoding
        // are scrubbed here so neither survives in a freed allocation.
        let mut plain = BytesMut::with_capacity(username.len() + 1 + password.len());
        plain.put_slice(username.as_bytes());
        plain.put_u8(b':');
        plain.put_slice(password.as_bytes());
        let mut encoded = BytesMut::zeroed(plain.len().div_ceil(3) * 4);
        let written = STANDARD
            .encode_slice(&plain[..], &mut encoded)
            .map_err(|_| HttpProxyError::Malformed("proxy credentials could not be encoded"))?;
        plain.fill(0);
        out.put_slice(b"Proxy-Authorization: Basic ");
        out.put_slice(&encoded[..written]);
        out.put_slice(CRLF);
        encoded.fill(0);
    }

    for (name, value) in headers {
        check_field_name(name)?;
        check_field_value(value.expose(), "a custom header value")?;
        out.put_slice(name.as_bytes());
        out.put_slice(b": ");
        out.put_slice(value.expose().as_bytes());
        out.put_slice(CRLF);
    }

    out.put_slice(CRLF);
    Ok(out)
}

fn check_field_name(name: &str) -> Result<(), HttpProxyError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b":\r\n".contains(&byte))
    {
        return Err(HttpProxyError::IllegalHeader("a custom header name"));
    }
    Ok(())
}

fn check_field_value(value: &str, what: &'static str) -> Result<(), HttpProxyError> {
    if value.is_empty() || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(HttpProxyError::IllegalHeader(what));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectResponse {
    pub(crate) status: u16,
    /// Bytes consumed by the status line and headers, including the blank line.
    pub(crate) header_len: usize,
}

/// Try to parse a complete response head out of `buffer`.
///
/// `Ok(None)` means "no `CRLFCRLF` yet, read more"; the caller enforces
/// [`MAX_HEADER_BYTES`] so this can never loop forever.
pub(crate) fn parse_response(buffer: &[u8]) -> Result<Option<ConnectResponse>, HttpProxyError> {
    let Some(end) = find_header_end(buffer) else {
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(HttpProxyError::HeadersTooLarge(MAX_HEADER_BYTES));
        }
        return Ok(None);
    };
    let head = &buffer[..end];
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines
        .next()
        .ok_or(HttpProxyError::Malformed("missing status line"))?;
    let status = parse_status_line(status_line)?;

    let mut fields = 0_usize;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        fields += 1;
        if fields > MAX_HEADER_FIELDS {
            return Err(HttpProxyError::TooManyHeaders(MAX_HEADER_FIELDS));
        }
        // A continuation line (obs-fold) is deprecated and ambiguous; anything
        // else must look like `name: value`.
        if !line[0].is_ascii_whitespace() && !line.contains(&b':') {
            return Err(HttpProxyError::Malformed("header field without a colon"));
        }
    }

    Ok(Some(ConnectResponse {
        status,
        header_len: end + HEADER_END.len(),
    }))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(HEADER_END.len())
        .position(|window| window == HEADER_END)
}

fn parse_status_line(line: &[u8]) -> Result<u16, HttpProxyError> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let version = line
        .get(..8)
        .ok_or(HttpProxyError::Malformed("truncated status line"))?;
    if !version.starts_with(b"HTTP/1.") || !version[7].is_ascii_digit() {
        return Err(HttpProxyError::Malformed("unsupported HTTP version"));
    }
    if line.get(8) != Some(&b' ') {
        return Err(HttpProxyError::Malformed("malformed status line"));
    }
    let digits = line
        .get(9..12)
        .ok_or(HttpProxyError::Malformed("truncated status code"))?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(HttpProxyError::Malformed("non-numeric status code"));
    }
    // The reason phrase is optional, but if present it must be separated.
    if !matches!(line.get(12), None | Some(b' ')) {
        return Err(HttpProxyError::Malformed("malformed status code"));
    }
    Ok(u16::from(digits[0] - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_is_byte_exact() {
        let request = encode_connect(
            &Destination::new("example.com", 443),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            request.as_ref(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
    }

    #[test]
    fn ipv6_destinations_are_bracketed_in_the_request_line_and_host() {
        let request = encode_connect(
            &Destination::new("2001:db8::1", 443),
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            request.as_ref(),
            b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"
        );
    }

    #[test]
    fn basic_credentials_are_base64_encoded_once() {
        let request = encode_connect(
            &Destination::new("example.com", 443),
            Some(("fox", "hole")),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            request.as_ref(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
              Proxy-Authorization: Basic Zm94OmhvbGU=\r\n\r\n"
        );
    }

    #[test]
    fn custom_headers_are_appended_in_a_stable_order() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Beta".to_owned(), SecretString::new("2"));
        headers.insert("X-Alpha".to_owned(), SecretString::new("1"));
        let request = encode_connect(&Destination::new("h.example", 80), None, &headers).unwrap();
        assert_eq!(
            request.as_ref(),
            b"CONNECT h.example:80 HTTP/1.1\r\nHost: h.example:80\r\n\
              X-Alpha: 1\r\nX-Beta: 2\r\n\r\n"
        );
    }

    #[test]
    fn header_injection_is_refused_everywhere_it_could_enter() {
        assert!(matches!(
            encode_connect(
                &Destination::new("evil\r\nX-Injected: 1", 443),
                None,
                &BTreeMap::new()
            ),
            Err(HttpProxyError::IllegalHeader(_))
        ));
        assert!(matches!(
            encode_connect(
                &Destination::new("h.example", 80),
                Some(("fox", "hole\r\nX: 1")),
                &BTreeMap::new()
            ),
            Err(HttpProxyError::IllegalHeader(_))
        ));
        assert!(matches!(
            encode_connect(
                &Destination::new("h.example", 80),
                Some(("fo:x", "hole")),
                &BTreeMap::new()
            ),
            Err(HttpProxyError::IllegalHeader(_))
        ));
        let mut headers = BTreeMap::new();
        headers.insert("X-Bad\r\nY".to_owned(), SecretString::new("1"));
        assert!(matches!(
            encode_connect(&Destination::new("h.example", 80), None, &headers),
            Err(HttpProxyError::IllegalHeader(_))
        ));
    }

    #[test]
    fn a_complete_2xx_head_reports_its_own_length() {
        let raw = b"HTTP/1.1 200 Connection established\r\nProxy-Agent: t\r\n\r\n";
        let parsed = parse_response(raw).unwrap().unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.header_len, raw.len());
    }

    #[test]
    fn a_status_line_without_a_reason_phrase_still_parses() {
        let parsed = parse_response(b"HTTP/1.0 201\r\n\r\n").unwrap().unwrap();
        assert_eq!(parsed.status, 201);
    }

    #[test]
    fn incomplete_headers_ask_for_more_bytes_instead_of_guessing() {
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\n").unwrap(), None);
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nX: 1\r\n").unwrap(),
            None
        );
    }

    #[test]
    fn oversized_headers_fail_before_the_buffer_can_grow_further() {
        let flood = vec![b'x'; MAX_HEADER_BYTES + 1];
        assert!(matches!(
            parse_response(&flood),
            Err(HttpProxyError::HeadersTooLarge(_))
        ));
    }

    #[test]
    fn a_header_field_flood_is_bounded_by_count_too() {
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        for index in 0..=MAX_HEADER_FIELDS {
            raw.extend_from_slice(format!("X{index}: 1\r\n").as_bytes());
        }
        raw.extend_from_slice(CRLF);
        assert!(matches!(
            parse_response(&raw),
            Err(HttpProxyError::TooManyHeaders(_))
        ));
    }

    #[test]
    fn malformed_status_lines_are_rejected() {
        for raw in [
            b"ICY 200 OK\r\n\r\n".as_slice(),
            b"HTTP/2.0 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 20 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 2xx OK\r\n\r\n".as_slice(),
            b"HTTP/1.1200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 200OK\r\n\r\n".as_slice(),
        ] {
            assert!(
                matches!(parse_response(raw), Err(HttpProxyError::Malformed(_))),
                "expected {raw:?} to be rejected"
            );
        }
    }

    #[test]
    fn a_header_line_without_a_colon_is_rejected() {
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nnonsense\r\n\r\n"),
            Err(HttpProxyError::Malformed(_))
        ));
    }
}
