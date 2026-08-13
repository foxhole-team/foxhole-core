//! The response-head parser, opened to the fuzz harness in `fuzz/`.
//!
//! Compiled only under the `fuzzing` feature, which nothing in the workspace
//! enables. `parse_response` is the crate's whole attacker-facing surface — an
//! adversarial proxy controls every byte it sees — and it is `pub(crate)` so
//! that no caller can bypass the buffering limits the parser enforces. Keeping
//! it unreachable from a fuzz target would mean fuzzing nothing at all.

use crate::error::HttpProxyError;

/// Hard cap on buffered response headers.
pub const MAX_HEADER_BYTES: usize = crate::codec::MAX_HEADER_BYTES;
/// Hard cap on header field count.
pub const MAX_HEADER_FIELDS: usize = crate::codec::MAX_HEADER_FIELDS;
/// The blank line that ends a response head.
pub const HEADER_END: &[u8; 4] = b"\r\n\r\n";

/// Try to parse a complete response head out of `buffer`, yielding
/// `(status, header_len)`.
///
/// `Ok(None)` means "no `CRLFCRLF` yet, read more". The tuple is flattened
/// rather than exposing `ConnectResponse`, which stays crate-private.
pub fn parse_response(buffer: &[u8]) -> Result<Option<(u16, usize)>, HttpProxyError> {
    crate::codec::parse_response(buffer)
        .map(|parsed| parsed.map(|response| (response.status, response.header_len)))
}
