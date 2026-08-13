//! QUIC variable-length integers (RFC 9000 §16).
//!
//! Hysteria2 frames every length/id with these. The server decodes them in
//! `read_quic_varint` / `parse_quic_varint_bytes`; this is the encode/decode pair the
//! client uses so the two stay bit-identical.

use crate::{CodecError, Result};

/// Largest value a QUIC varint can hold (2^62 − 1).
pub const MAX: u64 = (1 << 62) - 1;

/// Number of bytes `value` will occupy once encoded.
pub fn encoded_len(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Append `value` to `out` as a QUIC varint. Values above [`MAX`] are clamped in debug.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    debug_assert!(value <= MAX, "varint out of range: {value}");
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        out.push((0b01 << 6) | (value >> 8) as u8);
        out.push(value as u8);
    } else if value < (1 << 30) {
        out.push((0b10 << 6) | (value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push((0b11 << 6) | (value >> 56) as u8);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}

/// Decode a QUIC varint from `buf` at `*pos`, advancing `*pos` past it.
pub fn decode(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let first = *buf.get(*pos).ok_or(CodecError::Truncated)?;
    let len = 1usize << (first >> 6); // 1, 2, 4 or 8
    if buf.len() < *pos + len {
        return Err(CodecError::Truncated);
    }
    let mut value = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | buf[*pos + i] as u64;
    }
    *pos += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_across_length_classes() {
        for v in [
            0u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX,
        ] {
            let mut buf = Vec::new();
            encode(v, &mut buf);
            assert_eq!(buf.len(), encoded_len(v), "len mismatch for {v}");
            let mut pos = 0;
            assert_eq!(decode(&buf, &mut pos).unwrap(), v);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn hysteria2_request_frame_id_encodes_to_server_bytes() {
        // Server: HYSTERIA2_TCP_REQUEST_FRAME_BYTES = [0x44, 0x01] for value 0x401.
        let mut buf = Vec::new();
        encode(0x401, &mut buf);
        assert_eq!(buf, [0x44, 0x01]);
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        assert_eq!(decode(&[], &mut 0).unwrap_err(), CodecError::Truncated);
        // A 4-byte class header with only 2 bytes present.
        assert_eq!(
            decode(&[0x80, 0x00], &mut 0).unwrap_err(),
            CodecError::Truncated
        );
    }
}
