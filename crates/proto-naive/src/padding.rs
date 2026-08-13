//! NaiveProxy payload padding, "Variant1".
//!
//! Specification (informal, by the protocol's author):
//!   <https://github.com/klzgrad/naiveproxy/blob/master/README.md#padding-protocol-an-informal-specification>
//! Reference implementation, transcribed field for field:
//!   `src/net/tools/naive/naive_padding_framer.cc`  (frame layout, read state
//!   machine, `frame_header_size() == 3`)
//!   `src/net/tools/naive/naive_padding_socket.cc`  (`kFirstPaddings == 8`,
//!   client-side `padding_size = RandIntInclusive(0, 255)`)
//!   `src/net/tools/naive/naive_protocol.h`         (`PaddingType::kVariant1`,
//!   wire format "1", header names)
//!
//! Wire layout of one padded frame:
//! ```text
//! struct PaddedFrame {
//!   uint8_t payload_size_high;  // payload_size / 256
//!   uint8_t payload_size_low;   // payload_size % 256
//!   uint8_t padding_size;
//!   uint8_t payload[payload_size];
//!   uint8_t zeros[padding_size];
//! };
//! ```
//!
//! Only the first [`FIRST_PADDINGS`] reads and the first [`FIRST_PADDINGS`]
//! writes of a stream are framed this way; everything after is raw. That
//! asymmetry is the whole point of the scheme (it flattens the length spikes of
//! the initial handshake) and it is also the easiest thing to get wrong in a
//! way that still "works": an unpadded stream talks to a Naive server perfectly
//! well, it just is not NaiveProxy any more.

use bytes::{BufMut, BytesMut};

/// Number of leading reads and writes that carry padding.
pub(crate) const FIRST_PADDINGS: u32 = 8;
/// `kMaxPaddingSize`.
pub(crate) const MAX_PADDING_SIZE: u8 = u8::MAX;
/// A single frame cannot describe more payload than a `uint16_t`.
pub(crate) const MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;
/// `payload_size_high`, `payload_size_low`, `padding_size`.
pub(crate) const FRAME_HEADER_SIZE: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    PayloadLengthHigh,
    PayloadLengthLow,
    PaddingLength,
    Payload,
    Padding,
}

/// Streaming encoder/decoder for the padded frame format.
///
/// Reads are a byte-at-a-time state machine because the transport is free to
/// split a frame across any number of DATA frames.
#[derive(Debug)]
pub(crate) struct PaddingFramer {
    max_read_frames: Option<u32>,
    state: ReadState,
    read_payload_length: usize,
    read_padding_length: usize,
    read_frames: u32,
    written_frames: u32,
}

impl PaddingFramer {
    pub(crate) fn new(max_read_frames: Option<u32>) -> Self {
        Self {
            max_read_frames,
            state: ReadState::PayloadLengthHigh,
            read_payload_length: 0,
            read_padding_length: 0,
            read_frames: 0,
            written_frames: 0,
        }
    }

    /// Test-only observability: the read path decides framing through
    /// [`Self::read_is_raw`], not through this counter.
    #[cfg(test)]
    pub(crate) fn read_frames(&self) -> u32 {
        self.read_frames
    }

    pub(crate) fn written_frames(&self) -> u32 {
        self.written_frames
    }

    /// True once every remaining inbound byte is raw payload, so the caller may
    /// read straight into its own buffer.
    pub(crate) fn read_is_raw(&self) -> bool {
        self.state == ReadState::PayloadLengthHigh
            && self
                .max_read_frames
                .is_some_and(|limit| self.read_frames >= limit)
    }

    /// Strip framing from `padded`, appending the recovered payload to `out`.
    ///
    /// Never allocates on a length the peer supplied: the payload is copied out
    /// of a slice the caller already owns, so a bogus 65535-byte length just
    /// makes the state machine wait for bytes that never come.
    pub(crate) fn read(&mut self, padded: &[u8], out: &mut BytesMut) {
        let mut rest = padded;
        while !rest.is_empty() {
            match self.state {
                ReadState::PayloadLengthHigh => {
                    if self.read_is_raw() {
                        out.put_slice(rest);
                        return;
                    }
                    self.read_payload_length = usize::from(rest[0]);
                    rest = &rest[1..];
                    self.state = ReadState::PayloadLengthLow;
                }
                ReadState::PayloadLengthLow => {
                    self.read_payload_length =
                        self.read_payload_length * 256 + usize::from(rest[0]);
                    rest = &rest[1..];
                    self.state = ReadState::PaddingLength;
                }
                ReadState::PaddingLength => {
                    self.read_padding_length = usize::from(rest[0]);
                    rest = &rest[1..];
                    self.state = ReadState::Payload;
                }
                ReadState::Payload => {
                    let take = self.read_payload_length.min(rest.len());
                    out.put_slice(&rest[..take]);
                    rest = &rest[take..];
                    self.read_payload_length -= take;
                    if self.read_payload_length == 0 {
                        self.state = ReadState::Padding;
                    }
                }
                ReadState::Padding => {
                    let take = self.read_padding_length.min(rest.len());
                    rest = &rest[take..];
                    self.read_padding_length -= take;
                    if self.read_padding_length == 0 {
                        self.read_frames = self.read_frames.saturating_add(1);
                        self.state = ReadState::PayloadLengthHigh;
                    }
                }
            }
        }
    }

    /// Frame up to [`MAX_PAYLOAD_SIZE`] bytes of `payload` into `out`.
    ///
    /// Returns how much of `payload` was consumed, so a caller with a larger
    /// buffer keeps the remainder for the next frame.
    pub(crate) fn write(&mut self, payload: &[u8], padding_size: u8, out: &mut BytesMut) -> usize {
        let take = payload.len().min(MAX_PAYLOAD_SIZE);
        let padding_size = usize::from(padding_size);
        out.reserve(FRAME_HEADER_SIZE + take + padding_size);
        out.put_u8((take / 256) as u8);
        out.put_u8((take % 256) as u8);
        out.put_u8(padding_size as u8);
        out.put_slice(&payload[..take]);
        out.put_bytes(0, padding_size);
        self.written_frames = self.written_frames.saturating_add(1);
        take
    }
}

/// The 17 ASCII symbols whose HPACK Huffman codes are at least 8 bits long, in
/// symbol order — i.e. the characters HPACK cannot shrink.
///
/// Transcribed from `net/tools/naive/padding_utils.cc::InitializeNonindexCodes`,
/// which walks `spdy::HpackHuffmanCodeVector()` and keeps the first 17 symbols
/// with `id in [0x20, 0x7f]` and `length >= 8`.
const NONINDEX_CODES: [u8; 17] = *b"!\"#$&'()*+,;<>?@X";

/// Fill `span` with a padding-header value that HPACK will neither compress nor
/// want to index.
///
/// The low 4 bits of `unique_bits` pick each of the first 16 bytes; anything
/// beyond that is the 17th symbol. Deterministic in `unique_bits`, which is what
/// makes the header testable byte for byte.
pub(crate) fn fill_nonindex_header_value(mut unique_bits: u64, span: &mut [u8]) {
    let first = span.len().min(16);
    for slot in span[..first].iter_mut() {
        *slot = NONINDEX_CODES[(unique_bits & 0b1111) as usize];
        unique_bits >>= 4;
    }
    for slot in span[first..].iter_mut() {
        *slot = NONINDEX_CODES[16];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_three_header_bytes_then_payload_then_zeros() {
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        assert_eq!(framer.write(b"hi", 4, &mut wire), 2);
        assert_eq!(wire.as_ref(), b"\x00\x02\x04hi\x00\x00\x00\x00");
        assert_eq!(framer.written_frames(), 1);
    }

    #[test]
    fn payload_length_is_big_endian_across_the_two_header_bytes() {
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        let payload = vec![0x5a_u8; 300];
        assert_eq!(framer.write(&payload, 0, &mut wire), 300);
        // 300 == 1 * 256 + 44
        assert_eq!(&wire[..3], &[0x01, 0x2c, 0x00]);
        assert_eq!(wire.len(), 3 + 300);
    }

    #[test]
    fn a_pure_padding_frame_carries_no_payload() {
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        assert_eq!(framer.write(b"", MAX_PADDING_SIZE, &mut wire), 0);
        assert_eq!(&wire[..3], &[0x00, 0x00, 0xff]);
        assert_eq!(wire.len(), 3 + 255);
        assert!(wire[3..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn one_frame_never_describes_more_than_65535_payload_bytes() {
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        let payload = vec![7_u8; MAX_PAYLOAD_SIZE + 100];
        assert_eq!(framer.write(&payload, 0, &mut wire), MAX_PAYLOAD_SIZE);
        assert_eq!(&wire[..3], &[0xff, 0xff, 0x00]);
    }

    #[test]
    fn a_frame_split_across_every_possible_boundary_still_decodes() {
        let mut writer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        writer.write(b"payload-bytes", 9, &mut wire);

        for chunk_size in 1..=wire.len() {
            let mut reader = PaddingFramer::new(Some(FIRST_PADDINGS));
            let mut decoded = BytesMut::new();
            for chunk in wire.chunks(chunk_size) {
                reader.read(chunk, &mut decoded);
            }
            assert_eq!(
                decoded.as_ref(),
                b"payload-bytes",
                "chunk size {chunk_size}"
            );
            assert_eq!(reader.read_frames(), 1);
        }
    }

    #[test]
    fn padding_bytes_never_reach_the_payload() {
        let mut writer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        writer.write(b"a", 200, &mut wire);
        writer.write(b"b", 0, &mut wire);

        let mut reader = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut decoded = BytesMut::new();
        reader.read(&wire, &mut decoded);
        assert_eq!(decoded.as_ref(), b"ab");
    }

    #[test]
    fn a_zero_padding_frame_is_only_counted_once_the_next_byte_arrives() {
        // Matches the reference framer exactly: its `while (padded_len > 0)`
        // loop cannot run the padding branch when the buffer ends flush with a
        // zero-length padding field, so the counter lags by one until more data
        // shows up. The lag is invisible because the branch runs before the
        // next frame header is parsed — but an implementation that "fixed" it
        // would start unframing one frame earlier than the peer stops framing.
        let mut writer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        writer.write(b"a", 0, &mut wire);

        let mut reader = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut decoded = BytesMut::new();
        reader.read(&wire, &mut decoded);
        assert_eq!(reader.read_frames(), 0);

        let mut more = BytesMut::new();
        writer.write(b"b", 0, &mut more);
        reader.read(&more, &mut decoded);
        assert_eq!(decoded.as_ref(), b"ab");
        assert_eq!(reader.read_frames(), 1);
    }

    #[test]
    fn framing_stops_after_the_eighth_frame_in_both_directions() {
        let mut writer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        for _ in 0..FIRST_PADDINGS {
            writer.write(b"x", 0, &mut wire);
        }
        assert_eq!(writer.written_frames(), FIRST_PADDINGS);
        // Frame nine would be raw on the wire; the reader must treat it so.
        wire.put_slice(b"RAW-TAIL");

        let mut reader = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut decoded = BytesMut::new();
        reader.read(&wire, &mut decoded);
        assert_eq!(decoded.as_ref(), b"xxxxxxxxRAW-TAIL");
        assert!(reader.read_is_raw());
    }

    #[test]
    fn a_reader_without_a_frame_limit_keeps_framing_forever() {
        let mut writer = PaddingFramer::new(None);
        let mut wire = BytesMut::new();
        for _ in 0..(FIRST_PADDINGS + 4) {
            writer.write(b"z", 1, &mut wire);
        }
        let mut reader = PaddingFramer::new(None);
        let mut decoded = BytesMut::new();
        reader.read(&wire, &mut decoded);
        assert_eq!(decoded.len() as u32, FIRST_PADDINGS + 4);
        assert!(!reader.read_is_raw());
    }

    #[test]
    fn a_padded_stream_is_not_byte_identical_to_a_plain_one() {
        // The regression this guards: an implementation that "works" against a
        // Naive server by simply not padding at all.
        let mut framer = PaddingFramer::new(Some(FIRST_PADDINGS));
        let mut wire = BytesMut::new();
        framer.write(b"GET / HTTP/1.1\r\n", 17, &mut wire);
        assert_ne!(wire.as_ref(), b"GET / HTTP/1.1\r\n");
        assert_eq!(wire.len(), FRAME_HEADER_SIZE + 16 + 17);
    }

    #[test]
    fn the_padding_header_value_uses_only_incompressible_symbols() {
        let mut value = [0_u8; 24];
        fill_nonindex_header_value(0x0123_4567_89ab_cdef, &mut value);
        // Low nibble first: f, e, d, c, b, a, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0.
        assert_eq!(&value[..16], b"@?><;,+*)('&$#\"!");
        // Everything past the 16 seeded bytes is the 17th symbol.
        assert_eq!(&value[16..], b"XXXXXXXX");
        assert!(value.iter().all(|byte| NONINDEX_CODES.contains(byte)));
    }

    #[test]
    fn a_short_padding_header_value_is_still_fully_seeded() {
        let mut value = [0_u8; 3];
        fill_nonindex_header_value(0x02, &mut value);
        assert_eq!(&value, b"#!!");
    }
}
