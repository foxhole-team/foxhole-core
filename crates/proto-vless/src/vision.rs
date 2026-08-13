//! XTLS-Vision framing (client side).
//!
//! Vision is not an encryption layer. It does two things:
//!
//! 1. **Pads the opening writes** so the *inner* TLS handshake loses its length
//!    signature — a VLESS header followed by a 517-byte ClientHello is otherwise
//!    a fingerprint on its own.
//! 2. **Gets out of the way** once the inner connection reaches application
//!    data. From that point the inner TLS records are already ciphertext, so
//!    both peers stop wrapping them in the outer record layer and write them
//!    straight onto the socket. This is the "direct copy" switch, and it is the
//!    reason Vision cannot be implemented as a plain stream filter.
//!
//! Padded frame on the wire:
//! ```text
//!   [uuid(16) — only on the first frame a side emits]
//!   command(1) | contentLen(2 BE) | paddingLen(2 BE) | content | padding
//! ```
//!
//! The handover is command-driven, not inference-driven: a peer switches to raw
//! copy only after it has *seen* [`COMMAND_PADDING_DIRECT`], never because it
//! decided on its own that the inner stream looked spliceable. That is what lets
//! the two sides disagree about the TLS sniffing heuristics below without
//! desynchronising the stream.
//!
//! Wire behaviour is a native port of Xray-core's `proxy/proxy.go`
//! (`XtlsPadding` / `XtlsUnpadding` / `XtlsFilterTls` / `ReshapeMultiBuffer`),
//! with one deliberate deviation: a padding command outside the known set is an
//! error here, where the reference logs it and keeps reading. A desynchronised
//! padded stream cannot be recovered by guessing.

use std::io;
use std::time::Duration;

use foxcore_transport::InnerCodec;

/// The only flow value FoxCore emits; `-udp443` is a client-local flag upstream
/// and never reaches the wire.
pub const XRV: &str = "xtls-rprx-vision";

pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub const COMMAND_PADDING_END: u8 = 0x01;
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// Header size once the write-once UUID has been emitted.
pub const PADDING_HEADER_LEN: usize = 5;
/// Header size of the very first frame (UUID + header).
pub const FIRST_PADDING_HEADER_LEN: usize = 16 + PADDING_HEADER_LEN;

/// Reference buffer size (`buf.Size`). Frame shaping is defined against it, so
/// it is part of the wire contract rather than a local tuning knob.
const BUF_SIZE: usize = 8192;
/// Worst-case frame overhead: UUID plus header.
const FRAME_OVERHEAD: usize = FIRST_PADDING_HEADER_LEN;
/// Content below this length gets the long padding profile.
const LONG_PADDING_THRESHOLD: usize = 900;
/// Long padding is `rand(SPREAD) + BASE - contentLen`.
const LONG_PADDING_SPREAD: u32 = 500;
const LONG_PADDING_BASE: usize = 900;
/// Short padding is `rand(SPREAD)`.
const SHORT_PADDING_SPREAD: u32 = 256;
/// How many buffers to sniff for the inner handshake before giving up.
const FILTER_BUDGET: i32 = 8;
/// How long to wait for the application's first byte before emitting a padding
/// frame with no content, so the VLESS header does not travel alone.
const FIRST_WRITE_DELAY: Duration = Duration::from_millis(500);

const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
/// `supported_versions` extension carrying exactly TLS 1.3.
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// TLS 1.3 suites. `TLS_AES_128_CCM_8_SHA256` is excluded from the handover on
/// purpose — its 8-byte tag is what the reference refuses to splice.
const TLS13_CIPHER_SUITES: [u16; 4] = [0x1301, 0x1302, 0x1303, 0x1304];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingFrame {
    pub command: u8,
    /// Offset of the payload inside the parsed buffer.
    pub content_start: usize,
    pub content_len: usize,
    /// Total bytes consumed by this frame (header + content + padding).
    pub consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisionError {
    /// The first inbound frame did not start with the expected user UUID.
    UuidMismatch,
    /// A frame carried a command byte outside the known set.
    UnknownCommand(u8),
}

impl std::fmt::Display for VisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UuidMismatch => f.write_str("vision padding did not start with the user UUID"),
            Self::UnknownCommand(command) => {
                write!(f, "unknown vision padding command {command:#04x}")
            }
        }
    }
}

impl std::error::Error for VisionError {}

impl From<VisionError> for io::Error {
    fn from(error: VisionError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

/// Where padding lengths come from.
///
/// Padding is random on the wire; golden vectors pin the draw so the encoder can
/// be compared byte for byte against the reference formula.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingDraw {
    Random,
    Fixed(u32),
}

impl PaddingDraw {
    fn below(self, bound: u32) -> u32 {
        match self {
            Self::Fixed(value) => value % bound,
            Self::Random => {
                let mut bytes = [0_u8; 4];
                // A failed OS RNG must not stall the connection, and padding is
                // camouflage rather than a secret: fall back to no padding.
                if getrandom::fill(&mut bytes).is_err() {
                    return 0;
                }
                u32::from_be_bytes(bytes) % bound
            }
        }
    }
}

/// Encode one padded frame. `uuid` is `Some` only for the first frame a side emits.
pub fn encode_padding_frame(
    uuid: Option<&[u8; 16]>,
    command: u8,
    content: &[u8],
    padding_len: usize,
    out: &mut Vec<u8>,
) {
    debug_assert!(content.len() <= u16::MAX as usize);
    debug_assert!(padding_len <= u16::MAX as usize);
    if let Some(uuid) = uuid {
        out.extend_from_slice(uuid);
    }
    out.push(command);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    // Padding content is filler the peer discards; zeros keep it allocation-free.
    out.resize(out.len() + padding_len, 0);
}

/// Parse one padded frame from `buf`. `expect_uuid` is `Some` while the reader
/// has not yet located the write-once UUID that opens the padded region.
/// Returns `Ok(None)` when the frame has not fully arrived yet.
pub fn parse_padding_frame(
    buf: &[u8],
    expect_uuid: Option<&[u8; 16]>,
) -> Result<Option<PaddingFrame>, VisionError> {
    let mut offset = 0;
    if let Some(expected) = expect_uuid {
        if buf.len() < 16 {
            return Ok(None);
        }
        if buf[..16] != expected[..] {
            return Err(VisionError::UuidMismatch);
        }
        offset = 16;
    }
    if buf.len() < offset + PADDING_HEADER_LEN {
        return Ok(None);
    }
    let command = buf[offset];
    if !matches!(
        command,
        COMMAND_PADDING_CONTINUE | COMMAND_PADDING_END | COMMAND_PADDING_DIRECT
    ) {
        return Err(VisionError::UnknownCommand(command));
    }
    let content_len = u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]) as usize;
    let padding_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
    let content_start = offset + PADDING_HEADER_LEN;
    let consumed = content_start + content_len + padding_len;
    if buf.len() < consumed {
        return Ok(None);
    }
    Ok(Some(PaddingFrame {
        command,
        content_start,
        content_len,
        consumed,
    }))
}

/// Per-connection Vision state: the padding state machines for both directions
/// plus the inner-TLS sniffer that decides whether the handover is offered.
pub struct VisionSession {
    uuid: [u8; 16],
    padding: PaddingDraw,

    // Inner-TLS sniffing, shared by both directions exactly as the reference
    // shares one TrafficState between its reader and writer.
    filter_budget: i32,
    enable_xtls: bool,
    is_tls: bool,
    is_tls12_or_above: bool,
    cipher: u16,
    remaining_server_hello: i32,

    // Uplink writer.
    pending_uuid: bool,
    is_padding: bool,

    // Downlink reader.
    within_padding: bool,
    reader_direct: bool,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
}

impl VisionSession {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self::with_padding(uuid, PaddingDraw::Random)
    }

    pub fn with_padding(uuid: [u8; 16], padding: PaddingDraw) -> Self {
        Self {
            uuid,
            padding,
            filter_budget: FILTER_BUDGET,
            enable_xtls: false,
            is_tls: false,
            is_tls12_or_above: false,
            cipher: 0,
            remaining_server_hello: -1,
            pending_uuid: true,
            is_padding: true,
            within_padding: true,
            reader_direct: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: COMMAND_PADDING_CONTINUE,
        }
    }

    /// Whether the sniffer decided the inner stream is TLS 1.3 with a suite the
    /// handover is defined for.
    pub fn handover_offered(&self) -> bool {
        self.enable_xtls
    }

    /// Emit one padded frame, taking the write-once UUID if it is still pending.
    fn emit(&mut self, content: &[u8], command: u8, long_padding: bool, out: &mut Vec<u8>) {
        let content_len = content.len();
        let mut padding_len = if content_len < LONG_PADDING_THRESHOLD && long_padding {
            self.padding.below(LONG_PADDING_SPREAD) as usize + LONG_PADDING_BASE - content_len
        } else {
            self.padding.below(SHORT_PADDING_SPREAD) as usize
        };
        padding_len = padding_len.min(BUF_SIZE.saturating_sub(FRAME_OVERHEAD + content_len));
        let uuid = self.pending_uuid.then_some(self.uuid);
        self.pending_uuid = false;
        encode_padding_frame(uuid.as_ref(), command, content, padding_len, out);
    }

    /// Strip padding from decrypted bytes, updating the frame state machine.
    fn unpad(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), VisionError> {
        let mut rest = input;
        if self.remaining_command == -1
            && self.remaining_content == -1
            && self.remaining_padding == -1
        {
            // Below 21 bytes there cannot be a frame, and a leading block that is
            // not our UUID means the peer is not padding this direction.
            if rest.len() >= FRAME_OVERHEAD && rest[..16] == self.uuid {
                rest = &rest[16..];
                self.remaining_command = PADDING_HEADER_LEN as i32;
            } else {
                out.extend_from_slice(input);
                return Ok(());
            }
        }

        while !rest.is_empty() {
            if self.remaining_command > 0 {
                let byte = rest[0];
                rest = &rest[1..];
                match self.remaining_command {
                    5 => {
                        if !matches!(
                            byte,
                            COMMAND_PADDING_CONTINUE | COMMAND_PADDING_END | COMMAND_PADDING_DIRECT
                        ) {
                            return Err(VisionError::UnknownCommand(byte));
                        }
                        self.current_command = byte;
                    }
                    4 => self.remaining_content = i32::from(byte) << 8,
                    3 => self.remaining_content |= i32::from(byte),
                    2 => self.remaining_padding = i32::from(byte) << 8,
                    1 => self.remaining_padding |= i32::from(byte),
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let take = (self.remaining_content as usize).min(rest.len());
                out.extend_from_slice(&rest[..take]);
                rest = &rest[take..];
                self.remaining_content -= take as i32;
            } else {
                let take = (self.remaining_padding as usize).min(rest.len());
                rest = &rest[take..];
                self.remaining_padding -= take as i32;
            }

            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == COMMAND_PADDING_CONTINUE {
                    self.remaining_command = PADDING_HEADER_LEN as i32;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    // The padded region ended mid-buffer: everything left is
                    // already unframed application data.
                    out.extend_from_slice(rest);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Recognise the inner handshake well enough to know whether the handover is
    /// safe to offer. Runs on both directions, spending one unit of budget per
    /// buffer, and stops for good once the answer is known.
    fn filter_tls(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }
        self.filter_budget -= 1;
        if buffer.len() >= 6 {
            if buffer[..3] == TLS_SERVER_HANDSHAKE_START
                && buffer[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
            {
                self.remaining_server_hello =
                    (i32::from(buffer[3]) << 8 | i32::from(buffer[4])) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if buffer.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = usize::from(buffer[43]);
                    let suite_at = 43 + session_id_len + 1;
                    if suite_at + 2 <= buffer.len() {
                        self.cipher = u16::from_be_bytes([buffer[suite_at], buffer[suite_at + 1]]);
                    }
                }
            } else if buffer[..2] == TLS_CLIENT_HANDSHAKE_START
                && buffer[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
            {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(buffer.len());
            self.remaining_server_hello -= buffer.len() as i32;
            if contains(&buffer[..end], &TLS13_SUPPORTED_VERSIONS) {
                if TLS13_CIPHER_SUITES.contains(&self.cipher) {
                    self.enable_xtls = true;
                }
                self.filter_budget = 0;
            } else if self.remaining_server_hello <= 0 {
                // ServerHello ended without the 1.3 marker: TLS 1.2 or older,
                // and the handover is not defined for it.
                self.filter_budget = 0;
            }
        }
    }
}

impl InnerCodec for VisionSession {
    fn max_app_chunk(&self) -> usize {
        BUF_SIZE
    }

    fn first_write_delay(&self) -> Option<Duration> {
        Some(FIRST_WRITE_DELAY)
    }

    fn on_first_write_timeout(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        // No payload yet. A lone VLESS header is a length signature by itself,
        // so send an empty-content frame to bury it in padding.
        if self.is_padding {
            self.emit(&[], COMMAND_PADDING_CONTINUE, true, out);
        }
        Ok(())
    }

    fn uplink(&mut self, app: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        if self.filter_budget > 0 {
            self.filter_tls(app);
        }
        if !self.is_padding {
            out.extend_from_slice(app);
            return Ok(false);
        }

        let complete = is_complete_record(app);
        let pieces = reshape(app);
        let last = pieces.len() - 1;
        let mut switch = false;
        let mut long_padding = self.is_tls;

        for (index, piece) in pieces.iter().enumerate() {
            let piece = *piece;
            if self.is_tls
                && piece.len() >= 6
                && piece[..3] == TLS_APPLICATION_DATA_START
                && complete
            {
                // The inner handshake is done: this is the first record that is
                // already ciphertext, so it is the last one worth padding.
                if self.enable_xtls {
                    switch = true;
                }
                let mut command = COMMAND_PADDING_CONTINUE;
                if index == last {
                    command = if self.enable_xtls {
                        COMMAND_PADDING_DIRECT
                    } else {
                        COMMAND_PADDING_END
                    };
                }
                self.emit(piece, command, true, out);
                self.is_padding = false;
                long_padding = false;
                continue;
            } else if !self.is_tls12_or_above && self.filter_budget <= 1 {
                // Not TLS at all. Stop padding one buffer early, which is what
                // earlier Vision receivers expect.
                self.is_padding = false;
                self.emit(piece, COMMAND_PADDING_END, long_padding, out);
                break;
            }
            let mut command = COMMAND_PADDING_CONTINUE;
            if index == last && !self.is_padding {
                command = if self.enable_xtls {
                    COMMAND_PADDING_DIRECT
                } else {
                    COMMAND_PADDING_END
                };
            }
            self.emit(piece, command, long_padding, out);
        }
        Ok(switch)
    }

    fn downlink(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        if self.reader_direct {
            out.extend_from_slice(plain);
            return Ok(true);
        }
        let start = out.len();
        if self.within_padding || self.filter_budget > 0 {
            self.unpad(plain, out)?;
            if self.remaining_content > 0
                || self.remaining_padding > 0
                || self.current_command == COMMAND_PADDING_CONTINUE
            {
                self.within_padding = true;
            } else if self.current_command == COMMAND_PADDING_END {
                self.within_padding = false;
            } else if self.current_command == COMMAND_PADDING_DIRECT {
                self.within_padding = false;
                self.reader_direct = true;
            } else {
                return Err(VisionError::UnknownCommand(self.current_command).into());
            }
        } else {
            out.extend_from_slice(plain);
        }
        if self.filter_budget > 0 {
            let produced = out[start..].to_vec();
            self.filter_tls(&produced);
        }
        Ok(self.reader_direct)
    }
}

/// Vision framing wired to the VLESS header exchange.
///
/// Both headers sit *outside* the padded region, and both have to be handled
/// here rather than by the caller:
///
/// * The request header is held until the first framed write so it is flushed
///   in the same record — a header travelling alone is the length signature
///   Vision exists to bury.
/// * The response header therefore cannot be read before the connection carries
///   traffic, so reading it from the caller would deadlock every protocol whose
///   server speaks first.
pub struct VisionCodec {
    session: VisionSession,
    /// VLESS request header, emitted verbatim ahead of the first frame.
    request: Vec<u8>,
    response: ResponseHeader,
}

enum ResponseHeader {
    /// Still collecting `version(1) | addon_len(1) | addon`.
    Pending(Vec<u8>),
    Done,
}

impl VisionCodec {
    pub fn new(session: VisionSession, request: Vec<u8>) -> Self {
        Self {
            session,
            request,
            response: ResponseHeader::Pending(Vec::new()),
        }
    }

    fn take_request(&mut self, out: &mut Vec<u8>) {
        if !self.request.is_empty() {
            out.append(&mut self.request);
        }
    }
}

impl InnerCodec for VisionCodec {
    fn max_app_chunk(&self) -> usize {
        self.session.max_app_chunk()
    }

    fn first_write_delay(&self) -> Option<Duration> {
        self.session.first_write_delay()
    }

    fn on_first_write_timeout(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.take_request(out);
        self.session.on_first_write_timeout(out)
    }

    fn uplink(&mut self, app: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        self.take_request(out);
        self.session.uplink(app, out)
    }

    fn downlink(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        let ResponseHeader::Pending(buffered) = &mut self.response else {
            return self.session.downlink(plain, out);
        };
        buffered.extend_from_slice(plain);
        if buffered.len() < 2 {
            return Ok(false);
        }
        if buffered[0] != crate::codec::VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VLESS response version {}", buffered[0]),
            ));
        }
        let addon_len = usize::from(buffered[1]);
        if buffered.len() < 2 + addon_len {
            return Ok(false);
        }
        let body = buffered.split_off(2 + addon_len);
        self.response = ResponseHeader::Done;
        if body.is_empty() {
            return Ok(false);
        }
        self.session.downlink(&body, out)
    }
}

/// Split a buffer that leaves no room for a frame header, preferring the last
/// inner record boundary so a padded frame never straddles one.
fn reshape(buffer: &[u8]) -> Vec<&[u8]> {
    if buffer.len() < BUF_SIZE - FRAME_OVERHEAD {
        return vec![buffer];
    }
    let index = last_index(buffer, &TLS_APPLICATION_DATA_START).unwrap_or(usize::MAX);
    let index = if !(FRAME_OVERHEAD..=BUF_SIZE - FRAME_OVERHEAD).contains(&index) {
        BUF_SIZE / 2
    } else {
        index
    };
    let index = index.min(buffer.len());
    vec![&buffer[..index], &buffer[index..]]
}

/// Whether `buffer` is exactly a whole number of TLS application-data records.
///
/// The handover may only be offered on a record boundary: half a record written
/// raw would leave the peer's inner TLS stack parsing a truncated record.
fn is_complete_record(buffer: &[u8]) -> bool {
    let mut offset = 0;
    while offset < buffer.len() {
        if buffer.len() - offset < 5 {
            return false;
        }
        if buffer[offset..offset + 3] != TLS_APPLICATION_DATA_START {
            return false;
        }
        let length = u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]) as usize;
        if length == 0 {
            return false;
        }
        offset += 5;
        if buffer.len() - offset < length {
            return false;
        }
        offset += length;
    }
    offset == buffer.len() && !buffer.is_empty()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn last_index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0xd0, 0xcf, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    fn session() -> VisionSession {
        // Every draw returns 7: long padding becomes 907 - contentLen, short 7.
        VisionSession::with_padding(UUID, PaddingDraw::Fixed(7))
    }

    /// A TLS 1.3 ServerHello record whose body carries the supported_versions
    /// extension and the given cipher suite, padded to the length the sniffer
    /// needs to read the suite at 43 + session_id_len.
    fn server_hello(suite: u16) -> Vec<u8> {
        let mut body = vec![0x02, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(32); // session id length
        body.extend_from_slice(&[0x22; 32]); // session id
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0x00); // compression
        body.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        body.resize(120, 0);
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    fn application_data(len: usize) -> Vec<u8> {
        let mut record = TLS_APPLICATION_DATA_START.to_vec();
        record.extend_from_slice(&(len as u16).to_be_bytes());
        record.resize(5 + len, 0x5a);
        record
    }

    #[test]
    fn first_frame_carries_uuid_then_header_content_and_padding() {
        let mut out = Vec::new();
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_CONTINUE, b"hello", 3, &mut out);

        assert_eq!(
            &out[..16],
            &UUID,
            "first frame must open with the user UUID"
        );
        assert_eq!(out[16], COMMAND_PADDING_CONTINUE);
        assert_eq!(u16::from_be_bytes([out[17], out[18]]) as usize, 5);
        assert_eq!(u16::from_be_bytes([out[19], out[20]]) as usize, 3);
        assert_eq!(&out[21..26], b"hello");
        assert_eq!(out.len(), FIRST_PADDING_HEADER_LEN + 5 + 3);
    }

    #[test]
    fn later_frames_omit_the_uuid() {
        let mut out = Vec::new();
        encode_padding_frame(None, COMMAND_PADDING_DIRECT, b"xy", 0, &mut out);
        assert_eq!(out[0], COMMAND_PADDING_DIRECT);
        assert_eq!(u16::from_be_bytes([out[1], out[2]]) as usize, 2);
        assert_eq!(u16::from_be_bytes([out[3], out[4]]) as usize, 0);
        assert_eq!(&out[5..7], b"xy");
        assert_eq!(out.len(), PADDING_HEADER_LEN + 2);
    }

    #[test]
    fn parses_a_first_frame_and_reports_consumed_bytes() {
        let mut out = Vec::new();
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_END, b"payload", 4, &mut out);

        let frame = parse_padding_frame(&out, Some(&UUID)).unwrap().unwrap();
        assert_eq!(frame.command, COMMAND_PADDING_END);
        assert_eq!(frame.content_len, 7);
        assert_eq!(
            &out[frame.content_start..frame.content_start + 7],
            b"payload"
        );
        assert_eq!(frame.consumed, out.len());
    }

    #[test]
    fn incomplete_frames_yield_none() {
        let mut out = Vec::new();
        encode_padding_frame(None, COMMAND_PADDING_CONTINUE, b"abcd", 2, &mut out);
        // Everything but the final padding byte has arrived.
        assert!(
            parse_padding_frame(&out[..out.len() - 1], None)
                .unwrap()
                .is_none()
        );
        assert!(parse_padding_frame(&[], None).unwrap().is_none());
    }

    #[test]
    fn rejects_a_first_frame_with_the_wrong_uuid() {
        let mut out = Vec::new();
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_CONTINUE, b"z", 0, &mut out);
        let mut wrong = UUID;
        wrong[0] ^= 0xff;
        assert_eq!(
            parse_padding_frame(&out, Some(&wrong)).unwrap_err(),
            VisionError::UuidMismatch
        );
    }

    #[test]
    fn rejects_unknown_commands() {
        let mut frame = vec![0x7f];
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.push(b'q');
        assert_eq!(
            parse_padding_frame(&frame, None).unwrap_err(),
            VisionError::UnknownCommand(0x7f)
        );
    }

    // --- golden vectors against the reference padding formula -----------------

    #[test]
    fn the_opening_frame_is_a_golden_vector_of_the_reference_formula() {
        let mut vision = session();
        let mut out = Vec::new();
        // Content below 900 with long padding: rand(500)=7, so 7 + 900 - 5 = 902.
        vision.is_tls = true;
        vision.uplink(b"hello", &mut out).unwrap();

        let mut expected = UUID.to_vec();
        expected.extend_from_slice(&[COMMAND_PADDING_CONTINUE, 0x00, 0x05, 0x03, 0x86]);
        expected.extend_from_slice(b"hello");
        expected.resize(expected.len() + 902, 0);
        assert_eq!(out, expected);
        assert_eq!(0x0386, 902);
    }

    #[test]
    fn the_camouflage_frame_has_no_content_and_the_long_padding_profile() {
        let mut vision = session();
        let mut out = Vec::new();
        vision.on_first_write_timeout(&mut out).unwrap();

        let mut expected = UUID.to_vec();
        // 7 + 900 - 0 = 907 = 0x038b.
        expected.extend_from_slice(&[COMMAND_PADDING_CONTINUE, 0x00, 0x00, 0x03, 0x8b]);
        expected.resize(expected.len() + 907, 0);
        assert_eq!(out, expected);
    }

    #[test]
    fn only_the_first_frame_carries_the_uuid() {
        let mut vision = session();
        let mut first = Vec::new();
        vision.uplink(b"one", &mut first).unwrap();
        let mut second = Vec::new();
        vision.uplink(b"two", &mut second).unwrap();

        assert_eq!(&first[..16], &UUID);
        assert_eq!(
            second[0], COMMAND_PADDING_CONTINUE,
            "the UUID opens the padded region exactly once, so later frames \
             start at the command byte"
        );
        assert_eq!(second.len(), PADDING_HEADER_LEN + 3 + 7);
    }

    // --- the handover ---------------------------------------------------------

    #[test]
    fn a_tls13_server_hello_arms_the_handover_and_the_first_record_ends_it() {
        let mut vision = session();
        // Downlink ServerHello (already unpadded because the peer sent no UUID).
        let mut app = Vec::new();
        let switched = vision.downlink(&server_hello(0x1301), &mut app).unwrap();
        assert!(!switched, "reading a ServerHello does not itself splice");
        assert!(
            vision.handover_offered(),
            "TLS 1.3 with an accepted suite must arm the handover"
        );

        // Uplink: the first complete inner application-data record.
        let mut wire = Vec::new();
        let switch = vision.uplink(&application_data(64), &mut wire).unwrap();
        assert!(switch, "the writer hands the socket over after this frame");
        let frame = parse_padding_frame(&wire, Some(&UUID)).unwrap().unwrap();
        assert_eq!(frame.command, COMMAND_PADDING_DIRECT);
        assert_eq!(frame.content_len, 69);
    }

    #[test]
    fn an_unaccepted_cipher_suite_ends_padding_without_handing_over() {
        let mut vision = session();
        // TLS_AES_128_CCM_8_SHA256 is excluded by the reference.
        let mut app = Vec::new();
        vision.downlink(&server_hello(0x1305), &mut app).unwrap();
        assert!(!vision.handover_offered());

        let mut wire = Vec::new();
        let switch = vision.uplink(&application_data(32), &mut wire).unwrap();
        assert!(!switch, "no handover without an accepted suite");
        let frame = parse_padding_frame(&wire, Some(&UUID)).unwrap().unwrap();
        assert_eq!(
            frame.command, COMMAND_PADDING_END,
            "padding still ends, it just does not hand the socket over"
        );
    }

    #[test]
    fn a_direct_command_from_the_peer_switches_the_reader_and_drains_the_frame() {
        let mut vision = session();
        let mut wire = Vec::new();
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_DIRECT, b"tail", 3, &mut wire);
        // Bytes after the terminating frame are already unframed.
        wire.extend_from_slice(b"raw-follows");

        let mut app = Vec::new();
        let switched = vision.downlink(&wire, &mut app).unwrap();
        assert!(switched);
        assert_eq!(app, b"tailraw-follows");

        // Everything after the switch is copied verbatim.
        let mut more = Vec::new();
        assert!(vision.downlink(b"opaque", &mut more).unwrap());
        assert_eq!(more, b"opaque");
    }

    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let mut vision = session();
        let mut opening = Vec::new();
        encode_padding_frame(
            Some(&UUID),
            COMMAND_PADDING_CONTINUE,
            b"ab",
            2,
            &mut opening,
        );
        let mut rest = Vec::new();
        encode_padding_frame(None, COMMAND_PADDING_END, b"cdefgh", 5, &mut rest);

        let mut app = Vec::new();
        vision.downlink(&opening, &mut app).unwrap();
        // Header bytes, content and padding all arrive in pieces.
        for chunk in rest.chunks(3) {
            vision.downlink(chunk, &mut app).unwrap();
        }
        assert_eq!(app, b"abcdefgh");
    }

    #[test]
    fn an_opening_block_shorter_than_a_frame_header_is_not_treated_as_padding() {
        // Matching the reference: below 21 bytes there cannot be a UUID plus a
        // header, so the block is application data from a peer that is not
        // padding this direction — guessing otherwise would eat real bytes.
        let mut vision = session();
        let mut app = Vec::new();
        vision.downlink(&UUID[..15], &mut app).unwrap();
        assert_eq!(app, UUID[..15]);
    }

    #[test]
    fn several_continue_frames_in_one_read_all_decode() {
        let mut vision = session();
        let mut wire = Vec::new();
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_CONTINUE, b"aa", 2, &mut wire);
        encode_padding_frame(None, COMMAND_PADDING_CONTINUE, b"bb", 0, &mut wire);
        encode_padding_frame(None, COMMAND_PADDING_END, b"cc", 1, &mut wire);

        let mut app = Vec::new();
        assert!(!vision.downlink(&wire, &mut app).unwrap());
        assert_eq!(app, b"aabbcc");
    }

    #[test]
    fn a_downlink_that_does_not_open_with_the_uuid_is_passed_through() {
        let mut vision = session();
        let mut app = Vec::new();
        // A peer that never pads this direction: 21+ bytes, wrong leading block.
        let plain = vec![0x99_u8; 40];
        vision.downlink(&plain, &mut app).unwrap();
        assert_eq!(app, plain);
    }

    #[test]
    fn a_bad_padding_command_is_an_error_not_a_guess() {
        let mut vision = session();
        let mut wire = UUID.to_vec();
        wire.extend_from_slice(&[0x7f, 0x00, 0x01, 0x00, 0x00, b'x']);
        let mut app = Vec::new();
        let error = vision.downlink(&wire, &mut app).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    // --- shaping --------------------------------------------------------------

    #[test]
    fn complete_record_detection_matches_the_reference_rules() {
        assert!(is_complete_record(&application_data(10)));
        let mut two = application_data(4);
        two.extend_from_slice(&application_data(6));
        assert!(is_complete_record(&two));

        let short = &application_data(10)[..8];
        assert!(
            !is_complete_record(short),
            "a truncated record is not whole"
        );
        assert!(!is_complete_record(b""), "nothing is not a whole record");
        assert!(
            !is_complete_record(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x00]),
            "handshake records are not application data"
        );
    }

    #[test]
    fn oversized_buffers_are_split_so_a_frame_header_always_fits() {
        let small = vec![0_u8; 128];
        assert_eq!(reshape(&small).len(), 1);

        // One byte below the threshold still fits a frame header.
        assert_eq!(reshape(&vec![0_u8; BUF_SIZE - FRAME_OVERHEAD - 1]).len(), 1);

        let mut big = vec![0_u8; BUF_SIZE - 10];
        big[4000..4003].copy_from_slice(&TLS_APPLICATION_DATA_START);
        let pieces = reshape(&big);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), 4000, "split at the last record boundary");
        assert_eq!(pieces[0].len() + pieces[1].len(), big.len());

        // No boundary to split on: fall back to the midpoint.
        let plain = vec![0x41_u8; BUF_SIZE - 10];
        let pieces = reshape(&plain);
        assert_eq!(pieces[0].len(), BUF_SIZE / 2);
    }

    #[test]
    fn padding_never_pushes_a_frame_past_the_reference_buffer() {
        let mut vision = VisionSession::with_padding(UUID, PaddingDraw::Fixed(255));
        let mut out = Vec::new();
        let piece = vec![0x41_u8; BUF_SIZE - 40];
        vision.emit(&piece, COMMAND_PADDING_CONTINUE, false, &mut out);
        assert!(
            out.len() <= BUF_SIZE,
            "a padded frame must stay inside the reference buffer, got {}",
            out.len()
        );
    }

    #[test]
    fn non_tls_traffic_stops_padding_once_the_sniffer_gives_up() {
        let mut vision = session();
        let mut ended = false;
        for _ in 0..FILTER_BUDGET + 2 {
            let mut out = Vec::new();
            vision.uplink(b"plain-http-bytes", &mut out).unwrap();
            if !vision.is_padding {
                // The frame that ends padding says so on the wire.
                let frame = parse_padding_frame(&out, None)
                    .or_else(|_| parse_padding_frame(&out, Some(&UUID)))
                    .unwrap()
                    .unwrap();
                assert_eq!(frame.command, COMMAND_PADDING_END);
                ended = true;
                break;
            }
        }
        assert!(ended, "padding must not run forever on non-TLS traffic");

        // And from then on the writer is transparent.
        let mut out = Vec::new();
        vision.uplink(b"after", &mut out).unwrap();
        assert_eq!(out, b"after");
    }

    // --- the VLESS header exchange -------------------------------------------

    fn codec() -> VisionCodec {
        VisionCodec::new(session(), b"VLESS-REQUEST-HEADER".to_vec())
    }

    #[test]
    fn the_request_header_rides_ahead_of_the_first_frame_not_in_it() {
        let mut vision = codec();
        let mut out = Vec::new();
        vision.uplink(b"payload", &mut out).unwrap();
        assert!(out.starts_with(b"VLESS-REQUEST-HEADER"));
        // The frame that follows is a normal first frame, UUID and all.
        let frame = parse_padding_frame(&out[20..], Some(&UUID))
            .unwrap()
            .unwrap();
        assert_eq!(frame.content_len, 7);

        // And it is written once.
        let mut second = Vec::new();
        vision.uplink(b"more", &mut second).unwrap();
        assert!(!second.starts_with(b"VLESS-REQUEST-HEADER"));
    }

    #[test]
    fn a_silent_application_still_flushes_the_header_with_camouflage_padding() {
        // Left alone, the VLESS header would travel as a lone short record —
        // exactly the length signature Vision exists to bury.
        let mut vision = codec();
        let mut out = Vec::new();
        vision.on_first_write_timeout(&mut out).unwrap();
        assert!(out.starts_with(b"VLESS-REQUEST-HEADER"));
        let frame = parse_padding_frame(&out[20..], Some(&UUID))
            .unwrap()
            .unwrap();
        assert_eq!(frame.command, COMMAND_PADDING_CONTINUE);
        assert_eq!(frame.content_len, 0);
    }

    #[test]
    fn the_response_header_is_consumed_before_the_padding_state_machine() {
        let mut vision = codec();
        let mut wire = vec![crate::codec::VERSION, 0x00];
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_END, b"body", 2, &mut wire);

        let mut app = Vec::new();
        vision.downlink(&wire, &mut app).unwrap();
        assert_eq!(app, b"body", "the header must not reach the application");
    }

    #[test]
    fn a_response_header_split_across_records_is_still_consumed_whole() {
        let mut vision = codec();
        let mut app = Vec::new();
        // Version alone, then the addon length, then an addon, then the frame.
        vision.downlink(&[crate::codec::VERSION], &mut app).unwrap();
        vision.downlink(&[0x03], &mut app).unwrap();
        vision.downlink(&[0xaa, 0xbb], &mut app).unwrap();
        let mut wire = vec![0xcc];
        encode_padding_frame(Some(&UUID), COMMAND_PADDING_END, b"late", 1, &mut wire);
        vision.downlink(&wire, &mut app).unwrap();
        assert_eq!(app, b"late");
    }

    #[test]
    fn a_bad_response_version_fails_the_connection() {
        let mut vision = codec();
        let mut app = Vec::new();
        let error = vision.downlink(&[0x7f, 0x00], &mut app).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_client_hello_marks_the_stream_as_tls_without_arming_the_handover() {
        let mut vision = session();
        let mut hello = vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01];
        hello.resize(517, 0);
        let mut out = Vec::new();
        vision.uplink(&hello, &mut out).unwrap();
        assert!(vision.is_tls);
        assert!(!vision.is_tls12_or_above);
        assert!(!vision.handover_offered());
    }
}
