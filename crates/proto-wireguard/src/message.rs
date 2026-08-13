//! WireGuard wire formats.
//!
//! Every message is fixed-size except transport data, and the sizes are part of
//! the protocol's identity — a peer that sends a differently sized frame is not
//! speaking WireGuard, so parsing rejects rather than tolerates.
//!
//! ```text
//! initiation (148) := 01 00 00 00 | sender u32le | ephemeral[32]
//!                     | enc_static[48] | enc_timestamp[28] | mac1[16] | mac2[16]
//! response    (92) := 02 00 00 00 | sender u32le | receiver u32le
//!                     | ephemeral[32] | enc_empty[16] | mac1[16] | mac2[16]
//! cookie      (64) := 03 00 00 00 | receiver u32le | nonce[24] | enc_cookie[32]
//! transport (16+N) := 04 00 00 00 | receiver u32le | counter u64le | ciphertext
//! ```

use crate::WireguardError;

pub const TYPE_INITIATION: u8 = 1;
pub const TYPE_RESPONSE: u8 = 2;
pub const TYPE_COOKIE_REPLY: u8 = 3;
pub const TYPE_TRANSPORT: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
/// `type | reserved | receiver | counter` in front of every transport payload.
pub const TRANSPORT_HEADER_LEN: usize = 16;
/// Poly1305 tag appended by the AEAD.
pub const TAG_LEN: usize = 16;

/// Offset of `mac1` inside an initiation; everything before it is MAC'd.
pub const INITIATION_MAC1_OFFSET: usize = INITIATION_LEN - 32;
/// Offset of `mac1` inside a response.
pub const RESPONSE_MAC1_OFFSET: usize = RESPONSE_LEN - 32;
/// Offset of `mac2` inside an initiation. `mac2` covers `mac1` as well, so this
/// is not the `mac1` offset with the field skipped.
pub const INITIATION_MAC2_OFFSET: usize = INITIATION_LEN - 16;

/// Handshake initiation, initiator → responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initiation {
    pub sender_index: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Handshake response, responder → initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_empty: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Cookie reply — the responder's load-shedding challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieReply {
    pub receiver_index: u32,
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 32],
}

/// The first four bytes of a *vanilla* WireGuard datagram: a type plus three
/// zero bytes. Returns `None` for anything else.
///
/// Strict on purpose. AmneziaWG replaces this header with random bytes, and
/// this predicate is what tells an obfuscated datagram from a plain one — a
/// permissive version would classify obfuscated traffic as a real message type
/// most of the time. Decoding an *incoming* datagram uses [`message_kind`]
/// instead, which ignores the reserved bytes as the protocol requires.
pub fn message_type(datagram: &[u8]) -> Option<u8> {
    let header = datagram.first_chunk::<4>()?;
    if header[1..] != [0, 0, 0] {
        return None;
    }
    Some(header[0])
}

/// The type byte of a datagram, ignoring the reserved field.
///
/// Receivers are told to ignore those three bytes, and some providers use them
/// as a client identifier that the peer echoes back. Refusing such a datagram
/// would make the peer unreachable and would buy nothing: what proves a message
/// genuine is its AEAD tag, not three bytes any intermediary can rewrite.
fn message_kind(datagram: &[u8]) -> Option<u8> {
    datagram.first_chunk::<4>().map(|header| header[0])
}

fn header(kind: u8) -> [u8; 4] {
    [kind, 0, 0, 0]
}

impl Initiation {
    pub fn encode(&self) -> [u8; INITIATION_LEN] {
        let mut out = [0_u8; INITIATION_LEN];
        out[..4].copy_from_slice(&header(TYPE_INITIATION));
        out[4..8].copy_from_slice(&self.sender_index.to_le_bytes());
        out[8..40].copy_from_slice(&self.ephemeral);
        out[40..88].copy_from_slice(&self.encrypted_static);
        out[88..116].copy_from_slice(&self.encrypted_timestamp);
        out[116..132].copy_from_slice(&self.mac1);
        out[132..148].copy_from_slice(&self.mac2);
        out
    }

    pub fn decode(datagram: &[u8]) -> Result<Self, WireguardError> {
        let datagram = expect(datagram, TYPE_INITIATION, INITIATION_LEN)?;
        Ok(Self {
            sender_index: u32::from_le_bytes(read_array(datagram, 4)?),
            ephemeral: read_array(datagram, 8)?,
            encrypted_static: read_array(datagram, 40)?,
            encrypted_timestamp: read_array(datagram, 88)?,
            mac1: read_array(datagram, 116)?,
            mac2: read_array(datagram, 132)?,
        })
    }
}

impl Response {
    pub fn encode(&self) -> [u8; RESPONSE_LEN] {
        let mut out = [0_u8; RESPONSE_LEN];
        out[..4].copy_from_slice(&header(TYPE_RESPONSE));
        out[4..8].copy_from_slice(&self.sender_index.to_le_bytes());
        out[8..12].copy_from_slice(&self.receiver_index.to_le_bytes());
        out[12..44].copy_from_slice(&self.ephemeral);
        out[44..60].copy_from_slice(&self.encrypted_empty);
        out[60..76].copy_from_slice(&self.mac1);
        out[76..92].copy_from_slice(&self.mac2);
        out
    }

    pub fn decode(datagram: &[u8]) -> Result<Self, WireguardError> {
        let datagram = expect(datagram, TYPE_RESPONSE, RESPONSE_LEN)?;
        Ok(Self {
            sender_index: u32::from_le_bytes(read_array(datagram, 4)?),
            receiver_index: u32::from_le_bytes(read_array(datagram, 8)?),
            ephemeral: read_array(datagram, 12)?,
            encrypted_empty: read_array(datagram, 44)?,
            mac1: read_array(datagram, 60)?,
            mac2: read_array(datagram, 76)?,
        })
    }
}

impl CookieReply {
    pub fn encode(&self) -> [u8; COOKIE_REPLY_LEN] {
        let mut out = [0_u8; COOKIE_REPLY_LEN];
        out[..4].copy_from_slice(&header(TYPE_COOKIE_REPLY));
        out[4..8].copy_from_slice(&self.receiver_index.to_le_bytes());
        out[8..32].copy_from_slice(&self.nonce);
        out[32..64].copy_from_slice(&self.encrypted_cookie);
        out
    }

    pub fn decode(datagram: &[u8]) -> Result<Self, WireguardError> {
        let datagram = expect(datagram, TYPE_COOKIE_REPLY, COOKIE_REPLY_LEN)?;
        Ok(Self {
            receiver_index: u32::from_le_bytes(read_array(datagram, 4)?),
            nonce: read_array(datagram, 8)?,
            encrypted_cookie: read_array(datagram, 32)?,
        })
    }
}

/// Write the transport header, returning the slice the ciphertext must fill.
pub fn write_transport_header(receiver_index: u32, counter: u64, out: &mut [u8]) {
    out[..4].copy_from_slice(&header(TYPE_TRANSPORT));
    out[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    out[8..16].copy_from_slice(&counter.to_le_bytes());
}

/// Split a transport datagram into `(receiver_index, counter, ciphertext)`.
pub fn parse_transport(datagram: &[u8]) -> Result<(u32, u64, &[u8]), WireguardError> {
    if message_kind(datagram) != Some(TYPE_TRANSPORT) {
        return Err(WireguardError::UnexpectedMessage);
    }
    // A keepalive is an empty packet, so the payload is the bare AEAD tag; any
    // shorter frame cannot have been produced by the protocol.
    if datagram.len() < TRANSPORT_HEADER_LEN + TAG_LEN {
        return Err(WireguardError::MalformedMessage);
    }
    let receiver_index = u32::from_le_bytes(read_array(datagram, 4)?);
    let counter = u64::from_le_bytes(read_array(datagram, 8)?);
    Ok((receiver_index, counter, &datagram[TRANSPORT_HEADER_LEN..]))
}

fn read_array<const N: usize>(datagram: &[u8], offset: usize) -> Result<[u8; N], WireguardError> {
    datagram
        .get(offset..)
        .and_then(|tail| tail.first_chunk::<N>())
        .copied()
        .ok_or(WireguardError::MalformedMessage)
}

fn expect(datagram: &[u8], kind: u8, len: usize) -> Result<&[u8], WireguardError> {
    if message_kind(datagram) != Some(kind) {
        return Err(WireguardError::UnexpectedMessage);
    }
    if datagram.len() != len {
        return Err(WireguardError::MalformedMessage);
    }
    Ok(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initiation() -> Initiation {
        Initiation {
            sender_index: 0xDEAD_BEEF,
            ephemeral: [0x11; 32],
            encrypted_static: [0x22; 48],
            encrypted_timestamp: [0x33; 28],
            mac1: [0x44; 16],
            mac2: [0x55; 16],
        }
    }

    #[test]
    fn initiation_round_trips_at_the_protocol_size() {
        let encoded = initiation().encode();
        assert_eq!(encoded.len(), 148);
        assert_eq!(&encoded[..4], &[TYPE_INITIATION, 0, 0, 0]);
        assert_eq!(Initiation::decode(&encoded).unwrap(), initiation());
        // mac1 covers everything before itself.
        assert_eq!(INITIATION_MAC1_OFFSET, 116);
    }

    #[test]
    fn response_round_trips_at_the_protocol_size() {
        let response = Response {
            sender_index: 7,
            receiver_index: 9,
            ephemeral: [0xAB; 32],
            encrypted_empty: [0xCD; 16],
            mac1: [0x01; 16],
            mac2: [0x02; 16],
        };
        let encoded = response.encode();
        assert_eq!(encoded.len(), 92);
        assert_eq!(Response::decode(&encoded).unwrap(), response);
        assert_eq!(RESPONSE_MAC1_OFFSET, 60);
    }

    #[test]
    fn cookie_reply_round_trips_at_the_protocol_size() {
        let cookie = CookieReply {
            receiver_index: 42,
            nonce: [0x0F; 24],
            encrypted_cookie: [0xF0; 32],
        };
        let encoded = cookie.encode();
        assert_eq!(encoded.len(), 64);
        assert_eq!(CookieReply::decode(&encoded).unwrap(), cookie);
    }

    #[test]
    fn reserved_bytes_are_ignored_rather_than_rejected() {
        // Some providers put a client identifier here and echo it back. The
        // protocol says to ignore these bytes, and refusing the datagram would
        // make such a peer unreachable while buying no security: the AEAD tag
        // is what proves the message is genuine.
        let mut encoded = initiation().encode();
        encoded[2] = 1;
        assert_eq!(Initiation::decode(&encoded).unwrap(), initiation());
    }

    #[test]
    fn wrong_length_is_rejected_rather_than_tolerated() {
        let encoded = initiation().encode();
        assert!(matches!(
            Initiation::decode(&encoded[..147]),
            Err(WireguardError::MalformedMessage)
        ));
        let mut padded = encoded.to_vec();
        padded.push(0);
        assert!(matches!(
            Initiation::decode(&padded),
            Err(WireguardError::MalformedMessage)
        ));
    }

    #[test]
    fn transport_header_round_trips_and_rejects_runt_frames() {
        let mut datagram = vec![0_u8; TRANSPORT_HEADER_LEN + TAG_LEN];
        write_transport_header(0x0102_0304, 0x0A0B_0C0D_0E0F_1011, &mut datagram);
        let (receiver, counter, ciphertext) = parse_transport(&datagram).unwrap();
        assert_eq!(receiver, 0x0102_0304);
        assert_eq!(counter, 0x0A0B_0C0D_0E0F_1011);
        assert_eq!(ciphertext.len(), TAG_LEN, "keepalive is tag-only");

        assert!(matches!(
            parse_transport(&datagram[..TRANSPORT_HEADER_LEN + TAG_LEN - 1]),
            Err(WireguardError::MalformedMessage)
        ));
    }

    #[test]
    fn message_type_reads_only_well_formed_headers() {
        assert_eq!(message_type(&[4, 0, 0, 0, 9]), Some(TYPE_TRANSPORT));
        assert_eq!(
            message_type(&[4, 0, 1, 0]),
            None,
            "a non-zero reserved field is how an obfuscated datagram is told apart"
        );
        assert_eq!(message_type(&[4, 0, 0]), None, "too short to have a header");
        assert_eq!(
            message_kind(&[4, 0, 1, 0, 9]),
            Some(TYPE_TRANSPORT),
            "decoding ignores the reserved field, as the protocol requires"
        );
    }
}
