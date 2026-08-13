//! AmneziaWG obfuscation over standard WireGuard.
//!
//! AmneziaWG keeps WireGuard's cryptography untouched and only reshapes what a
//! DPI box sees on the wire, so it composes as a thin layer on top of the
//! [`crate::message`] formats rather than a second protocol:
//!
//! * `Jc` junk packets of `Jmin..=Jmax` random bytes are sent before the
//!   handshake, so the first thing on the wire is not a 148-byte initiation.
//! * `S1`/`S2` prepend random junk to the initiation and response, moving the
//!   recognisable fields off their fixed offsets.
//! * `H1..H4` replace WireGuard's four one-byte message types with arbitrary
//!   32-bit values, erasing the `01/02/03/04 00 00 00` signature.
//!
//! The obfuscation is symmetric: both peers share the same parameters, so a
//! sealed handshake is just a standard one with a different header and a junk
//! prefix. This module is parameters + transforms only; it performs no I/O.

use crate::WireguardError;
use crate::message::{
    COOKIE_REPLY_LEN, INITIATION_LEN, RESPONSE_LEN, TYPE_COOKIE_REPLY, TYPE_INITIATION,
    TYPE_RESPONSE, TYPE_TRANSPORT, message_type,
};

/// AmneziaWG obfuscation parameters (`Jc, Jmin, Jmax, S1, S2, H1..H4`).
///
/// The default is byte-for-byte standard WireGuard: no junk, one-byte headers.
/// That makes `AmneziaParams::default()` the honest representation of a plain
/// `wireguard` profile and lets the same code path serve both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaParams {
    /// Number of junk packets to send before the handshake.
    pub junk_packet_count: u16,
    /// Inclusive size bounds for each junk packet.
    pub junk_min_size: u16,
    pub junk_max_size: u16,
    /// Junk prepended to the initiation / response messages.
    pub init_junk_size: u16,
    pub response_junk_size: u16,
    /// `S3`/`S4` (AmneziaWG 2.0): the same random prefix extended to cookie
    /// replies and to transport packets. Both are a prefix *before* the custom
    /// header, exactly like `S1`/`S2`.
    pub cookie_junk_size: u16,
    pub transport_junk_size: u16,
    /// Replacement 32-bit header for each message type.
    pub header_initiation: u32,
    pub header_response: u32,
    pub header_cookie: u32,
    pub header_transport: u32,
}

impl Default for AmneziaParams {
    fn default() -> Self {
        Self {
            junk_packet_count: 0,
            junk_min_size: 0,
            junk_max_size: 0,
            init_junk_size: 0,
            response_junk_size: 0,
            cookie_junk_size: 0,
            transport_junk_size: 0,
            header_initiation: TYPE_INITIATION as u32,
            header_response: TYPE_RESPONSE as u32,
            header_cookie: TYPE_COOKIE_REPLY as u32,
            header_transport: TYPE_TRANSPORT as u32,
        }
    }
}

/// Amnezia caps junk at this size so a peer cannot be steered into unbounded
/// allocation by an oversized parameter.
pub const MAX_JUNK_SIZE: u16 = 1280;
const MAX_JUNK_PACKET_COUNT: u16 = 128;

impl AmneziaParams {
    /// True when these parameters are indistinguishable from plain WireGuard.
    pub fn is_vanilla(&self) -> bool {
        *self == Self::default()
    }

    /// Reject parameters that cannot describe a working session. Validation
    /// lives here so both config and link import share one definition.
    pub fn validate(&self) -> Result<(), WireguardError> {
        if self.is_vanilla() {
            return Ok(());
        }
        if self.junk_max_size > MAX_JUNK_SIZE
            || self.init_junk_size > MAX_JUNK_SIZE
            || self.response_junk_size > MAX_JUNK_SIZE
            || self.cookie_junk_size > MAX_JUNK_SIZE
            || self.transport_junk_size > MAX_JUNK_SIZE
        {
            return Err(WireguardError::InvalidParameters);
        }
        if self.junk_packet_count > MAX_JUNK_PACKET_COUNT {
            return Err(WireguardError::InvalidParameters);
        }
        if self.junk_packet_count > 0 && self.junk_min_size > self.junk_max_size {
            return Err(WireguardError::InvalidParameters);
        }
        // Custom headers must stay collision-free, otherwise the receiver cannot
        // tell an initiation from a transport packet.
        let headers = [
            self.header_initiation,
            self.header_response,
            self.header_cookie,
            self.header_transport,
        ];
        for i in 0..headers.len() {
            for j in i + 1..headers.len() {
                if headers[i] == headers[j] {
                    return Err(WireguardError::InvalidParameters);
                }
            }
        }
        Ok(())
    }

    /// Junk bytes AmneziaWG prepends to a given handshake message type. Only the
    /// initiation and response are padded; cookie replies are not.
    fn junk_for(&self, kind: u8) -> usize {
        match kind {
            TYPE_INITIATION => self.init_junk_size as usize,
            TYPE_RESPONSE => self.response_junk_size as usize,
            TYPE_COOKIE_REPLY => self.cookie_junk_size as usize,
            TYPE_TRANSPORT => self.transport_junk_size as usize,
            _ => 0,
        }
    }

    /// Type a message the way [`AmneziaParams::obfuscate`] does, without
    /// transforming it.
    ///
    /// Split out so that a caller who owns its buffer and knows the transform is
    /// the identity can skip the copy *without* skipping the check. The refusal
    /// is part of the contract: `obfuscate` rejects a datagram it cannot type,
    /// and a fast path that quietly accepted one would let a malformed message
    /// reach the peer only on vanilla profiles.
    pub fn classify(&self, message: &[u8]) -> Result<u8, WireguardError> {
        let Some(kind) = message_type(message) else {
            return Err(WireguardError::MalformedMessage);
        };
        match kind {
            TYPE_INITIATION | TYPE_RESPONSE | TYPE_COOKIE_REPLY | TYPE_TRANSPORT => Ok(kind),
            _ => Err(WireguardError::UnexpectedMessage),
        }
    }

    /// Obfuscate a freshly encoded handshake message: swap the 4-byte header for
    /// the custom one and prepend the per-type junk. `fill_junk` supplies the
    /// randomness so the transform stays deterministic under test.
    ///
    /// The junk size is taken from the shared parameters, never from the caller,
    /// so the peer can strip exactly as many bytes back off.
    pub fn obfuscate(
        &self,
        message: &[u8],
        fill_junk: impl FnOnce(&mut [u8]),
    ) -> Result<Vec<u8>, WireguardError> {
        let mut out = Vec::new();
        self.obfuscate_into(message, &mut out, fill_junk)?;
        Ok(out)
    }

    /// The same transform into a buffer the caller owns.
    ///
    /// This is the shape the send path uses, so that an obfuscated profile costs
    /// no allocation per packet either: `PeerTunnel` keeps a small set of
    /// datagram buffers and hands one in. `out` is cleared first, so a buffer
    /// that carried a previous datagram is reused rather than grown.
    ///
    /// Only the junk prefix is zeroed, and only so `fill_junk` has something to
    /// write into. Everything after it is appended byte for byte, which on a
    /// vanilla profile — where the prefix is empty — means the whole transform
    /// touches each byte exactly once.
    pub fn obfuscate_into(
        &self,
        message: &[u8],
        out: &mut Vec<u8>,
        fill_junk: impl FnOnce(&mut [u8]),
    ) -> Result<(), WireguardError> {
        let kind = self.classify(message)?;
        let (header, junk_size) = match kind {
            TYPE_INITIATION => (self.header_initiation, self.junk_for(kind)),
            TYPE_RESPONSE => (self.header_response, self.junk_for(kind)),
            TYPE_COOKIE_REPLY => (self.header_cookie, self.junk_for(kind)),
            _ => (self.header_transport, self.junk_for(kind)),
        };
        out.clear();
        out.reserve(junk_size + message.len());
        out.resize(junk_size, 0);
        fill_junk(&mut out[..junk_size]);
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(&message[4..]);
        Ok(())
    }

    /// Recover a standard handshake message from an obfuscated datagram.
    ///
    /// The junk prefix sits *before* the header, so its length cannot be read
    /// from the datagram — it is fixed per type by the shared parameters. Each
    /// candidate type is matched by total length and confirmed by its custom
    /// header, which also disambiguates any length collision.
    pub fn deobfuscate(&self, datagram: &[u8]) -> Result<Vec<u8>, WireguardError> {
        for (kind, body_len, junk_size, header) in [
            (
                TYPE_INITIATION,
                INITIATION_LEN,
                self.init_junk_size as usize,
                self.header_initiation,
            ),
            (
                TYPE_RESPONSE,
                RESPONSE_LEN,
                self.response_junk_size as usize,
                self.header_response,
            ),
            (
                TYPE_COOKIE_REPLY,
                COOKIE_REPLY_LEN,
                self.cookie_junk_size as usize,
                self.header_cookie,
            ),
        ] {
            if datagram.len() != junk_size + body_len {
                continue;
            }
            let body = &datagram[junk_size..];
            let Some(header_bytes) = body.first_chunk::<4>() else {
                continue;
            };
            let got = u32::from_le_bytes(*header_bytes);
            if got != header {
                continue;
            }
            let mut out = vec![0_u8; body_len];
            out[0] = kind;
            out[4..].copy_from_slice(&body[4..]);
            return Ok(out);
        }
        Err(WireguardError::UnexpectedMessage)
    }

    /// Recover a transport datagram: drop the `S4` prefix and swap the custom
    /// header back to the standard transport type.
    ///
    /// Transport frames are variable length, so unlike a handshake there is no
    /// total length to check the prefix against — `S4` has to be taken from the
    /// shared parameters, which is the same rule that already governs `S1`/`S2`.
    pub fn deobfuscate_transport<'a>(
        &self,
        datagram: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireguardError> {
        let junk = self.transport_junk_size as usize;
        if !self.is_transport(datagram) || datagram.len() < junk + 4 {
            return Err(WireguardError::UnexpectedMessage);
        }
        // In place, returning a view rather than a copy. The transform drops a
        // fixed-length prefix and rewrites four bytes, and the receive path is
        // already handed a `&mut [u8]` it owns for exactly this reason — copying
        // the whole datagram into a fresh `Vec` to change four bytes of it was
        // an allocation and a full-length copy on every received packet of an
        // obfuscated tunnel.
        let out = &mut datagram[junk..];
        out[..4].copy_from_slice(&[TYPE_TRANSPORT, 0, 0, 0]);
        Ok(out)
    }

    /// Whether an obfuscated datagram is a transport packet.
    ///
    /// The header sits behind the `S4` prefix, at the same place `S1` puts the
    /// initiation header. With `S4 = 0` this is the offset-zero check plain
    /// WireGuard and AmneziaWG 1.5 both use.
    pub fn is_transport(&self, datagram: &[u8]) -> bool {
        let junk = self.transport_junk_size as usize;
        datagram
            .get(junk..junk + 4)
            .and_then(|bytes| bytes.first_chunk::<4>().copied())
            .map(|bytes| u32::from_le_bytes(bytes) == self.header_transport)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Initiation;

    /// AmneziaWG 2.0 extends the S-prefix to the two message types 1.5 left
    /// alone.
    fn two_point_oh() -> AmneziaParams {
        AmneziaParams {
            init_junk_size: 8,
            response_junk_size: 9,
            cookie_junk_size: 10,
            transport_junk_size: 11,
            header_initiation: 0x1111_1111,
            header_response: 0x2222_2222,
            header_cookie: 0x3333_3333,
            header_transport: 0x4444_4444,
            ..AmneziaParams::default()
        }
    }

    #[test]
    fn s4_puts_the_transport_header_behind_a_prefix_and_takes_it_back_off() {
        let params = two_point_oh();
        // A transport frame: type byte, three zeros, then counter and payload.
        let mut frame = vec![0x04, 0, 0, 0];
        frame.extend_from_slice(&[0xab; 40]);

        let wire = params.obfuscate(&frame, |junk| junk.fill(0x5a)).unwrap();
        assert_eq!(
            wire.len(),
            11 + frame.len(),
            "S4 is a prefix, so the datagram grows by exactly S4"
        );
        assert_eq!(&wire[..11], &[0x5a; 11], "the prefix is junk, not header");
        assert_eq!(
            u32::from_le_bytes(wire[11..15].try_into().unwrap()),
            params.header_transport,
            "H4 sits behind the S4 prefix, where S1 puts H1"
        );
        assert!(
            params.is_transport(&wire),
            "classification has to look behind the prefix or every packet is a handshake"
        );
        let mut wire = wire;
        assert_eq!(params.deobfuscate_transport(&mut wire).unwrap(), frame);
    }

    #[test]
    fn s3_pads_the_cookie_reply_that_1_5_left_bare() {
        let params = two_point_oh();
        let mut cookie = vec![0x03, 0, 0, 0];
        cookie.resize(crate::message::COOKIE_REPLY_LEN, 0x11);

        let wire = params.obfuscate(&cookie, |junk| junk.fill(0x77)).unwrap();
        assert_eq!(wire.len(), 10 + crate::message::COOKIE_REPLY_LEN);
        assert_eq!(params.deobfuscate(&wire).unwrap(), cookie);
    }

    #[test]
    fn a_vanilla_profile_is_untouched_by_the_two_point_oh_fields() {
        // The whole point of the defaults: S3 and S4 at zero must reproduce
        // plain WireGuard byte for byte, including the offset-zero classifier.
        let params = AmneziaParams::default();
        assert!(params.is_vanilla());
        let mut frame = vec![0x04, 0, 0, 0];
        frame.extend_from_slice(&[0x22; 32]);
        let wire = params.obfuscate(&frame, |_| {}).unwrap();
        assert_eq!(wire, frame);
        assert!(params.is_transport(&wire));
        let mut wire = wire;
        assert_eq!(params.deobfuscate_transport(&mut wire).unwrap(), frame);
    }

    #[test]
    fn an_oversized_s3_or_s4_is_refused() {
        for params in [
            AmneziaParams {
                cookie_junk_size: MAX_JUNK_SIZE + 1,
                ..two_point_oh()
            },
            AmneziaParams {
                transport_junk_size: MAX_JUNK_SIZE + 1,
                ..two_point_oh()
            },
        ] {
            assert!(params.validate().is_err());
        }
    }

    fn tuned() -> AmneziaParams {
        AmneziaParams {
            junk_packet_count: 4,
            junk_min_size: 10,
            junk_max_size: 50,
            init_junk_size: 20,
            response_junk_size: 15,
            cookie_junk_size: 0,
            transport_junk_size: 0,
            header_initiation: 0x1000_0001,
            header_response: 0x2000_0002,
            header_cookie: 0x3000_0003,
            header_transport: 0x4000_0004,
        }
    }

    fn sample_initiation() -> Initiation {
        Initiation {
            sender_index: 0xAABB_CCDD,
            ephemeral: [0x11; 32],
            encrypted_static: [0x22; 48],
            encrypted_timestamp: [0x33; 28],
            mac1: [0x44; 16],
            mac2: [0x55; 16],
        }
    }

    #[test]
    fn default_params_are_plain_wireguard() {
        let params = AmneziaParams::default();
        assert!(params.is_vanilla());
        let encoded = sample_initiation().encode();
        let out = params.obfuscate(&encoded, |_| {}).unwrap();
        assert_eq!(out, encoded, "vanilla obfuscation is the identity");
        assert_eq!(params.deobfuscate(&out).unwrap(), encoded);
    }

    #[test]
    fn obfuscation_hides_the_signature_and_round_trips() {
        let params = tuned();
        let encoded = sample_initiation().encode();
        let on_wire = params.obfuscate(&encoded, |junk| junk.fill(0x9A)).unwrap();

        // Junk size comes from the params, and the header is the custom 32-bit
        // value rather than 01 00 00 00.
        assert_eq!(
            on_wire.len(),
            params.init_junk_size as usize + INITIATION_LEN
        );
        assert_eq!(&on_wire[20..24], &0x1000_0001_u32.to_le_bytes());
        assert_ne!(&on_wire[20..24], &[TYPE_INITIATION, 0, 0, 0]);
        assert!(message_type(&on_wire).is_none(), "DPI cannot read a type");

        let recovered = params.deobfuscate(&on_wire).unwrap();
        assert_eq!(recovered, encoded);
        assert_eq!(Initiation::decode(&recovered).unwrap(), sample_initiation());
    }

    #[test]
    fn response_and_cookie_recover_at_their_sizes() {
        let params = tuned();
        for (kind, len) in [
            (TYPE_RESPONSE, RESPONSE_LEN),
            (TYPE_COOKIE_REPLY, COOKIE_REPLY_LEN),
        ] {
            let mut plain = vec![0_u8; len];
            plain[0] = kind;
            for (i, byte) in plain.iter_mut().enumerate().skip(4) {
                *byte = i as u8;
            }
            let on_wire = params.obfuscate(&plain, |junk| junk.fill(1)).unwrap();
            assert_eq!(params.deobfuscate(&on_wire).unwrap(), plain);
        }
    }

    #[test]
    fn transport_header_is_swapped_both_ways() {
        let params = tuned();
        let mut plain = vec![TYPE_TRANSPORT, 0, 0, 0];
        plain.extend_from_slice(&[0xAB; 60]);
        let on_wire = params.obfuscate(&plain, |_| {}).unwrap();
        assert_eq!(on_wire.len(), plain.len(), "transport is never padded");
        assert_eq!(&on_wire[..4], &0x4000_0004_u32.to_le_bytes());
        let mut on_wire = on_wire;
        assert_eq!(params.deobfuscate_transport(&mut on_wire).unwrap(), plain);
    }

    #[test]
    fn transport_is_detected_by_its_custom_header() {
        let params = tuned();
        let mut datagram = 0x4000_0004_u32.to_le_bytes().to_vec();
        datagram.extend_from_slice(&[0; 32]);
        assert!(params.is_transport(&datagram));

        let mut handshake = 0x1000_0001_u32.to_le_bytes().to_vec();
        handshake.extend_from_slice(&[0; 32]);
        assert!(!params.is_transport(&handshake));
        assert!(params.deobfuscate_transport(&mut handshake).is_err());
    }

    #[test]
    fn colliding_headers_are_rejected() {
        let mut params = tuned();
        params.header_transport = params.header_initiation;
        assert!(matches!(
            params.validate(),
            Err(WireguardError::InvalidParameters)
        ));
    }

    #[test]
    fn oversized_or_inverted_junk_is_rejected() {
        let mut params = tuned();
        params.junk_max_size = MAX_JUNK_SIZE + 1;
        assert!(params.validate().is_err());

        let mut params = tuned();
        params.junk_min_size = 60;
        params.junk_max_size = 50;
        assert!(params.validate().is_err());

        let mut params = tuned();
        params.junk_packet_count = 200;
        assert!(params.validate().is_err());
    }

    #[test]
    fn vanilla_params_pass_validation() {
        assert!(AmneziaParams::default().validate().is_ok());
    }

    #[test]
    fn an_unknown_header_fails_closed() {
        let params = tuned();
        let mut datagram = 0xDEAD_BEEF_u32.to_le_bytes().to_vec();
        datagram.extend_from_slice(&[0; INITIATION_LEN]);
        assert!(matches!(
            params.deobfuscate(&datagram),
            Err(WireguardError::UnexpectedMessage)
        ));
    }
}
