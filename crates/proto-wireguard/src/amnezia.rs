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
//!   32-bit values — or, since AmneziaWG 2.0, with an inclusive *range* of them
//!   ([`HeaderRange`]) — erasing the `01/02/03/04 00 00 00` signature.
//!
//! The obfuscation is symmetric: both peers share the same parameters, so a
//! sealed handshake is just a standard one with a different header and a junk
//! prefix. This module is parameters + transforms only; it performs no I/O.

use crate::WireguardError;
use crate::message::{
    COOKIE_REPLY_LEN, INITIATION_LEN, RESPONSE_LEN, TYPE_COOKIE_REPLY, TYPE_INITIATION,
    TYPE_RESPONSE, TYPE_TRANSPORT, message_type,
};

/// One `H1..H4` value: a closed interval of 32-bit headers.
///
/// AmneziaWG 1.5 gave each message type one fixed replacement header. 2.0 made
/// it a range, and the upstream server generator emits ranges *by default*
/// (`H1 = 234567-345678`), so this is the ordinary shape rather than the exotic
/// one. The reference is `u32_range_t` in the kernel module's `src/type.h`:
///
/// * the sender draws a fresh value per datagram
///   (`u32_range_pick_one` → `get_random_u32_inclusive(lo, hi)`, called from
///   `send.c` on every initiation, response, cookie reply and data packet);
/// * the receiver accepts anything the interval contains
///   (`u32_range_contains`, `receive.c`);
/// * both bounds are inclusive, and `hi < lo` is rejected at parse time;
/// * two ranges may not overlap, because the interval is what tells the
///   receiver which of the four message types arrived.
///
/// A single value is the degenerate range `lo == hi`, which is exactly how the
/// reference stores a 1.5 profile — so this one type covers both versions and
/// there is no second code path to keep in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRange {
    start: u32,
    end: u32,
}

impl HeaderRange {
    /// The 1.5 form: one header, stored as the interval `[value, value]`.
    pub const fn single(value: u32) -> Self {
        Self {
            start: value,
            end: value,
        }
    }

    /// `start..=end`, or `None` when the bounds are inverted — the same refusal
    /// `u32_range_from_string` makes on `hi < lo`.
    pub const fn new(start: u32, end: u32) -> Option<Self> {
        if end < start {
            return None;
        }
        Some(Self { start, end })
    }

    pub const fn start(&self) -> u32 {
        self.start
    }

    pub const fn end(&self) -> u32 {
        self.end
    }

    /// Whether this interval names exactly one header, i.e. is a 1.5 value.
    pub const fn is_single(&self) -> bool {
        self.start == self.end
    }

    /// Inclusive both ends, mirroring `u32_range_contains`.
    pub const fn contains(&self, value: u32) -> bool {
        self.start <= value && value <= self.end
    }

    /// Mirrors `u32_range_overlap`. Two intervals that share any header make the
    /// message types ambiguous on the wire.
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// The header to put on one datagram, given a raw 32-bit draw.
    ///
    /// Randomness is the caller's — this crate takes all of it through
    /// [`crate::tunnel::Entropy`] so a test can pin it — and a single-valued
    /// range never consults it at all, which is what keeps a 1.5 or vanilla
    /// profile byte-identical to what it was before ranges existed.
    ///
    /// The reduction is `%` over a `u64` span, the same idiom the junk-size draw
    /// already uses. It is very slightly biased towards the low end of a span
    /// that does not divide 2^32; the value is a DPI decoy rather than a secret,
    /// and the reference's own `get_random_u32_inclusive` is a rejection loop
    /// this crate has no reason to reproduce.
    pub const fn pick(&self, draw: u32) -> u32 {
        if self.start == self.end {
            return self.start;
        }
        let span = (self.end as u64) - (self.start as u64) + 1;
        (self.start as u64 + (draw as u64) % span) as u32
    }
}

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
    /// Replacement 32-bit header for each message type. A 1.5 profile carries
    /// four single-valued ranges; a 2.0 one carries intervals.
    pub header_initiation: HeaderRange,
    pub header_response: HeaderRange,
    pub header_cookie: HeaderRange,
    pub header_transport: HeaderRange,
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
            header_initiation: HeaderRange::single(TYPE_INITIATION as u32),
            header_response: HeaderRange::single(TYPE_RESPONSE as u32),
            header_cookie: HeaderRange::single(TYPE_COOKIE_REPLY as u32),
            header_transport: HeaderRange::single(TYPE_TRANSPORT as u32),
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
        // `Jc = 4, Jmax = 0` passes every bound above and asks
        // `render_junk_packets` for four empty buffers, which reach the socket as
        // zero-length UDP datagrams. That is the junk-path twin of
        // amnezia-vpn/amneziawg-go#141, and a datagram with no payload is a
        // signature of its own: no WireGuard message type can be that short, so
        // it names the sender to anyone counting packet sizes. `render_init_packets`
        // drops a zero-width `I` template for the same reason; there is no
        // equivalent skip here, because junk with no size is not junk.
        if self.junk_packet_count > 0 && self.junk_max_size == 0 {
            return Err(WireguardError::InvalidParameters);
        }
        // Custom headers must stay collision-free, otherwise the receiver cannot
        // tell an initiation from a transport packet. With ranges the test is
        // overlap rather than equality — two intervals that share a single
        // header are ambiguous for exactly the datagrams that draw it, which is
        // an intermittent failure rather than a clean one. `netlink.c` refuses
        // the same way, and it refuses `H1` against all three others rather
        // than only its neighbour.
        let headers = [
            self.header_initiation,
            self.header_response,
            self.header_cookie,
            self.header_transport,
        ];
        for i in 0..headers.len() {
            for j in i + 1..headers.len() {
                if headers[i].overlaps(&headers[j]) {
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

    /// Whether these four header bytes name a header in `expected`.
    ///
    /// Containment on an obfuscated profile: `H1..H4` replace the whole 32-bit
    /// word, so every bit of it is signal, and on a 2.0 profile the peer draws a
    /// fresh value inside the interval for each datagram. A word outside the
    /// interval is not our peer. (For a 1.5 profile the interval holds one
    /// value, so this is the exact comparison it has always been.)
    ///
    /// Type-byte only on a vanilla one. The upper three bytes are then
    /// WireGuard's reserved field, which [`crate::message`] already ignores
    /// everywhere it decodes (`message_kind`) and which some providers use as a
    /// client identifier they stamp on what they send back. Comparing the whole
    /// word here refused those datagrams *before* any decoder saw them, so the
    /// leniency one layer down was unreachable: the handshake response was
    /// dropped, and on a peer that stamps only data frames the tunnel came up,
    /// counted bytes out, and delivered nothing to the tun. Nothing is weakened
    /// by accepting them — what proves a datagram genuine is its AEAD tag or its
    /// `mac1`, neither of which covers these three bytes.
    fn header_matches(&self, header: [u8; 4], expected: HeaderRange) -> bool {
        if self.is_vanilla() {
            header[0] == expected.start() as u8
        } else {
            expected.contains(u32::from_le_bytes(header))
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
    /// the custom one and prepend the per-type junk. `random` supplies every
    /// byte of randomness the transform needs so it stays deterministic under
    /// test.
    ///
    /// The junk size is taken from the shared parameters, never from the caller,
    /// so the peer can strip exactly as many bytes back off.
    pub fn obfuscate(
        &self,
        message: &[u8],
        random: impl FnMut(&mut [u8]),
    ) -> Result<Vec<u8>, WireguardError> {
        let mut out = Vec::new();
        self.obfuscate_into(message, &mut out, random)?;
        Ok(out)
    }

    /// The same transform into a buffer the caller owns.
    ///
    /// This is the shape the send path uses, so that an obfuscated profile costs
    /// no allocation per packet either: `PeerTunnel` keeps a small set of
    /// datagram buffers and hands one in. `out` is cleared first, so a buffer
    /// that carried a previous datagram is reused rather than grown.
    ///
    /// Only the junk prefix is zeroed, and only so `random` has something to
    /// write into. Everything after it is appended byte for byte, which on a
    /// vanilla profile — where the prefix is empty — means the whole transform
    /// touches each byte exactly once.
    ///
    /// `random` is asked for the header draw only when the range holds more than
    /// one header. A 1.5 or vanilla profile therefore consumes exactly the
    /// entropy it always did, and its output is byte-identical to what it was
    /// before ranges existed.
    pub fn obfuscate_into(
        &self,
        message: &[u8],
        out: &mut Vec<u8>,
        mut random: impl FnMut(&mut [u8]),
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
        random(&mut out[..junk_size]);
        // One draw per datagram, which is what `send.c` does: the interval is a
        // moving target for a DPI rule only if the value actually moves.
        let header = if header.is_single() {
            header.start()
        } else {
            let mut draw = [0_u8; 4];
            random(&mut draw);
            header.pick(u32::from_le_bytes(draw))
        };
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
            if !self.header_matches(*header_bytes, header) {
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
            .is_some_and(|bytes| self.header_matches(bytes, self.header_transport))
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
            header_initiation: HeaderRange::single(0x1111_1111),
            header_response: HeaderRange::single(0x2222_2222),
            header_cookie: HeaderRange::single(0x3333_3333),
            header_transport: HeaderRange::single(0x4444_4444),
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
            params.header_transport.start(),
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
            header_initiation: HeaderRange::single(0x1000_0001),
            header_response: HeaderRange::single(0x2000_0002),
            header_cookie: HeaderRange::single(0x3000_0003),
            header_transport: HeaderRange::single(0x4000_0004),
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

    /// On a vanilla profile the upper three header bytes are WireGuard's
    /// reserved field: a receiver is told to ignore them, and a provider that
    /// uses them as a client identifier stamps them on what it sends back.
    /// Classifying on the whole word dropped those datagrams before any decoder
    /// could apply the leniency it already had.
    #[test]
    fn a_vanilla_profile_reads_a_type_through_stamped_reserved_bytes() {
        let params = AmneziaParams::default();

        let mut transport = vec![TYPE_TRANSPORT, 0x11, 0x22, 0x33];
        transport.extend_from_slice(&[0xAB; 32]);
        assert!(params.is_transport(&transport));

        let mut response = vec![TYPE_RESPONSE, 0x11, 0x22, 0x33];
        response.resize(RESPONSE_LEN, 0x5A);
        let recovered = params.deobfuscate(&response).unwrap();
        assert_eq!(
            &recovered[..4],
            &[TYPE_RESPONSE, 0, 0, 0],
            "the message handed on is the canonical one, not the stamped bytes"
        );
        assert_eq!(&recovered[4..], &response[4..]);
    }

    /// And the leniency stops there. With `H1..H4` configured the header is a
    /// 32-bit value the peers agreed on, so a word that differs only in the
    /// bytes plain WireGuard calls reserved is not this peer's — accepting it
    /// would turn a custom header into eight bits of signal instead of
    /// thirty-two.
    #[test]
    fn an_obfuscated_profile_still_matches_the_whole_header_word() {
        let params = tuned();
        let mut datagram = params.header_transport.start().to_le_bytes().to_vec();
        datagram.extend_from_slice(&[0; 32]);
        assert!(params.is_transport(&datagram));

        datagram[1] ^= 0xFF;
        assert!(!params.is_transport(&datagram));
        assert!(params.deobfuscate_transport(&mut datagram).is_err());
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

    /// AmneziaWG 2.0 headers are intervals, and the upstream server generator
    /// emits them by default. A range profile has to work in three places at
    /// once: the sender draws inside the interval, the receiver accepts anything
    /// inside it, and nothing outside it is ours.
    fn ranged() -> AmneziaParams {
        AmneziaParams {
            header_initiation: HeaderRange::new(234_567, 345_678).unwrap(),
            header_response: HeaderRange::new(400_000, 500_000).unwrap(),
            header_cookie: HeaderRange::new(600_000, 700_000).unwrap(),
            header_transport: HeaderRange::new(800_000, 900_000).unwrap(),
            ..AmneziaParams::default()
        }
    }

    #[test]
    fn a_ranged_header_is_drawn_inside_the_interval_and_moves_between_datagrams() {
        let params = ranged();
        assert!(params.validate().is_ok(), "a range profile is a valid one");

        let mut plain = vec![TYPE_TRANSPORT, 0, 0, 0];
        plain.extend_from_slice(&[0xAB; 32]);

        // Two different draws, so two different headers — this is the property a
        // fixed value cannot have and the whole reason 2.0 introduced ranges.
        let mut draws = [0x00_u8, 0x01_u8].into_iter();
        let mut seen = Vec::new();
        for _ in 0..2 {
            let byte = draws.next().unwrap();
            let wire = params.obfuscate(&plain, |bytes| bytes.fill(byte)).unwrap();
            let header = u32::from_le_bytes(wire[..4].try_into().unwrap());
            assert!(
                params.header_transport.contains(header),
                "a drawn header must lie inside H4"
            );
            assert!(
                params.is_transport(&wire),
                "and the receiver must recognise every value it can draw"
            );
            seen.push(header);
        }
        assert_ne!(
            seen[0], seen[1],
            "a range that always produced one value would be a constant, \
             which is exactly the collapse this must not do"
        );
    }

    #[test]
    fn every_header_in_the_range_is_accepted_and_every_header_outside_it_is_not() {
        let params = ranged();
        for value in [234_567_u32, 290_000, 345_678] {
            let mut datagram = value.to_le_bytes().to_vec();
            datagram.resize(INITIATION_LEN, 0x5A);
            assert!(
                params.deobfuscate(&datagram).is_ok(),
                "{value} is inside H1 and must open"
            );
        }
        for value in [234_566_u32, 345_679] {
            let mut datagram = value.to_le_bytes().to_vec();
            datagram.resize(INITIATION_LEN, 0x5A);
            assert!(
                params.deobfuscate(&datagram).is_err(),
                "{value} is one step outside H1 and is not this peer's"
            );
        }
    }

    #[test]
    fn overlapping_ranges_are_refused_because_the_types_would_be_ambiguous() {
        let mut params = ranged();
        // One shared header is enough: the datagrams that draw it are
        // undecodable, which is an intermittent fault rather than a clean one.
        params.header_response = HeaderRange::new(345_678, 500_000).unwrap();
        assert!(matches!(
            params.validate(),
            Err(WireguardError::InvalidParameters)
        ));
    }

    #[test]
    fn an_inverted_range_has_no_representation() {
        assert!(HeaderRange::new(345_678, 234_567).is_none());
        assert_eq!(HeaderRange::new(7, 7), Some(HeaderRange::single(7)));
    }

    #[test]
    fn a_draw_lands_in_the_interval_for_every_corner_of_the_word() {
        let full = HeaderRange::new(0, u32::MAX).unwrap();
        for draw in [0, 1, u32::MAX / 2, u32::MAX] {
            assert!(full.contains(full.pick(draw)));
        }
        let narrow = HeaderRange::new(10, 11).unwrap();
        assert_eq!(narrow.pick(0), 10);
        assert_eq!(narrow.pick(1), 11);
        assert_eq!(narrow.pick(u32::MAX), 11);
        assert_eq!(
            HeaderRange::single(4).pick(u32::MAX),
            4,
            "a single value never consults the draw"
        );
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

    /// The junk-path twin of amnezia-vpn/amneziawg-go#141. `Jc` with `Jmax = 0`
    /// satisfies every other bound and would hand `render_junk_packets` empty
    /// buffers, so the socket would carry zero-length UDP datagrams — a length no
    /// WireGuard message type has, which identifies the sender rather than hiding
    /// it. Refused here because this is the layer that emits.
    #[test]
    fn junk_packets_that_would_be_empty_are_rejected() {
        let mut params = tuned();
        params.junk_packet_count = 4;
        params.junk_min_size = 0;
        params.junk_max_size = 0;
        assert!(params.validate().is_err());

        // A single byte is enough to be a packet, so the bound is `> 0` and not a
        // minimum size this crate invented.
        params.junk_max_size = 1;
        assert!(params.validate().is_ok());

        // And `Jc = 0` never reads `Jmax`, so it must not trip the same check.
        params.junk_packet_count = 0;
        params.junk_max_size = 0;
        assert!(params.validate().is_ok());
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
