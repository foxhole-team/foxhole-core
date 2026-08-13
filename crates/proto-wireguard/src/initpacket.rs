//! AmneziaWG 2.0 `I1..I5` — whole datagrams built from a tag template.
//!
//! Each `I` is a standalone UDP datagram carrying nothing protocol-bearing. The
//! initiator sends them, in order, immediately before the `Jc` junk packets and
//! the padded initiation, on **every** handshake attempt including retries:
//!
//! ```text
//!   I1 … I5  →  Jc junk packets  →  S1-padded MessageInitiation
//! ```
//!
//! Only the initiator emits them. The receiving side never parses them — it
//! drops them as stray UDP — which is why the reference tells you to configure
//! them on the client alone.
//!
//! Cross-checked against `amnezia-vpn/amneziawg-go` `device/obf.go` (the tag
//! table and the parser) plus `device/obf_bytes.go`, `obf_rand.go`,
//! `obf_randchars.go`, `obf_randdigits.go`, `obf_timestamp.go`, `obf_data.go`,
//! `obf_datastring.go`, `obf_datasize.go` (the eight builders), and
//! `device/send.go` `SendHandshakeInitiation` for the emission order.
//!
//! Two things about the tag table are worth stating because secondary sources
//! get them wrong: there are **eight** tags, not five, and `<c>` and `<wt N>`
//! do not exist.

use crate::WireguardError;
use crate::tunnel::Entropy;

/// Letters `<rc N>` draws from, in the reference's order.
const LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8; 10] = b"0123456789";

/// The reference allows five, and the field names are `I1`..`I5`.
pub const MAX_INIT_PACKETS: usize = 5;
/// Ceiling on one rendered datagram. The reference has none; this one exists so
/// a profile cannot make the core build a packet it could never send.
pub const MAX_INIT_PACKET_LEN: usize = 1280;

/// One element of a template.
///
/// A closed set, not a re-parsed string: the spec is parsed exactly once, where
/// the profile is imported, and everything below this point works on the tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitTag {
    /// `<b 0xHEX>` — literal bytes.
    Bytes(Vec<u8>),
    /// `<t>` — Unix seconds as a 4-byte **big-endian** integer.
    Timestamp,
    /// `<r N>` — N bytes from the OS CSPRNG.
    Random(u16),
    /// `<rc N>` — N random ASCII letters.
    RandomLetters(u16),
    /// `<rd N>` — N random ASCII digits.
    RandomDigits(u16),
    /// `<d>` — the chain's payload, verbatim.
    Payload,
    /// `<ds>` — the chain's payload, base64 (raw, unpadded).
    PayloadBase64,
    /// `<dz N>` — the payload's length as an N-byte big-endian integer.
    PayloadSize(u16),
}

impl InitTag {
    /// Bytes this tag contributes to an init packet.
    ///
    /// `Payload` and `PayloadBase64` contribute **nothing** here, and that is
    /// the reference's own behaviour rather than a simplification: an init
    /// packet is obfuscated with a nil source (`device/send.go`), so the two
    /// tags that encode the source encode zero bytes. `PayloadSize` still emits
    /// its N bytes — they just spell out the number zero.
    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Timestamp => 4,
            Self::Random(len) | Self::RandomLetters(len) | Self::RandomDigits(len) => {
                usize::from(*len)
            }
            Self::Payload | Self::PayloadBase64 => 0,
            Self::PayloadSize(len) => usize::from(*len),
        }
    }

    fn render(
        &self,
        out: &mut Vec<u8>,
        now_unix: u32,
        entropy: &mut dyn Entropy,
    ) -> Result<(), WireguardError> {
        match self {
            Self::Bytes(bytes) => out.extend_from_slice(bytes),
            Self::Timestamp => out.extend_from_slice(&now_unix.to_be_bytes()),
            Self::Random(len) => {
                let start = out.len();
                out.resize(start + usize::from(*len), 0);
                entropy.fill(&mut out[start..])?;
            }
            Self::RandomLetters(len) => render_alphabet(out, *len, LETTERS, entropy)?,
            Self::RandomDigits(len) => render_alphabet(out, *len, DIGITS, entropy)?,
            Self::Payload | Self::PayloadBase64 => {}
            // An init packet has no payload, so the encoded length is zero.
            Self::PayloadSize(len) => out.resize(out.len() + usize::from(*len), 0),
        }
        Ok(())
    }
}

/// Draw `len` bytes and fold each into `alphabet`, the way the reference does
/// (`dst[i] = alphabet[dst[i] % alphabet.len()]`). The modulo bias is the
/// reference's; reproducing it matters more than fixing it, because the point is
/// to look like what the peer's other clients look like.
fn render_alphabet(
    out: &mut Vec<u8>,
    len: u16,
    alphabet: &[u8],
    entropy: &mut dyn Entropy,
) -> Result<(), WireguardError> {
    let start = out.len();
    out.resize(start + usize::from(len), 0);
    entropy.fill(&mut out[start..])?;
    for byte in &mut out[start..] {
        *byte = alphabet[usize::from(*byte) % alphabet.len()];
    }
    Ok(())
}

/// One `I` template.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitPacket {
    tags: Vec<InitTag>,
}

impl InitPacket {
    pub fn new(tags: Vec<InitTag>) -> Result<Self, WireguardError> {
        let packet = Self { tags };
        if packet.len() > MAX_INIT_PACKET_LEN {
            return Err(WireguardError::InvalidParameters);
        }
        Ok(packet)
    }

    pub fn tags(&self) -> &[InitTag] {
        &self.tags
    }

    /// Size of the datagram this template produces. Fixed: every tag's width is
    /// known before rendering.
    pub fn len(&self) -> usize {
        self.tags.iter().map(InitTag::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build the datagram. `now_unix` is passed in rather than read here so a
    /// golden vector can pin `<t>`.
    pub fn render(
        &self,
        now_unix: u32,
        entropy: &mut dyn Entropy,
    ) -> Result<Vec<u8>, WireguardError> {
        let mut out = Vec::with_capacity(self.len());
        for tag in &self.tags {
            tag.render(&mut out, now_unix, entropy)?;
        }
        Ok(out)
    }

    /// Parse a template in the reference's `<key arg>` syntax.
    ///
    /// Faithful to `newObfChain` in two ways that look like bugs and are not:
    /// text **outside** the angle brackets is discarded without complaint, and
    /// an unknown key is a hard error rather than a skipped element. The second
    /// is what keeps a typo from quietly shortening the packet.
    pub fn parse(spec: &str) -> Result<Self, WireguardError> {
        let mut tags = Vec::new();
        let mut rest = spec;
        while let Some(start) = rest.find('<') {
            let Some(end) = rest[start..].find('>') else {
                return Err(WireguardError::InvalidParameters);
            };
            let body = &rest[start + 1..start + end];
            rest = &rest[start + end + 1..];
            let mut fields = body.split_whitespace();
            let Some(key) = fields.next() else {
                return Err(WireguardError::InvalidParameters);
            };
            let argument = fields.next().unwrap_or_default();
            tags.push(parse_tag(key, argument)?);
        }
        Self::new(tags)
    }
}

fn parse_tag(key: &str, argument: &str) -> Result<InitTag, WireguardError> {
    let count = || {
        argument
            .parse::<u16>()
            .map_err(|_| WireguardError::InvalidParameters)
    };
    match key {
        "b" => Ok(InitTag::Bytes(decode_hex(argument)?)),
        "t" => Ok(InitTag::Timestamp),
        "r" => Ok(InitTag::Random(count()?)),
        "rc" => Ok(InitTag::RandomLetters(count()?)),
        "rd" => Ok(InitTag::RandomDigits(count()?)),
        "d" => Ok(InitTag::Payload),
        "ds" => Ok(InitTag::PayloadBase64),
        "dz" => Ok(InitTag::PayloadSize(count()?)),
        _ => Err(WireguardError::InvalidParameters),
    }
}

/// `0x`-prefixed or bare hex, even length — the reference refuses an odd count
/// rather than padding it, and so does this.
fn decode_hex(value: &str) -> Result<Vec<u8>, WireguardError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(WireguardError::InvalidParameters);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| WireguardError::InvalidParameters)?;
            u8::from_str_radix(text, 16).map_err(|_| WireguardError::InvalidParameters)
        })
        .collect()
}

/// Render a template as the reference would write it. Used by config round-trip
/// and by diagnostics; never by the datapath.
pub fn render_spec(packet: &InitPacket) -> String {
    let mut spec = String::new();
    for tag in packet.tags() {
        match tag {
            InitTag::Bytes(bytes) => {
                spec.push_str("<b 0x");
                for byte in bytes {
                    spec.push_str(&format!("{byte:02x}"));
                }
                spec.push('>');
            }
            InitTag::Timestamp => spec.push_str("<t>"),
            InitTag::Random(len) => spec.push_str(&format!("<r {len}>")),
            InitTag::RandomLetters(len) => spec.push_str(&format!("<rc {len}>")),
            InitTag::RandomDigits(len) => spec.push_str(&format!("<rd {len}>")),
            InitTag::Payload => spec.push_str("<d>"),
            InitTag::PayloadBase64 => spec.push_str("<ds>"),
            InitTag::PayloadSize(len) => spec.push_str(&format!("<dz {len}>")),
        }
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts up from a seed so a rendered packet is reproducible.
    struct Counter(u8);

    impl Entropy for Counter {
        fn fill(&mut self, buffer: &mut [u8]) -> Result<(), WireguardError> {
            for byte in buffer {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn the_reference_example_is_a_golden_vector() {
        // `<b 0xc00000000108><r 32><t>` — six literal bytes, 32 random, four of
        // timestamp: 42 bytes, which is what the reference's own example builds.
        let packet = InitPacket::parse("<b 0xc00000000108><r 32><t>").unwrap();
        assert_eq!(packet.len(), 42);

        let rendered = packet.render(0x6543_2100, &mut Counter(0)).unwrap();
        assert_eq!(&rendered[..6], &[0xc0, 0x00, 0x00, 0x00, 0x01, 0x08]);
        assert_eq!(&rendered[6..38], &(0..32).collect::<Vec<u8>>()[..]);
        assert_eq!(
            &rendered[38..],
            &[0x65, 0x43, 0x21, 0x00],
            "the timestamp is big endian"
        );
        assert_eq!(rendered.len(), 42);
    }

    #[test]
    fn every_tag_contributes_the_width_the_reference_gives_it() {
        let packet = InitPacket::parse("<b 0xff><t><r 3><rc 4><rd 5><d><ds><dz 2>").unwrap();
        // 1 + 4 + 3 + 4 + 5 + 0 + 0 + 2
        assert_eq!(packet.len(), 19);
        let rendered = packet.render(1, &mut Counter(0)).unwrap();
        assert_eq!(rendered.len(), 19);
        assert_eq!(
            &rendered[17..],
            &[0, 0],
            "an init packet has no payload, so <dz> spells out zero"
        );
    }

    #[test]
    fn random_letters_and_digits_stay_inside_their_alphabets() {
        let packet = InitPacket::parse("<rc 64><rd 64>").unwrap();
        let rendered = packet.render(0, &mut Counter(0)).unwrap();
        assert!(rendered[..64].iter().all(|byte| byte.is_ascii_alphabetic()));
        assert!(rendered[64..].iter().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn text_outside_the_brackets_is_ignored_and_a_bad_tag_is_refused() {
        // The reference discards anything not inside <>, so a template that
        // looks like it carries a literal prefix does not.
        let packet = InitPacket::parse("GET / HTTP/1.1<b 0xaa>").unwrap();
        assert_eq!(packet.tags(), &[InitTag::Bytes(vec![0xaa])]);

        // An unknown key is an error, not a skipped element: silently dropping
        // it would shorten every packet the profile meant to send.
        assert!(InitPacket::parse("<b 0xaa><zz 4>").is_err());
        assert!(InitPacket::parse("<c>").is_err(), "<c> does not exist");
        assert!(InitPacket::parse("<wt 4>").is_err(), "<wt> does not exist");
        // An unclosed tag is malformed rather than ignored.
        assert!(InitPacket::parse("<b 0xaa").is_err());
    }

    #[test]
    fn odd_hex_is_refused_rather_than_padded() {
        assert!(InitPacket::parse("<b 0xaaa>").is_err());
        assert!(InitPacket::parse("<b >").is_err());
        assert!(InitPacket::parse("<b 0xzz>").is_err());
        // The 0x prefix is optional, as in the reference.
        assert_eq!(
            InitPacket::parse("<b aabb>").unwrap().tags(),
            &[InitTag::Bytes(vec![0xaa, 0xbb])]
        );
    }

    #[test]
    fn a_template_that_cannot_fit_a_datagram_is_refused() {
        let huge = format!("<r {}>", MAX_INIT_PACKET_LEN + 1);
        assert!(InitPacket::parse(&huge).is_err());
    }

    #[test]
    fn a_spec_round_trips_through_the_typed_form() {
        let spec = "<b 0xc00000000108><r 32><rc 3><rd 4><dz 2><t>";
        let packet = InitPacket::parse(spec).unwrap();
        assert_eq!(render_spec(&packet), spec);
        assert_eq!(InitPacket::parse(&render_spec(&packet)).unwrap(), packet);
    }
}
