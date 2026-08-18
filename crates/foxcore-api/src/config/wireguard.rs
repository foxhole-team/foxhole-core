use super::*;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::SecretString;

/// WireGuard / AmneziaWG peer settings for the L3 packet-tunnel path.
///
/// Keys stay in `SecretString` so they are redacted in `Debug` and zeroized on
/// drop; the peer public key is included because an unpublished endpoint key is
/// as identifying as the endpoint itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    /// Base64 X25519 private key of this client.
    pub private_key: SecretString,
    /// Base64 X25519 public key of the remote peer.
    pub peer_public_key: SecretString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<SecretString>,
    /// Interface addresses assigned by the peer, e.g. `10.8.0.2/32`.
    pub address: Vec<IpNet>,
    /// Destination prefixes the peer accepts. Required: an implicit default
    /// route would silently widen or narrow what the profile asked for.
    pub allowed_ips: Vec<IpNet>,
    #[serde(default = "default_wireguard_mtu")]
    pub mtu: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_s: Option<u16>,
    /// The three reserved bytes of the datagram header.
    ///
    /// The protocol calls them reserved, but some providers use them as a client
    /// identifier and drop datagrams that arrive with zeros. Absent means send
    /// zeros; the core never invents a value the profile did not give.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,
    /// AmneziaWG obfuscation. Absent means plain WireGuard on the wire; the
    /// core never invents obfuscation the profile did not ask for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amnezia: Option<AmneziaConfig>,
}

/// AmneziaWG `Jc/Jmin/Jmax/S1/S2/H1..H4` in typed form.
///
/// Every default reproduces standard WireGuard byte-for-byte, so an incomplete
/// block degrades to vanilla rather than to some half-obfuscated shape the peer
/// cannot decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmneziaConfig {
    /// `Jc`: junk packets sent before the handshake.
    #[serde(default)]
    pub junk_packet_count: u16,
    /// `Jmin`/`Jmax`: inclusive size bounds of each junk packet.
    #[serde(default)]
    pub junk_min_size: u16,
    #[serde(default)]
    pub junk_max_size: u16,
    /// `S1`/`S2`: junk prepended to the initiation and response messages.
    #[serde(default)]
    pub init_junk_size: u16,
    #[serde(default)]
    pub response_junk_size: u16,
    /// `S3`/`S4` (AmneziaWG 2.0): the same prefix on cookie replies and on
    /// transport packets. Zero is 1.5 behaviour, which is also plain WireGuard
    /// for these two message types.
    #[serde(default)]
    pub cookie_junk_size: u16,
    #[serde(default)]
    pub transport_junk_size: u16,
    /// `I1..I5` (AmneziaWG 2.0): whole datagrams sent ahead of every handshake
    /// attempt, built from a tag template.
    ///
    /// Typed rather than the reference's `<b 0x…><r 32><t>` string: a template
    /// re-parsed at each layer eventually gets parsed differently by one of
    /// them, and the failure mode is a packet that is silently the wrong length.
    /// The string form is parsed exactly once, where the profile is imported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init_packets: Vec<AmneziaInitPacket>,
    #[serde(default, skip_serializing_if = "AmneziaTimers::is_default")]
    pub timers: AmneziaTimers,
    /// `H1..H4`: replacement 32-bit message headers.
    #[serde(default = "default_header_initiation")]
    pub header_initiation: AmneziaHeaderRange,
    #[serde(default = "default_header_response")]
    pub header_response: AmneziaHeaderRange,
    #[serde(default = "default_header_cookie")]
    pub header_cookie: AmneziaHeaderRange,
    #[serde(default = "default_header_transport")]
    pub header_transport: AmneziaHeaderRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmneziaTimers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_timeout_s: Option<AmneziaTimerRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_after_time_s: Option<AmneziaTimerRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_after_time_s: Option<AmneziaTimerRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_timeout_s: Option<AmneziaTimerRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_handshake_attempts: Option<AmneziaTimerRange>,
}

impl AmneziaTimers {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AmneziaTimerRangeRepr", into = "AmneziaTimerRangeRepr")]
pub struct AmneziaTimerRange {
    pub start: u16,
    pub end: u16,
}

impl AmneziaTimerRange {
    pub const fn single(value: u16) -> Self {
        Self {
            start: value,
            end: value,
        }
    }

    pub const fn new(start: u16, end: u16) -> Option<Self> {
        if end < start {
            return None;
        }
        Some(Self { start, end })
    }

    pub const fn is_single(&self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AmneziaTimerRangeRepr {
    Single(u16),
    Range(String),
}

impl From<AmneziaTimerRange> for AmneziaTimerRangeRepr {
    fn from(value: AmneziaTimerRange) -> Self {
        if value.is_single() {
            Self::Single(value.start)
        } else {
            Self::Range(format!("{}-{}", value.start, value.end))
        }
    }
}

impl TryFrom<AmneziaTimerRangeRepr> for AmneziaTimerRange {
    type Error = String;

    fn try_from(value: AmneziaTimerRangeRepr) -> Result<Self, Self::Error> {
        match value {
            AmneziaTimerRangeRepr::Single(value) => Ok(Self::single(value)),
            AmneziaTimerRangeRepr::Range(text) => parse_amnezia_timer_range(&text),
        }
    }
}

pub fn parse_amnezia_timer_range(text: &str) -> Result<AmneziaTimerRange, String> {
    let malformed = || format!("AmneziaWG timer must be N or N-M seconds, got {text}");
    match text.split_once('-') {
        None => text
            .parse::<u16>()
            .map(AmneziaTimerRange::single)
            .map_err(|_| malformed()),
        Some((low, high)) => {
            let start = low.parse::<u16>().map_err(|_| malformed())?;
            let end = high.parse::<u16>().map_err(|_| malformed())?;
            AmneziaTimerRange::new(start, end)
                .ok_or_else(|| format!("AmneziaWG timer range {text} ends before it starts"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AmneziaHeaderRangeRepr", into = "AmneziaHeaderRangeRepr")]
pub struct AmneziaHeaderRange {
    pub start: u32,
    pub end: u32,
}

impl AmneziaHeaderRange {
    pub const fn single(value: u32) -> Self {
        Self {
            start: value,
            end: value,
        }
    }

    pub const fn new(start: u32, end: u32) -> Option<Self> {
        if end < start {
            return None;
        }
        Some(Self { start, end })
    }

    pub const fn is_single(&self) -> bool {
        self.start == self.end
    }

    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AmneziaHeaderRangeRepr {
    Single(u32),
    Range(String),
}

impl From<AmneziaHeaderRange> for AmneziaHeaderRangeRepr {
    fn from(value: AmneziaHeaderRange) -> Self {
        if value.is_single() {
            Self::Single(value.start)
        } else {
            Self::Range(format!("{}-{}", value.start, value.end))
        }
    }
}

impl TryFrom<AmneziaHeaderRangeRepr> for AmneziaHeaderRange {
    type Error = String;

    fn try_from(value: AmneziaHeaderRangeRepr) -> Result<Self, Self::Error> {
        match value {
            AmneziaHeaderRangeRepr::Single(value) => Ok(Self::single(value)),
            AmneziaHeaderRangeRepr::Range(text) => parse_amnezia_header_range(&text),
        }
    }
}

pub fn parse_amnezia_header_range(text: &str) -> Result<AmneziaHeaderRange, String> {
    let malformed = || format!("AmneziaWG header must be N or N-M, got {text}");
    match text.split_once('-') {
        None => text
            .parse::<u32>()
            .map(AmneziaHeaderRange::single)
            .map_err(|_| malformed()),
        Some((low, high)) => {
            let start = low.parse::<u32>().map_err(|_| malformed())?;
            let end = high.parse::<u32>().map_err(|_| malformed())?;
            AmneziaHeaderRange::new(start, end)
                .ok_or_else(|| format!("AmneziaWG header range {text} ends before it starts"))
        }
    }
}

/// One `I1..I5` template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AmneziaInitPacket {
    pub tags: Vec<AmneziaInitTag>,
}

/// One element of an `I` template. A closed set: the reference registers eight
/// tags and exactly eight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", rename_all = "snake_case", deny_unknown_fields)]
pub enum AmneziaInitTag {
    /// `<b 0xHEX>` — literal bytes, written as an even-length hex string.
    Bytes { hex: String },
    /// `<t>` — Unix seconds, four bytes big endian.
    Timestamp,
    /// `<r N>` — N random bytes.
    Random { len: u16 },
    /// `<rc N>` — N random ASCII letters.
    RandomLetters { len: u16 },
    /// `<rd N>` — N random ASCII digits.
    RandomDigits { len: u16 },
    /// `<d>` — the chain's payload. An init packet has none, so this emits
    /// nothing; it is kept so a template round-trips to the form the provider
    /// wrote.
    Payload,
    /// `<ds>` — the payload, base64. Emits nothing here, for the same reason.
    PayloadBase64,
    /// `<dz N>` — the payload length as an N-byte big-endian integer. Emits N
    /// bytes spelling zero.
    PayloadSize { len: u16 },
}

impl Default for AmneziaConfig {
    fn default() -> Self {
        Self {
            junk_packet_count: 0,
            junk_min_size: 0,
            junk_max_size: 0,
            init_junk_size: 0,
            response_junk_size: 0,
            cookie_junk_size: 0,
            transport_junk_size: 0,
            init_packets: Vec::new(),
            timers: AmneziaTimers::default(),
            header_initiation: default_header_initiation(),
            header_response: default_header_response(),
            header_cookie: default_header_cookie(),
            header_transport: default_header_transport(),
        }
    }
}

const fn default_header_initiation() -> AmneziaHeaderRange {
    AmneziaHeaderRange::single(1)
}

const fn default_header_response() -> AmneziaHeaderRange {
    AmneziaHeaderRange::single(2)
}

const fn default_header_cookie() -> AmneziaHeaderRange {
    AmneziaHeaderRange::single(3)
}

const fn default_header_transport() -> AmneziaHeaderRange {
    AmneziaHeaderRange::single(4)
}

/// Mirror of `proto_wireguard::amnezia::MAX_JUNK_SIZE`. `foxcore-api` cannot
/// depend on a protocol crate, so the bound is asserted against the wire
/// implementation by a test in the outbound builder instead.
const MAX_AMNEZIA_JUNK_SIZE: u16 = 1280;
const MAX_AMNEZIA_JUNK_PACKET_COUNT: u16 = 128;
/// The reference names them I1..I5 and stops there.
const MAX_AMNEZIA_INIT_PACKETS: usize = 5;

impl AmneziaConfig {
    pub fn junk_fragments_at_mtu(&self, mtu: u16) -> bool {
        self.junk_packet_count > 0 && self.junk_max_size >= mtu
    }

    pub(super) fn validate(&self, mtu: u16) -> Result<(), ConfigError> {
        if self.junk_max_size > MAX_AMNEZIA_JUNK_SIZE
            || self.init_junk_size > MAX_AMNEZIA_JUNK_SIZE
            || self.response_junk_size > MAX_AMNEZIA_JUNK_SIZE
            || self.cookie_junk_size > MAX_AMNEZIA_JUNK_SIZE
            || self.transport_junk_size > MAX_AMNEZIA_JUNK_SIZE
        {
            return Err(ConfigError::Invalid(format!(
                "AmneziaWG junk sizes must be at most {MAX_AMNEZIA_JUNK_SIZE} bytes"
            )));
        }
        if self.init_packets.len() > MAX_AMNEZIA_INIT_PACKETS {
            return Err(ConfigError::Invalid(format!(
                "AmneziaWG carries at most {MAX_AMNEZIA_INIT_PACKETS} init packets (I1..I5)"
            )));
        }
        for packet in &self.init_packets {
            let mut length = 0_usize;
            for tag in &packet.tags {
                length += match tag {
                    AmneziaInitTag::Bytes { hex } => {
                        let hex = hex.strip_prefix("0x").unwrap_or(hex);
                        if hex.is_empty()
                            || !hex.len().is_multiple_of(2)
                            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                        {
                            return Err(ConfigError::Invalid(
                                "AmneziaWG init packet bytes must be an even-length hex string"
                                    .into(),
                            ));
                        }
                        hex.len() / 2
                    }
                    AmneziaInitTag::Timestamp => 4,
                    AmneziaInitTag::Random { len }
                    | AmneziaInitTag::RandomLetters { len }
                    | AmneziaInitTag::RandomDigits { len }
                    | AmneziaInitTag::PayloadSize { len } => usize::from(*len),
                    // These two encode the chain's payload, and an init packet
                    // has none. Kept so a template round-trips, but they never
                    // put a byte on the wire here.
                    AmneziaInitTag::Payload | AmneziaInitTag::PayloadBase64 => 0,
                };
            }
            if length > usize::from(MAX_AMNEZIA_JUNK_SIZE) {
                return Err(ConfigError::Invalid(format!(
                    "AmneziaWG init packets must be at most {MAX_AMNEZIA_JUNK_SIZE} bytes"
                )));
            }
            if length == 0 {
                return Err(ConfigError::Invalid(
                    "AmneziaWG init packets must render at least one byte".into(),
                ));
            }
        }
        if self.junk_packet_count > MAX_AMNEZIA_JUNK_PACKET_COUNT {
            return Err(ConfigError::Invalid(format!(
                "AmneziaWG junk_packet_count must be at most {MAX_AMNEZIA_JUNK_PACKET_COUNT}"
            )));
        }
        if self.junk_packet_count > 0 && self.junk_min_size > self.junk_max_size {
            return Err(ConfigError::Invalid(
                "AmneziaWG junk_min_size must not exceed junk_max_size".into(),
            ));
        }
        if self.junk_packet_count > 0 && self.junk_max_size == 0 {
            return Err(ConfigError::Invalid(
                "AmneziaWG junk_max_size must be at least 1 byte when junk_packet_count is set"
                    .into(),
            ));
        }
        if self.junk_fragments_at_mtu(mtu) {
            return Err(ConfigError::Invalid(format!(
                "AmneziaWG junk_max_size {} must stay below the profile MTU {mtu}, \
                 or every junk datagram fragments",
                self.junk_max_size
            )));
        }
        let headers = [
            self.header_initiation,
            self.header_response,
            self.header_cookie,
            self.header_transport,
        ];
        for (index, header) in headers.iter().enumerate() {
            if headers[index + 1..]
                .iter()
                .any(|other| header.overlaps(other))
            {
                return Err(ConfigError::Invalid(
                    "AmneziaWG H1..H4 headers must not overlap".into(),
                ));
            }
        }
        Ok(())
    }
}

fn default_wireguard_mtu() -> u16 {
    1420
}

/// Decode-and-length check for an X25519/PSK key. The value itself never reaches
/// the error, so a malformed key cannot be recovered from a log line.
pub(super) fn validate_wireguard_key(field: &str, key: &SecretString) -> Result<(), ConfigError> {
    match STANDARD.decode(key.expose()) {
        Ok(bytes) if bytes.len() == WIREGUARD_KEY_BYTES => Ok(()),
        _ => Err(ConfigError::Invalid(format!(
            "WireGuard {field} must be {WIREGUARD_KEY_BYTES} base64-encoded bytes"
        ))),
    }
}
