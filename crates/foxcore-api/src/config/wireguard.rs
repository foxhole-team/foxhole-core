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
    /// `H1..H4`: replacement 32-bit message headers.
    #[serde(default = "default_header_initiation")]
    pub header_initiation: u32,
    #[serde(default = "default_header_response")]
    pub header_response: u32,
    #[serde(default = "default_header_cookie")]
    pub header_cookie: u32,
    #[serde(default = "default_header_transport")]
    pub header_transport: u32,
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
            header_initiation: default_header_initiation(),
            header_response: default_header_response(),
            header_cookie: default_header_cookie(),
            header_transport: default_header_transport(),
        }
    }
}

const fn default_header_initiation() -> u32 {
    1
}

const fn default_header_response() -> u32 {
    2
}

const fn default_header_cookie() -> u32 {
    3
}

const fn default_header_transport() -> u32 {
    4
}

/// Mirror of `proto_wireguard::amnezia::MAX_JUNK_SIZE`. `foxcore-api` cannot
/// depend on a protocol crate, so the bound is asserted against the wire
/// implementation by a test in the outbound builder instead.
const MAX_AMNEZIA_JUNK_SIZE: u16 = 1280;
const MAX_AMNEZIA_JUNK_PACKET_COUNT: u16 = 128;
/// The reference names them I1..I5 and stops there.
const MAX_AMNEZIA_INIT_PACKETS: usize = 5;

impl AmneziaConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
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
        let headers = [
            self.header_initiation,
            self.header_response,
            self.header_cookie,
            self.header_transport,
        ];
        for (index, header) in headers.iter().enumerate() {
            if headers[index + 1..].contains(header) {
                return Err(ConfigError::Invalid(
                    "AmneziaWG H1..H4 headers must be pairwise distinct".into(),
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
