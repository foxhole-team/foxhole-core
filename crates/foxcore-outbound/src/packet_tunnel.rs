//! L3 packet-tunnel outbounds.
//!
//! A packet tunnel is not a proxy: it takes whole IP packets rather than
//! terminating a connection and re-dialing it. Keeping it out of the [`crate::Outbound`]
//! enum is deliberate: no code path can accidentally
//! treat WireGuard as a stream proxy and spin up a second userspace TCP stack
//! on top of the one the tun already runs.

use std::io;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use foxcore_api::{SecretString, WireguardConfig};
use foxcore_dialer::ProtectedDialer;
use ipnet::IpNet;
use proto_wireguard::amnezia::{AmneziaParams, HeaderRange};
use proto_wireguard::initpacket::{InitPacket, InitTag};
use proto_wireguard::noise::Key;
use proto_wireguard::tunnel::{PeerSettings, PeerTimers};

/// Where the tunnel's datagrams go and what the tun side must look like.
pub struct PacketTunnelOutbound {
    settings: PeerSettings,
    endpoint: Endpoint,
    /// Addresses the peer assigned to this client. Packets leaving the tun are
    /// rewritten to the first one of the matching family.
    interface: Vec<IpNet>,
    /// Prefixes the peer accepts. Anything outside them is not this tunnel's
    /// traffic and must be refused rather than quietly sent in the clear.
    allowed_ips: Vec<IpNet>,
    mtu: u16,
    dialer: ProtectedDialer,
}

/// Peer endpoint. `ip` is present when the profile pinned one, which is what the
/// Android bootstrap path needs to avoid a system-DNS lookup before the tunnel
/// is up.
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub ip: Option<IpAddr>,
}

impl PacketTunnelOutbound {
    pub fn wireguard(config: WireguardConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        let settings = PeerSettings {
            private_key: decode_key("private_key", &config.private_key)?,
            peer_public_key: decode_key("peer_public_key", &config.peer_public_key)?,
            preshared_key: config
                .preshared_key
                .as_ref()
                .map(|key| decode_key("preshared_key", key))
                .transpose()?,
            amnezia: config
                .amnezia
                .as_ref()
                .map(amnezia_params)
                .unwrap_or_default(),
            persistent_keepalive_s: config.persistent_keepalive_s,
            reserved: config.reserved.unwrap_or([0, 0, 0]),
            init_packets: config
                .amnezia
                .as_ref()
                .map(init_packets)
                .transpose()?
                .unwrap_or_default(),
            timers: config
                .amnezia
                .as_ref()
                .map(|amnezia| peer_timers(&amnezia.timers))
                .unwrap_or_default(),
        };
        settings
            .amnezia
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(Self {
            settings,
            endpoint: Endpoint {
                host: config.server,
                port: config.port,
                ip: config.server_ip,
            },
            interface: config.address,
            allowed_ips: config.allowed_ips,
            mtu: config.mtu,
            dialer,
        })
    }

    pub fn settings(&self) -> &PeerSettings {
        &self.settings
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn interface(&self) -> &[IpNet] {
        &self.interface
    }

    pub fn allowed_ips(&self) -> &[IpNet] {
        &self.allowed_ips
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn dialer(&self) -> &ProtectedDialer {
        &self.dialer
    }
}

/// The config layer already proved the length; this repeats the check so a
/// mistake there cannot become a panic here.
fn decode_key(field: &str, value: &SecretString) -> io::Result<Key> {
    let bytes = STANDARD
        .decode(value.expose())
        .map_err(|_| invalid_key(field))?;
    Key::try_from(bytes.as_slice()).map_err(|_| invalid_key(field))
}

fn invalid_key(field: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("WireGuard {field} is not a 32-byte key"),
    )
}

fn amnezia_params(config: &foxcore_api::AmneziaConfig) -> AmneziaParams {
    AmneziaParams {
        junk_packet_count: config.junk_packet_count,
        junk_min_size: config.junk_min_size,
        junk_max_size: config.junk_max_size,
        init_junk_size: config.init_junk_size,
        response_junk_size: config.response_junk_size,
        cookie_junk_size: config.cookie_junk_size,
        transport_junk_size: config.transport_junk_size,
        header_initiation: header_range(config.header_initiation),
        header_response: header_range(config.header_response),
        header_cookie: header_range(config.header_cookie),
        header_transport: header_range(config.header_transport),
    }
}

/// The serialized header range as the wire crate's own.
///
/// Infallible by construction: both types refuse inverted bounds at the point
/// they are built, so `new` cannot fail here. The fallback is the low bound
/// alone rather than a panic — a header that lost its range still describes a
/// tunnel, where an aborted process describes nothing.
fn header_range(config: foxcore_api::AmneziaHeaderRange) -> HeaderRange {
    HeaderRange::new(config.start, config.end).unwrap_or(HeaderRange::single(config.start))
}

/// The AmneziaWG 3.0 timer block as the tunnel's own. Absent fields stay absent,
/// which is what makes the tunnel fall back to the WireGuard constants.
fn peer_timers(config: &foxcore_api::AmneziaTimers) -> PeerTimers {
    let range =
        |value: Option<foxcore_api::AmneziaTimerRange>| value.map(|range| (range.start, range.end));
    PeerTimers {
        rekey_timeout_s: range(config.rekey_timeout_s),
        rekey_after_time_s: range(config.rekey_after_time_s),
        reject_after_time_s: range(config.reject_after_time_s),
        keepalive_timeout_s: range(config.keepalive_timeout_s),
        max_handshake_attempts: range(config.max_handshake_attempts),
    }
}

/// Map the typed `I1..I5` templates onto the renderer.
///
/// The config already refused a malformed template, so a failure here is a
/// disagreement between the two definitions rather than bad input — which is
/// exactly why it is an error and not a silently shorter packet.
fn init_packets(config: &foxcore_api::AmneziaConfig) -> io::Result<Vec<InitPacket>> {
    config
        .init_packets
        .iter()
        .map(|packet| {
            let tags = packet
                .tags
                .iter()
                .map(|tag| match tag {
                    foxcore_api::AmneziaInitTag::Bytes { hex } => {
                        decode_init_hex(hex).map(InitTag::Bytes)
                    }
                    foxcore_api::AmneziaInitTag::Timestamp => Ok(InitTag::Timestamp),
                    foxcore_api::AmneziaInitTag::Random { len } => Ok(InitTag::Random(*len)),
                    foxcore_api::AmneziaInitTag::RandomLetters { len } => {
                        Ok(InitTag::RandomLetters(*len))
                    }
                    foxcore_api::AmneziaInitTag::RandomDigits { len } => {
                        Ok(InitTag::RandomDigits(*len))
                    }
                    foxcore_api::AmneziaInitTag::Payload => Ok(InitTag::Payload),
                    foxcore_api::AmneziaInitTag::PayloadBase64 => Ok(InitTag::PayloadBase64),
                    foxcore_api::AmneziaInitTag::PayloadSize { len } => {
                        Ok(InitTag::PayloadSize(*len))
                    }
                })
                .collect::<io::Result<Vec<_>>>()?;
            InitPacket::new(tags)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
        })
        .collect()
}

fn decode_init_hex(value: &str) -> io::Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(invalid_key("AmneziaWG init packet bytes"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| invalid_key("AmneziaWG init packet bytes"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxcore_api::{AmneziaConfig, AmneziaInitPacket, AmneziaInitTag};
    use proto_wireguard::WireguardError;
    use proto_wireguard::message::{INITIATION_LEN, RESPONSE_LEN, TYPE_RESPONSE};
    use proto_wireguard::tunnel::{Entropy, PeerTunnel};

    /// Deterministic filler, so a junk size can be asserted without asserting
    /// the junk itself.
    struct Counting(u8);

    impl Entropy for Counting {
        fn fill(&mut self, buffer: &mut [u8]) -> Result<(), WireguardError> {
            for byte in buffer {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    /// Every obfuscation field set to something a default could not produce, so
    /// a value that failed to arrive shows up as a wrong length or a wrong
    /// header rather than as a passing test.
    fn every_parameter_set() -> AmneziaConfig {
        AmneziaConfig {
            junk_packet_count: 3,
            junk_min_size: 40,
            junk_max_size: 40,
            init_junk_size: 24,
            response_junk_size: 18,
            cookie_junk_size: 12,
            transport_junk_size: 9,
            init_packets: vec![AmneziaInitPacket {
                tags: vec![
                    AmneziaInitTag::Bytes {
                        hex: "0xc0ffee".into(),
                    },
                    AmneziaInitTag::Random { len: 5 },
                ],
            }],
            header_initiation: foxcore_api::AmneziaHeaderRange::single(0x1111_1111),
            header_response: foxcore_api::AmneziaHeaderRange::single(0x2222_2222),
            header_cookie: foxcore_api::AmneziaHeaderRange::single(0x3333_3333),
            header_transport: foxcore_api::AmneziaHeaderRange::single(0x4444_4444),
            timers: foxcore_api::AmneziaTimers::default(),
        }
    }

    fn settings(config: &AmneziaConfig) -> PeerSettings {
        PeerSettings {
            private_key: [7_u8; 32],
            peer_public_key: proto_wireguard::noise::public_key(&[9_u8; 32]).unwrap(),
            preshared_key: None,
            amnezia: amnezia_params(config),
            persistent_keepalive_s: None,
            reserved: [0, 0, 0],
            init_packets: init_packets(config).unwrap(),
            timers: peer_timers(&config.timers),
        }
    }

    /// The claim this product makes to its user is that an imported AmneziaWG
    /// profile is obfuscated on the wire. A parameter that is parsed, validated,
    /// carried into `PeerSettings` and then not applied would keep every layer's
    /// tests green while the datagrams stay recognisably WireGuard — which is
    /// worse than plain WireGuard, because the user believes otherwise.
    ///
    /// So this asserts the bytes, from the profile's own config type through to
    /// what the socket would be handed.
    #[test]
    fn every_amneziawg_parameter_reaches_the_wire() {
        let config = every_parameter_set();
        let params = amnezia_params(&config);
        let mut tunnel = PeerTunnel::new(settings(&config), Box::new(Counting(0))).unwrap();
        tunnel.send_packet(&[0x45; 40], 0).unwrap();

        // I1 first: three literal bytes and five random ones.
        let mut datagram = Vec::new();
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert_eq!(datagram.len(), 8, "I1 = <b 0xc0ffee><r 5>");
        assert_eq!(&datagram[..3], &[0xc0, 0xff, 0xee]);

        // Then Jc junk datagrams, each Jmin..=Jmax bytes.
        for index in 0..config.junk_packet_count {
            assert!(
                tunnel.poll_transmit(&mut datagram).is_some(),
                "junk packet {index} of Jc={}",
                config.junk_packet_count
            );
            assert!(
                (usize::from(config.junk_min_size)..=usize::from(config.junk_max_size))
                    .contains(&datagram.len()),
                "junk packet {index} is {} bytes, outside Jmin..=Jmax",
                datagram.len()
            );
        }

        // Then the initiation: S1 bytes of junk, then H1 where the type was.
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert_eq!(
            datagram.len(),
            usize::from(config.init_junk_size) + INITIATION_LEN,
            "S1 has to lengthen the initiation by exactly S1"
        );
        let s1 = usize::from(config.init_junk_size);
        assert_eq!(
            u32::from_le_bytes(datagram[s1..s1 + 4].try_into().unwrap()),
            config.header_initiation.start,
            "H1 has to sit behind the S1 prefix"
        );
        assert!(
            tunnel.poll_transmit(&mut datagram).is_none(),
            "a handshake attempt is I-packets, junk, initiation — and nothing else"
        );

        // S2/H2 and S3/H3 are the peer's direction, so they are asserted where
        // the receiver reads them: at the length the peer must produce and with
        // the header it must carry.
        for (junk, body_len, header, kind) in [
            (
                config.response_junk_size,
                RESPONSE_LEN,
                config.header_response,
                TYPE_RESPONSE,
            ),
            (
                config.cookie_junk_size,
                proto_wireguard::message::COOKIE_REPLY_LEN,
                config.header_cookie,
                proto_wireguard::message::TYPE_COOKIE_REPLY,
            ),
        ] {
            let mut wire = vec![0x5A_u8; usize::from(junk)];
            wire.extend_from_slice(&header.start.to_le_bytes());
            wire.resize(usize::from(junk) + body_len, 0x33);
            let recovered = params
                .deobfuscate(&wire)
                .expect("S2/S3 and H2/H3 have to be the ones the profile asked for");
            assert_eq!(recovered.len(), body_len);
            assert_eq!(recovered[0], kind);
        }

        // S4/H4 on a data packet, which is the only one that carries traffic and
        // therefore the only one a DPI box sees more than once.
        let mut sealed = vec![proto_wireguard::message::TYPE_TRANSPORT, 0, 0, 0];
        sealed.extend_from_slice(&[0xAB; 48]);
        let wire = params.obfuscate(&sealed, |junk| junk.fill(0x5A)).unwrap();
        assert_eq!(
            wire.len(),
            usize::from(config.transport_junk_size) + sealed.len(),
            "S4 has to lengthen every data packet by exactly S4"
        );
        let s4 = usize::from(config.transport_junk_size);
        assert_eq!(
            u32::from_le_bytes(wire[s4..s4 + 4].try_into().unwrap()),
            config.header_transport.start,
            "H4 has to sit behind the S4 prefix"
        );
    }

    /// The other half of the same claim: a profile with no AmneziaWG block must
    /// be byte-for-byte plain WireGuard, not "obfuscation with everything at
    /// zero" — a peer that expects plain WireGuard has to be reachable.
    #[test]
    fn a_profile_without_an_amnezia_block_is_plain_wireguard() {
        let params = AmneziaParams::default();
        assert!(params.is_vanilla());
        assert_eq!(amnezia_params(&AmneziaConfig::default()), params);
    }
}
