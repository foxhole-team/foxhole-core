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
use proto_wireguard::amnezia::AmneziaParams;
use proto_wireguard::initpacket::{InitPacket, InitTag};
use proto_wireguard::noise::Key;
use proto_wireguard::tunnel::PeerSettings;

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
        header_initiation: config.header_initiation,
        header_response: config.header_response,
        header_cookie: config.header_cookie,
        header_transport: config.header_transport,
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
