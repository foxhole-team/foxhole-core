//! `packet_encoding=packetaddr`: the destination in front of every datagram.
//!
//! Plain UDP-over-stream pins one destination in the request header, so a client
//! that talks to several peers needs several streams and the server sees a
//! symmetric NAT. XUDP fixes that with a full multiplexing frame. `packetaddr`
//! fixes it with the smallest thing that can work — a bare address prefix:
//!
//! ```text
//!   atyp(1) | address(4 | 16) | port(2 BE) | payload
//! ```
//!
//! carried inside the ordinary VLESS UDP length prefix, in both directions.
//!
//! Two properties of the format are load-bearing and neither is negotiated:
//!
//! * **Only IPv4 and IPv6.** The reference registers exactly two address types
//!   and rejects domains outright. There is no `atyp` for a name, so a flow to
//!   an unresolved host cannot be expressed at all.
//! * **The mode is announced by the destination, not by a flag.** The request
//!   header carries the magic name [`MAGIC_ADDRESS`] on port 0, and the server
//!   recognises the mode by string-comparing it. A server that does not
//!   implement `packetaddr` will try to resolve that name and fail — which is
//!   why an unsupported peer looks like a dead one rather than falling back.
//!
//! Cross-checked against v2fly/v2ray-core `common/net/packetaddr/packetaddr.go`
//! (`AttachAddressToPacket`, `ExtractAddressFromPacket`) and SagerNet
//! `sing-vmess/packetaddr`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use foxcore_api::Destination;

/// The request-header destination that puts a stream into `packetaddr` mode.
pub const MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";
/// Port that travels with it. The name is the signal; the port is unused.
pub const MAGIC_PORT: u16 = 0;

const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;
/// Largest prefix: type byte, IPv6 address, port.
pub const MAX_HEADER_LEN: usize = 1 + 16 + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketAddrError {
    /// The destination is a name. The format has no address type for one.
    DomainDestination,
    /// The frame ended inside its address prefix.
    Truncated,
    /// An address type outside the two the format registers.
    UnknownAddressType(u8),
}

impl std::fmt::Display for PacketAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainDestination => {
                f.write_str("packetaddr carries IP destinations only, never names")
            }
            Self::Truncated => f.write_str("truncated packetaddr frame"),
            Self::UnknownAddressType(atyp) => {
                write!(f, "unknown packetaddr address type {atyp:#04x}")
            }
        }
    }
}

impl std::error::Error for PacketAddrError {}

impl From<PacketAddrError> for std::io::Error {
    fn from(error: PacketAddrError) -> Self {
        let kind = match error {
            PacketAddrError::DomainDestination => std::io::ErrorKind::Unsupported,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, error)
    }
}

/// Prepend the destination to `payload`.
pub fn encode(
    destination: &Destination,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), PacketAddrError> {
    let address = destination.ip().ok_or(PacketAddrError::DomainDestination)?;
    match address {
        IpAddr::V4(address) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&address.octets());
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Split one frame into its source address and payload.
pub fn decode(frame: &[u8]) -> Result<(SocketAddr, &[u8]), PacketAddrError> {
    let atyp = *frame.first().ok_or(PacketAddrError::Truncated)?;
    let (address, rest): (IpAddr, &[u8]) = match atyp {
        ATYP_IPV4 => {
            let octets: [u8; 4] = frame
                .get(1..5)
                .ok_or(PacketAddrError::Truncated)?
                .try_into()
                .map_err(|_| PacketAddrError::Truncated)?;
            (IpAddr::V4(Ipv4Addr::from(octets)), &frame[5..])
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = frame
                .get(1..17)
                .ok_or(PacketAddrError::Truncated)?
                .try_into()
                .map_err(|_| PacketAddrError::Truncated)?;
            (IpAddr::V6(Ipv6Addr::from(octets)), &frame[17..])
        }
        other => return Err(PacketAddrError::UnknownAddressType(other)),
    };
    let port: [u8; 2] = rest
        .get(..2)
        .ok_or(PacketAddrError::Truncated)?
        .try_into()
        .map_err(|_| PacketAddrError::Truncated)?;
    Ok((
        SocketAddr::new(address, u16::from_be_bytes(port)),
        &rest[2..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv4_frame_is_a_golden_vector_of_the_reference_layout() {
        // AttachAddressToPacket(1.2.3.4:53, "hi"): type, address, port, payload.
        let mut out = Vec::new();
        encode(&Destination::new("1.2.3.4", 53), b"hi", &mut out).unwrap();
        assert_eq!(
            out,
            vec![0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x35, b'h', b'i']
        );

        let (source, payload) = decode(&out).unwrap();
        assert_eq!(source, "1.2.3.4:53".parse::<SocketAddr>().unwrap());
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn an_ipv6_frame_carries_the_full_sixteen_bytes() {
        let mut out = Vec::new();
        encode(&Destination::new("2001:db8::1", 443), b"x", &mut out).unwrap();
        assert_eq!(out[0], 0x02);
        assert_eq!(out.len(), 1 + 16 + 2 + 1);
        assert_eq!(&out[17..19], &[0x01, 0xbb], "port is big endian");

        let (source, payload) = decode(&out).unwrap();
        assert_eq!(source, "[2001:db8::1]:443".parse::<SocketAddr>().unwrap());
        assert_eq!(payload, b"x");
    }

    #[test]
    fn an_empty_payload_is_a_valid_frame() {
        let mut out = Vec::new();
        encode(&Destination::new("10.0.0.1", 1), b"", &mut out).unwrap();
        assert_eq!(out.len(), 1 + 4 + 2);
        let (_, payload) = decode(&out).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn a_name_cannot_be_expressed_and_is_not_guessed_at() {
        // The format registers no address type for a domain, so there is no
        // encoding to fall back to — the flow simply cannot ride this carrier.
        let mut out = Vec::new();
        assert_eq!(
            encode(&Destination::new("example.com", 443), b"q", &mut out).unwrap_err(),
            PacketAddrError::DomainDestination
        );
    }

    #[test]
    fn malformed_frames_are_rejected_rather_than_half_read() {
        assert_eq!(decode(&[]).unwrap_err(), PacketAddrError::Truncated);
        assert_eq!(
            decode(&[0x01, 1, 2, 3, 4, 0x00]).unwrap_err(),
            PacketAddrError::Truncated,
            "a port cut in half is not a zero port"
        );
        assert_eq!(
            decode(&[0x02, 0, 0]).unwrap_err(),
            PacketAddrError::Truncated
        );
        assert_eq!(
            decode(&[0x03, 1, 2, 3, 4, 0, 53]).unwrap_err(),
            PacketAddrError::UnknownAddressType(0x03),
            "the reference registers two address types and only two"
        );
    }
}
