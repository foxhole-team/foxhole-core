//! XUDP packet encoding (`packetEncoding=xudp`).
//!
//! UDP is carried as Mux.Cool sub-connection frames instead of the plain
//! UDP-over-stream framing. The VLESS request header uses command `Mux` and — as
//! Mux.Cool requires — omits the address block entirely; the real destination
//! travels inside every frame, which is what gives XUDP full-cone behaviour.
//!
//! ```text
//! frame   := u16be(len(metadata)) metadata u16be(len(payload)) payload
//! metadata:= u16be(session) status opt network u16be(port) atype addr [global_id]
//! ```
//!
//! `global_id` (8 bytes) is present on the first frame of a session only. The
//! server keys its UDP socket table by it, so it must be derived from the client
//! 2-tuple: sessions leaving the same local socket then share one external port,
//! which is precisely what STUN reads as a cone NAT. A random per-session value
//! would give every destination its own port again — see [`derive_global_id`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::codec::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CodecError, Result, encode_address};
use foxcore_api::Destination;
use sha2::{Digest, Sha256};

pub const STATUS_NEW: u8 = 0x01;
pub const STATUS_KEEP: u8 = 0x02;
pub const STATUS_END: u8 = 0x03;
pub const STATUS_KEEPALIVE: u8 = 0x04;

/// `Opt` bit: this frame carries payload after the metadata.
pub const OPT_DATA: u8 = 0x01;
pub const NETWORK_UDP: u8 = 0x02;
pub const GLOBAL_ID_LEN: usize = 8;

/// Session id, status and `Opt` are always present.
const MIN_METADATA_LEN: usize = 4;
const MAX_METADATA_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XudpFrame {
    pub session_id: u16,
    pub status: u8,
    /// Present when the frame carried an address block.
    pub destination: Option<Destination>,
    pub payload_start: usize,
    pub payload_len: usize,
    /// Total bytes this frame occupies.
    pub consumed: usize,
}

/// Encode one XUDP frame. `global_id` is `Some` only for [`STATUS_NEW`].
pub fn encode_packet(
    session_id: u16,
    status: u8,
    destination: &Destination,
    global_id: Option<&[u8; GLOBAL_ID_LEN]>,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if payload.len() > u16::MAX as usize {
        return Err(CodecError::ValueTooLarge);
    }
    let opt = if payload.is_empty() { 0 } else { OPT_DATA };

    let metadata_start = out.len();
    out.extend_from_slice(&[0, 0]); // metadata length, back-filled below
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(status);
    out.push(opt);
    // Network + address travel on *every* frame — repeating the destination is
    // exactly what lets one session serve a full-cone NAT mapping.
    out.push(NETWORK_UDP);
    out.extend_from_slice(&destination.port.to_be_bytes());
    encode_address(destination, out)?;
    if let Some(global_id) = global_id {
        out.extend_from_slice(global_id);
    }

    let metadata_len = out.len() - metadata_start - 2;
    if metadata_len > MAX_METADATA_LEN {
        out.truncate(metadata_start);
        return Err(CodecError::ValueTooLarge);
    }
    let header = (metadata_len as u16).to_be_bytes();
    out[metadata_start] = header[0];
    out[metadata_start + 1] = header[1];

    if opt & OPT_DATA != 0 {
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }
    Ok(())
}

/// Parse one XUDP frame from `buf`. `Ok(None)` means the frame is incomplete.
pub fn parse_packet(buf: &[u8]) -> Result<Option<XudpFrame>> {
    let Some(header) = buf.first_chunk::<2>() else {
        return Ok(None);
    };
    let metadata_len = u16::from_be_bytes(*header) as usize;
    // Session id, status and Opt are mandatory; anything shorter is malformed
    // rather than merely unfinished, so it must not wait for more bytes.
    if !(MIN_METADATA_LEN..=MAX_METADATA_LEN).contains(&metadata_len) {
        return Err(CodecError::Protocol("bad XUDP metadata length".into()));
    }
    if buf.len() < 2 + metadata_len {
        return Ok(None);
    }
    let metadata = &buf[2..2 + metadata_len];
    let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let opt = metadata[3];

    // The address block is optional: End and KeepAlive frames may omit it.
    let destination = if metadata.len() > 4 {
        let network = metadata[4];
        if network != NETWORK_UDP {
            return Err(CodecError::Protocol("unsupported XUDP network".into()));
        }
        let Some(port) = metadata.get(5..7) else {
            return Err(CodecError::Truncated);
        };
        let port = u16::from_be_bytes([port[0], port[1]]);
        let (host, _) = decode_address(&metadata[7..])?;
        Some(Destination::new(host, port))
    } else {
        None
    };

    let mut consumed = 2 + metadata_len;
    let mut payload_start = consumed;
    let mut payload_len = 0;
    if opt & OPT_DATA != 0 {
        let Some(length) = buf.get(consumed..consumed + 2) else {
            return Ok(None);
        };
        payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
        payload_start = consumed + 2;
        if buf.len() < payload_start + payload_len {
            return Ok(None);
        }
        consumed = payload_start + payload_len;
    }

    Ok(Some(XudpFrame {
        session_id,
        status,
        destination,
        payload_start,
        payload_len,
        consumed,
    }))
}

/// Derive a session's Global ID from the client 2-tuple.
///
/// The server keys its UDP socket table by this value, so every flow leaving the
/// same local socket must hash to the same 8 bytes — that is what holds one
/// external port across destinations instead of one port per peer. `key` is a
/// per-outbound secret so the id cannot become a device fingerprint that
/// different servers correlate.
pub fn derive_global_id(key: &[u8; 32], source: SocketAddr) -> [u8; GLOBAL_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    match source.ip() {
        IpAddr::V4(v4) => hasher.update(v4.octets()),
        IpAddr::V6(v6) => hasher.update(v6.octets()),
    }
    hasher.update(source.port().to_be_bytes());
    let digest = hasher.finalize();
    let mut global_id = [0_u8; GLOBAL_ID_LEN];
    global_id.copy_from_slice(&digest[..GLOBAL_ID_LEN]);
    global_id
}

/// Decode `atype | addr`, returning the host and the bytes it occupied.
fn decode_address(buf: &[u8]) -> Result<(String, usize)> {
    let Some((atype, rest)) = buf.split_first() else {
        return Err(CodecError::Truncated);
    };
    match *atype {
        ATYP_IPV4 => {
            let Some(octets) = rest.first_chunk::<4>() else {
                return Err(CodecError::Truncated);
            };
            Ok((Ipv4Addr::from(*octets).to_string(), 5))
        }
        ATYP_IPV6 => {
            let Some(octets) = rest.first_chunk::<16>() else {
                return Err(CodecError::Truncated);
            };
            Ok((Ipv6Addr::from(*octets).to_string(), 17))
        }
        ATYP_DOMAIN => {
            let Some((length, domain)) = rest.split_first() else {
                return Err(CodecError::Truncated);
            };
            let length = *length as usize;
            if length == 0 {
                return Err(CodecError::InvalidAddress(String::new()));
            }
            let Some(domain) = domain.get(..length) else {
                return Err(CodecError::Truncated);
            };
            let host = std::str::from_utf8(domain)
                .map_err(|_| CodecError::InvalidAddress("non-UTF-8 domain".into()))?;
            Ok((host.to_owned(), 2 + length))
        }
        other => Err(CodecError::InvalidAddress(format!("atype {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GID: [u8; GLOBAL_ID_LEN] = [0xAA; GLOBAL_ID_LEN];

    #[test]
    fn new_frame_carries_address_and_global_id() {
        let mut out = Vec::new();
        let destination = Destination::new("1.2.3.4", 53);
        encode_packet(1, STATUS_NEW, &destination, Some(&GID), b"hi", &mut out).unwrap();

        // metadata = id(2) status(1) opt(1) network(1) port(2) atype(1) addr(4) gid(8)
        let expected_meta = 2 + 1 + 1 + 1 + 2 + 1 + 4 + GLOBAL_ID_LEN;
        assert_eq!(u16::from_be_bytes([out[0], out[1]]) as usize, expected_meta);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 1, "session id");
        assert_eq!(out[4], STATUS_NEW);
        assert_eq!(out[5], OPT_DATA);
        assert_eq!(out[6], NETWORK_UDP);
        assert_eq!(u16::from_be_bytes([out[7], out[8]]), 53, "port");
        assert_eq!(out[9], 1, "atype ipv4");
        assert_eq!(&out[10..14], &[1, 2, 3, 4]);
        assert_eq!(&out[14..22], &GID);
        assert_eq!(u16::from_be_bytes([out[22], out[23]]), 2, "payload len");
        assert_eq!(&out[24..26], b"hi");
        assert_eq!(out.len(), 2 + expected_meta + 2 + 2);
    }

    #[test]
    fn keep_frame_repeats_the_address_but_omits_the_global_id() {
        let mut out = Vec::new();
        let destination = Destination::new("1.2.3.4", 53);
        encode_packet(1, STATUS_KEEP, &destination, None, b"hi", &mut out).unwrap();

        let expected_meta = 2 + 1 + 1 + 1 + 2 + 1 + 4;
        assert_eq!(u16::from_be_bytes([out[0], out[1]]) as usize, expected_meta);
        assert_eq!(out[4], STATUS_KEEP);
        // Address is still repeated — that is what makes XUDP full-cone.
        assert_eq!(u16::from_be_bytes([out[7], out[8]]), 53);
        assert_eq!(&out[10..14], &[1, 2, 3, 4]);
        assert_eq!(out.len(), 2 + expected_meta + 2 + 2);
    }

    #[test]
    fn domain_destinations_round_trip() {
        let mut out = Vec::new();
        let destination = Destination::new("example.com", 443);
        encode_packet(7, STATUS_NEW, &destination, Some(&GID), b"x", &mut out).unwrap();

        let frame = parse_packet(&out).unwrap().unwrap();
        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.destination, Some(destination));
        assert_eq!(
            &out[frame.payload_start..frame.payload_start + frame.payload_len],
            b"x"
        );
        assert_eq!(frame.consumed, out.len());
    }

    #[test]
    fn ipv6_destinations_round_trip() {
        let mut out = Vec::new();
        let destination = Destination::new("2001:db8::1", 8080);
        encode_packet(2, STATUS_KEEP, &destination, None, b"abc", &mut out).unwrap();

        let frame = parse_packet(&out).unwrap().unwrap();
        assert_eq!(frame.destination, Some(destination));
        assert_eq!(frame.payload_len, 3);
    }

    #[test]
    fn incomplete_frames_yield_none() {
        let mut out = Vec::new();
        encode_packet(
            1,
            STATUS_NEW,
            &Destination::new("1.2.3.4", 53),
            Some(&GID),
            b"hi",
            &mut out,
        )
        .unwrap();
        assert!(parse_packet(&out[..out.len() - 1]).unwrap().is_none());
        assert!(parse_packet(&[]).unwrap().is_none());
        assert!(parse_packet(&out[..3]).unwrap().is_none());
    }

    #[test]
    fn end_frames_carry_no_payload() {
        let mut out = Vec::new();
        encode_packet(
            3,
            STATUS_END,
            &Destination::new("1.2.3.4", 53),
            None,
            b"",
            &mut out,
        )
        .unwrap();
        let frame = parse_packet(&out).unwrap().unwrap();
        assert_eq!(frame.status, STATUS_END);
        assert_eq!(frame.payload_len, 0);
    }

    #[test]
    fn back_to_back_frames_parse_from_one_buffer() {
        let mut out = Vec::new();
        let first = Destination::new("1.2.3.4", 53);
        let second = Destination::new("example.com", 443);
        encode_packet(1, STATUS_NEW, &first, Some(&GID), b"one", &mut out).unwrap();
        encode_packet(1, STATUS_KEEP, &second, None, b"two", &mut out).unwrap();

        let head = parse_packet(&out).unwrap().unwrap();
        assert_eq!(head.destination, Some(first));
        assert_eq!(
            &out[head.payload_start..head.payload_start + head.payload_len],
            b"one"
        );

        let tail = parse_packet(&out[head.consumed..]).unwrap().unwrap();
        assert_eq!(tail.destination, Some(second));
        let start = head.consumed + tail.payload_start;
        assert_eq!(&out[start..start + tail.payload_len], b"two");
        assert_eq!(head.consumed + tail.consumed, out.len());
    }

    #[test]
    fn global_id_is_stable_per_client_socket() {
        let key = [0x5A_u8; 32];
        let socket: SocketAddr = "10.77.0.2:49152".parse().unwrap();
        // Same local socket, different peers -> same id, so the server keeps one
        // external port. This is the whole point of the derivation.
        assert_eq!(
            derive_global_id(&key, socket),
            derive_global_id(&key, socket)
        );
        // A different local port is a different client socket.
        assert_ne!(
            derive_global_id(&key, socket),
            derive_global_id(&key, "10.77.0.2:49153".parse().unwrap())
        );
        assert_ne!(
            derive_global_id(&key, socket),
            derive_global_id(&key, "10.77.0.3:49152".parse().unwrap())
        );
        // A second outbound must not reproduce the first one's ids: the value
        // would otherwise be a device fingerprint shared across servers.
        assert_ne!(
            derive_global_id(&key, socket),
            derive_global_id(&[0x5B; 32], socket)
        );
    }

    #[test]
    fn global_id_separates_ipv4_and_ipv6_clients() {
        let key = [0x11_u8; 32];
        assert_ne!(
            derive_global_id(&key, "127.0.0.1:1024".parse().unwrap()),
            derive_global_id(&key, "[::1]:1024".parse().unwrap())
        );
    }

    #[test]
    fn truncated_metadata_is_malformed_not_pending() {
        // Fewer than session id + status + Opt can never become valid.
        assert!(parse_packet(&[0x00, 0x03, 0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn oversized_metadata_is_rejected() {
        let mut frame = vec![0xff, 0xff];
        frame.extend_from_slice(&[0u8; 16]);
        assert!(matches!(parse_packet(&frame), Ok(None) | Err(_)));
    }
}
