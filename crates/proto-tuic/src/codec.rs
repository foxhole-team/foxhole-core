//! TUIC v5 command and address codec.

use std::net::IpAddr;

use foxcore_api::Destination;

use crate::{CodecError, Result};

pub const VERSION: u8 = 0x05;
pub const COMMAND_AUTHENTICATE: u8 = 0x00;
pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_PACKET: u8 = 0x02;
pub const COMMAND_DISSOCIATE: u8 = 0x03;
pub const COMMAND_HEARTBEAT: u8 = 0x04;

pub const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;
pub const MAX_FRAGMENTS: u8 = 64;

const ADDRESS_NONE: u8 = 0xff;
const ADDRESS_DOMAIN: u8 = 0x00;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_IPV6: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub association_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub destination: Option<Destination>,
    pub payload: &'a [u8],
}

pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; 32], out: &mut Vec<u8>) {
    out.reserve(50);
    out.extend_from_slice(&[VERSION, COMMAND_AUTHENTICATE]);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
}

pub fn encode_connect(destination: &Destination, out: &mut Vec<u8>) -> Result<()> {
    out.extend_from_slice(&[VERSION, COMMAND_CONNECT]);
    encode_address(Some(destination), out)
}

pub fn encode_packet(
    association_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: Option<&Destination>,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if fragment_total == 0
        || fragment_total > MAX_FRAGMENTS
        || fragment_id >= fragment_total
        || (fragment_id == 0) != destination.is_some()
    {
        return Err(CodecError::InvalidFragment);
    }
    let size = u16::try_from(payload.len()).map_err(|_| CodecError::ValueTooLarge)?;
    out.extend_from_slice(&[VERSION, COMMAND_PACKET]);
    out.extend_from_slice(&association_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_total);
    out.push(fragment_id);
    out.extend_from_slice(&size.to_be_bytes());
    encode_address(destination, out)?;
    out.extend_from_slice(payload);
    Ok(())
}

pub fn decode_packet(frame: &[u8]) -> Result<Packet<'_>> {
    if frame.len() < 11 {
        return Err(CodecError::Truncated);
    }
    if frame[0] != VERSION {
        return Err(CodecError::InvalidVersion(frame[0]));
    }
    if frame[1] != COMMAND_PACKET {
        return Err(CodecError::InvalidCommand(frame[1]));
    }
    let association_id = u16::from_be_bytes([frame[2], frame[3]]);
    let packet_id = u16::from_be_bytes([frame[4], frame[5]]);
    let fragment_total = frame[6];
    let fragment_id = frame[7];
    if fragment_total == 0 || fragment_total > MAX_FRAGMENTS || fragment_id >= fragment_total {
        return Err(CodecError::InvalidFragment);
    }
    let payload_len = u16::from_be_bytes([frame[8], frame[9]]) as usize;
    let mut position = 10;
    let destination = decode_address(frame, &mut position)?;
    if (fragment_id == 0) != destination.is_some() {
        return Err(CodecError::InvalidFragment);
    }
    let end = position
        .checked_add(payload_len)
        .ok_or(CodecError::ValueTooLarge)?;
    if end > frame.len() {
        return Err(CodecError::Truncated);
    }
    if end != frame.len() {
        return Err(CodecError::TrailingData);
    }
    Ok(Packet {
        association_id,
        packet_id,
        fragment_total,
        fragment_id,
        destination,
        payload: &frame[position..end],
    })
}

pub fn encode_dissociate(association_id: u16) -> [u8; 4] {
    let [high, low] = association_id.to_be_bytes();
    [VERSION, COMMAND_DISSOCIATE, high, low]
}

pub const fn heartbeat() -> [u8; 2] {
    [VERSION, COMMAND_HEARTBEAT]
}

pub fn encoded_address_len(destination: Option<&Destination>) -> Result<usize> {
    match destination {
        None => Ok(1),
        Some(destination) => match destination.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => Ok(1 + 4 + 2),
            Ok(IpAddr::V6(_)) => Ok(1 + 16 + 2),
            Err(_) => {
                let length = destination.host.len();
                if length == 0 || length > u8::MAX as usize {
                    Err(CodecError::InvalidAddress)
                } else {
                    Ok(1 + 1 + length + 2)
                }
            }
        },
    }
}

fn encode_address(destination: Option<&Destination>, out: &mut Vec<u8>) -> Result<()> {
    let Some(destination) = destination else {
        out.push(ADDRESS_NONE);
        return Ok(());
    };
    if destination.port == 0 {
        return Err(CodecError::InvalidAddress);
    }
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            out.push(ADDRESS_IPV4);
            out.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            out.push(ADDRESS_IPV6);
            out.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let domain = destination.host.as_bytes();
            let length = u8::try_from(domain.len()).map_err(|_| CodecError::InvalidAddress)?;
            if length == 0 {
                return Err(CodecError::InvalidAddress);
            }
            out.extend_from_slice(&[ADDRESS_DOMAIN, length]);
            out.extend_from_slice(domain);
        }
    }
    out.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn decode_address(frame: &[u8], position: &mut usize) -> Result<Option<Destination>> {
    let family = take_byte(frame, position)?;
    let destination = match family {
        ADDRESS_NONE => return Ok(None),
        ADDRESS_DOMAIN => {
            let length = take_byte(frame, position)? as usize;
            if length == 0 || frame.len().saturating_sub(*position) < length {
                return Err(CodecError::InvalidAddress);
            }
            let bytes = &frame[*position..*position + length];
            *position += length;
            let domain = std::str::from_utf8(bytes).map_err(|_| CodecError::InvalidAddress)?;
            if !domain.is_ascii() || domain.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(CodecError::InvalidAddress);
            }
            domain.to_owned()
        }
        ADDRESS_IPV4 => {
            let octets = take_array::<4>(frame, position)?;
            IpAddr::from(octets).to_string()
        }
        ADDRESS_IPV6 => {
            let octets = take_array::<16>(frame, position)?;
            IpAddr::from(octets).to_string()
        }
        _ => return Err(CodecError::InvalidAddress),
    };
    let port = u16::from_be_bytes(take_array::<2>(frame, position)?);
    if port == 0 {
        return Err(CodecError::InvalidAddress);
    }
    Ok(Some(Destination::new(destination, port)))
}

fn take_byte(frame: &[u8], position: &mut usize) -> Result<u8> {
    let byte = *frame.get(*position).ok_or(CodecError::Truncated)?;
    *position += 1;
    Ok(byte)
}

fn take_array<const N: usize>(frame: &[u8], position: &mut usize) -> Result<[u8; N]> {
    let end = position.checked_add(N).ok_or(CodecError::ValueTooLarge)?;
    let bytes = frame.get(*position..end).ok_or(CodecError::Truncated)?;
    *position = end;
    bytes.try_into().map_err(|_| CodecError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normative_command_bytes_are_stable() {
        let uuid = [0x11; 16];
        let token = [0x22; 32];
        let mut auth = Vec::new();
        encode_authenticate(&uuid, &token, &mut auth);
        assert_eq!(&auth[..2], &[0x05, 0x00]);
        assert_eq!(&auth[2..18], &uuid);
        assert_eq!(&auth[18..], &token);

        let mut connect = Vec::new();
        encode_connect(&Destination::new("example.com", 443), &mut connect).unwrap();
        assert_eq!(
            connect,
            [
                0x05, 0x01, 0x00, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', 0x01, 0xbb
            ]
        );
        assert_eq!(encode_dissociate(0x1234), [0x05, 0x03, 0x12, 0x34]);
        assert_eq!(heartbeat(), [0x05, 0x04]);
    }

    #[test]
    fn packet_round_trips_with_big_endian_header() {
        let mut encoded = Vec::new();
        encode_packet(
            0x1234,
            0x5678,
            1,
            0,
            Some(&Destination::new("1.1.1.1", 53)),
            b"dns",
            &mut encoded,
        )
        .unwrap();
        assert_eq!(
            &encoded[..10],
            &[0x05, 0x02, 0x12, 0x34, 0x56, 0x78, 1, 0, 0, 3]
        );
        let decoded = decode_packet(&encoded).unwrap();
        assert_eq!(decoded.association_id, 0x1234);
        assert_eq!(decoded.packet_id, 0x5678);
        assert_eq!(decoded.destination, Some(Destination::new("1.1.1.1", 53)));
        assert_eq!(decoded.payload, b"dns");
    }

    #[test]
    fn later_fragment_uses_none_address() {
        let mut encoded = Vec::new();
        encode_packet(7, 9, 2, 1, None, b"tail", &mut encoded).unwrap();
        assert_eq!(encoded[10], ADDRESS_NONE);
        let decoded = decode_packet(&encoded).unwrap();
        assert_eq!(decoded.destination, None);
        assert_eq!(decoded.fragment_total, 2);
        assert_eq!(decoded.fragment_id, 1);
    }

    #[test]
    fn rejects_trailing_truncated_and_misaddressed_fragments() {
        let mut encoded = Vec::new();
        encode_packet(
            1,
            2,
            1,
            0,
            Some(&Destination::new("h", 1)),
            b"x",
            &mut encoded,
        )
        .unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_packet(&trailing), Err(CodecError::TrailingData));
        encoded.pop();
        assert_eq!(decode_packet(&encoded), Err(CodecError::Truncated));

        let mut invalid = Vec::new();
        assert_eq!(
            encode_packet(
                1,
                2,
                2,
                1,
                Some(&Destination::new("h", 1)),
                b"x",
                &mut invalid
            ),
            Err(CodecError::InvalidFragment)
        );
    }

    #[test]
    fn ipv6_address_round_trips() {
        let mut encoded = Vec::new();
        encode_packet(
            1,
            2,
            1,
            0,
            Some(&Destination::new("2001:db8::1", 853)),
            b"x",
            &mut encoded,
        )
        .unwrap();
        assert_eq!(
            decode_packet(&encoded).unwrap().destination,
            Some(Destination::new("2001:db8::1", 853))
        );
    }
}
