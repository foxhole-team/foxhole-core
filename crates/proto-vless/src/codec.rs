//! VLESS framing isolated from every transport and platform concern.
//!
//! In the `foxhole-2` deployment the link is `type=tcp&security=none&encryption=none`,
//! so VLESS is a thin header over a raw TCP stream (no TLS, no Reality). This module
//! encodes that header and skips the server's response header; the payload that follows
//! is relayed verbatim.
//!
//! Request header (client → server):
//! ```text
//!   version(1)=0 | uuid(16) | addon_len(1) [ + addon ] | command(1) | port(2 BE) | atyp(1) | addr
//! ```
//! `addon` (only when a flow like `xtls-rprx-vision` is set) is a 1-field protobuf:
//! `0x0A, leb128(flow_len), flow_utf8`.
//!
//! Response header (server → client): `version(1) | addon_len(1)` then `addon_len` bytes.
//!
//! UDP-over-TCP payloads (command 2) are length-delimited: `u16 BE len | bytes`.

use foxcore_api::Destination;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    ValueTooLarge,
    InvalidAddress(String),
    Protocol(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated VLESS frame"),
            Self::ValueTooLarge => f.write_str("VLESS value is too large"),
            Self::InvalidAddress(address) => write!(f, "invalid VLESS address: {address}"),
            Self::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CodecError {}

pub type Result<T> = std::result::Result<T, CodecError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    /// Mux.Cool carrier (XUDP). The request header omits the address block —
    /// every sub-connection frame carries its own destination instead.
    Mux,
}

pub const VERSION: u8 = 0;

pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;
pub const CMD_MUX: u8 = 3;

pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 2;
pub const ATYP_IPV6: u8 = 3;

/// Server limits mirrored so we never send a header the inbound will reject.
const MAX_FLOW_LEN: usize = 64;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_UDP_PACKET_LEN: usize = u16::MAX as usize;

/// Encode the VLESS request header into `out`.
///
/// `flow` is the optional XTLS flow addon (e.g. `"xtls-rprx-vision"`); pass `None` for
/// the plain `security=none` deployment.
pub fn encode_request(
    uuid: &[u8; 16],
    command: Command,
    target: &Destination,
    flow: Option<&str>,
    out: &mut Vec<u8>,
) -> Result<()> {
    out.push(VERSION);
    out.extend_from_slice(uuid);
    encode_addon(flow, out)?;
    out.push(match command {
        Command::Tcp => CMD_TCP,
        Command::Udp => CMD_UDP,
        Command::Mux => CMD_MUX,
    });
    if command == Command::Mux {
        // Mux.Cool defines no address in the request header; sending one here
        // desynchronises the inbound before the first sub-connection frame.
        return Ok(());
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    encode_address(target, out)
}

fn encode_addon(flow: Option<&str>, out: &mut Vec<u8>) -> Result<()> {
    match flow {
        None => {
            out.push(0);
            Ok(())
        }
        Some(flow) => {
            let flow = flow.as_bytes();
            if flow.len() > MAX_FLOW_LEN {
                return Err(CodecError::ValueTooLarge);
            }
            // protobuf field #1 (wire type 2): tag 0x0A, LEB128 length, bytes.
            let mut addon = Vec::with_capacity(2 + flow.len());
            addon.push(0x0A);
            leb128(flow.len() as u64, &mut addon);
            addon.extend_from_slice(flow);
            // Outer addon length is a single byte on the wire.
            debug_assert!(addon.len() <= u8::MAX as usize);
            out.push(addon.len() as u8);
            out.extend_from_slice(&addon);
            Ok(())
        }
    }
}

pub(crate) fn encode_address(target: &Destination, out: &mut Vec<u8>) -> Result<()> {
    use std::net::IpAddr;
    match target.ip() {
        Some(IpAddr::V4(v4)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
        None => {
            let domain = target.host.as_bytes();
            if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
                return Err(CodecError::InvalidAddress(target.host.clone()));
            }
            out.push(ATYP_DOMAIN);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain);
        }
    }
    Ok(())
}

/// Length of the VLESS response header at the front of `buf`, or [`CodecError::Truncated`]
/// if the header (`version | addon_len | addon`) has not fully arrived yet. Callers strip
/// this many bytes before treating the rest of the stream as payload.
pub fn response_header_len(buf: &[u8]) -> Result<usize> {
    if buf.len() < 2 {
        return Err(CodecError::Truncated);
    }
    let total = 2 + buf[1] as usize;
    if buf.len() < total {
        return Err(CodecError::Truncated);
    }
    Ok(total)
}

/// Frame one UDP payload for the VLESS UDP-over-TCP path (`u16 BE len | bytes`).
pub fn encode_udp(payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_UDP_PACKET_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Decode one framed UDP payload, returning `(payload_slice, bytes_consumed)` or
/// [`CodecError::Truncated`] when the whole frame has not arrived.
pub fn decode_udp(buf: &[u8]) -> Result<(&[u8], usize)> {
    if buf.len() < 2 {
        return Err(CodecError::Truncated);
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len == 0 {
        return Err(CodecError::Protocol("empty vless udp packet".into()));
    }
    if buf.len() < 2 + len {
        return Err(CodecError::Truncated);
    }
    Ok((&buf[2..2 + len], 2 + len))
}

/// Minimal LEB128 (protobuf-style) unsigned varint — used only for the flow addon length,
/// which the server reads with `read_uvarint`.
fn leb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [
        0xd0, 0xcf, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]; // d0cf0001-0000-4000-8000-000000000000 (documentation UUID; the wire encoding is what is under test)

    #[test]
    fn encodes_tcp_request_to_ipv4() {
        let mut out = Vec::new();
        encode_request(
            &UUID,
            Command::Tcp,
            &Destination::new("8.8.8.8", 53),
            None,
            &mut out,
        )
        .unwrap();
        let mut expected = vec![VERSION];
        expected.extend_from_slice(&UUID);
        expected.push(0); // addon_len
        expected.push(CMD_TCP);
        expected.extend_from_slice(&53u16.to_be_bytes());
        expected.push(ATYP_IPV4);
        expected.extend_from_slice(&[8, 8, 8, 8]);
        assert_eq!(out, expected);
        assert_eq!(out.len(), 1 + 16 + 1 + 1 + 2 + 1 + 4);
    }

    #[test]
    fn mux_request_omits_the_address_block() {
        let mut out = Vec::new();
        encode_request(
            &UUID,
            Command::Mux,
            &Destination::new("8.8.8.8", 53),
            None,
            &mut out,
        )
        .unwrap();
        let mut expected = vec![VERSION];
        expected.extend_from_slice(&UUID);
        expected.push(0); // addon_len
        expected.push(CMD_MUX);
        assert_eq!(out, expected);
    }

    #[test]
    fn encodes_domain_target() {
        let mut out = Vec::new();
        encode_request(
            &UUID,
            Command::Tcp,
            &Destination::new("example.com", 443),
            None,
            &mut out,
        )
        .unwrap();
        // ... atyp | len | "example.com"
        let tail = &out[out.len() - 13..];
        assert_eq!(tail[0], ATYP_DOMAIN);
        assert_eq!(tail[1] as usize, "example.com".len());
        assert_eq!(&tail[2..], b"example.com");
    }

    #[test]
    fn encodes_vision_flow_addon() {
        let mut out = Vec::new();
        encode_request(
            &UUID,
            Command::Tcp,
            &Destination::new("1.1.1.1", 443),
            Some("xtls-rprx-vision"),
            &mut out,
        )
        .unwrap();
        let flow = b"xtls-rprx-vision";
        let addon_len = out[17] as usize; // byte after version(1)+uuid(16)
        assert_eq!(addon_len, 2 + flow.len());
        assert_eq!(out[18], 0x0A); // protobuf tag
        assert_eq!(out[19] as usize, flow.len()); // leb128 (single byte for <128)
        assert_eq!(&out[20..20 + flow.len()], flow);
    }

    #[test]
    fn response_header_len_handles_partial_and_addon() {
        assert_eq!(
            response_header_len(&[0]).unwrap_err(),
            CodecError::Truncated
        );
        assert_eq!(response_header_len(&[0, 0]).unwrap(), 2);
        assert_eq!(response_header_len(&[0, 3, 1, 2, 3, 9, 9]).unwrap(), 5);
        assert_eq!(
            response_header_len(&[0, 3, 1]).unwrap_err(),
            CodecError::Truncated
        );
    }

    #[test]
    fn udp_frames_roundtrip() {
        let mut out = Vec::new();
        encode_udp(b"hello", &mut out).unwrap();
        assert_eq!(&out[..2], &5u16.to_be_bytes());
        let (payload, consumed) = decode_udp(&out).unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(consumed, out.len());
        assert_eq!(decode_udp(&out[..3]).unwrap_err(), CodecError::Truncated);
    }
}
