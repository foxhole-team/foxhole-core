//! Hysteria2 framing isolated from QUIC and platform concerns.
//!
//! Hysteria2 runs over QUIC (ALPN `h3`). The `foxhole-hy2-2` link uses `insecure=1`, i.e.
//! a self-signed server cert the client must accept without a CA (see the design doc for
//! how that is pinned rather than blindly trusted).
//!
//! Three wire pieces live here (the QUIC/H3 transport that carries them is in the engine
//! layer, not this crate):
//!
//! * **Auth** — an HTTP/3 `POST /auth` request whose headers carry the credential; encoded
//!   by [`AuthRequest`]. The server replies `:status 233` with `hysteria-udp` / `hysteria-cc-rx`.
//! * **TCP proxy** — a QUIC bidi stream opened with [`encode_tcp_request`]; the reply is
//!   parsed by [`decode_tcp_response`].
//! * **UDP** — QUIC datagrams built/parsed by [`encode_udp_datagram`] / [`decode_udp_datagram`].

use crate::{CodecError, Result, varint};
use foxcore_api::{Destination, SecretString};
use zerocopy::byteorder::network_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The fixed 8-byte prefix of a Hysteria2 UDP datagram, exactly as it sits on the wire
/// (`session_id` and `packet_id` are big-endian; the two fragment bytes are single octets).
/// `zerocopy` gives us bounds-checked, byte-order-correct access without hand-rolled indexing
/// or `from_be_bytes`, and keeps this crate free of `unsafe`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct UdpHeader {
    session_id: U32,
    packet_id: U16,
    frag_id: u8,
    frag_count: u8,
}

/// The TCP request stream begins with this varint frame type (server:
/// `HYSTERIA2_TCP_REQUEST_FRAME = 0x401`, wire bytes `[0x44, 0x01]`).
pub const TCP_REQUEST_FRAME_TYPE: u64 = 0x401;

/// H3 status string the server sends on successful auth.
pub const AUTH_OK_STATUS: &str = "233";

// Hard limits mirrored from the server so we never emit a frame it will reject.
pub const MAX_ADDRESS_LEN: u64 = 2048;
pub const MAX_PADDING_LEN: u64 = 4096;
/// Largest padding this client will skip on a TCP response.
///
/// Not mirrored from the server — it is a bound on *us*. The length is a
/// server-supplied varint that can name 2^62 bytes, and the response header is
/// now taken lazily, which means the reader accumulates until the header is
/// complete. Without a cap, a hostile or broken server could make that
/// accumulation unbounded by promising padding it never sends. 64 KiB is far
/// above any legitimate Hysteria2 padding and is the same figure the eager
/// reader used before.
pub const MAX_RESPONSE_PADDING_LEN: u64 = 64 * 1024;
pub const MAX_UDP_FRAGMENTS: u8 = 16;
pub const MAX_UDP_PAYLOAD_LEN: usize = u16::MAX as usize;

/// The header set the client puts on the H3 `/auth` request. Rendering to actual QPACK
/// bytes happens in the engine's H3 layer; keeping the *values* here means the credential
/// contract is unit-tested and fuzzed next to the rest of the protocol.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub password: SecretString,
    /// Client receive bandwidth in **bytes per second**. The server feeds this straight
    /// into its Brutal congestion target for the server→client direction, so `0` disables
    /// Brutal and falls back to the default controller. Send a real estimate.
    pub cc_rx_bytes_per_sec: u64,
}

impl AuthRequest {
    /// The `(name, value)` header pairs, in the order Hysteria2 expects. Pseudo-headers
    /// (`:method`, `:scheme`, `:authority`, `:path`) are added by the H3 encoder; these are
    /// the protocol-specific fields the server reads (`hysteria-auth`, `hysteria-cc-rx`,
    /// `hysteria-padding`).
    pub fn headers(&self, padding: &str) -> Vec<(&'static str, String)> {
        vec![
            ("hysteria-auth", self.password.expose().to_owned()),
            ("hysteria-cc-rx", self.cc_rx_bytes_per_sec.to_string()),
            ("hysteria-padding", padding.to_string()),
        ]
    }

    /// `(:authority, :path)` the server matches (`authority == "hysteria"`, `path == "/auth"`).
    pub const AUTHORITY: &'static str = "hysteria";
    pub const PATH: &'static str = "/auth";
}

/// Parsed server auth response (from the H3 `:status` + `hysteria-*` headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub ok: bool,
    pub udp_enabled: bool,
    /// Server receive bandwidth in bytes/sec (client uses it as its Brutal target).
    pub cc_rx_bytes_per_sec: u64,
}

/// Build the auth response view from decoded H3 header fields.
pub fn parse_auth_response<'a, I>(status: &str, headers: I) -> AuthResponse
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut resp = AuthResponse {
        ok: status == AUTH_OK_STATUS,
        udp_enabled: false,
        cc_rx_bytes_per_sec: 0,
    };
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("hysteria-udp") {
            resp.udp_enabled = value.eq_ignore_ascii_case("true");
        } else if name.eq_ignore_ascii_case("hysteria-cc-rx") {
            resp.cc_rx_bytes_per_sec = value.parse().unwrap_or(0);
        }
    }
    resp
}

/// Encode the Hysteria2 TCP proxy request onto a freshly opened QUIC bidi stream.
pub fn encode_tcp_request(target: &Destination, padding: &[u8], out: &mut Vec<u8>) -> Result<()> {
    varint::encode(TCP_REQUEST_FRAME_TYPE, out);
    let authority = target.authority();
    let addr = authority.as_bytes();
    if addr.is_empty() || addr.len() as u64 > MAX_ADDRESS_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    varint::encode(addr.len() as u64, out);
    out.extend_from_slice(addr);
    if padding.len() as u64 > MAX_PADDING_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    varint::encode(padding.len() as u64, out);
    out.extend_from_slice(padding);
    Ok(())
}

/// Parsed TCP proxy response header (`status | msg | padding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    pub ok: bool,
    pub message: String,
}

/// Decode the TCP response header from `buf` at `*pos`, advancing past the whole header
/// (including padding) so the remaining stream is pure payload.
///
/// The two error kinds are not interchangeable to the caller that reads this off
/// a live stream: [`CodecError::Truncated`] means *not yet* and is answered by
/// reading more, while [`CodecError::ValueTooLarge`] means *never* and must end
/// the flow. That is why the declared lengths are checked against their limits
/// before the buffer is checked against them — a length of 2^62 would otherwise
/// report "truncated" forever and the reader would buffer against a server that
/// is never going to finish its header.
pub fn decode_tcp_response(buf: &[u8], pos: &mut usize) -> Result<TcpResponse> {
    let status = varint::decode(buf, pos)?; // server writes 0 = ok, 1 = error
    let msg_len = varint::decode(buf, pos)?;
    if msg_len > MAX_ADDRESS_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    let msg_len = msg_len as usize;
    if buf.len() < *pos + msg_len {
        return Err(CodecError::Truncated);
    }
    let message = String::from_utf8_lossy(&buf[*pos..*pos + msg_len]).into_owned();
    *pos += msg_len;
    let pad_len = varint::decode(buf, pos)?;
    if pad_len > MAX_RESPONSE_PADDING_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    let pad_len = pad_len as usize;
    if buf.len() < *pos + pad_len {
        return Err(CodecError::Truncated);
    }
    *pos += pad_len;
    Ok(TcpResponse {
        ok: status == 0,
        message,
    })
}

/// A decoded UDP datagram header plus a view of its payload fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub destination: String,
    pub payload: &'a [u8],
}

/// Build a Hysteria2 UDP datagram (sent as a QUIC datagram).
pub fn encode_udp_datagram(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    target: &Destination,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if frag_count == 0 || frag_id >= frag_count {
        return Err(CodecError::Protocol("invalid udp fragment header".into()));
    }
    let authority = target.authority();
    let addr = authority.as_bytes();
    if addr.is_empty() || addr.len() as u64 > MAX_ADDRESS_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    if payload.len() > MAX_UDP_PAYLOAD_LEN {
        return Err(CodecError::ValueTooLarge);
    }
    let header = UdpHeader {
        session_id: U32::new(session_id),
        packet_id: U16::new(packet_id),
        frag_id,
        frag_count,
    };
    out.extend_from_slice(header.as_bytes());
    varint::encode(addr.len() as u64, out);
    out.extend_from_slice(addr);
    out.extend_from_slice(payload);
    Ok(())
}

/// Parse a Hysteria2 UDP datagram. Mirrors the server's validation exactly
/// (`frag_count != 0`, `frag_id < frag_count`, bounded address).
pub fn decode_udp_datagram(buf: &[u8]) -> Result<UdpDatagram<'_>> {
    // `ref_from_prefix` bounds-checks the 8-byte header and reads it in network order for us.
    let (header, rest) = UdpHeader::ref_from_prefix(buf).map_err(|_| CodecError::Truncated)?;
    let frag_id = header.frag_id;
    let frag_count = header.frag_count;
    if frag_count == 0 || frag_count > MAX_UDP_FRAGMENTS || frag_id >= frag_count {
        return Err(CodecError::Protocol("invalid udp fragment header".into()));
    }
    let mut pos = 0usize;
    let addr_len = varint::decode(rest, &mut pos)? as usize;
    if addr_len == 0 || addr_len as u64 > MAX_ADDRESS_LEN || rest.len() < pos + addr_len {
        return Err(CodecError::Truncated);
    }
    let destination = String::from_utf8_lossy(&rest[pos..pos + addr_len]).into_owned();
    pos += addr_len;
    Ok(UdpDatagram {
        session_id: header.session_id.get(),
        packet_id: header.packet_id.get(),
        frag_id,
        frag_count,
        destination,
        payload: &rest[pos..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_tcp_request_with_server_frame_bytes() {
        let mut out = Vec::new();
        encode_tcp_request(&Destination::new("example.com", 443), &[], &mut out).unwrap();
        let mut expected = vec![0x44, 0x01]; // varint(0x401)
        let authority = b"example.com:443";
        expected.push(authority.len() as u8); // varint(15) -> single byte 0x0F
        expected.extend_from_slice(authority);
        expected.push(0x00); // varint(padding_len = 0)
        assert_eq!(out, expected);
    }

    #[test]
    fn ipv6_target_uses_bracketed_authority() {
        let mut out = Vec::new();
        encode_tcp_request(&Destination::new("2001:db8::1", 443), &[], &mut out).unwrap();
        // frame(2) + varint len(1) then the authority, then padding_len varint (0x00)
        let authority = b"[2001:db8::1]:443";
        assert_eq!(&out[3..3 + authority.len()], authority);
        assert_eq!(out[3 + authority.len()], 0x00);
    }

    #[test]
    fn decodes_ok_tcp_response() {
        // status=0, msg_len=2 "ok", padding_len=3
        let buf = [0x00, 0x02, b'o', b'k', 0x03, 0, 0, 0];
        let mut pos = 0;
        let resp = decode_tcp_response(&buf, &mut pos).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.message, "ok");
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn udp_datagram_roundtrips() {
        let mut out = Vec::new();
        encode_udp_datagram(
            0xDEADBEEF,
            7,
            0,
            1,
            &Destination::new("1.1.1.1", 53),
            b"query",
            &mut out,
        )
        .unwrap();
        let dg = decode_udp_datagram(&out).unwrap();
        assert_eq!(dg.session_id, 0xDEADBEEF);
        assert_eq!(dg.packet_id, 7);
        assert_eq!(dg.frag_count, 1);
        assert_eq!(dg.destination, "1.1.1.1:53");
        assert_eq!(dg.payload, b"query");
    }

    #[test]
    fn udp_datagram_header_is_big_endian_on_the_wire() {
        // Pin the exact byte layout so the zerocopy struct can never silently drift from the
        // server's `session_id(4 BE) | packet_id(2 BE) | frag_id | frag_count | ...`.
        let mut out = Vec::new();
        encode_udp_datagram(
            0x01020304,
            0x0506,
            1,
            3,
            &Destination::new("h", 1),
            b"x",
            &mut out,
        )
        .unwrap();
        assert_eq!(&out[..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x03]);
        // varint(addr_len=3) | "h:1" | payload "x"
        assert_eq!(&out[8..], &[0x03, b'h', b':', b'1', b'x']);
    }

    #[test]
    fn decode_udp_datagram_rejects_short_header() {
        assert_eq!(
            decode_udp_datagram(&[0, 0, 0, 1, 0, 1, 0]).unwrap_err(),
            CodecError::Truncated
        );
    }

    #[test]
    fn rejects_bad_fragment_headers() {
        let mut out = Vec::new();
        assert!(
            encode_udp_datagram(1, 1, 2, 2, &Destination::new("h", 1), b"", &mut out,).is_err()
        );
        // frag_count = 0 in a raw datagram
        let bad = [0, 0, 0, 1, 0, 1, 0, 0, 0x01, b'x'];
        assert!(decode_udp_datagram(&bad).is_err());
    }

    #[test]
    fn parses_auth_response_headers() {
        let resp = parse_auth_response(
            "233",
            [("hysteria-udp", "true"), ("hysteria-cc-rx", "12500000")],
        );
        assert_eq!(
            resp,
            AuthResponse {
                ok: true,
                udp_enabled: true,
                cc_rx_bytes_per_sec: 12_500_000
            }
        );
    }

    #[test]
    fn auth_request_debug_redacts_password() {
        let request = AuthRequest {
            password: SecretString::new("do-not-log-hysteria-auth"),
            cc_rx_bytes_per_sec: 1,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(request.password.expose()));
        assert!(rendered.contains("REDACTED"));
    }
}
