//! Local ICMPv4 echo responder.
//!
//! Proxy outbounds do not carry ICMP, so a `ping` from behind the tunnel would otherwise get no
//! reply and read as
//! "internet down". To keep behaviour on par with a normal connection we answer echo requests
//! **locally** — the reply never leaves the device, it just makes `ping <ip>` succeed. Latency in
//! the benchmark is measured over TCP-handshake / DNS / HTTP-TTFB, never ICMP, so a local reply
//! does not distort any comparison.
//!
//! IPv6 (ICMPv6) is intentionally not handled: its checksum needs the IPv6 pseudo-header and the
//! parity test runs IPv4. An unhandled ICMPv6 echo is simply dropped.

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// If `msg` is an ICMPv4 echo request, return the bytes of the corresponding echo reply (with a
/// recomputed checksum). Returns `None` for anything else, which the caller drops.
pub fn echo_reply_v4(msg: &[u8]) -> Option<Vec<u8>> {
    // ICMP header is 8 bytes: type, code, checksum(2), rest-of-header(4), then data.
    if msg.len() < 8 || msg[0] != ICMP_ECHO_REQUEST {
        return None;
    }
    let mut reply = msg.to_vec();
    reply[0] = ICMP_ECHO_REPLY;
    // Zero the checksum field before recomputing.
    reply[2] = 0;
    reply[3] = 0;
    let sum = internet_checksum(&reply);
    reply[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(reply)
}

/// RFC 1071 internet checksum: one's-complement sum of 16-bit words.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_echo_reply_with_valid_checksum() {
        // type=8 code=0 csum=0000 id=0x1234 seq=0x0001 + 4 bytes data.
        let req = [
            8u8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, b'p', b'i', b'n', b'g',
        ];
        let reply = echo_reply_v4(&req).expect("echo request should produce a reply");
        assert_eq!(reply[0], ICMP_ECHO_REPLY);
        // A correct checksum makes the whole message sum to zero (one's complement).
        assert_eq!(internet_checksum(&reply), 0);
        // id/seq/data are echoed back unchanged.
        assert_eq!(&reply[4..], &req[4..]);
    }

    #[test]
    fn ignores_non_echo() {
        assert!(echo_reply_v4(&[0u8; 8]).is_none()); // type 0, not a request
        assert!(echo_reply_v4(&[8u8; 4]).is_none()); // too short
    }
}
