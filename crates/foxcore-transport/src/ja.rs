//! JA3 and JA4, computed from ClientHello bytes.
//!
//! Behind the off-by-default `fingerprinting` feature, because nothing in a
//! shipped build needs to fingerprint its own hello. It lives in `src` rather
//! than in a test so that `proto-reality` can point the *same* implementation
//! at its parrots: the computation is validated against a live detector in
//! `tests/ja_fingerprint.rs`, and a second copy would be a second thing to
//! validate.
//!
//! JA3: Salesforce, 2017. JA4: FoxIO JA4+ specification.
//! JA3 (Salesforce, 2017) and JA4 (FoxIO, JA4+ spec).
//!
//! Both are pure functions of the ClientHello, which is why a detector is
//! needed only once — to confirm the implementation — and never again.

/// RFC 8701 GREASE values are excluded from every JA3 and JA4 list.
pub fn is_grease(value: u16) -> bool {
    (value >> 8) == (value & 0xff) && (value & 0x0f) == 0x0a
}

pub struct Hello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub has_sni: bool,
}

fn join(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// `version,ciphers,extensions,curves,point_formats`, MD5 of that string.
pub fn ja3_text(hello: &Hello) -> String {
    let ciphers: Vec<u16> = hello
        .ciphers
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let extensions: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let groups: Vec<u16> = hello
        .groups
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let formats = hello
        .point_formats
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        hello.legacy_version,
        join(&ciphers),
        join(&extensions),
        join(&groups),
        formats
    )
}

pub fn ja3_hash(hello: &Hello) -> String {
    hex(&md5(ja3_text(hello).as_bytes()))
}

/// The first character of JA4_a. The JA4 specification calls it the transport:
/// "QUIC=`q`, DTLS=`d`, or TLS over TCP=`t`".
///
/// It exists because the same ClientHello means a different client depending on
/// what carried it — and because `t` was hardcoded here, every fingerprint this
/// workspace computed for a QUIC hello named the wrong protocol. FoxIO publish
/// Chrome's QUIC fingerprint as `q13d0312h3_…`; nothing that starts with `t`
/// can be compared against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    fn letter(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
        }
    }
}

/// JA4 for a hello that arrived over TCP.
///
/// `_r` is the raw (unhashed) form the detector also reports, which is what
/// makes a mismatch debuggable rather than a bare hash difference.
pub fn ja4(hello: &Hello) -> (String, String) {
    ja4_over(hello, Transport::Tcp)
}

/// JA4: `JA4_a_JA4_b_JA4_c`, for a hello that arrived over `transport`.
pub fn ja4_over(hello: &Hello, transport: Transport) -> (String, String) {
    let ciphers: Vec<u16> = hello
        .ciphers
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let extensions: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();

    // Highest offered version: `supported_versions` wins over the legacy
    // field, GREASE excluded.
    let version = hello
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(hello.legacy_version);
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };

    let sni = if hello.has_sni { 'd' } else { 'i' };
    let alpn = hello.alpn.first().map_or("00".to_owned(), |value| {
        let bytes = value.as_bytes();
        format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
    });

    let a = format!(
        "{}{version}{sni}{:02}{:02}{alpn}",
        transport.letter(),
        ciphers.len().min(99),
        extensions.len().min(99)
    );

    // JA4_b: ciphers, sorted, hex, comma-joined.
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let b_raw = hex_list(&sorted_ciphers);

    // JA4_c: extensions sorted with SNI and ALPN removed, then the
    // signature algorithms **in order**, separated by an underscore.
    let mut sorted_extensions: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|value| *value != 0x0000 && *value != 0x0010)
        .collect();
    sorted_extensions.sort_unstable();
    let sigalgs = hex_list(&hello.signature_algorithms);
    let c_raw = if sigalgs.is_empty() {
        hex_list(&sorted_extensions)
    } else {
        format!("{}_{}", hex_list(&sorted_extensions), sigalgs)
    };

    let raw = format!("{a}_{b_raw}_{c_raw}");
    let hashed = format!(
        "{a}_{}_{}",
        truncated_sha256(&b_raw),
        truncated_sha256(&c_raw)
    );
    (hashed, raw)
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// JA4 truncates to the first 12 hex characters. An empty list hashes to
/// twelve zeroes by definition, not to the hash of the empty string.
fn truncated_sha256(text: &str) -> String {
    if text.is_empty() {
        return "000000000000".to_owned();
    }
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, text.as_bytes());
    hex(digest.as_ref())[..12].to_owned()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// MD5, for JA3 only. JA3 specifies MD5 and nothing else; it is a label
/// here, never a security primitive.
fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301_u32,
        0xefcd_ab89_u32,
        0x98ba_dcfe_u32,
        0x1032_5476_u32,
    );
    for chunk in message.chunks(64) {
        let m: Vec<u32> = (0..16)
            .map(|i| {
                u32::from_le_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ])
            })
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0_u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// Parse a ClientHello *handshake message* (no record header).
pub fn parse(body: &[u8]) -> Hello {
    let be16 = |at: usize| u16::from_be_bytes([body[at], body[at + 1]]);
    let mut hello = Hello {
        legacy_version: be16(4),
        ciphers: Vec::new(),
        extensions: Vec::new(),
        groups: Vec::new(),
        point_formats: Vec::new(),
        signature_algorithms: Vec::new(),
        alpn: Vec::new(),
        supported_versions: Vec::new(),
        has_sni: false,
    };
    let session_id_len = body[38] as usize;
    let mut cursor = 39 + session_id_len;
    let cipher_len = be16(cursor) as usize;
    hello.ciphers = (0..cipher_len / 2)
        .map(|i| be16(cursor + 2 + i * 2))
        .collect();
    cursor += 2 + cipher_len;
    cursor += 1 + body[cursor] as usize;
    let extensions_len = be16(cursor) as usize;
    cursor += 2;
    let end = cursor + extensions_len;
    while cursor + 4 <= end {
        let extension_type = be16(cursor);
        let length = be16(cursor + 2) as usize;
        let start = cursor + 4;
        let slice = &body[start..start + length];
        hello.extensions.push(extension_type);
        let sbe16 = |at: usize| u16::from_be_bytes([slice[at], slice[at + 1]]);
        match extension_type {
            0x0000 => hello.has_sni = true,
            0x000a => {
                let list = sbe16(0) as usize;
                hello.groups = (0..list / 2).map(|i| sbe16(2 + i * 2)).collect();
            }
            0x000b => hello.point_formats = slice[1..].to_vec(),
            0x000d => {
                let list = sbe16(0) as usize;
                hello.signature_algorithms = (0..list / 2).map(|i| sbe16(2 + i * 2)).collect();
            }
            0x002b => {
                let list = slice[0] as usize;
                hello.supported_versions = (0..list / 2).map(|i| sbe16(1 + i * 2)).collect();
            }
            0x0010 => {
                let mut at = 2;
                while at < slice.len() {
                    let length = slice[at] as usize;
                    hello.alpn.push(
                        String::from_utf8_lossy(&slice[at + 1..at + 1 + length]).into_owned(),
                    );
                    at += 1 + length;
                }
            }
            _ => {}
        }
        cursor = start + length;
    }
    hello
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    /// The RFC 9001 Appendix A.2 hello, which is a QUIC hello by construction —
    /// it carries extension 0x39 and could not have travelled over TCP.
    fn quic_hello() -> Hello {
        Hello {
            legacy_version: 0x0303,
            ciphers: vec![0x1301, 0x1302],
            extensions: vec![0x0000, 0x000a, 0x0010, 0x0033, 0x002b, 0x000d, 0x0039],
            groups: vec![0x001d, 0x0017, 0x0018],
            point_formats: Vec::new(),
            signature_algorithms: vec![0x0403, 0x0503],
            alpn: vec!["h3".to_owned()],
            supported_versions: vec![0x0304],
            has_sni: true,
        }
    }

    /// The bug this fixes: `ja4` hardcoded `t`, so a QUIC hello was reported
    /// under the transport character that means TLS over TCP. FoxIO publish
    /// Chrome's QUIC fingerprint starting `q13d…`; nothing starting with `t`
    /// could ever be compared against it.
    #[test]
    fn the_transport_character_follows_the_transport() {
        let hello = quic_hello();
        assert!(ja4_over(&hello, Transport::Quic).0.starts_with('q'));
        assert!(ja4_over(&hello, Transport::Tcp).0.starts_with('t'));
    }

    /// Negative control: the character is the *only* thing the transport
    /// changes. If a future edit made it alter the hashes as well, the two
    /// strings would stop differing by exactly one byte and this would fail.
    #[test]
    fn the_transport_changes_the_first_character_and_nothing_else() {
        let hello = quic_hello();
        let (over_quic, quic_raw) = ja4_over(&hello, Transport::Quic);
        let (over_tcp, tcp_raw) = ja4_over(&hello, Transport::Tcp);
        assert_ne!(over_quic, over_tcp);
        assert_eq!(over_quic[1..], over_tcp[1..]);
        assert_eq!(quic_raw[1..], tcp_raw[1..]);
    }

    /// The plain `ja4` entry point keeps its old meaning, so every existing
    /// caller — the REALITY parrot tables and the live-detector test — is
    /// untouched by the new parameter.
    #[test]
    fn the_original_entry_point_is_still_tcp() {
        let hello = quic_hello();
        assert_eq!(ja4(&hello), ja4_over(&hello, Transport::Tcp));
    }
}
