//! Valid inputs for each target, lifted from the crates' own unit tests.
//!
//! A fuzzer that starts from random noise spends its whole budget rediscovering
//! that a DNS message begins with a twelve-byte header. Starting from real
//! packets means the first mutation is already inside the structure, which is
//! where the bugs are. These are also what `tests/` mutates, so a seed that
//! stops being valid fails on stable rather than silently degrading the corpus.

/// Every target, in the order they are worth fuzzing — most network-exposed
/// first.
pub const TARGETS: [&str; 8] = [
    "flow_key_from_packet",
    "dns_message",
    "wireguard_message",
    "socks_codec",
    "http_codec",
    "reality_records",
    "share_link",
    "shadowtls_server_stream",
];

pub struct Seed {
    /// File name under `fuzz/corpus/<target>/`.
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

/// Panics on an unknown target rather than returning an empty corpus, which
/// would look like "seeded" to every caller.
pub fn seeds_for(target: &str) -> Vec<Seed> {
    match target {
        "flow_key_from_packet" => flow_key_seeds(),
        "dns_message" => dns_seeds(),
        "wireguard_message" => wireguard_seeds(),
        "socks_codec" => socks_seeds(),
        "http_codec" => http_seeds(),
        "reality_records" => reality_seeds(),
        "share_link" => share_link_seeds(),
        "shadowtls_server_stream" => shadowtls_seeds(),
        other => panic!("no seeds defined for target {other}"),
    }
}

fn seed(name: &'static str, bytes: impl Into<Vec<u8>>) -> Seed {
    Seed {
        name,
        bytes: bytes.into(),
    }
}

const APP: [u8; 4] = [10, 0, 0, 2];
const REMOTE: [u8; 4] = [93, 184, 216, 34];

fn ipv4_packet(header_words: u8, protocol: u8, fragment_offset: u16, payload: &[u8]) -> Vec<u8> {
    let header_len = usize::from(header_words) * 4;
    let mut packet = vec![0_u8; header_len + payload.len()];
    packet[0] = 0x40 | header_words;
    let total = u16::try_from(packet.len()).expect("seed packets are small");
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&APP);
    packet[16..20].copy_from_slice(&REMOTE);
    packet[header_len..].copy_from_slice(payload);
    packet
}

fn ports(source: u16, destination: u16) -> Vec<u8> {
    let mut payload = vec![0_u8; 8];
    payload[0..2].copy_from_slice(&source.to_be_bytes());
    payload[2..4].copy_from_slice(&destination.to_be_bytes());
    payload
}

fn flow_key_seeds() -> Vec<Seed> {
    let mut ipv6 = vec![0_u8; 60];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&20_u16.to_be_bytes());
    ipv6[6] = 6; // TCP
    ipv6[7] = 64;
    ipv6[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    ipv6[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ipv6[40..42].copy_from_slice(&51_000_u16.to_be_bytes());
    ipv6[42..44].copy_from_slice(&443_u16.to_be_bytes());

    vec![
        seed("ipv4_udp", ipv4_packet(5, 17, 0, &ports(40_000, 443))),
        seed("ipv4_tcp", ipv4_packet(5, 6, 0, &ports(51_000, 443))),
        // ICMP has no ports at all; the parser must still key the flow.
        seed("ipv4_icmp", ipv4_packet(5, 1, 0, &[8, 0, 0, 0])),
        // A non-first fragment: the port bytes are payload, not ports.
        seed(
            "ipv4_fragment",
            ipv4_packet(5, 17, 0x0001, &ports(40_000, 443)),
        ),
        // IHL 6: four bytes of options shift the transport header.
        seed("ipv4_options", ipv4_packet(6, 17, 0, &ports(40_000, 443))),
        seed("ipv6_tcp", ipv6),
    ]
}

/// `example.com IN A`, the shape every `foxcore-dns` unit test builds.
fn dns_query(domain: &str, record_type: u16, transaction_id: u16) -> Vec<u8> {
    let mut packet = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    packet[..2].copy_from_slice(&transaction_id.to_be_bytes());
    for label in domain.split('.') {
        packet.push(u8::try_from(label.len()).expect("seed labels are short"));
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet
}

fn dns_seeds() -> Vec<Seed> {
    // Compressed A answer, byte for byte the `observes_compressed_a_answer`
    // fixture: the 0xc00c pointer is what makes `read_name` jump.
    let mut compressed_a = vec![
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1,
    ];
    compressed_a.extend_from_slice(&60_u32.to_be_bytes());
    compressed_a.extend_from_slice(&[0, 4]);
    compressed_a.extend_from_slice(&[93, 184, 216, 34]);

    let mut compressed_aaaa = vec![
        0x12, 0x35, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 3, b'c', b'o', b'm', 0, 0, 28, 0, 1, 0xc0, 0x0c, 0, 28, 0, 1,
    ];
    compressed_aaaa.extend_from_slice(&300_u32.to_be_bytes());
    compressed_aaaa.extend_from_slice(&[0, 16]);
    compressed_aaaa.extend_from_slice(&[
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
    ]);

    // NXDOMAIN with an SOA in the authority section: the record walk has to
    // cross a record whose rdata it does not understand.
    let mut nxdomain = vec![
        0x12, 0x36, 0x81, 0x83, 0, 1, 0, 0, 0, 1, 0, 0, 7, b'a', b'b', b's', b'e', b'n', b't',
        b'x', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0, 0x14, 0, 6, 0, 1,
    ];
    nxdomain.extend_from_slice(&900_u32.to_be_bytes());
    nxdomain.extend_from_slice(&[0, 4]);
    nxdomain.extend_from_slice(&[0xc0, 0x14, 0, 0]);

    // A query carrying an EDNS0 OPT record in the additional section, which the
    // TTL walk has to skip rather than treat as a cacheable TTL.
    let mut with_opt = dns_query("example.com", 1, 0x1237);
    with_opt[11] = 1; // ARCOUNT = 1
    with_opt.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);

    vec![
        seed("query_a", dns_query("example.com", 1, 0x1234)),
        seed("query_aaaa", dns_query("example.com", 28, 0x1235)),
        seed("query_ptr", dns_query("4.3.2.1.in-addr.arpa", 12, 0x1236)),
        seed("query_with_opt", with_opt),
        seed("response_a_compressed", compressed_a),
        seed("response_aaaa_compressed", compressed_aaaa),
        seed("response_nxdomain_soa", nxdomain),
    ]
}

fn wireguard_seeds() -> Vec<Seed> {
    let mut initiation = vec![0_u8; 148];
    initiation[0] = 1;
    initiation[4..8].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
    initiation[8..40].fill(0x11);
    initiation[40..88].fill(0x22);
    initiation[88..116].fill(0x33);
    initiation[116..132].fill(0x44);
    initiation[132..148].fill(0x55);

    // The same message with a provider's client identifier in the reserved
    // field: the decoder must ignore it, `message_type` must not.
    let mut identified = initiation.clone();
    identified[2] = 1;

    let mut response = vec![0_u8; 92];
    response[0] = 2;
    response[4..8].copy_from_slice(&7_u32.to_le_bytes());
    response[8..12].copy_from_slice(&9_u32.to_le_bytes());
    response[12..44].fill(0xAB);
    response[44..60].fill(0xCD);
    response[60..76].fill(0x01);
    response[76..92].fill(0x02);

    let mut cookie = vec![0_u8; 64];
    cookie[0] = 3;
    cookie[4..8].copy_from_slice(&42_u32.to_le_bytes());
    cookie[8..32].fill(0x0F);
    cookie[32..64].fill(0xF0);

    // Keepalive: header plus a bare AEAD tag, the shortest legal transport
    // frame there is.
    let mut keepalive = vec![0_u8; 32];
    keepalive[0] = 4;
    keepalive[4..8].copy_from_slice(&0x0102_0304_u32.to_le_bytes());
    keepalive[8..16].copy_from_slice(&0x0A0B_0C0D_0E0F_1011_u64.to_le_bytes());
    keepalive[16..32].fill(0x77);

    let mut transport = keepalive.clone();
    transport.extend_from_slice(&[0x5A; 96]);

    vec![
        seed("initiation", initiation),
        seed("initiation_reserved_set", identified),
        seed("response", response),
        seed("cookie_reply", cookie),
        seed("transport_keepalive", keepalive),
        seed("transport_data", transport),
    ]
}

fn socks_seeds() -> Vec<Seed> {
    let mut reply_ipv6 = vec![0x05, 0x00, 0x00, 0x04];
    reply_ipv6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    reply_ipv6.extend_from_slice(&[0x01, 0xbb]);

    vec![
        seed(
            "reply_ipv4",
            [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x27, 0x0f],
        ),
        seed("reply_ipv6", reply_ipv6),
        seed(
            "reply_domain",
            b"\x05\x00\x00\x03\x0brelay.local\x04\x38".to_vec(),
        ),
        seed("reply_refused", [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        seed(
            "udp_reply_ipv4",
            b"\x00\x00\x00\x01\x08\x08\x08\x08\x00\x35answer".to_vec(),
        ),
        seed(
            "udp_reply_domain",
            b"\x00\x00\x00\x03\x0bexample.com\x00\x35query".to_vec(),
        ),
        // FRAG != 0, which must never decode: reassembly is not implemented.
        seed(
            "udp_fragment",
            b"\x00\x00\x01\x01\x08\x08\x08\x08\x00\x35x".to_vec(),
        ),
    ]
}

fn http_seeds() -> Vec<Seed> {
    let mut flood = Vec::from(&b"HTTP/1.1 200 OK\r\n"[..]);
    for index in 0..64 {
        flood.extend_from_slice(format!("X-Pad-{index}: v\r\n").as_bytes());
    }
    flood.extend_from_slice(b"\r\n");

    vec![
        seed(
            "established",
            b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
        ),
        // A status line with no reason phrase is legal and nearly untested.
        seed("no_reason_phrase", b"HTTP/1.1 200\r\n\r\n".to_vec()),
        seed(
            "with_headers",
            b"HTTP/1.1 200 OK\r\nProxy-Agent: fox\r\nVia: 1.1 proxy\r\n\r\n".to_vec(),
        ),
        seed(
            "proxy_auth_required",
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\n\r\n".to_vec(),
        ),
        // No blank line yet: the "read more" branch.
        seed("incomplete", b"HTTP/1.1 200 OK\r\nProxy-Agent: fox\r\n".to_vec()),
        seed("header_flood", flood),
    ]
}

fn reality_seeds() -> Vec<Seed> {
    // One byte past the fragmentation threshold, so the multi-record path is in
    // the corpus from the first iteration.
    let fragmenting: Vec<u8> = (0..=16 * 1024_usize)
        .map(|index| u8::try_from(index % 251).expect("modulo 251 fits a byte"))
        .collect();

    vec![
        seed(
            "http_request",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        ),
        seed("single_byte", [0x17]),
        // Plaintext ending in zeros is what the read side's padding strip eats
        // if the content-type trailer is ever handled in the wrong order.
        seed("trailing_zeros", b"payload\x00\x00\x00\x00".to_vec()),
        seed("all_zeros", [0_u8; 8]),
        seed("tls_alert_body", [0x01, 0x00]),
        seed("fragmenting", fragmenting),
    ]
}

/// Real links, in the shapes a subscription actually carries: one per scheme
/// the core imports, one base64 body, and the two failure shapes a provider
/// produces without meaning to — a support URL among the servers, and a body
/// that is base64 of nothing useful.
///
/// Lifted from `foxcore-link`'s own tests, so a fixture that changes shape
/// fails `the_seeds_reach_the_parsers` rather than quietly degrading the corpus.
fn share_link_seeds() -> Vec<Seed> {
    const VLESS: &str =
        "vless://d0cf0001-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp#vless";
    const HY2: &str = "hysteria2://secret@example.com:8443/?sni=example.com&insecure=1#hy2";
    const TROJAN: &str = "trojan://secret@example.com:443?type=tcp&sni=example.com#trojan";
    const SS: &str = "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:8388#outline";
    // Percent-encoded exactly as a provider writes them: base64 keys carry `/`
    // and `=`, which a URL parser will not accept raw in userinfo or a query.
    const WG: &str = "wireguard://l40T7xeXzdV13X8f%2F1IjcRR0wbrACb0bebRqcN01mbQ%3D@edge.example:51820\
                      ?publickey=%2F94rCPHnchHT%2FrfGYWR3oBaNKtGcelLi4ainYamMiTc%3D&address=10.8.0.2%2F32";

    let plain_body = format!("{VLESS}\n{HY2}\n{TROJAN}\n{SS}\n");
    let base64_body = base64_standard(plain_body.as_bytes());

    vec![
        seed("vless", VLESS.as_bytes().to_vec()),
        seed("hysteria2", HY2.as_bytes().to_vec()),
        seed("trojan", TROJAN.as_bytes().to_vec()),
        seed("shadowsocks", SS.as_bytes().to_vec()),
        seed("wireguard", WG.as_bytes().to_vec()),
        seed("subscription_plain", plain_body.clone().into_bytes()),
        seed("subscription_base64", base64_body.into_bytes()),
        // What a real body has in it besides servers: a notice line the parser
        // must reject by itself without losing the servers around it.
        seed(
            "subscription_with_notice",
            format!("https://provider.example/support\n{VLESS}\n").into_bytes(),
        ),
        // A scheme the core knows the name of and does not implement. The
        // answer must stay "not supported", never a downgrade.
        seed(
            "unknown_scheme",
            b"ssr://ZXhhbXBsZS5jb206ODM4ODphdXRoX2FlczEyOF9tZDU=".to_vec(),
        ),
        seed("empty", Vec::new()),
    ]
}

/// Standard-alphabet base64 with padding, written out rather than pulled in:
/// the harness has no base64 dependency and one seed does not justify one.
fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let mut buffer = [0_u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let packed = u32::from(buffer[0]) << 16 | u32::from(buffer[1]) << 8 | u32::from(buffer[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let shift = 18 - index * 6;
                out.push(char::from(ALPHABET[(packed >> shift) as usize & 0x3f]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One socket read per element, packed into the `[length: u16][bytes]` encoding
/// `shadowtls_segments` expects.
///
/// Written this way so the seeds read as what they are — a server's reply
/// arriving in a particular number of pieces — rather than as a byte blob whose
/// framing has to be decoded by hand to be reviewed.
fn reads(name: &'static str, socket_reads: &[&[u8]]) -> Seed {
    let mut bytes = Vec::new();
    for read in socket_reads {
        let length = u16::try_from(read.len()).expect("seed reads are short");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(read);
    }
    seed(name, bytes)
}

/// A TLS record with an arbitrary body, for the shapes a *hostile* server sends
/// and the protocol's own encoder therefore refuses to produce.
fn tls_record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len()).expect("seed records are short");
    let mut record = vec![kind, 3, 3];
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(payload);
    record
}

/// Real ShadowTLS server traffic, in the shapes that put the client's state
/// machine into each of its states.
///
/// Built through `proto_shadowtls::fuzz_internals`, not written out as bytes, so
/// a seed cannot drift away from the protocol: if the record layout or the
/// chained tag changed, these stop authenticating and
/// `the_seeds_reach_the_parsers` says so on the pinned toolchain.
fn shadowtls_seeds() -> Vec<Seed> {
    use proto_shadowtls::fuzz_internals as shadowtls;

    use crate::{SHADOWTLS_PASSWORD, SHADOWTLS_RANDOM};

    let hello = shadowtls::server_hello_record(SHADOWTLS_RANDOM);
    let mut sender = shadowtls::ProofSender::new(SHADOWTLS_PASSWORD, SHADOWTLS_RANDOM)
        .expect("a fixed non-empty password cannot fail to key the chain");
    let first_proof = sender
        .record(b"GET / HTTP/1.1\r\n")
        .expect("a short payload");
    let second_proof = sender.record(b"").expect("an empty payload is legal");

    // The ServerHello with its record header in one read and its body in
    // another: the reassembly the fixed-size fixtures never reach.
    let split_hello: Vec<&[u8]> = vec![&hello[..3], &hello[3..20], &hello[20..]];

    // The proof record one byte at a time — the worst case a real network
    // produces and the one where an off-by-one in the length check shows up.
    let bytewise: Vec<&[u8]> = std::iter::once(&hello[..])
        .chain(first_proof.chunks(1))
        .collect();

    // A plain TLS server: the tag is not the chain's, so the client must write
    // the peer off rather than treat it as a proxy.
    let impostor = tls_record(23, b"\x00\x00\x00\x00not a chained tag");

    let mut whole = hello.clone();
    whole.extend_from_slice(&first_proof);
    whole.extend_from_slice(&second_proof);

    vec![
        reads("hello_whole", &[&hello]),
        reads("hello_split", &split_hello),
        reads("hello_then_proof", &[&hello, &first_proof]),
        reads("proof_bytewise", &bytewise),
        // Two records and a half in one read: the record walk has to drain the
        // buffer and keep the remainder rather than stop at the first record.
        reads(
            "records_coalesced",
            &[
                &whole[..hello.len() + first_proof.len() + 4],
                &whole[hello.len() + first_proof.len() + 4..],
            ],
        ),
        reads("plain_tls_server", &[&hello, &impostor]),
        // An alert is what a server sends when it is done; it carries no proof
        // and must pass through rather than be treated as one.
        reads("alert_after_hello", &[&hello, &tls_record(21, &[1, 0])]),
        // A header that declares more than the client will ever buffer. The
        // refusal is the memory bound, so it has to be in the corpus.
        reads("oversized_length", &[&[23, 3, 3, 0xff, 0xff, 0, 0, 0, 0]]),
        // A header that declares a record the server never finishes: the client
        // must keep waiting, not invent the missing bytes.
        reads("incomplete_record", &[&tls_record(23, &[7; 200])[..40]]),
        reads("empty", &[]),
    ]
}
