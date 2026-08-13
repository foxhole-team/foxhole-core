//! Bodies for the eight fuzz targets in `../fuzz_targets`.
//!
//! They live in a plain library, not inside `fuzz_target!`, for one reason:
//! `cargo fuzz` needs a nightly toolchain and a linked libFuzzer runtime, and
//! this repository is pinned to stable 1.97.1. Keeping the bodies here means
//! they compile, and can be fed inputs, on the toolchain the gate actually
//! runs — see `tests/`. The `fuzz_target!` wrappers are then one line each and
//! contain nothing that could rot without being noticed.
//!
//! Every body takes the raw bytes the fuzzer produced and hands them to the
//! parser under test unmodified. Where a parser documents an invariant — a
//! length prefix, a bound on a field, a suffix relationship — the body asserts
//! it, so a violation surfaces as a crash the fuzzer reports rather than as a
//! wrong answer that flows on into the data plane.
//!
//! Seven of the eight are sans-io and keep nothing between iterations, so what
//! they reach is "one message, parsed once". `shadowtls_server_stream` is the
//! exception and exists because of it: it feeds one decoder a *sequence* of
//! segments and looks at the state between them, which is the only way the
//! reassembly buffers, the chained HMAC and the mode flags of a session are
//! reached at all.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

pub mod seeds;

/// Drive a future that reads from an in-memory slice to completion.
///
/// The SOCKS5 decoders are `async` over `AsyncRead`, and `&[u8]` is an
/// `AsyncRead` that is never pending, so a single poll always finishes. Doing
/// it by hand rather than spinning up a Tokio runtime keeps a fuzz iteration at
/// the cost of the parse itself; a runtime per iteration would dominate the
/// profile. `Pending` is returned as `None` instead of being looped on, so a
/// future that unexpectedly parks cannot hang the fuzzer.
fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

// ---------------------------------------------------------------------------
// 1. foxcore-tun: FlowKey::from_packet
// ---------------------------------------------------------------------------

/// Every packet read off the tun goes through this before anything else does.
///
/// The fuzz bytes are the IP packet, passed whole to
/// `foxcore_tun::FlowKey::from_packet`, and then to `PacketSplitter::route`,
/// which is the caller that turns the parse into a routing decision.
pub fn flow_key_from_packet(packet: &[u8]) {
    use foxcore_tun::{FlowKey, PacketRoute, PacketSplitter};

    let Some(key) = FlowKey::from_packet(packet) else {
        // A refusal has to be stable. The splitter blocks a packet it cannot
        // key, so a parser that answered differently on a second look would
        // make the block depend on when the packet arrived.
        assert!(
            FlowKey::from_packet(packet).is_none(),
            "from_packet refused a packet and then accepted the same bytes"
        );
        return;
    };
    assert_eq!(
        Some(key),
        FlowKey::from_packet(packet),
        "the same bytes must always produce the same flow key, or the conntrack \
         cache keys one packet under two identities"
    );

    match packet[0] >> 4 {
        4 => {
            assert!(key.source.is_ipv4() && key.destination.is_ipv4());
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            assert!(
                (20..=packet.len()).contains(&header_len),
                "an IPv4 packet was accepted with IHL {header_len} against {} bytes",
                packet.len()
            );
            assert_eq!(key.protocol, packet[9]);
            // A non-first fragment carries no ports; inventing them would put
            // the fragment in a different flow from the rest of its datagram.
            let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0;
            if fragmented {
                assert_eq!(
                    (key.source_port, key.destination_port),
                    (0, 0),
                    "ports were read out of a non-first fragment"
                );
            }
        }
        6 => {
            assert!(key.source.is_ipv6() && key.destination.is_ipv6());
            assert!(packet.len() >= 40, "an IPv6 header is 40 bytes");
            assert_eq!(key.protocol, packet[6]);
        }
        version => panic!("from_packet accepted IP version {version}"),
    }

    // Ports exist only for TCP and UDP. A non-zero port on any other protocol
    // means four bytes of payload were read as a port pair.
    if key.source_port != 0 || key.destination_port != 0 {
        assert!(
            matches!(key.protocol, 6 | 17),
            "protocol {} was given ports {}/{}",
            key.protocol,
            key.source_port,
            key.destination_port
        );
    }

    const CAPACITY: usize = 4;
    const IDLE_MS: u64 = 30_000;
    let mut splitter = PacketSplitter::new(CAPACITY, IDLE_MS);
    let first = splitter.route(packet, 0, |_| PacketRoute::Tunnel);
    assert_eq!(first, PacketRoute::Tunnel);
    assert_eq!(
        splitter.route(packet, IDLE_MS, |_| PacketRoute::Block),
        PacketRoute::Tunnel,
        "a live decision must be reused, or identity resolution runs per packet"
    );
    assert_eq!(
        splitter.route(packet, IDLE_MS * 2 + 1, |_| PacketRoute::Block),
        PacketRoute::Block,
        "a decision must not outlive the idle timeout"
    );
    assert!(
        splitter.len() <= CAPACITY,
        "the conntrack table grew past its capacity, which is a device-wide failure"
    );
}

// ---------------------------------------------------------------------------
// 2. foxcore-dns: the message parser
// ---------------------------------------------------------------------------

/// Capacity small enough that eviction runs inside a fuzz iteration.
const DNS_CAPACITY: usize = 16;

/// The fuzz bytes are one DNS message, so a corpus file is a real packet and
/// anything captured off the wire can be dropped straight in.
///
/// Reached with the raw bytes: `parse_question` (via `DnsCache::question`,
/// `http_query`, `servfail_response`, `nxdomain_response`, `fake_response`),
/// `parse_addresses` and `read_name` (via `observe_response`), and
/// `response_metadata` (via `cache_response`, using a query derived from the
/// message's own question section so the two match and the record walk is
/// actually entered).
pub fn dns_message(message: &[u8]) {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use foxcore_dns::DnsCache;
    use ipnet::{Ipv4Net, Ipv6Net};

    // The pools the crate's own tests use. The /120 matters: it is small enough
    // that a fuzz iteration can exhaust it, which is the branch where fake-IP
    // allocation has to fail rather than wrap onto a live address.
    let fake_v4 = Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 15).expect("a fixed valid prefix");
    let fake_v6 = Ipv6Net::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 120)
        .expect("a fixed valid prefix");

    let cache = DnsCache::new(DNS_CAPACITY);

    if let Some(question) = DnsCache::question(message) {
        assert_domain_is_bounded(&question.domain);
    }

    // The A/AAAA learning path, which walks every answer's name and rdata.
    let _ = cache.observe_response(message);
    assert!(
        cache.len() <= DNS_CAPACITY,
        "the reverse map grew past its capacity"
    );

    if let Some((transaction_id, normalized)) = foxcore_dns::http_query(message) {
        assert_eq!(transaction_id, u16::from_be_bytes([message[0], message[1]]));
        assert_eq!(
            &normalized[..2],
            &[0, 0],
            "the cache key must not carry the transaction ID, or every query misses"
        );
        assert_eq!(normalized.len(), message.len());
    }

    for (rcode, synthesized) in [
        (2_u16, foxcore_dns::servfail_response(message)),
        (3_u16, foxcore_dns::nxdomain_response(message)),
    ] {
        let Some(response) = synthesized else {
            continue;
        };
        assert!(response.len() >= 12);
        assert_eq!(
            &response[..2],
            &message[..2],
            "the transaction ID must survive"
        );
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & 0x8000 != 0, "a response must have QR set");
        assert_eq!(flags & 0x000f, rcode);
    }

    // Fake-IP allocation, then the round trip through the response cache. The
    // TTL rewrite in `cached_response` indexes the packet at offsets recorded
    // during parsing, so a bad offset is an out-of-bounds write here.
    if let Some(response) = cache.fake_response(message, fake_v4, fake_v6, 300) {
        assert_eq!(&response[..2], &message[..2]);
        if cache.cache_response(message, &response, true)
            && let Some(cached) = cache.cached_response(message, true)
        {
            assert_eq!(
                &cached[..2],
                &message[..2],
                "a cached response must be handed back under the caller's transaction ID"
            );
        }
    }

    // The same message, now treated as an untrusted *response* to a query that
    // carries its question section. This is the only way the record walk in
    // `response_metadata` sees attacker bytes: it refuses a response whose
    // question does not match the query's.
    if let Some(query) = query_matching(message)
        && cache.cache_response(&query, message, true)
        && let Some(cached) = cache.cached_response(&query, true)
    {
        assert_eq!(&cached[..2], &query[..2]);
        assert_eq!(
            cached.len(),
            message.len(),
            "caching must store the response verbatim apart from its TTLs"
        );
    }

    let mut restorable = message.to_vec();
    if foxcore_dns::restore_transaction_id(&mut restorable, 0xBEEF) {
        assert_eq!(&restorable[..2], &[0xBE, 0xEF]);
        assert_eq!(restorable.len(), message.len());
    }
}

/// Build a well-formed query carrying whatever question `message` contains.
///
/// `servfail_response` emits exactly `header | question`, so clearing QR on a
/// copy of the message, asking for a SERVFAIL, and clearing QR again on the
/// result yields a query whose question section is byte-identical to the
/// message's. Doing it this way avoids re-implementing name parsing in the
/// harness, which would then be the thing under test.
pub fn query_matching(message: &[u8]) -> Option<Vec<u8>> {
    if message.len() < 12 {
        return None;
    }
    let mut probe = message.to_vec();
    probe[2] &= 0x07; // clear QR and OPCODE, keep the low flag bits
    probe[4] = 0;
    probe[5] = 1; // QDCOUNT = 1
    let mut query = foxcore_dns::servfail_response(&probe)?;
    query[2] &= 0x7f; // clear QR again: this has to read as a query
    query[3] = 0;
    Some(query)
}

/// `read_name` refuses a label over 63 bytes and a wire name over 255. The
/// joined string is one byte shorter than the wire form, so a name at or past
/// 255 characters means neither bound held.
fn assert_domain_is_bounded(domain: &str) {
    assert!(
        domain.len() < 255,
        "a {}-byte domain escaped the 255-byte wire bound",
        domain.len()
    );
    for label in domain.split('.') {
        assert!(
            label.len() <= 63,
            "a {}-byte label escaped the 63-byte bound",
            label.len()
        );
    }
    assert!(
        !domain.bytes().any(|byte| byte.is_ascii_uppercase()),
        "names are lowercased on parse, or two spellings of one name become two cache entries"
    );
}

// ---------------------------------------------------------------------------
// 3. proto-wireguard: message.rs
// ---------------------------------------------------------------------------

/// The fuzz bytes are one UDP datagram from a peer, handed to every decoder in
/// `proto_wireguard::message`.
///
/// Reached: `message_type`, `Initiation::decode`, `Response::decode`,
/// `CookieReply::decode`, `parse_transport` — each with the datagram whole.
pub fn wireguard_message(datagram: &[u8]) {
    use proto_wireguard::message::{
        COOKIE_REPLY_LEN, CookieReply, INITIATION_LEN, Initiation, RESPONSE_LEN, Response, TAG_LEN,
        TRANSPORT_HEADER_LEN, TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE, TYPE_TRANSPORT,
        message_type, parse_transport,
    };

    // `message_type` is the predicate that tells a vanilla datagram from an
    // AmneziaWG-obfuscated one, so it must stay strict about the reserved field.
    match message_type(datagram) {
        Some(kind) => {
            assert_eq!(kind, datagram[0]);
            assert_eq!(
                &datagram[1..4],
                &[0, 0, 0],
                "a non-zero reserved field must not read as a vanilla header"
            );
        }
        None => assert!(
            datagram.len() < 4 || datagram[1..4] != [0, 0, 0],
            "a well-formed vanilla header was rejected"
        ),
    }

    // Fixed-size messages: acceptance must be exactly "right type, right
    // length", and the decode must lose nothing but the reserved bytes, which
    // the protocol says to ignore.
    let initiation = Initiation::decode(datagram);
    assert_eq!(
        initiation.is_ok(),
        datagram.len() == INITIATION_LEN && datagram[0] == TYPE_INITIATION,
        "initiation decoding disagreed with the protocol's fixed size"
    );
    if let Ok(decoded) = initiation {
        assert_eq!(decoded.encode().as_slice(), canonical(datagram).as_slice());
    }

    let response = Response::decode(datagram);
    assert_eq!(
        response.is_ok(),
        datagram.len() == RESPONSE_LEN && datagram[0] == TYPE_RESPONSE,
        "response decoding disagreed with the protocol's fixed size"
    );
    if let Ok(decoded) = response {
        assert_eq!(decoded.encode().as_slice(), canonical(datagram).as_slice());
    }

    let cookie = CookieReply::decode(datagram);
    assert_eq!(
        cookie.is_ok(),
        datagram.len() == COOKIE_REPLY_LEN && datagram[0] == TYPE_COOKIE_REPLY,
        "cookie reply decoding disagreed with the protocol's fixed size"
    );
    if let Ok(decoded) = cookie {
        assert_eq!(decoded.encode().as_slice(), canonical(datagram).as_slice());
    }

    let transport = parse_transport(datagram);
    assert_eq!(
        transport.is_ok(),
        datagram.len() >= TRANSPORT_HEADER_LEN + TAG_LEN && datagram[0] == TYPE_TRANSPORT,
        "transport framing accepted a frame the protocol cannot have produced"
    );
    if let Ok((receiver_index, counter, ciphertext)) = transport {
        assert_eq!(
            receiver_index,
            u32::from_le_bytes(datagram[4..8].try_into().expect("checked length"))
        );
        assert_eq!(
            counter,
            u64::from_le_bytes(datagram[8..16].try_into().expect("checked length"))
        );
        assert_eq!(
            ciphertext.len(),
            datagram.len() - TRANSPORT_HEADER_LEN,
            "the ciphertext must be the whole frame past the header"
        );
        // A keepalive is empty, so the payload is the bare AEAD tag.
        assert!(ciphertext.len() >= TAG_LEN);
    }
}

/// The datagram with the reserved field zeroed, which is what a re-encode must
/// produce: receivers ignore those three bytes and some providers use them as a
/// client identifier.
fn canonical(datagram: &[u8]) -> Vec<u8> {
    let mut canonical = datagram.to_vec();
    canonical[1..4].fill(0);
    canonical
}

// ---------------------------------------------------------------------------
// 4. proto-socks: codec.rs
// ---------------------------------------------------------------------------

/// The fuzz bytes are what an adversarial SOCKS5 proxy sent back.
///
/// Reached: `decode_udp_datagram` with the whole frame, and `read_reply`,
/// `read_address`, `read_method_selection`, `read_auth_status` with the bytes
/// as the socket's contents.
pub fn socks_codec(frame: &[u8]) {
    use proto_socks::fuzz_internals as socks;

    if let Ok((destination, payload)) = socks::decode_udp_datagram(frame) {
        assert!(frame.len() >= 4);
        assert_eq!(
            frame[2], 0,
            "a fragment must never decode as a complete datagram: reassembly is not implemented"
        );
        assert!(
            !destination.host.is_empty(),
            "an empty bound host is unusable"
        );
        assert!(
            destination.host.len() <= socks::MAX_DOMAIN_LEN,
            "a {}-byte host escaped the protocol's own 255-byte cap",
            destination.host.len()
        );
        // The payload has to be a suffix of the frame. Anything else means the
        // header length was computed from a field the frame does not contain,
        // and the caller would forward bytes that are really header.
        assert!(payload.len() < frame.len());
        assert_eq!(
            &frame[frame.len() - payload.len()..],
            payload,
            "the payload was not the tail of the frame it came from"
        );
    }

    let mut reader = frame;
    if let Some(Ok(destination)) = poll_once(socks::read_address(&mut reader)) {
        assert!(!destination.host.is_empty());
        assert!(destination.host.len() <= socks::MAX_DOMAIN_LEN);
    }

    let mut reader = frame;
    if let Some(Ok(destination)) = poll_once(socks::read_reply(&mut reader)) {
        assert_eq!(frame[0], 0x05, "a reply must carry the SOCKS5 version");
        assert_eq!(frame[1], 0x00, "only a success reply may return an address");
        assert!(!destination.host.is_empty());
    }

    // The two-byte negotiation messages. No invariant beyond "does not panic":
    // every outcome is a typed error the dialer already handles.
    let mut reader = frame;
    let _ = poll_once(socks::read_method_selection(&mut reader, 0x02));
    let mut reader = frame;
    let _ = poll_once(socks::read_auth_status(&mut reader));
}

// ---------------------------------------------------------------------------
// 5. proto-http: codec.rs
// ---------------------------------------------------------------------------

/// The fuzz bytes are the response head an adversarial proxy is streaming.
///
/// Reached: `parse_response` with the whole buffer, and through it
/// `find_header_end` and `parse_status_line`.
pub fn http_codec(buffer: &[u8]) {
    use proto_http::fuzz_internals as http;

    match http::parse_response(buffer) {
        Ok(Some((status, header_len))) => {
            assert!(
                header_len <= buffer.len(),
                "the head was reported as {header_len} bytes of a {}-byte buffer, so the \
                 caller would split the stream past its end",
                buffer.len()
            );
            assert!(
                buffer[..header_len].ends_with(http::HEADER_END),
                "a head that does not end at a blank line would leave header bytes in the tunnel"
            );
            let first_end = buffer
                .windows(http::HEADER_END.len())
                .position(|window| window == http::HEADER_END)
                .expect("a complete head contains a blank line");
            assert_eq!(
                header_len,
                first_end + http::HEADER_END.len(),
                "the head must end at the *first* blank line; a later one lets a proxy \
                 smuggle a second response into the tunnel"
            );
            // Three ASCII digits and nothing else may become a status.
            assert!(status <= 999);
        }
        Ok(None) => {
            assert!(
                buffer.len() <= http::MAX_HEADER_BYTES,
                "{} buffered bytes were accepted past the {}-byte cap",
                buffer.len(),
                http::MAX_HEADER_BYTES
            );
            assert!(
                !buffer
                    .windows(http::HEADER_END.len())
                    .any(|window| window == http::HEADER_END),
                "a complete head was reported as needing more bytes, so the read loop \
                 would block on a proxy that has already finished speaking"
            );
        }
        Err(_) => {}
    }
}

// ---------------------------------------------------------------------------
// 6. proto-reality: reality_records.rs
// ---------------------------------------------------------------------------

/// Fixed key material. The record layer is what is under test, not the key
/// schedule, and a fixed key lets the harness produce records the decryptor
/// will accept — otherwise every input would die at the AEAD tag and the
/// plaintext parsing past it would never run.
const REALITY_KEY: [u8; 16] = *b"foxcore-fuzz-key";
const REALITY_IV: [u8; 12] = *b"foxcore-iv12";

/// Bound on the plaintext a single iteration encrypts. One byte past the
/// fragmentation threshold is enough to reach the multi-record path; more only
/// buys AES throughput measurements.
const REALITY_MAX_PLAINTEXT: usize = 16 * 1024 + 64;

/// The fuzz bytes are used twice: once as a raw record body straight off the
/// socket, and once as the plaintext of a record stream this harness builds and
/// then reads back.
///
/// Reached: `RecordDecryptor::decrypt_record_in_place` with attacker bytes (the
/// AEAD rejection path), `RecordEncryptor::encrypt_app_data`, and — via the
/// round trip — the `TLSInnerPlaintext` trailer walk that strips padding zeros
/// and validates the inner content type, which is the part of the record parser
/// an authenticated but hostile server still controls.
pub fn reality_records(data: &[u8]) {
    use proto_reality::fuzz_internals as records;

    // (a) The bytes as a record body. Almost every input fails the tag; what
    //     matters is that failing is all it does.
    {
        let mut body = data.to_vec();
        let declared = u16::try_from(body.len()).unwrap_or(u16::MAX);
        let mut seq = 0_u64;
        if let Ok((content_type, plaintext)) =
            records::decrypt_record(&REALITY_KEY, &REALITY_IV, &mut seq, &mut body, declared)
        {
            assert!(
                records::ALLOWED_CONTENT_TYPES.contains(&content_type),
                "content type 0x{content_type:02x} reached the caller"
            );
            assert_eq!(
                seq, 1,
                "a decrypted record must advance the sequence exactly once"
            );
            assert!(plaintext.len() + 1 + records::TAG <= data.len());
        }
    }

    if data.is_empty() {
        return;
    }

    // (b) Round trip. The framing is a length prefix the reader trusts, so it
    //     has to describe exactly the bytes that follow.
    let original: Vec<u8> = data.iter().copied().take(REALITY_MAX_PLAINTEXT).collect();
    let mut plaintext = original.clone();
    let mut stream = Vec::new();
    let mut write_seq = 0_u64;
    records::encrypt_app_data(
        &REALITY_KEY,
        &REALITY_IV,
        &mut write_seq,
        &mut plaintext,
        &mut stream,
    )
    .expect("a fixed valid key and IV cannot fail to encrypt");
    assert!(
        plaintext.is_empty(),
        "the writer reuses this buffer and relies on it being cleared"
    );
    assert_eq!(
        usize::try_from(write_seq).expect("a bounded record count"),
        original.len().div_ceil(records::MAX_PLAINTEXT),
        "fragmentation produced a different number of records than the plaintext needs"
    );

    let pristine = stream.clone();
    let mut read_seq = 0_u64;
    let mut recovered = Vec::new();
    let mut rest = stream.as_mut_slice();
    while !rest.is_empty() {
        assert!(
            rest.len() >= records::RECORD_HEADER,
            "the stream ended inside a record header"
        );
        let cursor = std::mem::take(&mut rest);
        let (header, body) = cursor.split_at_mut(records::RECORD_HEADER);
        let declared = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!(
            declared <= records::MAX_CIPHERTEXT,
            "a record declared {declared} bytes, past the {} cap the read buffer is sized for",
            records::MAX_CIPHERTEXT
        );
        assert!(
            declared <= body.len(),
            "the length prefix ran {declared} bytes past the record stream"
        );
        let (record, tail) = body.split_at_mut(declared);
        let (content_type, chunk) = records::decrypt_record(
            &REALITY_KEY,
            &REALITY_IV,
            &mut read_seq,
            record,
            u16::try_from(declared).expect("bounded by MAX_CIPHERTEXT"),
        )
        .expect("a record this harness just produced must authenticate");
        assert_eq!(
            content_type, 0x17,
            "application data must round trip as application data"
        );
        recovered.extend_from_slice(&chunk);
        rest = tail;
    }
    assert_eq!(
        recovered, original,
        "record framing must be lossless — plaintext ending in zero bytes is the case \
         the padding strip on the read side can eat"
    );
    assert_eq!(
        read_seq, write_seq,
        "the two sides must agree on the record count"
    );

    // (c) One flipped bit inside the first record's body. The tag is the only
    //     thing standing between a hostile server and the plaintext parser.
    let mut tampered = pristine;
    let declared = usize::from(u16::from_be_bytes([tampered[3], tampered[4]]));
    let body = records::RECORD_HEADER..records::RECORD_HEADER + declared;
    let target = body.start + usize::from(data[0]) % declared;
    tampered[target] ^= 0x01;
    let mut seq = 0_u64;
    assert!(
        records::decrypt_record(
            &REALITY_KEY,
            &REALITY_IV,
            &mut seq,
            &mut tampered[body],
            u16::try_from(declared).expect("bounded by MAX_CIPHERTEXT"),
        )
        .is_err(),
        "a flipped bit must fail the AEAD tag rather than reach the plaintext parser"
    );
}

// ---------------------------------------------------------------------------
// 7. foxcore-link: share links and subscription bodies
// ---------------------------------------------------------------------------

/// The fuzz bytes are what a provider's subscription URL returned.
///
/// The only parser in this file that runs on input **nobody authenticated**.
/// Every other target reads bytes from a server the user chose and, for most of
/// them, already authenticated; a subscription body is fetched over HTTPS from
/// a URL the user pasted, and it is parsed before a single handshake happens.
/// P1.1 names share links for exactly that reason.
///
/// Reached: `import_link` with the bytes as one link, `import_subscription_partial`
/// with them as a whole body (which base64-decodes, splits lines and re-enters
/// the per-link parser), and `inspect_link_shape`, which is what the app calls
/// before it is willing to show the user anything.
pub fn share_link(data: &[u8]) {
    // The parsers take `&str`: the ABI hands them a Java `String`, so invalid
    // UTF-8 is not a shape this code can be given. Fuzzing it would be fuzzing
    // `from_utf8`.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(profile) = foxcore_link::import_link(text) {
        assert_link_is_reportable(&profile);
        // A parse must be stable: the app imports once to show the user and
        // again to build the config, and a link that meant two different
        // servers between those calls is a profile nobody chose.
        let again =
            foxcore_link::import_link(text).expect("a link that imported once must import twice");
        assert_eq!(
            profile.outbound, again.outbound,
            "the same link produced two different outbounds"
        );
    }

    // The shape inspector runs on links the importer rejects too — it is what
    // reports "this build has no TUIC" rather than "unparseable".
    let _ = foxcore_link::inspect_link_shape(text);

    if let Ok(imported) = foxcore_link::import_subscription_partial(text) {
        for profile in &imported.profiles {
            assert_link_is_reportable(profile);
        }
        for rejected in &imported.rejected {
            // A rejection is shown to the user and written to the log, so it
            // must carry a bounded, single-line reason. Whether the same
            // generic words occur somewhere else in the subscription proves
            // nothing about a leak: libFuzzer can place a diagnostic phrase
            // in one line and make another line produce that same phrase.
            // Secret-bearing inputs are checked directly in foxcore-link's
            // rejection-report regression tests.
            assert!(!rejected.reason.is_empty(), "a rejection with no reason");
            assert!(
                rejected.reason.len() <= 4096,
                "a rejection carried a {}-byte reason",
                rejected.reason.len()
            );
            assert!(
                !rejected.reason.chars().any(char::is_control),
                "a rejection reason carried control characters"
            );
            // Fixed diagnostics may legitimately name a protocol grammar, for example the
            // literal `naive+https://`. Secret-bearing input is guarded in foxcore-link itself;
            // treating every delimiter in a fixed sentence as a leaked URI is a false invariant.
        }
    }
}

/// Everything `foxcore-link` hands back crosses the JNI boundary and lands in a
/// UI. `DroppedOption` in particular is built to be safe to show *and* to log,
/// which means it may name a parameter and must never carry its value.
fn assert_link_is_reportable(profile: &foxcore_link::ImportedProfile) {
    for dropped in &profile.dropped {
        assert!(
            !dropped.option.is_empty(),
            "a dropped option with no name tells the user nothing"
        );
        assert!(
            !dropped.reason.is_empty(),
            "a dropped option with no reason is indistinguishable from a bug"
        );
    }
    if let Some(name) = &profile.name {
        // The name is provider-controlled and goes straight into a list row.
        assert!(
            name.len() <= 4096,
            "a {}-byte profile name reached the app",
            name.len()
        );
    }
}

// ---------------------------------------------------------------------------
// 8. proto-shadowtls: the server's response stream as a state machine
// ---------------------------------------------------------------------------

/// The password both halves of this target pin.
///
/// Fixed for the same reason `reality_records` fixes a key: the proof chain is
/// keyed by it, and without a key the harness can also *write* with, no input a
/// fuzzer produces would ever authenticate — the states that exist only after
/// authentication would be unreachable and the target would spend its whole
/// budget on the first two branches of the record walk.
pub const SHADOWTLS_PASSWORD: &str = "foxcore-fuzz-password";

/// The `ServerRandom` the harness's own server announces.
///
/// It is what the client learns out of the ServerHello and then uses to key
/// every proof that follows, so a harness that made it up per iteration would
/// be fuzzing its own bookkeeping instead of the client's.
pub const SHADOWTLS_RANDOM: [u8; 32] = [0x5a; 32];

/// Cut points the round trip is allowed to use.
///
/// A byte-at-a-time delivery of a four-kilobyte stream is four thousand feeds
/// per iteration, and every one after the first few dozen re-tests the same
/// "still incomplete" branch. Capping it keeps the interesting property — that
/// a record may be cut anywhere — without spending the campaign on it.
const SHADOWTLS_MAX_CUTS: usize = 64;

/// The fuzz bytes are a *sequence* of TCP segments from a ShadowTLS server.
///
/// This is the one target with memory. The others hand a parser one message and
/// throw the parser away; here a single decoder is fed segment after segment,
/// because everything worth testing in this client only exists between reads: a
/// TLS record split across two segments, a ServerHello reassembled out of
/// several handshake records, an HMAC chain in which record N's tag depends on
/// records 1..N, and the flags that decide whether the peer is a proxy, a plain
/// TLS server to be given up on, or an attacker to fail closed against.
///
/// Reached, with one decoder per scenario and the segments delivered in order:
/// `HandshakeIo::process_read_records` and through it `collect_server_hello`,
/// `process_proof_record`, `reject_or_mark_hijacked`, `HmacChain::
/// verify_and_advance` and `xor_proof`; and `RecordReader::read`, the stage-2
/// framing that inherits stage 1's leftover bytes.
pub fn shadowtls_server_stream(data: &[u8]) {
    use proto_shadowtls::fuzz_internals as shadowtls;

    let segments = shadowtls_segments(data);

    // (a) A hostile server from the first byte: nothing here knows the
    //     password, so this is the path a censor or a MITM actually drives.
    let mut machine = shadowtls::HandshakeMachine::new(SHADOWTLS_PASSWORD);
    let mut was_hijacked = false;
    for segment in &segments {
        if machine.feed(segment).is_err() {
            // An error is the connection ending. Feeding past it would test a
            // machine the client has already thrown away.
            break;
        }
        assert!(
            machine.buffered_wire() < shadowtls::RECORD_HEADER + shadowtls::MAX_TLS_RECORD,
            "{} bytes of an incomplete record were held; a server that declares a length \
             and then stops sending must not be able to grow this without bound",
            machine.buffered_wire()
        );
        assert!(
            machine.buffered_transcript() <= shadowtls::MAX_HANDSHAKE_BUFFER,
            "{} bytes of an incomplete handshake message were held past the {}-byte cap",
            machine.buffered_transcript(),
            shadowtls::MAX_HANDSHAKE_BUFFER
        );
        assert!(
            !was_hijacked || machine.hijacked(),
            "the peer was written off as a plain TLS server and then taken back as a proxy"
        );
        was_hijacked = machine.hijacked();
        assert!(
            !machine.authenticated() || machine.server_random().is_some(),
            "a proof was accepted without the ServerRandom that keys it"
        );
        // Whatever is handed up is handed to rustls, which resynchronises on
        // nothing: a partial record there desynchronises the outer TLS session.
        assert_whole_tls_records(&machine.take_ready());
    }

    // (b) The same segments, but arriving *after* the server has proved it
    //     knows the password. This is the half of the state space an ordinary
    //     target cannot reach, and the one where the rule is strictest: a chain
    //     failure here has to end the connection, because the alternative —
    //     falling back to "this was a plain TLS server all along" — would let
    //     anyone on the path unauthenticate a session by injecting one record.
    let mut machine = shadowtls_authenticated_machine();
    for segment in &segments {
        if machine.feed(segment).is_err() {
            break;
        }
        assert!(
            machine.authenticated(),
            "an authenticated session was silently downgraded instead of failing closed"
        );
        assert!(
            !machine.hijacked(),
            "an authenticated session was marked hijacked, which is the downgrade in another form"
        );
        assert_whole_tls_records(&machine.take_ready());
    }

    // (c) Stage 2, the reader the client switches to once rustls is out of the
    //     way. Its first segment is the wire buffer stage 1 left behind, so the
    //     prefix is a real shape and not an empty start.
    let (prefix, rest): (&[u8], &[&[u8]]) = match segments.split_first() {
        Some((first, rest)) => (first, rest),
        None => (&[], &[]),
    };
    let mut reader = shadowtls::SwitchedRecordReader::new(prefix);
    let mut fed = prefix.to_vec();
    let mut delivered = Vec::new();
    for segment in rest {
        fed.extend_from_slice(segment);
        let Ok(records) = reader.feed(segment) else {
            break;
        };
        for record in records {
            assert_eq!(
                &record[1..3],
                &shadowtls::TLS_LEGACY_VERSION,
                "stage 2 refuses any version but TLS 1.2, so one must never come back"
            );
            let declared = usize::from(u16::from_be_bytes([record[3], record[4]]));
            assert_eq!(
                record.len(),
                shadowtls::RECORD_HEADER + declared,
                "a record was returned whose length disagrees with its own header"
            );
            assert!(declared <= shadowtls::MAX_TLS_RECORD);
            delivered.extend_from_slice(&record);
        }
        // The reader reframes; it must never invent, drop or reorder a byte,
        // because every byte it returns is authenticated as if it were on the
        // wire in exactly this position.
        assert!(
            fed.starts_with(&delivered),
            "the records handed on are not the head of the bytes that arrived"
        );
    }

    // (d) A legitimate server carrying the fuzzer's own bytes, delivered at the
    //     fuzzer's own cut points. This is what proves the machine is lossless
    //     rather than merely non-crashing: the same segments that (a) feeds as
    //     an attack are fed here as payload, and every one of them has to come
    //     back byte for byte no matter where the records were cut.
    let mut sender = shadowtls::ProofSender::new(SHADOWTLS_PASSWORD, SHADOWTLS_RANDOM)
        .expect("a fixed non-empty password cannot fail to key the chain");
    let mut stream = shadowtls::server_hello_record(SHADOWTLS_RANDOM);
    let mut sent = Vec::new();
    let mut records = 0_usize;
    for segment in &segments {
        // A payload larger than a record is not a case the protocol has; the
        // server would fragment it, which is what the segments already do.
        if segment.len() > shadowtls::MAX_PROOF_PLAINTEXT {
            continue;
        }
        stream.extend_from_slice(
            &sender
                .record(segment)
                .expect("a payload under the record cap must encode"),
        );
        sent.extend_from_slice(segment);
        records += 1;
    }

    let mut machine = shadowtls::HandshakeMachine::new(SHADOWTLS_PASSWORD);
    let mut ready = Vec::new();
    for chunk in shadowtls_cuts(&stream, &segments) {
        machine
            .feed(chunk)
            .expect("a stream this harness produced must parse wherever it is cut");
        ready.extend_from_slice(&machine.take_ready());
    }
    assert_eq!(
        machine.server_random(),
        Some(SHADOWTLS_RANDOM),
        "the ServerHello must be found however the stream was cut"
    );
    assert_eq!(
        machine.authenticated(),
        records > 0,
        "the session is authenticated exactly when a proof record was sent"
    );
    assert_whole_tls_records(&ready);

    // The ServerHello passes through untouched and everything after it is a
    // restored proof record, so dropping the first payload leaves the plaintext.
    let payloads = tls_record_payloads(&ready);
    let (hello, restored) = payloads
        .split_first()
        .expect("the ServerHello record is always handed up");
    assert_eq!(
        hello.len(),
        38,
        "the ServerHello must reach rustls whole, or the outer handshake stalls"
    );
    assert_eq!(
        restored.concat(),
        sent,
        "the proof layer lost or altered payload bytes: xor_proof is its own inverse and \
         the record framing must be transparent"
    );
}

/// Split the fuzz input into `[length: u16 big-endian][bytes]` segments.
///
/// A segment is one socket read. Two bytes rather than one because a TLS record
/// runs to 18 KiB and a one-byte length could never carry a whole one, which
/// would mean every record in the corpus was fragmented and the "arrived
/// complete" path was never taken. A length past the end takes what is left, so
/// a truncating mutation still produces a usable sequence rather than nothing.
pub fn shadowtls_segments(data: &[u8]) -> Vec<&[u8]> {
    let mut segments = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 {
        let declared = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
        let (segment, tail) = rest.split_at(declared.min(rest.len()));
        segments.push(segment);
        rest = tail;
    }
    segments
}

/// Cut `stream` at lengths taken from `sizes`, cycling and capped.
///
/// The cut points come from the input rather than from a fixed rule so the
/// fuzzer can steer them: where a record is split is exactly the variable this
/// target exists to explore. Zero-length sizes are skipped because they would
/// not advance, and an input that offers no usable size gets one chunk, which
/// is the "the whole response arrived at once" case.
fn shadowtls_cuts<'a>(stream: &'a [u8], sizes: &[&[u8]]) -> Vec<&'a [u8]> {
    let steps: Vec<usize> = sizes
        .iter()
        .map(|segment| segment.len())
        .filter(|length| *length > 0)
        .collect();
    if steps.is_empty() {
        return vec![stream];
    }
    let mut chunks = Vec::new();
    let mut rest = stream;
    let mut step = steps.iter().cycle();
    while !rest.is_empty() && chunks.len() + 1 < SHADOWTLS_MAX_CUTS {
        let take = (*step.next().expect("a non-empty cycle")).min(rest.len());
        let (chunk, tail) = rest.split_at(take);
        chunks.push(chunk);
        rest = tail;
    }
    if !rest.is_empty() {
        chunks.push(rest);
    }
    chunks
}

/// A machine that has already seen a ServerHello and one valid proof record.
///
/// Built with the harness's own server so the starting point is the real
/// post-authentication state rather than the flags being set by hand.
fn shadowtls_authenticated_machine() -> proto_shadowtls::fuzz_internals::HandshakeMachine {
    use proto_shadowtls::fuzz_internals as shadowtls;

    let mut machine = shadowtls::HandshakeMachine::new(SHADOWTLS_PASSWORD);
    let mut sender = shadowtls::ProofSender::new(SHADOWTLS_PASSWORD, SHADOWTLS_RANDOM)
        .expect("a fixed non-empty password cannot fail to key the chain");
    machine
        .feed(&shadowtls::server_hello_record(SHADOWTLS_RANDOM))
        .expect("a ServerHello this harness produced must parse");
    let first = sender
        .record(b"authenticated")
        .expect("a thirteen-byte payload fits one record");
    machine
        .feed(&first)
        .expect("a proof record this harness produced must authenticate");
    assert!(
        machine.authenticated(),
        "the priming sequence stopped authenticating, so scenario (b) tests nothing"
    );
    let _ = machine.take_ready();
    machine
}

/// Every byte handed up must belong to a complete TLS record.
///
/// The consumer is rustls in stage 1 and the inner protocol in stage 2, and
/// neither resynchronises: a header that describes more bytes than follow, or
/// fewer, silently shifts everything after it. The record *type* and version
/// are not checked here on purpose — in stage 1 a rejected record is passed
/// through verbatim, so those bytes are the peer's to choose.
fn assert_whole_tls_records(stream: &[u8]) {
    use proto_shadowtls::fuzz_internals as shadowtls;

    let mut rest = stream;
    while !rest.is_empty() {
        assert!(
            rest.len() >= shadowtls::RECORD_HEADER,
            "{} trailing bytes are not a record header",
            rest.len()
        );
        let declared = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        assert!(
            declared <= shadowtls::MAX_TLS_RECORD,
            "a record declaring {declared} bytes was handed up, past the {}-byte cap",
            shadowtls::MAX_TLS_RECORD
        );
        let record_len = shadowtls::RECORD_HEADER + declared;
        assert!(
            record_len <= rest.len(),
            "a record header declared {declared} bytes with only {} to follow",
            rest.len() - shadowtls::RECORD_HEADER
        );
        rest = &rest[record_len..];
    }
}

/// The payload of each record in a stream `assert_whole_tls_records` accepted.
fn tls_record_payloads(stream: &[u8]) -> Vec<&[u8]> {
    use proto_shadowtls::fuzz_internals as shadowtls;

    let mut payloads = Vec::new();
    let mut rest = stream;
    while rest.len() >= shadowtls::RECORD_HEADER {
        let declared = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        let end = shadowtls::RECORD_HEADER + declared;
        if end > rest.len() {
            break;
        }
        payloads.push(&rest[shadowtls::RECORD_HEADER..end]);
        rest = &rest[end..];
    }
    payloads
}
