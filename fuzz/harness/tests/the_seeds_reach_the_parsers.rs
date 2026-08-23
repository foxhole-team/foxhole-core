//! Proof that each target's seeds are structure, not just bytes that happen
//! not to crash.
//!
//! A harness can look busy while every input dies at the first length check, and
//! nothing about a passing fuzz run would say so. These assertions pin the
//! opposite: for each target, at least one seed reaches the parser and comes
//! back with a parsed value. If a seed stops being valid — a fixture changed
//! shape, a bound moved — this fails on stable instead of quietly turning the
//! corpus into noise.

use std::collections::BTreeMap;

use foxcore_fuzz_harness::seeds;

fn corpus(target: &str) -> BTreeMap<&'static str, Vec<u8>> {
    seeds::seeds_for(target)
        .into_iter()
        .map(|seed| (seed.name, seed.bytes))
        .collect()
}

#[test]
fn every_netstack_seed_reaches_the_transport_adapter() {
    for (name, packet) in corpus("netstack_packet") {
        assert!(
            foxcore_tun::netstack::fuzz_parse_packet(&packet),
            "seed {name} is not a packet the netstack adapter accepts"
        );
    }
}

#[test]
fn every_tun_seed_is_a_packet_the_splitter_can_key() {
    use foxcore_tun::FlowKey;

    let corpus = corpus("flow_key_from_packet");
    for (name, packet) in &corpus {
        let key = FlowKey::from_packet(packet)
            .unwrap_or_else(|| panic!("seed {name} is not a packet FlowKey accepts"));
        assert_eq!(key.source.to_string(), source_of(name));
    }

    // The seeds must disagree with each other, or the fuzzer starts from one
    // shape wearing six names.
    assert_eq!(
        FlowKey::from_packet(&corpus["ipv4_udp"]).unwrap().protocol,
        17
    );
    assert_eq!(
        FlowKey::from_packet(&corpus["ipv4_tcp"]).unwrap().protocol,
        6
    );
    // The port-bearing cases really carry ports, and the others really do not.
    assert_eq!(
        FlowKey::from_packet(&corpus["ipv4_options"])
            .unwrap()
            .destination_port,
        443,
        "the IHL-6 seed must have its ports read past the options, or it tests nothing"
    );
    assert_eq!(
        FlowKey::from_packet(&corpus["ipv4_fragment"])
            .unwrap()
            .destination_port,
        0
    );
    assert_eq!(
        FlowKey::from_packet(&corpus["ipv4_icmp"]).unwrap().protocol,
        1
    );
    assert_eq!(
        FlowKey::from_packet(&corpus["ipv6_tcp"])
            .unwrap()
            .destination_port,
        443
    );
}

fn source_of(name: &str) -> String {
    if name.starts_with("ipv6") {
        "fd00::2".to_owned()
    } else {
        "10.0.0.2".to_owned()
    }
}

#[test]
fn the_dns_seeds_reach_the_question_walk_the_answer_walk_and_the_ttl_rewrite() {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use foxcore_dns::DnsCache;
    use ipnet::{Ipv4Net, Ipv6Net};

    let corpus = corpus("dns_message");
    let v4 = Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 15).unwrap();
    let v6 = Ipv6Net::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 120).unwrap();

    for name in ["query_a", "query_aaaa", "query_ptr", "query_with_opt"] {
        let question = DnsCache::question(&corpus[name])
            .unwrap_or_else(|| panic!("seed {name} does not parse as a question"));
        assert!(!question.domain.is_empty());
    }
    assert_eq!(
        DnsCache::question(&corpus["query_ptr"]).unwrap().domain,
        "4.3.2.1.in-addr.arpa"
    );

    // `read_name` following a 0xc00c compression pointer, which is the loop the
    // pointer-jump bound protects.
    let cache = DnsCache::new(16);
    assert_eq!(
        cache.observe_response(&corpus["response_a_compressed"]),
        1,
        "the compressed A answer must be learned, or parse_addresses never ran"
    );
    assert_eq!(
        cache
            .reverse_domain("93.184.216.34".parse().unwrap())
            .as_deref(),
        Some("example.com")
    );
    assert_eq!(
        cache.observe_response(&corpus["response_aaaa_compressed"]),
        1
    );

    // Fake-IP synthesis, then the round trip whose TTL rewrite indexes the
    // cached packet at offsets recorded during parsing.
    let cache = DnsCache::new(16);
    let synthesized = cache
        .fake_response(&corpus["query_a"], v4, v6, 300)
        .expect("an A query must get a fake-IP answer");
    assert!(cache.cache_response(&corpus["query_a"], &synthesized, true));
    let cached = cache
        .cached_response(&corpus["query_a"], false)
        .expect("a freshly cached response must come back");
    assert_eq!(cached.len(), synthesized.len());

    // The derived-query trick: without it `response_metadata` refuses every
    // untrusted response and the record walk is dead code in the fuzzer.
    let cache = DnsCache::new(16);
    let query = foxcore_fuzz_harness::query_matching(&corpus["response_a_compressed"])
        .expect("a response with a question section must yield a matching query");
    assert_eq!(
        DnsCache::question(&query).unwrap().domain,
        "example.com",
        "the derived query must carry the response's own question"
    );
    assert!(
        cache.cache_response(&query, &corpus["response_a_compressed"], true),
        "the derived query must match, or response_metadata is never entered"
    );
    let cached = cache.cached_response(&query, false).unwrap();
    // 12 header + 13 question name + 4 type/class = 29, then the 0xc00c
    // pointer, type and class, so the answer's TTL sits at 35.
    assert_eq!(
        &cached[35..39],
        &60_u32.to_be_bytes(),
        "the TTL field must have been located and rewritten in place"
    );
}

#[test]
fn every_wireguard_seed_decodes_as_the_message_it_claims_to_be() {
    use proto_wireguard::message::{CookieReply, Initiation, Response, parse_transport};

    let corpus = corpus("wireguard_message");
    assert!(Initiation::decode(&corpus["initiation"]).is_ok());
    assert!(
        Initiation::decode(&corpus["initiation_reserved_set"]).is_ok(),
        "a provider's client identifier in the reserved field must still decode"
    );
    assert!(Response::decode(&corpus["response"]).is_ok());
    assert!(CookieReply::decode(&corpus["cookie_reply"]).is_ok());

    let (_, _, keepalive) = parse_transport(&corpus["transport_keepalive"]).unwrap();
    assert_eq!(keepalive.len(), 16, "a keepalive is the bare AEAD tag");
    let (_, _, data) = parse_transport(&corpus["transport_data"]).unwrap();
    assert_eq!(data.len(), 112);
}

#[test]
fn every_socks_seed_reaches_the_address_decoder() {
    let corpus = corpus("socks_codec");

    let (destination, payload) =
        proto_socks::fuzz_internals::decode_udp_datagram(&corpus["udp_reply_ipv4"]).unwrap();
    assert_eq!(destination.host, "8.8.8.8");
    assert_eq!(payload, b"answer");

    let (destination, payload) =
        proto_socks::fuzz_internals::decode_udp_datagram(&corpus["udp_reply_domain"]).unwrap();
    assert_eq!(destination.host, "example.com");
    assert_eq!(payload, b"query");

    assert!(
        proto_socks::fuzz_internals::decode_udp_datagram(&corpus["udp_fragment"]).is_err(),
        "a fragment must not decode: reassembly is not implemented"
    );

    // The reply path is `async`; the harness drives it with a single poll, so
    // this checks the same thing the harness relies on.
    for name in ["reply_ipv4", "reply_ipv6", "reply_domain"] {
        let bytes = corpus[name].clone();
        assert!(
            block_once(
                async move { proto_socks::fuzz_internals::read_reply(&mut &bytes[..]).await }
            )
            .is_ok(),
            "seed {name} does not parse as a reply"
        );
    }
    let refused = corpus["reply_refused"].clone();
    assert!(
        block_once(async move { proto_socks::fuzz_internals::read_reply(&mut &refused[..]).await })
            .is_err()
    );
}

/// Same single-poll trick the harness uses: `&[u8]` is an `AsyncRead` that is
/// never pending, so one poll is the whole future.
fn block_once<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::pin::pin!(future).poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("an in-memory reader parked"),
    }
}

#[test]
fn every_http_seed_reaches_the_status_line_parser() {
    use proto_http::fuzz_internals as http;

    let corpus = corpus("http_codec");

    let (status, header_len) = http::parse_response(&corpus["established"])
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(header_len, corpus["established"].len());

    assert_eq!(
        http::parse_response(&corpus["no_reason_phrase"])
            .unwrap()
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        http::parse_response(&corpus["proxy_auth_required"])
            .unwrap()
            .unwrap()
            .0,
        407
    );
    assert_eq!(
        http::parse_response(&corpus["with_headers"])
            .unwrap()
            .unwrap()
            .0,
        200
    );
    assert!(
        http::parse_response(&corpus["incomplete"])
            .unwrap()
            .is_none(),
        "the incomplete seed must exercise the read-more branch"
    );
    // 64 fields is under the cap, so the flood seed parses; the fuzzer's job is
    // to push it over.
    assert!(
        http::parse_response(&corpus["header_flood"])
            .unwrap()
            .is_some()
    );
}

#[test]
fn every_reality_seed_round_trips_through_the_record_layer() {
    use proto_reality::fuzz_internals as records;

    const KEY: [u8; 16] = *b"foxcore-fuzz-key";
    const IV: [u8; 12] = *b"foxcore-iv12";

    for (name, plaintext) in corpus("reality_records") {
        let expected_records = plaintext.len().div_ceil(records::MAX_PLAINTEXT);
        let mut buffer = plaintext.clone();
        let mut stream = Vec::new();
        let mut seq = 0_u64;
        records::encrypt_app_data(&KEY, &IV, &mut seq, &mut buffer, &mut stream).unwrap();
        assert_eq!(
            usize::try_from(seq).unwrap(),
            expected_records,
            "seed {name} produced the wrong number of records"
        );
        assert!(
            stream.len() > plaintext.len(),
            "seed {name} produced no record at all"
        );
    }

    // The seed that exists specifically to reach the multi-record path.
    let fragmenting = corpus("reality_records")["fragmenting"].clone();
    assert_eq!(
        fragmenting.len(),
        records::MAX_PLAINTEXT + 1,
        "the fragmenting seed must sit one byte past the threshold"
    );
}

/// Every scheme seed imports as the outbound it names, and the subscription
/// seeds carry more than one server each.
///
/// A corpus of links that all die at "unknown scheme" would look identical to
/// a corpus that works, from inside a fuzz run: the parser would return early
/// every time and the campaign would explore nothing but the scheme table.
#[test]
fn every_share_link_seed_reaches_the_profile_it_names() {
    use foxcore_api::OutboundConfig;

    let corpus = corpus("share_link");

    /// The seed name and the outbound its link must import as.
    type SchemeSeed = (&'static str, fn(&OutboundConfig) -> bool);

    let expected: [SchemeSeed; 5] = [
        ("vless", |outbound| {
            matches!(outbound, OutboundConfig::Vless(_))
        }),
        ("hysteria2", |outbound| {
            matches!(outbound, OutboundConfig::Hysteria2(_))
        }),
        ("trojan", |outbound| {
            matches!(outbound, OutboundConfig::Trojan(_))
        }),
        ("shadowsocks", |outbound| {
            matches!(outbound, OutboundConfig::Shadowsocks(_))
        }),
        ("wireguard", |outbound| {
            matches!(outbound, OutboundConfig::Wireguard(_))
        }),
    ];
    for (name, is_expected) in expected {
        let text = std::str::from_utf8(&corpus[name]).expect("the link seeds are text");
        let profile = foxcore_link::import_link(text)
            .unwrap_or_else(|error| panic!("seed {name} no longer imports: {error}"));
        assert!(
            is_expected(&profile.outbound),
            "seed {name} imported as something else: {:?}",
            profile.outbound
        );
    }

    // Both body shapes must yield the same four servers: the base64 seed exists
    // to prove the decode path is entered, not to be a second copy of the plain
    // one that happens to fail differently.
    for body in ["subscription_plain", "subscription_base64"] {
        let text = std::str::from_utf8(&corpus[body]).expect("the body seeds are text");
        let imported = foxcore_link::import_subscription_partial(text)
            .unwrap_or_else(|error| panic!("seed {body} no longer imports: {error}"));
        assert_eq!(
            imported.profiles.len(),
            4,
            "seed {body} yielded {} servers, not the four it contains",
            imported.profiles.len()
        );
        assert!(imported.rejected.is_empty(), "seed {body} rejected a line");
    }

    // And the seed that is a real body's real problem: one notice line among
    // the servers, which must cost the line and not the subscription.
    let text = std::str::from_utf8(&corpus["subscription_with_notice"]).expect("text");
    let imported = foxcore_link::import_subscription_partial(text).expect("a notice is survivable");
    assert_eq!(imported.profiles.len(), 1);
    assert_eq!(imported.rejected.len(), 1);

    // The scheme the core knows the name of and does not implement must stay
    // refused rather than downgraded into something weaker that does connect.
    let text = std::str::from_utf8(&corpus["unknown_scheme"]).expect("text");
    assert!(
        foxcore_link::import_link(text).is_err(),
        "an unimplemented scheme imported as something else"
    );
}

/// Each ShadowTLS seed drives the session machine into the state its name
/// claims, and the states are different from each other.
///
/// This is the target where a corpus can look busiest while doing least: a
/// sequence of segments that never completes a record exercises one `if`, and a
/// passing fuzz run would say nothing about it. So the seeds are checked here
/// against the thing they exist for — a ServerHello reassembled out of pieces,
/// a proof chain that authenticates, a peer written off as a plain TLS server,
/// and the two refusals — rather than against "did not panic".
#[test]
fn every_shadowtls_seed_drives_the_session_into_the_state_it_names() {
    use foxcore_fuzz_harness::{SHADOWTLS_PASSWORD, SHADOWTLS_RANDOM, shadowtls_segments};
    use proto_shadowtls::fuzz_internals as shadowtls;

    /// Replay a seed as the sequence of socket reads it encodes.
    fn replay(bytes: &[u8]) -> (shadowtls::HandshakeMachine, Option<std::io::Error>) {
        let mut machine = shadowtls::HandshakeMachine::new(SHADOWTLS_PASSWORD);
        for segment in shadowtls_segments(bytes) {
            if let Err(error) = machine.feed(segment) {
                return (machine, Some(error));
            }
        }
        (machine, None)
    }

    let corpus = corpus("shadowtls_server_stream");

    // The ServerHello has to be found whether it arrives whole or in pieces —
    // the piecewise case is the one no single-message target can reach.
    for name in ["hello_whole", "hello_split", "hello_then_proof"] {
        let (machine, error) = replay(&corpus[name]);
        assert!(error.is_none(), "seed {name} failed: {error:?}");
        assert_eq!(
            machine.server_random(),
            Some(SHADOWTLS_RANDOM),
            "seed {name} never reached the ServerHello"
        );
    }

    // The chained proof: these must actually authenticate, or the whole
    // post-authentication half of the state space is unreachable from the
    // corpus and scenario (b) starts from a shape the fuzzer cannot vary.
    for name in ["hello_then_proof", "proof_bytewise", "records_coalesced"] {
        let (machine, error) = replay(&corpus[name]);
        assert!(error.is_none(), "seed {name} failed: {error:?}");
        assert!(
            machine.authenticated(),
            "seed {name} does not authenticate, so it tests the same branch as the rest"
        );
        assert!(!machine.hijacked());
    }

    // A server that does not know the password is not an error — it is an
    // ordinary TLS server the client must stop treating as a proxy.
    let (machine, error) = replay(&corpus["plain_tls_server"]);
    assert!(error.is_none(), "a plain TLS server must not be an error");
    assert!(
        machine.hijacked(),
        "the impostor seed did not reach the hijack path"
    );
    assert!(!machine.authenticated());

    // The two refusals, which are the memory bounds of this parser.
    let (_, error) = replay(&corpus["oversized_length"]);
    assert!(
        error.is_some(),
        "a record header past the buffer cap must be refused"
    );
    let (machine, error) = replay(&corpus["incomplete_record"]);
    assert!(error.is_none(), "an unfinished record is not an error yet");
    assert!(
        machine.buffered_wire() > 0,
        "the unfinished record seed left nothing buffered, so it completed after all"
    );

    // Stage 2 sees the same bytes once rustls is out of the way, and it must
    // hand back whole records rather than the stream it was given.
    let segments = shadowtls_segments(&corpus["hello_then_proof"]);
    let mut reader = shadowtls::SwitchedRecordReader::new(&[]);
    let records: Vec<Vec<u8>> = segments
        .iter()
        .flat_map(|segment| reader.feed(segment).expect("well-formed records"))
        .collect();
    assert_eq!(
        records.len(),
        2,
        "stage 2 must reframe the seed into its two records"
    );
    assert_eq!(records[0][0], shadowtls::TLS_HANDSHAKE);
    assert_eq!(records[1][0], shadowtls::TLS_APPLICATION_DATA);
}
