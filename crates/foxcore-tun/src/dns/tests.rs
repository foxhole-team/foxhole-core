use crate::metrics::FlowMetrics;
use bytes::{Bytes, BytesMut};
use foxcore_api::{
    BlockReason, CoreEvent, Destination, DnsCategory, DnsConfig, DnsMode, DnsRoute, DnsUpstream,
    EventSink,
};
use foxcore_api::{DnsBlocklistConfig, I2pConfig, OutboundConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_dns::DnsCache;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_transport::{Datagram, datagram_channel, with_authenticated_peer};
use http::Method;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::*;

#[test]
fn parses_dns_upstream_endpoints() {
    assert_eq!(
        parse_endpoint("1.1.1.1", DNS_PORT).unwrap(),
        Destination::new("1.1.1.1", 53)
    );
    assert_eq!(
        parse_endpoint("[2606:4700:4700::1111]:853", 853).unwrap(),
        Destination::new("2606:4700:4700::1111", 853)
    );
    assert_eq!(
        parse_endpoint("resolver.example:5353", DNS_PORT).unwrap(),
        Destination::new("resolver.example", 5353)
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn protected_udp_upstream_is_cached_by_question_not_transaction_id() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let mut first_peer = None;
        for _ in 0..2 {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let response = a_response(&buffer[..length], [203, 0, 113, 9]);
            socket.send_to(&response, peer).await.unwrap();
            if let Some(first_peer) = first_peer {
                assert_eq!(peer, first_peer, "DNS UDP session must be reused");
            } else {
                first_peer = Some(peer);
            }
        }
    });

    let config = DnsConfig {
        route: DnsRoute::Direct,
        // Generous on purpose: this asserts caching, not latency, and a
        // budget tight enough to lose a race with the test runtime's
        // scheduler would fail for a reason that has nothing to do with it.
        timeout_ms: 5_000,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();

    let first = dns_query(0x1234);
    let first_response = proxy.exchange_for_test(&first).await.unwrap();
    assert_eq!(&first_response[..2], &[0x12, 0x34]);

    let mut different_question = dns_query(0x4567);
    different_question[19] = b'f';
    let second_response = proxy.exchange_for_test(&different_question).await.unwrap();
    assert_eq!(&second_response[..2], &[0x45, 0x67]);
    server.await.unwrap();

    let cached_query = dns_query(0xabcd);
    let cached = proxy.exchange_for_test(&cached_query).await.unwrap();
    assert_eq!(&cached[..2], &[0xab, 0xcd]);
    assert_eq!(&cached[cached.len() - 4..], &[203, 0, 113, 9]);
}

/// The second thing a network change has to move, and the one that is
/// easiest to miss because nothing looks wrong.
///
/// Cached answers outlive the network that produced them. On a
/// split-horizon corporate network or behind a captive portal the previous
/// resolver's addresses are simply not the right ones here, and they are
/// served for the rest of their TTL: the name resolves, the connection is
/// attempted, it fails, and every counter in the core is clean. That is the
/// D1 shape, which is why this is a reliability fix.
///
/// The other half is what must **not** happen. Flushing the fake-IP store
/// along with the cache makes existing synthetic destinations unmappable. Applications are
/// holding those addresses; dropping them makes nothing more correct and
/// breaks every live connection that resolved through the pool. Same for
/// the IP→name map domain rules are matched through.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_network_change_drops_cached_answers_and_keeps_the_fake_ip_pool() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    // The same name, answered differently by the two networks' resolvers.
    // Nothing else in this test can tell them apart, which is the point.
    let server = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        for reply in [[203, 0, 113, 9], [198, 51, 100, 4]] {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let response = a_response(&buffer[..length], reply);
            socket.send_to(&response, peer).await.unwrap();
        }
    });

    let config = DnsConfig {
        route: DnsRoute::Direct,
        timeout_ms: 5_000,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let (ipv4_pool, ipv6_pool, fake_ttl_s) = (
        config.fake_ipv4_pool,
        config.fake_ipv6_pool,
        config.fake_ttl_s,
    );
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache.clone(), outbounds, direct).unwrap();

    // An address an application is already holding when the network moves.
    let synthesised = cache
        .fake_response(
            &dns_query_for(0x0101, "held.example"),
            ipv4_pool,
            ipv6_pool,
            fake_ttl_s,
        )
        .expect("the pool must synthesise an address");
    let fake_address = std::net::IpAddr::from([
        synthesised[synthesised.len() - 4],
        synthesised[synthesised.len() - 3],
        synthesised[synthesised.len() - 2],
        synthesised[synthesised.len() - 1],
    ]);

    let first = proxy.exchange_for_test(&dns_query(0x1234)).await.unwrap();
    assert_eq!(&first[first.len() - 4..], &[203, 0, 113, 9]);

    // Still the first network's answer, because it is cached: the upstream
    // would have said something else.
    let cached = proxy.exchange_for_test(&dns_query(0x2222)).await.unwrap();
    assert_eq!(
        &cached[cached.len() - 4..],
        &[203, 0, 113, 9],
        "this test is only meaningful while the cache is actually serving"
    );

    proxy.network_changed();

    let fresh = proxy.exchange_for_test(&dns_query(0x3333)).await.unwrap();
    assert_eq!(
        &fresh[fresh.len() - 4..],
        &[198, 51, 100, 4],
        "after the switch the name has to be asked again: the previous \
             network's answer is not authoritative here, and serving it costs a \
             connection that fails with every counter clean"
    );
    server.await.unwrap();

    assert_eq!(
        cache.fake_domain(fake_address).as_deref(),
        Some("held.example"),
        "an application is holding this address; invalidating it makes \
             nothing more correct and breaks the flow that resolved through it"
    );
    assert_eq!(
        cache
            .reverse_domain("203.0.113.9".parse().unwrap())
            .as_deref(),
        Some("example.com"),
        "and the map domain rules are matched through must survive too, or \
             live flows are silently demoted to address rules"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn an_in_flight_answer_from_the_old_network_is_not_cached() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let old = a_response(&buffer[..length], [203, 0, 113, 9]);
        received_tx.send(()).unwrap();
        release_rx.await.unwrap();
        socket.send_to(&old, peer).await.unwrap();

        let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let fresh = a_response(&buffer[..length], [198, 51, 100, 4]);
        socket.send_to(&fresh, peer).await.unwrap();
    });

    let config = DnsConfig {
        route: DnsRoute::Direct,
        timeout_ms: 5_000,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache.clone(), outbounds, direct).unwrap();

    let in_flight = {
        let proxy = proxy.clone();
        tokio::spawn(async move { proxy.exchange_for_test(&dns_query(0x1111)).await })
    };
    received_rx.await.unwrap();
    proxy.network_changed();
    release_tx.send(()).unwrap();
    assert_eq!(
        in_flight.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(cache.cached_response(&dns_query(0x2222), false).is_none());

    let fresh = proxy.exchange_for_test(&dns_query(0x3333)).await.unwrap();
    assert_eq!(&fresh[fresh.len() - 4..], &[198, 51, 100, 4]);
    server.await.unwrap();
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn timeout_discards_the_pooled_udp_session() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        socket.recv_from(&mut buffer).await.unwrap()
    });

    let config = DnsConfig {
        route: DnsRoute::Direct,
        // The budget only has to outlast getting the query onto a loopback
        // socket; nothing ever replies, so the test still pays it in full.
        // It is generous because the failure mode of a tight one is a
        // timeout that fires *before* the send, which tests the opposite of
        // what this asserts and only shows up on a loaded machine.
        timeout_ms: 3_000,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();

    let error = proxy.exchange_for_test(&dns_query(1)).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    // Bounded: a query that never reached the wire is a failure to report,
    // not a reason to hang the whole suite on a bare `await`.
    tokio::time::timeout(Duration::from_secs(5), received)
        .await
        .expect("the query must have reached the upstream before the timeout fired")
        .unwrap();
    for lane in &proxy.upstream_state[0].lanes {
        assert!(matches!(*lane.lock().await, UpstreamState::Empty));
    }
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_lost_udp_response_does_not_block_an_independent_lookup() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (first_seen_tx, first_seen_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, first_peer) = socket.recv_from(&mut buffer).await.unwrap();
        first_seen_tx.send(()).unwrap();

        let (length, second_peer) = socket.recv_from(&mut buffer).await.unwrap();
        assert_ne!(
            second_peer, first_peer,
            "concurrent DNS transactions must use independent pooled sessions"
        );
        let response = a_response(&buffer[..length], [203, 0, 113, 10]);
        socket.send_to(&response, second_peer).await.unwrap();
    });

    let config = DnsConfig {
        route: DnsRoute::Direct,
        // The lookup this test strands has to reach the wire before it is
        // abandoned, and the budget is the only thing standing between the two.
        // At half a second a loaded machine spends the whole of it opening the
        // session, the query is dropped before the first send, and the wait
        // below then has nothing left to wake it: the upstream never saw a
        // query, so it never reports one. That is the shape this test hung in.
        // Three seconds is not the assertion — it is the margin around it.
        timeout_ms: 3_000,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();

    let stalled_proxy = proxy.clone();
    let stalled = tokio::spawn(async move {
        stalled_proxy
            .exchange_for_test(&dns_query_for(1, "lost.example"))
            .await
    });
    // Bounded: a query that never reached the wire is a failure to report, not
    // a reason to hang the whole suite on a bare `await`.
    tokio::time::timeout(Duration::from_secs(10), first_seen_rx)
        .await
        .expect("the stranded query must have reached the upstream")
        .unwrap();

    let fast = tokio::time::timeout(
        // Comfortably inside the stranded query's own budget, which is what
        // makes the assertion below meaningful, and far enough above scheduling
        // jitter that a busy machine is not mistaken for a blocked lane.
        Duration::from_secs(2),
        proxy.exchange_for_test(&dns_query_for(2, "fast.example")),
    )
    .await
    .expect("a lost response in one lane must not head-of-line block another")
    .unwrap();
    assert_eq!(&fast[..2], &[0, 2]);
    assert_eq!(&fast[fast.len() - 4..], &[203, 0, 113, 10]);
    // The timeout above IS the proof, and it is the only one that holds on a busy machine: a
    // head-of-line blocked lane could not answer before the stranded query's own budget expired,
    // and that budget is longer than the window the fast lookup was given. Asserting on top of
    // that the stranded task is *still running* adds nothing and races the same two clocks — it
    // failed here for that reason and for no other, on a host compiling an Android release
    // beside it.

    server.await.unwrap();
    let stalled_error = stalled.await.unwrap().unwrap_err();
    assert_eq!(stalled_error.kind(), io::ErrorKind::TimedOut);
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn onion_query_is_never_sent_without_a_tor_outbound() {
    let config = DnsConfig {
        mode: DnsMode::FakeIp,
        upstreams: vec![DnsUpstream::Udp {
            address: "127.0.0.1:9".into(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();

    let error = proxy
        .exchange(&dns_query_for(7, "hidden.onion"), None)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

/// The journal records *which rule set* refused a name, and the UI groups by
/// it. A category that stopped at the blocklist would leave both with
/// "blocked" and nothing else.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_categorised_refusal_names_its_rule_set_in_the_event() {
    let config = DnsConfig {
        mode: DnsMode::FakeIp,
        blocklist: DnsBlocklistConfig {
            categories: vec![
                foxcore_api::DnsBlocklistCategoryConfig {
                    category: DnsCategory::Ads,
                    exact: Vec::new(),
                    suffixes: vec!["ads.example".into()],
                },
                foxcore_api::DnsBlocklistCategoryConfig {
                    category: DnsCategory::Malicious,
                    exact: Vec::new(),
                    suffixes: vec!["evil.example".into()],
                },
            ],
            ..Default::default()
        },
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| recorded.lock().unwrap().push(event))
    };
    let proxy = DnsProxy::new_with_gates(
        1,
        config,
        cache,
        outbounds,
        direct,
        true,
        true,
        Arc::new(FlowMetrics::default()),
        sink,
    )
    .unwrap();

    proxy
        .exchange(&dns_query_for(21, "x.ads.example"), Some("com.example"))
        .await
        .unwrap();
    proxy
        .exchange(&dns_query_for(22, "evil.example"), None)
        .await
        .unwrap();

    assert_eq!(
        *recorded.lock().unwrap(),
        vec![
            CoreEvent::DnsBlocked {
                reason: BlockReason::DnsBlocklist,
                domain: "x.ads.example".into(),
                package: Some("com.example".into()),
                category: Some(DnsCategory::Ads),
            },
            CoreEvent::DnsBlocked {
                reason: BlockReason::DnsBlocklist,
                domain: "evil.example".into(),
                package: None,
                category: Some(DnsCategory::Malicious),
            },
        ]
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn blocked_domains_answer_nxdomain_and_never_reach_an_upstream() {
    let config = DnsConfig {
        mode: DnsMode::FakeIp,
        // Discard port: if a blocked name ever reached the upstream loop the
        // exchange would fail on timeout instead of answering NXDOMAIN.
        upstreams: vec![DnsUpstream::Udp {
            address: "127.0.0.1:9".into(),
        }],
        blocklist: DnsBlocklistConfig {
            exact: vec!["ads.example.com".into()],
            suffixes: vec!["tracker.net".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| recorded.lock().unwrap().push(event))
    };
    let proxy = DnsProxy::new_with_gates(
        1,
        config,
        cache,
        outbounds,
        direct,
        true,
        true,
        metrics.clone(),
        sink,
    )
    .unwrap();

    for (id, domain) in [(11_u16, "ads.example.com"), (12, "deep.tracker.net")] {
        let response = proxy
            .exchange_for_test(&dns_query_for(id, domain))
            .await
            .unwrap();
        assert_eq!(
            &response[..2],
            &id.to_be_bytes(),
            "transaction id preserved"
        );
        assert_eq!(response[3] & 0x0f, 3, "{domain} must be answered NXDOMAIN");
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            0,
            "a blocked answer carries no records"
        );
    }

    // A name outside the list still resolves (fake-IP), so the block is scoped.
    let allowed = proxy
        .exchange(&dns_query_for(13, "cdn.example.com"), None)
        .await
        .unwrap();
    assert_eq!(allowed[3] & 0x0f, 0, "unblocked names keep resolving");

    // A refusal the app cannot observe is half a firewall: the same block
    // has to show up both in the polled counters and in the audit stream.
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.dns_queries, 3);
    assert_eq!(snapshot.dns_blocked, 2);
    assert_eq!(snapshot.dns_allowed, 1);
    assert_eq!(
        *recorded.lock().unwrap(),
        vec![
            CoreEvent::DnsBlocked {
                reason: BlockReason::DnsBlocklist,
                domain: "ads.example.com".into(),
                package: None,
                category: None,
            },
            CoreEvent::DnsBlocked {
                reason: BlockReason::DnsBlocklist,
                domain: "deep.tracker.net".into(),
                package: None,
                category: None,
            },
        ],
        "a blocked name must be named in the audit event"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_shared_uid_bypasses_filtering_only_when_every_package_is_allowed() {
    let config = DnsConfig {
        mode: DnsMode::FakeIp,
        blocklist: DnsBlocklistConfig {
            exact: vec!["ads.example.com".into()],
            bypass_packages: vec!["com.example.allowed".into(), "com.example.second".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();
    let query = dns_query_for(31, "ads.example.com");

    let partially_allowed = vec![
        "com.example.allowed".to_owned(),
        "com.example.unlisted".to_owned(),
    ];
    let blocked = proxy
        .exchange_for_identity(&query, Some("com.example.allowed"), &partially_allowed)
        .await
        .unwrap();
    assert_eq!(
        blocked[3] & 0x0f,
        3,
        "one allowed package must not exempt its shared-UID neighbours"
    );

    let fully_allowed = vec![
        "com.example.allowed".to_owned(),
        "com.example.second".to_owned(),
    ];
    let allowed = proxy
        .exchange_for_identity(&query, Some("com.example.allowed"), &fully_allowed)
        .await
        .unwrap();
    assert_eq!(
        allowed[3] & 0x0f,
        0,
        "every package in the shared UID was explicitly allowed"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn i2p_query_is_never_sent_without_an_i2p_outbound() {
    let config = DnsConfig {
        mode: DnsMode::FakeIp,
        upstreams: vec![DnsUpstream::Udp {
            address: "127.0.0.1:9".into(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();

    let error = proxy
        .exchange(&dns_query_for(8, "service.i2p"), None)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn i2p_query_uses_fake_ip_and_never_contacts_upstream() {
    let config = DnsConfig {
        mode: DnsMode::FakeIp,
        upstreams: vec![DnsUpstream::Udp {
            address: "127.0.0.1:9".into(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let i2p = Arc::new(
        Outbound::from_config(
            OutboundConfig::I2p(I2pConfig {
                socks_address: "127.0.0.1:4447".parse().unwrap(),
                username: None,
                password: None,
                connect_timeout_ms: 1_000,
                handshake_timeout_ms: 1_000,
            }),
            ProtectedDialer::host(),
        )
        .await
        .unwrap(),
    );
    let mut named = std::collections::HashMap::new();
    named.insert("i2p".to_owned(), i2p);
    let outbounds = Arc::new(OutboundRegistry::new(direct.clone(), named).unwrap());
    let disabled = DnsProxy::new_with_gates(
        1,
        config.clone(),
        cache.clone(),
        outbounds.clone(),
        direct.clone(),
        true,
        false,
        Arc::new(FlowMetrics::default()),
        EventSink::none(),
    )
    .unwrap();
    let disabled_error = disabled
        .exchange(&dns_query_for(9, "service.i2p"), None)
        .await
        .unwrap_err();
    assert_eq!(disabled_error.kind(), io::ErrorKind::PermissionDenied);

    let proxy = DnsProxy::new(1, config, cache, outbounds, direct).unwrap();

    let response = proxy
        .exchange(&dns_query_for(9, "service.i2p"), None)
        .await
        .unwrap();
    assert_eq!(&response[..2], &[0, 9]);
    assert!(response.len() > dns_query_for(9, "service.i2p").len());
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn doh_request_uses_http2_wire_format_and_zero_dns_id() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (mut request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/dns-query");
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            DNS_MESSAGE_TYPE
        );
        assert_eq!(
            request.headers().get(CONTENT_LENGTH).unwrap(),
            &dns_query(0x9876).len().to_string()
        );
        let mut query = BytesMut::new();
        while let Some(chunk) = request.body_mut().data().await {
            let chunk = chunk.unwrap();
            request
                .body_mut()
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            query.extend_from_slice(&chunk);
        }
        assert_eq!(&query[..2], &[0, 0]);
        let response = a_response(&query, [192, 0, 2, 53]);
        let headers = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, DNS_MESSAGE_TYPE)
            .body(())
            .unwrap();
        let mut body = respond.send_response(headers, false).unwrap();
        body.send_data(Bytes::from(response), true).unwrap();
        let _ = connection.accept().await;
    });

    let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let config = DnsConfig {
        advertise: Some("10.77.0.1".into()),
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache, outbounds, direct)
        .expect("test config must enable the DNS proxy");
    let response = proxy
        .doh_request(
            &sender,
            "https://resolver.example/dns-query",
            &dns_query(0x9876),
        )
        .await
        .unwrap();
    assert_eq!(&response[..2], &[0x98, 0x76]);
    assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 53]);
    server.abort();
    client_connection.abort();
}

/// Run one DoH exchange against a server that answers with `content_type` and
/// whatever `body` describes, and hand back what the parser made of it.
async fn doh_exchange(
    content_type: &'static str,
    body: DohBody,
    max_response_bytes: usize,
) -> io::Result<Vec<u8>> {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (mut request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut query = BytesMut::new();
        while let Some(chunk) = request.body_mut().data().await {
            let chunk = chunk.unwrap();
            request
                .body_mut()
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            query.extend_from_slice(&chunk);
        }
        let payload = match body {
            DohBody::Answer => a_response(&query, [192, 0, 2, 53]),
            DohBody::Bytes(count) => vec![0x80; count],
        };
        let headers = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, content_type)
            .body(())
            .unwrap();
        let mut send = respond.send_response(headers, false).unwrap();
        send.send_data(Bytes::from(payload), true).unwrap();
        let _ = connection.accept().await;
    });

    let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let config = DnsConfig {
        advertise: Some("10.77.0.1".into()),
        max_response_bytes,
        ..Default::default()
    };
    let proxy = DnsProxy::new(
        1,
        config,
        Arc::new(DnsCache::new(8)),
        Arc::new(OutboundRegistry::single(Arc::new(Outbound::direct(
            ProtectedDialer::host(),
        )))),
        Arc::new(Outbound::direct(ProtectedDialer::host())),
    )
    .expect("test config must enable the DNS proxy");
    let result = proxy
        .doh_request(
            &sender,
            "https://resolver.example/dns-query",
            &dns_query(0x9876),
        )
        .await;
    server.abort();
    client_connection.abort();
    result
}

enum DohBody {
    /// A real answer to the query that was sent.
    Answer,
    /// This many bytes of filler, to exercise the size limits.
    Bytes(usize),
}

/// RFC 8484 §4.1 names one media type for a DNS answer, and RFC 9110 §8.3 says
/// how to compare it: case-insensitively, ignoring parameters.
///
/// The old test was `starts_with`, which got both halves wrong. It refused a
/// spelling a server is entitled to use, and — the half that matters — it
/// accepted any type merely *beginning* with those characters, so a body
/// labelled `application/dns-message-and-then-some` was parsed as a resolver's
/// answer.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_doh_answer_is_taken_only_from_the_dns_wire_media_type() {
    for accepted in [
        "application/dns-message",
        "Application/DNS-Message",
        "application/dns-message; charset=utf-8",
        "application/dns-message ;q=1",
    ] {
        let response = doh_exchange(accepted, DohBody::Answer, 65_535)
            .await
            .unwrap_or_else(|error| panic!("{accepted} must be accepted, got {error}"));
        assert_eq!(&response[..2], &[0x98, 0x76]);
    }

    for refused in [
        "application/dns-message-plus",
        "application/dns-messagex",
        "text/html",
        "text/html; charset=application/dns-message",
        "",
    ] {
        let error = doh_exchange(refused, DohBody::Answer, 65_535)
            .await
            .err()
            .unwrap_or_else(|| panic!("{refused:?} must not be read as a DNS answer"));
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{refused:?}");
    }
}

/// A body outside the range a DNS message can occupy is refused at both ends:
/// past the configured cap it is cut off rather than accumulated, and shorter
/// than the 12-byte header there is nothing to parse.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_doh_body_outside_the_dns_message_size_range_is_refused() {
    let short = doh_exchange("application/dns-message", DohBody::Bytes(8), 65_535)
        .await
        .unwrap_err();
    assert_eq!(short.kind(), io::ErrorKind::InvalidData);

    let empty = doh_exchange("application/dns-message", DohBody::Bytes(0), 65_535)
        .await
        .unwrap_err();
    assert_eq!(empty.kind(), io::ErrorKind::InvalidData);

    let oversized = doh_exchange("application/dns-message", DohBody::Bytes(4096), 512)
        .await
        .unwrap_err();
    assert_eq!(oversized.kind(), io::ErrorKind::InvalidData);
}

/// On an L3 profile there is no primary outbound to resolve through, so the
/// lookup is refused rather than answered outside the tunnel.
///
/// `DnsRoute::Primary` is what a configuration gets without asking, and the
/// registry's default on a packet-tunnel profile is the clearnet stand-in
/// for the tunnel — a protected dialer that goes around it. Answering
/// through it put every name the device looked up on the open network, which
/// on a hostile link is the browsing history the tunnel exists to hide. The
/// flow engine has refused this same placeholder for flows since it was
/// introduced; the interceptor never learned to.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn on_a_packet_tunnel_profile_the_primary_dns_route_is_refused_not_resolved_clearnet() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();

    let config = DnsConfig {
        route: DnsRoute::Primary,
        timeout_ms: 500,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()).with_packet_tunnel_primary());
    let proxy = DnsProxy::new(1, config, Arc::new(DnsCache::new(8)), outbounds, direct).unwrap();

    let error = proxy
        .exchange_for_test(&dns_query(0x1234))
        .await
        .expect_err("a clearnet placeholder must not answer an intercepted lookup");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

    let mut buffer = [0_u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut buffer),)
            .await
            .is_err(),
        "refusing has to mean nothing left the device: a query on the wire is \
             the leak, whatever the caller is told afterwards"
    );
}

/// Neither a stranger's address nor a stranger's transaction id makes an
/// answer.
///
/// A direct UDP flow must connect its socket to the address resolved for the
/// configured upstream. Without that kernel source pin, an upstream written as
/// a hostname accepts any source IP on the configured port: on shared Wi-Fi an
/// attacker that watched the query can race one forged answer into both the DNS
/// cache and the IP→name map used by domain-routing rules.
///
/// Both forgeries are sent before the genuine answer, and the assertion does
/// not depend on that order: whichever arrives first, only the upstream's
/// own answer to this query may be returned.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_forged_dns_answer_is_dropped_and_the_upstreams_own_is_still_taken() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let rogue = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let server = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (length, peer) = upstream.recv_from(&mut buffer).await.unwrap();
        let query = buffer[..length].to_vec();

        // Off-path: the real upstream's address, a guessed transaction id.
        let mut guessed_id = a_response(&query, [198, 51, 100, 66]);
        guessed_id[..2].copy_from_slice(&0x9999_u16.to_be_bytes());
        upstream.send_to(&guessed_id, peer).await.unwrap();

        // On-link: this query's transaction id, copied off the wire, from a
        // source that is not the upstream.
        let observed = a_response(&query, [198, 51, 100, 67]);
        rogue.send_to(&observed, peer).await.unwrap();

        upstream
            .send_to(&a_response(&query, [203, 0, 113, 9]), peer)
            .await
            .unwrap();
    });

    let config = DnsConfig {
        route: DnsRoute::Direct,
        timeout_ms: 5_000,
        upstreams: vec![DnsUpstream::Udp {
            address: address.to_string(),
        }],
        ..Default::default()
    };
    let cache = Arc::new(DnsCache::new(8));
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let proxy = DnsProxy::new(1, config, cache.clone(), outbounds, direct).unwrap();

    let response = proxy.exchange_for_test(&dns_query(0x1234)).await.unwrap();
    server.await.unwrap();

    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(
        &response[response.len() - 4..],
        &[203, 0, 113, 9],
        "only the upstream's answer to this query may be served"
    );
    for forged in ["198.51.100.66", "198.51.100.67"] {
        assert_eq!(
            cache.reverse_domain(forged.parse().unwrap()),
            None,
            "a refused answer must not reach the IP→name map either: it is \
                 read long after the query it came from is forgotten"
        );
    }
}

/// A hostname used to disable the IP half of source validation entirely: any
/// address using the configured port and observed transaction ID won the race.
/// The connected direct session now exports the numeric peer enforced by the
/// kernel, and the DNS layer checks that pin before accepting a response.
#[tokio::test]
async fn a_hostname_udp_upstream_rejects_the_right_id_from_an_unresolved_ip() {
    let configured = Destination::new("resolver.test", 53);
    let pinned = Destination::new("192.0.2.53", 53);
    let rogue = Destination::new("198.51.100.53", 53);
    let query = dns_query(0x1234);
    let forged = a_response(&query, [198, 51, 100, 66]);
    let genuine = a_response(&query, [203, 0, 113, 9]);

    let (session, mut io) = datagram_channel(4);
    let session = with_authenticated_peer(session, pinned.clone());
    let exchange = tokio::spawn({
        let query = query.clone();
        async move { super::proxy::exchange_datagram(&session, configured, &query).await }
    });

    let sent = io
        .uplink
        .recv()
        .await
        .expect("the query reaches the session");
    assert_eq!(sent.payload, query);
    io.downlink
        .send(Datagram::new(rogue, forged))
        .await
        .expect("inject the forged response first");
    io.downlink
        .send(Datagram::new(pinned, genuine.clone()))
        .await
        .expect("deliver the pinned upstream response");

    let response = exchange
        .await
        .expect("exchange task")
        .expect("DNS response");
    assert_eq!(response, genuine, "the unpinned source must be ignored");
}

fn dns_query(transaction_id: u16) -> Vec<u8> {
    dns_query_for(transaction_id, "example.com")
}

fn dns_query_for(transaction_id: u16, domain: &str) -> Vec<u8> {
    let mut packet = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    packet[..2].copy_from_slice(&transaction_id.to_be_bytes());
    for label in domain.split('.') {
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

fn a_response(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    response.extend_from_slice(&address);
    response
}

/// D7 in the resolver, which the first fix did not reach. A profile whose
/// outbound is TCP-only — Naive, HTTP CONNECT, I2P — with a UDP resolver is
/// a configuration the parser accepts and the owner's own subscription
/// produces. Every lookup failed with a bare `io::Error` and nothing
/// counted it, so DNS did not work and the telemetry said nothing at all.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn a_udp_resolver_on_a_tcp_only_outbound_is_counted_and_reported_once() {
    let tcp_only = Arc::new(
        Outbound::from_config(
            foxcore_api::OutboundConfig::I2p(foxcore_api::I2pConfig {
                socks_address: "127.0.0.1:4447".parse().unwrap(),
                username: None,
                password: None,
                connect_timeout_ms: 50,
                handshake_timeout_ms: 50,
            }),
            ProtectedDialer::host(),
        )
        .await
        .unwrap(),
    );
    let outbounds = Arc::new(OutboundRegistry::single(tcp_only));
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let recorded = recorded.clone();
        EventSink::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event)
        })
    };
    let config = DnsConfig {
        route: DnsRoute::Primary,
        upstreams: vec![DnsUpstream::Udp {
            address: "192.0.2.53:53".into(),
        }],
        timeout_ms: 200,
        ..DnsConfig::default()
    };
    let proxy = DnsProxy::new_with_gates_and_rule_sets(
        1,
        config,
        Arc::new(DnsCache::new(8)),
        outbounds,
        Arc::new(Outbound::direct(ProtectedDialer::host())),
        false,
        true,
        metrics.clone(),
        sink,
        Vec::new(),
    )
    .expect("a UDP resolver behind a TCP-only outbound still builds");

    for _ in 0..3 {
        assert!(
            proxy
                .exchange(&dns_query(0x4242), Some("com.example"))
                .await
                .is_err(),
            "a resolver the outbound cannot carry must fail, never fall back"
        );
    }

    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.udp_unsupported, 3,
        "the counter's job is to say how much failed"
    );
    assert_eq!(snapshot.dns_queries, 3);
    assert_eq!(snapshot.dns_blocked, 3);
    assert_eq!(snapshot.dns_allowed, 0);

    let events = recorded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        events,
        vec![CoreEvent::DnsBlocked {
            reason: BlockReason::UdpUnsupported,
            domain: "example.com".into(),
            package: Some("com.example".into()),
            category: None,
        }],
        "reported once: the condition is static until the config changes"
    );
}

/// D14, as the device ran it: the same blocklist under `fake_ip` and under
/// `real_ip`, two documents differing in exactly one field.
///
/// On the Pixel the `real_ip` side answered `dns_blocked=0` and resolved
/// every blocked name while the `fake_ip` side refused two. `real_ip` is the
/// only mode a packet-tunnel profile may use, so the filter was off exactly
/// where it had just been switched on.
///
/// Every other blocklist test in this file pins `mode: FakeIp`, which is how
/// a mode-dependent filter could pass all of them. This one asserts the
/// property the owner asked for directly: refusal is independent of whether
/// the resolver hands back an invented address or a real one.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test]
async fn the_blocklist_refuses_the_same_names_in_both_resolve_modes() {
    let mut refusals = Vec::new();
    for mode in [DnsMode::FakeIp, DnsMode::RealIp] {
        let config = DnsConfig {
            mode: mode.clone(),
            // Discard port: a blocked name that reached the upstream loop
            // would time out instead of answering NXDOMAIN, so "refused"
            // here also means "never forwarded".
            upstreams: vec![DnsUpstream::Udp {
                address: "127.0.0.1:9".into(),
            }],
            blocklist: DnsBlocklistConfig {
                exact: vec!["ads.example.com".into()],
                suffixes: vec!["tracker.net".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            config.intercepts(),
            "{mode:?}: a document carrying a blocklist has to produce an \
                 interceptor, or the filter is off before any query is asked"
        );
        let cache = Arc::new(DnsCache::new(8));
        let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
        let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
        let metrics = Arc::new(FlowMetrics::default());
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = {
            let recorded = recorded.clone();
            EventSink::new(move |event| recorded.lock().unwrap().push(event))
        };
        let proxy = DnsProxy::new_with_gates(
            1,
            config,
            cache,
            outbounds,
            direct,
            true,
            true,
            metrics.clone(),
            sink,
        )
        .expect("a blocklist must produce an interceptor in either mode");

        for (id, domain) in [(11_u16, "ads.example.com"), (12, "deep.tracker.net")] {
            let response = proxy
                .exchange(&dns_query_for(id, domain), None)
                .await
                .expect("a blocked name is answered, not failed");
            assert_eq!(
                response[3] & 0x0f,
                3,
                "{mode:?}: {domain} must be answered NXDOMAIN"
            );
        }

        let snapshot = metrics.snapshot();
        refusals.push((mode.clone(), snapshot.dns_queries, snapshot.dns_blocked));
        assert_eq!(
            recorded.lock().unwrap().len(),
            2,
            "{mode:?}: both refusals have to reach the audit stream"
        );
    }

    assert_eq!(
        refusals,
        vec![(DnsMode::FakeIp, 2, 2), (DnsMode::RealIp, 2, 2)],
        "the resolve mode decides what a resolved name is answered with. It \
             must not decide whether the name is answered at all: this is the \
             third time a blocklist has been found failing open (D1, D14)"
    );
}
