use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn query(id: u16, record_type: u16) -> Vec<u8> {
    let mut q = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q[..2].copy_from_slice(&id.to_be_bytes());
    for label in ["scope", "example", "test"] {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.push(0);
    q.extend(record_type.to_be_bytes());
    q.extend(1_u16.to_be_bytes());
    q
}

fn answer(query: &[u8], ttl: u32, last: u8) -> Vec<u8> {
    let mut r = query.to_vec();
    r[2] = 0x81;
    r[3] = 0x80;
    r[7] = 1;
    r.extend([0xc0, 0x0c]);
    let kind = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    r.extend(kind.to_be_bytes());
    r.extend(1_u16.to_be_bytes());
    r.extend(ttl.to_be_bytes());
    if kind == 28 {
        r.extend(16_u16.to_be_bytes());
        r.extend([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
        ]);
    } else {
        r.extend(4_u16.to_be_bytes());
        r.extend([192, 0, 2, last]);
    }
    r
}

fn negative(query: &[u8], ttl: u32) -> Vec<u8> {
    let mut r = query.to_vec();
    r[2] = 0x81;
    r[3] = 0x83;
    r[9] = 1;
    r.extend([0xc0, 0x0c, 0, 6, 0, 1]);
    r.extend(ttl.to_be_bytes());
    r.extend(24_u16.to_be_bytes());
    r.extend([0xc0, 0x0c, 0xc0, 0x0c]);
    for value in [1, ttl, ttl, ttl, ttl] {
        r.extend(value.to_be_bytes());
    }
    r
}

fn scope(lane: DnsResponseLane, uid: u32, packages: &[&str], epoch: u64) -> DnsResponseScope {
    DnsResponseScope::new(
        lane,
        Some(DnsIdentity::new(
            uid,
            packages.iter().map(|p| (*p).into()).collect(),
        )),
        epoch,
    )
}

#[test]
fn responses_are_separate_for_lane_uid_packages_epoch_and_legacy_namespace() {
    let cache = DnsCache::new(16);
    let q = query(0x1234, 1);
    let direct = scope(DnsResponseLane::Direct, 10001, &["app.one"], 7);
    assert!(cache.cache_response_scoped(&q, &answer(&q, 60, 1), true, &direct));
    for other in [
        scope(DnsResponseLane::Profile, 10001, &["app.one"], 7),
        scope(DnsResponseLane::Direct, 10002, &["app.one"], 7),
        scope(DnsResponseLane::Direct, 10001, &["app.two"], 7),
        scope(DnsResponseLane::Direct, 10001, &["app.one"], 8),
        DnsResponseScope::new(DnsResponseLane::Direct, None, 7),
    ] {
        assert!(cache.cached_response_scoped(&q, false, &other).is_none());
        assert!(cache.cached_response_scoped(&q, true, &other).is_none());
    }
    assert!(cache.cached_response(&q, true).is_none());
    let second = query(0xabcd, 1);
    let cached = cache
        .cached_response_scoped(&second, false, &direct)
        .unwrap();
    assert_eq!(&cached[..2], &0xabcd_u16.to_be_bytes());
    assert_eq!(cached.last(), Some(&1));

    let profile = scope(DnsResponseLane::Profile, 10001, &["app.one"], 7);
    assert!(cache.cache_response_scoped(&q, &answer(&q, 60, 2), true, &profile));
    assert_eq!(
        cache
            .cached_response_scoped(&q, false, &direct)
            .unwrap()
            .last(),
        Some(&1)
    );
    assert_eq!(
        cache
            .cached_response_scoped(&q, false, &profile)
            .unwrap()
            .last(),
        Some(&2)
    );
    assert!(cache.cache_response(&q, &answer(&q, 60, 3), true));
    assert_eq!(cache.cached_response(&q, false).unwrap().last(), Some(&3));
    assert_eq!(
        cache
            .cached_response_scoped(&q, false, &direct)
            .unwrap()
            .last(),
        Some(&1)
    );
}

#[test]
fn canonical_shared_uid_identity_has_one_scope_but_incomplete_identity_has_another() {
    let cache = DnsCache::new(8);
    let q = query(7, 1);
    let complete = scope(
        DnsResponseLane::Direct,
        10001,
        &["app.two", "app.one", "app.one"],
        4,
    );
    assert!(cache.cache_response_scoped(&q, &answer(&q, 60, 1), true, &complete));
    let reordered = scope(DnsResponseLane::Direct, 10001, &["app.one", "app.two"], 4);
    assert!(
        cache
            .cached_response_scoped(&q, false, &reordered)
            .is_some()
    );
    for other in [
        scope(DnsResponseLane::Direct, 10001, &["app.one"], 4),
        scope(DnsResponseLane::Direct, 10001, &[], 4),
        DnsResponseScope::new(DnsResponseLane::Direct, None, 4),
    ] {
        assert!(cache.cached_response_scoped(&q, false, &other).is_none());
    }
}

#[test]
fn stale_and_negative_answers_do_not_cross_scope_or_epoch() {
    let mut cache = DnsCache::new(8);
    let base = Instant::now();
    let seconds = Arc::new(AtomicU64::new(0));
    let now = seconds.clone();
    cache.clock = Arc::new(move || base + Duration::from_secs(now.load(Ordering::SeqCst)));
    let q = query(7, 1);
    let direct = scope(DnsResponseLane::Direct, 10001, &["app.one"], 4);
    assert!(cache.cache_response_scoped(&q, &answer(&q, 1, 1), true, &direct));
    seconds.store(2, Ordering::SeqCst);
    assert!(cache.cached_response_scoped(&q, false, &direct).is_none());
    let stale = cache.cached_response_scoped(&q, true, &direct).unwrap();
    assert_eq!(&stale[q.len() + 6..q.len() + 10], &0_u32.to_be_bytes());
    let next_epoch = scope(DnsResponseLane::Direct, 10001, &["app.one"], 5);
    assert!(
        cache
            .cached_response_scoped(&q, true, &next_epoch)
            .is_none()
    );
    let profile = scope(DnsResponseLane::Profile, 10001, &["app.one"], 4);
    assert!(cache.cached_response_scoped(&q, true, &profile).is_none());
    seconds.store(STALE_TTL.as_secs() + 2, Ordering::SeqCst);
    assert!(cache.cached_response_scoped(&q, true, &direct).is_none());

    assert!(cache.cache_response_scoped(&q, &negative(&q, 60), true, &direct));
    assert_eq!(
        cache.cached_response_scoped(&q, false, &direct).unwrap()[3] & 15,
        3
    );
    assert!(cache.cached_response_scoped(&q, false, &profile).is_none());
    assert!(
        cache
            .cached_response_scoped(&q, true, &next_epoch)
            .is_none()
    );
    let rejected = scope(DnsResponseLane::Profile, 20002, &["app.two"], 4);
    assert!(cache.cache_response_scoped(&q, &negative(&q, 60), false, &rejected));
    assert!(cache.cached_response_scoped(&q, false, &rejected).is_none());
}

#[test]
fn all_response_scopes_and_legacy_entries_share_one_total_lru_budget() {
    let cache = DnsCache::new(4);
    let q = query(7, 1);
    let scopes: Vec<_> = (1..=5)
        .map(|uid| scope(DnsResponseLane::Direct, uid, &["app.one"], 1))
        .collect();
    for (i, scope) in scopes[..4].iter().enumerate() {
        assert!(cache.cache_response_scoped(&q, &answer(&q, 60, i as u8), true, scope));
    }
    assert!(
        cache
            .cached_response_scoped(&q, false, &scopes[0])
            .is_some()
    );
    assert!(cache.cache_response_scoped(&q, &answer(&q, 60, 5), true, &scopes[4]));
    assert!(
        cache
            .cached_response_scoped(&q, false, &scopes[1])
            .is_none()
    );
    assert!(
        cache
            .cached_response_scoped(&q, false, &scopes[0])
            .is_some()
    );
    assert_eq!(lock(&cache.state).responses.len(), 4);
    assert!(cache.cache_response(&q, &answer(&q, 60, 6), true));
    assert_eq!(lock(&cache.state).responses.len(), 4);
    for uid in 10..1000 {
        let scope = scope(DnsResponseLane::Profile, uid, &["app.one"], uid as u64);
        assert!(cache.cache_response_scoped(&q, &answer(&q, 60, 7), true, &scope));
        assert!(lock(&cache.state).responses.len() <= 4);
    }
}

#[test]
fn scoped_response_validation_rejects_wrong_id_question_and_record_type() {
    let cache = DnsCache::new(8);
    let q = query(0x1234, 1);
    let scope = scope(DnsResponseLane::Direct, 10001, &["app.one"], 7);
    let mut foreign = answer(&q, 60, 1);
    foreign[..2].copy_from_slice(&0x4321_u16.to_be_bytes());
    assert!(!cache.cache_response_scoped(&q, &foreign, true, &scope));
    let different_type = query(0x1234, 28);
    assert!(!cache.cache_response_scoped(&q, &answer(&different_type, 60, 2), true, &scope));
    assert!(cache.cached_response_scoped(&q, true, &scope).is_none());
    assert!(cache.reverse_domain("192.0.2.1".parse().unwrap()).is_none());
    assert!(cache.cache_response_scoped(
        &different_type,
        &answer(&different_type, 60, 3),
        true,
        &scope
    ));
    assert!(cache.cached_response_scoped(&q, false, &scope).is_none());
    assert_eq!(
        cache
            .cached_response_scoped(&different_type, false, &scope)
            .unwrap()
            .last(),
        Some(&3)
    );
}

#[test]
fn flush_and_policy_fork_drop_every_response_scope_but_preserve_fake_promises() {
    let cache = DnsCache::new(8);
    let q = query(7, 1);
    let direct = scope(DnsResponseLane::Direct, 10001, &["app.one"], 7);
    let profile = scope(DnsResponseLane::Profile, 10002, &["app.two"], 7);
    for scope in [&direct, &profile] {
        assert!(cache.cache_response_scoped(&q, &answer(&q, 60, 1), true, scope));
    }
    assert!(cache.cache_response(&q, &answer(&q, 60, 2), true));
    let fake = cache
        .fake_response(
            &q,
            "198.18.0.0/15".parse().unwrap(),
            "fd00::/120".parse().unwrap(),
            300,
        )
        .unwrap();
    let ip = IpAddr::V4(Ipv4Addr::from(
        <[u8; 4]>::try_from(&fake[fake.len() - 4..]).unwrap(),
    ));
    let fork = cache.fork_for_policy(8);
    assert!(fork.cached_response_scoped(&q, true, &direct).is_none());
    assert!(fork.cached_response_scoped(&q, true, &profile).is_none());
    assert!(fork.cached_response(&q, true).is_none());
    assert_eq!(fork.fake_domain(ip).as_deref(), Some("scope.example.test"));
    assert_eq!(cache.flush_responses(), 3);
    assert!(cache.cached_response_scoped(&q, true, &direct).is_none());
    assert!(cache.cached_response_scoped(&q, true, &profile).is_none());
    assert_eq!(cache.fake_domain(ip).as_deref(), Some("scope.example.test"));
}

fn packet_hint_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q[..2].copy_from_slice(&id.to_be_bytes());
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    q
}

#[test]
fn packet_hints_are_separate_for_authority_uid_and_complete_package_identity() {
    let cache = DnsCache::new(8);
    let authority = [1; 32];
    let identity = DnsIdentity::new(10001, vec!["app.two".into(), "app.one".into()]);
    let reordered = DnsIdentity::new(
        10001,
        vec!["app.one".into(), "app.two".into(), "app.one".into()],
    );
    for kind in [1, 28] {
        let q = query(7, kind);
        let response = answer(&q, 60, 9);
        let address = if kind == 1 {
            "192.0.2.9"
        } else {
            "2001:db8::9"
        }
        .parse()
        .unwrap();
        cache.learn_packet_route_hints(authority, &q, &response, &identity);
        assert_eq!(
            cache.packet_route_hints(authority, &reordered, address),
            Some(vec!["scope.example.test".into()])
        );
        assert!(
            cache
                .packet_route_hints([2; 32], &identity, address)
                .is_none()
        );
        for other in [
            DnsIdentity::new(10002, vec!["app.one".into(), "app.two".into()]),
            DnsIdentity::new(10001, vec!["app.one".into()]),
            DnsIdentity::new(10001, vec![]),
        ] {
            assert!(
                cache
                    .packet_route_hints(authority, &other, address)
                    .is_none()
            );
        }
        assert!(cache.route_hints(&identity, address).is_none());
        assert!(cache.reverse_domain(address).is_none());
    }
}

#[test]
fn packet_hints_require_the_original_paired_nonzero_ttl_answer() {
    let cache = DnsCache::new(8);
    let identity = DnsIdentity::new(10001, vec!["app.one".into()]);
    let authority = [1; 32];
    let q = query(7, 1);
    let address = "192.0.2.9".parse().unwrap();
    let mut foreign = answer(&q, 60, 9);
    foreign[..2].copy_from_slice(&8_u16.to_be_bytes());
    for response in [
        foreign,
        answer(&query(7, 28), 60, 9),
        answer(&packet_hint_query(7, "other.example.test"), 60, 9),
    ] {
        cache.learn_packet_route_hints(authority, &q, &response, &identity);
        assert!(
            cache
                .packet_route_hints(authority, &identity, address)
                .is_none()
        );
    }
    let original = answer(&q, 0, 9);
    cache.learn_packet_route_hints(authority, &q, &original, &identity);
    assert!(
        cache
            .packet_route_hints(authority, &identity, address)
            .is_none()
    );
    let mut client_answer = original;
    client_answer[q.len() + 6..q.len() + 10].copy_from_slice(&30_u32.to_be_bytes());
    cache.observe_response(&client_answer);
    cache.learn_route_hints(&q, &client_answer, &identity);
    assert!(cache.route_hints(&identity, address).is_some());
    assert!(
        cache
            .packet_route_hints(authority, &identity, address)
            .is_none()
    );
}

#[test]
fn packet_hints_expire_at_original_ttl_and_maximum_without_a_floor() {
    let mut cache = DnsCache::new(1);
    let base = Instant::now();
    let seconds = Arc::new(AtomicU64::new(0));
    let now = seconds.clone();
    cache.clock = Arc::new(move || base + Duration::from_secs(now.load(Ordering::SeqCst)));
    let identity = DnsIdentity::new(10001, vec!["app.one".into()]);
    let q = query(7, 1);
    let address = "192.0.2.9".parse().unwrap();
    cache.learn_packet_route_hints([1; 32], &q, &answer(&q, 1, 9), &identity);
    seconds.store(1, Ordering::SeqCst);
    assert!(
        cache
            .packet_route_hints([1; 32], &identity, address)
            .is_none()
    );
    cache.learn_packet_route_hints([2; 32], &q, &answer(&q, u32::MAX, 9), &identity);
    assert!(
        cache
            .packet_route_hints([2; 32], &identity, address)
            .is_some()
    );
    seconds.store(1 + u64::from(MAX_TTL), Ordering::SeqCst);
    assert!(
        cache
            .packet_route_hints([2; 32], &identity, address)
            .is_none()
    );
}

#[test]
fn packet_hints_preserve_ambiguity_and_bounded_overflow_until_its_ttl() {
    let mut cache = DnsCache::new(1);
    let base = Instant::now();
    let seconds = Arc::new(AtomicU64::new(0));
    let now = seconds.clone();
    cache.clock = Arc::new(move || base + Duration::from_secs(now.load(Ordering::SeqCst)));
    let identity = DnsIdentity::new(10001, vec!["app.one".into()]);
    let address = "192.0.2.9".parse().unwrap();
    for index in 0..16 {
        let q = packet_hint_query(index, &format!("name{index}.example.test"));
        cache.learn_packet_route_hints([1; 32], &q, &answer(&q, 60, 9), &identity);
    }
    let names = cache
        .packet_route_hints([1; 32], &identity, address)
        .unwrap();
    assert_eq!(names.len(), 16);
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    let overflow = packet_hint_query(17, "overflow.example.test");
    cache.learn_packet_route_hints([1; 32], &overflow, &answer(&overflow, 1, 9), &identity);
    assert!(
        cache
            .packet_route_hints([1; 32], &identity, address)
            .is_none()
    );
    let fork = cache.fork_for_policy(64);
    cache.flush_responses();
    assert!(
        fork.packet_route_hints([1; 32], &identity, address)
            .is_none()
    );
    seconds.store(1, Ordering::SeqCst);
    assert_eq!(
        fork.packet_route_hints([1; 32], &identity, address)
            .unwrap(),
        names
    );
    assert!(
        fork.packet_route_hints([2; 32], &identity, address)
            .is_none()
    );
}

#[test]
fn packet_bindings_are_arc_shared_across_policy_fork_and_response_flush_only() {
    let cache = DnsCache::new(2);
    let identity = DnsIdentity::new(10001, vec!["app.one".into()]);
    let q = query(7, 1);
    let response = answer(&q, 60, 9);
    let address = "192.0.2.9".parse().unwrap();
    cache.learn_route_hints(&q, &response, &identity);
    cache.learn_packet_route_hints([1; 32], &q, &response, &identity);
    assert!(cache.cache_response(&q, &response, true));
    let fork = cache.fork_for_policy(8);
    assert!(Arc::ptr_eq(&cache.packet_hints, &fork.packet_hints));
    assert!(fork.route_hints(&identity, address).is_none());
    assert!(fork.cached_response(&q, true).is_none());
    assert_eq!(cache.flush_responses(), 1);
    assert!(cache.route_hints(&identity, address).is_none());
    assert_eq!(
        fork.packet_route_hints([1; 32], &identity, address),
        Some(vec!["scope.example.test".into()])
    );
    let second = packet_hint_query(8, "second.example.test");
    fork.learn_packet_route_hints([1; 32], &second, &answer(&second, 60, 9), &identity);
    assert_eq!(
        cache.packet_route_hints([1; 32], &identity, address),
        Some(vec![
            "scope.example.test".into(),
            "second.example.test".into()
        ])
    );
    assert!(
        cache
            .packet_route_hints([2; 32], &identity, address)
            .is_none()
    );
}

#[test]
fn packet_hint_key_budget_is_shared_and_not_multiplied_by_policy_forks() {
    let cache = DnsCache::new(1);
    let identity = DnsIdentity::new(10001, vec!["app.one".into()]);
    let q = query(7, 1);
    cache.learn_packet_route_hints([1; 32], &q, &answer(&q, 60, 9), &identity);
    let fork = cache.fork_for_policy(64);
    fork.learn_packet_route_hints([2; 32], &q, &answer(&q, 60, 10), &identity);
    assert!(
        fork.packet_route_hints([2; 32], &identity, "192.0.2.10".parse().unwrap())
            .is_none()
    );
    assert!(
        cache
            .packet_route_hints([1; 32], &identity, "192.0.2.9".parse().unwrap())
            .is_some()
    );
}
