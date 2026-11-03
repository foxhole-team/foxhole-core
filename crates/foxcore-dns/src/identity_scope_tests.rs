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
