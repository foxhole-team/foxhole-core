#![forbid(unsafe_code)]

mod consts;
mod message;
mod wire;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::consts::{
    CLASS_IN, DNS_HEADER_LEN, FAKE_SWEEP_INTERVAL, MAX_TTL, RECORD_A, RECORD_AAAA, RECORD_HTTPS,
    RECORD_SVCB, STALE_TTL,
};
use crate::message::nodata_response;
use crate::wire::{parse_addresses, parse_question, query_key, response_metadata};

pub use crate::message::{
    http_query, nxdomain_response, restore_transaction_id, servfail_response, truncated_response,
};
pub use crate::wire::DnsQuestion;

pub struct DnsCache {
    capacity: usize,
    state: Mutex<State>,
    fake: Arc<Mutex<FakeState>>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsIdentity {
    uid: u32,
    packages: Vec<String>,
}

impl DnsIdentity {
    pub fn new(uid: u32, mut packages: Vec<String>) -> Self {
        packages.sort();
        packages.dedup();
        Self { uid, packages }
    }
}

#[derive(Default)]
struct RouteHints {
    names: HashMap<String, Instant>,
    overflow_until: Option<Instant>,
}

#[derive(Default)]
struct State {
    sequence: u64,
    reverse: HashMap<IpAddr, CacheEntry>,
    route_hints: HashMap<(DnsIdentity, IpAddr), RouteHints>,
    responses: HashMap<Vec<u8>, ResponseEntry>,
}

#[derive(Default)]
struct FakeState {
    sequence: u64,
    fake_by_domain: HashMap<FakeKey, FakeEntry>,
    fake_reverse: HashMap<IpAddr, FakeEntry>,
    fake_v4_sequence: u64,
    fake_v6_sequence: u128,
}

#[derive(Clone)]
struct CacheEntry {
    domain: String,
    expires: Instant,
    last_used: u64,
}

struct ResponseEntry {
    packet: Vec<u8>,
    inserted: Instant,
    expires: Instant,
    stale_until: Instant,
    ttl_fields: Vec<(usize, u32)>,
    last_used: u64,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FakeKey {
    domain: String,
    record_type: u16,
}

#[derive(Clone)]
struct FakeEntry {
    domain: String,
    address: IpAddr,
    expires: Instant,
    last_used: u64,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(State::default()),
            fake: Arc::new(Mutex::new(FakeState::default())),
            clock: Arc::new(Instant::now),
        }
    }

    /// Create the cache for a new policy revision. Reverse and fake-IP
    /// mappings are migrated so active destinations remain routable, while
    /// upstream response entries are deliberately dropped to prevent answers
    /// crossing DNS policy boundaries.
    pub fn fork_for_policy(&self, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let now = (self.clock)();
        let mut source = lock(&self.state);
        source.reverse.retain(|_, entry| entry.expires > now);
        let mut state = State {
            sequence: source.sequence,
            reverse: source.reverse.clone(),
            route_hints: HashMap::new(),
            responses: HashMap::new(),
        };
        while state.reverse.len() > capacity {
            evict_if_needed(&mut state, capacity);
        }
        // A lower admission cap cannot withdraw an address before its advertised TTL.
        Self {
            capacity,
            state: Mutex::new(state),
            fake: self.fake.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Drop every upstream answer, keeping everything an address is already
    /// being used for.
    ///
    /// Called when the device moves between networks. The answers in
    /// `responses` were given by the resolver of a network that is gone, and on
    /// a split-horizon or captive network they are wrong for the new one — the
    /// same shape as D1, since a wrong address resolves, connects and fails
    /// while every counter stays clean.
    ///
    /// Three maps are deliberately **not** touched, and the distinction is the
    /// whole point of this being a method rather than a new cache:
    ///
    /// * `fake_by_domain` / `fake_reverse` — applications are holding those
    ///   addresses right now. Invalidating them does not make anything more
    ///   correct; it breaks every live connection that resolved through the
    ///   pool and leaves the next packet with a destination nothing can map.
    ///   Flushing both together breaks the next packet because its synthetic
    ///   destination no longer maps back to a domain.
    /// * `reverse` — historical IP→name telemetry, never routing authority.
    ///   Attributed routing hints are cleared with the response cache.
    ///
    /// This is exactly the split [`DnsCache::fork_for_policy`] already makes
    /// for a reload, for the same reason.
    pub fn flush_responses(&self) -> usize {
        let mut state = lock(&self.state);
        state.route_hints.clear();
        let dropped = state.responses.len();
        state.responses.clear();
        dropped
    }

    /// Observe A/AAAA answers for telemetry only. Routing requires a paired
    /// exchange and an explicit identity through `learn_route_hints`.
    pub fn observe_response(&self, packet: &[u8]) -> usize {
        let Some(answers) = parse_addresses(packet) else {
            return 0;
        };
        let now = (self.clock)();
        let mut state = lock(&self.state);
        state.reverse.retain(|_, entry| entry.expires > now);
        let mut inserted = 0;
        for answer in answers {
            if answer.ttl == 0 {
                continue;
            }
            state.sequence = state.sequence.wrapping_add(1);
            let sequence = state.sequence;
            state.reverse.insert(
                answer.address,
                CacheEntry {
                    domain: answer.domain,
                    expires: now + Duration::from_secs(u64::from(answer.ttl.min(MAX_TTL))),
                    last_used: sequence,
                },
            );
            inserted += 1;
            evict_if_needed(&mut state, self.capacity);
        }
        inserted
    }

    pub fn reverse_domain(&self, address: IpAddr) -> Option<String> {
        let now = (self.clock)();
        let mut state = lock(&self.state);
        let expired = state
            .reverse
            .get(&address)
            .is_some_and(|entry| entry.expires <= now);
        if expired {
            state.reverse.remove(&address);
            return None;
        }
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        let entry = state.reverse.get_mut(&address)?;
        entry.last_used = sequence;
        Some(entry.domain.clone())
    }

    /// Only a validated answer to this identity's own query can constrain its routes.
    pub fn learn_route_hints(&self, query: &[u8], response: &[u8], identity: &DnsIdentity) {
        if response_metadata(query, response).is_none() {
            return;
        }
        let Some(answers) = parse_addresses(response) else {
            return;
        };
        let now = (self.clock)();
        let mut state = lock(&self.state);
        state.route_hints.retain(|_, hints| {
            hints.names.retain(|_, expiry| *expiry > now);
            hints.overflow_until.is_some_and(|expiry| expiry > now) || !hints.names.is_empty()
        });
        for answer in answers {
            if answer.ttl == 0 {
                continue;
            }
            let key = (identity.clone(), answer.address);
            if !state.route_hints.contains_key(&key) && state.route_hints.len() >= self.capacity {
                continue;
            }
            let hints = state.route_hints.entry(key).or_default();
            let expires = now + Duration::from_secs(u64::from(answer.ttl.min(MAX_TTL)));
            if hints.names.contains_key(&answer.domain) || hints.names.len() < 16 {
                hints
                    .names
                    .entry(answer.domain)
                    .and_modify(|previous| *previous = (*previous).max(expires))
                    .or_insert(expires);
            } else {
                hints.overflow_until = Some(hints.overflow_until.unwrap_or(expires).max(expires));
            }
        }
    }

    /// None also represents bounded-cache overflow; callers must not infer permission from it.
    pub fn route_hints(&self, identity: &DnsIdentity, address: IpAddr) -> Option<Vec<String>> {
        let now = (self.clock)();
        let mut state = lock(&self.state);
        let hints = state.route_hints.get_mut(&(identity.clone(), address))?;
        if hints.overflow_until.is_some_and(|expiry| expiry > now) {
            return None;
        }
        hints.names.retain(|_, expiry| *expiry > now);
        if hints.names.is_empty() {
            return None;
        }
        let mut names: Vec<_> = hints.names.keys().cloned().collect();
        names.sort();
        Some(names)
    }

    pub fn len(&self) -> usize {
        lock(&self.state).reverse.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return a cached DNS response with the caller's transaction ID restored.
    /// When `allow_stale` is true, expired entries remain usable for a short
    /// bounded stale-on-error window and are returned with TTL zero.
    pub fn cached_response(&self, query: &[u8], allow_stale: bool) -> Option<Vec<u8>> {
        let key = query_key(query)?;
        let transaction_id = [*query.first()?, *query.get(1)?];
        let now = (self.clock)();
        let mut state = lock(&self.state);
        let remove = state
            .responses
            .get(&key)
            .is_some_and(|entry| entry.stale_until <= now);
        if remove {
            state.responses.remove(&key);
            return None;
        }
        if state
            .responses
            .get(&key)
            .is_some_and(|entry| entry.expires <= now && !allow_stale)
        {
            return None;
        }
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        let entry = state.responses.get_mut(&key)?;
        entry.last_used = sequence;
        let mut packet = entry.packet.clone();
        packet[..2].copy_from_slice(&transaction_id);
        let elapsed = now.saturating_duration_since(entry.inserted).as_secs();
        for (offset, original) in &entry.ttl_fields {
            let remaining = if now >= entry.expires {
                0
            } else {
                original.saturating_sub(u32::try_from(elapsed).unwrap_or(u32::MAX))
            };
            packet[*offset..*offset + 4].copy_from_slice(&remaining.to_be_bytes());
        }
        Some(packet)
    }

    /// Validate and cache a response. A valid zero-TTL response is accepted
    /// but deliberately not retained.
    pub fn cache_response(&self, query: &[u8], response: &[u8], negative_cache: bool) -> bool {
        let Some(key) = query_key(query) else {
            return false;
        };
        let Some(metadata) = response_metadata(query, response) else {
            return false;
        };
        self.observe_response(response);
        if metadata.negative && !negative_cache {
            return true;
        }
        let ttl = metadata.min_ttl.min(MAX_TTL);
        if ttl == 0 {
            return true;
        }
        let now = (self.clock)();
        let mut packet = response.to_vec();
        packet[..2].fill(0);
        let mut state = lock(&self.state);
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        state.responses.insert(
            key,
            ResponseEntry {
                packet,
                inserted: now,
                expires: now + Duration::from_secs(u64::from(ttl)),
                stale_until: now + Duration::from_secs(u64::from(ttl)) + STALE_TTL,
                ttl_fields: metadata.ttl_fields,
                last_used: sequence,
            },
        );
        evict_responses_if_needed(&mut state, self.capacity);
        true
    }

    pub fn question(packet: &[u8]) -> Option<DnsQuestion> {
        parse_question(packet).map(|question| question.question)
    }

    /// Allocate and synthesize an A/AAAA fake-IP response. Other question
    /// types return `None` and can be forwarded to a real upstream.
    ///
    /// SVCB and HTTPS are the exception, and they are answered NODATA. Those
    /// records carry `ipv4hint`/`ipv6hint` in their own RDATA, so forwarding one
    /// hands the client a *real* address for a name whose A record it was about
    /// to be given a synthetic one for. Android 11+ and Chrome ask for HTTPS by
    /// default and connect straight to the hint, and that flow arrives at the
    /// data plane with no domain to match on — every domain rule, including
    /// Block, silently stops applying to it. NODATA is the truthful answer here:
    /// this resolver really has no SVCB data for the name, and a client that
    /// gets it falls back to A/AAAA, which is the path fake-IP exists to own.
    pub fn fake_response(
        &self,
        query: &[u8],
        ipv4_pool: Ipv4Net,
        ipv6_pool: Ipv6Net,
        ttl: u32,
    ) -> Option<Vec<u8>> {
        let parsed = parse_question(query)?;
        if parsed.question.class != CLASS_IN {
            return None;
        }
        if matches!(parsed.question.record_type, RECORD_SVCB | RECORD_HTTPS) {
            return nodata_response(query);
        }
        if !matches!(parsed.question.record_type, RECORD_A | RECORD_AAAA) {
            return None;
        }
        let address = self.fake_address(
            &parsed.question.domain,
            parsed.question.record_type,
            ipv4_pool,
            ipv6_pool,
            ttl.min(MAX_TTL),
        )?;
        let mut response = Vec::with_capacity(parsed.question_end + 28);
        response.extend_from_slice(&query[..2]);
        let request_flags = u16::from_be_bytes([query[2], query[3]]);
        let response_flags = 0x8000 | 0x0080 | (request_flags & 0x0110);
        response.extend_from_slice(&response_flags.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[DNS_HEADER_LEN..parsed.question_end]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&parsed.question.record_type.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.min(MAX_TTL).to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                response.extend_from_slice(&16_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
        }
        Some(response)
    }

    pub fn fake_domain(&self, address: IpAddr) -> Option<String> {
        let now = (self.clock)();
        let mut state = lock(&self.fake);
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        // This runs once per new flow, so a full expiry scan here would be an O(n)
        // hot-path cost under the shared lock (final.txt §21). Expiry is therefore
        // lazy — checked on the entry actually being used — plus an amortised sweep.
        if sequence.is_multiple_of(FAKE_SWEEP_INTERVAL) {
            purge_fake(&mut state, now);
        }
        let record_type = match address {
            IpAddr::V4(_) => RECORD_A,
            IpAddr::V6(_) => RECORD_AAAA,
        };
        let domain = {
            let entry = state.fake_reverse.get(&address)?;
            if entry.expires <= now {
                // Expired on use: drop the pair instead of resurrecting a stale
                // mapping that could point a flow at the wrong domain.
                let domain = entry.domain.clone();
                state.fake_reverse.remove(&address);
                state.fake_by_domain.remove(&FakeKey {
                    domain,
                    record_type,
                });
                return None;
            }
            let domain = entry.domain.clone();
            if let Some(entry) = state.fake_reverse.get_mut(&address) {
                entry.last_used = sequence;
            }
            domain
        };
        if let Some(entry) = state.fake_by_domain.get_mut(&FakeKey {
            domain: domain.clone(),
            record_type,
        }) {
            entry.last_used = sequence;
        }
        Some(domain)
    }

    fn fake_address(
        &self,
        domain: &str,
        record_type: u16,
        ipv4_pool: Ipv4Net,
        ipv6_pool: Ipv6Net,
        ttl: u32,
    ) -> Option<IpAddr> {
        let now = (self.clock)();
        let mut state = lock(&self.fake);
        purge_fake(&mut state, now);
        let key = FakeKey {
            domain: domain.to_owned(),
            record_type,
        };
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        if let Some(address) = state.fake_by_domain.get_mut(&key).map(|entry| {
            entry.last_used = sequence;
            entry.expires = now + Duration::from_secs(u64::from(ttl.max(1)));
            entry.address
        }) {
            if let Some(reverse) = state.fake_reverse.get_mut(&address) {
                reverse.last_used = sequence;
                reverse.expires = now + Duration::from_secs(u64::from(ttl.max(1)));
            }
            return Some(address);
        }
        if state.fake_by_domain.len() >= self.capacity {
            return None;
        }
        let address = match record_type {
            RECORD_A => next_fake_v4(&mut state, ipv4_pool, self.capacity)?,
            RECORD_AAAA => next_fake_v6(&mut state, ipv6_pool, self.capacity)?,
            _ => return None,
        };
        let entry = FakeEntry {
            domain: domain.to_owned(),
            address,
            expires: now + Duration::from_secs(u64::from(ttl.max(1))),
            last_used: sequence,
        };
        state.fake_by_domain.insert(key, entry.clone());
        state.fake_reverse.insert(address, entry);
        Some(address)
    }
}

fn evict_if_needed(state: &mut State, capacity: usize) {
    while state.reverse.len() > capacity {
        let Some(oldest) = state
            .reverse
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(address, _)| *address)
        else {
            break;
        };
        state.reverse.remove(&oldest);
    }
}

fn evict_responses_if_needed(state: &mut State, capacity: usize) {
    while state.responses.len() > capacity {
        let Some(oldest) = state
            .responses
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        state.responses.remove(&oldest);
    }
}

fn purge_fake(state: &mut FakeState, now: Instant) {
    let expired: Vec<_> = state
        .fake_by_domain
        .iter()
        .filter(|(_, entry)| entry.expires <= now)
        .map(|(key, _)| key.clone())
        .collect();
    for key in expired {
        if let Some(entry) = state.fake_by_domain.remove(&key) {
            state.fake_reverse.remove(&entry.address);
        }
    }
}

fn next_fake_v4(state: &mut FakeState, pool: Ipv4Net, capacity: usize) -> Option<IpAddr> {
    let host_bits = 32_u32.checked_sub(u32::from(pool.prefix_len()))?;
    let total = 1_u64.checked_shl(host_bits)?;
    let usable = total.checked_sub(2)?;
    let network = u32::from(pool.network());
    for _ in 0..=capacity {
        state.fake_v4_sequence = state.fake_v4_sequence.wrapping_add(1);
        let offset = state.fake_v4_sequence % usable + 1;
        let address = IpAddr::V4(Ipv4Addr::from(network | u32::try_from(offset).ok()?));
        if !state.fake_reverse.contains_key(&address) {
            return Some(address);
        }
    }
    None
}

fn next_fake_v6(state: &mut FakeState, pool: Ipv6Net, capacity: usize) -> Option<IpAddr> {
    let host_bits = 128_u32.checked_sub(u32::from(pool.prefix_len()))?;
    let host_mask = if host_bits == 128 {
        u128::MAX
    } else {
        1_u128.checked_shl(host_bits)?.checked_sub(1)?
    };
    let network = u128::from(pool.network());
    for _ in 0..=capacity {
        state.fake_v6_sequence = state.fake_v6_sequence.wrapping_add(1);
        let mut offset = state.fake_v6_sequence & host_mask;
        if offset == 0 {
            offset = 1;
        }
        let address = IpAddr::V6(Ipv6Addr::from(network | offset));
        if !state.fake_reverse.contains_key(&address) {
            return Some(address);
        }
    }
    None
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_hints_are_paired_scoped_ambiguous_and_epoch_bound() {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let mut cache = DnsCache::new(8);
        let now = clock.clone();
        cache.clock = Arc::new(move || *now.lock().unwrap());
        let first = DnsIdentity::new(10001, vec!["protected.app".into()]);
        let second = DnsIdentity::new(10002, vec!["other.app".into()]);
        for record_type in [RECORD_A, RECORD_AAAA] {
            let maker = DnsCache::new(8);
            let original = query_for("protected.invalid", record_type, 1);
            let answer = maker
                .fake_response(
                    &original,
                    "198.18.0.0/15".parse().unwrap(),
                    "fd00::/64".parse().unwrap(),
                    60,
                )
                .unwrap();
            let address = parse_addresses(&answer).unwrap()[0].address;
            cache.observe_response(&answer);
            assert!(cache.route_hints(&first, address).is_none());
            let forged = query_for("allowed.invalid", record_type, 1);
            cache.learn_route_hints(&forged, &answer, &first);
            assert!(cache.route_hints(&first, address).is_none());
            cache.learn_route_hints(&original, &answer, &first);
            assert_eq!(
                cache.route_hints(&first, address).unwrap(),
                ["protected.invalid"]
            );
            assert!(cache.route_hints(&second, address).is_none());
            let other = query_for("allowed.invalid", record_type, 2);
            let mut response = maker
                .fake_response(
                    &other,
                    "198.18.0.0/15".parse().unwrap(),
                    "fd00::/64".parse().unwrap(),
                    60,
                )
                .unwrap();
            let length = if record_type == RECORD_A { 4 } else { 16 };
            let offset = response.len() - length;
            response[offset..].copy_from_slice(&answer[answer.len() - length..]);
            cache.learn_route_hints(&other, &response, &second);
            assert_eq!(
                cache.route_hints(&first, address).unwrap(),
                ["protected.invalid"]
            );
            cache.learn_route_hints(&other, &response, &first);
            assert_eq!(
                cache.route_hints(&first, address).unwrap(),
                ["allowed.invalid", "protected.invalid"]
            );
            assert!(
                cache
                    .fork_for_policy(8)
                    .route_hints(&first, address)
                    .is_none()
            );
        }
        *clock.lock().unwrap() += Duration::from_secs(61);
        assert!(
            cache
                .route_hints(&first, "198.18.0.2".parse().unwrap())
                .is_none()
        );
        cache.flush_responses();
        assert!(lock(&cache.state).route_hints.is_empty());
    }

    #[test]
    fn a_fake_answer_finishing_after_reload_belongs_to_the_shared_pool() {
        let cache = DnsCache::new(2);
        let fork = cache.fork_for_policy(1);
        let address = cache
            .fake_address(
                "late.invalid",
                RECORD_A,
                "198.18.0.0/15".parse().unwrap(),
                "fd00::/64".parse().unwrap(),
                60,
            )
            .unwrap();
        assert_eq!(fork.fake_domain(address).as_deref(), Some("late.invalid"));
        assert!(
            fork.fake_address(
                "new.invalid",
                RECORD_A,
                "198.18.0.0/15".parse().unwrap(),
                "fd00::/64".parse().unwrap(),
                60
            )
            .is_none()
        );
    }

    #[test]
    fn route_hints_follow_only_the_answered_cname_chain() {
        fn name(out: &mut Vec<u8>, domain: &str) {
            for label in domain.split('.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            out.push(0);
        }
        fn record(out: &mut Vec<u8>, owner: &str, kind: u16, ttl: u32, data: &[u8]) {
            name(out, owner);
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&1_u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        let question = query_for("protected.invalid", RECORD_A, 1);
        let mut answer = question.clone();
        answer[2..4].copy_from_slice(&[0x81, 0x80]);
        answer[6..8].copy_from_slice(&3_u16.to_be_bytes());
        let mut target = Vec::new();
        name(&mut target, "cdn.invalid");
        record(&mut answer, "unrelated.invalid", 1, 60, &[203, 0, 113, 66]);
        record(&mut answer, "cdn.invalid", 1, 60, &[203, 0, 113, 9]);
        record(&mut answer, "protected.invalid", 5, 10, &target);
        let parsed = parse_addresses(&answer).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].domain, "protected.invalid");
        assert_eq!(parsed[0].ttl, 10);
        assert_eq!(parsed[0].address.to_string(), "203.0.113.9");
        let cache = DnsCache::new(8);
        let identity = DnsIdentity::new(10001, vec!["app".into()]);
        cache.learn_route_hints(&question, &answer, &identity);
        assert!(
            cache
                .route_hints(&identity, "203.0.113.66".parse().unwrap())
                .is_none()
        );
        assert_eq!(
            cache
                .route_hints(&identity, "203.0.113.9".parse().unwrap())
                .unwrap(),
            ["protected.invalid"]
        );
    }

    #[test]
    fn reissued_fake_addresses_keep_the_last_promised_ttl_without_eviction() {
        for record_type in [RECORD_A, RECORD_AAAA] {
            let clock = Arc::new(Mutex::new(Instant::now()));
            let mut cache = DnsCache::new(1);
            let now = clock.clone();
            cache.clock = Arc::new(move || *now.lock().unwrap());
            let v4 = "198.18.0.0/15".parse().unwrap();
            let v6 = "fd00::/64".parse().unwrap();
            let first = cache
                .fake_response(&query(record_type, 1), v4, v6, 1)
                .unwrap();
            let address = parse_addresses(&first).unwrap()[0].address;
            *clock.lock().unwrap() += Duration::from_millis(700);
            let second = cache
                .fake_response(&query(record_type, 2), v4, v6, 1)
                .unwrap();
            assert_eq!(parse_addresses(&second).unwrap()[0].address, address);
            assert!(
                cache
                    .fake_address("other.invalid", record_type, v4, v6, 1)
                    .is_none()
            );
            cache.flush_responses();
            let fork = cache.fork_for_policy(1);
            *clock.lock().unwrap() += Duration::from_millis(450);
            assert_eq!(cache.fake_domain(address).as_deref(), Some("example.com"));
            assert_eq!(fork.fake_domain(address).as_deref(), Some("example.com"));
            *clock.lock().unwrap() += Duration::from_millis(551);
            assert!(cache.fake_domain(address).is_none());
            assert!(fork.fake_domain(address).is_none());
            assert!(
                cache
                    .fake_address("other.invalid", record_type, v4, v6, 1)
                    .is_some()
            );
        }
    }

    /// A client that sees TC retries over TCP, which this interceptor serves.
    /// A client that sees a second datagram instead sees a malformed message.
    #[test]
    fn a_truncated_answer_sets_tc_and_keeps_the_question() {
        let query = query(1, 0x4242);

        let response = truncated_response(&query).expect("a truncation reply");

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "must be a response");
        assert_eq!(flags & 0x0200, 0x0200, "TC must be set");
        assert_eq!(flags & 0x000f, 0, "rcode must stay NOERROR");
        assert_eq!(&response[..2], &query[..2], "transaction id must match");
        assert_eq!(
            u16::from_be_bytes([response[4], response[5]]),
            1,
            "the question must be echoed back"
        );
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            0,
            "a truncated answer carries no records"
        );
    }

    fn response(address: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1,
        ];
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&[0, 4]);
        packet.extend_from_slice(&address);
        packet
    }

    pub(crate) fn query(record_type: u16, transaction_id: u16) -> Vec<u8> {
        query_for("example.com", record_type, transaction_id)
    }

    fn query_for(domain: &str, record_type: u16, transaction_id: u16) -> Vec<u8> {
        let mut packet = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        packet[..2].copy_from_slice(&transaction_id.to_be_bytes());
        for label in domain.split('.') {
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&record_type.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet
    }

    #[test]
    fn observes_compressed_a_answer() {
        let cache = DnsCache::new(8);
        assert_eq!(cache.observe_response(&response([1, 2, 3, 4], 60)), 1);
        assert_eq!(
            cache.reverse_domain("1.2.3.4".parse().unwrap()),
            Some("example.com".into())
        );
    }

    #[test]
    fn stays_bounded_and_ignores_queries() {
        let cache = DnsCache::new(1);
        cache.observe_response(&response([1, 1, 1, 1], 60));
        cache.observe_response(&response([8, 8, 8, 8], 60));
        assert_eq!(cache.len(), 1);

        let mut query = response([9, 9, 9, 9], 60);
        query[2] = 0x01;
        assert_eq!(cache.observe_response(&query), 0);
    }

    #[test]
    fn response_cache_normalizes_transaction_id() {
        let cache = DnsCache::new(8);
        let first_query = query(RECORD_A, 0x1234);
        let response = response([1, 2, 3, 4], 60);
        assert!(cache.cache_response(&first_query, &response, true));

        let second_query = query(RECORD_A, 0xabcd);
        let cached = cache.cached_response(&second_query, false).unwrap();
        assert_eq!(&cached[..2], &[0xab, 0xcd]);
        assert_eq!(
            DnsCache::question(&second_query).unwrap().domain,
            "example.com"
        );
    }

    /// The one field of an answer an off-path forger cannot simply copy.
    ///
    /// Everything else is free to whoever can guess the question: echo it, set
    /// QR, attach any address. Accepting on that alone let a host on the same
    /// Wi-Fi beat the resolver to the reply, and the damage outlived the query —
    /// the answer is retained for up to `MAX_TTL` and its address is folded into
    /// the map domain routing rules are matched through.
    #[test]
    fn a_response_carrying_a_foreign_transaction_id_is_dropped() {
        let cache = DnsCache::new(8);
        let query = query(RECORD_A, 0x1234);
        let mut forged = response([203, 0, 113, 66], 60);
        forged[..2].copy_from_slice(&0x4321_u16.to_be_bytes());

        assert!(
            !cache.cache_response(&query, &forged, true),
            "an answer that does not carry this query's transaction id is not this query's answer"
        );
        assert!(cache.cached_response(&query, false).is_none());
        assert_eq!(
            cache.reverse_domain("203.0.113.66".parse().unwrap()),
            None,
            "a refused answer must not reach the IP→name map either: that map \
             is read long after the query it came from is forgotten"
        );

        assert!(
            cache.cache_response(&query, &response([1, 2, 3, 4], 60), true),
            "the genuine answer racing behind the forgery still has to be taken"
        );
        assert_eq!(
            cache.reverse_domain("1.2.3.4".parse().unwrap()),
            Some("example.com".into())
        );
    }

    #[test]
    fn fake_ip_response_has_reverse_mapping_and_stays_in_pool() {
        let cache = DnsCache::new(8);
        let query = query(RECORD_A, 7);
        let ipv4_pool = "198.18.0.0/15".parse().unwrap();
        let ipv6_pool = "fd00::/120".parse().unwrap();
        let response = cache
            .fake_response(&query, ipv4_pool, ipv6_pool, 300)
            .unwrap();
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        let address = IpAddr::V4(Ipv4Addr::new(
            response[response.len() - 4],
            response[response.len() - 3],
            response[response.len() - 2],
            response[response.len() - 1],
        ));
        assert!(ipv4_pool.contains(&match address {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => unreachable!(),
        }));
        assert_eq!(cache.fake_domain(address), Some("example.com".into()));
    }

    /// Forwarding an HTTPS question hands back the very address fake-IP just
    /// refused to hand back as an A record.
    ///
    /// `ipv4hint` lives inside the record, so the client connects to a real
    /// address for a name it never got a synthetic one for. That flow reaches
    /// the data plane with no domain attached, and every domain rule — Block
    /// included — stops applying to it. Android 11+ and Chrome ask for this
    /// record by default, so it is the common path, not an edge case.
    #[test]
    fn in_fake_ip_mode_an_https_question_is_answered_here_and_not_forwarded() {
        let cache = DnsCache::new(8);
        let ipv4_pool = "198.18.0.0/15".parse().unwrap();
        let ipv6_pool = "fd00::/120".parse().unwrap();

        let response = cache
            .fake_response(&query(RECORD_HTTPS, 0x0909), ipv4_pool, ipv6_pool, 300)
            .expect("an HTTPS question must be answered, never sent to an upstream");

        assert_eq!(&response[..2], &[0x09, 0x09]);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "must be a response");
        assert_eq!(
            flags & 0x000f,
            0,
            "NODATA, not NXDOMAIN: a client told the name does not exist may \
             stop asking for the A record fake-IP has to be asked for"
        );
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            0,
            "NODATA carries no answers"
        );
        assert!(
            cache
                .fake_response(&query(RECORD_SVCB, 0x0a0a), ipv4_pool, ipv6_pool, 300)
                .is_some(),
            "SVCB is the same record with the same hints in it"
        );
        assert!(
            cache
                .fake_response(&query(16, 0x0b0b), ipv4_pool, ipv6_pool, 300)
                .is_none(),
            "a TXT question carries no address hint and stays the upstream's to answer"
        );
    }

    #[test]
    fn fake_ip_pressure_preserves_every_unexpired_promise() {
        let cache = DnsCache::new(2);
        let ipv4_pool = "198.18.0.0/15".parse().unwrap();
        let ipv6_pool = "fd00::/120".parse().unwrap();
        let first = cache
            .fake_response(
                &query_for("first.example", RECORD_A, 1),
                ipv4_pool,
                ipv6_pool,
                300,
            )
            .unwrap();
        let first_address = IpAddr::V4(Ipv4Addr::new(
            first[first.len() - 4],
            first[first.len() - 3],
            first[first.len() - 2],
            first[first.len() - 1],
        ));
        let second = cache
            .fake_response(
                &query_for("second.example", RECORD_A, 2),
                ipv4_pool,
                ipv6_pool,
                300,
            )
            .unwrap();
        let second_address = IpAddr::V4(Ipv4Addr::new(
            second[second.len() - 4],
            second[second.len() - 3],
            second[second.len() - 2],
            second[second.len() - 1],
        ));

        assert_eq!(
            cache.fake_domain(first_address).as_deref(),
            Some("first.example")
        );
        assert!(
            cache
                .fake_response(
                    &query_for("third.example", RECORD_A, 3),
                    ipv4_pool,
                    ipv6_pool,
                    300,
                )
                .is_none()
        );

        assert_eq!(
            cache.fake_domain(first_address).as_deref(),
            Some("first.example")
        );
        assert_eq!(
            cache.fake_domain(second_address).as_deref(),
            Some("second.example")
        );
    }

    #[test]
    fn policy_fork_keeps_mappings_but_drops_upstream_answers() {
        let cache = DnsCache::new(8);
        let query = query(RECORD_A, 0x1234);
        assert!(cache.cache_response(&query, &response([1, 2, 3, 4], 60), true));
        let fake = cache
            .fake_response(
                &query_for("fake.example", RECORD_A, 2),
                "198.18.0.0/15".parse().unwrap(),
                "fd00::/120".parse().unwrap(),
                300,
            )
            .unwrap();
        let fake_address = IpAddr::V4(Ipv4Addr::new(
            fake[fake.len() - 4],
            fake[fake.len() - 3],
            fake[fake.len() - 2],
            fake[fake.len() - 1],
        ));

        let fork = cache.fork_for_policy(8);

        assert!(fork.cached_response(&query, false).is_none());
        assert_eq!(
            fork.reverse_domain("1.2.3.4".parse().unwrap()).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            fork.fake_domain(fake_address).as_deref(),
            Some("fake.example")
        );
    }

    /// The same split as the policy fork, in place, for a different event: the
    /// device moved to a network whose resolver answers differently.
    ///
    /// Serving the old network's answers until their TTL hands out addresses
    /// that are wrong here; dropping the fake-IP pool with them breaks every
    /// application that is holding one of its addresses right now. Only the
    /// first is a cache.
    #[test]
    fn a_network_flush_drops_upstream_answers_and_nothing_an_address_is_used_for() {
        let cache = DnsCache::new(8);
        let query = query(RECORD_A, 0x1234);
        assert!(cache.cache_response(&query, &response([1, 2, 3, 4], 60), true));
        let fake = cache
            .fake_response(
                &query_for("fake.example", RECORD_A, 2),
                "198.18.0.0/15".parse().unwrap(),
                "fd00::/120".parse().unwrap(),
                300,
            )
            .unwrap();
        let fake_address = IpAddr::V4(Ipv4Addr::new(
            fake[fake.len() - 4],
            fake[fake.len() - 3],
            fake[fake.len() - 2],
            fake[fake.len() - 1],
        ));

        assert_eq!(cache.flush_responses(), 1);

        assert!(
            cache.cached_response(&query, false).is_none(),
            "the previous network's answer must not outlive the network"
        );
        assert!(
            cache.cached_response(&query, true).is_none(),
            "and must not come back as a stale answer either"
        );
        assert_eq!(
            cache.fake_domain(fake_address).as_deref(),
            Some("fake.example"),
            "the pool is not a cache: applications are holding these addresses"
        );
        assert_eq!(
            cache.reverse_domain("1.2.3.4".parse().unwrap()).as_deref(),
            Some("example.com"),
            "nor is the map domain routing rules are matched through"
        );
        assert_eq!(cache.flush_responses(), 0);
    }

    #[test]
    fn creates_bounded_servfail_for_valid_query() {
        let query = query(RECORD_AAAA, 0xbeef);
        let response = servfail_response(&query).unwrap();
        assert_eq!(&response[..2], &[0xbe, 0xef]);
        assert_eq!(response[3] & 0x0f, 2);
        assert_eq!(response.len(), query.len());
    }
}
