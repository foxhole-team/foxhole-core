//! Per-query cost of the two routing lookups that run on every flow: the FST
//! blocklist and the compiled rule table.
//!
//! The blocklist is benchmarked at 200_000 entries because that is the order a
//! real list has, and an FST's walk cost depends on how much the automaton has
//! shared — a number taken on ten domains says nothing about the device.
//!
//! Nothing here is a fix. `route_decide` is measured in two shapes on purpose:
//! with a domain hint, where `normalize_domain` builds a fresh `String` per
//! flow, and against an IP destination, where it does not run at all. The gap is
//! that allocation plus the domain index lookups, stated rather than removed.

#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use foxcore_api::{
    Destination, FlowContext, IpTransport, OutboundId, PortRange, RouteAction, RouteRule,
};
use foxcore_route::RouteTable;
use foxcore_route::domain::DomainBlocklist;

const BLOCKLIST_ENTRIES: usize = 200_000;

/// Deterministic domains with the label shapes a real list has: two or three
/// labels under a spread of TLDs, so the automaton shares suffixes the way it
/// would in production. The counter in the second label is what guarantees
/// uniqueness — an FST refuses duplicate keys.
fn synthetic_domains(count: usize) -> Vec<String> {
    const WORDS: [&str; 16] = [
        "ads",
        "track",
        "metrics",
        "pixel",
        "beacon",
        "telemetry",
        "analytics",
        "cdn",
        "collect",
        "log",
        "stat",
        "event",
        "sync",
        "tag",
        "click",
        "promo",
    ];
    const TLDS: [&str; 8] = ["com", "net", "org", "io", "co.uk", "de", "ru", "info"];

    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    let mut domains = Vec::with_capacity(count);
    for index in 0..count {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let first = WORDS[(state >> 33) as usize % WORDS.len()];
        let second = WORDS[(state >> 17) as usize % WORDS.len()];
        let tld = TLDS[(state >> 5) as usize % TLDS.len()];
        domains.push(format!("{first}.{second}{index}.{tld}"));
    }
    domains
}

fn domain_blocklist(c: &mut Criterion) {
    let domains = synthetic_domains(BLOCKLIST_ENTRIES);
    let list = DomainBlocklist::compile(&[], &domains);
    assert_eq!(list.len(), BLOCKLIST_ENTRIES);

    // A name in the list, a name under one of its suffix entries, and two
    // misses: one that shares a TLD and so walks deep before failing, one whose
    // TLD is absent and fails within the first bytes. A live DNS stream is
    // mostly misses, so a baseline built only on hits would flatter the path.
    let hit = domains[BLOCKLIST_ENTRIES / 2].clone();
    let under = format!("img.static.{hit}");
    let miss_deep = format!("{hit}.notlisted");
    let miss_shallow = "unrelated.example.invalidtld".to_string();
    assert!(list.blocks(&hit) && list.blocks(&under));
    assert!(!list.blocks(&miss_deep) && !list.blocks(&miss_shallow));

    let mut group = c.benchmark_group("domain_blocklist_200k");
    group.bench_function("lookup/hit_exact_name", |b| {
        b.iter(|| black_box(list.lookup(black_box(&hit))));
    });
    group.bench_function("lookup/hit_under_suffix", |b| {
        b.iter(|| black_box(list.lookup(black_box(&under))));
    });
    group.bench_function("lookup/miss_walks_deep", |b| {
        b.iter(|| black_box(list.lookup(black_box(&miss_deep))));
    });
    group.bench_function("lookup/miss_fails_early", |b| {
        b.iter(|| black_box(list.lookup(black_box(&miss_shallow))));
    });
    group.bench_function("blocks/hit_under_suffix", |b| {
        b.iter(|| black_box(list.blocks(black_box(&under))));
    });
    group.bench_function("blocks/miss_walks_deep", |b| {
        b.iter(|| black_box(list.blocks(black_box(&miss_deep))));
    });
    group.finish();
}

fn empty_rule(action: RouteAction) -> RouteRule {
    RouteRule {
        uid: None,
        package: None,
        exact_domains: Vec::new(),
        domain_suffixes: Vec::new(),
        cidrs: Vec::new(),
        ports: Vec::new(),
        network: None,
        transport: None,
        action,
        expires_at_ms: None,
    }
}

/// A rule table of the size a configured profile has: exact-domain rules,
/// suffix rules and a port fallback, with at least one BLOCK rule so the
/// firewall pre-pass runs — that is the shape `decide` takes in production.
fn rule_table() -> RouteTable {
    let mut rules = Vec::new();
    for domain in synthetic_domains(128) {
        let mut exact = empty_rule(RouteAction::Direct);
        exact.exact_domains.push(domain);
        rules.push(exact);
    }
    for domain in synthetic_domains(128) {
        let mut suffix = empty_rule(RouteAction::Tor);
        suffix.domain_suffixes.push(domain);
        rules.push(suffix);
    }
    let mut blocked = empty_rule(RouteAction::Block);
    blocked.domain_suffixes.push("blocked.example".to_string());
    rules.push(blocked);

    let mut fallback = empty_rule(RouteAction::Direct);
    fallback.ports.push(PortRange { start: 80, end: 80 });
    rules.push(fallback);

    RouteTable::compile(rules, RouteAction::Outbound(OutboundId("default".into())))
}

fn route_decide(c: &mut Criterion) {
    let table = rule_table();

    let mut with_domain = FlowContext::new(
        1,
        IpTransport::Tcp,
        Destination::new("cdn.assets.example.com", 443),
    );
    with_domain.domain_hint = Some("CDN.Assets.Example.COM.".to_string());

    let ip_only = FlowContext::new(1, IpTransport::Tcp, Destination::new("93.184.216.34", 443));

    let mut group = c.benchmark_group("route_decide");
    group.bench_function("with_domain_hint", |b| {
        b.iter(|| black_box(table.decide(black_box(&with_domain))));
    });
    group.bench_function("ip_only_destination", |b| {
        b.iter(|| black_box(table.decide(black_box(&ip_only))));
    });
    group.finish();
}

criterion_group!(benches, domain_blocklist, route_decide);
criterion_main!(benches);
