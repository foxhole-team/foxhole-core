//! Property tests for route rule priority.
//!
//! Insertion order is *not* incidental here: `RouteTable` narrows to a candidate
//! set by domain specificity and then takes the first candidate that matches, so
//! the rule index is the tie-break inside every specificity bucket. That makes
//! the priority a two-level order, and the interesting question is not whether
//! order matters but exactly where it stops mattering — a question with one
//! example per bucket combination, which is why it is asked with proptest.
//!
//! The reference below re-derives the winner from the rule list directly, with
//! no suffix trie and no candidate vectors, so a bug in the indexing shows up as
//! a disagreement rather than as traffic quietly taking the wrong outbound.

use std::collections::BTreeSet;

use foxcore_api::{
    Destination, FlowContext, IpTransport, NetworkType, OutboundId, PortRange, RouteAction,
    RouteRule,
};
use foxcore_route::RouteTable;
use proptest::prelude::*;

/// Far enough in the past that no clock the test can run under makes it live.
const LAPSED: u64 = 1_000;

fn default_action() -> RouteAction {
    RouteAction::Outbound(OutboundId("default".into()))
}

/// Where a rule sits in the priority order for one flow. Smaller wins.
///
/// The third component is the rule's index in the compiled list, which is what
/// encodes "first one wins inside a bucket".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Priority {
    class: u8,
    /// Negated suffix depth, so that the longest suffix sorts first.
    depth: i32,
    index: usize,
}

fn normalize(domain: &str) -> String {
    domain.trim_matches('.').to_ascii_lowercase()
}

/// Labels of `suffix` that `domain` ends on, counted the way the trie counts
/// them: the suffix must align to a label boundary, so `nototonion` is not
/// inside `onion`.
fn suffix_depth(domain: &str, suffix: &str) -> Option<i32> {
    let aligned = domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.');
    aligned.then(|| suffix.split('.').count() as i32)
}

/// The domain the table decides on: the hint, or the destination host when it is
/// not a literal address.
fn flow_domain(flow: &FlowContext) -> Option<String> {
    flow.domain_hint
        .as_deref()
        .or_else(|| {
            flow.destination
                .ip()
                .is_none()
                .then_some(flow.destination.host.as_str())
        })
        .map(normalize)
}

/// True when every non-domain selector on the rule admits this flow.
fn selectors_admit(rule: &RouteRule, flow: &FlowContext, now_ms: u64) -> bool {
    if rule.expires_at_ms.is_some_and(|expires| now_ms >= expires) {
        return false;
    }
    if rule.uid.is_some_and(|uid| flow.uid != Some(uid)) {
        return false;
    }
    if rule.package.as_ref().is_some_and(|package| {
        flow.package.as_ref() != Some(package) && !flow.packages.contains(package)
    }) {
        return false;
    }
    if rule
        .network
        .is_some_and(|network| flow.network != Some(network))
    {
        return false;
    }
    if rule
        .transport
        .is_some_and(|transport| flow.transport != transport)
    {
        return false;
    }
    if !rule.ports.is_empty()
        && !rule
            .ports
            .iter()
            .any(|range| range.contains(flow.destination.port))
    {
        return false;
    }
    true
}

/// The priority of `rule` for `flow`, or `None` when it cannot win at all.
fn priority(index: usize, rule: &RouteRule, flow: &FlowContext, now_ms: u64) -> Option<Priority> {
    if !selectors_admit(rule, flow, now_ms) {
        return None;
    }
    let domain = flow_domain(flow);
    if let Some(domain) = &domain
        && rule
            .exact_domains
            .iter()
            .any(|exact| normalize(exact) == *domain)
    {
        return Some(Priority {
            class: 0,
            depth: 0,
            index,
        });
    }
    if let Some(domain) = &domain
        && let Some(depth) = rule
            .domain_suffixes
            .iter()
            .filter_map(|suffix| suffix_depth(domain, &normalize(suffix)))
            .max()
    {
        return Some(Priority {
            class: 1,
            depth: -depth,
            index,
        });
    }
    if rule.exact_domains.is_empty() && rule.domain_suffixes.is_empty() {
        return Some(Priority {
            class: 2,
            depth: 0,
            index,
        });
    }
    None
}

fn expected_action(rules: &[RouteRule], flow: &FlowContext, now_ms: u64) -> RouteAction {
    rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            priority(index, rule, flow, now_ms).map(|priority| (priority, &rule.action))
        })
        .min_by_key(|(priority, _)| *priority)
        .map(|(_, action)| action.clone())
        .unwrap_or_else(default_action)
}

/// The rules that tie for the winning bucket, ignoring the index tie-break. When
/// they all carry one action, no permutation of the list can change the verdict.
fn winning_bucket_actions(
    rules: &[RouteRule],
    flow: &FlowContext,
    now_ms: u64,
) -> BTreeSet<String> {
    let priorities: Vec<(Priority, &RouteAction)> = rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            priority(index, rule, flow, now_ms).map(|priority| (priority, &rule.action))
        })
        .collect();
    let Some(best) = priorities.iter().map(|(priority, _)| *priority).min() else {
        return BTreeSet::new();
    };
    priorities
        .iter()
        .filter(|(priority, _)| priority.class == best.class && priority.depth == best.depth)
        .map(|(_, action)| format!("{action:?}"))
        .collect()
}

/// Three labels, not thirty. The point of the generator is to make different
/// rules land in the *same* priority bucket as often as possible — with a wide
/// alphabet almost every case has a single matching rule, and a single matching
/// rule proves nothing about priority.
fn label() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("a".to_string()),
        Just("b".to_string()),
        Just("Com".to_string()),
    ]
}

fn domain() -> impl Strategy<Value = String> {
    prop::collection::vec(label(), 1..3).prop_map(|labels| labels.join("."))
}

fn action() -> impl Strategy<Value = RouteAction> {
    prop_oneof![
        Just(RouteAction::Direct),
        Just(RouteAction::Block),
        Just(RouteAction::Outbound(OutboundId("alpha".into()))),
    ]
}

/// Deadlines are either far in the past or unreachable, never near now: the
/// table reads the wall clock itself, so anything in between would make the
/// reference and the implementation disagree about the present rather than
/// about priority.
fn deadline() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![
        6 => Just(None),
        2 => Just(Some(LAPSED)),
        2 => Just(Some(u64::MAX)),
    ]
}

/// Non-domain selectors are mostly absent, for the same reason the alphabet is
/// small: every extra selector is another way for a rule to drop out of the
/// candidate set, and a rule that never matches never tests a priority.
fn rule() -> impl Strategy<Value = RouteRule> {
    (
        prop::option::weighted(0.2, 10_000_u32..10_002),
        prop::option::weighted(
            0.2,
            prop_oneof![
                Just("com.example.one".to_string()),
                Just("com.example.two".to_string())
            ],
        ),
        prop::collection::vec(domain(), 0..2),
        prop::collection::vec(domain(), 0..2),
        prop::collection::vec((0_u16..8, 0_u16..8), 0..2),
        prop::option::weighted(
            0.2,
            prop_oneof![Just(NetworkType::Wifi), Just(NetworkType::Cellular)],
        ),
        prop::option::weighted(
            0.2,
            prop_oneof![Just(IpTransport::Tcp), Just(IpTransport::Udp)],
        ),
        action(),
        deadline(),
    )
        .prop_map(
            |(uid, package, exact, suffixes, ports, network, transport, action, expires_at_ms)| {
                RouteRule {
                    uid,
                    package,
                    exact_domains: exact,
                    domain_suffixes: suffixes,
                    cidrs: Vec::new(),
                    ports: ports
                        .into_iter()
                        .map(|(low, high)| PortRange {
                            start: low.min(high),
                            end: low.max(high),
                        })
                        .collect(),
                    network,
                    transport,
                    action,
                    expires_at_ms,
                }
            },
        )
}

fn flow() -> impl Strategy<Value = FlowContext> {
    (
        domain(),
        0_u16..8,
        prop_oneof![Just(IpTransport::Tcp), Just(IpTransport::Udp)],
        prop::option::of(10_000_u32..10_002),
        prop::collection::vec(
            prop_oneof![
                Just("com.example.one".to_string()),
                Just("com.example.two".to_string()),
                Just("com.example.three".to_string())
            ],
            0..2,
        ),
        prop::option::of(prop_oneof![
            Just(NetworkType::Wifi),
            Just(NetworkType::Cellular)
        ]),
    )
        .prop_map(|(host, port, transport, uid, packages, network)| {
            let mut flow = FlowContext::new(1, transport, Destination::new(host, port));
            flow.uid = uid;
            flow.package = packages.first().cloned();
            flow.packages = packages;
            flow.network = network;
            flow
        })
}

/// A time strictly between the lapsed deadline and the unreachable one, so the
/// reference agrees with whatever the table's own clock read was.
fn reference_now() -> u64 {
    LAPSED + 1
}

/// The flow every bucket-targeted property decides on.
const BUCKET_HOST: &str = "a.b.com";

/// One priority bucket for [`BUCKET_HOST`], named so a rule can be built to land
/// in a chosen bucket instead of being generated and hoped over.
#[derive(Debug, Clone, Copy)]
enum Bucket {
    Exact,
    Suffix,
    ShallowSuffix,
    Fallback,
}

fn bucket_rule(bucket: Bucket, action: RouteAction) -> RouteRule {
    let mut rule = RouteRule {
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
    };
    match bucket {
        Bucket::Exact => rule.exact_domains.push(BUCKET_HOST.into()),
        Bucket::Suffix => rule.domain_suffixes.push("b.com".into()),
        Bucket::ShallowSuffix => rule.domain_suffixes.push("com".into()),
        Bucket::Fallback => {}
    }
    rule
}

fn bucket() -> impl Strategy<Value = Bucket> {
    prop_oneof![
        Just(Bucket::Exact),
        Just(Bucket::Suffix),
        Just(Bucket::ShallowSuffix),
        Just(Bucket::Fallback),
    ]
}

proptest! {
    /// The whole priority order in one statement: exact domain beats the longest
    /// matching suffix, which beats a rule with no domain selector, and inside
    /// each of those buckets the earlier rule in the list wins.
    #[test]
    fn the_winning_rule_is_the_first_one_in_the_most_specific_bucket(
        rules in prop::collection::vec(rule(), 0..8),
        flow in flow(),
    ) {
        let expected = expected_action(&rules, &flow, reference_now());
        let table = RouteTable::compile(rules, default_action());
        prop_assert_eq!(table.decide(&flow), &expected);
    }

    /// The tie-break on its own, with a generator that cannot miss it: every rule
    /// carries the *same* selector, so every rule is in the winning bucket and
    /// only position can decide. The broad property above covers this too, but
    /// only in the minority of cases where two rules happen to collide.
    #[test]
    fn inside_one_bucket_the_earliest_rule_wins_and_the_rest_are_dead(
        bucket in bucket(),
        actions in prop::collection::vec(action(), 1..6),
        lapsed_prefix in prop::collection::vec(action(), 0..3),
    ) {
        // Lapsed duplicates sit *in front* of the live ones: if expiry were
        // checked after the first-match cut rather than as part of it, the table
        // would answer with a rule that is no longer in force.
        let mut rules: Vec<RouteRule> = lapsed_prefix
            .iter()
            .map(|action| {
                let mut rule = bucket_rule(bucket, action.clone());
                rule.expires_at_ms = Some(LAPSED);
                rule
            })
            .collect();
        rules.extend(
            actions
                .iter()
                .map(|action| bucket_rule(bucket, action.clone())),
        );

        let flow = FlowContext::new(1, IpTransport::Tcp, Destination::new(BUCKET_HOST, 443));
        let table = RouteTable::compile(rules, default_action());
        prop_assert_eq!(
            table.decide(&flow),
            &actions[0],
            "the first live rule in the bucket must win outright"
        );
    }

    /// The bucket order itself, again with a generator that always populates
    /// every bucket, so exact-over-suffix-over-fallback is exercised on every
    /// case rather than whenever the dice cooperate.
    #[test]
    fn a_more_specific_bucket_always_outranks_a_less_specific_one(
        exact_action in action(),
        deep_action in action(),
        shallow_action in action(),
        fallback_action in action(),
        drop_exact in any::<bool>(),
        drop_deep in any::<bool>(),
        drop_shallow in any::<bool>(),
    ) {
        // The more specific rule is appended *last*, so index order and bucket
        // order disagree on every case and only one of them can be answering.
        let mut rules = vec![bucket_rule(Bucket::Fallback, fallback_action.clone())];
        let mut expected = fallback_action;
        if !drop_shallow {
            expected = shallow_action.clone();
            rules.push(bucket_rule(Bucket::ShallowSuffix, shallow_action));
        }
        if !drop_deep {
            expected = deep_action.clone();
            rules.push(bucket_rule(Bucket::Suffix, deep_action));
        }
        if !drop_exact {
            expected = exact_action.clone();
            rules.push(bucket_rule(Bucket::Exact, exact_action));
        }

        let flow = FlowContext::new(1, IpTransport::Tcp, Destination::new(BUCKET_HOST, 443));
        let table = RouteTable::compile(rules, default_action());
        prop_assert_eq!(table.decide(&flow), &expected);
    }

    /// Order is a tie-break, not a policy input: when everything that could win
    /// the top bucket agrees on an action, the list may be shuffled freely. If
    /// this ever fails, priority has started depending on something other than
    /// specificity and position.
    #[test]
    fn shuffling_rules_that_agree_in_the_winning_bucket_changes_nothing(
        rules in prop::collection::vec(rule(), 0..8),
        flow in flow(),
        permutation in prop::collection::vec(any::<usize>(), 0..8),
    ) {
        prop_assume!(winning_bucket_actions(&rules, &flow, reference_now()).len() <= 1);

        let mut shuffled = rules.clone();
        for (position, seed) in permutation.iter().enumerate() {
            if shuffled.is_empty() {
                break;
            }
            let length = shuffled.len();
            shuffled.swap(position % length, seed % length);
        }

        let original = RouteTable::compile(rules, default_action());
        let reordered = RouteTable::compile(shuffled, default_action());
        prop_assert_eq!(original.decide(&flow), reordered.decide(&flow));
    }

    /// A lapsed rule is dead weight: it must not win, and it must not shadow the
    /// rule that would have won without it. Adding one anywhere in the list is
    /// the strongest way to say that — it also catches a lapsed rule flipping the
    /// table's has-block-rules or has-deadlines flags into a different code path.
    #[test]
    fn inserting_lapsed_rules_anywhere_leaves_every_decision_untouched(
        rules in prop::collection::vec(rule(), 0..6),
        lapsed in prop::collection::vec(rule(), 1..4),
        positions in prop::collection::vec(any::<usize>(), 1..4),
        flow in flow(),
    ) {
        let live: Vec<RouteRule> = rules
            .into_iter()
            .filter(|rule| rule.expires_at_ms != Some(LAPSED))
            .collect();
        let baseline = RouteTable::compile(live.clone(), default_action());
        let before = baseline.decide(&flow).clone();

        let mut padded = live;
        for (rule, position) in lapsed.into_iter().zip(positions) {
            let mut rule = rule;
            rule.expires_at_ms = Some(LAPSED);
            let at = position % (padded.len() + 1);
            padded.insert(at, rule);
        }

        let padded = RouteTable::compile(padded, default_action());
        prop_assert_eq!(
            padded.decide(&flow),
            &before,
            "a rule whose deadline has passed still changed the verdict"
        );
    }

    /// Deciding the same flow twice against the same table must give the same
    /// answer. Trivial only in appearance: the table reads the wall clock on
    /// every call whenever any rule carries a deadline.
    #[test]
    fn deciding_the_same_flow_twice_gives_the_same_answer(
        rules in prop::collection::vec(rule(), 0..8),
        flow in flow(),
    ) {
        let table = RouteTable::compile(rules, default_action());
        prop_assert_eq!(table.decide(&flow), table.decide(&flow));
    }

    /// Compiling the same rules twice must produce the same verdicts, so nothing
    /// in the compiled form depends on hash iteration order.
    #[test]
    fn two_tables_compiled_from_the_same_rules_agree(
        rules in prop::collection::vec(rule(), 0..8),
        flow in flow(),
    ) {
        let first = RouteTable::compile(rules.clone(), default_action());
        let second = RouteTable::compile(rules, default_action());
        prop_assert_eq!(first.decide(&flow), second.decide(&flow));
    }
}
