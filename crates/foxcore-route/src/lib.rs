#![forbid(unsafe_code)]

pub mod domain;
pub mod ruleset;

use std::collections::HashMap;
use std::net::IpAddr;

use foxcore_api::{
    ApplicationRouteAction, FlowContext, RouteAction, RouteRule, TrafficPolicyConfig,
};

/// A compiled rule table. Exact and suffix-domain candidates are indexed; the
/// remaining dimensions are checked only inside the narrowed candidate set.
#[derive(Debug, Clone)]
pub struct RouteTable {
    rules: Vec<RouteRule>,
    exact_domains: HashMap<String, Vec<usize>>,
    suffix_domains: SuffixNode,
    fallback: Vec<usize>,
    default: RouteAction,
    applications: HashMap<String, ApplicationEntry>,
    block: RouteAction,
    tor_enabled: bool,
    i2p_enabled: bool,
    requires_uid: bool,
    requires_package: bool,
    has_block_rules: bool,
    kill_switch: bool,
    /// `Some` while quarantine is armed: package -> optional required signing digest.
    quarantine: Option<HashMap<String, Option<[u8; 32]>>>,
    /// True when any rule or application entry carries a deadline. Reading the
    /// wall clock is only worth it then.
    has_expiring: bool,
}

#[derive(Debug, Clone)]
struct ApplicationEntry {
    action: RouteAction,
    expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteExplanation {
    pub action: RouteAction,
    pub route_rule_index: Option<usize>,
    pub route_rule_applied: bool,
    pub shadowed_block_rules: Vec<usize>,
}

impl ApplicationEntry {
    fn is_active(&self, now_ms: Option<u64>) -> bool {
        match (self.expires_at_ms, now_ms) {
            (Some(expires), Some(now)) => now < expires,
            _ => true,
        }
    }
}

/// Wall-clock milliseconds. A clock that cannot be read yields `0`, which makes
/// every deadline look *unreached* — expiring a block early is the unsafe
/// direction, so time going backwards must never unblock traffic.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default)]
struct SuffixNode {
    rules: Vec<usize>,
    children: HashMap<String, SuffixNode>,
}

impl RouteTable {
    pub fn compile(rules: Vec<RouteRule>, default: RouteAction) -> Self {
        Self::compile_with_traffic(rules, default, TrafficPolicyConfig::default(), true, true)
    }

    pub fn compile_with_traffic(
        rules: Vec<RouteRule>,
        vpn: RouteAction,
        traffic: TrafficPolicyConfig,
        tor_enabled: bool,
        i2p_enabled: bool,
    ) -> Self {
        let mut exact_domains: HashMap<String, Vec<usize>> = HashMap::new();
        let mut suffix_domains = SuffixNode::default();
        let mut fallback = Vec::new();

        for (index, rule) in rules.iter().enumerate() {
            for domain in &rule.exact_domains {
                exact_domains
                    .entry(normalize_domain(domain))
                    .or_default()
                    .push(index);
            }
            for suffix in &rule.domain_suffixes {
                suffix_domains.insert(&normalize_domain(suffix), index);
            }
            if rule.exact_domains.is_empty() && rule.domain_suffixes.is_empty() {
                fallback.push(index);
            }
        }

        let kill_switch = traffic.kill_switch;
        let quarantine = traffic.quarantine_new_apps.then(|| {
            traffic
                .known_apps
                .iter()
                .map(|app| {
                    (
                        app.package.clone(),
                        app.signing_digest
                            .as_deref()
                            .and_then(foxcore_api::decode_signing_digest),
                    )
                })
                .collect()
        });
        let has_block_rules = rules.iter().any(|rule| rule.action == RouteAction::Block);
        let requires_uid = rules.iter().any(|rule| rule.uid.is_some());
        let requires_package = rules.iter().any(|rule| rule.package.is_some())
            || !traffic.applications.is_empty()
            // Quarantine judges every flow by package, so attribution is mandatory;
            // without this the engine would skip identity and quarantine would be a
            // silent no-op.
            || traffic.quarantine_new_apps;
        let default = application_action(traffic.default_action, &vpn);
        let applications: HashMap<String, ApplicationEntry> = traffic
            .applications
            .into_iter()
            .map(|application| {
                (
                    application.package,
                    ApplicationEntry {
                        action: application_action(application.action, &vpn),
                        expires_at_ms: application.expires_at_ms,
                    },
                )
            })
            .collect();
        let has_expiring = rules.iter().any(|rule| rule.expires_at_ms.is_some())
            || applications
                .values()
                .any(|entry| entry.expires_at_ms.is_some());
        Self {
            rules,
            exact_domains,
            suffix_domains,
            fallback,
            default,
            applications,
            block: RouteAction::Block,
            tor_enabled,
            i2p_enabled,
            requires_uid,
            requires_package,
            has_block_rules,
            kill_switch,
            quarantine,
            has_expiring,
        }
    }

    /// Global fail-closed switch. Callers that answer traffic outside `decide`
    /// (the local ICMP responder) must consult it too.
    pub fn kill_switch(&self) -> bool {
        self.kill_switch
    }

    pub fn requires_uid(&self) -> bool {
        self.requires_uid
    }

    pub fn requires_package(&self) -> bool {
        self.requires_package
    }

    pub fn requires_identity(&self) -> bool {
        self.requires_uid || self.requires_package
    }

    pub fn requires_domain_hints(&self) -> bool {
        !self.exact_domains.is_empty() || !self.suffix_domains.children.is_empty()
    }

    /// Inferred names can restrict an IP route, never grant a more permissive one.
    /// Distinct protected routes are incomparable and require explicit name binding.
    pub fn constrain_with_dns_hints(&self, flow: &mut FlowContext, names: &[String]) -> bool {
        flow.domain_hint = None;
        let mut candidate = flow.clone();
        let mut selected = self.decide(&candidate).clone();
        if selected == RouteAction::Block {
            return true;
        }
        if names.is_empty() {
            return false;
        }
        let mut selected_name = None;
        let mut conflict = false;
        for name in names {
            candidate.domain_hint = Some(name.clone());
            let action = self.decide(&candidate);
            if *action == RouteAction::Block {
                flow.domain_hint = Some(name.clone());
                return true;
            }
            if *action == RouteAction::Direct || *action == selected {
                continue;
            }
            if selected == RouteAction::Direct {
                selected = action.clone();
                selected_name = Some(name.clone());
            } else {
                conflict = true;
            }
        }
        flow.domain_hint = selected_name;
        !conflict
    }

    pub fn tor_enabled(&self) -> bool {
        self.tor_enabled
    }

    pub fn i2p_enabled(&self) -> bool {
        self.i2p_enabled
    }

    pub fn decide(&self, flow: &FlowContext) -> &RouteAction {
        self.decide_at(flow, self.has_expiring.then(now_millis))
    }

    /// Explain schema-v1 specificity exceptions without changing routing semantics.
    pub fn explain(&self, flow: &FlowContext) -> RouteExplanation {
        let now = self.has_expiring.then(now_millis);
        let action = self.decide_at(flow, now);
        let candidate = self.match_rules(flow, now);
        let route_rule_index = candidate.and_then(|action| {
            self.rules
                .iter()
                .position(|rule| std::ptr::eq(&rule.action, action))
        });
        let domain = flow
            .domain_hint
            .as_deref()
            .or_else(|| {
                flow.destination
                    .ip()
                    .is_none()
                    .then_some(flow.destination.host.as_str())
            })
            .map(normalize_domain);
        let shadowed_block_rules = self
            .rules
            .iter()
            .enumerate()
            .filter(|(index, rule)| {
                Some(*index) != route_rule_index
                    && rule.action == RouteAction::Block
                    && rule_matches(rule, flow, now)
                    && ((rule.exact_domains.is_empty() && rule.domain_suffixes.is_empty())
                        || domain.as_ref().is_some_and(|domain| {
                            rule.exact_domains
                                .iter()
                                .any(|name| normalize_domain(name) == *domain)
                                || rule.domain_suffixes.iter().any(|suffix| {
                                    let suffix = normalize_domain(suffix);
                                    *domain == suffix
                                        || domain
                                            .strip_suffix(&suffix)
                                            .is_some_and(|prefix| prefix.ends_with('.'))
                                })
                        }))
            })
            .map(|(index, _)| index)
            .collect();
        RouteExplanation {
            action: action.clone(),
            route_rule_index,
            route_rule_applied: candidate.is_some_and(|candidate| std::ptr::eq(candidate, action)),
            shadowed_block_rules,
        }
    }

    fn decide_at(&self, flow: &FlowContext, now_ms: Option<u64>) -> &RouteAction {
        // Stage 0: the global kill switch outranks everything — explicit application
        // allowances, the default allowlist and the `.onion`/`.i2p` auto-route alike.
        if self.kill_switch {
            return &self.block;
        }
        // A specificity-selected Block precedes application rules. More-specific
        // non-Block exceptions remain part of the schema-v1 routing contract.
        // Read the wall clock at most once per flow, and only when the compiled
        // policy actually carries deadlines.
        let matched = self.has_block_rules.then(|| self.match_rules(flow, now_ms));
        if let Some(Some(action)) = matched
            && matches!(action, RouteAction::Block)
        {
            return action;
        }
        // §6 stage 3: an application the user has not ruled on yet never reaches the
        // network, and a known package presenting the wrong signing digest counts as
        // unknown — identity is not the package name alone (final.txt §15).
        if let Some(known) = &self.quarantine
            && is_quarantined(known, flow)
        {
            return &self.block;
        }
        if let Some(action) = self.application_action(flow, now_ms) {
            return self.gated(action);
        }
        // A default-block policy is a firewall allowlist. Generic route rules
        // must never punch a hole through it; explicit application entries are
        // the only allowed exceptions.
        if self.default == RouteAction::Block {
            return &self.block;
        }
        let action = matched
            .unwrap_or_else(|| self.match_rules(flow, now_ms))
            .unwrap_or(&self.default);
        self.gated(action)
    }

    /// Most specific first: exact domain, then longest domain suffix, then the
    /// rules that carry no domain selector at all.
    fn match_rules<'a>(
        &'a self,
        flow: &FlowContext,
        now_ms: Option<u64>,
    ) -> Option<&'a RouteAction> {
        let domain = flow
            .domain_hint
            .as_deref()
            .or_else(|| {
                flow.destination
                    .ip()
                    .is_none()
                    .then_some(flow.destination.host.as_str())
            })
            .map(normalize_domain);

        if let Some(domain) = domain {
            if let Some(candidates) = self.exact_domains.get(&domain)
                && let Some(action) = self.first_match(candidates, flow, now_ms)
            {
                return Some(action);
            }
            let mut suffix_candidates = Vec::new();
            self.suffix_domains.collect(&domain, &mut suffix_candidates);
            if let Some(action) = self.first_match(&suffix_candidates, flow, now_ms) {
                return Some(action);
            }
        }
        self.first_match(&self.fallback, flow, now_ms)
    }

    fn application_action<'a>(
        &'a self,
        flow: &FlowContext,
        now_ms: Option<u64>,
    ) -> Option<&'a RouteAction> {
        if self.applications.is_empty() {
            return None;
        }
        let mut matched: Option<&RouteAction> = None;
        let mut has_unconfigured_package = false;
        let packages = flow
            .packages
            .iter()
            .map(String::as_str)
            .chain(flow.package.as_deref().filter(|_| flow.packages.is_empty()));
        for package in packages {
            // A lapsed entry is treated as if it had never been configured, so the
            // package falls back to the general policy instead of staying pinned.
            match self
                .applications
                .get(package)
                .filter(|entry| entry.is_active(now_ms))
            {
                Some(entry) => match matched {
                    Some(previous) if *previous != entry.action => return Some(&self.block),
                    None => matched = Some(&entry.action),
                    Some(_) => {}
                },
                None => has_unconfigured_package = true,
            }
        }
        match matched {
            Some(action) if has_unconfigured_package && action != &self.default => {
                // Android shared UIDs cannot be attributed to one package. A
                // mixed decision therefore fails closed instead of leaking.
                Some(&self.block)
            }
            action => action,
        }
    }

    fn gated<'a>(&'a self, action: &'a RouteAction) -> &'a RouteAction {
        if (!self.tor_enabled
            && (matches!(action, RouteAction::Tor)
                || matches!(action, RouteAction::Outbound(id) if id.0 == "tor")))
            || (!self.i2p_enabled
                && (matches!(action, RouteAction::I2p)
                    || matches!(action, RouteAction::Outbound(id) if id.0 == "i2p")))
        {
            &self.block
        } else {
            action
        }
    }

    fn first_match<'a>(
        &'a self,
        candidates: &[usize],
        flow: &FlowContext,
        now_ms: Option<u64>,
    ) -> Option<&'a RouteAction> {
        candidates
            .iter()
            .filter_map(|index| self.rules.get(*index))
            .find(|rule| rule_matches(rule, flow, now_ms))
            .map(|rule| &rule.action)
    }
}

/// True when the flow must be held back by quarantine: it carries no attributable
/// package, names a package the user has not ruled on, or presents a signing digest
/// that does not match the one recorded for a known package.
fn is_quarantined(known: &HashMap<String, Option<[u8; 32]>>, flow: &FlowContext) -> bool {
    let mut packages = flow
        .packages
        .iter()
        .map(String::as_str)
        .chain(flow.package.as_deref().filter(|_| flow.packages.is_empty()))
        .peekable();
    if packages.peek().is_none() {
        return true;
    }
    // Any unknown package in a shared UID quarantines the whole flow: the core
    // cannot tell which package owns it, so it fails closed.
    packages.any(|package| match known.get(package) {
        None => true,
        Some(None) => false,
        Some(Some(expected)) => flow.signing_digest != Some(*expected),
    })
}

fn application_action(action: ApplicationRouteAction, vpn: &RouteAction) -> RouteAction {
    match action {
        ApplicationRouteAction::Vpn => vpn.clone(),
        ApplicationRouteAction::Direct => RouteAction::Direct,
        ApplicationRouteAction::Tor => RouteAction::Tor,
        ApplicationRouteAction::Block => RouteAction::Block,
    }
}

impl SuffixNode {
    fn insert(&mut self, suffix: &str, rule: usize) {
        let mut node = self;
        for label in suffix.split('.').rev() {
            node = node.children.entry(label.to_owned()).or_default();
        }
        node.rules.push(rule);
    }

    fn collect(&self, domain: &str, output: &mut Vec<usize>) {
        let mut node = self;
        let mut levels = Vec::new();
        for label in domain.split('.').rev() {
            let Some(next) = node.children.get(label) else {
                break;
            };
            node = next;
            levels.push(&node.rules);
        }
        for rules in levels.into_iter().rev() {
            output.extend_from_slice(rules);
        }
    }
}

fn rule_matches(rule: &RouteRule, flow: &FlowContext, now_ms: Option<u64>) -> bool {
    // A lapsed rule stops matching, so a temporary block ends without a reload.
    if let (Some(expires), Some(now)) = (rule.expires_at_ms, now_ms)
        && now >= expires
    {
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
    if !rule.cidrs.is_empty() {
        let Some(ip) = flow.destination.ip().or_else(|| {
            flow.domain_hint
                .is_none()
                .then(|| flow.destination.host.parse::<IpAddr>().ok())
                .flatten()
        }) else {
            return false;
        };
        if !rule.cidrs.iter().any(|network| network.contains(&ip)) {
            return false;
        }
    }
    true
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use foxcore_api::{
        ApplicationRouteConfig, Destination, IpTransport, KnownAppConfig, OutboundId, PortRange,
        RouteAction, RouteRule,
    };

    use super::*;

    #[test]
    fn shared_addresses_cannot_weaken_routes_by_response_order() {
        let protected = RouteRule {
            exact_domains: vec!["protected.invalid".into()],
            action: RouteAction::Tor,
            ..empty_rule(RouteAction::Direct)
        };
        let allowed = RouteRule {
            exact_domains: vec!["allowed.invalid".into()],
            action: RouteAction::Direct,
            ..empty_rule(RouteAction::Direct)
        };
        let blocked = RouteRule {
            exact_domains: vec!["blocked.invalid".into()],
            action: RouteAction::Block,
            ..empty_rule(RouteAction::Direct)
        };
        let table = RouteTable::compile(vec![allowed, protected, blocked], RouteAction::Direct);
        for names in [
            vec!["protected.invalid", "allowed.invalid"],
            vec!["allowed.invalid", "protected.invalid"],
        ] {
            let mut flow =
                FlowContext::new(1, IpTransport::Tcp, Destination::new("203.0.113.9", 443));
            assert!(table.constrain_with_dns_hints(
                &mut flow,
                &names.into_iter().map(str::to_owned).collect::<Vec<_>>()
            ));
            assert_eq!(table.decide(&flow), &RouteAction::Tor);
            assert!(table.constrain_with_dns_hints(
                &mut flow,
                &["allowed.invalid".into(), "blocked.invalid".into()]
            ));
            assert_eq!(table.decide(&flow), &RouteAction::Block);
        }
        let table = RouteTable::compile(
            vec![
                RouteRule {
                    exact_domains: vec!["allowed.invalid".into()],
                    action: RouteAction::Direct,
                    ..empty_rule(RouteAction::Direct)
                },
                RouteRule {
                    cidrs: vec!["203.0.113.0/24".parse().unwrap()],
                    action: RouteAction::Block,
                    ..empty_rule(RouteAction::Direct)
                },
            ],
            RouteAction::Direct,
        );
        let mut flow = FlowContext::new(1, IpTransport::Tcp, Destination::new("203.0.113.9", 443));
        assert!(table.constrain_with_dns_hints(&mut flow, &["allowed.invalid".into()]));
        assert_eq!(table.decide(&flow), &RouteAction::Block);
        // An explicit name retains the existing specificity-first exception contract.
        flow.domain_hint = Some("allowed.invalid".into());
        assert_eq!(table.decide(&flow), &RouteAction::Direct);
        assert!(table.constrain_with_dns_hints(&mut flow, &["allowed.invalid".into()]));
        assert_eq!(table.decide(&flow), &RouteAction::Block);
    }

    #[test]
    fn specificity_exceptions_report_shadowed_blocks_across_identity_and_expiry() {
        for exact in [false, true] {
            for uid_matches in [false, true] {
                for package_matches in [false, true] {
                    for expired in [false, true] {
                        for action in [RouteAction::Direct, RouteAction::Tor, RouteAction::Block] {
                            let mut exception = empty_rule(action.clone());
                            if exact {
                                exception.exact_domains = vec!["www.example.com".into()];
                            } else {
                                exception.domain_suffixes = vec!["example.com".into()];
                            }
                            exception.uid = Some(10001);
                            exception.package = Some("app".into());
                            exception.expires_at_ms = expired.then_some(1);
                            let mut block = empty_rule(RouteAction::Block);
                            block.cidrs = vec!["203.0.113.0/24".parse().unwrap()];
                            let table =
                                RouteTable::compile(vec![block, exception], RouteAction::Direct);
                            let mut flow = FlowContext::new(
                                1,
                                IpTransport::Tcp,
                                Destination::new("203.0.113.9", 443),
                            );
                            flow.domain_hint = Some("www.example.com".into());
                            flow.uid = Some(if uid_matches { 10001 } else { 10002 });
                            flow.packages =
                                vec![if package_matches { "app" } else { "other" }.into()];
                            let matches = uid_matches && package_matches && !expired;
                            let trace = table.explain(&flow);
                            assert_eq!(
                                trace.action,
                                if matches { action } else { RouteAction::Block }
                            );
                            assert_eq!(trace.route_rule_index, Some(if matches { 1 } else { 0 }));
                            assert_eq!(
                                trace.shadowed_block_rules,
                                if matches { vec![0] } else { Vec::new() }
                            );
                            assert!(trace.route_rule_applied);
                        }
                    }
                }
            }
        }
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

    #[test]
    fn exact_precedes_suffix_and_fallback() {
        let mut exact = empty_rule(RouteAction::Block);
        exact.exact_domains.push("api.example.com".into());
        let mut suffix = empty_rule(RouteAction::Tor);
        suffix.domain_suffixes.push("example.com".into());
        let mut fallback = empty_rule(RouteAction::Direct);
        fallback.ports.push(PortRange {
            start: 443,
            end: 443,
        });
        let table = RouteTable::compile(
            vec![exact, suffix, fallback],
            RouteAction::Outbound(OutboundId("default".into())),
        );
        let flow = FlowContext::new(
            1,
            IpTransport::Tcp,
            Destination::new("api.example.com", 443),
        );
        assert_eq!(table.decide(&flow), &RouteAction::Block);
    }

    #[test]
    fn most_specific_suffix_wins() {
        let mut broad = empty_rule(RouteAction::Direct);
        broad.domain_suffixes.push("example.com".into());
        let mut specific = empty_rule(RouteAction::Block);
        specific.domain_suffixes.push(".api.example.com.".into());
        let table = RouteTable::compile(
            vec![broad, specific],
            RouteAction::Outbound(OutboundId("default".into())),
        );
        let flow = FlowContext::new(
            1,
            IpTransport::Tcp,
            Destination::new("v1.api.example.com", 443),
        );
        assert_eq!(table.decide(&flow), &RouteAction::Block);
    }

    #[test]
    fn identity_rules_match_uid_and_any_shared_uid_package() {
        let mut identity = empty_rule(RouteAction::Block);
        identity.uid = Some(10_123);
        identity.package = Some("com.example.second".into());
        let table = RouteTable::compile(
            vec![identity],
            RouteAction::Outbound(OutboundId("default".into())),
        );
        let mut flow = FlowContext::new(
            1,
            IpTransport::Tcp,
            Destination::new("api.example.com", 443),
        );
        flow.uid = Some(10_123);
        flow.package = Some("com.example.first".into());
        flow.packages = vec!["com.example.first".into(), "com.example.second".into()];

        assert!(table.requires_identity());
        assert!(table.requires_uid());
        assert!(table.requires_package());
        assert_eq!(table.decide(&flow), &RouteAction::Block);
    }

    #[test]
    fn application_split_is_constant_time_and_shared_uid_conflicts_fail_closed() {
        let traffic = TrafficPolicyConfig {
            default_action: ApplicationRouteAction::Direct,
            applications: vec![
                ApplicationRouteConfig {
                    package: "com.example.vpn".into(),
                    action: ApplicationRouteAction::Vpn,
                    expires_at_ms: None,
                },
                ApplicationRouteConfig {
                    package: "com.example.blocked".into(),
                    action: ApplicationRouteAction::Block,
                    expires_at_ms: None,
                },
            ],
            tor_enabled: Some(false),
            i2p_enabled: Some(false),
            ..Default::default()
        };
        let table = RouteTable::compile_with_traffic(
            Vec::new(),
            RouteAction::Outbound(OutboundId("default".into())),
            traffic,
            false,
            false,
        );
        let mut flow = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
        flow.packages = vec!["com.example.vpn".into()];
        assert_eq!(
            table.decide(&flow),
            &RouteAction::Outbound(OutboundId("default".into()))
        );

        flow.packages = vec!["com.example.other".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Direct);

        flow.packages = vec!["com.example.blocked".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Block);

        flow.packages = vec!["com.example.vpn".into(), "com.example.shared".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Block);
    }

    #[test]
    fn expired_entries_stop_applying_without_a_reload() {
        const LONG_PAST: u64 = 1_000;
        let default = RouteAction::Outbound(OutboundId("default".into()));
        let temporary_block = |expires: u64| TrafficPolicyConfig {
            default_action: ApplicationRouteAction::Direct,
            applications: vec![ApplicationRouteConfig {
                package: "com.temp.blocked".into(),
                action: ApplicationRouteAction::Block,
                expires_at_ms: Some(expires),
            }],
            ..Default::default()
        };
        let mut flow = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
        flow.packages = vec!["com.temp.blocked".into()];

        let lapsed = RouteTable::compile_with_traffic(
            Vec::new(),
            default.clone(),
            temporary_block(LONG_PAST),
            true,
            true,
        );
        assert_eq!(
            lapsed.decide(&flow),
            &RouteAction::Direct,
            "a lapsed per-app block must not survive its deadline"
        );

        let still_armed = RouteTable::compile_with_traffic(
            Vec::new(),
            default.clone(),
            temporary_block(u64::MAX),
            true,
            true,
        );
        assert_eq!(still_armed.decide(&flow), &RouteAction::Block);

        // The same deadline applies to an expiring route rule.
        let mut expiring = empty_rule(RouteAction::Block);
        expiring.exact_domains.push("temp.example".into());
        expiring.expires_at_ms = Some(LONG_PAST);
        let table = RouteTable::compile_with_traffic(
            vec![expiring],
            default,
            TrafficPolicyConfig {
                default_action: ApplicationRouteAction::Direct,
                ..Default::default()
            },
            true,
            true,
        );
        let expired_flow =
            FlowContext::new(1, IpTransport::Tcp, Destination::new("temp.example", 443));
        assert_eq!(table.decide(&expired_flow), &RouteAction::Direct);
    }

    #[test]
    fn quarantine_holds_back_unknown_and_repackaged_apps() {
        // 64 hex chars, i.e. 32 bytes of 0xaa.
        let trusted_hex = "a".repeat(64);
        let trusted = [0xaa_u8; 32];
        let traffic = TrafficPolicyConfig {
            default_action: ApplicationRouteAction::Direct,
            quarantine_new_apps: true,
            known_apps: vec![
                KnownAppConfig {
                    package: "com.known.nodigest".into(),
                    signing_digest: None,
                    first_seen_at_ms: None,
                },
                KnownAppConfig {
                    package: "com.known.pinned".into(),
                    signing_digest: Some(trusted_hex),
                    first_seen_at_ms: None,
                },
            ],
            ..Default::default()
        };
        let table = RouteTable::compile_with_traffic(
            Vec::new(),
            RouteAction::Outbound(OutboundId("default".into())),
            traffic,
            true,
            true,
        );
        assert!(
            table.requires_package(),
            "quarantine must force per-flow attribution or it silently no-ops"
        );

        let mut flow = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));

        flow.packages = vec!["com.brand.new".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Block, "unknown app");

        flow.packages = vec!["com.known.nodigest".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Direct, "cleared app");

        flow.packages = vec!["com.known.pinned".into()];
        flow.signing_digest = Some(trusted);
        assert_eq!(table.decide(&flow), &RouteAction::Direct, "matching digest");

        flow.signing_digest = Some([0xbb_u8; 32]);
        assert_eq!(table.decide(&flow), &RouteAction::Block, "repackaged app");

        flow.signing_digest = None;
        assert_eq!(
            table.decide(&flow),
            &RouteAction::Block,
            "a pinned package that presents no digest cannot be verified"
        );

        flow.packages = Vec::new();
        flow.package = None;
        assert_eq!(
            table.decide(&flow),
            &RouteAction::Block,
            "unattributed flows are never cleared by quarantine"
        );
    }

    #[test]
    fn kill_switch_blocks_everything_including_allowed_apps_and_overlays() {
        let traffic = TrafficPolicyConfig {
            default_action: ApplicationRouteAction::Direct,
            applications: vec![ApplicationRouteConfig {
                package: "com.foxhole.map".into(),
                action: ApplicationRouteAction::Direct,
                expires_at_ms: None,
            }],
            tor_enabled: None,
            i2p_enabled: None,
            kill_switch: true,
            ..Default::default()
        };
        let table = RouteTable::compile_with_traffic(
            vec![empty_rule(RouteAction::Direct)],
            RouteAction::Outbound(OutboundId("default".into())),
            traffic,
            true,
            true,
        );
        assert!(table.kill_switch());

        let mut allowed_app =
            FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
        allowed_app.packages = vec!["com.foxhole.map".into()];
        assert_eq!(
            table.decide(&allowed_app),
            &RouteAction::Block,
            "an explicitly allowed application is still blocked"
        );

        // `.onion` is force-routed to Tor downstream, so the verdict itself must
        // already be Block or the overlay would escape the switch.
        let onion = FlowContext::new(1, IpTransport::Tcp, Destination::new("hidden.onion", 443));
        assert_eq!(table.decide(&onion), &RouteAction::Block);
    }

    #[test]
    fn explicit_block_rule_outranks_per_app_routes() {
        // final.txt §6: an explicit firewall BLOCK sits above Tor/VPN application
        // rules, and §14 requires the firewall to run before route selection. Until
        // that ordering existed, a package listed in traffic.applications silently
        // bypassed an explicit domain block.
        let mut blocked = empty_rule(RouteAction::Block);
        blocked.exact_domains.push("ads.example.com".into());
        let traffic = TrafficPolicyConfig {
            default_action: ApplicationRouteAction::Direct,
            applications: vec![ApplicationRouteConfig {
                package: "com.example.vpn".into(),
                action: ApplicationRouteAction::Vpn,
                expires_at_ms: None,
            }],
            tor_enabled: Some(false),
            i2p_enabled: Some(false),
            ..Default::default()
        };
        let table = RouteTable::compile_with_traffic(
            vec![blocked],
            RouteAction::Outbound(OutboundId("default".into())),
            traffic,
            false,
            false,
        );

        let mut blocked_flow = FlowContext::new(
            1,
            IpTransport::Tcp,
            Destination::new("ads.example.com", 443),
        );
        blocked_flow.packages = vec!["com.example.vpn".into()];
        assert_eq!(
            table.decide(&blocked_flow),
            &RouteAction::Block,
            "an explicit domain block must not be bypassed by a per-app vpn route"
        );

        // Anything the firewall does not block still follows the per-app decision.
        let mut allowed_flow = FlowContext::new(
            1,
            IpTransport::Tcp,
            Destination::new("cdn.example.com", 443),
        );
        allowed_flow.packages = vec!["com.example.vpn".into()];
        assert_eq!(
            table.decide(&allowed_flow),
            &RouteAction::Outbound(OutboundId("default".into()))
        );
    }

    #[test]
    fn firewall_default_block_allows_only_explicit_application_exceptions() {
        let traffic = TrafficPolicyConfig {
            default_action: ApplicationRouteAction::Block,
            applications: vec![ApplicationRouteConfig {
                package: "com.foxhole.map".into(),
                action: ApplicationRouteAction::Direct,
                expires_at_ms: None,
            }],
            tor_enabled: None,
            i2p_enabled: None,
            ..Default::default()
        };
        let table = RouteTable::compile_with_traffic(
            vec![empty_rule(RouteAction::Direct)],
            RouteAction::Outbound(OutboundId("default".into())),
            traffic,
            false,
            false,
        );
        let mut flow = FlowContext::new(1, IpTransport::Tcp, Destination::new("example.com", 443));
        flow.packages = vec!["com.example.blocked-by-default".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Block);

        flow.packages = vec!["com.foxhole.map".into()];
        assert_eq!(table.decide(&flow), &RouteAction::Direct);
    }
}
