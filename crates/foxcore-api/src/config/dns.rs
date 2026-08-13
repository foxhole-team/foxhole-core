use super::*;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    #[default]
    RealIp,
    FakeIp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsRoute {
    Direct,
    #[default]
    Primary,
    Tor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DnsUpstream {
    Udp {
        address: String,
    },
    Tcp {
        address: String,
    },
    Dot {
        host: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_ip: Option<IpAddr>,
        #[serde(default)]
        insecure: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pinned_spki_sha256: Option<String>,
    },
    Doh {
        url: SecretString,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_ip: Option<IpAddr>,
        #[serde(default)]
        insecure: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pinned_spki_sha256: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise: Option<String>,
    /// Kept for schema-v1 compatibility. New configurations should use `upstreams`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(default)]
    pub mode: DnsMode,
    #[serde(default)]
    pub upstreams: Vec<DnsUpstream>,
    #[serde(default)]
    pub route: DnsRoute,
    #[serde(default = "default_dns_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_true")]
    pub negative_cache: bool,
    #[serde(default = "default_true")]
    pub stale_on_error: bool,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_dns_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_fake_ipv4_pool")]
    pub fake_ipv4_pool: Ipv4Net,
    #[serde(default = "default_fake_ipv6_pool")]
    pub fake_ipv6_pool: Ipv6Net,
    #[serde(default = "default_fake_ttl_s")]
    pub fake_ttl_s: u32,
    /// Names answered with NXDOMAIN before the cache and before any upstream, so a
    /// blocked lookup never leaves the device. Bounded separately from route rules;
    /// the JSON envelope caps still apply, so very large lists need an out-of-band
    /// loader rather than an inline config.
    #[serde(default, skip_serializing_if = "DnsBlocklistConfig::is_empty")]
    pub blocklist: DnsBlocklistConfig,
    /// Signed compact rule sets supplied through the native bootstrap/update
    /// API. The JSON carries only the trust policy; artifact bytes never travel
    /// through a profile or the 1 MiB configuration envelope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_sets: Vec<DnsRuleSetConfig>,
}

/// Trust policy for one externally supplied DNS rule set.
///
/// `public_key` is a pinned P-256 verification key encoded with standard
/// base64. It is configuration, not bundle data: accepting a key alongside an
/// update would let an attacker sign their own manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRuleSetConfig {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub minimum_sequence: u64,
    /// When true, startup/reload fails unless a compatible verified artifact is
    /// already installed. Optional sources may be absent, but a supplied
    /// malformed update is still rejected rather than ignored.
    #[serde(default = "default_true")]
    pub required: bool,
}

impl DnsRuleSetConfig {
    pub fn decoded_public_key(&self) -> Result<Vec<u8>, ConfigError> {
        let decoded = STANDARD.decode(&self.public_key).map_err(|_| {
            ConfigError::Invalid("dns.rule_sets public_key is not valid base64".into())
        })?;
        if decoded.is_empty() || decoded.len() > MAX_DNS_RULE_SET_PUBLIC_KEY_BYTES {
            return Err(ConfigError::Invalid(
                "dns.rule_sets public_key must decode to 1..=4096 bytes".into(),
            ));
        }
        Ok(decoded)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty()
            || self.name.len() > MAX_DNS_RULE_SET_NAME_BYTES
            || !self.name.is_ascii()
            || self
                .name
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ConfigError::Invalid(
                "dns.rule_sets name must be bounded non-whitespace ASCII".into(),
            ));
        }
        self.decoded_public_key()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsBlocklistConfig {
    /// Blocks only this exact name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact: Vec<String>,
    /// Blocks this name and every label beneath it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suffixes: Vec<String>,
    /// The same matching, but the verdict says which rule set refused. The app's
    /// security journal records that, and the UI groups by it; without a
    /// category a refusal can only say "blocked", which is the least useful
    /// thing it could say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<DnsBlocklistCategoryConfig>,
    /// Exact names that bypass every inline or out-of-band block list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_exact: Vec<String>,
    /// These names and all labels beneath them bypass every block list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_suffixes: Vec<String>,
    /// Applications whose attributed DNS questions bypass filtering. A shared
    /// UID is bypassed only when every attributed package is listed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass_packages: Vec<String>,
}

/// Which rule set a blocked name came from.
///
/// A closed set. It leaves the core in the DNS verdict and in the audit event
/// stream, and the app's own security journal persists it from there — so the
/// names are part of a contract with something outside this workspace, not an
/// internal enum that can be renamed at will.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsCategory {
    Malicious,
    Telemetry,
    Trackers,
    Ads,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsBlocklistCategoryConfig {
    pub category: DnsCategory,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suffixes: Vec<String>,
}

impl DnsBlocklistConfig {
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffixes.is_empty()
            && self.allow_exact.is_empty()
            && self.allow_suffixes.is_empty()
            && self.bypass_packages.is_empty()
            && self
                .categories
                .iter()
                .all(|group| group.exact.is_empty() && group.suffixes.is_empty())
    }

    /// Every name in the list, categorised or not. Used by both the bound check
    /// and the per-name validation, so a categorised entry cannot slip past
    /// either of them.
    fn names(&self) -> impl Iterator<Item = &String> {
        self.exact
            .iter()
            .chain(self.suffixes.iter())
            .chain(self.allow_exact.iter())
            .chain(self.allow_suffixes.iter())
            .chain(
                self.categories
                    .iter()
                    .flat_map(|group| group.exact.iter().chain(group.suffixes.iter())),
            )
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.names().count() > MAX_DNS_BLOCKLIST_ENTRIES {
            return Err(ConfigError::Invalid(
                "dns.blocklist must contain at most 65536 entries".into(),
            ));
        }
        let mut seen = HashSet::with_capacity(self.categories.len());
        for group in &self.categories {
            if !seen.insert(group.category) {
                return Err(ConfigError::Invalid(
                    "dns.blocklist.categories must not repeat a category".into(),
                ));
            }
        }
        if self.bypass_packages.len() > MAX_ROUTE_RULES {
            return Err(ConfigError::Invalid(
                "dns.blocklist bypass_packages must contain at most 4096 entries".into(),
            ));
        }
        let mut packages = HashSet::with_capacity(self.bypass_packages.len());
        for package in &self.bypass_packages {
            validate_package(package)?;
            if !packages.insert(package) {
                return Err(ConfigError::Invalid(
                    "dns.blocklist bypass_packages must not repeat a package".into(),
                ));
            }
        }
        for name in self.names() {
            let trimmed = name.trim_matches('.');
            if trimmed.is_empty()
                || trimmed.len() > 255
                || !trimmed.is_ascii()
                || trimmed
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            {
                return Err(ConfigError::Invalid(
                    "dns.blocklist entries must be bounded ASCII DNS names".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            advertise: None,
            upstream: None,
            mode: DnsMode::RealIp,
            upstreams: Vec::new(),
            route: DnsRoute::default(),
            cache_size: default_dns_cache_size(),
            negative_cache: true,
            stale_on_error: true,
            timeout_ms: default_dns_timeout_ms(),
            max_response_bytes: default_dns_max_response_bytes(),
            fake_ipv4_pool: default_fake_ipv4_pool(),
            fake_ipv6_pool: default_fake_ipv6_pool(),
            fake_ttl_s: default_fake_ttl_s(),
            blocklist: DnsBlocklistConfig::default(),
            rule_sets: Vec::new(),
        }
    }
}

impl DnsConfig {
    /// Whether this configuration produces a DNS interceptor at all.
    ///
    /// Without one, queries pass through untouched — which means the blocklist,
    /// the `.onion`/`.i2p` gates and fake-IP do nothing. The data plane decides
    /// the same question, so the predicate lives here and both sides call it:
    /// when the two drifted, a config carrying only a blocklist validated
    /// cleanly and then resolved every blocked name (found on device).
    pub fn intercepts(&self) -> bool {
        !self.upstreams.is_empty()
            || self.upstream.is_some()
            || self.advertise.is_some()
            || self.mode == DnsMode::FakeIp
    }

    /// Whether this resolver invented `address` rather than learning it.
    ///
    /// A synthetic address means something on the way out has to turn it back
    /// into the name it stands for. Only the userspace stack can: it terminates
    /// the flow and dials by name. Asked by the data plane about a flow that is
    /// about to leave as an IP packet, a `true` here means the packet would go
    /// to a destination nothing routes.
    ///
    /// The pools are checked rather than the reverse mapping on purpose — a
    /// mapping that expired while a flow was open leaves the address just as
    /// unroutable, and reading the table would call it clearnet.
    pub fn synthesizes(&self, address: IpAddr) -> bool {
        if self.mode != DnsMode::FakeIp {
            return false;
        }
        match address {
            IpAddr::V4(address) => self.fake_ipv4_pool.contains(&address),
            IpAddr::V6(address) => self.fake_ipv6_pool.contains(&address),
        }
    }

    /// The address this document told the platform to send DNS to.
    ///
    /// `None` when nothing was advertised, in which case nothing here can claim
    /// a flow: the resolver the device uses is one the core never named.
    /// Parsed rather than stored because `validate` has already refused
    /// anything that is not an address, so a failure here cannot reach a
    /// running engine.
    pub fn advertised_resolver(&self) -> Option<IpAddr> {
        self.advertise
            .as_deref()
            .and_then(|value| value.parse::<IpAddr>().ok())
    }

    /// Whether a flow to `address:port` is *this* resolver being asked the same
    /// question over a transport the interceptor does not terminate.
    ///
    /// The interceptor is gated on `destination.port == 53`, and that is a
    /// statement about a transport rather than about a question. Android in the
    /// opportunistic Private DNS mode — **the default**, shown as "Automatic" —
    /// probes DoT on 853 against the resolver addresses the link advertises,
    /// which through a VPN means the address in `dns.advertise`. A probe that
    /// succeeds moves *every* subsequent query onto 853, and from then on the
    /// blocklist, the rule sets, the `.onion`/`.i2p` gates and fake-IP see
    /// nothing at all: proven on device with one variable changed, blocklist
    /// off at `opportunistic` and on at `off`.
    ///
    /// Deliberately narrow. Only the advertised address counts — DoT to a
    /// server the core never named is ordinary traffic and stays ordinary — and
    /// only when the document advertises one at all, because an address the
    /// core did not hand the platform is not this resolver.
    pub fn bypasses_interceptor(&self, address: IpAddr, port: u16) -> bool {
        port == DNS_ENCRYPTED_PORT
            && self
                .advertised_resolver()
                .is_some_and(|resolver| resolver == address)
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        self.blocklist.validate()?;
        if self.rule_sets.len() > MAX_DNS_RULE_SETS {
            return Err(ConfigError::Invalid(
                "dns.rule_sets must contain at most 16 entries".into(),
            ));
        }
        let mut rule_set_names = HashSet::with_capacity(self.rule_sets.len());
        for rule_set in &self.rule_sets {
            rule_set.validate()?;
            if !rule_set_names.insert(rule_set.name.as_str()) {
                return Err(ConfigError::Invalid(
                    "dns.rule_sets must not repeat a name".into(),
                ));
            }
        }
        // Fail-closed on a contradiction rather than fail-open on the wire. A
        // blocklist with nothing to intercept has no way to answer the names it
        // does *not* block either, so this is a config mistake, not a mode.
        let filters = !self.blocklist.is_empty() || !self.rule_sets.is_empty();
        if filters && !self.intercepts() {
            return Err(ConfigError::Invalid(
                "DNS filtering requires an interceptor: set dns.upstreams, dns.advertise or dns.mode='fake_ip'"
                    .into(),
            ));
        }
        // And having an interceptor is not the same as being asked. A document
        // that configures filtering has to declare itself the resolver, or the
        // filtering is decoration.
        //
        // `dns.advertise` is the only field in this document that reaches the
        // platform: it is the address the app hands `VpnService.Builder`, and
        // without it Android keeps the resolver it already had. A config with
        // `mode='real_ip'`, a blocklist and a full set of upstreams then
        // validates cleanly, starts cleanly, and filters only the queries that
        // happen to arrive as plain DNS through the tunnel — while the resolver
        // the device actually uses answers everything else, unfiltered and
        // outside. Nothing in the core is wrong in that state, which is exactly
        // why it survives review: every component does its job and the feature
        // is off.
        //
        // `fake_ip` is exempt because it cannot reach that state quietly. In
        // that mode the interceptor is the source of the addresses the flows
        // will carry — they exist in no zone and on no other resolver — so a
        // device answered by something else does not get quietly-unfiltered
        // results, it gets ordinary routable ones, and the fake-IP path visibly
        // never engages.
        //
        // Deliberately checked against `advertise` rather than against
        // `intercepts()`: upstreams alone are what make this look configured.
        if filters && self.mode != DnsMode::FakeIp && self.advertise.is_none() {
            return Err(ConfigError::Invalid(
                "DNS filtering with dns.mode='real_ip' requires dns.advertise: without an \
                 advertised resolver address the device keeps resolving outside the tunnel and \
                 the blocklist and rule sets only see what happens to pass through"
                    .into(),
            ));
        }
        if let Some(advertise) = &self.advertise {
            advertise
                .parse::<IpAddr>()
                .map_err(|_| ConfigError::Invalid("dns.advertise must be an IP address".into()))?;
        }
        if !(1..=65_536).contains(&self.cache_size) {
            return Err(ConfigError::Invalid(
                "dns.cache_size must be in 1..=65536".into(),
            ));
        }
        if !(100..=30_000).contains(&self.timeout_ms) {
            return Err(ConfigError::Invalid(
                "dns.timeout_ms must be in 100..=30000".into(),
            ));
        }
        if !(512..=65_535).contains(&self.max_response_bytes) {
            return Err(ConfigError::Invalid(
                "dns.max_response_bytes must be in 512..=65535".into(),
            ));
        }
        if !(30..=86_400).contains(&self.fake_ttl_s) {
            return Err(ConfigError::Invalid(
                "dns.fake_ttl_s must be in 30..=86400".into(),
            ));
        }
        if fake_ipv4_capacity(self.fake_ipv4_pool) < self.cache_size as u128
            || fake_ipv6_capacity(self.fake_ipv6_pool) < self.cache_size as u128
        {
            return Err(ConfigError::Invalid(
                "DNS fake-IP pools must each contain at least dns.cache_size usable addresses"
                    .into(),
            ));
        }
        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::Invalid(
                "dns.upstream and dns.upstreams are mutually exclusive".into(),
            ));
        }
        if self.upstreams.len() > 8 {
            return Err(ConfigError::Invalid(
                "dns.upstreams must contain at most 8 entries".into(),
            ));
        }
        if let Some(upstream) = &self.upstream
            && upstream.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "dns.upstream must not be empty".into(),
            ));
        }
        for upstream in &self.upstreams {
            upstream.validate()?;
        }
        Ok(())
    }
}

impl DnsUpstream {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Udp { address } | Self::Tcp { address } => {
                if address.trim().is_empty()
                    || address.len() > 255
                    || address.chars().any(char::is_control)
                {
                    return Err(ConfigError::Invalid(
                        "DNS upstream address is invalid".into(),
                    ));
                }
            }
            Self::Dot {
                host,
                port,
                pinned_spki_sha256,
                ..
            } => {
                validate_server(host, *port)?;
                if let Some(pin) = pinned_spki_sha256 {
                    validate_spki_pin(pin)?;
                }
            }
            Self::Doh {
                url,
                pinned_spki_sha256,
                ..
            } => {
                if url.expose().len() > 4096 {
                    return Err(ConfigError::Invalid(
                        "DNS DoH URL exceeds 4096 bytes".into(),
                    ));
                }
                let parsed = url::Url::parse(url.expose())
                    .map_err(|_| ConfigError::Invalid("DNS DoH URL is not a valid URL".into()))?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || parsed.username() != ""
                    || parsed.password().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(ConfigError::Invalid(
                        "DNS DoH URL must be an HTTPS URL without userinfo or fragment".into(),
                    ));
                }
                if let Some(pin) = pinned_spki_sha256 {
                    validate_spki_pin(pin)?;
                }
            }
        }
        Ok(())
    }
}

fn default_dns_cache_size() -> usize {
    4096
}

fn default_dns_timeout_ms() -> u64 {
    5_000
}

fn default_dns_max_response_bytes() -> usize {
    65_535
}

fn default_fake_ipv4_pool() -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15)
}

fn default_fake_ipv6_pool() -> Ipv6Net {
    Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 18)
}

pub(super) fn fake_ipv4_capacity(pool: Ipv4Net) -> u128 {
    let addresses = 1_u128 << (u32::BITS - u32::from(pool.prefix_len()));
    addresses.saturating_sub(2)
}

pub(super) fn fake_ipv6_capacity(pool: Ipv6Net) -> u128 {
    let host_bits = u128::BITS - u32::from(pool.prefix_len());
    if host_bits == u128::BITS {
        u128::MAX
    } else {
        (1_u128 << host_bits).saturating_sub(1)
    }
}

fn default_fake_ttl_s() -> u32 {
    300
}
