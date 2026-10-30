use super::*;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use foxcore_api::{DnsConfig, DnsRuleSetConfig, EventSink};
use foxcore_dns::DnsCache;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_route::ruleset::{
    RuleSetArtifact, RuleSetBundle, RuleSetVerificationPolicy, TrustedRuleSetBundle,
    VerifiedRuleSet, parse_trusted_categorized_rule_set, parse_trusted_embedded_rule_set,
    verify_rule_set,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::FlowMetrics;
use crate::dns::DnsProxy;

/// Only this typed source denotes an expected-revision CAS failure.
#[derive(Debug)]
pub struct PolicyRevisionConflict {
    pub expected: u64,
    pub current: u64,
}
impl std::fmt::Display for PolicyRevisionConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "policy revision mismatch: expected {}, current {}",
            self.expected, self.current
        )
    }
}
impl std::error::Error for PolicyRevisionConflict {}

/// A rejected DNS update that nevertheless armed the independent emergency gate.
#[derive(Debug)]
pub struct PolicyEmergencyBlock {
    pub revision: u64,
    cause: io::Error,
}
impl std::fmt::Display for PolicyEmergencyBlock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; emergency kill switch applied at revision {}",
            self.cause, self.revision
        )
    }
}
impl std::error::Error for PolicyEmergencyBlock {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl FlowPolicyStore {
    pub fn new(
        generation: u64,
        routes: RouteTable,
        dns_config: DnsConfig,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
        metrics: Arc<FlowMetrics>,
        events: EventSink,
    ) -> io::Result<Self> {
        Self::new_with_rule_sets(
            generation,
            routes,
            dns_config,
            outbounds,
            direct,
            metrics,
            events,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_rule_sets(
        generation: u64,
        routes: RouteTable,
        dns_config: DnsConfig,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
        metrics: Arc<FlowMetrics>,
        events: EventSink,
        bundles: Vec<RuleSetBundle>,
    ) -> io::Result<Self> {
        Self::new_with_trusted_rule_sets(
            generation,
            routes,
            dns_config,
            outbounds,
            direct,
            metrics,
            events,
            bundles,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_trusted_rule_sets(
        generation: u64,
        routes: RouteTable,
        dns_config: DnsConfig,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
        metrics: Arc<FlowMetrics>,
        events: EventSink,
        bundles: Vec<RuleSetBundle>,
        trusted_bundles: Vec<TrustedRuleSetBundle>,
    ) -> io::Result<Self> {
        Self::new_with_trusted_rule_sets_and_dns_continuation(
            generation,
            routes,
            dns_config,
            outbounds,
            direct,
            metrics,
            events,
            bundles,
            trusted_bundles,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_trusted_rule_sets_and_dns_continuation(
        generation: u64,
        routes: RouteTable,
        dns_config: DnsConfig,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
        metrics: Arc<FlowMetrics>,
        events: EventSink,
        bundles: Vec<RuleSetBundle>,
        trusted_bundles: Vec<TrustedRuleSetBundle>,
        dns_continuation: Option<Arc<DnsCache>>,
    ) -> io::Result<Self> {
        let rule_sets = verify_initial_rule_sets(&dns_config, bundles)?;
        let trusted_rule_sets = parse_initial_trusted_rule_sets(&dns_config, trusted_bundles)?;
        let artifacts = active_rule_set_artifacts(&dns_config, &rule_sets, &trusted_rule_sets)?;
        let dns = Arc::new(match dns_continuation {
            Some(previous) => previous.fork_for_policy(dns_config.cache_size),
            None => DnsCache::new(dns_config.cache_size),
        });
        let dns_proxy = DnsProxy::new_with_gates_and_rule_sets(
            generation,
            dns_config.clone(),
            dns.clone(),
            outbounds.clone(),
            direct.clone(),
            routes.tor_enabled(),
            routes.i2p_enabled(),
            metrics.clone(),
            events.clone(),
            artifacts,
        );
        Ok(Self {
            generation,
            outbounds,
            direct,
            metrics,
            events,
            current: ArcSwap::from_pointee(FlowPolicySnapshot {
                revision: 1,
                routes,
                dns_config,
                dns,
                dns_proxy,
                revocation: CancellationToken::new(),
            }),
            reload: Mutex::new(PolicyMutable {
                rule_sets,
                trusted_rule_sets,
            }),
        })
    }

    /// The latest DNS state only. The runtime's clean-stop capability gates access.
    pub fn dns_for_continuation(&self) -> Arc<DnsCache> {
        self.current.load().dns.clone()
    }

    pub fn reload(
        &self,
        expected_revision: Option<u64>,
        routes: RouteTable,
        dns_config: DnsConfig,
    ) -> io::Result<u64> {
        let mutable = self
            .reload
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.current.load_full();
        if expected_revision.is_some_and(|expected| expected != current.revision) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                PolicyRevisionConflict {
                    expected: expected_revision.unwrap_or_default(),
                    current: current.revision,
                },
            ));
        }
        let artifacts = match active_rule_set_artifacts(
            &dns_config,
            &mutable.rule_sets,
            &mutable.trusted_rule_sets,
        ) {
            Ok(artifacts) => artifacts,
            Err(error) => {
                if routes.kill_switch() && !current.routes.kill_switch() {
                    let revision = current.revision.saturating_add(1);
                    self.current.store(Arc::new(FlowPolicySnapshot {
                        revision,
                        routes: current.routes.with_emergency_block(),
                        dns_config: current.dns_config.clone(),
                        dns: current.dns.clone(),
                        dns_proxy: current.dns_proxy.clone(),
                        revocation: CancellationToken::new(),
                    }));
                    current.revocation.cancel();
                    if let Some(proxy) = &current.dns_proxy {
                        // The emergency snapshot retains the admitted DNS policy,
                        // not its idle sockets or late-response cache epoch.
                        proxy.network_changed();
                    }
                    return Err(io::Error::new(
                        error.kind(),
                        PolicyEmergencyBlock {
                            revision,
                            cause: error,
                        },
                    ));
                }
                return Err(error);
            }
        };
        let revision = current.revision.saturating_add(1);
        let dns = Arc::new(current.dns.fork_for_policy(dns_config.cache_size));
        let dns_proxy = DnsProxy::new_with_gates_and_rule_sets(
            self.generation,
            dns_config.clone(),
            dns.clone(),
            self.outbounds.clone(),
            self.direct.clone(),
            routes.tor_enabled(),
            routes.i2p_enabled(),
            self.metrics.clone(),
            self.events.clone(),
            artifacts,
        );
        let kill_switch = routes.kill_switch();
        let revocation = if kill_switch {
            CancellationToken::new()
        } else {
            // Retained flows from every ordinary reload share one cancellation epoch.
            current.revocation.clone()
        };
        self.current.store(Arc::new(FlowPolicySnapshot {
            revision,
            routes,
            dns_config,
            dns,
            dns_proxy,
            revocation,
        }));
        // After the swap, so no flow can slip in under the old snapshot between
        // the revoke and the new policy becoming visible.
        if kill_switch {
            current.revocation.cancel();
            if let Some(proxy) = &current.dns_proxy {
                proxy.network_changed();
            }
        }
        Ok(revision)
    }

    /// Verifies and atomically activates a rule-set update against the trust
    /// policy of the current DNS snapshot. A rejected candidate cannot replace
    /// the last verified artifact or alter the active resolver.
    pub fn install_dns_rule_set(&self, bundle: RuleSetBundle) -> io::Result<u64> {
        let mut mutable = self
            .reload
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.current.load_full();
        let configured = current
            .dns_config
            .rule_sets
            .iter()
            .find(|source| source.name == bundle.name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS rule-set update has no pinned trust policy",
                )
            })?;
        let previous = mutable.rule_sets.get(&bundle.name);
        let minimum_sequence = previous
            .map(|rule_set| rule_set.metadata().sequence)
            .unwrap_or(configured.minimum_sequence)
            .max(configured.minimum_sequence);
        let verified = verify_bundle(configured, bundle, minimum_sequence)?;
        if let Some(previous) = previous
            && verified.metadata().sequence == previous.metadata().sequence
        {
            if verified.metadata().artifact_sha256 == previous.metadata().artifact_sha256
                && verified.metadata().public_key_sha256 == previous.metadata().public_key_sha256
                && verified.metadata().categorized_manifest_sha256
                    == previous.metadata().categorized_manifest_sha256
            {
                return Ok(current.revision);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS rule-set sequence was reused for different bytes",
            ));
        }

        let mut candidate = mutable.rule_sets.clone();
        candidate.insert(configured.name.clone(), verified);
        let artifacts =
            active_rule_set_artifacts(&current.dns_config, &candidate, &mutable.trusted_rule_sets)?;
        let revision = current.revision.saturating_add(1);
        let dns_proxy = DnsProxy::new_with_gates_and_rule_sets(
            self.generation,
            current.dns_config.clone(),
            current.dns.clone(),
            self.outbounds.clone(),
            self.direct.clone(),
            current.routes.tor_enabled(),
            current.routes.i2p_enabled(),
            self.metrics.clone(),
            self.events.clone(),
            artifacts,
        );
        self.current.store(Arc::new(FlowPolicySnapshot {
            revision,
            routes: current.routes.clone(),
            dns_config: current.dns_config.clone(),
            dns: current.dns.clone(),
            dns_proxy,
            // A rule-set update changes which *names* resolve, never which
            // flows are allowed, so nothing live is revoked by it.
            revocation: current.revocation.clone(),
        }));
        mutable.rule_sets = candidate;
        Ok(revision)
    }

    pub fn revision(&self) -> u64 {
        self.current.load().revision
    }

    /// The device moved to a different network.
    ///
    /// Not a reload: the policy is the same and its revision does not change.
    /// What changes is that every live stream is bound to an interface that no
    /// longer carries it, and every answer in the cache came from a resolver
    /// that may no longer be authoritative for this link. The old policy token
    /// is therefore revoked after an identical snapshot with a fresh token is
    /// installed: existing flows close and applications reconnect through the
    /// new Android Network, while new flows never observe a cancelled token.
    ///
    /// What is **not** dropped is the fake-IP pool. Applications are holding
    /// those addresses; invalidating them makes nothing more correct and breaks
    /// every live connection that resolved through it, leaving the next packet
    /// with a destination the tunnel cannot map. Neither is the IP→name map
    /// domain rules are matched through. See [`DnsCache::flush_responses`].
    pub fn network_changed(&self) {
        self.network_changed_transaction(|| {});
    }

    pub(super) fn network_changed_transaction(&self, before_publish: impl FnOnce()) {
        let _mutable = self
            .reload
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.current.load();
        before_publish();
        match &current.dns_proxy {
            // The interceptor also drops its idle upstream connections, which
            // are sockets on the interface that went away.
            Some(proxy) => proxy.network_changed(),
            // Nothing fills the response cache without an interceptor, but the
            // flush is unconditional so the guarantee does not depend on which
            // DNS mode the profile happens to be in.
            None => {
                current.dns.flush_responses();
            }
        }
        self.current.store(Arc::new(FlowPolicySnapshot {
            revision: current.revision,
            routes: current.routes.clone(),
            dns_config: current.dns_config.clone(),
            dns: current.dns.clone(),
            dns_proxy: current.dns_proxy.clone(),
            revocation: CancellationToken::new(),
        }));
        // After the swap, for the same reason as a kill-switch reload: a flow
        // entering concurrently either belongs to the old network and is
        // revoked, or belongs to the new snapshot and remains usable.
        current.revocation.cancel();
    }

    /// The routing gates as they are right now.
    ///
    /// For control-plane consumers — the LAN ingress in particular — that must
    /// read the live policy per session rather than a snapshot taken when they
    /// started. A gate cached at start would leave a listener carrying traffic
    /// after the kill switch stopped the device's own flows.
    pub fn gates(&self) -> PolicyGates {
        self.gates_and_revocation().0
    }

    /// The admission gates and cancellation epoch from the same snapshot.
    pub fn gates_and_revocation(&self) -> (PolicyGates, CancellationToken) {
        let current = self.current.load();
        (
            PolicyGates {
                kill_switch: current.routes.kill_switch(),
                tor_enabled: current.routes.tor_enabled(),
                i2p_enabled: current.routes.i2p_enabled(),
            },
            current.revocation.clone(),
        )
    }
}

/// A read of the live routing gates. Copied out rather than borrowed so a
/// caller cannot hold the policy snapshot alive across an await.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyGates {
    kill_switch: bool,
    tor_enabled: bool,
    i2p_enabled: bool,
}

impl PolicyGates {
    pub fn kill_switch(self) -> bool {
        self.kill_switch
    }

    pub fn tor_enabled(self) -> bool {
        self.tor_enabled
    }

    pub fn i2p_enabled(self) -> bool {
        self.i2p_enabled
    }
}

fn verify_initial_rule_sets(
    config: &DnsConfig,
    bundles: Vec<RuleSetBundle>,
) -> io::Result<HashMap<String, VerifiedRuleSet>> {
    let mut installed = HashMap::with_capacity(bundles.len());
    let mut names = HashSet::with_capacity(bundles.len());
    for bundle in bundles {
        if !names.insert(bundle.name.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS rule-set bootstrap contains a duplicate name",
            ));
        }
        let configured = config
            .rule_sets
            .iter()
            .find(|source| source.name == bundle.name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS rule-set bootstrap has no pinned trust policy",
                )
            })?;
        let verified = verify_bundle(configured, bundle, configured.minimum_sequence)?;
        installed.insert(configured.name.clone(), verified);
    }
    Ok(installed)
}

fn parse_initial_trusted_rule_sets(
    config: &DnsConfig,
    bundles: Vec<TrustedRuleSetBundle>,
) -> io::Result<HashMap<String, RuleSetArtifact>> {
    let mut installed = HashMap::with_capacity(bundles.len());
    for bundle in bundles {
        let (name, artifact) = bundle.into_parts();
        if installed.contains_key(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted DNS rule-set bootstrap contains a duplicate name",
            ));
        }
        let configured = config
            .rule_sets
            .iter()
            .find(|source| source.name == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted DNS rule-set bootstrap has no pinned update policy",
                )
            })?;
        let parsed = if configured.enabled_categories.is_some() {
            parse_trusted_categorized_rule_set(&name, &artifact)
        } else if name.starts_with("foxhole-dns-categories-") {
            Err(foxcore_route::ruleset::RuleSetError::UnsupportedManifest)
        } else {
            parse_trusted_embedded_rule_set(&artifact)
        }
        .and_then(|parsed| parsed.select_categories(configured.enabled_categories.as_deref()))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("trusted DNS rule-set is invalid: {error}"),
            )
        })?;
        installed.insert(name, parsed);
    }
    Ok(installed)
}

fn verify_bundle(
    configured: &DnsRuleSetConfig,
    bundle: RuleSetBundle,
    minimum_sequence: u64,
) -> io::Result<VerifiedRuleSet> {
    let public_key = configured
        .decoded_public_key()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let now_unix_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
        .as_secs();
    verify_rule_set(
        &bundle.manifest,
        &bundle.signature,
        &public_key,
        &bundle.artifact,
        RuleSetVerificationPolicy::new(&configured.name, minimum_sequence, now_unix_s),
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DNS rule-set verification failed: {error}"),
        )
    })
}

fn active_rule_set_artifacts(
    config: &DnsConfig,
    installed: &HashMap<String, VerifiedRuleSet>,
    trusted: &HashMap<String, RuleSetArtifact>,
) -> io::Result<Vec<RuleSetArtifact>> {
    let mut artifacts = Vec::with_capacity(config.rule_sets.len());
    for configured in &config.rule_sets {
        if let Some(rule_set) = installed.get(&configured.name)
            && rule_set.metadata().categorized_manifest_sha256.is_some()
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| io::Error::other("system clock is before the Unix epoch"))?
                .as_secs();
            validate_categorized_freshness(rule_set.metadata(), now)?;
        }
        let public_key = configured
            .decoded_public_key()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let expected_key: [u8; 32] = Sha256::digest(&public_key).into();
        let compatible = installed.get(&configured.name).filter(|rule_set| {
            let metadata = rule_set.metadata();
            metadata.name == configured.name
                && metadata.sequence >= configured.minimum_sequence
                && metadata.public_key_sha256 == expected_key
        });
        match (compatible, trusted.get(&configured.name)) {
            (Some(rule_set), _) => artifacts.push(
                rule_set
                    .artifact()
                    .select_categories(configured.enabled_categories.as_deref())
                    .map_err(category_selection_error)?,
            ),
            (None, Some(rule_set)) => artifacts.push(
                rule_set
                    .select_categories(configured.enabled_categories.as_deref())
                    .map_err(category_selection_error)?,
            ),
            (None, None) if configured.required => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "required DNS rule set '{}' is not installed or is incompatible",
                        configured.name
                    ),
                ));
            }
            (None, None) => {}
        }
    }
    Ok(artifacts)
}

fn validate_categorized_freshness(
    metadata: &foxcore_route::ruleset::VerifiedRuleSetMetadata,
    now: u64,
) -> io::Result<()> {
    if metadata.categorized_manifest_sha256.is_some()
        && (now >= metadata.expires_at_unix || metadata.generated_at_unix > now.saturating_add(600))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "categorized DNS rule set is no longer fresh",
        ));
    }
    Ok(())
}

fn category_selection_error(error: foxcore_route::ruleset::RuleSetError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("DNS category selection is incompatible: {error}"),
    )
}

#[cfg(test)]
mod category_freshness_tests {
    use super::*;

    #[test]
    fn reload_rechecks_categorized_expiry_without_inventing_embedded_freshness() {
        let mut metadata = foxcore_route::ruleset::VerifiedRuleSetMetadata {
            name: "foxhole-dns-categories-normal-medium".into(),
            sequence: 1,
            generated_at_unix: 1000,
            expires_at_unix: 2000,
            source_commit: "2".repeat(40),
            block_entries: 1,
            allow_entries: 0,
            artifact_sha256: [0; 32],
            public_key_sha256: [0; 32],
            categorized_manifest_sha256: Some([0; 32]),
        };
        assert!(validate_categorized_freshness(&metadata, 1500).is_ok());
        assert!(validate_categorized_freshness(&metadata, 2000).is_err());
        assert!(validate_categorized_freshness(&metadata, 399).is_err());
        metadata.categorized_manifest_sha256 = None;
        assert!(validate_categorized_freshness(&metadata, 2000).is_ok());
    }
}
