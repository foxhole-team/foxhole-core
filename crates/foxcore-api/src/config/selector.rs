use super::*;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Upper bound on selector members. A real subscription is tens of nodes, not
/// thousands; members are built lazily, but the id table is still bounded so a
/// hostile config cannot make config validation itself expensive.
const MAX_SELECTOR_MEMBERS: usize = 64;
/// Default ceiling for one member attempt during failover. Without a bound a
/// single black-holed node would stall every flow instead of yielding to the
/// next member, which is the whole point of the group.
pub(super) const DEFAULT_SELECTOR_MEMBER_TIMEOUT_MS: u64 = 5_000;
const MAX_SELECTOR_MEMBER_TIMEOUT_MS: u64 = 120_000;

/// A group of interchangeable proxy outbounds with one active member.
///
/// This is not an optional convenience. The Android app wraps every imported
/// profile in a selector tagged `proxy` and points `route.final` at it, so a
/// core without this type cannot start a single real profile.
///
/// Members are owned inline rather than referenced by top-level id: a member is
/// an implementation detail of the group, not an independently routable
/// outbound, and inlining is what lets the group build members lazily instead
/// of handshaking every node in a subscription at startup.
///
/// Only stream proxies may join. `direct`, Tor, I2P and WireGuard are refused,
/// because failover across those boundaries would silently change the privacy
/// class of the traffic — a proxied flow dropping to the open network, or a
/// `.onion` flow leaving through a clearnet node. A selector may not contain a
/// selector, so the group is always one level deep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorConfig {
    /// Members in preference order. Failover walks this order starting from the
    /// active member.
    pub members: Vec<NamedOutboundConfig>,
    /// Member active at start. Defaults to the first member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<crate::OutboundId>,
    /// Ceiling for one member attempt (construction plus connect) before
    /// failover moves on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_timeout_ms: Option<u64>,
    /// Active latency probing. Absent means the group only fails over, which is
    /// a different promise: failover finds a member that is *alive*, probing
    /// finds the one that is *fastest*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<UrlTestConfig>,
}

/// Periodic latency probe that picks the fastest member.
///
/// Enabling it trades away the group's lazy construction: a node cannot be
/// measured without connecting to it, so every member is built on the first
/// round. That is the cost of the feature, not an oversight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlTestConfig {
    /// Probe target. Plain `http://` only — see `validate`.
    pub url: String,
    #[serde(default = "default_urltest_interval_ms")]
    pub interval_ms: u64,
    /// How much faster a challenger must be before the active member is
    /// replaced. Without it two nodes a millisecond apart would swap on every
    /// round, and every swap is a reconnect for the flows that follow.
    #[serde(default = "default_urltest_tolerance_ms")]
    pub tolerance_ms: u64,
}

const MIN_URLTEST_INTERVAL_MS: u64 = 5_000;
const MAX_URLTEST_INTERVAL_MS: u64 = 3_600_000;
const MAX_URLTEST_TOLERANCE_MS: u64 = 10_000;

fn default_urltest_interval_ms() -> u64 {
    180_000
}

fn default_urltest_tolerance_ms() -> u64 {
    50
}

impl UrlTestConfig {
    /// Splits the probe URL into the pieces the prober needs.
    ///
    /// Returned rather than stored so the parsed form cannot drift from the
    /// string the profile carries.
    pub fn target(&self) -> Result<(String, u16, String), ConfigError> {
        let url = url::Url::parse(&self.url)
            .map_err(|_| ConfigError::Invalid("selector probe url is not a URL".into()))?;
        // HTTPS would mean terminating TLS inside the probe, which is a second
        // TLS surface for a health check. Refused rather than silently probed
        // over plaintext, which would measure a different thing than it claims.
        if url.scheme() != "http" {
            return Err(ConfigError::Invalid(
                "selector probe url must be plain http://".into(),
            ));
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| ConfigError::Invalid("selector probe url has no host".into()))?
            .to_owned();
        let port = url.port().unwrap_or(80);
        let mut path = url.path().to_owned();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok((host, port, path))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.target()?;
        if !(MIN_URLTEST_INTERVAL_MS..=MAX_URLTEST_INTERVAL_MS).contains(&self.interval_ms) {
            return Err(ConfigError::Invalid(format!(
                "selector probe interval_ms must be {MIN_URLTEST_INTERVAL_MS}..={MAX_URLTEST_INTERVAL_MS}"
            )));
        }
        if self.tolerance_ms > MAX_URLTEST_TOLERANCE_MS {
            return Err(ConfigError::Invalid(format!(
                "selector probe tolerance_ms must be at most {MAX_URLTEST_TOLERANCE_MS}"
            )));
        }
        Ok(())
    }
}

impl SelectorConfig {
    pub fn member_timeout_ms(&self) -> u64 {
        self.member_timeout_ms
            .unwrap_or(DEFAULT_SELECTOR_MEMBER_TIMEOUT_MS)
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if self.members.is_empty() {
            return Err(ConfigError::Invalid(
                "selector must contain at least one member".into(),
            ));
        }
        if self.members.len() > MAX_SELECTOR_MEMBERS {
            return Err(ConfigError::Invalid(format!(
                "selector must contain at most {MAX_SELECTOR_MEMBERS} members"
            )));
        }
        if let Some(timeout) = self.member_timeout_ms
            && !(1..=MAX_SELECTOR_MEMBER_TIMEOUT_MS).contains(&timeout)
        {
            return Err(ConfigError::Invalid(format!(
                "selector member_timeout_ms must be 1..={MAX_SELECTOR_MEMBER_TIMEOUT_MS}"
            )));
        }
        let mut ids = HashSet::with_capacity(self.members.len());
        for member in &self.members {
            validate_outbound_id(&member.id.0)?;
            if !ids.insert(member.id.0.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate selector member id '{}'",
                    member.id.0
                )));
            }
            if matches!(
                member.id.0.as_str(),
                "default" | "primary" | "direct" | "block" | "tor" | "i2p"
            ) {
                return Err(ConfigError::Invalid(format!(
                    "selector member id '{}' is reserved",
                    member.id.0
                )));
            }
            match &member.outbound {
                OutboundConfig::Selector(_) => {
                    return Err(ConfigError::Invalid(
                        "selector members must not be selectors".into(),
                    ));
                }
                // Refusing these is a privacy boundary, not tidiness: failover
                // must never move a flow between anonymity networks or out to
                // the open network.
                OutboundConfig::Tor(_) | OutboundConfig::I2p(_) => {
                    return Err(ConfigError::Invalid(
                        "selector members must not be Tor or I2P outbounds".into(),
                    ));
                }
                OutboundConfig::Wireguard(_) => {
                    return Err(ConfigError::Invalid(
                        "selector members must not be WireGuard: a packet tunnel has no stream semantics"
                            .into(),
                    ));
                }
                other => other.validate()?,
            }
        }
        if let Some(default) = &self.default
            && !ids.contains(default.0.as_str())
        {
            return Err(ConfigError::Invalid(format!(
                "selector default '{}' is not a member",
                default.0
            )));
        }
        if let Some(probe) = &self.probe {
            probe.validate()?;
        }
        Ok(())
    }
}
