use super::*;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::RouteRule;

/// Reloadable policy surface. Outbound sessions and the TUN remain owned by
/// the running generation while route and DNS snapshots are replaced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Optional compare-and-swap guard for concurrent control-plane writers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    #[serde(default)]
    pub traffic: TrafficPolicyConfig,
}

/// User-facing application decision compiled into an O(1) package table.
/// `Vpn` always means the immutable primary/default outbound of this runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationRouteAction {
    #[default]
    Vpn,
    Direct,
    Tor,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRouteConfig {
    pub package: String,
    pub action: ApplicationRouteAction,
    /// Wall-clock deadline in milliseconds since the epoch. Once it passes the
    /// entry stops applying, so a temporary per-app block lapses on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
}

/// Unified policy used by VPN, Tor, split-tunnel and firewall UI modes.
///
/// Missing network toggles preserve legacy behavior (`auto`): the private
/// network is available when its outbound is registered. `Some(false)` is an
/// explicit fail-closed kill switch suitable for the main-screen buttons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficPolicyConfig {
    #[serde(default)]
    pub default_action: ApplicationRouteAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<ApplicationRouteConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tor_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2p_enabled: Option<bool>,
    /// Global fail-closed switch. While it is set nothing leaves the device —
    /// including explicitly allowed applications, `.onion`/`.i2p` auto-routes and
    /// the locally answered ICMP echo. Reloadable without rebuilding the TUN.
    #[serde(default)]
    pub kill_switch: bool,
    /// Block any application that is not in `known_apps` until the user decides
    /// (final.txt §15). Enabling this forces per-flow identity resolution.
    #[serde(default)]
    pub quarantine_new_apps: bool,
    /// Applications the user has already ruled on. The control plane fills this
    /// from `PACKAGE_ADDED`; the data plane never enumerates packages itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_apps: Vec<KnownAppConfig>,
    /// Which self-repairs the core is still allowed to perform silently.
    #[serde(default)]
    pub continuity: ContinuityConfig,
}

/// How much the core is allowed to heal on its own.
///
/// Every flag defaults to `true`, which is the behaviour the core has always
/// had. Turning one off never selects a weaker route — it stops the core at the
/// point where it would have healed itself, holds the affected traffic blocked,
/// and raises [`crate::CoreEvent::ConfirmationRequired`]. The app then either
/// confirms, which costs a full reconnect, or stops the engine. There is no
/// third outcome in which packets keep moving by some other path; that is the
/// whole point of turning a flag off.
///
/// **A hold never resolves into "there is no tunnel".** Not when it is
/// confirmed, not when it is answered late, and not when nobody answers at all:
/// the only ways out are a confirmation, which reconnects, and the user
/// stopping the engine, which they did on purpose. There is no third, and there
/// is no longer a setting that adds one.
///
/// There used to be: `confirmation_timeout_action`, whose
/// `stop_engine_leaving_network_open` value ended a hold by tearing the tunnel
/// down. The defence was that the name admitted the cost. That defence protects
/// the wrong person — the one who reads the name is not the one who is left on
/// the open network — and an invariant that holds only while nobody picks the
/// other value is a default, not an invariant. The field is gone, and because
/// this struct is `deny_unknown_fields`, a config that still names it is
/// **rejected** rather than quietly ignored.
///
/// This lives in the reloadable policy because it is a main-screen preference:
/// changing it must not rebuild the TUN. Changing a flag never itself triggers
/// an interruption — it only decides what happens at the *next* one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityConfig {
    /// Re-establish a dead proxy session underneath live flows.
    #[serde(default = "default_true")]
    pub seamless_reconnect: bool,
    /// Move a flow to the next selector member when the active one fails.
    /// Independent of `seamless_reconnect`: failing over to a different server
    /// is a different decision from redialling the same one.
    #[serde(default = "default_true")]
    pub seamless_failover: bool,
    /// Survive a default-network change (Wi-Fi to mobile and back) without
    /// asking. Off means every network change is an explicit reconnect.
    #[serde(default = "default_true")]
    pub seamless_network_switch: bool,
    /// Keep the direct lane alive when the VPN outbound fails.
    ///
    /// This is the failure half of split tunnelling, not the routing half:
    /// per-app `direct` rules still exist either way. With it on, a VPN failure
    /// suspends only VPN-routed applications and `direct` ones keep working
    /// through the protected dialer. With it off, a VPN failure suspends the
    /// whole device until the user confirms — stricter, and the reason someone
    /// would turn it off is precisely to not have clearnet traffic continue at
    /// the moment the tunnel dies.
    #[serde(default = "default_true")]
    pub split_tunnel_on_vpn_failure: bool,
    /// Milliseconds after which an unanswered confirmation stops counting as
    /// fresh. `0` — the default — means it never does and the hold simply
    /// waits.
    ///
    /// **This is a reminder, not an action.** Nothing about the traffic changes
    /// when it elapses: the lanes stay held, the tunnel stays up, and the same
    /// token still confirms. What it does is publish
    /// [`crate::CoreEvent::ConfirmationExpired`] once and set the polled
    /// `expired` flag, so a screen can say the pause has been going on since
    /// the morning instead of showing a question that looks new.
    ///
    /// It kept the name it had when it also chose what happened next, because
    /// the name is in the frozen v1 config corpus and an app that sets it is
    /// setting the same thing it always set — the deadline. What is gone is the
    /// second field that decided what the deadline *did*.
    #[serde(default = "default_confirmation_timeout_ms")]
    pub confirmation_timeout_ms: u64,
}

impl Default for ContinuityConfig {
    fn default() -> Self {
        Self {
            seamless_reconnect: true,
            seamless_failover: true,
            seamless_network_switch: true,
            split_tunnel_on_vpn_failure: true,
            confirmation_timeout_ms: default_confirmation_timeout_ms(),
        }
    }
}

impl ContinuityConfig {
    /// Whether any repair now needs a user decision. Cheap enough for the
    /// runtime to consult per interruption instead of caching a derived flag.
    pub fn requires_confirmation(&self) -> bool {
        !self.seamless_reconnect
            || !self.seamless_failover
            || !self.seamless_network_switch
            || !self.split_tunnel_on_vpn_failure
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.confirmation_timeout_ms != 0
            && !(1_000..=3_600_000).contains(&self.confirmation_timeout_ms)
        {
            return Err(ConfigError::Invalid(
                "traffic.continuity.confirmation_timeout_ms must be 0 or in 1000..=3600000".into(),
            ));
        }
        Ok(())
    }
}

fn default_confirmation_timeout_ms() -> u64 {
    // No deadline at all.
    //
    // This was two minutes, and the argument for it was that "the traffic is
    // blocked either way, so the choice is only between a stopped engine and a
    // waiting one". That is false on Android, which is the platform this core
    // ships on. A stopped engine closes the tun descriptor it owns; the
    // platform takes the interface down behind it; and a device with no tunnel
    // interface is a device on the open network. So the two-minute default did
    // not choose between two blocked states — it chose the moment at which a
    // fail-closed hold turned into clearnet, without asking and without a word;
    // that transition was reproduced in device acceptance.
    //
    // The default that cannot do this is no deadline. A phone whose user has
    // not answered yet is a phone that is still protected, for as long as that
    // takes; the cost is that the engine keeps its descriptors while it waits,
    // which is the same cost as any other blocked state.
    //
    // The setting that let a deadline stop the engine is gone entirely, so an
    // app that sets one now is asking to be *told* the pause has gone stale,
    // and nothing more. Which makes zero a weaker default than it used to be —
    // it no longer guards against anything, it just means "do not remind me".
    0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownAppConfig {
    pub package: String,
    /// Hex SHA-256 of the signing certificate. When present the flow must present
    /// the same digest, so a repackaged app under a known package name fails
    /// closed. Omit it to match on the package name alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_digest: Option<String>,
    /// Informational: when the control plane first saw this identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_at_ms: Option<u64>,
}

impl Default for TrafficPolicyConfig {
    fn default() -> Self {
        Self {
            default_action: ApplicationRouteAction::Vpn,
            applications: Vec::new(),
            tor_enabled: None,
            i2p_enabled: None,
            kill_switch: false,
            quarantine_new_apps: false,
            known_apps: Vec::new(),
            continuity: ContinuityConfig::default(),
        }
    }
}

impl TrafficPolicyConfig {
    pub fn requires_identity(&self) -> bool {
        // Quarantine judges every flow by its package, so it needs attribution
        // exactly like an explicit per-app entry does.
        !self.applications.is_empty() || self.quarantine_new_apps
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if self.applications.len() > MAX_ROUTE_RULES {
            return Err(ConfigError::Invalid(
                "traffic.applications must contain at most 4096 entries".into(),
            ));
        }
        if self.known_apps.len() > MAX_ROUTE_RULES {
            return Err(ConfigError::Invalid(
                "traffic.known_apps must contain at most 4096 entries".into(),
            ));
        }
        let mut known = HashSet::with_capacity(self.known_apps.len());
        for app in &self.known_apps {
            validate_package(&app.package)?;
            if !known.insert(app.package.as_str()) {
                return Err(ConfigError::Invalid(
                    "traffic.known_apps must not repeat a package".into(),
                ));
            }
            if let Some(digest) = &app.signing_digest
                && decode_signing_digest(digest).is_none()
            {
                return Err(ConfigError::Invalid(
                    "traffic.known_apps signing_digest must be 64 hexadecimal characters".into(),
                ));
            }
        }
        let mut packages = HashSet::with_capacity(self.applications.len());
        for application in &self.applications {
            validate_package(&application.package)?;
            if !packages.insert(application.package.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate traffic application package '{}'",
                    application.package
                )));
            }
        }
        self.continuity.validate()?;
        if self.tor_enabled == Some(false)
            && (self.default_action == ApplicationRouteAction::Tor
                || self
                    .applications
                    .iter()
                    .any(|application| application.action == ApplicationRouteAction::Tor))
        {
            return Err(ConfigError::Invalid(
                "traffic Tor actions require traffic.tor_enabled to be true or auto".into(),
            ));
        }
        Ok(())
    }

    pub fn uses_tor(&self) -> bool {
        self.default_action == ApplicationRouteAction::Tor
            || self
                .applications
                .iter()
                .any(|application| application.action == ApplicationRouteAction::Tor)
    }
}

impl PolicyConfig {
    pub fn parse(json: &str) -> Result<Self, ConfigError> {
        if json.len() > MAX_POLICY_CONFIG_BYTES {
            return Err(ConfigError::Invalid(
                "policy config exceeds 262144 bytes".into(),
            ));
        }
        let config: Self = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.dns.validate()?;
        self.traffic.validate()?;
        validate_route_count(
            self.routes
                .len()
                .saturating_add(self.traffic.applications.len()),
        )?;
        for rule in &self.routes {
            validate_route_rule(rule)?;
        }
        if self.traffic.tor_enabled == Some(false)
            && (self.dns.route == DnsRoute::Tor
                || self.routes.iter().any(|rule| action_uses_tor(&rule.action)))
        {
            return Err(ConfigError::Invalid(
                "Tor routes require traffic.tor_enabled to be true or auto".into(),
            ));
        }
        if self.traffic.i2p_enabled == Some(false)
            && self.routes.iter().any(|rule| action_uses_i2p(&rule.action))
        {
            return Err(ConfigError::Invalid(
                "I2P routes require traffic.i2p_enabled to be true or auto".into(),
            ));
        }
        Ok(())
    }
}
