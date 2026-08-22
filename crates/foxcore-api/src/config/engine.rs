use super::*;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{RouteAction, RouteRule};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub schema_version: u32,
    /// Schema-v1 primary outbound. It is always addressable as `default`
    /// (and by the legacy alias `primary`) from route actions.
    pub outbound: OutboundConfig,
    /// Additional named outbounds used by `RouteAction::Outbound`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<NamedOutboundConfig>,
    pub tun: TunConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub routes: Vec<RouteRule>,
    /// Reloadable per-application routing policy. The Android TUN remains up;
    /// only the immutable decision snapshot changes.
    #[serde(default)]
    pub traffic: TrafficPolicyConfig,
}

impl EngineConfig {
    pub fn parse(json: &str) -> Result<Self, ConfigError> {
        if json.len() > MAX_ENGINE_CONFIG_BYTES {
            return Err(ConfigError::Invalid(
                "engine config exceeds 1048576 bytes".into(),
            ));
        }
        let config: Self = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::Schema {
                actual: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        if self.tun.mtu < 1280 {
            return Err(ConfigError::Invalid(format!(
                "TUN MTU {} is below the IPv6 minimum 1280",
                self.tun.mtu
            )));
        }
        self.tun
            .ipv4
            .parse::<Ipv4Addr>()
            .map_err(|_| ConfigError::Invalid("tun.ipv4 is not an IPv4 address".into()))?;
        if let Some(ipv6) = &self.tun.ipv6 {
            ipv6.parse::<Ipv6Addr>()
                .map_err(|_| ConfigError::Invalid("tun.ipv6 is not an IPv6 address".into()))?;
        }
        self.dns.validate()?;
        self.traffic.validate()?;
        self.outbound.validate()?;
        if matches!(self.outbound, OutboundConfig::Direct(_)) != self.runtime.local_guard {
            return Err(ConfigError::Invalid(
                "a direct primary requires runtime.local_guard=true, and local_guard requires a direct primary"
                    .into(),
            ));
        }
        if self.outbounds.len() > 16 {
            return Err(ConfigError::Invalid(
                "outbounds must contain at most 16 entries".into(),
            ));
        }
        let mut outbound_ids = HashSet::with_capacity(self.outbounds.len());
        for named in &self.outbounds {
            validate_outbound_id(&named.id.0)?;
            if !outbound_ids.insert(named.id.0.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate outbound id '{}'",
                    named.id.0
                )));
            }
            if matches!(
                named.id.0.as_str(),
                "default" | "primary" | "direct" | "block"
            ) {
                return Err(ConfigError::Invalid(format!(
                    "outbound id '{}' is reserved",
                    named.id.0
                )));
            }
            if named.id.0 == "tor" && !matches!(named.outbound, OutboundConfig::Tor(_)) {
                return Err(ConfigError::Invalid(
                    "outbound id 'tor' must contain a Tor outbound".into(),
                ));
            }
            if named.id.0 != "tor" && matches!(named.outbound, OutboundConfig::Tor(_)) {
                return Err(ConfigError::Invalid(
                    "a named Tor outbound must use the canonical id 'tor'".into(),
                ));
            }
            if named.id.0 == "i2p" && !matches!(named.outbound, OutboundConfig::I2p(_)) {
                return Err(ConfigError::Invalid(
                    "outbound id 'i2p' must contain an I2P outbound".into(),
                ));
            }
            if named.id.0 != "i2p" && matches!(named.outbound, OutboundConfig::I2p(_)) {
                return Err(ConfigError::Invalid(
                    "a named I2P outbound must use the canonical id 'i2p'".into(),
                ));
            }
            if matches!(named.outbound, OutboundConfig::Direct(_)) {
                return Err(ConfigError::Invalid(
                    "a direct outbound cannot be registered under a named route".into(),
                ));
            }
            named.outbound.validate()?;
        }
        let has_tor_route = matches!(self.outbound, OutboundConfig::Tor(_))
            || self.outbounds.iter().any(|named| named.id.0 == "tor");
        let has_i2p_route = matches!(self.outbound, OutboundConfig::I2p(_))
            || self.outbounds.iter().any(|named| named.id.0 == "i2p");
        validate_route_count(
            self.routes
                .len()
                .saturating_add(self.traffic.applications.len()),
        )?;
        for rule in &self.routes {
            validate_route_rule(rule)?;
            if let RouteAction::Outbound(id) = &rule.action
                && id.0 != "default"
                && id.0 != "primary"
                && !outbound_ids.contains(id.0.as_str())
            {
                return Err(ConfigError::Invalid(format!(
                    "route references unknown outbound id '{}'",
                    id.0
                )));
            }
            if matches!(rule.action, RouteAction::Tor) && !has_tor_route {
                return Err(ConfigError::Invalid(
                    "route action 'tor' requires a primary Tor outbound or named outbound 'tor'"
                        .into(),
                ));
            }
            if matches!(rule.action, RouteAction::I2p) && !has_i2p_route {
                return Err(ConfigError::Invalid(
                    "route action 'i2p' requires a primary I2P outbound or named outbound 'i2p'"
                        .into(),
                ));
            }
        }
        if self.dns.route == DnsRoute::Tor && !has_tor_route {
            return Err(ConfigError::Invalid(
                "dns.route='tor' requires a primary Tor outbound or named outbound 'tor'".into(),
            ));
        }
        if self.traffic.tor_enabled == Some(true) && !has_tor_route {
            return Err(ConfigError::Invalid(
                "traffic.tor_enabled=true requires a registered Tor outbound".into(),
            ));
        }
        if self.traffic.i2p_enabled == Some(true) && !has_i2p_route {
            return Err(ConfigError::Invalid(
                "traffic.i2p_enabled=true requires a registered I2P outbound".into(),
            ));
        }
        if self.traffic.uses_tor() && !has_tor_route {
            return Err(ConfigError::Invalid(
                "traffic Tor actions require a registered Tor outbound".into(),
            ));
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
        // A fake address is a promise that something will restore the name from
        // it before the flow leaves the device. A proxy outbound keeps that
        // promise: the userspace stack terminates the flow and re-dials it by
        // name. An L3 packet tunnel has no stack in the path at all — the packet
        // is translated, sealed and handed to the peer with the destination the
        // application wrote — so the synthetic address goes on the wire and
        // nothing routes it. Every counter stays clean while it happens, which
        // is why device acceptance was needed to expose it.
        //
        // Overlay names are not the problem and must not read as the problem:
        // `.onion`/`.i2p` flows are sent to the stack before routing is
        // consulted, so their fake addresses never reach the packet path. What
        // cannot work is a *clearnet* name answered with a fake address on a
        // profile whose primary outbound carries flows at L3.
        if self.outbound.is_packet_tunnel() && self.dns.mode == DnsMode::FakeIp {
            return Err(ConfigError::Invalid(format!(
                "dns.mode='fake_ip' and an L3 packet tunnel as the primary outbound cannot \
                 both be used: a clearnet name is answered from {} and the packet path seals \
                 that address as the destination, which no WireGuard/AmneziaWG peer can \
                 route — the tunnel comes up, reports no errors and carries nothing. Use \
                 dns.mode='real_ip' with this profile, or a proxy outbound, which restores \
                 the name before dialling",
                self.dns.fake_ipv4_pool
            )));
        }
        // The other thing the DNS block can ask of a primary that is not a
        // stream outbound, and the quieter of the two.
        //
        // `dns.route` defaults to `primary`, so a document that merely sets
        // `dns.upstreams` — the ordinary way to configure a resolver — asks for
        // it without naming it. On an L3 profile the registry's default is a
        // clearnet placeholder that dials on a protected socket beside the
        // tunnel, so every intercepted lookup left in the open: the names, and
        // with them the browsing the tunnel exists to hide, while the tunnel
        // itself reported a healthy session. The interceptor now refuses this at
        // query time, but a profile that cannot resolve must not start at all
        // rather than start and fail every lookup.
        //
        // `dns.route='direct'` stays allowed: it is the same socket, but a
        // document that names it has chosen it.
        if self.outbound.is_packet_tunnel()
            && self.dns.intercepts()
            && self.dns.route == DnsRoute::Primary
        {
            return Err(ConfigError::Invalid(
                "dns.route='primary' and an L3 packet tunnel as the primary outbound cannot \
                 both be used: the tunnel carries IP packets and offers no stream outbound to \
                 resolve through, so intercepted lookups would leave beside it in the clear. \
                 Set dns.route='direct' if resolving outside the tunnel is intended, or use a \
                 proxy outbound"
                    .into(),
            ));
        }
        // Reached only with `real_ip`, because the rule above already refused
        // fake-IP here. Saying it in one step matters: the overlay rules below
        // would otherwise answer "set fake_ip", and setting it lands on the
        // refusal above with no hint that the two demands are incompatible.
        if self.outbound.is_packet_tunnel()
            && ((has_tor_route && self.traffic.tor_enabled != Some(false))
                || (has_i2p_route && self.traffic.i2p_enabled != Some(false)))
        {
            return Err(ConfigError::Invalid(
                "overlay routing and an L3 packet tunnel as the primary outbound cannot share \
                 a profile: .onion/.i2p names require dns.mode='fake_ip' to stay inside the \
                 core, and fake addresses cannot be sealed into a packet tunnel. Run the \
                 overlay on a profile whose primary outbound is a proxy"
                    .into(),
            ));
        }
        // Without fake-IP the DNS gateway may not even be constructed (it needs an
        // upstream, an advertise address or fake-IP), and then `.onion` lookups leave
        // as ordinary port-53 traffic to a clearnet resolver.
        if has_tor_route
            && self.traffic.tor_enabled != Some(false)
            && self.dns.mode != DnsMode::FakeIp
        {
            return Err(ConfigError::Invalid(
                "Tor routing requires dns.mode='fake_ip' so .onion names stay inside the core"
                    .into(),
            ));
        }
        if has_i2p_route
            && self.traffic.i2p_enabled != Some(false)
            && self.dns.mode != DnsMode::FakeIp
        {
            return Err(ConfigError::Invalid(
                "I2P routing requires dns.mode='fake_ip' so .i2p names stay inside the core".into(),
            ));
        }
        self.runtime.validate()?;
        Ok(())
    }
}
