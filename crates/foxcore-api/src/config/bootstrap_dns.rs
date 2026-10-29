use super::{ConfigError, DnsUpstream, OutboundConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapDnsConfig {
    pub domains: Vec<String>,
    pub upstreams: Vec<DnsUpstream>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_candidates")]
    pub max_candidates: usize,
}

fn default_timeout() -> u64 {
    3000
}
fn default_candidates() -> usize {
    8
}

pub fn canonical_bootstrap_domain(value: &str) -> Option<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 || !value.is_ascii() || value.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label
                .as_bytes()
                .first()
                .is_none_or(|byte| !byte.is_ascii_alphanumeric())
            || label
                .as_bytes()
                .last()
                .is_none_or(|byte| !byte.is_ascii_alphanumeric())
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

impl BootstrapDnsConfig {
    pub fn matches(&self, host: &str) -> bool {
        let Some(host) = canonical_bootstrap_domain(host) else {
            return false;
        };
        self.domains
            .iter()
            .any(|domain| canonical_bootstrap_domain(domain).as_ref() == Some(&host))
    }

    pub(super) fn validate<'a>(
        &self,
        outbounds: impl IntoIterator<Item = &'a OutboundConfig>,
    ) -> Result<(), ConfigError> {
        if !(1..=32).contains(&self.domains.len())
            || !(1..=4).contains(&self.upstreams.len())
            || !(500..=10_000).contains(&self.timeout_ms)
            || !(1..=8).contains(&self.max_candidates)
        {
            return invalid("bootstrap DNS limits are invalid");
        }
        let mut domains = HashSet::new();
        for domain in &self.domains {
            let canonical = canonical_bootstrap_domain(domain).ok_or_else(|| {
                ConfigError::Invalid("bootstrap DNS requires exact ASCII hostnames".into())
            })?;
            if !domains.insert(canonical) {
                return invalid("bootstrap DNS domains are duplicated");
            }
        }
        let mut endpoints = Vec::new();
        for outbound in outbounds {
            collect_endpoints(outbound, &mut endpoints);
        }
        for domain in domains {
            let matching: Vec<_> = endpoints
                .iter()
                .filter(|(host, _)| canonical_bootstrap_domain(host).as_ref() == Some(&domain))
                .collect();
            if matching.is_empty() || matching.iter().any(|(_, address)| address.is_some()) {
                return invalid("bootstrap DNS domain must name an outbound without server_ip");
            }
        }
        for upstream in &self.upstreams {
            upstream.validate()?;
            match upstream {
                DnsUpstream::Udp { address } | DnsUpstream::Tcp { address } => {
                    if address.contains('%') {
                        return invalid("bootstrap DNS scoped endpoints are refused");
                    }
                    let endpoint = address.parse::<SocketAddr>().map_err(|_| {
                        ConfigError::Invalid(
                            "bootstrap DNS endpoint must be a literal IP and explicit port".into(),
                        )
                    })?;
                    if endpoint.port() == 0
                        || invalid_ip(endpoint.ip())
                        || matches!(endpoint, SocketAddr::V6(address) if address.scope_id() != 0)
                    {
                        return invalid("bootstrap DNS endpoint is invalid");
                    }
                }
                DnsUpstream::Dot {
                    host,
                    server_ip,
                    insecure,
                    ..
                }
                | DnsUpstream::Doq {
                    host,
                    server_ip,
                    insecure,
                    ..
                } => {
                    if *insecure
                        || server_ip.is_none_or(invalid_ip)
                        || (host.parse::<IpAddr>().is_err()
                            && canonical_bootstrap_domain(host).is_none())
                    {
                        return invalid(
                            "bootstrap DoT requires a verified TLS identity and literal server_ip",
                        );
                    }
                }
                DnsUpstream::Doh {
                    url,
                    server_ip,
                    insecure,
                    ..
                }
                | DnsUpstream::Doh3 {
                    url,
                    server_ip,
                    insecure,
                    ..
                } => {
                    let parsed = url::Url::parse(url.expose())
                        .map_err(|_| ConfigError::Invalid("invalid bootstrap DoH URL".into()))?;
                    let host = parsed
                        .host_str()
                        .unwrap_or_default()
                        .trim_matches(['[', ']']);
                    if *insecure
                        || server_ip.is_none_or(invalid_ip)
                        || parsed.query().is_some()
                        || parsed.port() == Some(0)
                        || (host.parse::<IpAddr>().is_err()
                            && canonical_bootstrap_domain(host).is_none())
                    {
                        return invalid(
                            "bootstrap DoH requires a verified TLS identity, literal server_ip and no query",
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

fn invalid_ip(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(address) if address.is_broadcast())
}
fn invalid<T>(message: &str) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(message.into()))
}

fn collect_endpoints<'a>(
    outbound: &'a OutboundConfig,
    endpoints: &mut Vec<(&'a str, Option<IpAddr>)>,
) {
    let endpoint = match outbound {
        OutboundConfig::Vless(value) => (&value.server, value.server_ip),
        OutboundConfig::Vmess(value) => (&value.server, value.server_ip),
        OutboundConfig::Hysteria2(value) => (&value.server, value.server_ip),
        OutboundConfig::Tuic(value) => (&value.server, value.server_ip),
        OutboundConfig::Trojan(value) => (&value.server, value.server_ip),
        OutboundConfig::Shadowsocks(value) => (&value.server, value.server_ip),
        OutboundConfig::Wireguard(value) => (&value.server, value.server_ip),
        OutboundConfig::Socks(value) => (&value.server, value.server_ip),
        OutboundConfig::Http(value) => (&value.server, value.server_ip),
        OutboundConfig::Naive(value) => (&value.server, value.server_ip),
        OutboundConfig::AnyTls(value) => (&value.server, value.server_ip),
        OutboundConfig::ShadowTls(value) => (&value.server, value.server_ip),
        OutboundConfig::Selector(value) => {
            for member in &value.members {
                collect_endpoints(&member.outbound, endpoints);
            }
            return;
        }
        OutboundConfig::Direct(_) | OutboundConfig::Tor(_) | OutboundConfig::I2p(_) => return,
    };
    endpoints.push((endpoint.0, endpoint.1));
}
