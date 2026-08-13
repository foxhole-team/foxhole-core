use super::*;

use crate::{RouteAction, RouteRule, SecretString};

/// Decode a hex SHA-256 signing-certificate digest into raw bytes.
pub fn decode_signing_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

pub(super) fn validate_route_count(count: usize) -> Result<(), ConfigError> {
    if count > MAX_ROUTE_RULES {
        return Err(ConfigError::Invalid(
            "routes must contain at most 4096 rules".into(),
        ));
    }
    Ok(())
}

pub(super) fn action_uses_tor(action: &RouteAction) -> bool {
    matches!(action, RouteAction::Tor)
        || matches!(action, RouteAction::Outbound(id) if id.0 == "tor")
}

pub(super) fn action_uses_i2p(action: &RouteAction) -> bool {
    matches!(action, RouteAction::I2p)
        || matches!(action, RouteAction::Outbound(id) if id.0 == "i2p")
}

pub(super) fn validate_route_rule(rule: &RouteRule) -> Result<(), ConfigError> {
    if rule
        .exact_domains
        .len()
        .saturating_add(rule.domain_suffixes.len())
        > 128
        || rule.cidrs.len() > 64
        || rule.ports.len() > 64
    {
        return Err(ConfigError::Invalid(
            "route matcher lists exceed their configured limits".into(),
        ));
    }
    for domain in rule.exact_domains.iter().chain(rule.domain_suffixes.iter()) {
        validate_route_domain(domain)?;
    }
    if rule.ports.iter().any(|range| range.start > range.end) {
        return Err(ConfigError::Invalid(
            "route port range start must not exceed end".into(),
        ));
    }
    if let RouteAction::Outbound(id) = &rule.action {
        validate_outbound_id(&id.0)?;
    }
    if let Some(package) = &rule.package {
        validate_package(package)?;
    }
    Ok(())
}

pub(super) fn validate_package(package: &str) -> Result<(), ConfigError> {
    if package.is_empty()
        || package.len() > 255
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        return Err(ConfigError::Invalid(
            "application package must contain 1..=255 ASCII letters, digits, '.', or '_'".into(),
        ));
    }
    Ok(())
}

fn validate_route_domain(value: &str) -> Result<(), ConfigError> {
    let domain = value.trim_matches('.');
    if domain.is_empty()
        || domain.len() > 253
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(ConfigError::Invalid(
            "route domain must be a valid ASCII DNS name".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_server(server: &str, port: u16) -> Result<(), ConfigError> {
    if server.trim().is_empty() {
        return Err(ConfigError::Invalid("server must not be empty".into()));
    }
    if port == 0 {
        return Err(ConfigError::Invalid("server port must not be zero".into()));
    }
    Ok(())
}

pub(super) fn require_secret(label: &str, value: &SecretString) -> Result<(), ConfigError> {
    if value.is_empty() {
        Err(ConfigError::Invalid(format!("{label} must not be empty")))
    } else {
        Ok(())
    }
}

pub(super) fn validate_uuid(protocol: &str, value: &str) -> Result<(), ConfigError> {
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::Invalid(format!(
            "{protocol} uuid must contain 32 hexadecimal digits"
        )));
    }
    Ok(())
}

pub(super) fn validate_outbound_id(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ConfigError::Invalid(
            "outbound id must be 1..=64 lowercase ASCII letters, digits, '.', '_' or '-' and start with a letter or digit"
                .into(),
        ));
    }
    Ok(())
}
