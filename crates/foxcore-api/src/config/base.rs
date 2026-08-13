use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;
pub(super) const MAX_ENGINE_CONFIG_BYTES: usize = 1024 * 1024;
pub(super) const MAX_POLICY_CONFIG_BYTES: usize = 256 * 1024;
pub(super) const MAX_ROUTE_RULES: usize = 4096;
pub(super) const MAX_HYSTERIA2_OBFS_KEY_BYTES: usize = 1024;
pub(super) const MAX_REALITY_SPIDER_X_BYTES: usize = 2048;
pub(super) const WIREGUARD_KEY_BYTES: usize = 32;
pub(super) const MAX_WEBSOCKET_PATH_BYTES: usize = 2048;
pub(super) const MAX_WEBSOCKET_HEADERS: usize = 32;
pub(super) const MAX_WEBSOCKET_HEADER_BYTES: usize = 8192;
/// Blocklists are bounded independently of route rules: a real one is orders of
/// magnitude larger than the route-rule budget.
pub(super) const MAX_DNS_BLOCKLIST_ENTRIES: usize = 65_536;
pub(super) const MAX_DNS_RULE_SETS: usize = 16;
pub(super) const MAX_DNS_RULE_SET_NAME_BYTES: usize = 128;
pub(super) const MAX_DNS_RULE_SET_PUBLIC_KEY_BYTES: usize = 4 * 1024;
/// The well-known port for DNS over TLS (RFC 7858) and DNS over QUIC (RFC 9250).
///
/// Not configurable and not a policy knob: it is where every DoT client looks,
/// which is the only reason the data plane has to know about it at all. See
/// [`DnsConfig::bypasses_interceptor`].
pub const DNS_ENCRYPTED_PORT: u16 = 853;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("engine config schema {actual} != supported {expected}")]
    Schema { actual: u32, expected: u32 },
    #[error("invalid config: {0}")]
    Invalid(String),
}
