use super::*;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Config {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub password: SecretString,
    #[serde(default)]
    pub up_mbps: u32,
    #[serde(default)]
    pub down_mbps: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2ObfsConfig>,
    /// Extra destination ports the server answers on. Non-empty turns on port
    /// hopping; `port` stays the address the connection is established to and
    /// the one every reply is attributed to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_ports: Vec<Hysteria2PortRange>,
    /// How long to stay on one port. Only meaningful with `server_ports`.
    #[serde(default = "default_hysteria2_hop_interval_ms")]
    pub hop_interval_ms: u64,
    #[serde(default)]
    pub tls: TlsConfig,
}

/// An inclusive UDP port range for Hysteria2 port hopping.
///
/// Typed rather than the reference's `"20000-50000"` string: a range that has to
/// be re-parsed at every layer eventually gets parsed differently by one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2PortRange {
    pub start: u16,
    pub end: u16,
}

impl Hysteria2PortRange {
    pub fn len(&self) -> usize {
        usize::from(self.end - self.start) + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn ports(&self) -> impl Iterator<Item = u16> + use<> {
        self.start..=self.end
    }
}

fn default_hysteria2_hop_interval_ms() -> u64 {
    30_000
}

/// Largest port set we will expand. The reference allows the whole 16-bit space;
/// the cap exists so a malformed profile cannot make the core materialise a
/// 65k-entry table for a server that only listens on ten ports.
const MAX_HYSTERIA2_HOP_PORTS: usize = 4096;
/// The reference refuses anything under five seconds, and so do we: hopping
/// faster costs a handshake-sized burst of path validation for no extra cover.
const MIN_HYSTERIA2_HOP_INTERVAL_MS: u64 = 5_000;
const MAX_HYSTERIA2_HOP_INTERVAL_MS: u64 = 600_000;

pub(super) fn validate_hysteria2_hopping(config: &Hysteria2Config) -> Result<(), ConfigError> {
    if config.server_ports.is_empty() {
        return Ok(());
    }
    let mut total = 0_usize;
    for range in &config.server_ports {
        if range.start == 0 || range.start > range.end {
            return Err(ConfigError::Invalid(
                "hysteria2 server_ports range must be 1..=65535 with start <= end".into(),
            ));
        }
        total = total.saturating_add(range.len());
    }
    if total > MAX_HYSTERIA2_HOP_PORTS {
        return Err(ConfigError::Invalid(format!(
            "hysteria2 server_ports must expand to at most {MAX_HYSTERIA2_HOP_PORTS} ports"
        )));
    }
    if !(MIN_HYSTERIA2_HOP_INTERVAL_MS..=MAX_HYSTERIA2_HOP_INTERVAL_MS)
        .contains(&config.hop_interval_ms)
    {
        return Err(ConfigError::Invalid(format!(
            "hysteria2 hop_interval_ms must be in {MIN_HYSTERIA2_HOP_INTERVAL_MS}..={MAX_HYSTERIA2_HOP_INTERVAL_MS}"
        )));
    }
    Ok(())
}

/// TUIC protocol v5 over a protected QUIC socket.
///
/// Early data is represented so imported profiles are never silently changed,
/// but validation rejects it: TUIC authenticates the connection after the TLS
/// handshake and replayable 0-RTT proxy commands are not an acceptable
/// production default for this core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuicConfig {
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<IpAddr>,
    pub uuid: SecretString,
    pub password: SecretString,
    #[serde(default)]
    pub congestion_control: TuicCongestionControl,
    #[serde(default)]
    pub udp_relay_mode: TuicUdpRelayMode,
    #[serde(default = "default_true")]
    pub tcp: bool,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default = "default_tuic_heartbeat_ms")]
    pub heartbeat_ms: u64,
    #[serde(default = "default_tuic_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    #[serde(default = "default_tuic_tls")]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TuicCongestionControl {
    #[default]
    Cubic,
    NewReno,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TuicUdpRelayMode {
    #[default]
    Native,
    Quic,
}

fn default_tuic_heartbeat_ms() -> u64 {
    10_000
}

fn default_tuic_idle_timeout_ms() -> u64 {
    30_000
}

fn default_tuic_tls() -> TlsConfig {
    TlsConfig {
        enabled: true,
        ..TlsConfig::default()
    }
}

/// Optional wire obfuscation below QUIC. The key is independent from HY2
/// authentication and is always redacted by [`SecretString`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Hysteria2ObfsConfig {
    Salamander { password: SecretString },
}
