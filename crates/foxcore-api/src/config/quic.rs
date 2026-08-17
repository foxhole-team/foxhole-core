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
    /// QUIC PING spacing. Defaults to the reference client's 10s; raising it
    /// trades NAT-binding margin for radio wakeups on a metered handset.
    #[serde(default = "default_hysteria2_keepalive_ms")]
    pub keepalive_ms: u64,
    #[serde(default = "default_hysteria2_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
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

fn default_hysteria2_keepalive_ms() -> u64 {
    10_000
}

fn default_hysteria2_idle_timeout_ms() -> u64 {
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

const MIN_HYSTERIA2_KEEPALIVE_MS: u64 = 1_000;
const MAX_HYSTERIA2_KEEPALIVE_MS: u64 = 120_000;
const MIN_HYSTERIA2_IDLE_TIMEOUT_MS: u64 = 5_000;
const MAX_HYSTERIA2_IDLE_TIMEOUT_MS: u64 = 600_000;

pub(super) fn validate_hysteria2_timing(config: &Hysteria2Config) -> Result<(), ConfigError> {
    if !(MIN_HYSTERIA2_KEEPALIVE_MS..=MAX_HYSTERIA2_KEEPALIVE_MS).contains(&config.keepalive_ms) {
        return Err(ConfigError::Invalid(format!(
            "hysteria2 keepalive_ms must be in {MIN_HYSTERIA2_KEEPALIVE_MS}..={MAX_HYSTERIA2_KEEPALIVE_MS}"
        )));
    }
    if !(MIN_HYSTERIA2_IDLE_TIMEOUT_MS..=MAX_HYSTERIA2_IDLE_TIMEOUT_MS)
        .contains(&config.idle_timeout_ms)
    {
        return Err(ConfigError::Invalid(format!(
            "hysteria2 idle_timeout_ms must be in {MIN_HYSTERIA2_IDLE_TIMEOUT_MS}..={MAX_HYSTERIA2_IDLE_TIMEOUT_MS}"
        )));
    }
    // One PING may be lost without the peer declaring the path dead.
    if config.keepalive_ms.saturating_mul(2) >= config.idle_timeout_ms {
        return Err(ConfigError::Invalid(
            "hysteria2 keepalive_ms must be less than half of idle_timeout_ms".into(),
        ));
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

impl TuicConfig {
    /// The heartbeat spacing this connection will actually run at.
    ///
    /// `heartbeat_ms` and `idle_timeout_ms` are validated independently, so a
    /// profile can hold a pair that cannot work: with `heartbeat_ms` at or
    /// above `idle_timeout_ms` the peer's idle timer expires before the first
    /// heartbeat is ever sent, and the connection dies once per idle period
    /// with every counter reading healthy.
    ///
    /// This is **clamped rather than rejected**, which is where it parts
    /// company with hysteria2's `validate_hysteria2_timing`. Two reasons, and
    /// only the second is about this function.
    ///
    /// The hysteria2 rule is `keepalive * 2 < idle_timeout` — a margin, so one
    /// lost PING does not kill the path — and applying that as a *refusal*
    /// here would reject pairs that work: `heartbeat_ms: 10000` with
    /// `idle_timeout_ms: 15000` has a thin margin but its heartbeat does fire,
    /// and these are long-standing TUIC fields that saved profiles already
    /// carry. A refusal is a failed start, so it would take a user's whole
    /// tunnel over a timing field. Nothing in the thin-margin band is touched
    /// here for the same reason in reverse: shortening a working heartbeat
    /// would buy a sleeping handset extra radio wakeups it never asked for.
    ///
    /// When the pair genuinely cannot work the value is moved, and it is moved
    /// to half the idle timeout rather than to the largest value that merely
    /// fires — if the profile is being overridden at all, the number it is
    /// overridden with should be the correct one, which is hysteria2's margin.
    /// [`Self::heartbeat_clamp`] says so out loud.
    pub fn effective_heartbeat_ms(&self) -> u64 {
        if self.heartbeat_ms < self.idle_timeout_ms {
            return self.heartbeat_ms;
        }
        // Never zero: `tokio::time::interval` panics on a zero period, and this
        // may be read from a config that has not been validated.
        (self.idle_timeout_ms / 2).max(1)
    }

    /// The diagnostic to record when the profile's heartbeat is not the one in
    /// use. `None` in the ordinary case, so nothing is logged for a profile
    /// that is being honoured exactly.
    pub fn heartbeat_clamp(&self) -> Option<String> {
        let effective = self.effective_heartbeat_ms();
        (effective != self.heartbeat_ms).then(|| {
            format!(
                "TUIC heartbeat_ms={} would never fire before idle_timeout_ms={} expires; \
                 using {effective}ms instead",
                self.heartbeat_ms, self.idle_timeout_ms
            )
        })
    }
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

#[cfg(test)]
mod tuic_timing_tests {
    use super::*;

    fn config(heartbeat_ms: u64, idle_timeout_ms: u64) -> TuicConfig {
        serde_json::from_value(serde_json::json!({
            "server": "tuic.example",
            "port": 443,
            "uuid": "2dd61d93-75d8-4da4-ac0e-6aece7eac365",
            "password": "synthetic",
            "heartbeat_ms": heartbeat_ms,
            "idle_timeout_ms": idle_timeout_ms,
        }))
        .expect("a TUIC profile carrying only the timing fields")
    }

    /// The hole this closes: both fields validate on their own, and the pair
    /// then idles the connection out before the first heartbeat is ever sent.
    #[test]
    fn a_heartbeat_that_could_never_fire_is_moved_to_one_that_can() {
        let config = config(120_000, 5_000);
        assert!(
            crate::OutboundConfig::Tuic(config.clone())
                .validate()
                .is_ok(),
            "the profile is still importable"
        );
        assert_eq!(
            config.effective_heartbeat_ms(),
            2_500,
            "half the idle timeout — hysteria2's margin, not merely the largest value that fires"
        );
        let diagnostic = config.heartbeat_clamp().expect("the change is recorded");
        assert!(diagnostic.contains("120000"), "{diagnostic}");
        assert!(diagnostic.contains("2500"), "{diagnostic}");
    }

    #[test]
    fn the_defaults_are_honoured_exactly_and_say_nothing() {
        let config = config(10_000, 30_000);
        assert_eq!(config.effective_heartbeat_ms(), 10_000);
        assert_eq!(config.heartbeat_clamp(), None);
    }

    /// A thin margin is not a broken profile. This pair has one heartbeat
    /// inside the idle window and no room for a second, which works — and
    /// shortening it would cost a sleeping handset extra radio wakeups for a
    /// profile that was already carrying traffic.
    #[test]
    fn a_working_profile_with_a_thin_margin_is_left_exactly_as_written() {
        let config = config(10_000, 15_000);
        assert!(
            crate::OutboundConfig::Tuic(config.clone())
                .validate()
                .is_ok()
        );
        assert_eq!(config.effective_heartbeat_ms(), 10_000);
        assert_eq!(config.heartbeat_clamp(), None);
    }

    /// Equal is the boundary, and it is on the broken side: a heartbeat due at
    /// the same instant the idle timer expires is a race the connection loses
    /// about half the time.
    #[test]
    fn an_equal_pair_is_treated_as_the_broken_case() {
        let config = config(30_000, 30_000);
        assert_eq!(config.effective_heartbeat_ms(), 15_000);
        assert!(config.heartbeat_clamp().is_some());
    }

    /// Never a zero period: `tokio::time::interval` panics on one, and this is
    /// readable from a config that has not been through `validate`.
    #[test]
    fn an_unvalidated_profile_cannot_produce_a_zero_interval() {
        assert_eq!(config(1, 1).effective_heartbeat_ms(), 1);
        assert_eq!(config(0, 0).effective_heartbeat_ms(), 1);
    }
}
