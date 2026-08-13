use super::*;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::SecretString;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct I2pConfig {
    /// Loopback SOCKS5 listener owned by the external i2pd process.
    pub socks_address: SocketAddr,
    /// Optional RFC 1929 credentials for the app-owned i2pd listener. Both
    /// values must be present together; when present the client offers only
    /// username/password authentication and never downgrades to anonymous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    #[serde(default = "default_i2p_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_i2p_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

fn default_i2p_connect_timeout_ms() -> u64 {
    3_000
}

fn default_i2p_handshake_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorConfig {
    pub state_dir: String,
    pub cache_dir: String,
    /// Optional stream proxy used for every Arti guard connection.
    ///
    /// This is the explicit Tor-over-VPN seam. It is inline because the Tor client is built before
    /// the route registry can lend out a named outbound. Validation permits only stream proxies:
    /// direct, I2P, nested Tor and packet tunnels are rejected rather than changing privacy class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Box<OutboundConfig>>,
    #[serde(default = "default_tor_bootstrap_timeout")]
    pub bootstrap_timeout_s: u64,
    #[serde(default = "default_tor_stream_connect_timeout")]
    pub stream_connect_timeout_s: u64,
    #[serde(default = "default_true")]
    pub isolate_streams: bool,
    #[serde(default)]
    pub circuit: TorCircuitConfig,
    /// Direct Tor bridge lines. Values are redacted because unpublished bridge
    /// addresses are privacy-sensitive. A line naming a transport requires that
    /// transport to be configured in `transports` below; see the validation
    /// further down this file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridges: Vec<SecretString>,
    /// Managed pluggable transports used by bridge lines. The Android layer supplies only
    /// ABI-pinned executables from the application bundle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<TorTransportConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorTransportConfig {
    pub protocols: Vec<String>,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<SecretString>,
    #[serde(default = "default_true")]
    pub run_on_startup: bool,
}

fn default_tor_bootstrap_timeout() -> u64 {
    120
}

fn default_tor_stream_connect_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorCircuitConfig {
    #[serde(default = "default_tor_circuit_max_dirtiness")]
    pub max_dirtiness_s: u64,
    #[serde(default = "default_tor_circuit_request_timeout")]
    pub request_timeout_s: u64,
    #[serde(default = "default_tor_circuit_request_max_retries")]
    pub request_max_retries: u32,
}

impl Default for TorCircuitConfig {
    fn default() -> Self {
        Self {
            max_dirtiness_s: default_tor_circuit_max_dirtiness(),
            request_timeout_s: default_tor_circuit_request_timeout(),
            request_max_retries: default_tor_circuit_request_max_retries(),
        }
    }
}

fn default_tor_circuit_max_dirtiness() -> u64 {
    600
}

fn default_tor_circuit_request_timeout() -> u64 {
    60
}

fn default_tor_circuit_request_max_retries() -> u32 {
    16
}
