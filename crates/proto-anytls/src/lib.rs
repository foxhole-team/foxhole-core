//! Clean-room AnyTLS protocol-v2 client.
//!
//! The implementation is derived from the public protocol and URI documents,
//! without copying an unlicensed or copyleft implementation. It
//! implements TLS authentication, bounded padding updates, v2 SYNACK, session
//! reuse/multiplexing, heartbeat responses, TCP and UoT-v2 UDP.
//!
//! Protocol source: <https://github.com/anytls/anytls-go/blob/main/docs/protocol.md>
//! URI source: <https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md>

#![forbid(unsafe_code)]

mod codec;
mod padding;
mod session;
mod uot;

use std::io;
use std::sync::Arc;

use foxcore_api::{AnyTlsConfig, Destination};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream};

use session::SessionPool;

#[derive(Clone)]
pub struct AnyTlsOutbound {
    pool: Arc<SessionPool>,
}

impl AnyTlsOutbound {
    pub async fn new(config: AnyTlsConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        validate_runtime_config(&config)?;
        let server_addresses = dialer
            .resolve_server_addresses(&config.server, config.port, config.server_ip)
            .await?;
        Ok(Self {
            pool: SessionPool::new(Arc::new(config), server_addresses, dialer)?,
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        self.pool.open_stream(destination.clone()).await
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        let stream = self.pool.open_stream(uot::magic_destination()).await?;
        uot::open(stream, destination.clone()).await
    }

    /// Existing TLS sessions are bound to the previous Android `Network`.
    /// They cannot migrate, so they must never be selected for a new flow.
    pub fn network_changed(&self) {
        SessionPool::network_changed(&self.pool);
    }
}

fn validate_runtime_config(config: &AnyTlsConfig) -> io::Result<()> {
    if !config.tls.enabled {
        return Err(invalid("AnyTLS requires TLS"));
    }
    if config.password.is_empty() {
        return Err(invalid("AnyTLS password must not be empty"));
    }
    if !(1..=120_000).contains(&config.handshake_timeout_ms) {
        return Err(invalid("AnyTLS handshake_timeout_ms must be in 1..=120000"));
    }
    if !(1_000..=3_600_000).contains(&config.idle_session_check_interval_ms)
        || !(1_000..=3_600_000).contains(&config.idle_session_timeout_ms)
    {
        return Err(invalid(
            "AnyTLS idle-session timeouts must be in 1000..=3600000",
        ));
    }
    if config.min_idle_session > 32 {
        return Err(invalid("AnyTLS min_idle_session must be at most 32"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
