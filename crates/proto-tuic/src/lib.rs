#![forbid(unsafe_code)]

//! Clean-room TUIC protocol v5 client.
//!
//! The wire format follows the protocol's normative `SPEC.md`. QUIC sockets
//! are created through [`foxcore_dialer::ProtectedDialer`] before the first
//! packet, 0-RTT is deliberately unavailable, and all receive/reassembly
//! queues are bounded.

pub mod codec;
mod connection;
mod session;
mod udp;

use std::fmt;
use std::io;
use std::sync::Arc;

use foxcore_api::{ContinuityPermit, Destination, TuicConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream};
use tokio_util::sync::CancellationToken;

use crate::session::TuicSession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    TrailingData,
    InvalidVersion(u8),
    InvalidCommand(u8),
    InvalidAddress,
    InvalidFragment,
    ValueTooLarge,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated TUIC frame"),
            Self::TrailingData => f.write_str("TUIC frame contains trailing data"),
            Self::InvalidVersion(version) => {
                write!(f, "unsupported TUIC version {version:#04x}")
            }
            Self::InvalidCommand(command) => {
                write!(f, "unsupported TUIC command {command:#04x}")
            }
            Self::InvalidAddress => f.write_str("invalid TUIC address"),
            Self::InvalidFragment => f.write_str("invalid TUIC UDP fragment"),
            Self::ValueTooLarge => f.write_str("TUIC value exceeds protocol limit"),
        }
    }
}

impl std::error::Error for CodecError {}

pub type Result<T> = std::result::Result<T, CodecError>;

#[derive(Clone)]
pub struct TuicOutbound {
    config: TuicConfig,
    session: Arc<TuicSession>,
    _lifecycle: Arc<CancelOnDrop>,
}

impl TuicOutbound {
    pub async fn new(config: TuicConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        Self::new_with_reconnect_hook(config, dialer, None).await
    }

    pub async fn new_with_reconnect_hook(
        config: TuicConfig,
        dialer: ProtectedDialer,
        reconnect_hook: Option<Arc<dyn Fn() -> ContinuityPermit + Send + Sync>>,
    ) -> io::Result<Self> {
        let cancel = CancellationToken::new();
        let session =
            TuicSession::start(config.clone(), dialer, cancel.clone(), reconnect_hook).await?;
        Ok(Self {
            config,
            session,
            _lifecycle: Arc::new(CancelOnDrop(cancel)),
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        if !self.config.tcp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUIC TCP is disabled by profile",
            ));
        }
        let (connection, _) = self.ready().await?;
        Ok(Box::new(connection.open_tcp(destination).await?))
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        if !self.config.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUIC UDP is disabled by profile",
            ));
        }
        let (_, relay) = self.ready().await?;
        relay.open_session(destination.clone())
    }

    pub fn network_changed(&self) {
        self.session.nudge();
    }

    pub fn reconnects(&self) -> u64 {
        self.session.reconnects()
    }

    /// See [`session::TuicSession::set_reconnect_hook`].
    pub fn set_reconnect_hook(
        &self,
        hook: std::sync::Arc<dyn Fn() -> ContinuityPermit + Send + Sync>,
    ) {
        self.session.set_reconnect_hook(hook);
    }

    async fn ready(&self) -> io::Result<(Arc<connection::TuicConnection>, Arc<udp::TuicUdpRelay>)> {
        self.session.wait_ready().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "TUIC session is not ready after reconnect",
            )
        })
    }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
