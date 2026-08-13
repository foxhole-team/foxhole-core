#![forbid(unsafe_code)]

pub mod brutal;
pub mod codec;
mod connection;
mod hop;
mod obfs;
mod session;
mod udp;
pub mod varint;

use std::fmt;
use std::io;
use std::sync::Arc;

use foxcore_api::{ContinuityPermit, Destination, Hysteria2Config};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream};
use tokio_util::sync::CancellationToken;

use crate::session::Hysteria2Session;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    ValueTooLarge,
    Protocol(String),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated Hysteria2 frame"),
            Self::ValueTooLarge => f.write_str("Hysteria2 value exceeds protocol limit"),
            Self::Protocol(message) => write!(f, "Hysteria2 protocol error: {message}"),
        }
    }
}

impl std::error::Error for CodecError {}

pub type Result<T> = std::result::Result<T, CodecError>;

#[derive(Clone)]
pub struct Hysteria2Outbound {
    session: Arc<Hysteria2Session>,
    _lifecycle: Arc<CancelOnDrop>,
}

impl Hysteria2Outbound {
    pub async fn new(config: Hysteria2Config, dialer: ProtectedDialer) -> io::Result<Self> {
        Self::new_with_reconnect_hook(config, dialer, None).await
    }

    pub async fn new_with_reconnect_hook(
        config: Hysteria2Config,
        dialer: ProtectedDialer,
        reconnect_hook: Option<Arc<dyn Fn() -> ContinuityPermit + Send + Sync>>,
    ) -> io::Result<Self> {
        let cancel = CancellationToken::new();
        let session =
            Hysteria2Session::start(config, dialer, cancel.clone(), reconnect_hook).await?;
        Ok(Self {
            session,
            _lifecycle: Arc::new(CancelOnDrop(cancel)),
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let (connection, _) = self.ready().await?;
        Ok(Box::new(connection.open_tcp(destination).await?))
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        let (connection, relay) = self.ready().await?;
        if !connection.udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria2 server did not enable UDP",
            ));
        }
        Ok(relay.open_session(destination.clone()))
    }

    pub fn network_changed(&self) {
        self.session.nudge();
    }

    pub fn reconnects(&self) -> u64 {
        self.session.reconnects()
    }

    /// See [`session::Hysteria2Session::set_reconnect_hook`].
    pub fn set_reconnect_hook(
        &self,
        hook: std::sync::Arc<dyn Fn() -> ContinuityPermit + Send + Sync>,
    ) {
        self.session.set_reconnect_hook(hook);
    }

    async fn ready(
        &self,
    ) -> io::Result<(Arc<connection::Hysteria2Conn>, Arc<udp::Hysteria2UdpRelay>)> {
        self.session.wait_ready().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Hysteria2 session is not ready after reconnect",
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
