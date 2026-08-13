use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use foxcore_api::Destination;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub destination: Destination,
    pub payload: Bytes,
}

impl Datagram {
    pub fn new(destination: Destination, payload: impl Into<Bytes>) -> Self {
        Self {
            destination,
            payload: payload.into(),
        }
    }
}

#[async_trait]
pub trait DatagramSession: Send + Sync {
    async fn send(&self, datagram: Datagram) -> io::Result<()>;
    async fn recv(&self) -> io::Result<Datagram>;

    /// A peer whose source identity is enforced below this trait.
    ///
    /// Connected UDP sockets return the numeric endpoint the kernel filters
    /// against. Encapsulated/multiplexed transports leave this as `None`
    /// because their datagram metadata may contain either a hostname or an IP.
    fn authenticated_peer(&self) -> Option<Destination> {
        None
    }
}

pub type BoxDatagramSession = Arc<dyn DatagramSession>;

/// Attach the source identity enforced by the transport to a session.
pub fn with_authenticated_peer(inner: BoxDatagramSession, peer: Destination) -> BoxDatagramSession {
    Arc::new(AuthenticatedPeerDatagramSession { inner, peer })
}

struct AuthenticatedPeerDatagramSession {
    inner: BoxDatagramSession,
    peer: Destination,
}

#[async_trait]
impl DatagramSession for AuthenticatedPeerDatagramSession {
    async fn send(&self, datagram: Datagram) -> io::Result<()> {
        self.inner.send(datagram).await
    }

    async fn recv(&self) -> io::Result<Datagram> {
        self.inner.recv().await
    }

    fn authenticated_peer(&self) -> Option<Destination> {
        Some(self.peer.clone())
    }
}

pub struct DatagramChannelIo {
    pub uplink: mpsc::Receiver<Datagram>,
    pub downlink: mpsc::Sender<Datagram>,
    pub cancel: CancellationToken,
}

pub fn datagram_channel(capacity: usize) -> (BoxDatagramSession, DatagramChannelIo) {
    let (uplink_tx, uplink_rx) = mpsc::channel(capacity);
    let (downlink_tx, downlink_rx) = mpsc::channel(capacity);
    let cancel = CancellationToken::new();
    let session = Arc::new(ChannelDatagramSession {
        uplink: uplink_tx,
        downlink: Mutex::new(downlink_rx),
        cancel: cancel.clone(),
    });
    (
        session,
        DatagramChannelIo {
            uplink: uplink_rx,
            downlink: downlink_tx,
            cancel,
        },
    )
}

struct ChannelDatagramSession {
    uplink: mpsc::Sender<Datagram>,
    downlink: Mutex<mpsc::Receiver<Datagram>>,
    cancel: CancellationToken,
}

impl Drop for ChannelDatagramSession {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl DatagramSession for ChannelDatagramSession {
    async fn send(&self, datagram: Datagram) -> io::Result<()> {
        self.uplink
            .send(datagram)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "datagram uplink is closed"))
    }

    async fn recv(&self) -> io::Result<Datagram> {
        self.downlink.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "datagram downlink is closed")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_channel_moves_both_directions() {
        let (session, mut io) = datagram_channel(1);
        let destination = Destination::new("example.com", 53);
        session
            .send(Datagram::new(destination.clone(), Bytes::from_static(b"q")))
            .await
            .unwrap();
        assert_eq!(io.uplink.recv().await.unwrap().payload, b"q"[..]);

        io.downlink
            .send(Datagram::new(destination, Bytes::from_static(b"answer")))
            .await
            .unwrap();
        assert_eq!(session.recv().await.unwrap().payload, b"answer"[..]);
    }
}
