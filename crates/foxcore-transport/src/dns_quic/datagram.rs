//! Fixed-peer Quinn I/O over the already selected outbound. This module never
//! resolves a hostname or opens an OS socket.
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use foxcore_api::Destination;
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{BoxDatagramSession, Datagram};

pub(super) const UDP_PAYLOAD_BYTES: usize = 1200;
const DATAGRAM_QUEUE_CAPACITY: usize = 64;

type Failure = Arc<Mutex<Option<io::ErrorKind>>>;

pub(super) struct DatagramSocket {
    // Quinn requires numeric addresses. Each endpoint has exactly one logical
    // peer: this alias is translated only here, never resolved or sent on wire.
    peer: SocketAddr,
    send: mpsc::Sender<Bytes>,
    receive: Mutex<mpsc::Receiver<Bytes>>,
    cancel: CancellationToken,
    failure: Failure,
}

impl fmt::Debug for DatagramSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsQuicDatagramSocket")
            .finish_non_exhaustive()
    }
}

pub(super) struct DatagramGuard {
    cancel: CancellationToken,
    send: tokio::task::JoinHandle<()>,
    receive: tokio::task::JoinHandle<()>,
}

impl DatagramGuard {
    pub(super) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

impl Drop for DatagramGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.send.abort();
        self.receive.abort();
    }
}

impl DatagramSocket {
    pub(super) fn new(
        session: BoxDatagramSession,
        destination: Destination,
    ) -> (Arc<Self>, DatagramGuard) {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, destination.port));
        let authenticated = session.authenticated_peer();
        let (send, mut outbound) = mpsc::channel::<Bytes>(DATAGRAM_QUEUE_CAPACITY);
        let (inbound, receive) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
        let cancel = CancellationToken::new();
        let failure = Arc::new(Mutex::new(None));
        let socket = Arc::new(Self {
            peer,
            send,
            receive: Mutex::new(receive),
            cancel: cancel.clone(),
            failure: failure.clone(),
        });
        let sender = session.clone();
        let send_target = destination.clone();
        let send_cancel = cancel.clone();
        let send_failure = failure.clone();
        let send_task = tokio::spawn(async move {
            loop {
                let payload = tokio::select! {
                    _ = send_cancel.cancelled() => break,
                    payload = outbound.recv() => match payload { Some(value) => value, None => break },
                };
                let result = tokio::select! {
                    _ = send_cancel.cancelled() => break,
                    result = sender.send(Datagram::new(send_target.clone(), payload)) => result,
                };
                if let Err(error) = result {
                    fail(&send_failure, &send_cancel, error.kind());
                    break;
                }
            }
        });
        let receive_cancel = cancel.clone();
        let receive_task = tokio::spawn(async move {
            loop {
                let result = tokio::select! {
                    _ = receive_cancel.cancelled() => break,
                    result = session.recv() => result,
                };
                let packet = match result {
                    Ok(packet) => packet,
                    Err(error) => {
                        fail(&failure, &receive_cancel, error.kind());
                        break;
                    }
                };
                if packet.payload.is_empty()
                    || packet.payload.len() > UDP_PAYLOAD_BYTES
                    || !matches_source(&destination, &packet.destination, authenticated.as_ref())
                {
                    continue;
                }
                tokio::select! {
                    _ = receive_cancel.cancelled() => break,
                    result = inbound.send(packet.payload) => if result.is_err() { break; },
                }
            }
        });
        (
            socket,
            DatagramGuard {
                cancel,
                send: send_task,
                receive: receive_task,
            },
        )
    }

    pub(super) fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn check(&self) -> io::Result<()> {
        if self.cancel.is_cancelled() {
            let kind = self
                .failure
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .unwrap_or(io::ErrorKind::BrokenPipe);
            Err(io::Error::new(kind, "DNS QUIC outbound is closed"))
        } else {
            Ok(())
        }
    }
}

fn fail(failure: &Failure, cancel: &CancellationToken, kind: io::ErrorKind) {
    *failure.lock().unwrap_or_else(|p| p.into_inner()) = Some(kind);
    cancel.cancel();
}

fn matches_source(
    destination: &Destination,
    source: &Destination,
    authenticated: Option<&Destination>,
) -> bool {
    // Same policy as the existing DNS datagram boundary: direct connected
    // sockets enforce the numeric peer; an authenticated proxy can report the
    // hostname or its resolved IP, retaining the configured port check.
    let expected = authenticated.unwrap_or(destination);
    source.port == expected.port && expected.ip().is_none_or(|ip| source.ip() == Some(ip))
}

impl AsyncUdpSocket for DatagramSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(DatagramPoller {
            socket: self,
            wait: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.check()?;
        if transmit.destination != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS QUIC peer migration is refused",
            ));
        }
        if transmit.contents.len() > UDP_PAYLOAD_BYTES
            || transmit
                .segment_size
                .is_some_and(|size| size < transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS QUIC datagram exceeds its bounded MTU",
            ));
        }
        self.send
            .try_send(Bytes::copy_from_slice(transmit.contents))
            .map_err(|error| {
                io::Error::new(
                    match error {
                        mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                        mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe,
                    },
                    "DNS QUIC outbound queue is unavailable",
                )
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS QUIC receive slots are empty",
            )));
        }
        let mut receive = self.receive.lock().unwrap_or_else(|p| p.into_inner());
        match receive.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if packet.len() > bufs[0].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS QUIC receive buffer is too small",
                    )));
                }
                bufs[0][..packet.len()].copy_from_slice(&packet);
                meta[0] = quinn::udp::RecvMeta {
                    addr: self.peer,
                    len: packet.len(),
                    stride: packet.len(),
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DNS QUIC outbound receive closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
    }
}

type Writable = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct DatagramPoller {
    socket: Arc<DatagramSocket>,
    wait: Mutex<Option<Writable>>,
}

impl fmt::Debug for DatagramPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsQuicDatagramPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for DatagramPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.socket.check()?;
        let wait = this.wait.get_mut().unwrap_or_else(|p| p.into_inner());
        if wait.is_none() {
            let sender = this.socket.send.clone();
            let cancel = this.socket.cancel.clone();
            *wait = Some(Box::pin(async move {
                tokio::select! {
                    _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "DNS QUIC outbound closed")),
                    permit = sender.reserve_owned() => permit.map(drop).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "DNS QUIC send queue closed")),
                }
            }));
        }
        let Some(pending) = wait.as_mut() else {
            return Poll::Ready(Err(io::Error::other("DNS writable waiter missing")));
        };
        let result = pending.as_mut().poll(cx);
        if result.is_ready() {
            *wait = None;
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Datagram, datagram_channel, with_authenticated_peer};
    use futures::future::poll_fn;
    use std::io::IoSliceMut;
    use std::time::Duration;

    fn transmit(destination: SocketAddr, body: &[u8]) -> quinn::udp::Transmit<'_> {
        quinn::udp::Transmit {
            destination,
            ecn: None,
            contents: body,
            segment_size: None,
            src_ip: None,
        }
    }

    #[tokio::test]
    async fn fixed_peer_adapter_preserves_the_proxy_destination_without_resolving_it() {
        let (session, mut channel) = datagram_channel(4);
        let destination = Destination::new("resolver.example", 853);
        let (socket, _guard) = DatagramSocket::new(session, destination.clone());
        socket
            .try_send(&transmit(socket.peer(), b"encrypted QUIC"))
            .unwrap();
        let sent = channel.uplink.recv().await.unwrap();
        assert_eq!(sent.destination, destination);
        assert_eq!(sent.payload, b"encrypted QUIC"[..]);
        assert_eq!(
            socket
                .try_send(&transmit("192.0.2.99:853".parse().unwrap(), b"redirect"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied,
        );
    }

    #[tokio::test]
    async fn source_filter_keeps_the_authenticated_numeric_peer_and_port() {
        let (session, channel) = datagram_channel(4);
        let peer = Destination::new("192.0.2.53", 853);
        let session = with_authenticated_peer(session, peer.clone());
        let (socket, _guard) =
            DatagramSocket::new(session, Destination::new("resolver.example", 853));
        channel
            .downlink
            .send(Datagram::new(peer.clone(), Bytes::new()))
            .await
            .unwrap();
        channel
            .downlink
            .send(Datagram::new(
                Destination::new("192.0.2.54", 853),
                b"wrong IP".as_slice(),
            ))
            .await
            .unwrap();
        channel
            .downlink
            .send(Datagram::new(
                Destination::new("192.0.2.53", 443),
                b"wrong port".as_slice(),
            ))
            .await
            .unwrap();
        channel
            .downlink
            .send(Datagram::new(peer, b"valid".as_slice()))
            .await
            .unwrap();
        let mut body = [0; UDP_PAYLOAD_BYTES];
        let mut slices = [IoSliceMut::new(&mut body)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let count = tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| socket.poll_recv(cx, &mut slices, &mut meta)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, socket.peer());
        assert_eq!(&body[..meta[0].len], b"valid");
    }

    #[tokio::test]
    async fn a_full_send_queue_backpressures_and_wakes_after_the_outbound_drains() {
        let (session, mut channel) = datagram_channel(1);
        let (socket, _guard) =
            DatagramSocket::new(session, Destination::new("resolver.example", 853));
        for _ in 0..DATAGRAM_QUEUE_CAPACITY {
            socket.try_send(&transmit(socket.peer(), b"q")).unwrap();
        }
        assert_eq!(
            socket
                .try_send(&transmit(socket.peer(), b"q"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut poller = socket.clone().create_io_poller();
        channel.uplink.recv().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| poller.as_mut().poll_writable(cx)),
        )
        .await
        .unwrap()
        .unwrap();
        socket
            .try_send(&transmit(socket.peer(), b"resumed"))
            .unwrap();
    }

    #[tokio::test]
    async fn an_outbound_send_error_wakes_the_socket_as_an_error() {
        let (session, mut channel) = datagram_channel(1);
        channel.uplink.close();
        let (socket, _guard) =
            DatagramSocket::new(session, Destination::new("resolver.example", 853));
        socket.try_send(&transmit(socket.peer(), b"q")).unwrap();
        tokio::time::timeout(Duration::from_secs(1), socket.cancel.cancelled())
            .await
            .unwrap();
        assert_eq!(
            socket
                .try_send(&transmit(socket.peer(), b"q"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn dropping_the_endpoint_lease_cancels_both_pumps_and_releases_the_outbound() {
        let (session, channel) = datagram_channel(1);
        let (socket, guard) =
            DatagramSocket::new(session, Destination::new("resolver.example", 853));
        drop(guard);
        assert_eq!(
            socket
                .try_send(&transmit(socket.peer(), b"q"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        tokio::time::timeout(Duration::from_secs(1), channel.cancel.cancelled())
            .await
            .unwrap();
    }
}
