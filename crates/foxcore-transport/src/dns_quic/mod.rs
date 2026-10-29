//! Bounded DNS QUIC clients. Ordinary DNS supplies an already selected outbound
//! datagram session; bootstrap supplies its protected, literal-peer UDP socket.
mod datagram;
mod doh3;
mod doq;
mod h3io;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use foxcore_api::{Destination, TlsConfig, TlsVersion};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::sync::Semaphore;

use crate::{BoxDatagramSession, Datagram, DatagramSession, rustls_client_config};
use datagram::{DatagramGuard, DatagramSocket, UDP_PAYLOAD_BYTES};

const MAX_CONCURRENT_REQUESTS: usize = 16;
const STREAM_WINDOW: u32 = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsQuicProtocol {
    Doq,
    Doh3,
}

impl DnsQuicProtocol {
    fn alpn(self) -> &'static str {
        match self {
            Self::Doq => "doq",
            Self::Doh3 => "h3",
        }
    }
}

pub struct DnsQuicConnection {
    lease: ConnectionLease,
    origin: (String, u16),
    requests: Semaphore,
    http3: Option<doh3::Http3Client>,
    closed: tokio::task::JoinHandle<()>,
}

impl DnsQuicConnection {
    pub fn is_closed(&self) -> bool {
        self.lease.connection.close_reason().is_some()
            || self
                .http3
                .as_ref()
                .is_some_and(doh3::Http3Client::is_closed)
    }

    pub async fn exchange_doq(
        &self,
        query: &[u8],
        max_response_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        if self.http3.is_some() {
            return Err(invalid("DNS QUIC connection is not DoQ"));
        }
        let _permit = self
            .requests
            .acquire()
            .await
            .map_err(|_| invalid("DNS QUIC request pool closed"))?;
        doq::exchange(&self.lease.connection, query, max_response_bytes).await
    }

    pub async fn exchange_doh3(
        &self,
        endpoint: &str,
        query: &[u8],
        max_response_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        if endpoint.len() > 4096 {
            return Err(invalid("DNS HTTP/3 URI exceeds its bound"));
        }
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|_| invalid("invalid DNS HTTP/3 URI"))?;
        let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
        if uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_none_or(|value| value.as_str().contains('@'))
            || !host.eq_ignore_ascii_case(&self.origin.0)
            || uri.port_u16().unwrap_or(443) != self.origin.1
        {
            return Err(invalid(
                "DNS HTTP/3 request changed its authenticated origin",
            ));
        }
        let http3 = self
            .http3
            .as_ref()
            .ok_or_else(|| invalid("DNS QUIC connection is not HTTP/3"))?;
        let _permit = self
            .requests
            .acquire()
            .await
            .map_err(|_| invalid("DNS QUIC request pool closed"))?;
        http3.exchange(endpoint, query, max_response_bytes).await
    }
}

impl Drop for DnsQuicConnection {
    fn drop(&mut self) {
        self.closed.abort();
    }
}

struct ConnectionLease {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    datagram: DatagramGuard,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"DNS context ended");
        self.endpoint.close(0u32.into(), b"DNS context ended");
    }
}

struct EndpointLease {
    endpoint: Option<quinn::Endpoint>,
    datagram: Option<DatagramGuard>,
}

impl Drop for EndpointLease {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"DNS handshake cancelled");
        }
    }
}

/// The destination is passed to the supplied session exactly as configured.
/// Names stay with the proxy; there is no local DNS lookup or direct fallback.
pub async fn connect_dns_quic_datagram(
    session: BoxDatagramSession,
    destination: Destination,
    tls: &TlsConfig,
    server_name: &str,
    protocol: DnsQuicProtocol,
) -> io::Result<DnsQuicConnection> {
    if destination.port == 0 || (protocol == DnsQuicProtocol::Doq && destination.port == 53) {
        return Err(invalid("DNS QUIC port is invalid"));
    }
    let config = client_config(tls, server_name, protocol)?;
    let origin = (server_name.to_owned(), destination.port);
    let (socket, guard) = DatagramSocket::new(session, destination);
    let peer = socket.peer();
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(UDP_PAYLOAD_BYTES as u16)
        .map_err(|_| invalid("DNS QUIC MTU is invalid"))?;
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config,
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(config);
    let mut pending = EndpointLease {
        endpoint: Some(endpoint),
        datagram: Some(guard),
    };
    let connection = pending
        .endpoint
        .as_ref()
        .ok_or_else(|| invalid("DNS QUIC endpoint missing"))?
        .connect(peer, server_name)
        .map_err(|_| invalid("DNS QUIC connection setup failed"))?
        .await
        .map_err(|_| invalid("DNS QUIC TLS handshake failed"))?;
    let negotiated = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol);
    if negotiated.as_deref() != Some(protocol.alpn().as_bytes()) {
        connection.close(2u32.into(), b"unexpected DNS ALPN");
        return Err(invalid("DNS QUIC negotiated an incompatible ALPN"));
    }
    let lease = ConnectionLease {
        endpoint: pending
            .endpoint
            .take()
            .ok_or_else(|| invalid("DNS QUIC endpoint missing"))?,
        connection,
        datagram: pending
            .datagram
            .take()
            .ok_or_else(|| invalid("DNS QUIC datagram lease missing"))?,
    };
    let http3 = match protocol {
        DnsQuicProtocol::Doq => None,
        DnsQuicProtocol::Doh3 => Some(doh3::Http3Client::new(lease.connection.clone()).await?),
    };
    let closed_connection = lease.connection.clone();
    let cancel = lease.datagram.cancellation();
    let closed = tokio::spawn(async move {
        let _ = closed_connection.closed().await;
        cancel.cancel();
    });
    Ok(DnsQuicConnection {
        lease,
        origin,
        requests: Semaphore::new(MAX_CONCURRENT_REQUESTS),
        http3,
        closed,
    })
}

/// `socket` must already have passed the caller's protection/network-binding
/// callbacks. Connecting it enforces the one numeric bootstrap peer below QUIC.
pub async fn connect_dns_quic_socket(
    socket: std::net::UdpSocket,
    peer: SocketAddr,
    tls: &TlsConfig,
    server_name: &str,
    protocol: DnsQuicProtocol,
) -> io::Result<DnsQuicConnection> {
    socket.set_nonblocking(true)?;
    socket.connect(peer)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    let destination = Destination::new(peer.ip().to_string(), peer.port());
    let session = Arc::new(ConnectedSocket {
        socket,
        peer: destination.clone(),
    });
    connect_dns_quic_datagram(session, destination, tls, server_name, protocol).await
}

struct ConnectedSocket {
    socket: tokio::net::UdpSocket,
    peer: Destination,
}

#[async_trait]
impl DatagramSession for ConnectedSocket {
    async fn send(&self, packet: Datagram) -> io::Result<()> {
        if packet.destination != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bootstrap DNS peer changed",
            ));
        }
        let length = self.socket.send(&packet.payload).await?;
        if length != packet.payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "DNS QUIC datagram was truncated",
            ));
        }
        Ok(())
    }

    async fn recv(&self) -> io::Result<Datagram> {
        let mut bytes = vec![0; UDP_PAYLOAD_BYTES + 1];
        let length = self.socket.recv(&mut bytes).await?;
        bytes.truncate(length);
        Ok(Datagram::new(self.peer.clone(), bytes))
    }

    fn authenticated_peer(&self) -> Option<Destination> {
        Some(self.peer.clone())
    }
}

fn client_config(
    tls: &TlsConfig,
    name: &str,
    protocol: DnsQuicProtocol,
) -> io::Result<quinn::ClientConfig> {
    if tls.fingerprint.is_some()
        || tls.ech.is_some()
        || tls
            .min_version
            .is_some_and(|version| version != TlsVersion::Tls13)
        || tls
            .max_version
            .is_some_and(|version| version != TlsVersion::Tls13)
        || (!tls.alpn.is_empty() && tls.alpn != [protocol.alpn()])
        || tls
            .server_name
            .as_deref()
            .is_some_and(|configured| configured != name)
    {
        return Err(invalid(
            "DNS QUIC TLS requirements are incompatible with its protocol",
        ));
    }
    let mut configured = tls.clone();
    configured.enabled = true;
    configured.min_version = Some(TlsVersion::Tls13);
    configured.max_version = Some(TlsVersion::Tls13);
    configured.alpn = vec![protocol.alpn().into()];
    // Preserve the configured verifier, including explicit pin policy. The
    // cached ordinary TLS config must not share DNS tickets or early data.
    let mut crypto = rustls_client_config(&configured)?.as_ref().clone();
    crypto.enable_early_data = false;
    crypto.resumption = rustls::client::Resumption::disabled();
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|_| invalid("DNS QUIC TLS provider is incompatible"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.max_concurrent_uni_streams(
        match protocol {
            DnsQuicProtocol::Doq => 0u32,
            DnsQuicProtocol::Doh3 => 8u32,
        }
        .into(),
    );
    transport.stream_receive_window(STREAM_WINDOW.into());
    transport.receive_window((STREAM_WINDOW * MAX_CONCURRENT_REQUESTS as u32).into());
    transport.send_window(u64::from(STREAM_WINDOW) * MAX_CONCURRENT_REQUESTS as u64);
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|_| invalid("DNS idle timeout invalid"))?,
    ));
    transport.keep_alive_interval(None);
    transport.initial_mtu(UDP_PAYLOAD_BYTES as u16);
    transport.min_mtu(UDP_PAYLOAD_BYTES as u16);
    transport.mtu_discovery_config(None);
    transport.pad_to_mtu(true);
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
