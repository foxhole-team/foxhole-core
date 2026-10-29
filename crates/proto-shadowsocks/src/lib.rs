#![forbid(unsafe_code)]

mod outline;
mod simple_obfs;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use foxcore_api::{Destination, ShadowsocksConfig, StreamTransportConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{
    BoxDatagramSession, BoxStream, Datagram, ServerFirstStream, datagram_channel, establish_stream,
};
use rand::TryRngCore;

use crate::outline::{PrefixedProxyStream, prefixed_salt};
use crate::simple_obfs::SimpleObfsStream;
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use tokio::io::ReadBuf;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ShadowsocksOutbound {
    server: Arc<ServerConfig>,
    context: SharedContext,
    dialer: ProtectedDialer,
    udp: bool,
    method: CipherKind,
    /// The carrier under the codec. Non-`Raw` is a SIP003 `v2ray-plugin`
    /// tunnel expressed natively instead of as a subprocess; `obfs` is the
    /// other SIP003 plugin this core speaks, `simple-obfs`.
    config: Arc<ShadowsocksConfig>,
}

impl ShadowsocksOutbound {
    pub async fn new(config: ShadowsocksConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        let server_address = dialer
            .resolve_server(&config.server, config.port, config.server_ip)
            .await?;
        let method = CipherKind::from_str(&config.method)
            .map_err(|error| invalid(format!("unsupported Shadowsocks method: {error}")))?;
        let server = ServerConfig::new(
            ServerAddr::SocketAddr(server_address),
            config.password.expose(),
            method,
        )
        .map_err(|error| invalid(format!("invalid Shadowsocks configuration: {error}")))?;
        if let Some(prefix) = &config.outline_prefix {
            // Checked once here so an impossible pairing of prefix and cipher
            // is a refused profile rather than a connection that fails later.
            prefixed_salt(method, prefix)?;
        }
        Ok(Self {
            server: Arc::new(server),
            context: Context::new_shared(ServerType::Local),
            dialer,
            udp: config.udp,
            method,
            config: Arc::new(config),
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        // The codec does not care what it rides on, so the carrier is composed
        // first and the Shadowsocks stream is layered over whatever came back.
        let carrier: BoxStream = match &self.config.obfs {
            Some(obfs) => Box::new(SimpleObfsStream::new(tcp, obfs, self.config.port)),
            None => {
                establish_stream(
                    tcp,
                    &self.config.tls,
                    &self.config.transport,
                    &self.config.server,
                    self.config.port,
                )
                .await?
            }
        };
        let Some(prefix) = &self.config.outline_prefix else {
            let stream = ProxyClientStream::from_stream(
                self.context.clone(),
                carrier,
                &self.server,
                to_address(destination),
            );
            // Salt and target address leave on the first write, so a server-first
            // destination — SSH, SMTP, IMAP, FTP, MySQL — would otherwise wait for
            // a banner the Shadowsocks server cannot ask for. `ServerFirstStream`
            // turns the caller's first *read* into the zero-length write that
            // upstream documents as "send the handshake and no payload".
            return Ok(Box::new(ServerFirstStream::new(stream)));
        };
        // A prefixed connection has to *derive* from the salt it sends, so the
        // salt is drawn here and handed to the writer rather than rewritten on
        // the wire afterwards.
        let salt = prefixed_salt(self.method, prefix)?;
        Ok(Box::new(ServerFirstStream::new(PrefixedProxyStream::new(
            self.context.clone(),
            carrier,
            self.method,
            self.server.key(),
            &salt,
            to_address(destination),
        ))))
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is disabled for this Shadowsocks profile",
            ));
        }
        if !matches!(self.config.transport, StreamTransportConfig::Raw)
            || self.config.obfs.is_some()
        {
            // Refused rather than sent around the carrier: a datagram aimed at
            // the plugin's port in the clear is a different protocol than the
            // profile describes, and the port will not answer it anyway.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Shadowsocks over a stream transport carries TCP only",
            ));
        }
        let socket = self
            .dialer
            .connect_udp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Client,
            self.context.clone(),
            &self.server,
            ProtectedUdpSocket(socket),
        );
        let control = if self.config.method.starts_with("2022-") {
            Some(Ss2022UdpState::new()?)
        } else {
            None
        };
        let (session, mut channels) = datagram_channel(64);
        let default_destination = destination.clone();
        let cancel = channels.cancel.clone();
        tokio::spawn(async move {
            relay_datagrams(
                proxy,
                default_destination,
                &mut channels.uplink,
                channels.downlink,
                cancel,
                control,
            )
            .await;
        });
        Ok(session)
    }
}

fn to_address(destination: &Destination) -> Address {
    match destination.ip() {
        Some(ip) => Address::SocketAddress(SocketAddr::new(ip, destination.port)),
        None => Address::DomainNameAddress(destination.host.clone(), destination.port),
    }
}

fn from_address(address: Address) -> Destination {
    match address {
        Address::SocketAddress(address) => {
            Destination::new(address.ip().to_string(), address.port())
        }
        Address::DomainNameAddress(domain, port) => Destination::new(domain, port),
    }
}

const SS2022_REPLAY_BITS: u64 = 1024;
const SS2022_MAX_SERVER_SESSIONS: usize = 64;

#[derive(Default)]
struct Ss2022ReplayWindow {
    highest: Option<u64>,
    seen: [u64; 16],
}

impl Ss2022ReplayWindow {
    fn accept(&mut self, packet: u64) -> bool {
        if let Some(highest) = self.highest {
            if packet > highest {
                if packet - highest >= SS2022_REPLAY_BITS {
                    self.seen.fill(0);
                } else {
                    for expired in highest + 1..=packet {
                        let bit = expired % SS2022_REPLAY_BITS;
                        self.seen[(bit / 64) as usize] &= !(1_u64 << (bit % 64));
                    }
                }
            } else if highest - packet >= SS2022_REPLAY_BITS {
                return false;
            }
        }
        let bit = packet % SS2022_REPLAY_BITS;
        let block = &mut self.seen[(bit / 64) as usize];
        let mask = 1_u64 << (bit % 64);
        if *block & mask != 0 {
            return false;
        }
        *block |= mask;
        self.highest = Some(self.highest.map_or(packet, |old| old.max(packet)));
        true
    }
}

struct Ss2022UdpState {
    client_session_id: u64,
    next_packet_id: Option<u64>,
    replies: HashMap<u64, Ss2022ReplayWindow>,
}

impl Ss2022UdpState {
    fn new() -> io::Result<Self> {
        let client_session_id = rand::rngs::OsRng
            .try_next_u64()
            .map_err(|_| io::Error::other("operating system RNG failed"))?;
        Ok(Self {
            client_session_id,
            next_packet_id: Some(0),
            replies: HashMap::new(),
        })
    }

    fn reserve_packet(&mut self) -> io::Result<UdpSocketControlData> {
        let packet_id = self
            .next_packet_id
            .take()
            .ok_or_else(|| io::Error::other("SS2022 datagram counter is exhausted"))?;
        // Reservation is never rolled back, including after failed/cancelled I/O:
        // using a nonce again would be worse than leaving a gap in the sequence.
        self.next_packet_id = packet_id.checked_add(1);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.packet_id = packet_id;
        Ok(control)
    }

    fn accept_reply(&mut self, control: &UdpSocketControlData) -> io::Result<bool> {
        if control.client_session_id != self.client_session_id {
            return Ok(false);
        }
        if !self.replies.contains_key(&control.server_session_id)
            && self.replies.len() >= SS2022_MAX_SERVER_SESSIONS
        {
            // Evicting an authenticated session would forget its replay window.
            // Close this association at the bound; a fresh association gets a
            // different client identity without accepting old captured packets.
            return Err(io::Error::other("SS2022 reply session bound exceeded"));
        }
        Ok(self
            .replies
            .entry(control.server_session_id)
            .or_default()
            .accept(control.packet_id))
    }
}

async fn relay_datagrams(
    proxy: ProxySocket<ProtectedUdpSocket>,
    default_destination: Destination,
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
    mut control: Option<Ss2022UdpState>,
) {
    let mut receive_buffer = vec![0_u8; 65_536];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            outgoing = uplink.recv() => {
                let Some(outgoing) = outgoing else { break };
                let destination = if outgoing.destination.host.is_empty() {
                    &default_destination
                } else {
                    &outgoing.destination
                };
                let sent = if let Some(state) = &mut control {
                    let Ok(packet) = state.reserve_packet() else { break };
                    proxy.send_with_ctrl(&to_address(destination), &packet, &outgoing.payload).await
                } else {
                    proxy.send(&to_address(destination), &outgoing.payload).await
                };
                if sent.is_err() {
                    break;
                }
            }
            received = proxy.recv_with_ctrl(&mut receive_buffer) => {
                let Ok((length, address, _wire_length, packet)) = received else { break };
                if let Some(state) = &mut control {
                    let Some(packet) = packet else { break };
                    match state.accept_reply(&packet) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(_) => break,
                    }
                }
                let datagram = Datagram::new(
                    from_address(address),
                    Bytes::copy_from_slice(&receive_buffer[..length]),
                );
                if downlink.send(datagram).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[derive(Debug)]
struct ProtectedUdpSocket(tokio::net::UdpSocket);

impl DatagramSocket for ProtectedUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl DatagramReceive for ProtectedUdpSocket {
    fn poll_recv(
        &self,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0.poll_recv(context, buffer)
    }

    fn poll_recv_from(
        &self,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.0.poll_recv_from(context, buffer)
    }

    fn poll_recv_ready(&self, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.poll_recv_ready(context)
    }
}

impl DatagramSend for ProtectedUdpSocket {
    fn poll_send(&self, context: &mut TaskContext<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(context, buffer)
    }

    fn poll_send_to(
        &self,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send_to(context, buffer, target)
    }

    fn poll_send_ready(&self, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.poll_send_ready(context)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_address_roundtrips() {
        let destinations = [
            Destination::new("example.com", 443),
            Destination::new("1.2.3.4", 53),
            Destination::new("2001:db8::1", 853),
        ];
        for destination in destinations {
            assert_eq!(from_address(to_address(&destination)), destination);
        }
    }

    #[test]
    fn known_aead_methods_parse() {
        assert!(CipherKind::from_str("aes-128-gcm").is_ok());
        assert!(CipherKind::from_str("2022-blake3-aes-128-gcm").is_ok());
    }

    #[tokio::test]
    async fn ss2022_udp_uses_one_session_and_advancing_packet_counters() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use std::time::Duration;

        for (name, key_len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
            ("2022-blake3-chacha20-poly1305", 32),
        ] {
            let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
            let address = socket.local_addr().unwrap();
            let password = STANDARD.encode(vec![7_u8; key_len]);
            let method = CipherKind::from_str(name).unwrap();
            let server =
                ServerConfig::new(ServerAddr::SocketAddr(address), &password, method).unwrap();
            let peer = ProxySocket::from_socket(
                UdpSocketType::Server,
                Context::new_shared(ServerType::Server),
                &server,
                ProtectedUdpSocket(socket),
            );
            let mut config = profile(address.port());
            config.method = name.to_owned();
            config.password = foxcore_api::SecretString::new(password);
            config.udp = true;
            let outbound = ShadowsocksOutbound::new(config, ProtectedDialer::host())
                .await
                .unwrap();
            let destination = Destination::new("127.0.0.1", 19003);
            let session = outbound.connect_datagram(&destination).await.unwrap();
            let mut controls = Vec::new();
            for length in [1_usize, 31] {
                let payload = vec![length as u8; length];
                session
                    .send(Datagram::new(destination.clone(), payload.clone()))
                    .await
                    .unwrap();
                let mut buffer = [0_u8; 4096];
                let (count, _, target, _, control) = tokio::time::timeout(
                    Duration::from_secs(2),
                    peer.recv_from_with_ctrl(&mut buffer),
                )
                .await
                .expect("actual encrypted datagram reached the reference decryptor")
                .unwrap();
                assert_eq!(&buffer[..count], payload);
                assert_eq!(from_address(target), destination);
                let control = control.expect("SS2022 carries actual session/counter fields");
                controls.push((control.client_session_id, control.packet_id));
            }
            assert_eq!(
                controls[0].0, controls[1].0,
                "one datagram session identity"
            );
            assert_eq!(
                controls[1].1,
                controls[0].1.checked_add(1).unwrap(),
                "the next real SS2022 datagram must not replay the first packet id",
            );
        }
    }

    #[tokio::test]
    async fn ss2022_udp_independent_sessions_have_distinct_client_ids() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use std::time::Duration;

        for (name, key_len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
            ("2022-blake3-chacha20-poly1305", 32),
        ] {
            let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
            let address = socket.local_addr().unwrap();
            let password = STANDARD.encode(vec![7_u8; key_len]);
            let method = CipherKind::from_str(name).unwrap();
            let server =
                ServerConfig::new(ServerAddr::SocketAddr(address), &password, method).unwrap();
            let peer = ProxySocket::from_socket(
                UdpSocketType::Server,
                Context::new_shared(ServerType::Server),
                &server,
                ProtectedUdpSocket(socket),
            );
            let mut config = profile(address.port());
            config.method = name.to_owned();
            config.password = foxcore_api::SecretString::new(password);
            config.udp = true;
            let outbound = ShadowsocksOutbound::new(config, ProtectedDialer::host())
                .await
                .unwrap();
            let destination = Destination::new("127.0.0.1", 19003);
            let first = outbound.connect_datagram(&destination).await.unwrap();
            let second = outbound.connect_datagram(&destination).await.unwrap();
            let mut session_ids = Vec::new();
            for (session, byte) in [(&first, 11_u8), (&second, 12_u8)] {
                session
                    .send(Datagram::new(destination.clone(), vec![byte]))
                    .await
                    .unwrap();
                let mut buffer = [0_u8; 4096];
                let (count, _, target, _, control) = tokio::time::timeout(
                    Duration::from_secs(2),
                    peer.recv_from_with_ctrl(&mut buffer),
                )
                .await
                .expect("independent actual session reached the reference decryptor")
                .unwrap();
                assert_eq!(&buffer[..count], &[byte]);
                assert_eq!(from_address(target), destination);
                session_ids.push(control.unwrap().client_session_id);
            }
            assert_ne!(
                session_ids[0], session_ids[1],
                "independent sessions must not reuse the AES session key and packet nonce",
            );
        }
    }

    struct UdpReferencePeer {
        session: BoxDatagramSession,
        proxy: ProxySocket<ProtectedUdpSocket>,
        client: SocketAddr,
        control: UdpSocketControlData,
        destination: Destination,
    }

    async fn udp_reference_peer(method: &str) -> UdpReferencePeer {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use std::time::Duration;

        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let cipher = CipherKind::from_str(method).unwrap();
        let password = if method.starts_with("2022-") {
            STANDARD.encode(vec![7_u8; if method.contains("aes-128") { 16 } else { 32 }])
        } else {
            "synthetic-udp-password".to_owned()
        };
        let server = ServerConfig::new(ServerAddr::SocketAddr(address), &password, cipher).unwrap();
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &server,
            ProtectedUdpSocket(socket),
        );
        let mut config = profile(address.port());
        config.method = method.to_owned();
        config.password = foxcore_api::SecretString::new(password);
        config.udp = true;
        let outbound = ShadowsocksOutbound::new(config, ProtectedDialer::host())
            .await
            .unwrap();
        let destination = Destination::new("127.0.0.1", 19003);
        let session = outbound.connect_datagram(&destination).await.unwrap();
        session
            .send(Datagram::new(destination.clone(), vec![13]))
            .await
            .unwrap();
        let mut buffer = [0_u8; 4096];
        let (count, client, target, _, control) = tokio::time::timeout(
            Duration::from_secs(2),
            proxy.recv_from_with_ctrl(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..count], &[13]);
        assert_eq!(from_address(target), destination);
        UdpReferencePeer {
            session,
            proxy,
            client,
            control: control.unwrap_or_default(),
            destination,
        }
    }

    async fn reference_reply(
        peer: &UdpReferencePeer,
        client_id: u64,
        server_id: u64,
        packet_id: u64,
        destination: &Destination,
        payload: &[u8],
    ) {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = client_id;
        control.server_session_id = server_id;
        control.packet_id = packet_id;
        peer.proxy
            .send_to_with_ctrl(peer.client, &to_address(destination), &control, payload)
            .await
            .unwrap();
    }

    async fn receive_reply(peer: &UdpReferencePeer) -> Datagram {
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.session.recv())
            .await
            .expect("accepted authenticated reply reached the actual session")
            .unwrap()
    }

    #[tokio::test]
    async fn ss2022_udp_rejects_wrong_client_and_replay_preserving_reordered_destinations() {
        for method in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let peer = udp_reference_peer(method).await;
            let client_id = peer.control.client_session_id;
            let other = Destination::new("127.0.0.1", 19004);
            reference_reply(
                &peer,
                client_id.wrapping_add(1),
                11,
                50,
                &peer.destination,
                b"wrong-client",
            )
            .await;
            reference_reply(&peer, client_id, 9, 2, &peer.destination, b"two").await;
            let first = receive_reply(&peer).await;
            assert_eq!(first.payload.as_ref(), b"two");
            assert_eq!(first.destination, peer.destination);
            reference_reply(&peer, client_id, 9, 1, &other, b"one").await;
            let second = receive_reply(&peer).await;
            assert_eq!(second.payload.as_ref(), b"one");
            assert_eq!(second.destination, other);
            reference_reply(&peer, client_id, 9, 2, &peer.destination, b"duplicate").await;
            reference_reply(&peer, client_id, 9, 0, &peer.destination, b"zero").await;
            assert_eq!(receive_reply(&peer).await.payload.as_ref(), b"zero");
            // Packet zero is valid in a different authenticated server session.
            reference_reply(&peer, client_id, 10, 0, &other, b"second-server-session").await;
            let next = receive_reply(&peer).await;
            assert_eq!(next.payload.as_ref(), b"second-server-session");
            assert_eq!(next.destination, other);
        }
    }

    #[tokio::test]
    async fn ss2022_udp_discards_stale_packets_but_keeps_recent_reordering() {
        let peer = udp_reference_peer("2022-blake3-aes-128-gcm").await;
        let id = peer.control.client_session_id;
        reference_reply(&peer, id, 9, 1500, &peer.destination, b"highest").await;
        assert_eq!(receive_reply(&peer).await.payload.as_ref(), b"highest");
        reference_reply(&peer, id, 9, 0, &peer.destination, b"stale").await;
        reference_reply(&peer, id, 9, 1499, &peer.destination, b"reordered").await;
        assert_eq!(receive_reply(&peer).await.payload.as_ref(), b"reordered");
    }

    #[tokio::test]
    async fn ss2022_udp_reply_session_bound_closes_without_eviction() {
        let peer = udp_reference_peer("2022-blake3-aes-128-gcm").await;
        let id = peer.control.client_session_id;
        for server in 1000..1064 {
            reference_reply(&peer, id, server, 0, &peer.destination, b"accepted").await;
            assert_eq!(receive_reply(&peer).await.payload.as_ref(), b"accepted");
        }
        reference_reply(&peer, id, 1064, 0, &peer.destination, b"over-limit").await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), peer.session.recv())
                .await
                .expect("bounded association terminates instead of forgetting replay state")
                .is_err()
        );
    }

    #[tokio::test]
    async fn ss2022_udp_counter_exhaustion_never_wraps_on_the_wire() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use std::time::Duration;

        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let password = STANDARD.encode([7_u8; 16]);
        let method = CipherKind::from_str("2022-blake3-aes-128-gcm").unwrap();
        let server = ServerConfig::new(ServerAddr::SocketAddr(address), &password, method).unwrap();
        let client_socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client_socket.connect(address).await.unwrap();
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Client,
            Context::new_shared(ServerType::Local),
            &server,
            ProtectedUdpSocket(client_socket),
        );
        let peer = ProxySocket::from_socket(
            UdpSocketType::Server,
            Context::new_shared(ServerType::Server),
            &server,
            ProtectedUdpSocket(socket),
        );
        let (session, mut channels) = datagram_channel(4);
        let destination = Destination::new("127.0.0.1", 19003);
        let mut state = Ss2022UdpState::new().unwrap();
        state.next_packet_id = Some(u64::MAX);
        let cancel = channels.cancel.clone();
        let expected = destination.clone();
        let task = tokio::spawn(async move {
            relay_datagrams(
                proxy,
                expected,
                &mut channels.uplink,
                channels.downlink,
                cancel,
                Some(state),
            )
            .await;
        });
        session
            .send(Datagram::new(destination.clone(), vec![1]))
            .await
            .unwrap();
        let mut buffer = [0_u8; 4096];
        let (count, _, _, _, control) = tokio::time::timeout(
            Duration::from_secs(2),
            peer.recv_from_with_ctrl(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..count], &[1]);
        assert_eq!(control.unwrap().packet_id, u64::MAX);
        session
            .send(Datagram::new(destination, vec![2]))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), session.recv())
                .await
                .unwrap()
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                peer.recv_from_with_ctrl(&mut buffer)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn basic_aead_udp_replies_keep_existing_wire_behavior() {
        for method in ["chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"] {
            let peer = udp_reference_peer(method).await;
            reference_reply(&peer, 0, 0, 0, &peer.destination, b"basic-aead").await;
            assert_eq!(receive_reply(&peer).await.payload.as_ref(), b"basic-aead");
        }
    }

    fn profile(port: u16) -> ShadowsocksConfig {
        ShadowsocksConfig {
            server: "127.0.0.1".into(),
            port,
            server_ip: None,
            method: "chacha20-ietf-poly1305".into(),
            password: foxcore_api::SecretString::new("hunter2"),
            udp: false,
            transport: StreamTransportConfig::Raw,
            tls: Default::default(),
            outline_prefix: None,
            obfs: None,
        }
    }

    /// Open one connection through the real outbound and hand back what
    /// actually arrived at the far end. The module tests prove each carrier in
    /// isolation; this proves the config field reaches the socket.
    async fn first_bytes_on_the_wire(config: ShadowsocksConfig, count: usize) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            let mut head = vec![0_u8; count];
            server.read_exact(&mut head).await.unwrap();
            head
        });

        let outbound = ShadowsocksOutbound::new(
            ShadowsocksConfig { port, ..config },
            foxcore_dialer::ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"payload").await.unwrap();
        stream.flush().await.unwrap();
        accept.await.unwrap()
    }

    #[tokio::test]
    async fn an_outline_profile_opens_the_connection_with_its_prefix() {
        let head = first_bytes_on_the_wire(
            ShadowsocksConfig {
                outline_prefix: Some(b"POST ".to_vec()),
                ..profile(0)
            },
            5,
        )
        .await;
        assert_eq!(head, b"POST ");
    }

    #[tokio::test]
    async fn a_simple_obfs_profile_opens_the_connection_with_its_disguise() {
        let head = first_bytes_on_the_wire(
            ShadowsocksConfig {
                obfs: Some(foxcore_api::SimpleObfsConfig::Tls {
                    host: "www.bing.com".into(),
                }),
                ..profile(0)
            },
            3,
        )
        .await;
        assert_eq!(head, &[0x16, 0x03, 0x01]);

        let head = first_bytes_on_the_wire(
            ShadowsocksConfig {
                obfs: Some(foxcore_api::SimpleObfsConfig::Http {
                    host: "www.bing.com".into(),
                    uri: "/".into(),
                    method: "GET".into(),
                }),
                ..profile(0)
            },
            16,
        )
        .await;
        assert_eq!(&head, b"GET / HTTP/1.1\r\n");
    }

    /// Open a connection through the real outbound, read before writing
    /// anything, and hand back the plaintext a Shadowsocks server would see.
    ///
    /// Nothing is ever written by the caller, so whatever the server decrypts
    /// is the request header and nothing else.
    async fn opening_payload_when_the_caller_reads_first(config: ShadowsocksConfig) -> Vec<u8> {
        use shadowsocks::relay::tcprelay::crypto_io::{CryptoRead, CryptoStream, StreamType};
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let method = CipherKind::from_str(&config.method).unwrap();
        let password = config.password.expose().to_owned();
        let accept = tokio::spawn(async move {
            let (server, _) = listener.accept().await.unwrap();
            let context = Context::new_shared(ServerType::Server);
            let server_config = ServerConfig::new(
                ServerAddr::SocketAddr(SocketAddr::from(([127, 0, 0, 1], 1))),
                password,
                method,
            )
            .unwrap();
            let mut crypto = CryptoStream::from_stream(
                &context,
                server,
                StreamType::Server,
                method,
                server_config.key(),
            );
            let mut buffer = vec![0_u8; 512];
            let mut read = ReadBuf::new(&mut buffer);
            std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut crypto).poll_read_decrypted(cx, &context, &mut read)
            })
            .await
            .unwrap();
            read.filled().to_vec()
        });

        let outbound = ShadowsocksOutbound::new(
            ShadowsocksConfig { port, ..config },
            foxcore_dialer::ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        // The caller reads and never writes, which is every protocol whose
        // server sends the banner.
        let reader = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        let payload = tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("a server-first destination must not deadlock")
            .unwrap();
        reader.abort();
        payload
    }

    /// The deadlock this closes: salt and target address only ever left on an
    /// application *write*, so SSH, SMTP, IMAP, FTP and MySQL through a
    /// Shadowsocks profile hung with zero bytes on the wire — the client waiting
    /// for a banner and the server waiting to be told where to connect.
    #[tokio::test]
    async fn a_caller_that_reads_first_still_sends_salt_and_target_address() {
        let mut expected = bytes::BytesMut::new();
        Address::DomainNameAddress("example.com".to_owned(), 443).write_to_buf(&mut expected);

        assert_eq!(
            opening_payload_when_the_caller_reads_first(profile(0)).await,
            &expected[..]
        );

        // The Outline variant runs its own stream type, so it needs its own
        // proof rather than inheriting this one.
        assert_eq!(
            opening_payload_when_the_caller_reads_first(ShadowsocksConfig {
                outline_prefix: Some(b"POST ".to_vec()),
                ..profile(0)
            })
            .await,
            &expected[..]
        );
    }

    /// Without a prefix nothing about the existing path changes, including the
    /// salt being drawn by the crate rather than by us.
    #[tokio::test]
    async fn a_plain_profile_still_opens_with_a_random_salt() {
        let first = first_bytes_on_the_wire(profile(0), 32).await;
        let second = first_bytes_on_the_wire(profile(0), 32).await;
        assert_ne!(first, second);
    }
}
