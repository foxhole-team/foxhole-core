use std::io;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use foxcore_api::{ContinuityPermit, Hysteria2Config};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::backoff::ReconnectBackoff;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::connection::Hysteria2Conn;
use crate::udp::Hysteria2UdpRelay;

const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(8);
const WAIT_READY_TIMEOUT: Duration = Duration::from_secs(6);

struct Slot {
    epoch: u64,
    connection: Option<Arc<Hysteria2Conn>>,
    udp: Option<Arc<Hysteria2UdpRelay>>,
}

pub struct Hysteria2Session {
    slot: Mutex<Slot>,
    changed: Notify,
    reconnect_now: Notify,
    reconnect_epoch: AtomicU64,
    reconnects: AtomicU64,
    /// Must permit a replacement session before its first dial.
    before_reconnect: OnceLock<Arc<dyn Fn() -> ContinuityPermit + Send + Sync>>,
}

impl Hysteria2Session {
    pub async fn start(
        config: Hysteria2Config,
        dialer: ProtectedDialer,
        cancel: CancellationToken,
        reconnect_hook: Option<Arc<dyn Fn() -> ContinuityPermit + Send + Sync>>,
    ) -> io::Result<Arc<Self>> {
        let connection = connect_server(&config, &dialer).await?;
        let udp = Hysteria2UdpRelay::new(connection.clone());
        let before_reconnect = OnceLock::new();
        if let Some(hook) = reconnect_hook {
            let _ = before_reconnect.set(hook);
        }
        let session = Arc::new(Self {
            slot: Mutex::new(Slot {
                epoch: 0,
                connection: Some(connection),
                udp: Some(udp),
            }),
            changed: Notify::new(),
            reconnect_now: Notify::new(),
            reconnect_epoch: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            before_reconnect,
        });
        tokio::spawn(supervise(session.clone(), config, dialer, cancel));
        Ok(session)
    }

    pub async fn current(&self) -> Option<(Arc<Hysteria2Conn>, Arc<Hysteria2UdpRelay>)> {
        let slot = self.slot.lock().await;
        if slot.epoch != self.reconnect_epoch.load(Ordering::Acquire) {
            return None;
        }
        Some((
            slot.connection.as_ref()?.clone(),
            slot.udp.as_ref()?.clone(),
        ))
    }

    pub async fn wait_ready(&self) -> Option<(Arc<Hysteria2Conn>, Arc<Hysteria2UdpRelay>)> {
        if let Some(ready) = self.current().await {
            return Some(ready);
        }
        let deadline = Instant::now() + WAIT_READY_TIMEOUT;
        loop {
            let notified = self.changed.notified();
            if let Some(ready) = self.current().await {
                return Some(ready);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    pub fn nudge(&self) {
        self.reconnect_epoch.fetch_add(1, Ordering::AcqRel);
        self.reconnect_now.notify_waiters();
    }

    pub fn reconnects(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// Install the pre-reconnect continuity hook.
    pub fn set_reconnect_hook(&self, hook: Arc<dyn Fn() -> ContinuityPermit + Send + Sync>) {
        let _ = self.before_reconnect.set(hook);
    }
}

async fn supervise(
    session: Arc<Hysteria2Session>,
    config: Hysteria2Config,
    dialer: ProtectedDialer,
    cancel: CancellationToken,
) {
    loop {
        let reconnect_now = session.reconnect_now.notified();
        let current = session.current().await.map(|(connection, _)| connection);
        let Some(connection) = current else {
            mark_down(&session).await;
            if !reconnect(&session, &config, &dialer, &cancel).await {
                return;
            }
            continue;
        };

        tokio::select! {
            _ = cancel.cancelled() => {
                mark_down(&session).await;
                return;
            }
            _ = connection.connection().closed() => mark_down(&session).await,
            _ = reconnect_now => mark_down(&session).await,
        }
    }
}

async fn mark_down(session: &Hysteria2Session) {
    let mut slot = session.slot.lock().await;
    if let Some(connection) = slot.connection.take() {
        connection
            .connection()
            .close(quinn::VarInt::from_u32(0), b"Hysteria session invalidated");
    }
    slot.udp = None;
}

async fn reconnect(
    session: &Arc<Hysteria2Session>,
    config: &Hysteria2Config,
    dialer: &ProtectedDialer,
    cancel: &CancellationToken,
) -> bool {
    'permission: loop {
        if let Some(hook) = session.before_reconnect.get() {
            loop {
                let permitted = tokio::select! {
                    _ = cancel.cancelled() => return false,
                    permitted = hook().wait() => permitted,
                };
                if permitted {
                    break;
                }
            }
        }
        let reconnect_epoch = session.reconnect_epoch.load(Ordering::Acquire);
        let mut backoff = ReconnectBackoff::new(BACKOFF_MIN, BACKOFF_MAX);
        loop {
            if cancel.is_cancelled() {
                return false;
            }
            let reconnect_now = session.reconnect_now.notified();
            if session.reconnect_epoch.load(Ordering::Acquire) != reconnect_epoch {
                continue 'permission;
            }
            let connected = tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = reconnect_now => continue 'permission,
                connected = connect_server(config, dialer) => connected,
            };
            match connected {
                Ok(connection) => {
                    let udp = Hysteria2UdpRelay::new(connection.clone());
                    {
                        let mut slot = session.slot.lock().await;
                        if session.reconnect_epoch.load(Ordering::Acquire) != reconnect_epoch {
                            continue 'permission;
                        }
                        slot.epoch = reconnect_epoch;
                        slot.connection = Some(connection);
                        slot.udp = Some(udp);
                    }
                    if session.reconnect_epoch.load(Ordering::Acquire) != reconnect_epoch {
                        mark_down(session).await;
                        continue 'permission;
                    }
                    session.reconnects.fetch_add(1, Ordering::Relaxed);
                    session.changed.notify_waiters();
                    return true;
                }
                Err(_) => {
                    let reconnect_now = session.reconnect_now.notified();
                    if session.reconnect_epoch.load(Ordering::Acquire) != reconnect_epoch {
                        continue 'permission;
                    }
                    tokio::select! {
                        _ = cancel.cancelled() => return false,
                        _ = reconnect_now => continue 'permission,
                        _ = tokio::time::sleep(backoff.next_delay()) => {}
                    }
                }
            }
        }
    }
}

async fn connect_server(
    config: &Hysteria2Config,
    dialer: &ProtectedDialer,
) -> io::Result<Arc<Hysteria2Conn>> {
    let owned_config = config.clone();
    let owned_dialer = dialer.clone();
    dialer
        .connect_server_candidates(
            &config.server,
            config.port,
            config.server_ip,
            move |address| {
                let config = owned_config.clone();
                let dialer = owned_dialer.clone();
                async move { Hysteria2Conn::connect(&config, address, &dialer).await }
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxcore_api::{SecretString, TlsConfig};
    use foxcore_dialer::SocketCallbacks;
    use qpack::{HeaderField, decode_stateless, encode_stateless};
    use quinn::{Connection, Endpoint};
    use rustls_pki_types::PrivatePkcs8KeyDer;

    fn local_server() -> Endpoint {
        local_server_with_control_streams(100)
    }

    fn local_server_with_control_streams(uni_streams: u32) -> Endpoint {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(uni_streams));
        server.transport_config(Arc::new(transport));
        Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    fn local_config(port: u16) -> Hysteria2Config {
        Hysteria2Config {
            server: "localhost".into(),
            port,
            server_ip: None,
            password: SecretString::new("synthetic"),
            up_mbps: 0,
            down_mbps: 0,
            obfs: None,
            server_ports: Vec::new(),
            hop_interval_ms: 30_000,
            keepalive_ms: 100,
            idle_timeout_ms: 30_000,
            tls: TlsConfig {
                enabled: true,
                insecure: true,
                server_name: Some("localhost".into()),
                ..Default::default()
            },
        }
    }

    async fn read_varint(stream: &mut quinn::RecvStream) -> u64 {
        let mut bytes = [0_u8; 8];
        stream.read_exact(&mut bytes[..1]).await.unwrap();
        let length = 1_usize << (bytes[0] >> 6);
        stream.read_exact(&mut bytes[1..length]).await.unwrap();
        crate::varint::decode(&bytes[..length], &mut 0).unwrap()
    }

    async fn authenticate_peer(endpoint: Endpoint) -> Connection {
        let peer = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, mut receive) = peer.accept_bi().await.unwrap();
        assert_eq!(read_varint(&mut receive).await, 1);
        let length = read_varint(&mut receive).await as usize;
        assert!(length <= 16 * 1024);
        let mut request = vec![0_u8; length];
        receive.read_exact(&mut request).await.unwrap();
        let decoded = decode_stateless(&mut &request[..], 16 * 1024).unwrap();
        for (name, value) in [
            (b":method".as_slice(), b"POST".as_slice()),
            (b":path".as_slice(), b"/auth".as_slice()),
            (b"hysteria-auth".as_slice(), b"synthetic".as_slice()),
        ] {
            assert!(
                decoded
                    .fields
                    .iter()
                    .any(|field| { field.name.as_ref() == name && field.value.as_ref() == value })
            );
        }
        let mut headers = Vec::new();
        encode_stateless(
            &mut headers,
            vec![
                HeaderField::new(b":status".to_vec(), b"233".to_vec()),
                HeaderField::new(b"hysteria-udp".to_vec(), b"true".to_vec()),
            ],
        )
        .unwrap();
        let mut response = vec![1];
        crate::varint::encode(headers.len() as u64, &mut response);
        response.extend_from_slice(&headers);
        send.write_all(&response).await.unwrap();
        send.finish().unwrap();
        peer
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn a_blackholed_first_address_does_not_hide_a_working_hysteria_peer() {
        let endpoint = local_server();
        let reachable = endpoint.local_addr().unwrap();
        let black_hole = tokio::net::UdpSocket::bind(("127.0.0.2", reachable.port()))
            .await
            .unwrap();
        let silent = black_hole.local_addr().unwrap();
        let second_black_hole = tokio::net::UdpSocket::bind(("127.0.0.3", reachable.port()))
            .await
            .unwrap();
        let second_silent = second_black_hole.local_addr().unwrap();
        let server = tokio::spawn(authenticate_peer(endpoint.clone()));
        let config = local_config(reachable.port());
        let callbacks = SocketCallbacks::none()
            .with_resolver(move |_, _, _| Ok(vec![silent, second_silent, reachable]));
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1))
            .with_handshake_timeout(Duration::from_secs(1));
        dialer.set_network_handle(1);

        let connection =
            tokio::time::timeout(dialer.handshake_timeout(), connect_server(&config, &dialer))
                .await
                .expect(
                    "the reachable candidate must authenticate within the shared handshake budget",
                )
                .unwrap();
        assert!(connection.udp_enabled);
        let peer = server.await.unwrap();
        peer.close(quinn::VarInt::from_u32(0), b"test complete");
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn a_peer_that_never_answers_authentication_is_bounded_by_the_profile() {
        let endpoint = local_server();
        let reachable = endpoint.local_addr().unwrap();
        let server_endpoint = endpoint.clone();
        let server = tokio::spawn(async move {
            let peer = server_endpoint.accept().await.unwrap().await.unwrap();
            let (_send, _receive) = peer.accept_bi().await.unwrap();
            peer.closed().await;
        });
        let mut config = local_config(reachable.port());
        config.server_ip = Some(reachable.ip());
        let dialer = ProtectedDialer::host().with_handshake_timeout(Duration::from_millis(300));

        let result = tokio::time::timeout(Duration::from_secs(1), connect_server(&config, &dialer))
            .await
            .expect("authentication must share the profile's handshake deadline");
        let Err(error) = result else {
            panic!("a peer that sends no auth response cannot be ready");
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("an expired attempt must close its QUIC connection")
            .unwrap();
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn a_peer_that_never_grants_a_control_stream_is_closed_at_the_deadline() {
        let endpoint = local_server_with_control_streams(0);
        let reachable = endpoint.local_addr().unwrap();
        let server_endpoint = endpoint.clone();
        let server = tokio::spawn(async move {
            let peer = server_endpoint.accept().await.unwrap().await.unwrap();
            peer.closed().await;
        });
        let mut config = local_config(reachable.port());
        config.server_ip = Some(reachable.ip());
        let dialer = ProtectedDialer::host().with_handshake_timeout(Duration::from_millis(300));
        let result = tokio::time::timeout(Duration::from_secs(1), connect_server(&config, &dialer))
            .await
            .expect("HTTP/3 control stream setup must share the handshake deadline");
        let Err(error) = result else {
            panic!("a withheld control stream cannot authenticate");
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("the stalled HTTP/3 connection must be closed")
            .unwrap();
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn dropping_a_hysteria_relay_closes_the_demux_connection() {
        let endpoint = local_server();
        let reachable = endpoint.local_addr().unwrap();
        let server = tokio::spawn(authenticate_peer(endpoint.clone()));
        let connection = Hysteria2Conn::connect(
            &local_config(reachable.port()),
            reachable,
            &ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let relay = Hysteria2UdpRelay::new(connection.clone());
        let peer = server.await.unwrap();
        drop(relay);
        drop(connection);

        tokio::time::timeout(Duration::from_millis(500), peer.closed())
            .await
            .expect("a detached UDP demux must not retain a discarded Hysteria connection");
    }

    #[test]
    fn the_reconnect_window_keeps_the_bounds_the_ladder_had() {
        let mut backoff = ReconnectBackoff::new(BACKOFF_MIN, BACKOFF_MAX);
        for _ in 0..64 {
            let delay = backoff.next_delay();
            assert!((BACKOFF_MIN..=BACKOFF_MAX).contains(&delay), "{delay:?}");
        }
    }
}
