use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use foxcore_api::Destination;
use foxcore_transport::{BoxDatagramSession, Datagram, DatagramChannelIo, datagram_channel};
use quinn::Connection;

use crate::connection::Hysteria2Conn;
use crate::{codec, varint};

const MAX_PARTIAL_PACKETS: usize = 256;
const MAX_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;
const REASSEMBLY_TTL: Duration = Duration::from_secs(10);

type Sessions = Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Datagram>>>>;

pub struct Hysteria2UdpRelay {
    connection: Arc<Hysteria2Conn>,
    sessions: Sessions,
    next_session: AtomicU32,
}

impl Hysteria2UdpRelay {
    pub fn new(connection: Arc<Hysteria2Conn>) -> Arc<Self> {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(demux_loop(
            connection.connection().clone(),
            sessions.clone(),
        ));
        Arc::new(Self {
            connection,
            sessions,
            next_session: AtomicU32::new(1),
        })
    }

    pub fn open_session(self: &Arc<Self>, default_destination: Destination) -> BoxDatagramSession {
        let session_id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let (session, channels) = datagram_channel(64);
        self.sessions
            .lock()
            // A poisoned lock means some other task panicked while holding it.
            // The map itself is still consistent, and refusing every later
            // datagram over someone else's panic helps nobody.
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session_id, channels.downlink.clone());

        let connection = self.connection.connection().clone();
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            run_uplink(connection, session_id, default_destination, channels).await;
            sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&session_id);
        });
        session
    }
}

async fn run_uplink(
    connection: Connection,
    session_id: u32,
    default_destination: Destination,
    mut channels: DatagramChannelIo,
) {
    let mut packet_id = 0_u16;
    loop {
        tokio::select! {
            _ = channels.cancel.cancelled() => break,
            _ = connection.closed() => break,
            outgoing = channels.uplink.recv() => {
                let Some(outgoing) = outgoing else { break };
                let destination = if outgoing.destination.host.is_empty() {
                    &default_destination
                } else {
                    &outgoing.destination
                };
                if send_datagram(
                    &connection,
                    session_id,
                    packet_id,
                    destination,
                    &outgoing.payload,
                )
                .is_err()
                {
                    break;
                }
                packet_id = packet_id.wrapping_add(1);
            }
        }
    }
}

fn send_datagram(
    connection: &Connection,
    session_id: u32,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
) -> io::Result<()> {
    let max = connection
        .max_datagram_size()
        .ok_or_else(|| io::Error::other("peer does not accept QUIC datagrams"))?;
    let address_length = destination.authority().len();
    let overhead = 8 + varint::encoded_len(address_length as u64) + address_length;
    if overhead >= max {
        return Err(io::Error::other(
            "QUIC datagram limit is too small for Hysteria2 header",
        ));
    }
    let chunk_capacity = max - overhead;
    let fragment_count = payload.len().div_ceil(chunk_capacity).max(1);
    if fragment_count > codec::MAX_UDP_FRAGMENTS as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP payload needs too many Hysteria2 fragments",
        ));
    }

    if payload.is_empty() {
        send_fragment(
            connection,
            session_id,
            packet_id,
            destination,
            0,
            1,
            &[],
            overhead,
        )?;
        return Ok(());
    }

    for (fragment, chunk) in payload.chunks(chunk_capacity).enumerate() {
        send_fragment(
            connection,
            session_id,
            packet_id,
            destination,
            fragment as u8,
            fragment_count as u8,
            chunk,
            overhead,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send_fragment(
    connection: &Connection,
    session_id: u32,
    packet_id: u16,
    destination: &Destination,
    fragment_id: u8,
    fragment_count: u8,
    chunk: &[u8],
    overhead: usize,
) -> io::Result<()> {
    let mut encoded = Vec::with_capacity(overhead + chunk.len());
    codec::encode_udp_datagram(
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        destination,
        chunk,
        &mut encoded,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    connection
        .send_datagram(encoded.into())
        .map_err(|error| io::Error::other(format!("send QUIC datagram: {error}")))?;
    Ok(())
}

async fn demux_loop(connection: Connection, sessions: Sessions) {
    let mut reassembly: HashMap<(u32, u16), Reassembly> = HashMap::new();
    while let Ok(encoded) = connection.read_datagram().await {
        let Ok(datagram) = codec::decode_udp_datagram(&encoded) else {
            continue;
        };
        let payload = if datagram.frag_count <= 1 {
            Some(datagram.payload.to_vec())
        } else {
            reassemble(
                &mut reassembly,
                datagram.session_id,
                datagram.packet_id,
                datagram.frag_id,
                datagram.frag_count,
                datagram.payload,
            )
        };
        let Some(payload) = payload else {
            continue;
        };
        let destination = parse_authority(&datagram.destination)
            .unwrap_or_else(|| Destination::new(datagram.destination.clone(), 0));
        if let Some(sender) = sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&datagram.session_id)
        {
            let _ = sender.try_send(Datagram::new(destination, Bytes::from(payload)));
        }
    }
}

fn parse_authority(authority: &str) -> Option<Destination> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, port) = stripped.rsplit_once("]:")?;
        return Some(Destination::new(host, port.parse().ok()?));
    }
    let (host, port) = authority.rsplit_once(':')?;
    Some(Destination::new(host, port.parse().ok()?))
}

struct Reassembly {
    fragments: Vec<Option<Vec<u8>>>,
    remaining: usize,
    buffered_bytes: usize,
    created_at: Instant,
}

fn reassemble(
    map: &mut HashMap<(u32, u16), Reassembly>,
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let now = Instant::now();
    map.retain(|_, partial| now.duration_since(partial.created_at) <= REASSEMBLY_TTL);
    let buffered_bytes: usize = map.values().map(|partial| partial.buffered_bytes).sum();
    if buffered_bytes.saturating_add(payload.len()) > MAX_REASSEMBLY_BYTES {
        map.clear();
    }
    let key = (session_id, packet_id);
    if map.len() >= MAX_PARTIAL_PACKETS && !map.contains_key(&key) {
        map.clear();
    }
    let entry = map.entry(key).or_insert_with(|| Reassembly {
        fragments: vec![None; fragment_count as usize],
        remaining: fragment_count as usize,
        buffered_bytes: 0,
        created_at: now,
    });
    if entry.fragments.len() != fragment_count as usize {
        map.remove(&key);
        return None;
    }
    let index = fragment_id as usize;
    if index < entry.fragments.len() && entry.fragments[index].is_none() {
        entry.fragments[index] = Some(payload.to_vec());
        entry.remaining -= 1;
        entry.buffered_bytes = entry.buffered_bytes.saturating_add(payload.len());
    }
    if entry.remaining != 0 {
        return None;
    }
    let complete = map.remove(&key)?;
    Some(complete.fragments.into_iter().flatten().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxcore_api::{Hysteria2Config, SecretString, TlsConfig};
    use qpack::{HeaderField, decode_stateless, encode_stateless};
    use quinn::{Connection, Endpoint};
    use rustls_pki_types::PrivatePkcs8KeyDer;

    #[test]
    fn authority_parser_handles_domain_and_ipv6() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(Destination::new("example.com", 443))
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:853"),
            Some(Destination::new("2001:db8::1", 853))
        );
    }

    #[test]
    fn reassembles_out_of_order_fragments() {
        let mut map = HashMap::new();
        assert_eq!(reassemble(&mut map, 7, 9, 1, 2, b"b"), None);
        assert_eq!(reassemble(&mut map, 7, 9, 0, 2, b"a"), Some(b"ab".to_vec()));
    }
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

    async fn authenticated_outbound() -> (crate::Hysteria2Outbound, Endpoint, Connection) {
        let endpoint = local_server();
        let port = endpoint.local_addr().unwrap().port();
        let server = tokio::spawn(authenticate_peer(endpoint.clone()));
        let mut config = local_config(port);
        config.server_ip = Some(endpoint.local_addr().unwrap().ip());
        let outbound = tokio::time::timeout(
            Duration::from_secs(2),
            crate::Hysteria2Outbound::new(config, foxcore_dialer::ProtectedDialer::host()),
        )
        .await
        .expect("local client must authenticate")
        .unwrap();
        let peer = server.await.unwrap();
        (outbound, endpoint, peer)
    }

    async fn wait_session_count(relay: &Hysteria2UdpRelay, count: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if relay.sessions.lock().unwrap().len() == count {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session registration must settle");
    }

    async fn assert_datagram_echo(session: &BoxDatagramSession, peer: &Connection, body: &[u8]) {
        let target = Destination::new("127.0.0.1", 28054);
        session
            .send(Datagram::new(target.clone(), body.to_vec()))
            .await
            .unwrap();
        let encoded = tokio::time::timeout(Duration::from_secs(1), peer.read_datagram())
            .await
            .expect("live session must send a real QUIC datagram")
            .unwrap();
        peer.send_datagram(encoded).unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(1), session.recv())
            .await
            .expect("live session must receive its datagram")
            .unwrap();
        assert_eq!(reply.destination, target);
        assert_eq!(reply.payload.as_ref(), body);
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn closed_outbound_wakes_retained_udp_receiver_and_deregisters_session() {
        let (outbound, _endpoint, peer) = authenticated_outbound().await;
        let (_, relay) = outbound.session.current().await.unwrap();
        let session = outbound
            .connect_datagram(&Destination::new("127.0.0.1", 28054))
            .await
            .unwrap();
        assert_datagram_echo(&session, &peer, b"before-owner-drop").await;
        assert_eq!(relay.sessions.lock().unwrap().len(), 1);
        let mut pending = Box::pin(session.recv());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pending.as_mut())
                .await
                .is_err()
        );
        drop(outbound);
        let close = tokio::time::timeout(Duration::from_secs(1), peer.closed())
            .await
            .expect("unique outbound owner must close its authenticated QUIC connection");
        assert!(close.to_string().contains("Hysteria session invalidated"));
        let error = tokio::time::timeout(Duration::from_secs(1), pending.as_mut())
            .await
            .expect("a closed QUIC owner must wake a retained UDP receiver")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(error.to_string(), "datagram downlink is closed");
        wait_session_count(&relay, 0).await;
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn dropped_udp_session_deregisters_without_closing_other_live_sessions() {
        let (outbound, _endpoint, peer) = authenticated_outbound().await;
        let (_, relay) = outbound.session.current().await.unwrap();
        let target = Destination::new("127.0.0.1", 28054);
        let dropped = outbound.connect_datagram(&target).await.unwrap();
        let retained = outbound.connect_datagram(&target).await.unwrap();
        assert_eq!(relay.sessions.lock().unwrap().len(), 2);
        let weak = Arc::downgrade(&dropped);
        drop(dropped);
        assert!(weak.upgrade().is_none());
        wait_session_count(&relay, 1).await;
        assert_datagram_echo(&retained, &peer, b"other-session-still-live").await;
        drop(retained);
        wait_session_count(&relay, 0).await;
        drop(outbound);
        tokio::time::timeout(Duration::from_secs(1), peer.closed())
            .await
            .unwrap();
    }

    #[cfg_attr(miri, ignore = "requires QUIC sockets")]
    #[tokio::test]
    async fn reconnect_deregisters_old_udp_sessions_and_preserves_replacement_traffic() {
        let (outbound, endpoint, old_peer) = authenticated_outbound().await;
        let (_, old_relay) = outbound.session.current().await.unwrap();
        let target = Destination::new("127.0.0.1", 28054);
        let old_session = outbound.connect_datagram(&target).await.unwrap();
        assert_datagram_echo(&old_session, &old_peer, b"before-reconnect").await;
        let server = tokio::spawn(authenticate_peer(endpoint.clone()));
        outbound.network_changed();
        tokio::time::timeout(Duration::from_secs(1), old_peer.closed())
            .await
            .expect("network replacement must close the old QUIC owner");
        let error = tokio::time::timeout(Duration::from_secs(1), old_session.recv())
            .await
            .expect("old UDP receive must settle after its QUIC connection closes")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        wait_session_count(&old_relay, 0).await;
        let replacement = outbound.connect_datagram(&target).await.unwrap();
        let new_peer = server.await.unwrap();
        assert_datagram_echo(&replacement, &new_peer, b"replacement-session-live").await;
        let (_, new_relay) = outbound.session.current().await.unwrap();
        assert_eq!(new_relay.sessions.lock().unwrap().len(), 1);
        drop(replacement);
        wait_session_count(&new_relay, 0).await;
        drop(outbound);
        tokio::time::timeout(Duration::from_secs(1), new_peer.closed())
            .await
            .unwrap();
    }
}
