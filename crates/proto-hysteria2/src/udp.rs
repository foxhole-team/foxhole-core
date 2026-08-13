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
}
