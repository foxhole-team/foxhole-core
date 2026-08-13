use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use foxcore_api::{Destination, TuicUdpRelayMode};
use foxcore_transport::{BoxDatagramSession, Datagram, DatagramChannelIo, datagram_channel};
use quinn::Connection;

use crate::codec;
use crate::connection::TuicConnection;

const MAX_ASSOCIATIONS: usize = 1_024;
const MAX_PARTIAL_PACKETS: usize = 256;
const MAX_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;
const REASSEMBLY_TTL: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const DISSOCIATE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PACKET_FRAME: usize = 10 + 1 + 1 + u8::MAX as usize + 2 + u16::MAX as usize;

type Sessions = Arc<Mutex<HashMap<u16, tokio::sync::mpsc::Sender<Datagram>>>>;

pub struct TuicUdpRelay {
    connection: Arc<TuicConnection>,
    mode: TuicUdpRelayMode,
    sessions: Sessions,
    next_association: AtomicU16,
}

impl TuicUdpRelay {
    pub fn new(connection: Arc<TuicConnection>, mode: TuicUdpRelayMode) -> Arc<Self> {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        match mode {
            TuicUdpRelayMode::Native => {
                tokio::spawn(datagram_demux(
                    connection.connection().clone(),
                    sessions.clone(),
                ));
            }
            TuicUdpRelayMode::Quic => {
                tokio::spawn(stream_demux(
                    connection.connection().clone(),
                    sessions.clone(),
                ));
                // Heartbeats are QUIC datagrams even in stream relay mode.
                // Drain them so an untrusted peer cannot fill the bounded
                // datagram receive buffer indefinitely.
                tokio::spawn(datagram_drain(connection.connection().clone()));
            }
        }
        Arc::new(Self {
            connection,
            mode,
            sessions,
            next_association: AtomicU16::new(1),
        })
    }

    pub fn open_session(
        self: &Arc<Self>,
        default_destination: Destination,
    ) -> io::Result<BoxDatagramSession> {
        let (session, channels) = datagram_channel(64);
        let association_id = {
            let mut sessions = lock(&self.sessions);
            if sessions.len() >= MAX_ASSOCIATIONS {
                return Err(io::Error::other(
                    "TUIC UDP association limit has been reached",
                ));
            }
            let mut selected = None;
            for _ in 0..=u16::MAX {
                let candidate = self.next_association.fetch_add(1, Ordering::Relaxed);
                if let std::collections::hash_map::Entry::Vacant(entry) = sessions.entry(candidate)
                {
                    entry.insert(channels.downlink.clone());
                    selected = Some(candidate);
                    break;
                }
            }
            selected.ok_or_else(|| io::Error::other("no TUIC UDP association id available"))?
        };

        let connection = self.connection.connection().clone();
        let sessions = self.sessions.clone();
        let mode = self.mode;
        tokio::spawn(async move {
            run_uplink(
                connection.clone(),
                mode,
                association_id,
                default_destination,
                channels,
            )
            .await;
            lock(&sessions).remove(&association_id);
            let _ = tokio::time::timeout(
                DISSOCIATE_TIMEOUT,
                send_dissociate(&connection, association_id),
            )
            .await;
        });
        Ok(session)
    }
}

async fn run_uplink(
    connection: Connection,
    mode: TuicUdpRelayMode,
    association_id: u16,
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
                let result = tokio::time::timeout(
                    SEND_TIMEOUT,
                    send_packet(
                        &connection,
                        mode,
                        association_id,
                        packet_id,
                        destination,
                        &outgoing.payload,
                    ),
                )
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    break;
                }
                packet_id = packet_id.wrapping_add(1);
            }
        }
    }
    channels.cancel.cancel();
}

async fn send_packet(
    connection: &Connection,
    mode: TuicUdpRelayMode,
    association_id: u16,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > codec::MAX_UDP_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUIC UDP payload exceeds 65535 bytes",
        ));
    }
    match mode {
        TuicUdpRelayMode::Native => {
            send_native(connection, association_id, packet_id, destination, payload).await
        }
        TuicUdpRelayMode::Quic => {
            let mut encoded = Vec::with_capacity(10 + destination.host.len() + payload.len());
            codec::encode_packet(
                association_id,
                packet_id,
                1,
                0,
                Some(destination),
                payload,
                &mut encoded,
            )
            .map_err(codec_io)?;
            send_stream_frame(connection, &encoded).await
        }
    }
}

async fn send_native(
    connection: &Connection,
    association_id: u16,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
) -> io::Result<()> {
    let maximum = connection
        .max_datagram_size()
        .ok_or_else(|| io::Error::other("TUIC peer does not accept QUIC datagrams"))?;
    let first_header = 10 + codec::encoded_address_len(Some(destination)).map_err(codec_io)?;
    if maximum <= first_header {
        return Err(io::Error::other(
            "QUIC datagram limit is too small for a TUIC packet header",
        ));
    }
    let chunk_capacity = maximum - first_header;
    let fragment_count = payload.len().div_ceil(chunk_capacity).max(1);
    if fragment_count > codec::MAX_FRAGMENTS as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUIC UDP payload needs too many fragments",
        ));
    }

    if payload.is_empty() {
        return send_native_fragment(
            connection,
            association_id,
            packet_id,
            1,
            0,
            Some(destination),
            &[],
        );
    }
    for (fragment_id, fragment) in payload.chunks(chunk_capacity).enumerate() {
        send_native_fragment(
            connection,
            association_id,
            packet_id,
            fragment_count as u8,
            fragment_id as u8,
            (fragment_id == 0).then_some(destination),
            fragment,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send_native_fragment(
    connection: &Connection,
    association_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: Option<&Destination>,
    payload: &[u8],
) -> io::Result<()> {
    let mut encoded = Vec::with_capacity(10 + payload.len() + 32);
    codec::encode_packet(
        association_id,
        packet_id,
        fragment_total,
        fragment_id,
        destination,
        payload,
        &mut encoded,
    )
    .map_err(codec_io)?;
    connection
        .send_datagram(encoded.into())
        .map_err(|error| io::Error::other(format!("send TUIC QUIC datagram: {error}")))
}

async fn send_stream_frame(connection: &Connection, frame: &[u8]) -> io::Result<()> {
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| io::Error::other(format!("open TUIC uni stream: {error}")))?;
    stream
        .write_all(frame)
        .await
        .map_err(|error| io::Error::other(format!("write TUIC uni stream: {error}")))?;
    stream
        .finish()
        .map_err(|error| io::Error::other(format!("finish TUIC uni stream: {error}")))
}

async fn send_dissociate(connection: &Connection, association_id: u16) -> io::Result<()> {
    send_stream_frame(connection, &codec::encode_dissociate(association_id)).await
}

async fn datagram_demux(connection: Connection, sessions: Sessions) {
    let mut partial = HashMap::new();
    while let Ok(frame) = connection.read_datagram().await {
        handle_frame(&frame, &sessions, &mut partial);
    }
}

async fn stream_demux(connection: Connection, sessions: Sessions) {
    let mut partial = HashMap::new();
    while let Ok(mut stream) = connection.accept_uni().await {
        let Ok(frame) = stream.read_to_end(MAX_PACKET_FRAME).await else {
            continue;
        };
        handle_frame(&frame, &sessions, &mut partial);
    }
}

async fn datagram_drain(connection: Connection) {
    while connection.read_datagram().await.is_ok() {}
}

fn handle_frame(frame: &[u8], sessions: &Sessions, partial: &mut HashMap<(u16, u16), Reassembly>) {
    let Ok(packet) = codec::decode_packet(frame) else {
        return;
    };
    let assembled = if packet.fragment_total == 1 {
        packet
            .destination
            .map(|destination| (destination, packet.payload.to_vec()))
    } else {
        reassemble(partial, &packet)
    };
    let Some((destination, payload)) = assembled else {
        return;
    };
    if let Some(sender) = lock(sessions).get(&packet.association_id) {
        let _ = sender.try_send(Datagram::new(destination, Bytes::from(payload)));
    }
}

struct Reassembly {
    destination: Option<Destination>,
    fragments: Vec<Option<Vec<u8>>>,
    remaining: usize,
    buffered_bytes: usize,
    created_at: Instant,
}

fn reassemble(
    map: &mut HashMap<(u16, u16), Reassembly>,
    packet: &codec::Packet<'_>,
) -> Option<(Destination, Vec<u8>)> {
    let now = Instant::now();
    map.retain(|_, value| now.duration_since(value.created_at) <= REASSEMBLY_TTL);
    let total_buffered: usize = map.values().map(|value| value.buffered_bytes).sum();
    if total_buffered.saturating_add(packet.payload.len()) > MAX_REASSEMBLY_BYTES {
        map.clear();
    }
    let key = (packet.association_id, packet.packet_id);
    if map.len() >= MAX_PARTIAL_PACKETS && !map.contains_key(&key) {
        map.clear();
    }
    let entry = map.entry(key).or_insert_with(|| Reassembly {
        destination: None,
        fragments: vec![None; packet.fragment_total as usize],
        remaining: packet.fragment_total as usize,
        buffered_bytes: 0,
        created_at: now,
    });
    if entry.fragments.len() != packet.fragment_total as usize
        || entry.buffered_bytes.saturating_add(packet.payload.len()) > codec::MAX_UDP_PAYLOAD
    {
        map.remove(&key);
        return None;
    }
    let index = packet.fragment_id as usize;
    if entry.fragments[index].is_none() {
        entry.fragments[index] = Some(packet.payload.to_vec());
        entry.remaining -= 1;
        entry.buffered_bytes += packet.payload.len();
        if packet.fragment_id == 0 {
            entry.destination.clone_from(&packet.destination);
        }
    }
    if entry.remaining != 0 {
        return None;
    }
    let complete = map.remove(&key)?;
    let destination = complete.destination?;
    let payload = complete.fragments.into_iter().flatten().flatten().collect();
    Some((destination, payload))
}

fn codec_io(error: crate::CodecError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(
        association_id: u16,
        packet_id: u16,
        total: u8,
        fragment: u8,
        destination: Option<Destination>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        codec::encode_packet(
            association_id,
            packet_id,
            total,
            fragment,
            destination.as_ref(),
            payload,
            &mut encoded,
        )
        .unwrap();
        encoded
    }

    #[test]
    fn reassembles_out_of_order_with_address_only_in_first_fragment() {
        let second = packet(7, 9, 2, 1, None, b"tail");
        let first = packet(
            7,
            9,
            2,
            0,
            Some(Destination::new("example.com", 53)),
            b"head",
        );
        let mut map = HashMap::new();
        assert_eq!(
            reassemble(&mut map, &codec::decode_packet(&second).unwrap()),
            None
        );
        assert_eq!(
            reassemble(&mut map, &codec::decode_packet(&first).unwrap()),
            Some((Destination::new("example.com", 53), b"headtail".to_vec()))
        );
    }

    #[test]
    fn conflicting_fragment_counts_are_dropped() {
        let first = packet(1, 2, 2, 0, Some(Destination::new("h", 1)), b"a");
        let second = packet(1, 2, 3, 1, None, b"b");
        let mut map = HashMap::new();
        assert_eq!(
            reassemble(&mut map, &codec::decode_packet(&first).unwrap()),
            None
        );
        assert_eq!(
            reassemble(&mut map, &codec::decode_packet(&second).unwrap()),
            None
        );
        assert!(map.is_empty());
    }
}
