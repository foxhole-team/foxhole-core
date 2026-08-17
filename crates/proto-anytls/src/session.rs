use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use foxcore_api::{AnyTlsConfig, Destination};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxStream, wrap_tls};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::codec::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING, CMD_WASTE, encode_frame,
    encode_socks_address, invalid, read_frame,
};
use crate::padding::PaddingScheme;

const COMMAND_QUEUE: usize = 256;
const FRAME_QUEUE: usize = 64;
const STREAM_QUEUE: usize = 32;
const STREAM_BUFFER: usize = 64 * 1024;
const MAX_STREAMS_PER_SESSION: usize = 32;
const MAX_FRAME_DATA: usize = u16::MAX as usize;
const CLIENT_NAME: &str = "foxcore/0.1.0";

pub(crate) struct SessionPool {
    config: Arc<AnyTlsConfig>,
    server_addresses: RwLock<Vec<SocketAddr>>,
    resolved_epoch: AtomicU32,
    dialer: ProtectedDialer,
    scheme: Arc<RwLock<PaddingScheme>>,
    sessions: Mutex<Vec<Arc<Session>>>,
    network_epoch: AtomicU32,
}

impl SessionPool {
    pub(crate) fn new(
        config: Arc<AnyTlsConfig>,
        server_addresses: Vec<SocketAddr>,
        dialer: ProtectedDialer,
    ) -> io::Result<Arc<Self>> {
        let pool = Arc::new(Self {
            config,
            server_addresses: RwLock::new(server_addresses),
            resolved_epoch: AtomicU32::new(0),
            dialer,
            scheme: Arc::new(RwLock::new(PaddingScheme::default_scheme()?)),
            sessions: Mutex::new(Vec::new()),
            network_epoch: AtomicU32::new(0),
        });
        Self::spawn_maintenance(&pool);
        Ok(pool)
    }

    pub(crate) async fn open_stream(&self, destination: Destination) -> io::Result<BoxStream> {
        let network_epoch = self.network_epoch.load(Ordering::Acquire);
        let candidates = {
            let mut sessions = self.sessions.lock().await;
            for session in sessions.iter().filter(|session| {
                session.network_epoch != network_epoch || !session.healthy.load(Ordering::Acquire)
            }) {
                session.shutdown();
            }
            sessions.retain(|session| {
                session.network_epoch == network_epoch && session.healthy.load(Ordering::Acquire)
            });
            sessions.iter().rev().cloned().collect::<Vec<_>>()
        };
        for session in candidates {
            if session.try_reserve() {
                match session
                    .open_reserved(destination.clone(), false, self.handshake_timeout())
                    .await
                {
                    Ok(stream) if self.network_epoch.load(Ordering::Acquire) == network_epoch => {
                        return Ok(stream);
                    }
                    Ok(_) => {
                        session.shutdown();
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "network changed during AnyTLS stream open",
                        ));
                    }
                    Err(error)
                        if !session.healthy.load(Ordering::Acquire)
                            || retryable_stream_open(&error) =>
                    {
                        session.shutdown();
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        let server_addresses = self.server_addresses(network_epoch).await?;
        let mut last_error = None;
        for server_address in server_addresses {
            for _attempt in 0..2 {
                match Session::connect_first(
                    self.config.clone(),
                    server_address,
                    self.dialer.clone(),
                    self.scheme.clone(),
                    destination.clone(),
                    network_epoch,
                )
                .await
                {
                    Ok((session, stream)) => {
                        if self.network_epoch.load(Ordering::Acquire) != network_epoch {
                            session.shutdown();
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "network changed during AnyTLS connect",
                            ));
                        }
                        self.sessions.lock().await.push(session);
                        return Ok(stream);
                    }
                    Err(error) => last_error = Some(error),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS stream could not be opened",
            )
        }))
    }

    async fn server_addresses(&self, network_epoch: u32) -> io::Result<Vec<SocketAddr>> {
        if self.resolved_epoch.load(Ordering::Acquire) == network_epoch {
            return self
                .server_addresses
                .read()
                .map(|addresses| addresses.clone())
                .map_err(|_| io::Error::other("AnyTLS server address state is poisoned"));
        }
        let resolved = self
            .dialer
            .resolve_server_addresses(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let mut addresses = self
            .server_addresses
            .write()
            .map_err(|_| io::Error::other("AnyTLS server address state is poisoned"))?;
        if self.network_epoch.load(Ordering::Acquire) != network_epoch {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "network changed during AnyTLS resolution",
            ));
        }
        *addresses = resolved.clone();
        self.resolved_epoch.store(network_epoch, Ordering::Release);
        Ok(resolved)
    }

    pub(crate) fn network_changed(pool: &Arc<Self>) {
        pool.network_epoch.fetch_add(1, Ordering::AcqRel);
        // Fast path: eagerly stop stale sessions when no open/maintenance pass
        // owns the list. If it is busy, the next open_stream pass performs the
        // same epoch check before selecting anything.
        if let Ok(sessions) = pool.sessions.try_lock() {
            for session in sessions.iter() {
                session.shutdown();
            }
        }
    }

    fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.config.handshake_timeout_ms)
    }

    fn spawn_maintenance(pool: &Arc<Self>) {
        let weak = Arc::downgrade(pool);
        let interval = Duration::from_millis(pool.config.idle_session_check_interval_ms);
        let timeout = Duration::from_millis(pool.config.idle_session_timeout_ms);
        let minimum = pool.config.min_idle_session;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let Some(pool) = weak.upgrade() else {
                    break;
                };
                let mut sessions = pool.sessions.lock().await;
                sessions.retain(|session| session.healthy.load(Ordering::Acquire));
                let idle_count = sessions
                    .iter()
                    .filter(|session| session.active.load(Ordering::Acquire) == 0)
                    .count();
                let mut removable = idle_count.saturating_sub(minimum);
                for session in sessions.iter() {
                    if removable == 0 {
                        break;
                    }
                    if session.idle_for().is_some_and(|idle| idle >= timeout) {
                        session.shutdown();
                        removable -= 1;
                    }
                }
                sessions.retain(|session| session.healthy.load(Ordering::Acquire));
            }
        });
    }
}

fn retryable_stream_open(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}

struct Session {
    command: mpsc::Sender<Command>,
    healthy: AtomicBool,
    active: AtomicUsize,
    next_stream_id: AtomicU32,
    idle_since: StdMutex<Option<Instant>>,
    network_epoch: u32,
}

impl Session {
    async fn connect_first(
        config: Arc<AnyTlsConfig>,
        server_address: SocketAddr,
        dialer: ProtectedDialer,
        shared_scheme: Arc<RwLock<PaddingScheme>>,
        destination: Destination,
        network_epoch: u32,
    ) -> io::Result<(Arc<Self>, BoxStream)> {
        let tcp = dialer.connect_tcp(server_address).await?;
        let tls = tokio::time::timeout(
            Duration::from_millis(config.handshake_timeout_ms),
            wrap_tls(tcp, &config.tls, &config.server),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "AnyTLS TLS handshake timed out"))??;

        let scheme = shared_scheme
            .read()
            .map_err(|_| io::Error::other("AnyTLS padding state is poisoned"))?
            .clone();
        let mut stream = tls;
        write_authentication(&mut stream, config.password.expose(), &scheme).await?;

        let (command, commands) = mpsc::channel(COMMAND_QUEUE);
        let session = Arc::new(Self {
            command,
            healthy: AtomicBool::new(true),
            active: AtomicUsize::new(1),
            next_stream_id: AtomicU32::new(2),
            idle_since: StdMutex::new(None),
            network_epoch,
        });
        tokio::spawn(run_session(
            Arc::downgrade(&session),
            stream,
            commands,
            scheme,
            shared_scheme,
        ));
        let first = session
            .open_reserved(
                destination,
                true,
                Duration::from_millis(config.handshake_timeout_ms),
            )
            .await?;
        Ok((session, first))
    }

    fn try_reserve(&self) -> bool {
        if !self.healthy.load(Ordering::Acquire) {
            return false;
        }
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= MAX_STREAMS_PER_SESSION {
                return false;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if let Ok(mut idle) = self.idle_since.lock() {
                        *idle = None;
                    }
                    return true;
                }
                Err(observed) => current = observed,
            }
        }
    }

    async fn open_reserved(
        self: &Arc<Self>,
        destination: Destination,
        first: bool,
        timeout: Duration,
    ) -> io::Result<BoxStream> {
        let stream_id = if first {
            1
        } else {
            self.next_stream_id.fetch_add(1, Ordering::Relaxed)
        };
        if stream_id == 0 {
            self.release();
            self.shutdown();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS stream id space exhausted",
            ));
        }
        let mut guard = OpenGuard::new(self.clone(), stream_id);
        let (application, bridge) = tokio::io::duplex(STREAM_BUFFER);
        let (incoming, incoming_rx) = mpsc::channel(STREAM_QUEUE);
        let (ack, ack_rx) = oneshot::channel();
        let remote_fin = Arc::new(AtomicBool::new(false));
        if self
            .command
            .send(Command::Open {
                stream_id,
                destination,
                incoming,
                ack,
                first,
                remote_fin: remote_fin.clone(),
            })
            .await
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        guard.mark_opened();

        match tokio::time::timeout(timeout, ack_rx).await {
            Ok(Ok(Ok(()))) => {
                guard.disarm();
                tokio::spawn(bridge_stream(
                    self.clone(),
                    stream_id,
                    bridge,
                    incoming_rx,
                    remote_fin,
                ));
                Ok(Box::new(application))
            }
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "AnyTLS session closed before SYNACK",
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "AnyTLS v2 SYNACK timed out",
            )),
        }
    }

    fn release(&self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1
            && let Ok(mut idle) = self.idle_since.lock()
        {
            *idle = Some(Instant::now());
        }
    }

    fn idle_for(&self) -> Option<Duration> {
        self.idle_since
            .lock()
            .ok()
            .and_then(|idle| idle.as_ref().map(Instant::elapsed))
    }

    fn shutdown(&self) {
        self.healthy.store(false, Ordering::Release);
        let _ = self.command.try_send(Command::Shutdown);
    }
}

/// Cancellation-safe ownership of one reserved stream slot.
///
/// Dropping the `open_stream` future while DNS/TLS has already completed is a
/// normal consequence of a caller timeout. Without this guard the stream would
/// remain in the session map and its active-count slot would never be returned.
struct OpenGuard {
    session: Arc<Session>,
    stream_id: u32,
    armed: bool,
    opened: bool,
}

impl OpenGuard {
    fn new(session: Arc<Session>, stream_id: u32) -> Self {
        Self {
            session,
            stream_id,
            armed: true,
            opened: false,
        }
    }

    fn mark_opened(&mut self) {
        self.opened = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.session.release();
        if !self.opened {
            return;
        }
        let command = self.session.command.clone();
        let stream_id = self.stream_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = command.send(Command::Close { stream_id }).await;
            });
        } else {
            let _ = command.try_send(Command::Close { stream_id });
        }
    }
}

enum Command {
    Open {
        stream_id: u32,
        destination: Destination,
        incoming: mpsc::Sender<Bytes>,
        ack: oneshot::Sender<io::Result<()>>,
        first: bool,
        remote_fin: Arc<AtomicBool>,
    },
    Data {
        stream_id: u32,
        data: Bytes,
    },
    Close {
        stream_id: u32,
    },
    Shutdown,
}

async fn bridge_stream(
    session: Arc<Session>,
    stream_id: u32,
    bridge: tokio::io::DuplexStream,
    mut incoming: mpsc::Receiver<Bytes>,
    remote_fin: Arc<AtomicBool>,
) {
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let mut buffer = vec![0_u8; 32 * 1024];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(length) => {
                        if session.command.send(Command::Data {
                            stream_id,
                            data: Bytes::copy_from_slice(&buffer[..length]),
                        }).await.is_err() {
                            break;
                        }
                    }
                }
            }
            received = incoming.recv() => {
                match received {
                    Some(data) if writer.write_all(&data).await.is_ok() => {}
                    _ => break,
                }
            }
        }
    }
    // AnyTLS FIN is unidirectional and the protocol explicitly says not to
    // answer a received FIN. Only a local EOF initiates our FIN.
    if !remote_fin.load(Ordering::Acquire) {
        let _ = session.command.send(Command::Close { stream_id }).await;
    }
    let _ = writer.shutdown().await;
    session.release();
}

async fn run_session(
    session: Weak<Session>,
    stream: BoxStream,
    mut commands: mpsc::Receiver<Command>,
    scheme: PaddingScheme,
    shared_scheme: Arc<RwLock<PaddingScheme>>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frames_tx, mut frames_rx) = mpsc::channel(FRAME_QUEUE);
    tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut reader).await;
            let failed = frame.is_err();
            if frames_tx.send(frame).await.is_err() || failed {
                break;
            }
        }
    });

    struct StreamState {
        incoming: mpsc::Sender<Bytes>,
        remote_fin: Arc<AtomicBool>,
    }

    let mut streams = HashMap::<u32, StreamState>::new();
    let mut pending = HashMap::<u32, oneshot::Sender<io::Result<()>>>::new();
    let mut packet_index = 1usize;
    // A CSPRNG, not the fast non-cryptographic generator this used before: it feeds padding
    // lengths *and* the padding bytes themselves. xoshiro state is recoverable from a modest
    // run of its own output, so a predictable generator would let an observer predict the whole
    // padding sequence — the one thing padding exists to prevent. One small draw per packet, so
    // the cost is nothing.
    let mut rng = StdRng::from_os_rng();
    let mut negotiated_v2 = false;
    let result: io::Result<()> = async {
        loop {
            tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(Command::Open {
                            stream_id,
                            destination,
                            incoming,
                            ack,
                            first,
                            remote_fin,
                        }) => {
                            let mut packet = BytesMut::new();
                            if first {
                                let settings = format!(
                                    "v=2\nclient={CLIENT_NAME}\npadding-md5={}\n",
                                    scheme.md5_hex()
                                );
                                encode_frame(CMD_SETTINGS, 0, settings.as_bytes(), &mut packet)?;
                            }
                            encode_frame(CMD_SYN, stream_id, &[], &mut packet)?;
                            let mut address = BytesMut::new();
                            encode_socks_address(&destination, &mut address)?;
                            encode_frame(CMD_PSH, stream_id, &address, &mut packet)?;
                            write_packet(
                                &mut writer,
                                &scheme,
                                &mut packet_index,
                                &packet,
                                &mut rng,
                            )
                            .await?;
                            streams.insert(
                                stream_id,
                                StreamState {
                                    incoming,
                                    remote_fin,
                                },
                            );
                            pending.insert(stream_id, ack);
                        }
                        Some(Command::Data { stream_id, data }) => {
                            // A remote FIN removes the stream first. Bytes that
                            // raced with that close must not resurrect it by
                            // emitting PSH after the peer closed its direction.
                            if streams.contains_key(&stream_id) {
                                for chunk in data.chunks(MAX_FRAME_DATA) {
                                    let mut packet = BytesMut::new();
                                    encode_frame(CMD_PSH, stream_id, chunk, &mut packet)?;
                                    write_packet(
                                        &mut writer,
                                        &scheme,
                                        &mut packet_index,
                                        &packet,
                                        &mut rng,
                                    )
                                    .await?;
                                }
                            }
                        }
                        Some(Command::Close { stream_id }) => {
                            streams.remove(&stream_id);
                            if let Some(ack) = pending.remove(&stream_id) {
                                let _ = ack.send(Err(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    "AnyTLS stream closed before SYNACK",
                                )));
                            }
                            let mut packet = BytesMut::new();
                            encode_frame(CMD_FIN, stream_id, &[], &mut packet)?;
                            write_packet(
                                &mut writer,
                                &scheme,
                                &mut packet_index,
                                &packet,
                                &mut rng,
                            )
                            .await?;
                        }
                        Some(Command::Shutdown) | None => break,
                    }
                }
                frame = frames_rx.recv() => {
                    let Some(frame) = frame else {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "AnyTLS session reader stopped",
                        ));
                    };
                    let frame = frame?;
                    match frame.command {
                        CMD_WASTE => {}
                        CMD_SERVER_SETTINGS if frame.stream_id == 0 => {
                            negotiated_v2 = parse_server_version(&frame.data)? >= 2;
                        }
                        CMD_SYNACK => {
                            if !negotiated_v2 {
                                return Err(invalid(
                                    "AnyTLS SYNACK arrived before v2 server settings",
                                ));
                            }
                            if let Some(ack) = pending.remove(&frame.stream_id) {
                                if frame.data.is_empty() {
                                    let _ = ack.send(Ok(()));
                                } else {
                                    streams.remove(&frame.stream_id);
                                    let _ = ack.send(Err(io::Error::new(
                                        io::ErrorKind::ConnectionRefused,
                                        "AnyTLS server refused the stream",
                                    )));
                                }
                            }
                        }
                        CMD_PSH => {
                            if let Some(stream) = streams.get(&frame.stream_id)
                                && stream.incoming.try_send(frame.data).is_err()
                            {
                                // One application that stops reading must not
                                // stall the shared session and every other
                                // multiplexed stream behind this bounded queue.
                                streams.remove(&frame.stream_id);
                            }
                        }
                        CMD_FIN => {
                            if let Some(stream) = streams.remove(&frame.stream_id) {
                                stream.remote_fin.store(true, Ordering::Release);
                            }
                            if let Some(ack) = pending.remove(&frame.stream_id) {
                                let _ = ack.send(Err(io::Error::new(
                                    io::ErrorKind::ConnectionRefused,
                                    "AnyTLS server closed the stream before SYNACK",
                                )));
                            }
                        }
                        CMD_HEART_REQUEST if frame.stream_id == 0 && frame.data.is_empty() => {
                            let mut packet = BytesMut::new();
                            encode_frame(CMD_HEART_RESPONSE, 0, &[], &mut packet)?;
                            write_packet(
                                &mut writer,
                                &scheme,
                                &mut packet_index,
                                &packet,
                                &mut rng,
                            )
                            .await?;
                        }
                        CMD_HEART_RESPONSE if frame.stream_id == 0 && frame.data.is_empty() => {}
                        CMD_UPDATE_PADDING if frame.stream_id == 0 => {
                            let update = std::str::from_utf8(&frame.data)
                                .map_err(|_| invalid("AnyTLS padding update is not UTF-8"))?;
                            let parsed = PaddingScheme::parse(update)?;
                            *shared_scheme.write().map_err(|_| {
                                io::Error::other("AnyTLS padding state is poisoned")
                            })? = parsed;
                        }
                        CMD_ALERT => {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "AnyTLS server sent an alert",
                            ));
                        }
                        CMD_SETTINGS | CMD_SYN => {
                            return Err(invalid("AnyTLS server sent a client-only command"));
                        }
                        _ => return Err(invalid("AnyTLS server sent an invalid frame")),
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    if let Some(session) = session.upgrade() {
        session.healthy.store(false, Ordering::Release);
    }
    for (_, ack) in pending {
        let kind = result
            .as_ref()
            .err()
            .map_or(io::ErrorKind::ConnectionAborted, io::Error::kind);
        let _ = ack.send(Err(io::Error::new(kind, "AnyTLS session stopped")));
    }
    streams.clear();
    let _ = writer.shutdown().await;
}

async fn write_authentication<W>(
    writer: &mut W,
    password: &str,
    scheme: &PaddingScheme,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // A CSPRNG, not the fast non-cryptographic generator this used before: it feeds padding
    // lengths *and* the padding bytes themselves. xoshiro state is recoverable from a modest
    // run of its own output, so a predictable generator would let an observer predict the whole
    // padding sequence — the one thing padding exists to prevent. One small draw per packet, so
    // the cost is nothing.
    let mut rng = StdRng::from_os_rng();
    let padding_length = scheme.auth_padding_length(&mut rng);
    let mut packet = BytesMut::with_capacity(34 + padding_length);
    packet.extend_from_slice(&Sha256::digest(password.as_bytes()));
    packet.extend_from_slice(&(padding_length as u16).to_be_bytes());
    let start = packet.len();
    packet.resize(start + padding_length, 0);
    rng.fill_bytes(&mut packet[start..]);
    writer.write_all(&packet).await?;
    writer.flush().await
}

async fn write_packet<W>(
    writer: &mut W,
    scheme: &PaddingScheme,
    packet_index: &mut usize,
    payload: &[u8],
    rng: &mut StdRng,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for chunk in scheme.packet_chunks(*packet_index, payload, rng)? {
        writer.write_all(&chunk).await?;
        writer.flush().await?;
    }
    *packet_index = packet_index.saturating_add(1);
    Ok(())
}

fn parse_server_version(data: &[u8]) -> io::Result<u32> {
    let text =
        std::str::from_utf8(data).map_err(|_| invalid("AnyTLS server settings are not UTF-8"))?;
    let mut version = None;
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("AnyTLS server setting has no '='"))?;
        if key == "v" {
            if version.is_some() {
                return Err(invalid("AnyTLS server settings repeat v"));
            }
            version = Some(
                value
                    .parse()
                    .map_err(|_| invalid("AnyTLS server version is not an integer"))?,
            );
        }
    }
    version.ok_or_else(|| invalid("AnyTLS server settings have no version"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(command: mpsc::Sender<Command>) -> Arc<Session> {
        Arc::new(Session {
            command,
            healthy: AtomicBool::new(true),
            active: AtomicUsize::new(1),
            next_stream_id: AtomicU32::new(2),
            idle_since: StdMutex::new(None),
            network_epoch: 0,
        })
    }

    #[test]
    fn server_settings_are_strict_and_bounded_by_frame_codec() {
        assert_eq!(parse_server_version(b"v=2\n").unwrap(), 2);
        assert!(parse_server_version(b"v=x\n").is_err());
        assert!(parse_server_version(b"client=x\n").is_err());
        assert!(parse_server_version(b"v=2\nv=1\n").is_err());
    }

    #[tokio::test]
    async fn cancelled_open_releases_its_slot_and_closes_an_enqueued_stream() {
        let (command, mut commands) = mpsc::channel(2);
        let session = test_session(command);
        let mut guard = OpenGuard::new(session.clone(), 7);
        guard.mark_opened();
        drop(guard);
        assert_eq!(session.active.load(Ordering::Acquire), 0);
        assert!(matches!(
            commands.recv().await,
            Some(Command::Close { stream_id: 7 })
        ));
    }
}
