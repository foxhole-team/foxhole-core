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

/// Floor and ceiling of the reconnect window. The delay between them is drawn,
/// not counted: see [`ReconnectBackoff`] for why a deterministic ladder is both
/// a thundering herd on the server and a timing fingerprint of this client.
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
            if !reconnect(&session, &config, &dialer, &cancel).await {
                return;
            }
            continue;
        };

        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = connection.connection().closed() => mark_down(&session).await,
            _ = reconnect_now => mark_down(&session).await,
        }
    }
}

async fn mark_down(session: &Hysteria2Session) {
    let mut slot = session.slot.lock().await;
    slot.connection = None;
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
    let addresses = dialer
        .resolve_server_addresses(&config.server, config.port, config.server_ip)
        .await?;
    let mut last_error = None;
    for address in addresses {
        match Hysteria2Conn::connect(config, address, dialer).await {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "Hysteria2 server has no address")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The jittered window is the ladder's own bounds, not new ones.
    ///
    /// Asserted on the range rather than on a value: the delay is drawn from
    /// the OS RNG here, and the property under test is the one that holds for
    /// every draw. A reconnect that could wait longer than the old ceiling
    /// would read to the user as a lane that died.
    #[test]
    fn the_reconnect_window_keeps_the_bounds_the_ladder_had() {
        let mut backoff = ReconnectBackoff::new(BACKOFF_MIN, BACKOFF_MAX);
        for _ in 0..64 {
            let delay = backoff.next_delay();
            assert!((BACKOFF_MIN..=BACKOFF_MAX).contains(&delay), "{delay:?}");
        }
    }
}
