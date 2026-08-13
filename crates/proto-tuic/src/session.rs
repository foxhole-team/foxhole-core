use std::io;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use foxcore_api::{ContinuityPermit, TuicConfig};
use foxcore_dialer::ProtectedDialer;
use quinn::VarInt;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::connection::TuicConnection;
use crate::udp::TuicUdpRelay;

const BACKOFF_MIN: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(8);
const WAIT_READY_TIMEOUT: Duration = Duration::from_secs(8);

struct Slot {
    epoch: u64,
    connection: Option<Arc<TuicConnection>>,
    udp: Option<Arc<TuicUdpRelay>>,
}

pub struct TuicSession {
    slot: Mutex<Slot>,
    changed: Notify,
    reconnect_now: Notify,
    reconnect_epoch: AtomicU64,
    reconnects: AtomicU64,
    /// Must permit a replacement session before its first dial.
    before_reconnect: OnceLock<Arc<dyn Fn() -> ContinuityPermit + Send + Sync>>,
}

impl TuicSession {
    pub async fn start(
        config: TuicConfig,
        dialer: ProtectedDialer,
        cancel: CancellationToken,
        reconnect_hook: Option<Arc<dyn Fn() -> ContinuityPermit + Send + Sync>>,
    ) -> io::Result<Arc<Self>> {
        let connection = TuicConnection::connect(&config, &dialer).await?;
        let udp = TuicUdpRelay::new(connection.clone(), config.udp_relay_mode);
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

    pub async fn current(&self) -> Option<(Arc<TuicConnection>, Arc<TuicUdpRelay>)> {
        let slot = self.slot.lock().await;
        if slot.epoch != self.reconnect_epoch.load(Ordering::Acquire) {
            return None;
        }
        Some((
            slot.connection.as_ref()?.clone(),
            slot.udp.as_ref()?.clone(),
        ))
    }

    pub async fn wait_ready(&self) -> Option<(Arc<TuicConnection>, Arc<TuicUdpRelay>)> {
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
    session: Arc<TuicSession>,
    config: TuicConfig,
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
            _ = cancel.cancelled() => {
                connection.connection().close(VarInt::from_u32(0), b"TUIC runtime stopped");
                mark_down(&session).await;
                return;
            }
            _ = connection.connection().closed() => mark_down(&session).await,
            _ = reconnect_now => {
                connection.connection().close(VarInt::from_u32(0), b"TUIC network changed");
                mark_down(&session).await;
            }
        }
    }
}

async fn mark_down(session: &TuicSession) {
    let mut slot = session.slot.lock().await;
    slot.connection = None;
    slot.udp = None;
}

async fn reconnect(
    session: &Arc<TuicSession>,
    config: &TuicConfig,
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
        let mut backoff = BACKOFF_MIN;
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
                connected = TuicConnection::connect(config, dialer) => connected,
            };
            match connected {
                Ok(connection) => {
                    let udp = TuicUdpRelay::new(connection.clone(), config.udp_relay_mode);
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
                        _ = tokio::time::sleep(backoff) => {
                            backoff = (backoff * 2).min(BACKOFF_MAX);
                        }
                    }
                }
            }
        }
    }
}
