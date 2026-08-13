use super::*;

use std::io;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use foxcore_api::{EngineConfig, OutboundConfig, RuntimeConfig};

pub(crate) fn build_runtime(config: &RuntimeConfig) -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads)
        .max_blocking_threads(config.max_blocking_threads)
        .thread_name("foxcore-worker")
        .enable_all()
        .build()
}

pub(crate) fn startup_wait(config: &EngineConfig) -> Duration {
    std::iter::once(&config.outbound)
        .chain(config.outbounds.iter().map(|named| &named.outbound))
        .map(|outbound| match outbound {
            OutboundConfig::Tor(tor) => Duration::from_secs(tor.bootstrap_timeout_s),
            _ => Duration::from_millis(config.runtime.handshake_timeout_ms),
        })
        .max()
        .unwrap_or_default()
        .saturating_add(Duration::from_secs(2))
}

pub(crate) fn set_error(target: &Mutex<Option<String>>, message: String) {
    *lock(target) = Some(message);
}

pub(crate) fn quarantine_worker(thread: JoinHandle<()>) {
    lock(QUARANTINED_WORKERS.get_or_init(|| Mutex::new(Vec::new()))).push(thread);
}

pub(crate) fn reap_quarantined_workers() {
    let workers = QUARANTINED_WORKERS.get_or_init(|| Mutex::new(Vec::new()));
    let finished = {
        let mut workers = lock(workers);
        let mut finished = Vec::new();
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                finished.push(workers.swap_remove(index));
            } else {
                index += 1;
            }
        }
        finished
    };
    for worker in finished {
        let _ = worker.join();
    }
}

/// Wall clock in milliseconds, for the share vault's expiry and limits.
pub(crate) fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or_default()
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
