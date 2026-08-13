use super::*;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Poll a thread until the join budget expires, returning ownership on timeout.
pub(crate) fn join_within(thread: JoinHandle<()>, budget: Duration) -> Result<(), JoinHandle<()>> {
    let deadline = Instant::now() + budget;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return Err(thread);
        }
        std::thread::sleep(JOIN_POLL);
    }
    let _ = thread.join();
    Ok(())
}

/// Render the common panic payload forms.
pub(crate) fn panic_text(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&'static str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

pub(crate) fn shutdown_worker_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
}

pub(crate) struct RuntimeWorker {
    pub(crate) state: AtomicU8,
    /// Serializes stop calls; `abandon` must never acquire it.
    pub(crate) stop_lock: Mutex<()>,
    /// Ownership token for both the worker and the `Stopped` result.
    pub(crate) thread: Mutex<Option<JoinHandle<()>>>,
    pub(crate) done: Mutex<mpsc::Receiver<()>>,
}

impl RuntimeWorker {
    pub(crate) fn new(thread: JoinHandle<()>, done: mpsc::Receiver<()>) -> Self {
        Self {
            state: AtomicU8::new(WORKER_RUNNING),
            stop_lock: Mutex::new(()),
            thread: Mutex::new(Some(thread)),
            done: Mutex::new(done),
        }
    }

    pub(crate) fn stop(&self, timeout: Duration, request_stop: impl FnOnce()) -> StopResult {
        let _stop_guard = lock(&self.stop_lock);
        match self.state.load(Ordering::Acquire) {
            WORKER_STOPPED => return StopResult::AlreadyStopped,
            WORKER_RUNNING => {
                self.state.store(WORKER_STOPPING, Ordering::Release);
                request_stop();
            }
            WORKER_STOPPING => {}
            _ => unreachable!("runtime worker state is private and bounded"),
        }

        let completed = match lock(&self.done).recv_timeout(timeout) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        };
        if !completed {
            return StopResult::TimedOut;
        }

        // Take outside `if let`; its scrutinee guard would outlive the branch.
        let thread = lock(&self.thread).take();
        let Some(thread) = thread else {
            // Another caller owns the worker and the right to report `Stopped`.
            self.state.store(WORKER_STOPPED, Ordering::Release);
            return StopResult::AlreadyStopped;
        };
        if let Err(thread) = join_within(thread, JOIN_GRACE) {
            *lock(&self.thread) = Some(thread);
            return StopResult::TimedOut;
        }
        self.state.store(WORKER_STOPPED, Ordering::Release);
        StopResult::Stopped
    }

    /// Quarantine the worker without waiting.
    ///
    /// Never acquire `stop_lock`: a force kill must not queue behind `stop`.
    /// Ownership is settled by taking `thread`, which is never held while waiting.
    pub(crate) fn abandon(&self) -> StopResult {
        if self.state.load(Ordering::Acquire) == WORKER_STOPPED {
            return StopResult::AlreadyStopped;
        }
        let Some(thread) = lock(&self.thread).take() else {
            // Another stop or force-kill call owns it.
            return StopResult::TimedOut;
        };
        if thread.is_finished() {
            let _ = thread.join();
            self.state.store(WORKER_STOPPED, Ordering::Release);
            return StopResult::Stopped;
        }
        self.state.store(WORKER_STOPPING, Ordering::Release);
        quarantine_worker(thread);
        StopResult::TimedOut
    }

    pub(crate) fn quarantine(&self) {
        if let Some(thread) = lock(&self.thread).take() {
            quarantine_worker(thread);
        }
    }
}

/// Android process-wide lease preventing concurrent data-plane generations.
pub(crate) struct ProcessWorkerLease;

impl ProcessWorkerLease {
    pub(crate) fn acquire() -> io::Result<Self> {
        #[cfg(target_os = "android")]
        ANDROID_WORKER_ACTIVE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "a previous FoxCore worker is still active",
                )
            })?;
        Ok(Self)
    }
}

impl Drop for ProcessWorkerLease {
    fn drop(&mut self) {
        #[cfg(target_os = "android")]
        ANDROID_WORKER_ACTIVE.store(0, Ordering::Release);
    }
}

pub(crate) struct WorkerAvailabilityGuard(pub(crate) Arc<AtomicBool>);

impl Drop for WorkerAvailabilityGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) struct RootRuntimeLease {
    pub(crate) availability: Arc<AtomicBool>,
}

impl RuntimeLease for RootRuntimeLease {
    fn is_available(&self) -> bool {
        self.availability.load(Ordering::Acquire)
    }
}

pub(crate) struct RootRuntimeLeaseProvider {
    pub(crate) availability: Arc<AtomicBool>,
    pub(crate) tor_available: bool,
}

impl RuntimeLeaseProvider for RootRuntimeLeaseProvider {
    fn acquire(&self, runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError> {
        if !self.availability.load(Ordering::Acquire)
            || (runtime == RuntimeKind::Tor && !self.tor_available)
        {
            return Err(ComponentError::RuntimeUnavailable);
        }
        Ok(Arc::new(RootRuntimeLease {
            availability: self.availability.clone(),
        }))
    }
}
