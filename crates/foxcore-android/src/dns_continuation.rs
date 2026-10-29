use foxcore_runtime::StopResult;

pub(crate) enum BootstrapShape {
    None,
    Trusted,
    Signed,
}

pub(crate) fn bootstrap_shape(
    name: bool,
    manifest: bool,
    signature: bool,
    artifact: bool,
    trusted: bool,
) -> Option<BootstrapShape> {
    match (name, manifest, signature, artifact, trusted) {
        (false, false, false, false, false) => Some(BootstrapShape::None),
        (true, false, false, true, true) => Some(BootstrapShape::Trusted),
        (true, true, true, true, false) => Some(BootstrapShape::Signed),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseError {
    InvalidOwner,
    StaleOwner,
    Busy,
    Exhausted,
}

impl LeaseError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::InvalidOwner => "DNS continuation owner is invalid",
            Self::StaleOwner => "DNS continuation owner is no longer current",
            Self::Busy => "DNS continuation lease capacity is exhausted",
            Self::Exhausted => "DNS continuation token space is exhausted",
        }
    }
}

struct Lease<T> {
    token: u64,
    owner: u64,
    continuation: T,
}

pub(crate) struct DnsContinuationPool<T> {
    next_token: u64,
    lease: Option<Lease<T>>,
}

impl<T> Default for DnsContinuationPool<T> {
    fn default() -> Self {
        Self {
            next_token: 1,
            lease: None,
        }
    }
}

impl<T> DnsContinuationPool<T> {
    pub(crate) fn retain(&mut self, owner: u64, continuation: T) -> Result<u64, (LeaseError, T)> {
        if owner == 0 {
            return Err((LeaseError::InvalidOwner, continuation));
        }
        if self.lease.is_some() {
            return Err((LeaseError::Busy, continuation));
        }
        let token = self.next_token;
        if token == 0 || token > i64::MAX as u64 {
            return Err((LeaseError::Exhausted, continuation));
        }
        self.next_token = token + 1;
        self.lease = Some(Lease {
            token,
            owner,
            continuation,
        });
        Ok(token)
    }

    pub(crate) fn contains(&self, token: u64) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.token == token)
    }

    pub(crate) fn clone_for_start(&self, token: u64) -> Option<T>
    where
        T: Clone,
    {
        self.lease
            .as_ref()
            .filter(|lease| lease.token == token)
            .map(|lease| lease.continuation.clone())
    }

    pub(crate) fn release(&mut self, token: u64) -> Option<T> {
        if !self.contains(token) {
            return None;
        }
        self.lease.take().map(|lease| lease.continuation)
    }

    pub(crate) fn revoke_owner(&mut self, owner: u64) -> Option<T> {
        if !self
            .lease
            .as_ref()
            .is_some_and(|lease| lease.owner == owner)
        {
            return None;
        }
        self.lease.take().map(|lease| lease.continuation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnpublishedCleanup {
    Clean,
    Quarantined,
    Failed,
}

pub(crate) fn cooperative_retire(
    stop: impl FnOnce() -> StopResult,
    force_kill: impl FnOnce() -> StopResult,
) -> UnpublishedCleanup {
    match stop() {
        StopResult::Stopped | StopResult::AlreadyStopped => UnpublishedCleanup::Clean,
        StopResult::TimedOut => match force_kill() {
            StopResult::Stopped | StopResult::AlreadyStopped => UnpublishedCleanup::Clean,
            StopResult::TimedOut => UnpublishedCleanup::Quarantined,
        },
    }
}

pub(crate) fn commit_or_retire<T>(
    successor: &T,
    commit: impl FnOnce(&T) -> bool,
    retire: impl FnOnce(&T) -> UnpublishedCleanup,
) -> Result<(), UnpublishedCleanup> {
    if commit(successor) {
        Ok(())
    } else {
        Err(retire(successor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn pool_has_one_owner_and_released_tokens_never_alias_a_successor() {
        let mut pool = DnsContinuationPool::default();
        let first = pool.retain(9, 4u8).unwrap();
        assert_eq!(pool.retain(10, 5), Err((LeaseError::Busy, 5)));
        assert_eq!(pool.clone_for_start(first), Some(4));
        assert_eq!(pool.revoke_owner(10), None);
        assert_eq!(pool.release(first + 1), None);
        assert_eq!(pool.release(first), Some(4));
        assert_eq!(pool.release(first), None);
        let next = pool.retain(10, 6).unwrap();
        assert_ne!(first, next);
        assert_eq!(pool.clone_for_start(first), None);
        assert_eq!(pool.revoke_owner(10), Some(6));
        assert_eq!(pool.clone_for_start(next), None);
    }

    #[test]
    fn only_three_bootstrap_shapes_are_accepted() {
        let mut accepted = 0;
        for bits in 0u8..32 {
            accepted += usize::from(
                bootstrap_shape(
                    bits & 1 != 0,
                    bits & 2 != 0,
                    bits & 4 != 0,
                    bits & 8 != 0,
                    bits & 16 != 0,
                )
                .is_some(),
            );
        }
        assert_eq!(accepted, 3);
    }

    #[test]
    fn revoked_during_start_retires_unpublished_worker_outside_the_pool_lock() {
        let ready = Arc::new(AtomicBool::new(true));
        let pool = Mutex::new(DnsContinuationPool::default());
        let token = pool.lock().unwrap().retain(9, Arc::clone(&ready)).unwrap();
        let borrowed = pool.lock().unwrap().clone_for_start(token).unwrap();
        let worker = Arc::new(());
        let worker_weak = Arc::downgrade(&worker);
        let revoked = { pool.lock().unwrap().revoke_owner(9) }.unwrap();
        revoked.store(false, Ordering::Release);
        let mut quarantine = None;
        let result = commit_or_retire(
            &worker,
            |_| {
                let guard = pool.lock().unwrap();
                guard.contains(token) && borrowed.load(Ordering::Acquire)
            },
            |successor| {
                assert!(pool.try_lock().is_ok());
                quarantine = Some(Arc::clone(successor));
                UnpublishedCleanup::Quarantined
            },
        );
        assert!(matches!(result, Err(UnpublishedCleanup::Quarantined)));
        drop(worker);
        assert!(worker_weak.upgrade().is_some());
        drop(quarantine);
        assert!(worker_weak.upgrade().is_none());
    }

    #[test]
    fn successful_commit_does_not_retire_and_stale_commit_stops_once() {
        let mut retired = 0;
        assert!(
            commit_or_retire(
                &(),
                |_| true,
                |_| {
                    retired += 1;
                    UnpublishedCleanup::Clean
                }
            )
            .is_ok()
        );
        assert_eq!(retired, 0);
        assert!(matches!(
            commit_or_retire(
                &(),
                |_| false,
                |_| {
                    retired += 1;
                    UnpublishedCleanup::Clean
                }
            ),
            Err(UnpublishedCleanup::Clean)
        ));
        assert_eq!(retired, 1);
    }

    #[test]
    fn cooperative_cleanup_never_forces_a_healthy_join() {
        let result = cooperative_retire(
            || StopResult::Stopped,
            || panic!("healthy worker must not be force-killed"),
        );
        assert_eq!(result, UnpublishedCleanup::Clean);
    }

    #[test]
    fn cleanup_timeout_escalates_once_and_reports_quarantine() {
        let events = std::cell::RefCell::new(Vec::new());
        let result = cooperative_retire(
            || {
                events.borrow_mut().push("stop_timeout");
                StopResult::TimedOut
            },
            || {
                events.borrow_mut().push("force_quarantine");
                StopResult::TimedOut
            },
        );
        assert_eq!(result, UnpublishedCleanup::Quarantined);
        assert_eq!(*events.borrow(), vec!["stop_timeout", "force_quarantine"]);
    }
}
