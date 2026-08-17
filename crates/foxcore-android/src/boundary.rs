//! The part of the JNI boundary that is in every build.
//!
//! This module exists because of the `mini-platform` feature. The component and
//! share entry points move in and out of the artifact with that feature, but
//! three things they use do not: the result-code table, the two error mappings,
//! and the panic guard. `lib.rs` resolves all four for the LAN proxy and the
//! loopback inbounds, which ship unconditionally.
//!
//! Keeping them here rather than in `ecosystem.rs` is what makes the feature a
//! one-line `cfg` on a module declaration instead of forty attributes on
//! individual items — and it keeps the tests that pin the ABI numbering running
//! in the shipped configuration, where the numbering actually matters. A test
//! that only runs in a build nobody installs is not a check on the shipment.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard};

use foxcore_runtime::{ComponentError, CoreRuntime, ShareError};
use jni::JNIEnv;
use jni::objects::JString;
use jni::sys::jint;

/// Result codes shared by every call that returns a verdict rather than a
/// value. Negative is "the boundary itself failed"; zero is success.
///
/// Reused by the LAN proxy entry points in `lib.rs` rather than copied: those
/// answer with the same `ComponentError`s the component entry points do, and a
/// second numbering for the same refusals is how an app ends up reading
/// "denied" as "ok".
pub(crate) const RESULT_OK: jint = 0;
pub(crate) const RESULT_INVALID_ARGUMENT: jint = 1;
pub(crate) const RESULT_NO_ENGINE: jint = 2;
pub(crate) const RESULT_NOT_FOUND: jint = 3;
pub(crate) const RESULT_ALREADY_EXISTS: jint = 4;
pub(crate) const RESULT_CAPACITY: jint = 5;
pub(crate) const RESULT_DENIED: jint = 6;
pub(crate) const RESULT_RUNTIME_UNAVAILABLE: jint = 7;
pub(crate) const RESULT_VAULT_ERROR: jint = 8;
pub(crate) const RESULT_NETWORK_REFUSED: jint = 9;
pub(crate) const RESULT_NETWORK_UNCONFIRMED: jint = 10;
pub(crate) const RESULT_BIND_FAILED: jint = 11;
pub(crate) const RESULT_PANICKED: jint = -1;

/// A poisoned table is recovered rather than propagated: one panicked call must
/// not make every component permanently unusable.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn component_result(error: ComponentError) -> jint {
    match error {
        ComponentError::InvalidIdentity
        | ComponentError::InvalidOrigin
        | ComponentError::OriginMismatch => RESULT_INVALID_ARGUMENT,
        ComponentError::AlreadyExists => RESULT_ALREADY_EXISTS,
        ComponentError::NotFound => RESULT_NOT_FOUND,
        ComponentError::Capacity => RESULT_CAPACITY,
        ComponentError::InvalidLease
        | ComponentError::WrongPurpose
        | ComponentError::NotificationsDisabled
        | ComponentError::Blocked => RESULT_DENIED,
        ComponentError::RuntimeUnavailable | ComponentError::RandomUnavailable => {
            RESULT_RUNTIME_UNAVAILABLE
        }
        ComponentError::LanBindingRefused => RESULT_NETWORK_REFUSED,
        ComponentError::LanNetworkNotConfirmed => RESULT_NETWORK_UNCONFIRMED,
        ComponentError::LanBindFailed => RESULT_BIND_FAILED,
    }
}

/// Kept beside `component_result` even though only the gated share entry points
/// call it: both map a runtime error onto the one numbering above, and a mapping
/// that lives away from the numbering is a mapping that drifts from it.
///
/// `not(test)` in the condition because the test below is the remaining caller in
/// a build without the feature — which is the point of keeping it here.
#[cfg_attr(all(not(feature = "mini-platform"), not(test)), expect(dead_code))]
pub(crate) fn share_result(error: &ShareError) -> jint {
    match error {
        ShareError::InvalidConfig | ShareError::InvalidMetadata => RESULT_INVALID_ARGUMENT,
        ShareError::Capacity => RESULT_CAPACITY,
        ShareError::NotFound => RESULT_NOT_FOUND,
        _ => RESULT_VAULT_ERROR,
    }
}

pub(crate) fn read_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Option<String> {
    if value.is_null() {
        return None;
    }
    env.get_string(value).ok().map(Into::into)
}

pub(crate) fn guarded(action: impl FnOnce() -> jint) -> jint {
    catch_unwind(AssertUnwindSafe(action)).unwrap_or(RESULT_PANICKED)
}

/// Drop every mini-platform handle owned by an engine generation.
///
/// A shim rather than a direct call so `nativeStop` and `nativeForceKill` read
/// the same in both configurations. Without the feature there are no leases,
/// shares or publications to release, so there is nothing to do — and saying
/// that here is better than two `cfg` attributes buried in the teardown path,
/// where a reader is trying to work out whether teardown is complete.
pub(crate) fn release_engine_handles(engine: u64, runtime: &CoreRuntime) {
    #[cfg(feature = "mini-platform")]
    crate::ecosystem::release_engine_handles(engine, runtime);
    #[cfg(not(feature = "mini-platform"))]
    let _ = (engine, runtime);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_this_abi_hands_out_is_distinct() {
        // A collision here is a caller that reads "denied" as "ok", which is the
        // one direction this boundary must never fail in.
        let codes = [
            RESULT_OK,
            RESULT_INVALID_ARGUMENT,
            RESULT_NO_ENGINE,
            RESULT_NOT_FOUND,
            RESULT_ALREADY_EXISTS,
            RESULT_CAPACITY,
            RESULT_DENIED,
            RESULT_RUNTIME_UNAVAILABLE,
            RESULT_VAULT_ERROR,
            RESULT_NETWORK_REFUSED,
            RESULT_NETWORK_UNCONFIRMED,
            RESULT_BIND_FAILED,
            RESULT_PANICKED,
        ];
        let mut seen = codes.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), codes.len());
    }

    #[test]
    fn a_refusal_never_maps_to_success() {
        for error in [
            ComponentError::LanBindingRefused,
            ComponentError::LanNetworkNotConfirmed,
            ComponentError::LanBindFailed,
            ComponentError::InvalidLease,
            ComponentError::WrongPurpose,
            ComponentError::NotificationsDisabled,
            ComponentError::Blocked,
            ComponentError::OriginMismatch,
            ComponentError::RuntimeUnavailable,
        ] {
            let label = format!("{error:?}");
            assert_ne!(component_result(error), RESULT_OK, "{label}");
        }
        for error in [
            ShareError::InvalidConfig,
            ShareError::NotFound,
            ShareError::Revoked,
            ShareError::Authentication,
        ] {
            assert_ne!(share_result(&error), RESULT_OK, "{error:?}");
        }
    }
}
