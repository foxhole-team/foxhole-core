use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard};

use foxcore_runtime::{ComponentError, CoreRuntime, ShareError};
use jni::JNIEnv;
use jni::objects::JString;
use jni::sys::jint;

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

/// Drop every component/share handle owned by this engine generation.
pub(crate) fn release_engine_handles(engine: u64, runtime: &CoreRuntime) {
    crate::ecosystem::release_engine_handles(engine, runtime);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_this_abi_hands_out_is_distinct() {
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
