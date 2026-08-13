#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod capabilities;
mod ecosystem;
mod link;
#[cfg(target_os = "android")]
mod logcat;

use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::ffi::CString;
#[cfg(target_os = "android")]
use std::io;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "android")]
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
#[cfg(target_os = "android")]
use std::time::{Duration, Instant};

use foxcore_api::{
    CORE_ABI_VERSION, CORE_VERSION, EngineConfig, FlowAttributor, LoopbackInboundConfig,
    PolicyConfig, SCHEMA_VERSION,
};
#[cfg(target_os = "android")]
use foxcore_api::{FlowIdentity, IpTransport, decode_signing_digest};
use foxcore_dialer::SocketCallbacks;
use foxcore_runtime::{
    ComponentId, ConfirmResult, CoreRuntime, LanCredentials, LanProxyConfig, LanProxyPreset,
    LanTransport, MAX_DNS_RULE_SET_ARTIFACT_BYTES, MAX_DNS_RULE_SET_MANIFEST_BYTES,
    MAX_DNS_RULE_SET_SIGNATURE_BYTES, NetworkBinding, PolicyRefusal, RevokeTarget, RuleSetBundle,
    StopResult, TrustedRuleSetBundle, lan_proxy_stopped_status_json, loopback_inbounds_empty_json,
};
#[cfg(target_os = "android")]
use jni::objects::JObjectArray;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::capabilities::capabilities_json;
use crate::ecosystem::{
    RESULT_INVALID_ARGUMENT, RESULT_NO_ENGINE, RESULT_NOT_FOUND, RESULT_OK, RESULT_PANICKED,
    component_result, guarded, read_string,
};

static RUNTIMES: OnceLock<Mutex<HashMap<u64, Arc<CoreRuntime>>>> = OnceLock::new();
static STOP_REAPERS: OnceLock<Mutex<HashMap<u64, std::thread::JoinHandle<()>>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
const NATIVE_STOPPED: jint = 0;
const NATIVE_ALREADY_STOPPED: jint = 1;
const NATIVE_STOP_TIMED_OUT: jint = 2;
const NATIVE_STOP_UNKNOWN_HANDLE: jint = 3;
const NATIVE_STOP_PANICKED: jint = -1;
const NATIVE_CONTINUITY_CONFIRMED: jint = 0;
const NATIVE_CONTINUITY_NOTHING_PENDING: jint = 1;
const NATIVE_CONTINUITY_STALE_TOKEN: jint = 2;
const NATIVE_CONTINUITY_UNKNOWN_HANDLE: jint = 3;
const NATIVE_CONTINUITY_PANICKED: jint = -1;
/// `nativeRevokeFlows` answers with a *count*, so its failures have to be
/// negative: a zero or a two would otherwise be indistinguishable from "no
/// flows matched" and "two flows were cut". `-1` is deliberately the value
/// [`guarded`] already returns on a panic, so the panic arm needs no special
/// case and cannot drift away from the documented code.
const NATIVE_REVOKE_PANICKED: jint = -1;
const NATIVE_REVOKE_NO_ENGINE: jint = -2;
const NATIVE_REVOKE_INVALID_TARGET: jint = -3;
/// Checked rather than commented, because nothing else would notice: the panic
/// arm of `nativeRevokeFlows` is `guarded`'s own return value, so a change to
/// `RESULT_PANICKED` would silently make the documented `-1` wrong and no test
/// that does not deliberately panic across the boundary could see it.
const _: () = assert!(NATIVE_REVOKE_PANICKED == RESULT_PANICKED);

struct JavaCallbacks {
    vm: JavaVM,
    host: GlobalRef,
}

#[cfg(target_os = "android")]
struct JavaFlowAttributor {
    vm: JavaVM,
    host: GlobalRef,
    connectivity_manager: GlobalRef,
    package_manager: GlobalRef,
    package_cache: Mutex<HashMap<u32, CachedJavaFlowIdentity>>,
}

#[cfg(target_os = "android")]
#[derive(Clone)]
struct CachedJavaFlowIdentity {
    inserted: Instant,
    packages: Vec<String>,
    signing_digest: Option<[u8; 32]>,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeVersion(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        env.new_string(CORE_VERSION)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeAbiVersion(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    CORE_ABI_VERSION as jint
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeCapabilities(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        env.new_string(capabilities_json())
            .map(|value| value.into_raw())
            .unwrap_or(ptr::null_mut())
    }))
    .unwrap_or(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn foxhole_core_abi_version() -> u32 {
    CORE_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn foxhole_core_config_schema_version() -> u32 {
    SCHEMA_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn foxhole_core_capabilities_json_len() -> usize {
    capabilities_json().len().checked_add(1).unwrap_or(0)
}

/// Writes the versioned capabilities document to a caller-owned buffer.
///
/// # Safety
///
/// When buffer is non-null and capacity is sufficient, it must point to writable
/// memory valid for capacity bytes. The buffer may not alias the internal document.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn foxhole_core_capabilities_json_write(
    buffer: *mut u8,
    capacity: usize,
) -> usize {
    catch_unwind(AssertUnwindSafe(|| {
        let document = capabilities_json().as_bytes();
        let Some(required) = document.len().checked_add(1) else {
            return 0;
        };
        if buffer.is_null() || capacity < required {
            return required;
        }
        // SAFETY: guaranteed by the public function contract and the capacity check above.
        unsafe {
            ptr::copy_nonoverlapping(document.as_ptr(), buffer, document.len());
            buffer.add(document.len()).write(0);
        }
        required
    }))
    .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStart(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    tun_fd: jint,
    config_json: JString<'_>,
    host: JObject<'_>,
) -> jlong {
    native_start(env, tun_fd, config_json, 0, host)
}

/// Production bootstrap ABI. `network_handle` is obtained from
/// `Network.getNetworkHandle()` before the TUN route is handed to FoxCore.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartWithNetwork(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    tun_fd: jint,
    config_json: JString<'_>,
    network_handle: jlong,
    host: JObject<'_>,
) -> jlong {
    native_start(env, tun_fd, config_json, network_handle, host)
}

/// Starts with one signed DNS rule set present before the resolver can answer
/// its first query. Additional updates use `nativeInstallDnsRuleSet`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartWithNetworkAndDnsRuleSet(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    tun_fd: jint,
    config_json: JString<'_>,
    network_handle: jlong,
    name: JString<'_>,
    manifest: JByteArray<'_>,
    signature: JByteArray<'_>,
    artifact: JByteArray<'_>,
    host: JObject<'_>,
) -> jlong {
    reap_stop_reapers();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let tun_fd = take_tun_fd(tun_fd)?;
        let bundle = read_rule_set_bundle(&mut env, name, &manifest, &signature, &artifact)?;
        start_owned(
            &mut env,
            tun_fd,
            config_json,
            network_handle,
            host,
            vec![bundle],
            Vec::new(),
        )
    }));
    finish_native_start(&mut env, result)
}

/// Starts with one FST artifact whose trust comes from the signed APK.
///
/// There is intentionally no corresponding unsigned update entry point:
/// downloaded bytes must use `nativeInstallDnsRuleSet` and pass the pinned
/// signature, freshness and rollback policy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartWithNetworkAndTrustedDnsRuleSet(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    tun_fd: jint,
    config_json: JString<'_>,
    network_handle: jlong,
    name: JString<'_>,
    artifact: JByteArray<'_>,
    host: JObject<'_>,
) -> jlong {
    reap_stop_reapers();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let tun_fd = take_tun_fd(tun_fd)?;
        let name = read_rule_set_name(&mut env, name)?;
        let artifact =
            read_bounded_array(&env, &artifact, MAX_DNS_RULE_SET_ARTIFACT_BYTES, "artifact")?;
        start_owned(
            &mut env,
            tun_fd,
            config_json,
            network_handle,
            host,
            Vec::new(),
            vec![TrustedRuleSetBundle::from_signed_package(name, artifact)],
        )
    }));
    finish_native_start(&mut env, result)
}

fn native_start(
    mut env: JNIEnv<'_>,
    tun_fd: jint,
    config_json: JString<'_>,
    network_handle: jlong,
    host: JObject<'_>,
) -> jlong {
    reap_stop_reapers();
    let result = catch_unwind(AssertUnwindSafe(|| {
        start(&mut env, tun_fd, config_json, network_handle, host)
    }));
    finish_native_start(&mut env, result)
}

/// Render an error with everything underneath it.
///
/// `Display` on an `io::Error` prints only the top of the chain, and the top is
/// routinely the least useful part: Arti's bootstrap failure says "problem with
/// filesystem permissions" while the source underneath names the directory and
/// the mode that were wrong. Three device runs were lost to that difference, so
/// the whole chain goes out.
fn render_error(error: &(dyn std::error::Error + 'static)) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        // Arti and std both repeat the parent's text in places; a message that
        // says the same thing four times is its own kind of unreadable.
        if !rendered.contains(&text) {
            rendered.push_str(": ");
            rendered.push_str(&text);
        }
        source = cause.source();
    }
    rendered
}

fn finish_native_start(
    env: &mut JNIEnv<'_>,
    result: Result<Result<u64, String>, Box<dyn std::any::Any + Send>>,
) -> jlong {
    match result {
        Ok(Ok(handle)) => handle as jlong,
        Ok(Err(message)) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            0
        }
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "panic inside FoxCore JNI boundary",
            );
            0
        }
    }
}

/// Verify and atomically install an update. The current artifact remains active
/// on every conversion, signature, freshness, rollback or rebuild error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeInstallDnsRuleSet(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    name: JString<'_>,
    manifest: JByteArray<'_>,
    signature: JByteArray<'_>,
    artifact: JByteArray<'_>,
) -> jlong {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let runtime = runtime(handle).ok_or_else(|| "FoxCore handle is not running".to_string())?;
        let bundle = read_rule_set_bundle(&mut env, name, &manifest, &signature, &artifact)?;
        runtime
            .install_dns_rule_set(bundle)
            .map_err(|error| error.to_string())
    }));
    match result {
        Ok(Ok(revision)) => jlong::try_from(revision).unwrap_or(jlong::MAX),
        Ok(Err(message)) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            0
        }
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "panic inside FoxCore DNS rule-set boundary",
            );
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStop(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    if handle <= 0 {
        return NATIVE_STOP_UNKNOWN_HANDLE;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let key = handle as u64;
        let Some(runtime) = lock(registry()).get(&key).cloned() else {
            return NATIVE_STOP_UNKNOWN_HANDLE;
        };
        ecosystem::release_engine_handles(key, &runtime);
        match runtime.stop() {
            StopResult::Stopped => {
                lock(registry()).remove(&key);
                NATIVE_STOPPED
            }
            StopResult::AlreadyStopped => {
                lock(registry()).remove(&key);
                NATIVE_ALREADY_STOPPED
            }
            // Keep both the Arc and the JoinHandle reachable. A retry can
            // complete the join, while the Android worker lease prevents a
            // replacement generation from overlapping this one.
            StopResult::TimedOut => {
                schedule_stop_reaper(key, runtime);
                NATIVE_STOP_TIMED_OUT
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "panic inside FoxCore JNI stop boundary",
            );
            NATIVE_STOP_PANICKED
        }
    }
}

/// Stop this engine and drop the handle without waiting for the worker at all.
///
/// `nativeStop` is the ordinary path and reports whether the worker actually
/// finished. This is for the case where it reported `TIMED_OUT` and the app is
/// being torn down anyway: cancellation is requested, the handle stops
/// resolving, and a wedged worker goes to the process-wide quarantine list,
/// which keeps ownership until it really exits. Android's process worker lease
/// means a replacement generation still cannot start until then — a force kill
/// buys the app a return from the call, not a free descriptor.
///
/// Unlike `nativeStop` this never waits on the worker, not even the stop
/// timeout, and — the part that is easy to lose — it does not queue behind a
/// `nativeStop` that is already waiting one out. It is called precisely because
/// that call has not come back, so serialising against it would be the same
/// wait wearing a different name.
///
/// The one join left on this path is the continuity watch thread, which touches
/// a channel and two atomics and is bounded at `JOIN_GRACE` (250 ms).
///
/// Returns the same codes as `nativeStop`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeForceKill(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    if handle <= 0 {
        return NATIVE_STOP_UNKNOWN_HANDLE;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let key = handle as u64;
        // Removed first: after this call the app is entitled to believe the
        // handle is gone, whatever the worker is still doing.
        let Some(runtime) = lock(registry()).remove(&key) else {
            return NATIVE_STOP_UNKNOWN_HANDLE;
        };
        ecosystem::release_engine_handles(key, &runtime);
        match runtime.force_kill() {
            StopResult::Stopped => NATIVE_STOPPED,
            StopResult::AlreadyStopped => NATIVE_ALREADY_STOPPED,
            // The quarantine list owns the worker now. Nothing in the app has
            // to wait for it, and nothing here did.
            StopResult::TimedOut => NATIVE_STOP_TIMED_OUT,
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "panic inside FoxCore JNI force-kill boundary",
            );
            NATIVE_STOP_PANICKED
        }
    }
}

/// Release the lanes a continuity hold suspended, at the cost of a reconnect.
///
/// `token` is the one carried by the `confirmation_required` event. An older
/// token is refused rather than accepted, so a dialog the user answers late
/// cannot resume a lane that has since failed again for a different reason —
/// the app must read the newer event and ask again.
///
/// Returns `0` confirmed, `1` nothing pending, `2` stale token, `3` unknown
/// handle, `-1` panic.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeConfirmContinuity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: jlong,
) -> jint {
    match catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime(handle) else {
            return NATIVE_CONTINUITY_UNKNOWN_HANDLE;
        };
        let Ok(token) = u64::try_from(token) else {
            // A negative token is not a token this core ever minted.
            return NATIVE_CONTINUITY_STALE_TOKEN;
        };
        match runtime.confirm_continuity(token) {
            ConfirmResult::Confirmed => NATIVE_CONTINUITY_CONFIRMED,
            ConfirmResult::NothingPending => NATIVE_CONTINUITY_NOTHING_PENDING,
            ConfirmResult::StaleToken => NATIVE_CONTINUITY_STALE_TOKEN,
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "panic inside FoxCore JNI continuity boundary",
            );
            NATIVE_CONTINUITY_PANICKED
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStats(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = runtime(handle)
            .map(|runtime| runtime.snapshot_json())
            .unwrap_or_else(|| "{}".into());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

const EMPTY_TRAFFIC_MAP: &str = concat!(
    r#"{"generation":0,"connections":[],"packages":[],"lanes":[],"omitted_rows":0,"#,
    r#""dropped_events":0,"dns":{"queries":0,"blocked":0,"allowed":0}}"#
);

/// The traffic map as JSON: live flows with the route each one took, per-app
/// and per-lane totals, DNS verdict counts and the active selector members.
///
/// Separate from `nativeStats` because it is proportional to the number of open
/// flows: a UI polling the cheap counters every second must not pay for this,
/// and a screen that wants the map asks for it explicitly.
///
/// This is the only source of per-app numbers while the VPN is up — Android's
/// own `NetworkStats` attributes every tunnelled byte to the tun interface
/// rather than to the app behind it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeTrafficMap(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    traffic_map(env, handle)
}

/// The name this call had while the document was only a connection list. Same
/// document, and the old fields are unchanged; kept so the existing app ABI
/// keeps working.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeConnections(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    traffic_map(env, handle)
}

fn traffic_map(env: JNIEnv<'_>, handle: jlong) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = runtime(handle)
            .map(|runtime| runtime.traffic_map_json())
            .unwrap_or_else(|| EMPTY_TRAFFIC_MAP.to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Take the map updates produced since the previous call.
///
/// A map that is only polled cannot show a flow that opened and closed between
/// two polls; this stream can. It is bounded and drops on overflow, so a screen
/// that stopped reading loses updates rather than holding up traffic —
/// `dropped` says how many, and a non-zero value means the caller must
/// reconcile against `nativeTrafficMap` instead of trusting the deltas.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeDrainTrafficEvents(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    max: jint,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let max = usize::try_from(max).unwrap_or(0).max(1);
        let json = runtime(handle)
            .map(|runtime| runtime.drain_traffic_events_json(max))
            .unwrap_or_else(|| r#"{"events":[],"dropped":0}"#.to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Take the audit events produced since the previous call.
///
/// Returns `{"events":[...],"dropped":N}`. `dropped` is non-zero when the app
/// read too slowly and the bounded queue discarded events — the data plane is
/// never allowed to wait for this consumer, so a slow reader loses records and
/// is told so rather than throttling traffic.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeDrainEvents(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    max: jint,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        // A non-positive request is a caller bug, not a reason to return
        // everything: clamping to one keeps the batch bounded either way.
        let max = usize::try_from(max).unwrap_or(0).max(1);
        let json = runtime(handle)
            .map(|runtime| runtime.drain_events_json(max))
            .unwrap_or_else(|| r#"{"events":[],"dropped":0}"#.to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Atomically replace route and DNS policy without restarting the TUN or
/// outbound sessions.
///
/// Returns the installed revision, which is always positive, or a **negative**
/// refusal code: `-1` invalid policy, `-2` unknown outbound, `-3` Tor
/// unavailable in this build or profile, `-4` I2P unavailable, `-5` an overlay
/// route without fake-IP DNS, `-6` per-app routing with no platform
/// attribution, `-7` revision conflict. Zero means the handle is not running.
///
/// Codes rather than an exception because the app has to act differently on
/// each: "this build has no Tor" is permanent and should retire the switch,
/// "the policy is malformed" is an app bug, and a revision conflict is a
/// retry. All three used to arrive as the same `IllegalStateException` with
/// prose inside it, so the app could only ever show the same shrug (D11). The
/// live tunnel is unaffected either way — a refused reload changes nothing.
///
/// Seven of the eight codes name the thing that was wrong and can be acted on
/// alone. `-1` cannot: it covers a truncated write, a missing comma, a field
/// spelled wrong and a field this schema removed, and the app is expected to
/// respond differently to at least the first and the last. The words are kept
/// where [`Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLastPolicyError`]
/// can read them, which is the remainder D11 left behind.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeReloadPolicy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    policy_json: JString<'_>,
) -> jlong {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime(handle) else {
            return 0;
        };
        let Ok(json) = env.get_string(&policy_json) else {
            runtime.record_policy_error("the policy document is not readable as a Java string");
            return -(PolicyRefusal::Invalid as jlong);
        };
        let policy = match PolicyConfig::parse(&String::from(json)) {
            Ok(policy) => policy,
            Err(error) => {
                runtime.record_policy_error(&error.to_string());
                return -(PolicyRefusal::Invalid as jlong);
            }
        };
        match runtime.reload_policy(policy) {
            Ok(revision) => revision as jlong,
            Err(error) => -jlong::from(error.code()),
        }
    }));
    match result {
        Ok(revision) => revision,
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "panic inside FoxCore JNI boundary",
            );
            0
        }
    }
}

/// Stop the live flows a target names, without touching policy.
///
/// The second half of blocking an app. `nativeReloadPolicy` decides what the
/// *next* flow is allowed to do and deliberately leaves open connections alone
/// — a reordered routing rule must not kill a download. That is wrong for a
/// `Block`, where the user's intent is that the app stops talking and the old
/// behaviour let it keep talking over the connections it already had. The two
/// are separate calls because the difference is not in the policy document: the
/// same edited rule list arrives either way, and only the caller knows which it
/// meant.
///
/// Call **after** the reload, so the new policy is already refusing new flows
/// by the time the old ones are cut and the app cannot open one in between.
///
/// `target_json` names the target. One required field per kind:
///
/// ```json
/// {"kind": "all"}
/// {"kind": "lane",     "lane": "vpn"}
/// {"kind": "uid",      "uid": 10123}
/// {"kind": "package",  "package": "com.example.app"}
/// {"kind": "outbound", "outbound": "default"}
/// {"kind": "flow",     "flow": 42}
/// ```
///
/// `lane` is one of `vpn`, `tor`, `i2p`, `direct`. `flow` is the `id` of a row
/// from `nativeTrafficMap`. Unknown kinds, missing fields and extra fields are
/// all refused rather than interpreted: the two ways to misread a malformed
/// target are to cut nothing and to cut everything, and neither is a guess
/// worth making for the user.
///
/// Returns **the number of live flows revoked**, which is zero or more, or a
/// negative refusal: `-1` a panic crossed the boundary, `-2` the handle is not
/// running, `-3` the target is missing, unreadable or does not parse.
///
/// Zero is a success, not an error — the app was not talking, and the state the
/// caller asked for already holds. Idempotent and safe to call while traffic is
/// moving; calling it twice reports the flows that have not finished tearing
/// down yet and does nothing further to them.
///
/// A revoked TCP flow is reset towards the application, so its `connect`ed
/// socket fails at once rather than hanging until the app's own timeout; a
/// revoked UDP flow stops and releases its session. Both appear in
/// `nativeStats` as `flows_revoked` and in `nativeDrainEvents` as a
/// `flows_revoked` event carrying the target and the count.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeRevokeFlows(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    target_json: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return NATIVE_REVOKE_NO_ENGINE;
        };
        let Some(json) = read_string(&mut env, &target_json) else {
            return NATIVE_REVOKE_INVALID_TARGET;
        };
        let Ok(target) = RevokeTarget::parse(&json) else {
            return NATIVE_REVOKE_INVALID_TARGET;
        };
        // Saturating rather than `as`: the count is bounded by the engine's own
        // flow caps and cannot approach `i32::MAX`, but a silent wrap here
        // would report a teardown of a thousand flows as a negative refusal
        // code, which is the one way this call could lie.
        jint::try_from(runtime.revoke_flows(&target)).unwrap_or(jint::MAX)
    })
}

/// Why the most recent reload on this handle was refused, in words.
///
/// Empty when the last reload was applied, when none has been attempted, or
/// when the handle is not running — never `null`, so the caller has one shape
/// to read rather than two.
///
/// Read *after* a negative return from `nativeReloadPolicy`, and only for the
/// detail: the code is still the answer the app switches on. It exists because
/// `-1` alone cannot be acted on. The other seven refusals each name their
/// cause — no Tor in this build, an outbound this generation does not have, a
/// revision somebody else already moved — while `-1` is "does not parse or does
/// not validate", which is a truncated write and a field removed two releases
/// ago in the same code, and those need different fixes.
///
/// Deliberately not folded into the return value or thrown: the whole point of
/// D11 was that prose is not switchable, and the whole point of this is that a
/// switch with one general arm is not diagnosable. Both are true, so there are
/// two calls.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLastPolicyError(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let message = runtime(handle)
            .and_then(|runtime| runtime.last_policy_error())
            .unwrap_or_default();
        env.new_string(message)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Where the last stop in this process spent its budget, as JSON.
///
/// Takes no handle, and that is the whole design. The caller who needs this has
/// just been told its stop timed out; the handle it would have passed is the
/// one it is about to force-kill, and `nativeStats` on a dead handle answers
/// `{}`. Before this existed a stop timeout reached the journal as a single
/// line naming only its own deadline — three seconds that could have been the
/// engine loop or the Tokio shutdown, with no way to tell which without a
/// device round trip and a custom build.
///
/// Fields: `phase` (`engine` | `runtime_shutdown` | `complete`) says how far
/// the worker got, `engine_ms` and `shutdown_ms` say how long each half took,
/// `null` meaning "not reached". `generation` names the runtime it describes,
/// so a snapshot taken late cannot be mistaken for the current one.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLastStopDiagnostics(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        env.new_string(foxcore_runtime::last_stop_diagnostics_json())
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Compatibility callback used by the existing app ABI. It forces stateful
/// outbounds to reconnect but leaves the current Android network handle intact.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeNetworkChanged(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(runtime) = runtime(handle) {
            runtime.network_changed();
        }
    }));
}

/// New ABI for ConnectivityManager.NetworkCallback. The handle is the value
/// returned by Android's `Network.getNetworkHandle()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeNetworkChangedWithHandle(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network_handle: jlong,
) {
    if network_handle < 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(runtime) = runtime(handle) {
            runtime.network_changed_with_handle(network_handle as u64);
        }
    }));
}

// ----------------------------------------------------------------- LAN proxy
//
// SOCKS5 and HTTP CONNECT on the phone's Wi-Fi address, for the other devices on
// that network. The component behind these four calls has been complete for some
// time; until now nothing here could reach it, so the app drew a saved toggle as
// though it were live state. These are the calls that make the toggle mean
// something, and `nativeLanProxyStatus` is what it should be drawn from.

/// The one identity a LAN proxy runs under. Fixed rather than supplied by the
/// caller: the component refuses a duplicate, the runtime holds exactly one
/// session, and a name the app could choose would be a way to end up with two
/// answers to "is it running".
const LAN_PROXY_COMPONENT_ID: &str = "runtime:lan-proxy";

/// Confirm, for this engine generation, that the user agreed to serve this
/// network.
///
/// `nativeStartLanProxy` refuses a network that has not been through here. The
/// two calls must be given the same `networkHandle`, `interfaceName` and
/// `transport`, because those are what the confirmation is keyed on;
/// `localAddress` is read and validated but is deliberately not part of the key,
/// so a DHCP renewal does not ask the user again.
///
/// Returns `0` confirmed, `1` an argument was unreadable or malformed, `2` the
/// engine handle is not running, `5` the confirmation list is full (64 networks),
/// `10` the network cannot be identified at all, `-1` panic.
///
/// A confirmation lasts for one Android `Network` and one engine generation, and
/// is held in memory only. Reconnecting to the same Wi-Fi mints a new network
/// handle and therefore asks again — which is stricter than the component's own
/// SSID-keyed rule, and stricter is the only direction this boundary is allowed
/// to be wrong in. See [`lan_session_identity`].
///
/// Confirming is not authorization to bind. A cellular or unknown transport can
/// be recorded here and is still refused at start, where the binding rules live;
/// nothing is gained by a second copy of them in the ABI layer.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeConfirmLanNetwork(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network_handle: jlong,
    local_address: JString<'_>,
    interface_name: JString<'_>,
    transport: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let (Some(local_address), Some(interface_name), Some(transport), Ok(network_handle)) = (
            read_string(&mut env, &local_address),
            read_string(&mut env, &interface_name),
            read_string(&mut env, &transport),
            u64::try_from(network_handle),
        ) else {
            runtime.record_lan_error(
                "the LAN network arguments are not readable, or the network handle is negative",
            );
            return RESULT_INVALID_ARGUMENT;
        };
        let binding = match lan_binding(
            network_handle,
            &local_address,
            &interface_name,
            &transport,
            runtime.generation(),
        ) {
            Ok(binding) => binding,
            Err(reason) => {
                runtime.record_lan_error(&reason);
                return RESULT_INVALID_ARGUMENT;
            }
        };
        match runtime.component_manager().confirm_lan_network(&binding) {
            Ok(()) => RESULT_OK,
            Err(error) => {
                runtime.record_lan_error(&error.to_string());
                component_result(error)
            }
        }
    })
}

/// Bind the LAN listeners described by `configJson`.
///
/// Returns `0` bound, `1` the document is malformed or asks for something that
/// cannot be served, `2` the engine handle is not running, `4` the component
/// identity is already taken, `7` the engine is stopping or a required upstream
/// (VPN/Tor) is unavailable, `9` the binding is refused — a wildcard or cellular
/// address, or an interface that is not one this may listen on, `10` this network
/// was not confirmed, `11` a listener could not bind (a port already in use is the
/// usual reason), `-1` panic.
///
/// Every refusal also leaves its reason in `nativeLanProxyStatus().last_error`,
/// in words. The code is what the app switches on; the words are what it shows.
///
/// Calling this while a proxy is running replaces it — see
/// [`foxcore_runtime::CoreRuntime::install_lan_proxy`]. Nothing is left listening
/// if the new binding fails.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartLanProxy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    config_json: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        // The document carries the proxy password, so the copy this side holds
        // is wiped rather than left in whatever heap page it landed on.
        let Some(json) = read_string(&mut env, &config_json).map(Zeroizing::new) else {
            runtime.record_lan_error("the LAN proxy request is not readable as a Java string");
            return RESULT_INVALID_ARGUMENT;
        };
        let (config, binding) = match lan_start_request(&json, runtime.generation()) {
            Ok(request) => request,
            Err(reason) => {
                runtime.record_lan_error(&reason);
                return RESULT_INVALID_ARGUMENT;
            }
        };
        match runtime.install_lan_proxy(config, binding) {
            Ok(()) => RESULT_OK,
            // `install_lan_proxy` records the reason itself: it is the only
            // place that knows which of the component's refusals it hit.
            Err(error) => component_result(error),
        }
    })
}

/// Close the LAN listeners and invalidate their credentials.
///
/// Idempotent: `0` whether or not one was running, because "stop what is not
/// running" is not an error the app can act on differently. `2` is an engine
/// handle that is not running — which has already stopped everything this call
/// would have — and `-1` is a panic.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStopLanProxy(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    guarded(|| match runtime(handle) {
        Some(runtime) => {
            runtime.stop_lan_proxy();
            RESULT_OK
        }
        None => RESULT_NO_ENGINE,
    })
}

/// Everything the LAN screen draws, as one JSON document.
///
/// This is the source of truth for that screen. A saved preference says what the
/// user asked for; only this says what is true — whether the listeners are up,
/// on which addresses, and why the last attempt failed if it did.
///
/// Always a well-formed document, never `null` and never `{}` — including for a
/// handle that is not running and for an engine where nothing was ever started,
/// both of which answer `state":"stopped"`. Fields:
///
/// * `state` — `stopped`, `checking_permission`, `resolving_network`,
///   `acquiring_components`, `binding_listeners`, `ready`, `degraded`,
///   `network_lost`, `stopping`, `failed`.
/// * `socks_address`, `http_address` — `"address:port"` for a device on this
///   network to point its client at, or `null` when that protocol was not
///   offered.
/// * `preset`, `network_handle`, `local_address`, `interface_name`, `transport`
///   — what the running proxy was started with, all `null` when none is.
/// * `last_error` — why the last start or stop was refused, or `null`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLanProxyStatus(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = runtime(handle)
            .map(|runtime| runtime.lan_proxy_status_json())
            .unwrap_or_else(|| lan_proxy_stopped_status_json().to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// The document `nativeStartLanProxy` accepts.
///
/// `deny_unknown_fields` and no defaults: every field is required, and a field
/// this core does not know is an error rather than something silently dropped.
/// A LAN listener is the largest blast radius in the platform and a request that
/// half-arrived must not half-bind.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct LanProxyRequest {
    /// `vpn`, `tor` or `mixed`. There is no direct preset and there will not be
    /// one: a LAN proxy whose upstream could fall back to the open network would
    /// carry another device's traffic in the clear.
    preset: String,
    /// Zero means "do not offer this protocol". Both zero is refused.
    socks_port: u16,
    http_port: u16,
    username: String,
    password: String,
    /// From Android's `Network.getNetworkHandle()`, and the same value that was
    /// passed to `nativeConfirmLanNetwork`.
    network_handle: u64,
    /// The IPv4 address the platform reported for that network. Never a
    /// wildcard: `0.0.0.0` on a phone is reachable from the mobile network.
    local_address: String,
    interface_name: String,
    /// `wifi`, `ethernet`, `cellular` or `unknown`. The last two are accepted by
    /// the parser and refused by the binding, so the app is told which rule it
    /// hit rather than being handed a parse error for a real network.
    transport: String,
}

/// Parse a start request into the two values the runtime takes.
///
/// The `Err` is the sentence the app shows. Every refusal here is a refusal —
/// nothing in this function can panic on a hostile or truncated document.
fn lan_start_request(
    json: &str,
    generation: u64,
) -> Result<(LanProxyConfig, NetworkBinding), String> {
    let mut request: LanProxyRequest = serde_json::from_str(json)
        .map_err(|error| format!("the LAN proxy request is not valid: {error}"))?;
    // Out of the struct and into a wiping wrapper before anything below can
    // return early. Every refusal from here on is a path that would otherwise
    // free the parsed password without erasing it, and there are five of them.
    // `into_bytes` reuses the string's own allocation, so this moves the secret
    // rather than copying it.
    let password = Zeroizing::new(std::mem::take(&mut request.password).into_bytes());
    // A proxy with neither protocol is a component that takes runtime leases,
    // holds an identity and serves nobody.
    if request.socks_port == 0 && request.http_port == 0 {
        return Err(
            "the LAN proxy request offers neither protocol: socks_port and http_port \
             are both zero"
                .into(),
        );
    }
    let preset = lan_preset(&request.preset).ok_or_else(|| {
        format!(
            "the LAN proxy preset '{}' is not one of vpn, tor, mixed",
            request.preset
        )
    })?;
    let binding = lan_binding(
        request.network_handle,
        &request.local_address,
        &request.interface_name,
        &request.transport,
        generation,
    )?;
    let id = ComponentId::new(LAN_PROXY_COMPONENT_ID)
        .map_err(|error| format!("the LAN proxy identity is unusable: {error}"))?;
    // The one copy this makes is moved straight into `LanCredentials`, which
    // holds it zeroizing; the original stays in `password` and is wiped when
    // this function returns, however it returns.
    let credentials = LanCredentials::new(
        std::mem::take(&mut request.username),
        password.as_slice().to_vec(),
    )
    .ok_or_else(|| {
        "the LAN proxy credentials are unusable: username must be 1..=255 ASCII bytes \
         and password 1..=255 bytes, and neither may be empty"
            .to_string()
    })?;
    Ok((
        LanProxyConfig {
            id,
            preset,
            socks_port: request.socks_port,
            http_port: request.http_port,
            credentials,
        },
        binding,
    ))
}

/// Bind one named loopback CONNECT listener for a single application.
///
/// This is the call the Web Apps feature is built on. Android runs every web app
/// in one process under one uid, so the TUN cannot route them apart; a separate
/// authenticated loopback proxy per app is the only separation available, and
/// this creates one.
///
/// `configJson`:
///
/// ```json
/// {
///   "name": "webapp.mastodon",
///   "http_port": 0,
///   "username": "...",
///   "password": "...",
///   "upstream": "profile",
///   "max_sessions": 8
/// }
/// ```
///
/// `http_port` may be omitted or `0`, which binds an ephemeral port — the
/// recommended form, since a phone has no port registry and a fixed number is a
/// coin flip against every other app. Read the bound address back from
/// [`Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLoopbackInbounds`].
/// `max_sessions` may be omitted; it defaults to 8 and is capped at 64.
/// `upstream` is `profile`, `tor` or `direct` — there is no fourth value and no
/// "whatever is available".
///
/// Returns `0` bound, `1` the document is malformed or a field is out of range,
/// `2` the engine handle is not running, `4` the name **or either credential** is
/// already in use by another inbound or by `runtime.control_proxy`, `5` this
/// generation already holds the maximum number of inbounds, `7` the upstream is
/// not available in this generation — no Tor in this build, or no Tor outbound
/// in the profile — `9` the credentials are unusable, `11` the port could not be
/// bound, `-1` panic.
///
/// `4` covers a repeated username or a repeated password as well as a repeated
/// name, and that is not fussiness: every one of these listeners is on
/// `127.0.0.1`, where any app on the device can connect to any port. The
/// credential is the entire separation between the web app you routed through
/// Tor and the one you left on the profile, so two inbounds must never share
/// one. Generate a fresh pair per inbound.
///
/// Nothing is left listening on any refusal. A `7` in particular is the
/// fail-closed answer and never a downgrade: an inbound whose upstream is
/// missing does not become a direct one.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartLoopbackInbound(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    config_json: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        // The document carries the inbound's password; the copy this side holds
        // is wiped rather than left in whatever heap page it landed on.
        let Some(json) = read_string(&mut env, &config_json).map(Zeroizing::new) else {
            return RESULT_INVALID_ARGUMENT;
        };
        let Ok(config) = serde_json::from_str::<LoopbackInboundConfig>(&json) else {
            return RESULT_INVALID_ARGUMENT;
        };
        if config.validate().is_err() {
            return RESULT_INVALID_ARGUMENT;
        }
        match runtime.install_loopback_inbound(&config) {
            Ok(()) => RESULT_OK,
            Err(error) => component_result(error),
        }
    })
}

/// Close one named loopback inbound and invalidate its credentials.
///
/// `0` when one was running and is now closed, `3` when no inbound of that name
/// exists — which is a real distinction here and not pedantry: the app tears
/// these down when a web app is removed, and "there was nothing to remove"
/// usually means the name it is holding is not the name it created. `1` the name
/// is not readable, `2` the engine handle is not running (which has already
/// closed everything this call would have), `-1` panic.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStopLoopbackInbound(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    name: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let Some(name) = read_string(&mut env, &name) else {
            return RESULT_INVALID_ARGUMENT;
        };
        if runtime.remove_loopback_inbound(&name) {
            RESULT_OK
        } else {
            RESULT_NOT_FOUND
        }
    })
}

/// Every named loopback inbound that is listening, as one JSON document.
///
/// This is where the app learns which port to put in each web app's `Proxy`, and
/// it is the only place that knows: the port may have been ephemeral, and the
/// state may have moved since the start call returned.
///
/// Always well formed, never `null` — a handle that is not running answers
/// `{"inbounds":[]}`, the same shape as a running engine with none configured.
///
/// ```json
/// {"inbounds":[{"name":"webapp.mastodon","upstream":"profile",
///               "state":"ready","http_address":"127.0.0.1:41337"}]}
/// ```
///
/// `upstream` is what the inbound resolves to, not what its last session
/// managed to reach. `state` uses the same vocabulary as `nativeLanProxyStatus`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLoopbackInbounds(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = runtime(handle)
            .map(|runtime| runtime.loopback_inbounds_json())
            .unwrap_or_else(|| loopback_inbounds_empty_json().to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// The binding both entry points agree on, from the four values both are given.
fn lan_binding(
    network_handle: u64,
    local_address: &str,
    interface_name: &str,
    transport: &str,
    generation: u64,
) -> Result<NetworkBinding, String> {
    // IPv4 only, and parsed rather than trusted: this string becomes a bind
    // address. IPv6 is refused here rather than at bind time so the app is told
    // why. (A wildcard parses fine and is refused by the component, which is the
    // rule's home.)
    let local_address: Ipv4Addr = local_address
        .parse()
        .map_err(|_| format!("the LAN local address '{local_address}' is not an IPv4 address"))?;
    let transport = lan_transport(transport).ok_or_else(|| {
        format!("the LAN transport '{transport}' is not one of wifi, ethernet, cellular, unknown")
    })?;
    Ok(NetworkBinding {
        network_handle,
        interface_name: interface_name.to_owned(),
        local_address: IpAddr::V4(local_address),
        ssid_hash: Some(lan_session_identity(network_handle)),
        transport,
        generation,
    })
}

fn lan_preset(preset: &str) -> Option<LanProxyPreset> {
    match preset {
        "vpn" => Some(LanProxyPreset::Vpn),
        "tor" => Some(LanProxyPreset::Tor),
        "mixed" => Some(LanProxyPreset::Mixed),
        _ => None,
    }
}

fn lan_transport(transport: &str) -> Option<LanTransport> {
    match transport {
        "wifi" => Some(LanTransport::Wifi),
        "ethernet" => Some(LanTransport::Ethernet),
        "cellular" => Some(LanTransport::Cellular),
        "unknown" => Some(LanTransport::Unknown),
        _ => None,
    }
}

/// What goes in `NetworkBinding::ssid_hash` at this boundary, and why it is not
/// an SSID.
///
/// The component identifies a network by a 32-byte hash so that a reconnect —
/// new network handle, new DHCP address — is still recognisably the same Wi-Fi,
/// and asking the user again every time is what trains them to click yes.
/// Android only names the SSID to an app holding a location permission, and this
/// ABI deliberately does not require one for a feature that is about the local
/// network rather than the user's position.
///
/// So the identity here is the *session*: a domain-separated hash of the Android
/// network handle. The consequences are exactly two, and both are the safe
/// direction:
///
///   * a confirmation covers one `Network` and no more, so reconnecting to the
///     same access point asks again — stricter than the SSID rule, never looser;
///   * the tag means this value cannot collide with a genuine SSID hash, so a
///     session identity can never be mistaken for a network the user confirmed
///     under a build that does have the permission.
///
/// It is never `None`: a binding without a fingerprint cannot be confirmed at
/// all, which would leave the whole feature unreachable from this ABI.
fn lan_session_identity(network_handle: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foxhole-lan-session-network-v1");
    hasher.update(network_handle.to_be_bytes());
    hasher.finalize().into()
}

fn start(
    env: &mut JNIEnv<'_>,
    tun_fd: jint,
    config_json: JString<'_>,
    network_handle: jlong,
    host: JObject<'_>,
) -> Result<u64, String> {
    let tun_fd = take_tun_fd(tun_fd)?;
    start_owned(
        env,
        tun_fd,
        config_json,
        network_handle,
        host,
        Vec::new(),
        Vec::new(),
    )
}

/// Adopt the descriptor `nativeStart` was handed, after asking the kernel
/// whether it is one.
///
/// A number is not a descriptor. `OwnedFd` reserves nothing, so taking a
/// number this process does not hold open has two ends, and both are worse
/// than an exception:
///
///   * the kernel is free to give that exact number to the next `socket()`,
///     and `CoreRuntime::start` opens several straight away — after which the
///     "TUN" and a live outbound socket are one descriptor, the data plane
///     writes IP packets into the proxy connection, and any later failure path
///     closes that socket by dropping this guard;
///   * and if nothing takes the number, `OwnedFd::drop` calls `close`, gets
///     `EBADF`, and the standard library **aborts the process** — "IO Safety
///     violation: owned file descriptor already closed". On a device that is
///     a native crash of the VPN service with no Java exception and nothing in
///     the log naming FoxCore.
///
/// `F_GETFD` separates "Java transferred a descriptor" from "Java transferred
/// a number" for the price of one syscall per start.
///
/// A transferred descriptor is then validated fail-closed before ownership can
/// reach the runtime. On every host it must be a read/write character device;
/// on Android `TUNGETIFF` must additionally identify an `IFF_TUN` interface.
fn take_tun_fd(tun_fd: jint) -> Result<OwnedFd, String> {
    if tun_fd < 0 {
        return Err("TUN file descriptor must be non-negative".into());
    }
    let raw = tun_fd as RawFd;
    // SAFETY: `F_GETFD` reads one descriptor's flags. It touches no memory in
    // this process and is defined for every integer: an unheld number answers
    // EBADF rather than doing anything.
    if unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        return Err(format!(
            "TUN file descriptor {tun_fd} is not open in this process: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the descriptor is open, and nativeStart's contract transfers
    // ownership of a detached fd to FoxCore. OwnedFd closes it on every
    // parse/start failure path.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    validate_tun_fd(owned.as_raw_fd())
        .map_err(|error| format!("TUN file descriptor {tun_fd} failed validation: {error}"))?;
    Ok(owned)
}

/// What kind of file the descriptor actually is, as `st_mode & S_IFMT`.
///
/// Split out from [`take_tun_fd`] so the `fstat` branch is reachable from a
/// host test: everything else that distinguishes a tun device from a socket is
/// behind `cfg(target_os = "android")` and needs Android device acceptance.
/// This classification check runs on every platform the tests run on.
fn tun_fd_kind(raw: RawFd) -> std::io::Result<u64> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` writes one `struct stat` through the pointer and reads
    // nothing else in this process. The buffer is a live, correctly aligned
    // `libc::stat`, and the descriptor was shown to be open one syscall ago.
    if unsafe { libc::fstat(raw, status.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fstat` returned 0, which is its contract for having filled the
    // structure.
    let status = unsafe { status.assume_init() };
    // Android's 32-bit libc exposes `stat::st_mode` as u32 but `mode_t` (and
    // therefore `S_IFMT`) as u16. Normalize both operands before masking so
    // this compiles identically on the host and every shipping Android ABI.
    Ok(u64::from(status.st_mode) & u64::from(libc::S_IFMT))
}

/// Validate the packet device before any runtime task can read or write it.
fn validate_tun_fd(raw: RawFd) -> std::io::Result<()> {
    let kind = tun_fd_kind(raw)?;
    if kind != u64::from(libc::S_IFCHR) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("descriptor is not a character device (S_IFMT=0o{kind:o})"),
        ));
    }

    // SAFETY: F_GETFL reads flags from an open descriptor and touches no Rust
    // memory. The fd is owned by `take_tun_fd` while this runs.
    let status_flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if status_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if status_flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "descriptor is not open for both packet reads and writes",
        ));
    }

    #[cfg(target_os = "android")]
    validate_android_tun(raw)?;
    Ok(())
}

/// Ask Android's Linux kernel to identify the transferred interface.
///
/// A character-device check alone still accepts `/dev/null`, serial devices and
/// any other open character fd. Android SELinux explicitly grants third-party
/// VPN apps `TUNGETIFF` on the TUN descriptor received from the framework, so
/// this is the kernel-backed discriminator rather than a filename heuristic.
#[cfg(target_os = "android")]
fn validate_android_tun(raw: RawFd) -> std::io::Result<()> {
    const IFF_TUN: libc::c_short = 0x0001;
    let mut request = std::mem::MaybeUninit::<libc::ifreq>::zeroed();
    // SAFETY: `request` is a correctly sized, writable `ifreq`; TUNGETIFF
    // writes the interface name and flags and does not retain the pointer.
    if unsafe { libc::ioctl(raw, libc::TUNGETIFF as _, request.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful TUNGETIFF initialized the ifreq, including the flags
    // member of its union, which is the member this ioctl defines.
    let flags = unsafe { request.assume_init().ifr_ifru.ifru_flags };
    if flags & IFF_TUN != IFF_TUN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "descriptor is a TAP interface, not a TUN interface",
        ));
    }
    Ok(())
}

fn start_owned(
    env: &mut JNIEnv<'_>,
    tun_fd: OwnedFd,
    config_json: JString<'_>,
    network_handle: jlong,
    host: JObject<'_>,
    rule_sets: Vec<RuleSetBundle>,
    trusted_rule_sets: Vec<TrustedRuleSetBundle>,
) -> Result<u64, String> {
    // Every start path funnels through here, and this is idempotent, so the
    // core's own diagnostics are readable from the first generation onwards
    // rather than from whenever someone remembered to call it.
    #[cfg(target_os = "android")]
    logcat::install();
    let json: String = env
        .get_string(&config_json)
        .map_err(|error| format!("read engine config: {error}"))?
        .into();
    let config = EngineConfig::parse(&json).map_err(|error| error.to_string())?;
    let network_handle = u64::try_from(network_handle)
        .map_err(|_| "Android Network handle must not be negative".to_string())?;
    let requires_attribution = config
        .routes
        .iter()
        .any(|rule| rule.uid.is_some() || rule.package.is_some())
        || config.traffic.requires_identity();
    let (callbacks, attributor) = java_callbacks(env, host, requires_attribution)?;
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    let runtime = Arc::new(
        CoreRuntime::start_on_network_with_attributor_and_trusted_rule_sets(
            generation,
            config,
            tun_fd,
            callbacks,
            network_handle,
            attributor,
            rule_sets,
            trusted_rule_sets,
        )
        .map_err(|error| render_error(&error))?,
    );
    let handle = next_handle();
    lock(registry()).insert(handle, runtime);
    Ok(handle)
}

fn read_rule_set_bundle(
    env: &mut JNIEnv<'_>,
    name: JString<'_>,
    manifest: &JByteArray<'_>,
    signature: &JByteArray<'_>,
    artifact: &JByteArray<'_>,
) -> Result<RuleSetBundle, String> {
    let name = read_rule_set_name(env, name)?;
    Ok(RuleSetBundle {
        name,
        manifest: read_bounded_array(env, manifest, MAX_DNS_RULE_SET_MANIFEST_BYTES, "manifest")?,
        signature: read_bounded_array(
            env,
            signature,
            MAX_DNS_RULE_SET_SIGNATURE_BYTES,
            "signature",
        )?,
        artifact: read_bounded_array(env, artifact, MAX_DNS_RULE_SET_ARTIFACT_BYTES, "artifact")?,
    })
}

fn read_rule_set_name(env: &mut JNIEnv<'_>, name: JString<'_>) -> Result<String, String> {
    let name: String = env
        .get_string(&name)
        .map_err(|_| "DNS rule-set name could not be read".to_string())?
        .into();
    if name.is_empty()
        || name.len() > 128
        || !name.is_ascii()
        || name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("DNS rule-set name is invalid".into());
    }
    Ok(name)
}

fn read_bounded_array(
    env: &JNIEnv<'_>,
    array: &JByteArray<'_>,
    max: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    if array.is_null() {
        return Err(format!("DNS rule-set {label} is missing"));
    }
    let length = env
        .get_array_length(array)
        .map_err(|_| format!("DNS rule-set {label} length could not be read"))?;
    let length =
        usize::try_from(length).map_err(|_| format!("DNS rule-set {label} length is invalid"))?;
    if length == 0 || length > max {
        return Err(format!("DNS rule-set {label} length must be in 1..={max}"));
    }
    env.convert_byte_array(array)
        .map_err(|_| format!("DNS rule-set {label} could not be read"))
}

fn java_callbacks(
    env: &mut JNIEnv<'_>,
    host: JObject<'_>,
    requires_attribution: bool,
) -> Result<(SocketCallbacks, FlowAttributor), String> {
    let attributor = match java_flow_attributor(env, &host) {
        Ok(attributor) => attributor,
        Err(error) if requires_attribution => return Err(error),
        Err(_) => FlowAttributor::none(),
    };
    if requires_attribution && !attributor.is_available() {
        return Err("UID/package routing requires Android API level 29 or newer".into());
    }
    let callbacks = Arc::new(JavaCallbacks {
        vm: env
            .get_java_vm()
            .map_err(|error| format!("get Java VM: {error}"))?,
        host: env
            .new_global_ref(host)
            .map_err(|error| format!("retain VPN service host: {error}"))?,
    });
    let callbacks = SocketCallbacks::new(
        {
            let callbacks = callbacks.clone();
            move |fd| callbacks.protect(fd)
        },
        bind_socket_to_network,
    );
    Ok((with_network_resolver(callbacks), attributor))
}

#[cfg(target_os = "android")]
fn with_network_resolver(callbacks: SocketCallbacks) -> SocketCallbacks {
    callbacks.with_resolver(resolve_host_on_network)
}

#[cfg(not(target_os = "android"))]
fn with_network_resolver(callbacks: SocketCallbacks) -> SocketCallbacks {
    callbacks
}

#[cfg(target_os = "android")]
fn java_flow_attributor(
    env: &mut JNIEnv<'_>,
    host: &JObject<'_>,
) -> Result<FlowAttributor, String> {
    let sdk = env
        .get_static_field("android/os/Build$VERSION", "SDK_INT", "I")
        .and_then(|value| value.i())
        .map_err(|error| clear_jni_error(env, "read Android API level", error))?;
    if sdk < 29 {
        return Ok(FlowAttributor::none());
    }

    let service_name = env
        .new_string("connectivity")
        .map_err(|error| clear_jni_error(env, "create connectivity service name", error))?;
    let service_name = JObject::from(service_name);
    let connectivity_manager = env
        .call_method(
            host,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[JValue::Object(&service_name)],
        )
        .and_then(|value| value.l())
        .map_err(|error| clear_jni_error(env, "get ConnectivityManager", error))?;
    if connectivity_manager.is_null() {
        return Err("Android ConnectivityManager is unavailable".into());
    }
    let package_manager = env
        .call_method(
            host,
            "getPackageManager",
            "()Landroid/content/pm/PackageManager;",
            &[],
        )
        .and_then(|value| value.l())
        .map_err(|error| clear_jni_error(env, "get PackageManager", error))?;
    if package_manager.is_null() {
        return Err("Android PackageManager is unavailable".into());
    }

    let resolver = Arc::new(JavaFlowAttributor {
        vm: env
            .get_java_vm()
            .map_err(|error| format!("get Java VM for flow attribution: {error}"))?,
        host: env
            .new_global_ref(host)
            .map_err(|error| format!("retain VPN service host for flow attribution: {error}"))?,
        connectivity_manager: env
            .new_global_ref(connectivity_manager)
            .map_err(|error| format!("retain ConnectivityManager: {error}"))?,
        package_manager: env
            .new_global_ref(package_manager)
            .map_err(|error| format!("retain PackageManager: {error}"))?,
        package_cache: Mutex::new(HashMap::new()),
    });
    let invalidator = resolver.clone();
    Ok(FlowAttributor::new_with_invalidator(
        move |transport, source, destination| resolver.resolve(transport, source, destination),
        move || lock(&invalidator.package_cache).clear(),
    ))
}

#[cfg(not(target_os = "android"))]
fn java_flow_attributor(
    _env: &mut JNIEnv<'_>,
    _host: &JObject<'_>,
) -> Result<FlowAttributor, String> {
    Ok(FlowAttributor::none())
}

#[cfg(target_os = "android")]
impl JavaFlowAttributor {
    fn resolve(
        &self,
        transport: IpTransport,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<FlowIdentity>> {
        let mut env = self.vm.attach_current_thread().map_err(|error| {
            io::Error::other(format!("attach flow-attribution thread: {error}"))
        })?;
        let local = inet_socket_address(&mut env, source)?;
        let remote = inet_socket_address(&mut env, destination)?;
        let protocol = match transport {
            IpTransport::Tcp => libc::IPPROTO_TCP,
            IpTransport::Udp => libc::IPPROTO_UDP,
        };
        let uid = env
            .call_method(
                &self.connectivity_manager,
                "getConnectionOwnerUid",
                "(ILjava/net/InetSocketAddress;Ljava/net/InetSocketAddress;)I",
                &[
                    JValue::Int(protocol),
                    JValue::Object(&local),
                    JValue::Object(&remote),
                ],
            )
            .and_then(|value| value.i())
            .map_err(|error| {
                io::Error::other(clear_jni_error(
                    &mut env,
                    "resolve Android connection owner",
                    error,
                ))
            })?;
        let Ok(uid) = u32::try_from(uid) else {
            return Ok(None);
        };
        let identity = self.identity_for_uid(&mut env, uid)?;
        Ok(Some(FlowIdentity {
            uid,
            packages: identity.packages,
            signing_digest: identity.signing_digest,
        }))
    }

    fn identity_for_uid(
        &self,
        env: &mut JNIEnv<'_>,
        uid: u32,
    ) -> io::Result<CachedJavaFlowIdentity> {
        const PACKAGE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
        const MAX_PACKAGE_CACHE: usize = 1024;

        if let Some(identity) = lock(&self.package_cache).get(&uid)
            && identity.inserted.elapsed() < PACKAGE_CACHE_TTL
        {
            return Ok(identity.clone());
        }
        let java_uid = jint::try_from(uid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UID exceeds Java int"))?;
        let packages = env
            .call_method(
                &self.package_manager,
                "getPackagesForUid",
                "(I)[Ljava/lang/String;",
                &[JValue::Int(java_uid)],
            )
            .and_then(|value| value.l())
            .map_err(|error| {
                io::Error::other(clear_jni_error(
                    env,
                    "resolve packages for Android UID",
                    error,
                ))
            })?;
        let mut output = Vec::new();
        if !packages.is_null() {
            let packages = JObjectArray::from(packages);
            let length = env.get_array_length(&packages).map_err(|error| {
                io::Error::other(clear_jni_error(env, "read Android package array", error))
            })?;
            for index in 0..length.min(32) {
                let package = env
                    .get_object_array_element(&packages, index)
                    .map_err(|error| {
                        io::Error::other(clear_jni_error(env, "read Android package name", error))
                    })?;
                let package = JString::from(package);
                let package: String = env
                    .get_string(&package)
                    .map_err(|error| {
                        io::Error::other(clear_jni_error(env, "decode Android package name", error))
                    })?
                    .into();
                output.push(package);
            }
        }
        let signing_digest = match unique_package_for_signing_digest(&output) {
            Some(package) => self.signing_digest_for_package(env, package)?,
            // A shared UID is accepted only when every package in it is present in the frozen
            // baseline. The baseline intentionally carries no per-package digest for that case,
            // because Android cannot identify which package in the UID opened this flow.
            None => None,
        };
        let identity = CachedJavaFlowIdentity {
            inserted: Instant::now(),
            packages: output,
            signing_digest,
        };
        let mut cache = lock(&self.package_cache);
        if cache.len() >= MAX_PACKAGE_CACHE {
            cache.clear();
        }
        cache.insert(uid, identity.clone());
        Ok(identity)
    }

    fn signing_digest_for_package(
        &self,
        env: &mut JNIEnv<'_>,
        package: &str,
    ) -> io::Result<Option<[u8; 32]>> {
        let package = env
            .new_string(package)
            .map_err(|error| io::Error::other(format!("encode Android package name: {error}")))?;
        let package = JObject::from(package);
        let digest = env
            .call_method(
                &self.host,
                "signingDigestForPackage",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&package)],
            )
            .and_then(|value| value.l())
            .map_err(|error| {
                io::Error::other(clear_jni_error(
                    env,
                    "resolve Android package signing digest",
                    error,
                ))
            })?;
        if digest.is_null() {
            return Ok(None);
        }
        let digest = JString::from(digest);
        let digest: String = env
            .get_string(&digest)
            .map_err(|error| {
                io::Error::other(clear_jni_error(
                    env,
                    "decode Android package signing digest",
                    error,
                ))
            })?
            .into();
        decode_signing_digest(&digest).map(Some).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid package signing digest")
        })
    }
}

#[cfg(any(target_os = "android", test))]
fn unique_package_for_signing_digest(packages: &[String]) -> Option<&str> {
    let [package] = packages else {
        return None;
    };
    Some(package)
}

#[cfg(target_os = "android")]
fn inet_socket_address<'local>(
    env: &mut JNIEnv<'local>,
    address: SocketAddr,
) -> io::Result<JObject<'local>> {
    let host = env
        .new_string(address.ip().to_string())
        .map_err(|error| io::Error::other(format!("encode flow address: {error}")))?;
    let host = JObject::from(host);
    env.new_object(
        "java/net/InetSocketAddress",
        "(Ljava/lang/String;I)V",
        &[
            JValue::Object(&host),
            JValue::Int(jint::from(address.port())),
        ],
    )
    .map_err(|error| {
        io::Error::other(clear_jni_error(
            env,
            "create Java flow socket address",
            error,
        ))
    })
}

/// Take the pending Java exception off the thread and describe what raised it.
///
/// Not gated on Android any more: `protect` runs in the host test build too, and
/// leaving an exception pending is undefined behaviour on any JVM, not just
/// ART's.
fn clear_jni_error(env: &mut JNIEnv<'_>, operation: &str, error: jni::errors::Error) -> String {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    format!("{operation}: {error}")
}

impl JavaCallbacks {
    fn protect(&self, fd: RawFd) -> bool {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return false;
        };
        env.call_method(
            &self.host,
            "protectSocket",
            "(I)Z",
            &[JValue::Int(fd as jint)],
        )
        .and_then(|value| value.z())
        // The clear is not tidiness. `call_method` reports a Java exception as
        // `Err` and leaves it pending; the `jni` crate checks for it and does
        // not clear it. Returning `false` from here is correct — the dialer
        // refuses the socket rather than putting the user's packets on the wire
        // outside the tunnel — but the attach guard then detaches a thread with
        // an exception still raised, and ART routes that to the uncaught
        // handler, which kills the process with a stack that names nothing in
        // this crate. On a nested attach it is worse: the exception simply
        // stays pending and the next JNI call from this thread is undefined.
        // This was the only JNI call site in the crate not going through
        // `clear_jni_error`, while §2.2 of the docs claimed all of them did.
        .map_err(|error| clear_jni_error(&mut env, "protect outbound socket", error))
        .unwrap_or(false)
    }
}

pub(crate) fn runtime(handle: jlong) -> Option<Arc<CoreRuntime>> {
    if handle <= 0 {
        return None;
    }
    lock(registry()).get(&(handle as u64)).cloned()
}

fn registry() -> &'static Mutex<HashMap<u64, Arc<CoreRuntime>>> {
    RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How many times the reaper retries a stop that keeps timing out.
///
/// Each attempt costs `STOP_TIMEOUT`, so this is a couple of minutes of patience
/// and then the worker is the quarantine list's problem rather than a thread
/// that never exits.
const STOP_REAP_ATTEMPTS: usize = 40;

fn stop_reapers() -> &'static Mutex<HashMap<u64, std::thread::JoinHandle<()>>> {
    STOP_REAPERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn schedule_stop_reaper(handle: u64, runtime: Arc<CoreRuntime>) {
    reap_stop_reapers();
    let mut reapers = lock(stop_reapers());
    if reapers.contains_key(&handle) {
        return;
    }
    let Ok(reaper) = std::thread::Builder::new()
        .name(format!("foxcore-stop-{handle}"))
        .spawn(move || {
            // Bounded, and quiet. Unbounded, this thread outlived a
            // genuinely wedged worker forever while holding an `Arc` to the
            // whole generation — the outbound registry, and with Tor in the
            // default build an `Arc<TorClient>` keeping Arti's state directory
            // locked. `stop_quiet` because `stop` republishes the process-wide
            // stop diagnostics: the reaper's next lap used to erase the
            // `force_killed` record the app had just been told to go read.
            for _ in 0..STOP_REAP_ATTEMPTS {
                if runtime.stop_quiet() != StopResult::TimedOut {
                    break;
                }
            }
            lock(registry()).remove(&handle);
        })
    else {
        return;
    };
    reapers.insert(handle, reaper);
}

fn reap_stop_reapers() {
    let finished = {
        let mut reapers = lock(stop_reapers());
        let handles = reapers
            .iter()
            .filter_map(|(handle, reaper)| reaper.is_finished().then_some(*handle))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| reapers.remove(&handle))
            .collect::<Vec<_>>()
    };
    for reaper in finished {
        let _ = reaper.join();
    }
}

fn next_handle() -> u64 {
    loop {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle != 0 && handle <= jlong::MAX as u64 {
            return handle;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(target_os = "android")]
fn resolve_host_on_network(
    host: &str,
    port: u16,
    network_handle: u64,
) -> io::Result<Vec<SocketAddr>> {
    if network_handle == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Android Network handle is required for DNS bootstrap",
        ));
    }
    let host = CString::new(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "host contains NUL"))?;
    let service = CString::new(port.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server port"))?;

    // SAFETY: `addrinfo` is a C plain-data hints structure and zero is its
    // documented initialization state before selected fields are assigned.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_flags = libc::AI_ADDRCONFIG;
    let mut result = ptr::null_mut();
    // SAFETY: both C strings and `hints` live through the call, and `result`
    // points to writable storage freed by `AddrInfoList`.
    let status = unsafe {
        android_getaddrinfofornetwork(
            network_handle,
            host.as_ptr(),
            service.as_ptr(),
            &hints,
            &mut result,
        )
    };
    let result = AddrInfoList(result);
    if status != 0 {
        return Err(io::Error::other(format!(
            "Android Network DNS failed with getaddrinfo status {status}"
        )));
    }
    let mut addresses = Vec::new();
    let mut current = result.0;
    while !current.is_null() {
        // SAFETY: `current` belongs to the live `AddrInfoList`; the C linked
        // list remains immutable until it is freed after this loop.
        let info = unsafe { &*current };
        if let Some(address) = socket_address(info)
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
        current = info.ai_next;
    }
    if addresses.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Android Network DNS returned no usable addresses",
        ))
    } else {
        Ok(addresses)
    }
}

#[cfg(target_os = "android")]
fn socket_address(info: &libc::addrinfo) -> Option<SocketAddr> {
    if info.ai_addr.is_null() {
        return None;
    }
    match info.ai_family {
        libc::AF_INET if info.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: family and length were checked and `ai_addr` is non-null. Android's
            // resolver API does not promise Rust alignment for this foreign pointer, so copy
            // the POD socket address with an unaligned read instead of creating a reference.
            let address =
                unsafe { std::ptr::read_unaligned(info.ai_addr.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 if info.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: see the IPv4 branch above. Copying also prevents a foreign allocation
            // from being observed through a Rust reference after the resolver frees it.
            let address =
                unsafe { std::ptr::read_unaligned(info.ai_addr.cast::<libc::sockaddr_in6>()) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(target_os = "android")]
struct AddrInfoList(*mut libc::addrinfo);

#[cfg(target_os = "android")]
impl Drop for AddrInfoList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from `android_getaddrinfofornetwork`,
            // has not been freed, and ownership is unique to this guard.
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
}

#[cfg(target_os = "android")]
fn bind_socket_to_network(fd: RawFd, network_handle: u64) -> bool {
    // SAFETY: Android's libc owns neither argument; the descriptor remains owned
    // by the dialer and `network_handle` came from Network.getNetworkHandle().
    unsafe { android_setsocknetwork(network_handle, fd) == 0 }
}

#[cfg(not(target_os = "android"))]
fn bind_socket_to_network(_fd: RawFd, _network_handle: u64) -> bool {
    true
}

#[cfg(target_os = "android")]
#[link(name = "android")]
unsafe extern "C" {
    fn android_setsocknetwork(network_handle: u64, fd: RawFd) -> std::os::raw::c_int;
    fn android_getaddrinfofornetwork(
        network_handle: u64,
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        result: *mut *mut libc::addrinfo,
    ) -> libc::c_int;
}

#[cfg(test)]
mod abi_tests {
    use std::os::fd::{AsRawFd, IntoRawFd};

    use super::*;

    #[test]
    fn signing_identity_is_pinned_only_for_an_exact_unique_package() {
        let unique = vec!["com.example.unique".to_owned()];
        let shared = vec!["com.example.one".to_owned(), "com.example.two".to_owned()];

        assert_eq!(
            unique_package_for_signing_digest(&unique),
            Some("com.example.unique"),
        );
        assert_eq!(unique_package_for_signing_digest(&shared), None);
        assert_eq!(unique_package_for_signing_digest(&[]), None);
    }

    /// A descriptor number this process does not hold open must be refused,
    /// not adopted.
    ///
    /// Before the check this test aborted the whole binary rather than
    /// failing:
    ///
    /// ```text
    /// running 19 tests
    /// fatal runtime error: IO Safety violation: owned file descriptor
    ///                     already closed, aborting
    /// (signal: 6, SIGABRT)
    /// ```
    ///
    /// which is exactly what `nativeStart` did on a device: `OwnedFd::drop`
    /// closes, `close` answers EBADF, and the standard library takes the
    /// process down. No Java exception, no FoxCore error, a native crash of
    /// the VPN service. The other end of the same defect is quieter and worse
    /// — the kernel hands the number to a socket `start` opens, and the data
    /// plane writes IP packets into the proxy connection.
    #[test]
    fn a_descriptor_this_process_does_not_hold_is_refused_rather_than_adopted() {
        let error = take_tun_fd(jint::MAX)
            .expect_err("a number that cannot be an open descriptor must not become the TUN");
        assert!(
            error.contains(&jint::MAX.to_string()),
            "the refusal must name the descriptor the app passed: {error}"
        );

        let negative =
            take_tun_fd(-1).expect_err("a negative descriptor was already refused, and stays so");
        assert!(negative.contains("non-negative"), "{negative}");
    }

    /// The ownership contract still works after validation. `/dev/null` is only
    /// the host-test stand-in for a read/write character device; Android adds
    /// the TUNGETIFF check and would correctly refuse it.
    #[cfg(not(target_os = "android"))]
    #[test]
    fn a_validated_character_descriptor_is_taken_whole() {
        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("read/write character device");
        let raw = device.into_raw_fd();
        let owned = take_tun_fd(raw).expect("validated descriptor");
        assert_eq!(
            owned.as_raw_fd(),
            raw,
            "the guard must own the descriptor it was handed, not a copy"
        );
        drop(owned);
    }

    /// An arbitrary open FD must not become the packet interface. Both examples
    /// are readable and writable and therefore made it all the way into the
    /// runtime before this guard; the data plane then wrote IP packets into a
    /// socket or pipe and failed far away from the JNI mistake.
    #[test]
    fn sockets_and_pipes_are_refused_before_runtime_start() {
        let (near, far) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        let raw = near.into_raw_fd();
        assert_eq!(
            tun_fd_kind(raw).expect("fstat on an open descriptor"),
            u64::from(libc::S_IFSOCK),
            "negative control must really be a socket"
        );
        let socket_error = take_tun_fd(raw).expect_err("a socket must never become the TUN");
        assert!(
            socket_error.contains("not a character device"),
            "{socket_error}"
        );
        drop(far);

        let mut pipe = [-1; 2];
        // SAFETY: `pipe` points to exactly two writable c_int slots; on success
        // the kernel initializes both with new descriptors owned by this test.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        // SAFETY: the successful `pipe` call transferred ownership of its write
        // descriptor to this guard. `take_tun_fd` takes and closes the read end.
        let write_end = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let pipe_error = take_tun_fd(pipe[0]).expect_err("a pipe must never become the TUN");
        assert!(
            pipe_error.contains("not a character device"),
            "{pipe_error}"
        );
        drop(write_end);
    }

    #[test]
    fn c_capabilities_buffer_contract_is_sized_and_nul_terminated() {
        let required = foxhole_core_capabilities_json_len();
        assert!(required > 1);

        let mut short = [0xaa_u8; 4];
        // SAFETY: short is writable for its reported capacity.
        let reported =
            unsafe { foxhole_core_capabilities_json_write(short.as_mut_ptr(), short.len()) };
        assert_eq!(reported, required);
        assert_eq!(short, [0xaa; 4]);

        let mut buffer = vec![0_u8; required];
        // SAFETY: buffer is writable for exactly required bytes.
        let written =
            unsafe { foxhole_core_capabilities_json_write(buffer.as_mut_ptr(), buffer.len()) };
        assert_eq!(written, required);
        assert_eq!(buffer.pop(), Some(0));
        let document: serde_json::Value = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(document["abi_version"], CORE_ABI_VERSION);
    }

    /// Three device runs were lost to a start failure whose message was
    /// "problem with filesystem permissions" and nothing else — the source
    /// underneath named the directory. `Display` on an error prints only the
    /// top of the chain, and the top is routinely the least useful part.
    #[test]
    fn a_start_failure_carries_everything_underneath_it() {
        #[derive(Debug)]
        struct Cause(&'static str, Option<Box<Cause>>);
        impl std::fmt::Display for Cause {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.0)
            }
        }
        impl std::error::Error for Cause {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1
                    .as_deref()
                    .map(|cause| cause as &dyn std::error::Error)
            }
        }

        let error = Cause(
            "Arti bootstrap failed",
            Some(Box::new(Cause(
                "problem with filesystem permissions",
                Some(Box::new(Cause(
                    "/data/user/0/com.example/files is mode 0777",
                    None,
                ))),
            ))),
        );

        let rendered = render_error(&error);
        assert!(
            rendered.contains("0777") && rendered.contains("/data/user/0"),
            "the actionable part is the deepest one: {rendered}"
        );
        assert!(rendered.starts_with("Arti bootstrap failed"));

        // A chain that repeats itself must not be rendered four times.
        let repeated = Cause("same thing", Some(Box::new(Cause("same thing", None))));
        assert_eq!(render_error(&repeated), "same thing");
    }
}

#[cfg(test)]
mod lan_abi_tests {
    use super::*;

    const GENERATION: u64 = 7;

    fn request(overrides: &[(&str, &str)]) -> String {
        let mut fields = vec![
            ("preset", "\"mixed\""),
            ("socks_port", "1080"),
            ("http_port", "8080"),
            ("username", "\"laptop\""),
            ("password", "\"correct horse\""),
            ("network_handle", "1234567890"),
            ("local_address", "\"192.168.1.20\""),
            ("interface_name", "\"wlan0\""),
            ("transport", "\"wifi\""),
        ];
        for (name, value) in overrides {
            match fields.iter_mut().find(|(field, _)| field == name) {
                Some(field) => field.1 = value,
                None => fields.push((name, value)),
            }
        }
        let body = fields
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{{body}}}")
    }

    /// `LanProxyConfig` holds credentials and is deliberately not `Debug`, so
    /// the usual `expect_err` is not available: this says the same thing without
    /// asking the type to render itself.
    fn refusal(document: &str) -> String {
        match lan_start_request(document, GENERATION) {
            Ok(_) => panic!("this must be refused rather than bound: {document}"),
            Err(reason) => reason,
        }
    }

    #[test]
    fn a_complete_request_becomes_the_binding_and_config_the_runtime_takes() {
        let (config, binding) = lan_start_request(&request(&[]), GENERATION)
            .expect("a well-formed request must be accepted");

        assert_eq!(config.id.as_str(), LAN_PROXY_COMPONENT_ID);
        assert_eq!(config.preset, LanProxyPreset::Mixed);
        assert_eq!(config.socks_port, 1080);
        assert_eq!(config.http_port, 8080);
        assert_eq!(binding.network_handle, 1234567890);
        assert_eq!(binding.interface_name, "wlan0");
        assert_eq!(
            binding.local_address,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))
        );
        assert_eq!(binding.transport, LanTransport::Wifi);
        // The generation the credentials are minted under: a handshake in flight
        // when it moves must not complete.
        assert_eq!(binding.generation, GENERATION);
        // Without a fingerprint no network can ever be confirmed, and the whole
        // feature would be unreachable from this ABI.
        assert!(binding.fingerprint().is_some());
        // The password must not survive into a rendering anyone can log.
        assert!(!format!("{:?}", config.credentials).contains("correct horse"));
    }

    /// One protocol is a configuration; neither is a component that takes
    /// runtime leases, holds an identity and serves nobody.
    #[test]
    fn a_request_with_neither_protocol_is_refused_and_one_protocol_is_not() {
        let reason = refusal(&request(&[("socks_port", "0"), ("http_port", "0")]));
        assert!(reason.contains("neither protocol"), "{reason}");

        for (offered, absent) in [("socks_port", "http_port"), ("http_port", "socks_port")] {
            let (config, _) = lan_start_request(&request(&[(absent, "0")]), GENERATION)
                .unwrap_or_else(|error| panic!("{offered} alone must be startable: {error}"));
            assert!(config.socks_port == 0 || config.http_port == 0);
            assert!(config.socks_port != 0 || config.http_port != 0);
        }
    }

    /// An open proxy with extra steps is still an open proxy.
    #[test]
    fn blank_credentials_are_refused_rather_than_compared() {
        for blank in [
            ("username", "\"\""),
            ("password", "\"\""),
            // Non-ASCII usernames are refused by the component, and a refusal
            // is what the app has to be told.
            ("username", "\"пароль\""),
        ] {
            let reason = refusal(&request(&[blank]));
            assert!(reason.contains("credentials"), "{blank:?}: {reason}");
        }
    }

    #[test]
    fn an_address_this_boundary_cannot_bind_is_refused_in_words() {
        for address in ["\"\"", "\"not-an-address\"", "\"fe80::1\"", "\"192.168.1\""] {
            let reason = refusal(&request(&[("local_address", address)]));
            assert!(reason.contains("IPv4"), "{address}: {reason}");
        }
        // A wildcard parses; refusing it is the component's rule, and the parse
        // must reach it rather than pre-empt it with a different message.
        let (_, binding) =
            lan_start_request(&request(&[("local_address", "\"0.0.0.0\"")]), GENERATION)
                .expect("a wildcard is well-formed and is refused where the rule lives");
        assert!(binding.local_address.is_unspecified());
    }

    #[test]
    fn unknown_presets_and_transports_are_named_rather_than_guessed() {
        // There is no direct preset and there must not be one.
        let reason = refusal(&request(&[("preset", "\"direct\"")]));
        assert!(reason.contains("vpn, tor, mixed"), "{reason}");

        let reason = refusal(&request(&[("transport", "\"wi-fi\"")]));
        assert!(reason.contains("wifi, ethernet"), "{reason}");

        // Cellular and unknown parse and are refused by the binding rules, so
        // the app is told which rule it hit rather than that its JSON is bad.
        for transport in ["\"cellular\"", "\"unknown\""] {
            let (_, binding) = lan_start_request(&request(&[("transport", transport)]), GENERATION)
                .expect("a real transport parses; the binding is what refuses it");
            assert!(matches!(
                binding.transport,
                LanTransport::Cellular | LanTransport::Unknown
            ));
        }
    }

    /// A field this core does not know is an error, not something dropped. A
    /// request that half-arrived must not half-bind.
    #[test]
    fn a_malformed_or_unexpected_document_is_refused_without_panicking() {
        for document in [
            String::from(""),
            String::from("null"),
            String::from("[]"),
            String::from("{"),
            request(&[("socks_port", "70000")]),
            request(&[("socks_port", "-1")]),
            request(&[("network_handle", "-1")]),
            request(&[("allow_anonymous", "true")]),
            // Every field is required: none of them has a default that could
            // silently mean something safer than what the app meant.
            String::from(r#"{"preset":"vpn"}"#),
        ] {
            assert!(
                lan_start_request(&document, GENERATION).is_err(),
                "must be refused: {document}"
            );
        }
    }

    /// The confirmation is keyed on the network handle, the interface and the
    /// transport — and on nothing else, so a DHCP renewal does not ask again.
    #[test]
    fn the_session_identity_survives_a_new_address_but_not_a_new_network() {
        let binding = |handle: u64, address: &str, interface: &str| {
            lan_binding(handle, address, interface, "wifi", GENERATION).unwrap()
        };
        let base = binding(42, "192.168.1.20", "wlan0");

        assert_eq!(
            base.fingerprint(),
            binding(42, "192.168.1.57", "wlan0").fingerprint(),
            "a DHCP renewal is the same network and must not re-ask"
        );
        assert_ne!(
            base.fingerprint(),
            binding(43, "192.168.1.20", "wlan0").fingerprint(),
            "a new Android Network is a new session and must be confirmed again"
        );
        assert_ne!(
            base.fingerprint(),
            binding(42, "192.168.1.20", "wlan1").fingerprint()
        );

        // Domain-separated, so this can never collide with a real SSID hash
        // taken from a build that does hold the location permission.
        let mut plain = Sha256::new();
        plain.update(42_u64.to_be_bytes());
        let plain: [u8; 32] = plain.finalize().into();
        assert_ne!(lan_session_identity(42), plain);
    }

    /// The document the LAN screen is drawn from. It is the answer for a handle
    /// that is not running as well, because that is the case the app hits first
    /// — the screen opening before the tunnel is up — and a second shape there
    /// is a second parser.
    #[test]
    fn the_status_document_is_well_formed_before_anything_has_ever_started() {
        let document: serde_json::Value =
            serde_json::from_str(lan_proxy_stopped_status_json()).expect("valid JSON");

        assert_eq!(document["state"], "stopped");
        for field in [
            "socks_address",
            "http_address",
            "preset",
            "network_handle",
            "local_address",
            "last_error",
        ] {
            assert!(
                document.get(field).is_some(),
                "{field} must be present in every answer"
            );
            assert!(
                document[field].is_null(),
                "{field} must be null when nothing is running, not absent"
            );
        }
    }

    /// `nativeLanProxyStatus` on a handle nobody started must not be `null` or
    /// `{}`: the app parses one shape, always.
    #[test]
    fn a_handle_that_is_not_running_answers_the_stopped_document() {
        let json = runtime(0)
            .map(|runtime| runtime.lan_proxy_status_json())
            .unwrap_or_else(|| lan_proxy_stopped_status_json().to_owned());
        assert_eq!(json, lan_proxy_stopped_status_json());
    }
}
