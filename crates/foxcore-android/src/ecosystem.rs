//! Source-only JNI for isolated web apps and the share vault.
//! Release builds exclude these symbols; handles are generation-scoped and
//! never expose lease or share capabilities to Java.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use foxcore_runtime::{
    ComponentError, ComponentEventKind, ComponentId, ComponentLease, ComponentOperation,
    ComponentRoute, CoreRuntime, CreatedShare, FileId, FileShareConfig, LeasePurpose,
    PublishedShare, ShareConfig, ShareEventKind, ShareId, ShareManager, WebAppConfig,
};
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::boundary::{
    RESULT_DENIED, RESULT_INVALID_ARGUMENT, RESULT_NO_ENGINE, RESULT_NOT_FOUND, RESULT_OK,
    RESULT_PANICKED, RESULT_RUNTIME_UNAVAILABLE, RESULT_VAULT_ERROR, component_result, guarded,
    lock, read_string, share_result,
};
use crate::runtime;

/// Route codes. Numeric because they cross the ABI, and a mistyped string would
/// have to fail as "unknown route" — which the caller could then read as
/// "blocked", the one answer that must never be reached by accident.
const ROUTE_VPN: jint = 1;
const ROUTE_TOR: jint = 2;
const ROUTE_DIRECT: jint = 3;
const ROUTE_BLOCK: jint = 4;

const PURPOSE_WEB_NAVIGATION: jint = 1;
const PURPOSE_WEB_NOTIFICATION: jint = 2;
const PURPOSE_FILE_SHARING: jint = 3;

const OPERATION_NAVIGATION: jint = 1;
const OPERATION_SUBRESOURCE: jint = 2;
const OPERATION_NOTIFICATION_DELIVERY: jint = 3;
const OPERATION_NOTIFICATION_ACTION: jint = 4;
const OPERATION_FILE_SHARE_PUBLISH: jint = 5;
const OPERATION_FILE_SHARE_DOWNLOAD: jint = 6;

/// The largest event batch one call will assemble.
const MAX_EVENT_BATCH: usize = 512;
const SHARE_KEY_BYTES: usize = 32;
const SHARE_INVITATION_VERSION: u8 = 1;

static LEASES: OnceLock<Mutex<HashMap<u64, OwnedLease>>> = OnceLock::new();
static SHARES: OnceLock<Mutex<HashMap<u64, OwnedShare>>> = OnceLock::new();
static NEXT_LEASE_HANDLE: AtomicU64 = AtomicU64::new(1);
static NEXT_SHARE_HANDLE: AtomicU64 = AtomicU64::new(1);

struct OwnedLease {
    engine: u64,
    lease: ComponentLease,
}

/// A share the app created, with the capabilities that prove ownership.
///
/// The tokens live here and only here. Java is given the handle; the vault is
/// given the tokens. Nothing in between ever sees them.
struct OwnedShare {
    engine: u64,
    id: ShareId,
    owner: Zeroizing<[u8; 32]>,
    download: Zeroizing<[u8; 32]>,
    files: Vec<FileId>,
    password_required: bool,
}

fn leases() -> &'static Mutex<HashMap<u64, OwnedLease>> {
    LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn shares() -> &'static Mutex<HashMap<u64, OwnedShare>> {
    SHARES.get_or_init(|| Mutex::new(HashMap::new()))
}

struct OwnedPublication {
    engine: u64,
    published: PublishedShare,
    virtual_port: u16,
}

static PUBLICATIONS: OnceLock<Mutex<HashMap<u64, OwnedPublication>>> = OnceLock::new();
static NEXT_PUBLICATION_HANDLE: AtomicU64 = AtomicU64::new(1);

fn publications() -> &'static Mutex<HashMap<u64, OwnedPublication>> {
    PUBLICATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Publish the attached vault as an onion service.
///
/// Returns an opaque publication handle, or zero. Zero covers every refusal on
/// purpose: no vault, no Tor outbound in the profile, a build without the
/// `onion-service` feature, or Tor declining to publish. None of them has a
/// fallback, so none of them needs to be told apart here — the audit stream
/// carries the detail.
///
/// `nickname` scopes this publication inside Arti's ephemeral primary keystore.
/// Android supplies a fresh random nickname for every runtime session, so the
/// onion identity neither survives restart nor links two sharing sessions.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativePublishShare(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    nickname: JString<'_>,
    virtual_port: jint,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime(handle) else {
            return 0;
        };
        let Some(nickname) = read_string(&mut env, &nickname) else {
            return 0;
        };
        let Ok(virtual_port) = u16::try_from(virtual_port) else {
            return 0;
        };
        if virtual_port == 0 {
            return 0;
        }
        let _ = &runtime;
        let published = publish_over_tor(&runtime, &nickname, virtual_port);
        let Some(published) = published else {
            return 0;
        };
        let publication = NEXT_PUBLICATION_HANDLE.fetch_add(1, Ordering::Relaxed);
        lock(publications()).insert(
            publication,
            OwnedPublication {
                engine: handle as u64,
                published,
                virtual_port,
            },
        );
        publication as jlong
    }))
    .unwrap_or(0)
}

#[cfg(feature = "onion-service")]
fn publish_over_tor(
    runtime: &Arc<CoreRuntime>,
    nickname: &str,
    virtual_port: u16,
) -> Option<PublishedShare> {
    runtime.publish_share_over_tor(nickname, virtual_port).ok()
}

/// Without the feature there is no onion service, and therefore no publication.
/// Deliberately not a loopback listener "for now": a share that is served
/// anywhere Tor is not is the fallback this whole component refuses.
#[cfg(not(feature = "onion-service"))]
fn publish_over_tor(
    _runtime: &Arc<CoreRuntime>,
    _nickname: &str,
    _virtual_port: u16,
) -> Option<PublishedShare> {
    None
}

/// The `.onion` address a publication is reachable at.
///
/// Every caller of this is handing the address to someone: it is the locator
/// for the user's private files, and it is redacted everywhere else in the core.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativePublicationAddress(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    publication: jlong,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let address = lock(publications())
            .get(&(publication.max(0) as u64))
            .filter(|publication| publication.published.is_live())
            .map(|publication| publication.published.address().as_str().to_owned());
        match address {
            Some(address) => env
                .new_string(address)
                .map(|value| value.into_raw())
                .unwrap_or(std::ptr::null_mut()),
            None => std::ptr::null_mut(),
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Withdraw a publication: the onion service is unpublished first, then the
/// loopback server behind it stops. In-flight transfers are cut with it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeWithdrawShare(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    publication: jlong,
) -> jint {
    guarded(
        || match lock(publications()).remove(&(publication.max(0) as u64)) {
            // Dropping it is the withdrawal, in that order.
            Some(_) => RESULT_OK,
            None => RESULT_NOT_FOUND,
        },
    )
}

/// Write a transferable invitation without returning the download capability
/// to Java. The destination must be a fresh app-private cache file which the
/// Android side exposes through a one-shot FileProvider grant.
///
/// The password is deliberately absent: when configured it is sent through a
/// second channel. The URL contains only locator ids; the capability remains a
/// Basic-auth username and never appears in URL, Referer or browser history.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeWriteInvitation(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    publication_handle: jlong,
    share_handle: jlong,
    file_id_hex: JString<'_>,
    destination_path: JString<'_>,
) -> jint {
    guarded(|| {
        let (Some(file_id_hex), Some(destination_path)) = (
            read_string(&mut env, &file_id_hex),
            read_string(&mut env, &destination_path),
        ) else {
            return RESULT_INVALID_ARGUMENT;
        };
        let Some(file_id) = FileId::from_hex(&file_id_hex) else {
            return RESULT_INVALID_ARGUMENT;
        };
        let publication = {
            let publications = lock(publications());
            let Some(publication) = publications.get(&(publication_handle.max(0) as u64)) else {
                return RESULT_NOT_FOUND;
            };
            if !publication.published.is_live() {
                return RESULT_RUNTIME_UNAVAILABLE;
            }
            (
                publication.engine,
                publication.published.address().as_str().to_owned(),
                publication.virtual_port,
            )
        };
        let invitation = {
            let shares = lock(shares());
            let Some(share) = shares.get(&(share_handle.max(0) as u64)) else {
                return RESULT_NOT_FOUND;
            };
            if share.engine != publication.0 || !share.files.contains(&file_id) {
                return RESULT_DENIED;
            }
            share_invitation_text(
                &publication.1,
                publication.2,
                share.id,
                file_id,
                &share.download,
                share.password_required,
            )
        };
        match write_new_private_file(&destination_path, invitation.as_bytes()) {
            Ok(()) => RESULT_OK,
            Err(_) => RESULT_VAULT_ERROR,
        }
    })
}

fn share_invitation_text(
    onion_address: &str,
    virtual_port: u16,
    share_id: ShareId,
    file_id: FileId,
    download_capability: &[u8; 32],
    password_required: bool,
) -> Zeroizing<String> {
    let port = if virtual_port == 80 {
        String::new()
    } else {
        format!(":{virtual_port}")
    };
    let capability = encode_secret_hex(download_capability);
    Zeroizing::new(format!(
        "FOXHOLE-SHARE/{SHARE_INVITATION_VERSION}\n\
url=http://{onion_address}{port}/{}/{}\n\
username={}\n\
password={}\n\
open-with=Tor Browser\n",
        share_id.to_hex(),
        file_id.to_hex(),
        capability.as_str(),
        if password_required {
            "required-separate-channel"
        } else {
            "leave-empty"
        },
    ))
}

fn encode_secret_hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut encoded = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn write_new_private_file(path: &str, contents: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn route(code: jint) -> Option<ComponentRoute> {
    match code {
        ROUTE_VPN => Some(ComponentRoute::Vpn),
        ROUTE_TOR => Some(ComponentRoute::Tor),
        ROUTE_DIRECT => Some(ComponentRoute::Direct),
        ROUTE_BLOCK => Some(ComponentRoute::Block),
        _ => None,
    }
}

fn route_code(route: ComponentRoute) -> jint {
    match route {
        ComponentRoute::Vpn => ROUTE_VPN,
        ComponentRoute::Tor => ROUTE_TOR,
        ComponentRoute::Direct => ROUTE_DIRECT,
        ComponentRoute::Block => ROUTE_BLOCK,
    }
}

fn purpose(code: jint) -> Option<LeasePurpose> {
    match code {
        PURPOSE_WEB_NAVIGATION => Some(LeasePurpose::WebNavigation),
        PURPOSE_WEB_NOTIFICATION => Some(LeasePurpose::WebNotification),
        PURPOSE_FILE_SHARING => Some(LeasePurpose::FileSharing),
        _ => None,
    }
}

fn operation(code: jint) -> Option<ComponentOperation> {
    match code {
        OPERATION_NAVIGATION => Some(ComponentOperation::Navigation),
        OPERATION_SUBRESOURCE => Some(ComponentOperation::Subresource),
        OPERATION_NOTIFICATION_DELIVERY => Some(ComponentOperation::NotificationDelivery),
        OPERATION_NOTIFICATION_ACTION => Some(ComponentOperation::NotificationAction),
        OPERATION_FILE_SHARE_PUBLISH => Some(ComponentOperation::FileSharePublish),
        OPERATION_FILE_SHARE_DOWNLOAD => Some(ComponentOperation::FileShareDownload),
        _ => None,
    }
}

fn component_id(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Option<ComponentId> {
    ComponentId::new(read_string(env, value)?).ok()
}

/// Register an isolated web application under its own route and identity.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeRegisterWebApp(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    id: JString<'_>,
    origin: JString<'_>,
    route_code: jint,
    notifications_enabled: jboolean,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let (Some(id), Some(origin), Some(route)) = (
            component_id(&mut env, &id),
            read_string(&mut env, &origin),
            route(route_code),
        ) else {
            return RESULT_INVALID_ARGUMENT;
        };
        match runtime.component_manager().register_web_app(WebAppConfig {
            id,
            origin,
            route,
            notifications_enabled: notifications_enabled != 0,
        }) {
            Ok(()) => RESULT_OK,
            Err(error) => component_result(error),
        }
    })
}

/// Register a file share. It never gains an origin or a notification channel,
/// and its publication route is fixed by the core rather than chosen here.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeRegisterFileShare(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    id: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let Some(id) = component_id(&mut env, &id) else {
            return RESULT_INVALID_ARGUMENT;
        };
        match runtime
            .component_manager()
            .register_file_share(FileShareConfig { id })
        {
            Ok(()) => RESULT_OK,
            Err(error) => component_result(error),
        }
    })
}

/// Remove a component. Its leases are revoked immediately, so anything holding
/// one starts failing closed rather than running on a component that is gone.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeRemoveComponent(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    id: JString<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let Some(id) = component_id(&mut env, &id) else {
            return RESULT_INVALID_ARGUMENT;
        };
        let components = runtime.component_manager();
        // A caller knows which kind it registered, but making it say so here
        // would let a typo silently remove nothing. Either removal succeeding
        // is the answer.
        match components.remove_web_app(&id) {
            Ok(()) => RESULT_OK,
            Err(ComponentError::NotFound) => match components.remove_file_share(&id) {
                Ok(()) => RESULT_OK,
                Err(error) => component_result(error),
            },
            Err(error) => component_result(error),
        }
    })
}

/// Move a web application to a different route.
///
/// The manager acquires every new lease before publishing the new policy, so a
/// failure leaves the old route active. `Vpn`/`Tor` never degrade to `Direct`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeSetWebAppRoute(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    id: JString<'_>,
    route_code: jint,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let (Some(id), Some(route)) = (component_id(&mut env, &id), route(route_code)) else {
            return RESULT_INVALID_ARGUMENT;
        };
        match runtime.component_manager().set_web_app_route(&id, route) {
            Ok(_) => RESULT_OK,
            Err(error) => component_result(error),
        }
    })
}

/// Take a lease for one purpose. Returns an opaque handle, or zero.
///
/// The lease's credential is not returned and never leaves this process: a
/// `byte[]` in the app is a `byte[]` in a log sooner or later, and this one
/// authorizes navigation on the user's behalf.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeAcquireLease(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    id: JString<'_>,
    purpose_code: jint,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime(handle) else {
            return 0;
        };
        let (Some(id), Some(purpose)) = (component_id(&mut env, &id), purpose(purpose_code)) else {
            return 0;
        };
        let Ok(lease) = runtime.component_manager().acquire(&id, purpose) else {
            return 0;
        };
        let lease_handle = NEXT_LEASE_HANDLE.fetch_add(1, Ordering::Relaxed);
        lock(leases()).insert(
            lease_handle,
            OwnedLease {
                engine: handle as u64,
                lease,
            },
        );
        lease_handle as jlong
    }))
    .unwrap_or(0)
}

/// Release a lease. Dropping it is what revokes the credential, so an app that
/// forgets is exactly as safe as one that does not: the lease dies with the
/// engine either way.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeReleaseLease(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    lease_handle: jlong,
) -> jint {
    guarded(|| {
        if lease_handle <= 0 {
            return RESULT_INVALID_ARGUMENT;
        }
        match lock(leases()).remove(&(lease_handle as u64)) {
            Some(_) => RESULT_OK,
            None => RESULT_NOT_FOUND,
        }
    })
}

#[derive(Serialize)]
struct Decision {
    route: jint,
    operation: jint,
    policy_generation: u64,
}

/// Authorize one operation against a lease. Returns the decision as JSON, or
/// null when it was refused — the refusal itself is already in the component's
/// event stream.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeAuthorize(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    lease_handle: jlong,
    operation_code: jint,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime(handle) else {
            return std::ptr::null_mut();
        };
        let Some(operation) = operation(operation_code) else {
            return std::ptr::null_mut();
        };
        let leases = lock(leases());
        let Some(lease) = leases.get(&(lease_handle.max(0) as u64)) else {
            return std::ptr::null_mut();
        };
        if lease.engine != handle as u64 {
            return std::ptr::null_mut();
        }
        let Ok(decision) = runtime
            .component_manager()
            .authorize(&lease.lease, operation)
        else {
            return std::ptr::null_mut();
        };
        drop(leases);
        let json = serde_json::to_string(&Decision {
            route: route_code(decision.route),
            operation: operation_code,
            policy_generation: decision.policy_generation,
        })
        .unwrap_or_else(|_| "{}".to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Authorize a notification for an exact origin.
///
/// The origin is checked against the registered web app rather than trusted:
/// a notification lease is not a navigation lease, and neither one may be used
/// to widen the scope the user agreed to.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeAuthorizeNotification(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    lease_handle: jlong,
    origin: JString<'_>,
    operation_code: jint,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let (Some(origin), Some(operation)) =
            (read_string(&mut env, &origin), operation(operation_code))
        else {
            return RESULT_INVALID_ARGUMENT;
        };
        let leases = lock(leases());
        let Some(lease) = leases.get(&(lease_handle.max(0) as u64)) else {
            return RESULT_NOT_FOUND;
        };
        if lease.engine != handle as u64 {
            return RESULT_DENIED;
        }
        match runtime
            .component_manager()
            .authorize_notification(&lease.lease, &origin, operation)
        {
            Ok(_) => RESULT_OK,
            Err(error) => component_result(error),
        }
    })
}

#[derive(Serialize)]
struct ComponentEventRow {
    sequence: u64,
    channel: &'static str,
    kind: &'static str,
}

#[derive(Serialize)]
struct ComponentEventBatch {
    events: Vec<ComponentEventRow>,
    dropped: u64,
}

/// Take one component's events since the previous call.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeComponents_nativeDrainComponentEvents(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    id: JString<'_>,
    max: jint,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let empty = r#"{"events":[],"dropped":0}"#;
        let json = (|| {
            let runtime = runtime(handle)?;
            let id = component_id(&mut env, &id)?;
            let max = usize::try_from(max).unwrap_or(1).clamp(1, MAX_EVENT_BATCH);
            let drain = runtime.component_manager().drain_events(&id, max);
            let batch = ComponentEventBatch {
                events: drain
                    .events
                    .into_iter()
                    .map(|event| ComponentEventRow {
                        sequence: event.sequence,
                        channel: purpose_name(event.channel),
                        kind: component_event_name(event.kind),
                    })
                    .collect(),
                dropped: drain.dropped,
            };
            serde_json::to_string(&batch).ok()
        })()
        .unwrap_or_else(|| empty.to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

pub(crate) fn purpose_name(purpose: LeasePurpose) -> &'static str {
    match purpose {
        LeasePurpose::WebNavigation => "web_navigation",
        LeasePurpose::WebNotification => "web_notification",
        LeasePurpose::FileSharing => "file_sharing",
        LeasePurpose::LanProxy => "lan_proxy",
    }
}

pub(crate) fn component_event_name(kind: ComponentEventKind) -> &'static str {
    match kind {
        ComponentEventKind::Registered => "registered",
        ComponentEventKind::Removed => "removed",
        ComponentEventKind::RouteChanged => "route_changed",
        ComponentEventKind::LeaseAcquired => "lease_acquired",
        ComponentEventKind::LeaseReleased => "lease_released",
        ComponentEventKind::NotificationAllowed => "notification_allowed",
        ComponentEventKind::NotificationDenied => "notification_denied",
        ComponentEventKind::OperationBlocked => "operation_blocked",
        ComponentEventKind::LanProxyReady => "lan_proxy_ready",
        ComponentEventKind::LanProxyNetworkLost => "lan_proxy_network_lost",
        ComponentEventKind::LanProxyStopped => "lan_proxy_stopped",
        ComponentEventKind::LanProxyAuthFailed => "lan_proxy_auth_failed",
        ComponentEventKind::LanProxyRefused => "lan_proxy_refused",
    }
}

pub(crate) fn share_event_name(kind: ShareEventKind) -> &'static str {
    match kind {
        ShareEventKind::Created => "created",
        ShareEventKind::Restored => "restored",
        ShareEventKind::FileAdded => "file_added",
        ShareEventKind::DownloadAuthorized => "download_authorized",
        ShareEventKind::DownloadDenied => "download_denied",
        ShareEventKind::DownloadLimitReached => "download_limit_reached",
        ShareEventKind::Expired => "expired",
        ShareEventKind::Revoked => "revoked",
        ShareEventKind::IntegrityFailure => "integrity_failure",
    }
}

/// Unlock the encrypted vault and bind it to this engine generation.
///
/// The key is copied in, used and wiped, including on every error path. Binding
/// it to the engine is what keeps a single root: when the engine stops, the
/// vault stops answering.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeOpenVault(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    root: JString<'_>,
    key: JByteArray<'_>,
) -> jint {
    guarded(|| {
        let Some(runtime) = runtime(handle) else {
            return RESULT_NO_ENGINE;
        };
        let Some(root) = read_string(&mut env, &root) else {
            return RESULT_INVALID_ARGUMENT;
        };
        if key.is_null() || env.get_array_length(&key).unwrap_or(0) != SHARE_KEY_BYTES as jint {
            return RESULT_INVALID_ARGUMENT;
        }
        let mut master = Zeroizing::new([0_u8; SHARE_KEY_BYTES]);
        {
            let mut signed = Zeroizing::new([0_i8; SHARE_KEY_BYTES]);
            if env.get_byte_array_region(&key, 0, &mut signed[..]).is_err() {
                return RESULT_INVALID_ARGUMENT;
            }
            for (target, source) in master.iter_mut().zip(signed.iter()) {
                *target = *source as u8;
            }
        }
        match ShareManager::open(&root, *master) {
            Ok(manager) => {
                runtime.attach_share_manager(Arc::new(manager));
                RESULT_OK
            }
            Err(error) => share_result(&error),
        }
    })
}

/// Create a share. Returns an opaque handle; the owner and download
/// capabilities stay native.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeCreateShare(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now_ms: jlong,
    expires_at_ms: jlong,
    max_downloads: jint,
    password: JByteArray<'_>,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime(handle) else {
            return 0;
        };
        let Some(manager) = runtime.share_manager() else {
            return 0;
        };
        let (Ok(now_ms), Ok(expires_at_ms), Ok(max_downloads)) = (
            u64::try_from(now_ms),
            u64::try_from(expires_at_ms),
            u32::try_from(max_downloads),
        ) else {
            return 0;
        };
        let secret = if password.is_null() {
            None
        } else {
            match env.convert_byte_array(&password) {
                Ok(bytes) => Some(Zeroizing::new(bytes)),
                Err(_) => return 0,
            }
        };
        let password_required = secret.as_ref().is_some_and(|value| !value.is_empty());
        let created = manager.create(
            now_ms,
            ShareConfig {
                expires_at_ms,
                max_downloads,
            },
            secret.as_deref().map(Vec::as_slice),
        );
        let Ok(CreatedShare {
            id,
            owner,
            download,
        }) = created
        else {
            return 0;
        };
        let share_handle = NEXT_SHARE_HANDLE.fetch_add(1, Ordering::Relaxed);
        lock(shares()).insert(
            share_handle,
            OwnedShare {
                engine: handle.max(0) as u64,
                id,
                owner: Zeroizing::new(*owner.as_bytes()),
                download: Zeroizing::new(*download.as_bytes()),
                files: Vec::new(),
                password_required,
            },
        );
        share_handle as jlong
    }))
    .unwrap_or(0)
}

/// Add a file to a share, encrypting it into the vault as it is read.
///
/// `source_path` is an app-owned file; nothing about it reaches the vault's own
/// naming, which is generated. Returns the file id as hex, or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeAddFile(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    share_handle: jlong,
    now_ms: jlong,
    display_name: JString<'_>,
    media_type: JString<'_>,
    source_path: JString<'_>,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = (|| {
            let display_name = read_string(&mut env, &display_name)?;
            let media_type = read_string(&mut env, &media_type)?;
            let source_path = read_string(&mut env, &source_path)?;
            let now_ms = u64::try_from(now_ms).ok()?;
            // Everything needed for the encryption is copied out and the
            // registry guard released *before* the file is touched.
            //
            // Holding it across `add_file` meant the process-global shares lock
            // was held for the length of a whole-file streaming encryption —
            // and `nativeStop` takes the same lock through
            // `release_engine_handles`. Stopping the VPN while a large file was
            // being imported blocked the calling thread for the whole
            // encryption: an ANR on the service thread, and a `nativeStop` that
            // reports a timeout for a runtime that was never the problem.
            let (runtime, (share_id, owner)) =
                engine_and_share(share_handle, |share| (share.id, share.owner.clone()))?;
            let manager = runtime.share_manager()?;
            let mut source = std::fs::File::open(&source_path).ok()?;
            let plaintext_bytes = source.metadata().ok()?.len();
            let file = manager
                .add_file(
                    share_id,
                    &owner[..],
                    now_ms,
                    display_name,
                    media_type,
                    plaintext_bytes,
                    &mut source,
                )
                .ok()?;
            // Retaken only to record the result. If the share went away while
            // the file was being encrypted, the ciphertext is orphaned in the
            // vault rather than attached to a share that no longer exists —
            // which is the same outcome as revoking mid-import.
            lock(shares())
                .get_mut(&(share_handle.max(0) as u64))?
                .files
                .push(file.id);
            Some(file.id.to_hex())
        })();
        match json {
            Some(json) => env
                .new_string(json)
                .map(|value| value.into_raw())
                .unwrap_or(std::ptr::null_mut()),
            None => std::ptr::null_mut(),
        }
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Decrypt one file out of the vault to an app-owned path, spending one of the
/// share's download allowances.
///
/// This is the local retrieval path. Remote delivery uses the separate
/// root-owned onion publication and loopback-only HTTP adapter; it never calls
/// this export and has no clearnet fallback.
///
/// Returns the number of plaintext bytes written, or a negative result code.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeExportFile(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    share_handle: jlong,
    now_ms: jlong,
    file_id_hex: JString<'_>,
    password: JByteArray<'_>,
    destination_path: JString<'_>,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let written = (|| {
            let file_id_hex = read_string(&mut env, &file_id_hex)?;
            let destination_path = read_string(&mut env, &destination_path)?;
            let now_ms = u64::try_from(now_ms).ok()?;
            let secret = if password.is_null() {
                None
            } else {
                Some(Zeroizing::new(env.convert_byte_array(&password).ok()?))
            };
            // Authorised under the lock, written without it — the same reason
            // `nativeAddFile` does: `nativeStop` needs this mutex, and a
            // whole-file decrypt is not a length of time to hold it for.
            let (runtime, (share_id, download)) =
                engine_and_share(share_handle, |share| (share.id, share.download.clone()))?;
            let manager = runtime.share_manager()?;
            let file = FileId::from_hex(&file_id_hex)?;
            let permit = manager
                .authorize_download(
                    share_id,
                    file,
                    &download[..],
                    secret.as_deref().map(Vec::as_slice),
                    now_ms,
                )
                .ok()?;
            let mut destination = std::fs::File::create(&destination_path).ok()?;
            permit.write_plaintext(&mut destination).ok()
        })();
        match written {
            Some(bytes) => jlong::try_from(bytes).unwrap_or(jlong::MAX),
            None => jlong::from(-RESULT_VAULT_ERROR),
        }
    }))
    .unwrap_or(export_panic_code())
}

/// What `nativeExportFile` returns when its body panicked.
///
/// A named function rather than the expression inline, because the expression
/// was wrong in a way that reads as right: every other code in this module is a
/// positive constant negated at the call site, but `RESULT_PANICKED` is already
/// negative, so `-RESULT_PANICKED` handed back `+1`. This function returns a
/// byte count, so the app read a crash as "exported one byte successfully" into
/// a destination file it had created and never written.
fn export_panic_code() -> jlong {
    jlong::from(RESULT_PANICKED)
}

/// Revoke a share: already-issued permits stop at their next block, the secret
/// is wiped and the ciphertext is deleted.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeRevokeShare(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    share_handle: jlong,
) -> jint {
    guarded(|| {
        let Some(share) = lock(shares()).remove(&(share_handle.max(0) as u64)) else {
            return RESULT_NOT_FOUND;
        };
        let Some(runtime) = engine_for(&share) else {
            // The engine is gone, so the vault is closed and the share is
            // already unreachable. Reporting success would claim a deletion
            // that did not happen.
            return RESULT_NO_ENGINE;
        };
        let Some(manager) = runtime.share_manager() else {
            return RESULT_NO_ENGINE;
        };
        match manager.revoke(share.id, &share.owner[..]) {
            Ok(()) => RESULT_OK,
            Err(error) => share_result(&error),
        }
    })
}

#[derive(Serialize)]
struct ShareEventRow {
    sequence: u64,
    kind: &'static str,
}

#[derive(Serialize)]
struct ShareEventBatch {
    events: Vec<ShareEventRow>,
    dropped: u64,
}

/// Take one share's events since the previous call.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_core_component_FoxholeNativeShares_nativeDrainShareEvents(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    share_handle: jlong,
    max: jint,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let empty = r#"{"events":[],"dropped":0}"#;
        let json = (|| {
            let (runtime, share_id) = engine_and_share(share_handle, |share| share.id)?;
            let manager = runtime.share_manager()?;
            let max = usize::try_from(max).unwrap_or(1).clamp(1, MAX_EVENT_BATCH);
            let drain = manager.drain_events(share_id, max);
            serde_json::to_string(&ShareEventBatch {
                events: drain
                    .events
                    .into_iter()
                    .map(|event| ShareEventRow {
                        sequence: event.sequence,
                        kind: share_event_name(event.kind),
                    })
                    .collect(),
                dropped: drain.dropped,
            })
            .ok()
        })()
        .unwrap_or_else(|| empty.to_owned());
        env.new_string(json)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut())
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Resolve a share's engine **without** holding the shares table.
///
/// `engine_for` takes the runtime registry, and three paths here used to call it
/// with the shares mutex already held. §2.7 of the docs claims no path holds two
/// of these at once; three did. Nothing deadlocks today only because every
/// registry holder releases its guard before touching shares — one edit away
/// from a cycle whose victim is `nativeStop` on the service thread.
///
/// Returns the copied share fields the caller needs plus the runtime, with the
/// shares guard already dropped.
fn engine_and_share<T>(
    share_handle: jlong,
    copy: impl FnOnce(&OwnedShare) -> T,
) -> Option<(Arc<CoreRuntime>, T)> {
    let (engine, copied) = {
        let shares = lock(shares());
        let share = shares.get(&(share_handle.max(0) as u64))?;
        (share.engine, copy(share))
    };
    Some((runtime(engine as jlong)?, copied))
}

fn engine_for(share: &OwnedShare) -> Option<Arc<CoreRuntime>> {
    runtime(share.engine as jlong)
}

/// Drop every opaque JNI handle owned by one engine generation.
///
/// This runs while the engine is still alive. Publications go first so the
/// externally reachable onion address disappears before its loopback server,
/// then leases are released, and finally session-only shares are revoked while
/// their owner capability is still available.
pub(crate) fn release_engine_handles(engine: u64, runtime: &CoreRuntime) {
    let publications = remove_engine_entries(publications(), engine, |value| value.engine);
    drop(publications);

    let leases = remove_engine_entries(leases(), engine, |value| value.engine);
    drop(leases);

    let shares = remove_engine_entries(shares(), engine, |value| value.engine);
    if let Some(manager) = runtime.share_manager() {
        for share in &shares {
            let _ = manager.revoke(share.id, &share.owner[..]);
        }
    }
    drop(shares);
}

fn remove_engine_entries<T>(
    table: &Mutex<HashMap<u64, T>>,
    engine: u64,
    owner: impl Fn(&T) -> u64,
) -> Vec<T> {
    let mut table = lock(table);
    let handles = table
        .iter()
        .filter_map(|(handle, value)| (owner(value) == engine).then_some(*handle))
        .collect::<Vec<_>>();
    handles
        .into_iter()
        .filter_map(|handle| table.remove(&handle))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `nativeExportFile` returns a byte count, so its failure codes have to be
    /// on the other side of zero from every count it can legitimately produce.
    /// It used to negate an already-negative constant and hand back `+1`, which
    /// the app read as a one-byte export that succeeded.
    #[test]
    fn a_panic_in_the_export_boundary_is_negative_like_every_other_failure() {
        assert!(
            export_panic_code() < 0,
            "the value nativeExportFile returns on a panic must not be a byte count"
        );
    }

    #[test]
    fn route_codes_round_trip_and_reject_anything_else() {
        for code in [ROUTE_VPN, ROUTE_TOR, ROUTE_DIRECT, ROUTE_BLOCK] {
            assert_eq!(route_code(route(code).unwrap()), code);
        }
        // Nothing unknown may resolve to a route at all — least of all by
        // landing on Block, which a caller would read as a deliberate refusal.
        assert!(route(0).is_none());
        assert!(route(99).is_none());
        assert!(purpose(0).is_none());
        assert!(operation(0).is_none());
    }

    #[test]
    fn opaque_handle_cleanup_is_scoped_to_one_engine_generation() {
        #[derive(Debug, Eq, PartialEq)]
        struct OwnedValue {
            engine: u64,
            label: &'static str,
        }

        let table = Mutex::new(HashMap::from([
            (
                11,
                OwnedValue {
                    engine: 1,
                    label: "old-a",
                },
            ),
            (
                12,
                OwnedValue {
                    engine: 2,
                    label: "current",
                },
            ),
            (
                13,
                OwnedValue {
                    engine: 1,
                    label: "old-b",
                },
            ),
        ]));

        let mut removed = remove_engine_entries(&table, 1, |value| value.engine);
        removed.sort_by_key(|value| value.label);

        assert_eq!(removed.len(), 2);
        assert_eq!(lock(&table).values().next().unwrap().label, "current");
        assert_eq!(lock(&table).len(), 1);
    }

    #[test]
    fn invitation_keeps_capability_out_of_the_url_and_never_contains_a_password() {
        let share = ShareId::from_hex("00112233445566778899aabbccddeeff").unwrap();
        let file = FileId::from_hex("ffeeddccbbaa99887766554433221100").unwrap();
        let capability = [0xab; 32];
        let invitation =
            share_invitation_text("exampleexample.onion", 80, share, file, &capability, true);
        let url = invitation
            .lines()
            .find_map(|line| line.strip_prefix("url="))
            .unwrap();
        let username = invitation
            .lines()
            .find_map(|line| line.strip_prefix("username="))
            .unwrap();

        assert_eq!(
            url,
            "http://exampleexample.onion/00112233445566778899aabbccddeeff/ffeeddccbbaa99887766554433221100"
        );
        assert_eq!(username, "ab".repeat(32));
        assert!(!url.contains(username));
        assert!(invitation.contains("password=required-separate-channel"));
    }
}
