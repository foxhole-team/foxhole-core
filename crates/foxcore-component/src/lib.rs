#![forbid(unsafe_code)]

//! Isolated control-plane identities for web applications and other FoxCore
//! components.
//!
//! A component never owns VPN or Tor. It holds an RAII lease returned by the
//! root runtime provider, and every operation is authorised against the
//! component's current route. There is no `VPN -> DIRECT` fallback.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use foxcore_api::ApplicationRouteAction;
use getrandom::fill;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub mod lan;

pub use lan::{
    LanConnect, LanCredentials, LanIo, LanProxyConfig, LanProxyHandle, LanProxyPreset,
    LanProxyState, LanRoute, LanTransport, LanUpstream, LoopbackInbound, NetworkBinding,
};

const MAX_COMPONENTS: usize = 1024;
/// Networks the user has said yes to. Bounded: a confirmation list that grows
/// without limit is a list nobody can review, and the point of it is review.
const MAX_CONFIRMED_NETWORKS: usize = 64;
const MAX_LEASES: usize = 4096;
const MAX_COMPONENT_ID_BYTES: usize = 96;
const MAX_ORIGIN_BYTES: usize = 2048;
const MAX_EVENTS_PER_COMPONENT: usize = 256;
const CREDENTIAL_BYTES: usize = 32;
/// A file share has no configurable route. `FileShareConfig` carries no route
/// field on purpose, so publication is Tor-only by construction rather than by
/// a default someone can later widen to `Direct`.
const FILE_SHARE_ROUTE: ComponentRoute = ComponentRoute::Tor;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentId(String);

impl ComponentId {
    pub fn new(value: impl Into<String>) -> Result<Self, ComponentError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_COMPONENT_ID_BYTES
            || !value.is_ascii()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err(ComponentError::InvalidIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ComponentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ComponentId").field(&self.0).finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentRoute {
    Vpn,
    Tor,
    Direct,
    Block,
}

impl From<ComponentRoute> for ApplicationRouteAction {
    fn from(route: ComponentRoute) -> Self {
        match route {
            ComponentRoute::Vpn => Self::Vpn,
            ComponentRoute::Tor => Self::Tor,
            ComponentRoute::Direct => Self::Direct,
            ComponentRoute::Block => Self::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKind {
    /// Root-generation liveness for routes that do not need a VPN/Tor
    /// transport of their own. A Direct component must still die with the
    /// supervisor that authorised it.
    Root,
    Vpn,
    Tor,
}

pub trait RuntimeLease: Send + Sync {
    /// A lease can outlive the root runtime handle that issued it. Every
    /// operation must therefore re-check liveness instead of treating
    /// successful acquisition as a permanent routing guarantee.
    fn is_available(&self) -> bool;
}

pub trait RuntimeLeaseProvider: Send + Sync {
    /// Acquire the shared root-owned runtime. Returning an error must never
    /// cause the caller to try another privacy route.
    fn acquire(&self, runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeasePurpose {
    WebNavigation,
    WebNotification,
    FileSharing,
    /// The LAN ingress. Its own channel because its events are about listeners
    /// and credentials, which no other component has.
    LanProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentOperation {
    Navigation,
    Subresource,
    NotificationDelivery,
    NotificationAction,
    FileSharePublish,
    FileShareDownload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentDecision {
    pub route: ComponentRoute,
    pub operation: ComponentOperation,
    pub policy_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAppConfig {
    pub id: ComponentId,
    /// Canonical HTTPS origin. Paths, queries, fragments and userinfo are
    /// forbidden so a notification cannot smuggle a different scope.
    pub origin: String,
    pub route: ComponentRoute,
    pub notifications_enabled: bool,
}

/// A file share is never a web application and never gains an origin or a
/// notification channel. Its publication route is deliberately fixed to Tor;
/// clearnet publication is not representable at this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileShareConfig {
    pub id: ComponentId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentEventKind {
    Registered,
    Removed,
    RouteChanged,
    LeaseAcquired,
    LeaseReleased,
    NotificationAllowed,
    NotificationDenied,
    OperationBlocked,
    /// LAN listeners are up on a confirmed network.
    LanProxyReady,
    /// Listeners closed, credentials invalidated, and a new network needs a new
    /// confirmation before anything binds again.
    LanProxyNetworkLost,
    LanProxyStopped,
    /// A client failed authentication, including by offering only anonymous
    /// SOCKS. Recorded because repeated failures on a shared Wi-Fi are the
    /// signal that somebody is guessing.
    LanProxyAuthFailed,
    /// An authenticated session was refused because its upstream was not
    /// available. Never a fallback: this is the event that exists instead of
    /// one.
    LanProxyRefused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentEvent {
    pub component: ComponentId,
    pub sequence: u64,
    pub channel: LeasePurpose,
    pub kind: ComponentEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentEventDrain {
    pub events: Vec<ComponentEvent>,
    pub dropped: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ComponentError {
    #[error("component identity is invalid")]
    InvalidIdentity,
    #[error("web application origin must be a canonical HTTPS origin")]
    InvalidOrigin,
    #[error("component already exists")]
    AlreadyExists,
    #[error("component does not exist")]
    NotFound,
    #[error("component capacity is exhausted")]
    Capacity,
    #[error("component lease is invalid or revoked")]
    InvalidLease,
    #[error("operation is not permitted by this lease")]
    WrongPurpose,
    #[error("notifications are disabled for this web application")]
    NotificationsDisabled,
    #[error("notification origin does not match the isolated web application")]
    OriginMismatch,
    #[error("component route is blocked")]
    Blocked,
    #[error("required shared runtime is unavailable")]
    RuntimeUnavailable,
    #[error("secure random source is unavailable")]
    RandomUnavailable,
    #[error("network binding is not permitted for a LAN listener")]
    LanBindingRefused,
    #[error("this network has not been confirmed for LAN listeners")]
    LanNetworkNotConfirmed,
    #[error("LAN listener could not bind")]
    LanBindFailed,
}

struct WebAppRecord {
    origin: String,
    route: ComponentRoute,
    notifications_enabled: bool,
    policy_generation: u64,
}

struct FileShareRecord {
    policy_generation: u64,
}

struct LeaseRecord {
    component: ComponentId,
    purpose: LeasePurpose,
    credential_digest: [u8; 32],
    runtime: Option<Arc<dyn RuntimeLease>>,
}

struct State {
    /// The audit recorder, when one is attached. Held in the state so
    /// `push_event` reaches it without a second lock on the event path.
    recorder: Option<ComponentRecorder>,
    next_lease: u64,
    next_policy_generation: u64,
    web_apps: HashMap<ComponentId, WebAppRecord>,
    file_shares: HashMap<ComponentId, FileShareRecord>,
    leases: HashMap<u64, LeaseRecord>,
    /// Fingerprints of networks the user explicitly approved for LAN
    /// listeners. Never populated by observation.
    confirmed_networks: std::collections::HashSet<[u8; 32]>,
    lan_proxies: std::collections::HashSet<ComponentId>,
    next_event_sequence: HashMap<ComponentId, u64>,
    events: HashMap<ComponentId, VecDeque<ComponentEvent>>,
    dropped_events: HashMap<ComponentId, u64>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            recorder: None,
            confirmed_networks: std::collections::HashSet::new(),
            lan_proxies: std::collections::HashSet::new(),
            next_lease: 1,
            next_policy_generation: 1,
            web_apps: HashMap::new(),
            file_shares: HashMap::new(),
            leases: HashMap::new(),
            next_event_sequence: HashMap::new(),
            events: HashMap::new(),
            dropped_events: HashMap::new(),
        }
    }
}

pub(crate) struct Inner {
    pub(crate) provider: Arc<dyn RuntimeLeaseProvider>,
    /// Serialises register/remove/route transitions. Runtime acquisition may
    /// call into the root supervisor and therefore never happens under `state`.
    control: Mutex<()>,
    pub(crate) state: Mutex<State>,
}

/// A second consumer that sees every component event as it happens.
///
/// The per-component drain is what a screen reads; this is what an audit
/// consumer reads. They are separate because their lifetimes are: a recorder is
/// attached once and must not depend on anyone remembering to poll each of up to
/// 1024 components, and an event nobody drained is exactly the one worth
/// keeping.
pub type ComponentRecorder = Arc<dyn Fn(&ComponentEvent) + Send + Sync>;

#[derive(Clone)]
pub struct ComponentManager {
    inner: Arc<Inner>,
}

impl fmt::Debug for ComponentManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        formatter
            .debug_struct("ComponentManager")
            .field("web_apps", &state.web_apps.len())
            .field("file_shares", &state.file_shares.len())
            .field("leases", &state.leases.len())
            .finish_non_exhaustive()
    }
}

pub struct ComponentLease {
    inner: Arc<Inner>,
    id: u64,
    credential: Zeroizing<[u8; CREDENTIAL_BYTES]>,
}

impl fmt::Debug for ComponentLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentLease")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ComponentLease {
    pub fn credential(&self) -> LeaseCredential {
        LeaseCredential(Zeroizing::new(*self.credential))
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for ComponentLease {
    fn drop(&mut self) {
        let removed = {
            let mut state = lock(&self.inner.state);
            let removed = state.leases.remove(&self.id);
            if let Some(record) = &removed {
                push_event(
                    &mut state,
                    &record.component,
                    record.purpose,
                    ComponentEventKind::LeaseReleased,
                );
            }
            removed
        };
        // Dropping a runtime lease may stop Tor/VPN. Never do that under the
        // component-state mutex.
        drop(removed);
    }
}

pub struct LeaseCredential(Zeroizing<[u8; CREDENTIAL_BYTES]>);

impl LeaseCredential {
    pub fn as_bytes(&self) -> &[u8; CREDENTIAL_BYTES] {
        &self.0
    }
}

impl fmt::Debug for LeaseCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeaseCredential([REDACTED])")
    }
}

impl ComponentManager {
    pub fn new(provider: Arc<dyn RuntimeLeaseProvider>) -> Self {
        Self {
            inner: Arc::new(Inner {
                provider,
                control: Mutex::new(()),
                state: Mutex::new(State::default()),
            }),
        }
    }

    pub fn register_web_app(&self, config: WebAppConfig) -> Result<(), ComponentError> {
        let _control = lock(&self.inner.control);
        let origin = canonical_origin(&config.origin)?;
        let mut state = lock(&self.inner.state);
        let new_identity = !state.next_event_sequence.contains_key(&config.id);
        if component_count(&state) >= MAX_COMPONENTS
            || (new_identity && state.next_event_sequence.len() >= MAX_COMPONENTS)
        {
            return Err(ComponentError::Capacity);
        }
        if state.web_apps.contains_key(&config.id) || state.file_shares.contains_key(&config.id) {
            return Err(ComponentError::AlreadyExists);
        }
        let generation = take_generation(&mut state);
        state.web_apps.insert(
            config.id.clone(),
            WebAppRecord {
                origin,
                route: config.route,
                notifications_enabled: config.notifications_enabled,
                policy_generation: generation,
            },
        );
        push_event(
            &mut state,
            &config.id,
            LeasePurpose::WebNavigation,
            ComponentEventKind::Registered,
        );
        Ok(())
    }

    pub fn register_file_share(&self, config: FileShareConfig) -> Result<(), ComponentError> {
        let _control = lock(&self.inner.control);
        let mut state = lock(&self.inner.state);
        let new_identity = !state.next_event_sequence.contains_key(&config.id);
        if component_count(&state) >= MAX_COMPONENTS
            || (new_identity && state.next_event_sequence.len() >= MAX_COMPONENTS)
        {
            return Err(ComponentError::Capacity);
        }
        if state.web_apps.contains_key(&config.id) || state.file_shares.contains_key(&config.id) {
            return Err(ComponentError::AlreadyExists);
        }
        let generation = take_generation(&mut state);
        state.file_shares.insert(
            config.id.clone(),
            FileShareRecord {
                policy_generation: generation,
            },
        );
        push_event(
            &mut state,
            &config.id,
            LeasePurpose::FileSharing,
            ComponentEventKind::Registered,
        );
        Ok(())
    }

    pub fn remove_web_app(&self, id: &ComponentId) -> Result<(), ComponentError> {
        let _control = lock(&self.inner.control);
        let removed = {
            let mut state = lock(&self.inner.state);
            if state.web_apps.remove(id).is_none() {
                return Err(ComponentError::NotFound);
            }
            let lease_ids = state
                .leases
                .iter()
                .filter_map(|(lease_id, record)| (&record.component == id).then_some(*lease_id))
                .collect::<Vec<_>>();
            let removed = lease_ids
                .into_iter()
                .filter_map(|lease_id| state.leases.remove(&lease_id))
                .collect::<Vec<_>>();
            push_event(
                &mut state,
                id,
                LeasePurpose::WebNavigation,
                ComponentEventKind::Removed,
            );
            removed
        };
        drop(removed);
        Ok(())
    }

    pub fn remove_file_share(&self, id: &ComponentId) -> Result<(), ComponentError> {
        let _control = lock(&self.inner.control);
        let removed = {
            let mut state = lock(&self.inner.state);
            if state.file_shares.remove(id).is_none() {
                return Err(ComponentError::NotFound);
            }
            let lease_ids = state
                .leases
                .iter()
                .filter_map(|(lease_id, record)| (&record.component == id).then_some(*lease_id))
                .collect::<Vec<_>>();
            let removed = lease_ids
                .into_iter()
                .filter_map(|lease_id| state.leases.remove(&lease_id))
                .collect::<Vec<_>>();
            push_event(
                &mut state,
                id,
                LeasePurpose::FileSharing,
                ComponentEventKind::Removed,
            );
            removed
        };
        drop(removed);
        Ok(())
    }

    pub fn set_web_app_route(
        &self,
        id: &ComponentId,
        route: ComponentRoute,
    ) -> Result<u64, ComponentError> {
        let _control = lock(&self.inner.control);
        let (lease_ids, current_route, current_generation) = {
            let state = lock(&self.inner.state);
            let component = state.web_apps.get(id).ok_or(ComponentError::NotFound)?;
            (
                state
                    .leases
                    .iter()
                    .filter_map(|(lease_id, record)| (&record.component == id).then_some(*lease_id))
                    .collect::<Vec<_>>(),
                component.route,
                component.policy_generation,
            )
        };
        if current_route == route {
            return Ok(current_generation);
        }
        let mut replacements = HashMap::with_capacity(lease_ids.len());
        for lease_id in lease_ids {
            replacements.insert(lease_id, acquire_runtime(&self.inner.provider, route)?);
        }
        let old = {
            let mut state = lock(&self.inner.state);
            let generation = take_generation(&mut state);
            let record = state.web_apps.get_mut(id).ok_or(ComponentError::NotFound)?;
            record.route = route;
            record.policy_generation = generation;
            let mut old = Vec::new();
            for (lease_id, runtime) in replacements {
                let lease = state
                    .leases
                    .get_mut(&lease_id)
                    .ok_or(ComponentError::InvalidLease)?;
                old.push(std::mem::replace(&mut lease.runtime, runtime));
            }
            push_event(
                &mut state,
                id,
                LeasePurpose::WebNavigation,
                ComponentEventKind::RouteChanged,
            );
            (generation, old)
        };
        drop(old.1);
        Ok(old.0)
    }

    pub fn acquire(
        &self,
        id: &ComponentId,
        purpose: LeasePurpose,
    ) -> Result<ComponentLease, ComponentError> {
        let _control = lock(&self.inner.control);
        let route = {
            let state = lock(&self.inner.state);
            if state.leases.len() >= MAX_LEASES {
                return Err(ComponentError::Capacity);
            }
            if purpose == LeasePurpose::WebNotification
                && !state
                    .web_apps
                    .get(id)
                    .ok_or(ComponentError::NotFound)?
                    .notifications_enabled
            {
                return Err(ComponentError::NotificationsDisabled);
            }
            let (route, _) =
                resolve_component(&state, id, purpose).ok_or(ComponentError::NotFound)?;
            route
        };
        let runtime = acquire_runtime(&self.inner.provider, route)?;
        let mut credential = Zeroizing::new([0_u8; CREDENTIAL_BYTES]);
        fill(&mut *credential).map_err(|_| ComponentError::RandomUnavailable)?;
        let credential_digest: [u8; 32] = Sha256::digest(*credential).into();
        let id_number = {
            let mut state = lock(&self.inner.state);
            if state.leases.len() >= MAX_LEASES {
                return Err(ComponentError::Capacity);
            }
            let id_number = state.next_lease;
            state.next_lease = state
                .next_lease
                .checked_add(1)
                .ok_or(ComponentError::Capacity)?;
            state.leases.insert(
                id_number,
                LeaseRecord {
                    component: id.clone(),
                    purpose,
                    credential_digest,
                    runtime,
                },
            );
            push_event(&mut state, id, purpose, ComponentEventKind::LeaseAcquired);
            id_number
        };
        Ok(ComponentLease {
            inner: self.inner.clone(),
            id: id_number,
            credential,
        })
    }

    pub fn authorize(
        &self,
        lease: &ComponentLease,
        operation: ComponentOperation,
    ) -> Result<ComponentDecision, ComponentError> {
        if !Arc::ptr_eq(&self.inner, &lease.inner) {
            return Err(ComponentError::InvalidLease);
        }
        let mut state = lock(&self.inner.state);
        let lease_record = state
            .leases
            .get(&lease.id)
            .ok_or(ComponentError::InvalidLease)?;
        ensure_operation(lease_record.purpose, operation)?;
        ensure_runtime_available(lease_record)?;
        let component = lease_record.component.clone();
        let purpose = lease_record.purpose;
        let (route, policy_generation) =
            resolve_component(&state, &component, purpose).ok_or(ComponentError::InvalidLease)?;
        let decision = ComponentDecision {
            route,
            operation,
            policy_generation,
        };
        if route == ComponentRoute::Block {
            push_event(
                &mut state,
                &component,
                purpose,
                ComponentEventKind::OperationBlocked,
            );
            return Err(ComponentError::Blocked);
        }
        Ok(decision)
    }

    pub fn authorize_notification(
        &self,
        lease: &ComponentLease,
        origin: &str,
        operation: ComponentOperation,
    ) -> Result<ComponentDecision, ComponentError> {
        if !matches!(
            operation,
            ComponentOperation::NotificationDelivery | ComponentOperation::NotificationAction
        ) {
            return Err(ComponentError::WrongPurpose);
        }
        if !Arc::ptr_eq(&self.inner, &lease.inner) {
            return Err(ComponentError::InvalidLease);
        }
        let expected = canonical_origin(origin)?;
        let mut state = lock(&self.inner.state);
        let lease_record = state
            .leases
            .get(&lease.id)
            .ok_or(ComponentError::InvalidLease)?;
        if lease_record.purpose != LeasePurpose::WebNotification {
            return Err(ComponentError::WrongPurpose);
        }
        ensure_runtime_available(lease_record)?;
        let component = lease_record.component.clone();
        let record = state
            .web_apps
            .get(&component)
            .ok_or(ComponentError::InvalidLease)?;
        if record.origin != expected {
            push_event(
                &mut state,
                &component,
                LeasePurpose::WebNotification,
                ComponentEventKind::NotificationDenied,
            );
            return Err(ComponentError::OriginMismatch);
        }
        if record.route == ComponentRoute::Block {
            push_event(
                &mut state,
                &component,
                LeasePurpose::WebNotification,
                ComponentEventKind::NotificationDenied,
            );
            return Err(ComponentError::Blocked);
        }
        let decision = ComponentDecision {
            route: record.route,
            operation,
            policy_generation: record.policy_generation,
        };
        push_event(
            &mut state,
            &component,
            LeasePurpose::WebNotification,
            ComponentEventKind::NotificationAllowed,
        );
        Ok(decision)
    }

    /// Authenticate a local proxy connection without storing or comparing the
    /// raw credential. This is the cross-FFI equivalent of holding
    /// `ComponentLease`.
    pub fn authorize_credential(
        &self,
        lease_id: u64,
        credential: &[u8],
        operation: ComponentOperation,
    ) -> Result<ComponentDecision, ComponentError> {
        if credential.len() != CREDENTIAL_BYTES {
            return Err(ComponentError::InvalidLease);
        }
        let supplied: [u8; 32] = Sha256::digest(credential).into();
        let state = lock(&self.inner.state);
        let record = state
            .leases
            .get(&lease_id)
            .ok_or(ComponentError::InvalidLease)?;
        if !bool::from(record.credential_digest.ct_eq(&supplied)) {
            return Err(ComponentError::InvalidLease);
        }
        drop(state);
        let synthetic = ComponentLeaseReference {
            inner: &self.inner,
            id: lease_id,
        };
        self.authorize_reference(synthetic, operation)
    }

    fn authorize_reference(
        &self,
        lease: ComponentLeaseReference<'_>,
        operation: ComponentOperation,
    ) -> Result<ComponentDecision, ComponentError> {
        if !Arc::ptr_eq(&self.inner, lease.inner) {
            return Err(ComponentError::InvalidLease);
        }
        let mut state = lock(&self.inner.state);
        let lease_record = state
            .leases
            .get(&lease.id)
            .ok_or(ComponentError::InvalidLease)?;
        ensure_operation(lease_record.purpose, operation)?;
        ensure_runtime_available(lease_record)?;
        let component = lease_record.component.clone();
        let purpose = lease_record.purpose;
        let (route, policy_generation) =
            resolve_component(&state, &component, purpose).ok_or(ComponentError::InvalidLease)?;
        if route == ComponentRoute::Block {
            push_event(
                &mut state,
                &component,
                purpose,
                ComponentEventKind::OperationBlocked,
            );
            return Err(ComponentError::Blocked);
        }
        Ok(ComponentDecision {
            route,
            operation,
            policy_generation,
        })
    }

    /// Record that the user approved this network for LAN listeners.
    ///
    /// Only ever called from an explicit user decision. A binding with no SSID
    /// hash has no fingerprint and therefore cannot be confirmed at all — the
    /// core would have no way to tell that network from any other later.
    pub fn confirm_lan_network(&self, binding: &NetworkBinding) -> Result<(), ComponentError> {
        let fingerprint = binding
            .fingerprint()
            .ok_or(ComponentError::LanNetworkNotConfirmed)?;
        let mut state = lock(&self.inner.state);
        if state.confirmed_networks.len() >= MAX_CONFIRMED_NETWORKS
            && !state.confirmed_networks.contains(&fingerprint)
        {
            return Err(ComponentError::Capacity);
        }
        state.confirmed_networks.insert(fingerprint);
        Ok(())
    }

    /// Withdraw a confirmation. Running listeners are not affected; stop them
    /// first if that is what is meant.
    pub fn forget_lan_network(&self, binding: &NetworkBinding) {
        if let Some(fingerprint) = binding.fingerprint() {
            lock(&self.inner.state)
                .confirmed_networks
                .remove(&fingerprint);
        }
    }

    pub fn is_lan_network_confirmed(&self, binding: &NetworkBinding) -> bool {
        binding.fingerprint().is_some_and(|fingerprint| {
            lock(&self.inner.state)
                .confirmed_networks
                .contains(&fingerprint)
        })
    }

    /// Bind SOCKS5 and HTTP CONNECT listeners on one confirmed network.
    ///
    /// Runtime leases are taken through the same provider every other component
    /// uses — there is no second supervisor — and they are taken *before*
    /// anything binds, so a listener is never up while its upstream is not.
    pub fn start_lan_proxy(
        &self,
        handle: tokio::runtime::Handle,
        config: LanProxyConfig,
        binding: NetworkBinding,
        upstream: Arc<dyn LanUpstream>,
    ) -> Result<LanProxyHandle, ComponentError> {
        let _control = lock(&self.inner.control);
        lan::start(self.inner.clone(), handle, config, binding, upstream)
    }

    /// [`Self::start_lan_proxy`] with a shortened handshake deadline.
    ///
    /// One test needs this and nothing else does: the deadline is what gives a
    /// silent client's session slot back, so proving that costs wall clock. It
    /// used to be bought with a `cfg(test)` constant that shortened the deadline
    /// for the whole process — which is how ten unrelated socket tests came to
    /// fail, but only in the full workspace run, on a machine busy compiling.
    /// The shared state, for the one test that has to reach `lan::start_with_binding`
    /// directly: the rule it asserts — no anonymous listener on a confirmed LAN
    /// binding — lives below every public entry point, and a test that could only
    /// reach it through `LanProxyConfig` would be asserting the type, not the rule.
    #[cfg(test)]
    pub(crate) fn inner_for_test(&self) -> Arc<Inner> {
        self.inner.clone()
    }

    #[cfg(test)]
    pub(crate) fn start_lan_proxy_with_handshake_timeout(
        &self,
        handle: tokio::runtime::Handle,
        config: LanProxyConfig,
        binding: NetworkBinding,
        upstream: Arc<dyn LanUpstream>,
        handshake_timeout: std::time::Duration,
    ) -> Result<LanProxyHandle, ComponentError> {
        let _control = lock(&self.inner.control);
        lan::start_with_handshake_timeout(
            self.inner.clone(),
            handle,
            config,
            binding,
            upstream,
            handshake_timeout,
        )
    }

    /// Bind an authenticated HTTP CONNECT surface to `127.0.0.1` for the root
    /// runtime's own control plane.
    ///
    /// The caller supplies no address, interface or network identity. Unlike a
    /// user-facing LAN proxy this path needs no Wi-Fi confirmation, while the
    /// component still owns its credentials, leases, events and shutdown.
    pub fn start_loopback_proxy(
        &self,
        handle: tokio::runtime::Handle,
        config: LanProxyConfig,
        generation: u64,
        upstream: Arc<dyn LanUpstream>,
    ) -> Result<LanProxyHandle, ComponentError> {
        let _control = lock(&self.inner.control);
        lan::start_loopback(self.inner.clone(), handle, config, generation, upstream)
    }

    /// Bind one named loopback CONNECT listener.
    ///
    /// Same guarantees as [`Self::start_loopback_proxy`] — `127.0.0.1` chosen
    /// here and not by the caller, mandatory credentials, a lease taken before
    /// anything binds — with the route named per inbound instead of derived from
    /// a preset, because each of these *is* one application's whole route.
    pub fn start_loopback_inbound(
        &self,
        handle: tokio::runtime::Handle,
        config: LoopbackInbound,
        generation: u64,
        upstream: Arc<dyn LanUpstream>,
    ) -> Result<LanProxyHandle, ComponentError> {
        let _control = lock(&self.inner.control);
        lan::start_loopback_inbound(self.inner.clone(), handle, config, generation, upstream)
    }

    /// Send every component event to a second consumer as well as to the
    /// per-component queue. Replaces any previous recorder.
    pub fn attach_recorder(&self, recorder: ComponentRecorder) {
        lock(&self.inner.state).recorder = Some(recorder);
    }

    /// Stops recording. Idempotent.
    pub fn detach_recorder(&self) {
        lock(&self.inner.state).recorder = None;
    }

    pub fn drain_events(&self, component: &ComponentId, max: usize) -> ComponentEventDrain {
        let max = max.min(MAX_EVENTS_PER_COMPONENT);
        let mut state = lock(&self.inner.state);
        let queue = state.events.entry(component.clone()).or_default();
        let mut events = Vec::with_capacity(max.min(queue.len()));
        for _ in 0..max {
            let Some(event) = queue.pop_front() else {
                break;
            };
            events.push(event);
        }
        ComponentEventDrain {
            events,
            dropped: state.dropped_events.remove(component).unwrap_or(0),
        }
    }
}

struct ComponentLeaseReference<'a> {
    inner: &'a Arc<Inner>,
    id: u64,
}

fn canonical_origin(value: &str) -> Result<String, ComponentError> {
    if value.is_empty() || value.len() > MAX_ORIGIN_BYTES {
        return Err(ComponentError::InvalidOrigin);
    }
    let parsed = Url::parse(value).map_err(|_| ComponentError::InvalidOrigin)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ComponentError::InvalidOrigin);
    }
    Ok(parsed.origin().ascii_serialization())
}

fn acquire_runtime(
    provider: &Arc<dyn RuntimeLeaseProvider>,
    route: ComponentRoute,
) -> Result<Option<Arc<dyn RuntimeLease>>, ComponentError> {
    match route {
        ComponentRoute::Vpn => provider.acquire(RuntimeKind::Vpn).map(Some),
        ComponentRoute::Tor => provider.acquire(RuntimeKind::Tor).map(Some),
        ComponentRoute::Direct | ComponentRoute::Block => Ok(None),
    }
}

fn ensure_operation(
    purpose: LeasePurpose,
    operation: ComponentOperation,
) -> Result<(), ComponentError> {
    let allowed = match purpose {
        LeasePurpose::WebNavigation => matches!(
            operation,
            ComponentOperation::Navigation | ComponentOperation::Subresource
        ),
        LeasePurpose::WebNotification => matches!(
            operation,
            ComponentOperation::NotificationDelivery | ComponentOperation::NotificationAction
        ),
        // A LAN lease authorizes nothing through this path: its sessions are
        // authenticated on the wire, not by a component operation.
        LeasePurpose::LanProxy => false,
        LeasePurpose::FileSharing => matches!(
            operation,
            ComponentOperation::FileSharePublish | ComponentOperation::FileShareDownload
        ),
    };
    allowed.then_some(()).ok_or(ComponentError::WrongPurpose)
}

fn ensure_runtime_available(record: &LeaseRecord) -> Result<(), ComponentError> {
    if record
        .runtime
        .as_ref()
        .is_some_and(|runtime| !runtime.is_available())
    {
        return Err(ComponentError::RuntimeUnavailable);
    }
    Ok(())
}

/// Resolve a registered component through the registry its lease purpose
/// belongs to.
///
/// Keying on `purpose` is what keeps the two identity kinds from bleeding into
/// each other: a `FileSharing` lease can never resolve to a web app's route, and
/// a navigation lease can never resolve to a share. Returns `None` when the
/// component is absent from its own registry; the caller picks the error, since
/// "not registered yet" and "lease outlived its component" are different faults.
fn resolve_component(
    state: &State,
    id: &ComponentId,
    purpose: LeasePurpose,
) -> Option<(ComponentRoute, u64)> {
    match purpose {
        LeasePurpose::WebNavigation | LeasePurpose::WebNotification => state
            .web_apps
            .get(id)
            .map(|record| (record.route, record.policy_generation)),
        LeasePurpose::FileSharing => state
            .file_shares
            .get(id)
            .map(|record| (FILE_SHARE_ROUTE, record.policy_generation)),
        // The LAN proxy holds its runtime leases directly and routes per
        // preset, so it has no single component route to resolve. Handing one
        // out here would make it addressable as a web app.
        LeasePurpose::LanProxy => None,
    }
}

/// Live components, counted across both registries.
///
/// `web_apps` and `file_shares` share one `MAX_COMPONENTS` budget: they are two
/// kinds of the same isolated identity, and counting them separately would let a
/// caller register 2048 of them.
fn component_count(state: &State) -> usize {
    state.web_apps.len().saturating_add(state.file_shares.len())
}

fn take_generation(state: &mut State) -> u64 {
    let generation = state.next_policy_generation;
    state.next_policy_generation = state.next_policy_generation.saturating_add(1);
    generation
}

pub(crate) fn push_event(
    state: &mut State,
    component: &ComponentId,
    channel: LeasePurpose,
    kind: ComponentEventKind,
) {
    let sequence = state
        .next_event_sequence
        .entry(component.clone())
        .or_insert(1);
    let event = ComponentEvent {
        component: component.clone(),
        sequence: *sequence,
        channel,
        kind,
    };
    *sequence = sequence.saturating_add(1);
    let dropped_one = {
        let queue = state.events.entry(component.clone()).or_default();
        if queue.len() >= MAX_EVENTS_PER_COMPONENT {
            queue.pop_front();
            true
        } else {
            false
        }
    };
    if dropped_one {
        let dropped = state.dropped_events.entry(component.clone()).or_default();
        *dropped = dropped.saturating_add(1);
    }
    // The recorder first and by reference: it queues rather than writes, so an
    // event the per-component queue had no room for still reaches the recorder.
    if let Some(recorder) = state.recorder.clone() {
        recorder(&event);
    }
    state
        .events
        .entry(component.clone())
        .or_default()
        .push_back(event);
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Drop for LeaseCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[derive(Default)]
    struct AvailableProvider;

    struct AvailableLease;

    impl RuntimeLease for AvailableLease {
        fn is_available(&self) -> bool {
            true
        }
    }

    impl RuntimeLeaseProvider for AvailableProvider {
        fn acquire(&self, _runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError> {
            Ok(Arc::new(AvailableLease))
        }
    }

    struct ToggleLease(Arc<AtomicBool>);

    impl RuntimeLease for ToggleLease {
        fn is_available(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    struct ToggleProvider(Arc<AtomicBool>);

    impl RuntimeLeaseProvider for ToggleProvider {
        fn acquire(&self, _runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError> {
            if !self.0.load(Ordering::Acquire) {
                return Err(ComponentError::RuntimeUnavailable);
            }
            Ok(Arc::new(ToggleLease(self.0.clone())))
        }
    }

    fn web_app(route: ComponentRoute) -> WebAppConfig {
        WebAppConfig {
            id: ComponentId::new("web:mail").unwrap(),
            origin: "https://mail.example".into(),
            route,
            notifications_enabled: true,
        }
    }

    #[test]
    fn navigation_and_notifications_have_separate_leases_but_the_same_route_policy() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let config = web_app(ComponentRoute::Tor);
        manager.register_web_app(config.clone()).unwrap();
        let navigation = manager
            .acquire(&config.id, LeasePurpose::WebNavigation)
            .unwrap();
        let notification = manager
            .acquire(&config.id, LeasePurpose::WebNotification)
            .unwrap();

        assert_eq!(
            manager
                .authorize(&navigation, ComponentOperation::Navigation)
                .unwrap()
                .route,
            ComponentRoute::Tor
        );
        assert_eq!(
            manager
                .authorize_notification(
                    &notification,
                    "https://mail.example",
                    ComponentOperation::NotificationDelivery,
                )
                .unwrap()
                .route,
            ComponentRoute::Tor
        );
        assert_eq!(
            manager.authorize(&navigation, ComponentOperation::NotificationDelivery),
            Err(ComponentError::WrongPurpose)
        );
    }

    #[test]
    fn a_notification_from_another_origin_is_refused_and_scoped_to_its_app() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let config = web_app(ComponentRoute::Vpn);
        manager.register_web_app(config.clone()).unwrap();
        let notification = manager
            .acquire(&config.id, LeasePurpose::WebNotification)
            .unwrap();

        assert_eq!(
            manager.authorize_notification(
                &notification,
                "https://lookalike.example",
                ComponentOperation::NotificationDelivery,
            ),
            Err(ComponentError::OriginMismatch)
        );
        let events = manager.drain_events(&config.id, 32).events;
        assert!(events.iter().any(|event| {
            event.channel == LeasePurpose::WebNotification
                && event.kind == ComponentEventKind::NotificationDenied
        }));
    }

    #[test]
    fn route_changes_are_atomic_for_new_operations_and_never_fall_back() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let config = web_app(ComponentRoute::Vpn);
        manager.register_web_app(config.clone()).unwrap();
        let lease = manager
            .acquire(&config.id, LeasePurpose::WebNavigation)
            .unwrap();
        let old_generation = manager
            .authorize(&lease, ComponentOperation::Navigation)
            .unwrap()
            .policy_generation;
        let new_generation = manager
            .set_web_app_route(&config.id, ComponentRoute::Block)
            .unwrap();
        assert!(new_generation > old_generation);
        assert_eq!(
            manager.authorize(&lease, ComponentOperation::Navigation),
            Err(ComponentError::Blocked)
        );
    }

    #[test]
    fn proxy_credentials_are_random_redacted_and_revoked_with_the_lease() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let config = web_app(ComponentRoute::Direct);
        manager.register_web_app(config.clone()).unwrap();
        let lease = manager
            .acquire(&config.id, LeasePurpose::WebNavigation)
            .unwrap();
        let id = lease.id();
        let credential = lease.credential();
        assert!(!format!("{credential:?}").contains(&hex(credential.as_bytes())));
        assert!(
            manager
                .authorize_credential(id, credential.as_bytes(), ComponentOperation::Subresource)
                .is_ok()
        );
        assert_eq!(
            manager.authorize_credential(id, &[7_u8; 31], ComponentOperation::Subresource),
            Err(ComponentError::InvalidLease)
        );
        drop(lease);
        assert_eq!(
            manager.authorize_credential(
                id,
                credential.as_bytes(),
                ComponentOperation::Subresource
            ),
            Err(ComponentError::InvalidLease)
        );
    }

    #[test]
    fn an_existing_lease_fails_closed_after_its_root_runtime_stops() {
        let available = Arc::new(AtomicBool::new(true));
        let manager = ComponentManager::new(Arc::new(ToggleProvider(available.clone())));
        let config = web_app(ComponentRoute::Vpn);
        manager.register_web_app(config.clone()).unwrap();
        let lease = manager
            .acquire(&config.id, LeasePurpose::WebNavigation)
            .unwrap();
        assert!(
            manager
                .authorize(&lease, ComponentOperation::Navigation)
                .is_ok()
        );

        available.store(false, Ordering::Release);

        assert_eq!(
            manager.authorize(&lease, ComponentOperation::Navigation),
            Err(ComponentError::RuntimeUnavailable)
        );
        assert!(matches!(
            manager.acquire(&config.id, LeasePurpose::WebNavigation),
            Err(ComponentError::RuntimeUnavailable)
        ));
    }

    fn file_share() -> FileShareConfig {
        FileShareConfig {
            id: ComponentId::new("share:vault").unwrap(),
        }
    }

    #[test]
    fn a_registered_file_share_publishes_and_downloads_over_tor() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let config = file_share();
        manager.register_file_share(config.clone()).unwrap();
        let lease = manager
            .acquire(&config.id, LeasePurpose::FileSharing)
            .unwrap();

        for operation in [
            ComponentOperation::FileSharePublish,
            ComponentOperation::FileShareDownload,
        ] {
            let decision = manager.authorize(&lease, operation).unwrap();
            assert_eq!(decision.route, ComponentRoute::Tor);
            assert_eq!(decision.operation, operation);
        }
    }

    #[test]
    fn a_lease_never_resolves_across_the_two_registries() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let web = web_app(ComponentRoute::Vpn);
        let share = file_share();
        manager.register_web_app(web.clone()).unwrap();
        manager.register_file_share(share.clone()).unwrap();

        // A web identity has no share registry entry, and vice versa: the
        // purpose decides which map is consulted, so neither can borrow the
        // other's route.
        assert!(matches!(
            manager.acquire(&web.id, LeasePurpose::FileSharing),
            Err(ComponentError::NotFound)
        ));
        assert!(matches!(
            manager.acquire(&share.id, LeasePurpose::WebNavigation),
            Err(ComponentError::NotFound)
        ));

        let lease = manager
            .acquire(&share.id, LeasePurpose::FileSharing)
            .unwrap();
        assert_eq!(
            manager.authorize(&lease, ComponentOperation::Navigation),
            Err(ComponentError::WrongPurpose)
        );
    }

    #[test]
    fn removing_a_file_share_revokes_its_lease() {
        let manager = ComponentManager::new(Arc::new(AvailableProvider));
        let config = file_share();
        manager.register_file_share(config.clone()).unwrap();
        let lease = manager
            .acquire(&config.id, LeasePurpose::FileSharing)
            .unwrap();
        let credential = lease.credential();
        let id = lease.id();

        manager.remove_file_share(&config.id).unwrap();

        assert_eq!(
            manager.authorize(&lease, ComponentOperation::FileShareDownload),
            Err(ComponentError::InvalidLease)
        );
        assert_eq!(
            manager.authorize_credential(
                id,
                credential.as_bytes(),
                ComponentOperation::FileShareDownload
            ),
            Err(ComponentError::InvalidLease)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
