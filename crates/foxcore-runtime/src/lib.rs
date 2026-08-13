#![forbid(unsafe_code)]

mod lan;

pub mod events;
pub mod publish;

pub use events::{DEFAULT_EVENT_CAPACITY, EventDrain, EventQueue, EventRecorder};
pub use foxcore_component::{
    ComponentDecision, ComponentError, ComponentEvent, ComponentEventDrain, ComponentEventKind,
    ComponentId, ComponentLease, ComponentManager, ComponentOperation, ComponentRecorder,
    ComponentRoute, FileShareConfig, LanCredentials, LanProxyConfig, LanProxyHandle,
    LanProxyPreset, LanProxyState, LanRoute, LanTransport, LeaseCredential, LeasePurpose,
    LoopbackInbound, NetworkBinding, RuntimeKind, RuntimeLease, RuntimeLeaseProvider, WebAppConfig,
};
pub use foxcore_route::ruleset::{
    MAX_ARTIFACT_BYTES as MAX_DNS_RULE_SET_ARTIFACT_BYTES,
    MAX_MANIFEST_BYTES as MAX_DNS_RULE_SET_MANIFEST_BYTES,
    MAX_SIGNATURE_BYTES as MAX_DNS_RULE_SET_SIGNATURE_BYTES, RuleSetBundle, TrustedRuleSetBundle,
};
pub use foxcore_share::{
    CreatedShare, DownloadCapability, FileId, OwnerCapability, ShareConfig, ShareError, ShareEvent,
    ShareEventDrain, ShareEventKind, ShareId, ShareManager, ShareRecorder, SharedFile,
};
pub use foxcore_trafficmap::{
    ConnectionRow, FlowLane, FlowRoute, LaneTraffic, PackageTraffic, RevokeTarget, TrafficEvent,
    TrafficEventDrain, TrafficMap as TrafficMapHandle, TrafficSnapshot as TrafficMapSnapshot,
};
pub use publish::{OnionAddress, OnionPublisher, PublishError, PublishedShare, publish_share};

mod continuity;
mod control;
mod registry;
mod snapshot;
mod start;
mod state;
mod stop_diagnostics;
mod util;
mod worker;

#[cfg(all(test, unix, feature = "vless"))]
mod tests;

pub use continuity::*;
pub(crate) use registry::*;
pub(crate) use snapshot::*;
pub use state::*;
pub(crate) use util::*;
pub(crate) use worker::*;
