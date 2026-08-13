use super::*;

use foxcore_api::OutboundUnavailable;
use foxcore_tun::{FlowSnapshot, TrafficSnapshot};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct SelectorState<'a> {
    pub(crate) tag: &'a str,
    pub(crate) active: &'a str,
}

/// The document `nativeTrafficMap` returns. Answered in one call so its parts
/// cannot disagree with each other.
#[derive(Serialize)]
pub(crate) struct TrafficMapDocument<'a> {
    pub(crate) generation: u64,
    #[serde(flatten)]
    pub(crate) map: TrafficSnapshot,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) selectors: Vec<SelectorState<'a>>,
    pub(crate) dns: DnsVerdicts,
}

/// What the resolver decided, beside the map rather than inside it: a refused
/// *name* never becomes a flow, so it has no row to be counted on.
#[derive(Serialize)]
pub(crate) struct DnsVerdicts {
    pub(crate) queries: u64,
    pub(crate) blocked: u64,
    pub(crate) allowed: u64,
}

pub(crate) const EMPTY_TRAFFIC_MAP: &str = concat!(
    r#"{"generation":0,"connections":[],"packages":[],"lanes":[],"omitted_rows":0,"#,
    r#""dropped_events":0,"dns":{"queries":0,"blocked":0,"allowed":0}}"#
);

#[derive(Serialize)]
pub(crate) struct RuntimeSnapshot<'a> {
    pub(crate) generation: u64,
    pub(crate) policy_revision: u64,
    pub(crate) reconnects: u64,
    /// Which member each selector is on right now.
    ///
    /// Empty for a config with no selectors, so a UI can hide the row rather
    /// than draw an empty one. Without this the app shows the group name and
    /// the user cannot tell which server they are actually on — nor that
    /// urltest moved them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) selectors: Vec<SelectorState<'a>>,
    #[serde(flatten)]
    pub(crate) flow: FlowSnapshot,
    /// Outbounds in the profile that could not be built, with why and how many
    /// flows each has refused.
    ///
    /// Absent for the ordinary case. Present means the engine is running on
    /// part of the profile: everything not listed here is carrying traffic, and
    /// flows that need what is listed are refused — never re-routed. This is
    /// the field that keeps a partial start from being a silent one; before it
    /// existed, a failed Tor bootstrap and a healthy engine produced the same
    /// snapshot, and the difference only showed up as traffic that never moved.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) unavailable: Vec<OutboundUnavailable>,
    /// Present only while a lane is suspended or an answer is outstanding, so
    /// an ordinary snapshot does not carry a row that always reads "nothing is
    /// wrong".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) continuity: Option<ContinuityState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_error: Option<String>,
}

/// The document `nativeLanProxyStatus` answers with: everything the LAN screen
/// draws, in one read.
///
/// Nothing here is skipped when it is empty, unlike the snapshot above. That is
/// the whole point of the document: the app had been drawing a *saved toggle* as
/// though it were live state, and a shape that changes with the state is a shape
/// a UI can only read by guessing. Every field is present in every answer, and
/// "not applicable" is `null`.
#[derive(Serialize)]
pub(crate) struct LanProxyStatus<'a> {
    /// Snake case of [`LanProxyState`]. `stopped` when nothing was ever started.
    pub(crate) state: &'static str,
    /// `address:port` a device on this network points its client at, or `null`
    /// when that protocol was not offered. Not derivable from `local_address`:
    /// either protocol may be switched off, and the port is whatever bound.
    pub(crate) socks_address: Option<String>,
    pub(crate) http_address: Option<String>,
    pub(crate) preset: Option<&'static str>,
    pub(crate) network_handle: Option<u64>,
    pub(crate) local_address: Option<String>,
    pub(crate) interface_name: Option<&'a str>,
    pub(crate) transport: Option<&'static str>,
    /// Why the last start or stop was refused, in words. Cleared by a start that
    /// succeeds and by an explicit stop, so a reason on screen is always about
    /// the attempt the user just made.
    pub(crate) last_error: Option<String>,
}

/// The answer for "no LAN proxy has ever been started on this handle", and the
/// fallback if serialization itself ever failed.
///
/// A literal rather than a serialized default because it is also the answer for
/// a handle that does not resolve, where there is no runtime to ask. Returning
/// `null` or `{}` there would make the app's parser carry a second shape for the
/// one case it hits first — before the engine is up.
pub(crate) const LAN_PROXY_STOPPED: &str = concat!(
    r#"{"state":"stopped","socks_address":null,"http_address":null,"preset":null,"#,
    r#""network_handle":null,"local_address":null,"interface_name":null,"#,
    r#""transport":null,"last_error":null}"#
);

/// The document `nativeLoopbackInbounds` returns.
///
/// An object with one array in it rather than a bare array: a top-level array
/// has nowhere to grow a field, and this document will grow one — the first
/// thing anybody will ask for is a per-inbound session count.
#[derive(Serialize)]
pub(crate) struct LoopbackInbounds<'a> {
    pub(crate) inbounds: Vec<LoopbackInboundStatus<'a>>,
}

#[derive(Serialize)]
pub(crate) struct LoopbackInboundStatus<'a> {
    /// The name from the configuration, unchanged. This is the join key between
    /// what the app asked for and what is listening.
    pub(crate) name: &'a str,
    /// `profile`, `tor` or `direct` — what this inbound resolves to, not what
    /// it managed to reach on its last session.
    pub(crate) upstream: &'static str,
    /// Snake case of `LanProxyState`, the same vocabulary the LAN proxy uses.
    pub(crate) state: &'static str,
    /// `127.0.0.1:port`. `null` only if the listener is gone, which for a named
    /// inbound means the session is on its way out.
    pub(crate) http_address: Option<String>,
}

/// The answer for an engine handle that does not resolve, and the fallback if
/// serializing ever failed.
pub(crate) const LOOPBACK_INBOUNDS_EMPTY: &str = r#"{"inbounds":[]}"#;

/// A name from configuration, turned into the component identity that names the
/// listener in events and in the component registry.
///
/// Prefixed, and the prefix is the security property rather than tidiness: the
/// app writes these names, `ComponentId` allows `:`, and without a namespace an
/// app could ask for `runtime:control-proxy` and collide with the runtime's own
/// surface. `LoopbackInboundConfig::validate` refuses `:` in a name, so the
/// prefix cannot be forged from the other side either.
pub(crate) fn loopback_inbound_id(name: &str) -> Result<ComponentId, ComponentError> {
    ComponentId::new(format!("loopback:{name}"))
}

pub(crate) fn lan_state_name(state: LanProxyState) -> &'static str {
    match state {
        LanProxyState::Stopped => "stopped",
        LanProxyState::CheckingPermission => "checking_permission",
        LanProxyState::ResolvingNetwork => "resolving_network",
        LanProxyState::AcquiringComponents => "acquiring_components",
        LanProxyState::BindingListeners => "binding_listeners",
        LanProxyState::Ready => "ready",
        LanProxyState::Degraded => "degraded",
        LanProxyState::NetworkLost => "network_lost",
        LanProxyState::Stopping => "stopping",
        LanProxyState::Failed => "failed",
    }
}

pub(crate) fn lan_preset_name(preset: LanProxyPreset) -> &'static str {
    match preset {
        LanProxyPreset::Vpn => "vpn",
        LanProxyPreset::Tor => "tor",
        LanProxyPreset::Mixed => "mixed",
    }
}

pub(crate) fn lan_transport_name(transport: LanTransport) -> &'static str {
    match transport {
        LanTransport::Wifi => "wifi",
        LanTransport::Ethernet => "ethernet",
        LanTransport::Cellular => "cellular",
        LanTransport::Unknown => "unknown",
    }
}

#[cfg(test)]
mod lan_status_tests {
    use super::*;

    /// The literal and the struct must produce the same bytes. They are two
    /// declarations of one document — the constant is what a handle that does
    /// not resolve answers, where there is no runtime to serialize — and a
    /// field added to one and not the other is an app parsing two shapes and
    /// finding out on a device.
    #[test]
    fn the_stopped_literal_is_exactly_what_serializing_an_empty_status_produces() {
        let serialized = serde_json::to_string(&LanProxyStatus {
            state: lan_state_name(LanProxyState::Stopped),
            socks_address: None,
            http_address: None,
            preset: None,
            network_handle: None,
            local_address: None,
            interface_name: None,
            transport: None,
            last_error: None,
        })
        .unwrap();
        assert_eq!(serialized, LAN_PROXY_STOPPED);
    }

    /// Every field is present in every answer, `null` rather than absent. A
    /// shape that changes with the state is a shape a UI can only read by
    /// guessing, and guessing is what the saved-toggle bug was.
    #[test]
    fn a_running_status_carries_every_field_and_names_its_addresses() {
        let json = serde_json::to_string(&LanProxyStatus {
            state: lan_state_name(LanProxyState::Ready),
            socks_address: Some("192.168.1.20:1080".into()),
            http_address: None,
            preset: Some(lan_preset_name(LanProxyPreset::Mixed)),
            network_handle: Some(1234567890),
            local_address: Some("192.168.1.20".into()),
            interface_name: Some("wlan0"),
            transport: Some(lan_transport_name(LanTransport::Wifi)),
            last_error: Some("previous attempt: port in use".into()),
        })
        .unwrap();
        let document: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(document["state"], "ready");
        assert_eq!(document["socks_address"], "192.168.1.20:1080");
        assert!(
            document.get("http_address").is_some() && document["http_address"].is_null(),
            "a protocol that was not offered is null, never missing"
        );
        assert_eq!(document["preset"], "mixed");
        assert_eq!(document["network_handle"], 1234567890_u64);
        assert_eq!(document["local_address"], "192.168.1.20");
        assert_eq!(document["interface_name"], "wlan0");
        assert_eq!(document["transport"], "wifi");
        assert_eq!(document["last_error"], "previous attempt: port in use");
        // The stopped literal and a live document must have the same keys.
        let stopped: serde_json::Value = serde_json::from_str(LAN_PROXY_STOPPED).unwrap();
        let mut live: Vec<_> = document.as_object().unwrap().keys().collect();
        let mut empty: Vec<_> = stopped.as_object().unwrap().keys().collect();
        live.sort_unstable();
        empty.sort_unstable();
        assert_eq!(live, empty);
    }

    /// Snake case of the enum, distinct, and exhaustive by construction: the
    /// match in `lan_state_name` has no wildcard arm, so a state added to the
    /// component fails to compile until it is named here.
    #[test]
    fn every_state_preset_and_transport_has_a_distinct_wire_name() {
        let states = [
            LanProxyState::Stopped,
            LanProxyState::CheckingPermission,
            LanProxyState::ResolvingNetwork,
            LanProxyState::AcquiringComponents,
            LanProxyState::BindingListeners,
            LanProxyState::Ready,
            LanProxyState::Degraded,
            LanProxyState::NetworkLost,
            LanProxyState::Stopping,
            LanProxyState::Failed,
        ];
        let mut names: Vec<_> = states.iter().copied().map(lan_state_name).collect();
        assert_eq!(names[0], "stopped");
        assert_eq!(names[7], "network_lost");
        for name in &names {
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{name} is not snake_case"
            );
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), states.len(), "two states share a name");

        assert_eq!(lan_preset_name(LanProxyPreset::Vpn), "vpn");
        assert_eq!(lan_preset_name(LanProxyPreset::Tor), "tor");
        assert_eq!(lan_preset_name(LanProxyPreset::Mixed), "mixed");
        assert_eq!(lan_transport_name(LanTransport::Wifi), "wifi");
        assert_eq!(lan_transport_name(LanTransport::Ethernet), "ethernet");
        assert_eq!(lan_transport_name(LanTransport::Cellular), "cellular");
        assert_eq!(lan_transport_name(LanTransport::Unknown), "unknown");
    }
}
