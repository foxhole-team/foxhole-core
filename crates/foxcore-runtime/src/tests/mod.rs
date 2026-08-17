use super::*;
use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use foxcore_api::{
    ContinuityInterruption, ControlProxyConfig, CoreEvent, DnsRoute, EngineConfig,
    LoopbackInboundConfig, LoopbackUpstream, MAX_LOOPBACK_INBOUNDS, NamedOutboundConfig,
    OutboundConfig, OutboundId, PolicyConfig, RouteAction, RuntimeConfig, TrafficPolicyConfig,
};
use foxcore_dialer::{ProtectedDialer, SocketCallbacks};
use foxcore_outbound::{Outbound, OutboundRegistry};

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::net::UnixStream;

use foxcore_api::{
    DnsConfig, SecretString, StreamTransportConfig, TlsConfig, TunConfig, VlessConfig,
};

fn tor_profile() -> OutboundConfig {
    OutboundConfig::Tor(foxcore_api::TorConfig {
        state_dir: "/nonexistent/state".into(),
        cache_dir: "/nonexistent/cache".into(),
        upstream: None,
        bootstrap_timeout_s: 1,
        stream_connect_timeout_s: 1,
        isolate_streams: true,
        circuit: foxcore_api::TorCircuitConfig::default(),
        bridges: Vec::new(),
        transports: Vec::new(),
    })
}

fn socks_profile() -> OutboundConfig {
    OutboundConfig::Socks(foxcore_api::SocksConfig {
        server: "127.0.0.1".into(),
        port: 1080,
        server_ip: None,
        username: None,
        password: None,
        handshake_timeout_ms: 100,
    })
}

/// A lane comes up in the registry entry routing is already holding, with
/// no new registry, no new engine and no new tun.
///
/// Driven through the same pass the runtime runs on a network change. The
/// SOCKS profile builds offline, so what is under test is the swap itself
/// rather than a proxy handshake.
#[tokio::test]
async fn a_lane_that_was_not_there_at_start_comes_up_in_place() {
    let dialer = ProtectedDialer::host();
    let deferred = foxcore_outbound::DeferredOutbound::new(
        "proxy",
        foxcore_outbound::OutboundKind::Socks,
        socks_profile(),
        &io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"),
    );
    let outbounds = Arc::new(
        OutboundRegistry::new(
            Arc::new(Outbound::direct(dialer.clone())),
            HashMap::from([(
                "proxy".to_owned(),
                Arc::new(Outbound::Deferred(deferred.clone())),
            )]),
        )
        .unwrap(),
    );
    // The handle the flow engine would be holding for the life of the
    // generation. Nothing below replaces it.
    let routing = outbounds.clone();
    assert_eq!(routing.unavailable().len(), 1);

    let events = Arc::new(EventQueue::new(DEFAULT_EVENT_CAPACITY));
    let restored = retry_deferred_outbounds(
        outbounds,
        dialer,
        100,
        OverlayGates::new(true, true),
        events.sink(),
    )
    .await;

    assert_eq!(restored, vec!["proxy".to_owned()]);
    assert!(
        deferred.is_available(),
        "the entry routing holds is the entry that came up"
    );
    assert!(
        routing.unavailable().is_empty(),
        "and the snapshot stops reporting a lane that is carrying traffic"
    );
    let drained = serde_json::to_string(&events.drain(16)).unwrap();
    assert!(drained.contains("outbound_restored"), "{drained}");
    assert!(drained.contains(r#""attempts":2"#), "{drained}");
}

/// The gate decides whether a skipped overlay is ever built, and nothing else
/// does.
///
/// Both halves matter. A gated-off lane must survive every network change
/// without a bootstrap — that is the defect — and it must still come up the
/// moment a reload turns the overlay back on, or switching Tor off once would
/// leave the lane permanently dead for the life of the generation.
#[test]
fn a_switched_off_lane_is_built_only_when_the_switch_comes_back_on() {
    let gated = foxcore_outbound::DeferredOutbound::gated_off(
        "tor",
        foxcore_outbound::OutboundKind::Tor,
        tor_profile(),
    );
    assert!(
        !OverlayGates::new(false, true).may_build(&gated),
        "a network change with Tor still off starts nothing"
    );
    assert!(
        OverlayGates::new(true, true).may_build(&gated),
        "and a reload that turns it on makes the lane buildable again"
    );

    let failed = foxcore_outbound::DeferredOutbound::new(
        "proxy",
        foxcore_outbound::OutboundKind::Socks,
        socks_profile(),
        &io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"),
    );
    assert!(
        OverlayGates::new(false, false).may_build(&failed),
        "the overlay gates say nothing about a lane that is not an overlay"
    );
}

/// A profile that cannot work is not retried, and a retry pass in flight is
/// not stacked on by the next network change.
#[tokio::test]
async fn the_retry_pass_neither_hammers_nor_loops() {
    let dialer = ProtectedDialer::host();
    let unusable = foxcore_outbound::DeferredOutbound::new(
        "proxy",
        foxcore_outbound::OutboundKind::Socks,
        socks_profile(),
        &io::Error::new(io::ErrorKind::InvalidInput, "password must not be empty"),
    );
    let outbounds = Arc::new(
        OutboundRegistry::new(
            Arc::new(Outbound::direct(dialer.clone())),
            HashMap::from([(
                "proxy".to_owned(),
                Arc::new(Outbound::Deferred(unusable.clone())),
            )]),
        )
        .unwrap(),
    );
    let events = Arc::new(EventQueue::new(DEFAULT_EVENT_CAPACITY));
    assert!(
        retry_deferred_outbounds(
            outbounds.clone(),
            dialer.clone(),
            100,
            OverlayGates::new(true, true),
            events.sink()
        )
        .await
        .is_empty()
    );
    assert_eq!(
        unusable.attempts(),
        1,
        "a malformed profile is skipped, not attempted again on every network change"
    );

    let retryable = foxcore_outbound::DeferredOutbound::new(
        "proxy",
        foxcore_outbound::OutboundKind::Socks,
        socks_profile(),
        &io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"),
    );
    assert!(retryable.begin_attempt(), "one attempt claims the entry");
    let outbounds = Arc::new(
        OutboundRegistry::new(
            Arc::new(Outbound::direct(dialer.clone())),
            HashMap::from([(
                "proxy".to_owned(),
                Arc::new(Outbound::Deferred(retryable.clone())),
            )]),
        )
        .unwrap(),
    );
    assert!(
        retry_deferred_outbounds(
            outbounds,
            dialer,
            100,
            OverlayGates::new(true, true),
            events.sink()
        )
        .await
        .is_empty(),
        "a second trigger while one attempt is in flight starts nothing"
    );
}

/// A reload containing `{"dns": {"mode": "fake_ip", "route": "primary"}}`
/// is unsafe on a generation whose primary outbound is a packet
/// tunnel that document is a black hole switch: the outbound cannot change
/// on a reload, so from the next flow onward every clearnet destination is
/// an address the resolver invented and the peer cannot route.
///
/// A typed refusal, not a downgrade to `real_ip`: the app asked for a mode,
/// and quietly running a different one is the failure this core does not
/// commit anywhere else.
/// The owner's WireGuard profile as a started generation: a real peer port
/// so the handshake this runtime sends is dropped rather than bounced, and
/// the DNS block §27.4 proved carries traffic end to end on this exact peer.
#[cfg(feature = "wireguard")]
fn packet_tunnel_engine_config(endpoint: std::net::SocketAddr) -> EngineConfig {
    EngineConfig {
        schema_version: foxcore_api::SCHEMA_VERSION,
        outbound: OutboundConfig::Wireguard(foxcore_api::WireguardConfig {
            server: endpoint.ip().to_string(),
            port: endpoint.port(),
            server_ip: Some(endpoint.ip()),
            private_key: SecretString::new("l40T7xeXzdV13X8f/1IjcRR0wbrACb0bebRqcN01mbQ="),
            peer_public_key: SecretString::new("/94rCPHnchHT/rfGYWR3oBaNKtGcelLi4ainYamMiTc="),
            preshared_key: None,
            address: vec!["10.8.0.2/32".parse().unwrap()],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            mtu: 1400,
            persistent_keepalive_s: None,
            reserved: None,
            amnezia: None,
        }),
        outbounds: Vec::new(),
        tun: TunConfig {
            mtu: 1400,
            ipv4: "10.0.0.2".into(),
            ipv6: None,
        },
        dns: DnsConfig::default(),
        runtime: RuntimeConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig::default(),
    }
}

fn vless_member(id: &str, server_ip: [u8; 4]) -> NamedOutboundConfig {
    NamedOutboundConfig {
        id: OutboundId(id.to_owned()),
        outbound: OutboundConfig::Vless(VlessConfig {
            server: format!("{id}.invalid"),
            port: 443,
            server_ip: Some(IpAddr::V4(Ipv4Addr::from(server_ip))),
            uuid: SecretString::new("d0cf0001-0000-4000-8000-000000000000"),
            flow: None,
            transport: StreamTransportConfig::Raw,
            packet_encoding: foxcore_api::PacketEncoding::None,
            tls: TlsConfig::default(),
            reality: None,
            encryption: None,
        }),
    }
}

fn vless_engine_config() -> EngineConfig {
    EngineConfig {
        schema_version: foxcore_api::SCHEMA_VERSION,
        outbound: OutboundConfig::Vless(VlessConfig {
            server: "bootstrap.invalid".into(),
            port: 443,
            server_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            uuid: SecretString::new("d0cf0001-0000-4000-8000-000000000000"),
            flow: None,
            transport: StreamTransportConfig::Raw,
            packet_encoding: foxcore_api::PacketEncoding::None,
            tls: TlsConfig::default(),
            reality: None,
            encryption: None,
        }),
        outbounds: Vec::new(),
        tun: TunConfig {
            mtu: 1400,
            ipv4: "10.77.0.1".into(),
            ipv6: None,
        },
        dns: DnsConfig::default(),
        runtime: RuntimeConfig::default(),
        routes: Vec::new(),
        traffic: TrafficPolicyConfig::default(),
    }
}

fn manual_continuity(timeout_ms: u64) -> TrafficPolicyConfig {
    TrafficPolicyConfig {
        continuity: foxcore_api::ContinuityConfig {
            seamless_reconnect: false,
            seamless_failover: false,
            seamless_network_switch: false,
            split_tunnel_on_vpn_failure: false,
            confirmation_timeout_ms: timeout_ms,
        },
        ..Default::default()
    }
}

mod lifecycle;
mod network;
mod stops;
