#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use foxcore_api::{EngineConfig, EventSink, FlowAttributor, OutboundId, RouteAction};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_tun::{FlowEngine, FlowEngineContext, FlowMetrics, FlowPolicyStore, TunDevice};
use tokio_util::sync::CancellationToken;

pub async fn run_named_tun(config: EngineConfig, tun_name: &str) -> io::Result<()> {
    if config
        .routes
        .iter()
        .any(|rule| rule.uid.is_some() || rule.package.is_some())
        || config.traffic.requires_identity()
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host testkit has no UID/package flow attributor",
        ));
    }
    // The owner is held for the whole harness run: this binary is the process,
    // so the descriptor closes when it exits, which is what a host harness
    // wants. On Android the owner lives on the worker thread instead — see
    // `TunDevice::from_owned_fd`.
    let (device, _tun_fd_owner) = TunDevice::open_named(tun_name)?;
    let dialer = ProtectedDialer::host();
    let default = Arc::new(Outbound::from_config(config.outbound, dialer.clone()).await?);
    let mut named = HashMap::with_capacity(config.outbounds.len());
    for named_config in config.outbounds {
        let id = named_config.id.0;
        let outbound = Arc::new(
            Outbound::from_config(named_config.outbound, dialer.clone())
                .await
                .map_err(|error| {
                    io::Error::new(error.kind(), format!("outbound '{id}' failed: {error}"))
                })?,
        );
        named.insert(id, outbound);
    }
    let outbounds = Arc::new(OutboundRegistry::new(default, named)?);
    let direct = Arc::new(Outbound::direct(dialer));
    let tor_enabled = config
        .traffic
        .tor_enabled
        .unwrap_or_else(|| outbounds.tor().is_some());
    let i2p_enabled = config
        .traffic
        .i2p_enabled
        .unwrap_or_else(|| outbounds.i2p().is_some());
    let routes = RouteTable::compile_with_traffic(
        config.routes,
        RouteAction::Outbound(OutboundId("default".into())),
        config.traffic,
        tor_enabled,
        i2p_enabled,
    );
    let metrics = Arc::new(FlowMetrics::default());
    let dns = config.dns;
    let policy = Arc::new(FlowPolicyStore::new(
        1,
        routes,
        dns,
        outbounds.clone(),
        direct.clone(),
        metrics.clone(),
        EventSink::none(),
    )?);
    FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy,
        attributor: FlowAttributor::none(),
        runtime: config.runtime,
        metrics,
        events: EventSink::none(),
        packet_tunnel: false,
        connections: std::sync::Arc::new(foxcore_tun::ConnectionTracker::default()),
    })
    .run(device, config.tun.mtu, CancellationToken::new())
    .await
}
