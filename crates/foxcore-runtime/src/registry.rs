use super::*;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use foxcore_api::{CoreEvent, EventSink, NamedOutboundConfig, OutboundConfig, OutboundId};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::{InterruptionSink, Outbound, OutboundRegistry};

/// The addresses the platform put on the tun.
///
/// The packet tunnel pairs each with the address its peer assigned, so a packet
/// leaves carrying the peer's address instead of the tun's. Validation has
/// already accepted these, so an unparsable one here is not a case to invent
/// behaviour for — it is simply not offered to the translator.
#[cfg(feature = "wireguard")]
pub(crate) fn tun_addresses(tun: &foxcore_api::TunConfig) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut addresses = Vec::new();
    if let Ok(address) = tun.ipv4.parse::<Ipv4Addr>() {
        addresses.push(IpAddr::V4(address));
    }
    if let Some(Ok(address)) = tun.ipv6.as_ref().map(|value| value.parse::<Ipv6Addr>()) {
        addresses.push(IpAddr::V6(address));
    }
    addresses
}

/// Build the outbound set for one generation.
///
/// Returns the packet tunnel separately when the primary profile is an L3 one:
/// a tunnel has no stream semantics, so it cannot live in the registry beside
/// the proxies. The registry still needs *a* default — routing, DNS and the
/// flow engine all assume one exists — so it gets a `direct` placeholder that
/// `FlowEngine::select_outbound` refuses to hand out while `packet_tunnel` is
/// set. Without that refusal the placeholder would be a clearnet leak.
///
/// **One outbound that fails to build does not fail the start.** The builds run
/// in parallel and their results used to be collected with `?`, so the slowest,
/// least reliable member of the profile decided whether the engine came up at
/// all: a Tor bootstrap that timed out on a censored network, or failed on a
/// state directory the app had mispermissioned, took the VPN, I2P and direct
/// lanes down with it and reported a failed start. Three device runs in this
/// pass were spent on exactly that.
///
/// A failed build now becomes a [`foxcore_outbound::DeferredOutbound`] under
/// the same id: the engine starts, every other lane carries traffic, and flows
/// routed to this one are refused with `BlockReason::LaneUnavailable` — never
/// answered by another lane. It can be filled in later by
/// [`CoreRuntime::retry_unavailable_outbounds`] without restarting anything.
///
/// The primary is not special here. If it cannot be built the engine still
/// comes up, because the alternative is worse than a blocked lane: a failed
/// start closes the tun, Android takes the interface down behind it, and the
/// device is on the open network — the same fail-closed trade exercised by the
/// confirmation-deadline tests. A profile whose primary is down blocks its VPN
/// apps and keeps its `direct`, Tor and I2P apps working.
#[cfg(feature = "wireguard")]
type PacketTunnel = foxcore_outbound::PacketTunnelOutbound;
#[cfg(not(feature = "wireguard"))]
type PacketTunnel = std::convert::Infallible;

pub(crate) async fn create_outbound_registry(
    default_config: OutboundConfig,
    named_configs: Vec<NamedOutboundConfig>,
    dialer: ProtectedDialer,
    handshake_timeout_ms: u64,
    events: &EventSink,
    interruption: &InterruptionSink,
    #[allow(unused_variables)] tun: &foxcore_api::TunConfig,
) -> io::Result<(OutboundRegistry, Option<PacketTunnel>)> {
    let is_packet_tunnel = default_config.is_packet_tunnel();
    let mut tasks = tokio::task::JoinSet::new();
    let default_dialer = dialer.clone();
    // Held back when the primary is a packet tunnel: it is built after the
    // proxies, by a path that produces an `OutboundMode` instead of an
    // `Outbound`.
    let packet_tunnel_config = if is_packet_tunnel {
        Some(default_config)
    } else {
        let interruption = interruption.clone();
        tasks.spawn(async move {
            let result = create_outbound(
                default_config.clone(),
                default_dialer,
                handshake_timeout_ms,
                Some(interruption),
            )
            .await;
            ("default".to_owned(), true, default_config, result)
        });
        None
    };
    for NamedOutboundConfig {
        id: OutboundId(id),
        outbound,
    } in named_configs
    {
        let dialer = dialer.clone();
        let interruption = interruption.clone();
        tasks.spawn(async move {
            let result = create_outbound(
                outbound.clone(),
                dialer,
                handshake_timeout_ms,
                Some(interruption),
            )
            .await;
            (id, false, outbound, result)
        });
    }

    let mut default = None;
    let mut named = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        // A `JoinError` is a panic in our own build task, not a network
        // failure, and it takes the id and the profile down with it — there is
        // nothing left to file an unavailable entry under. Still fatal.
        let (id, is_default, config, result) =
            joined.map_err(|error| io::Error::other(format!("outbound task failed: {error}")))?;
        let outbound = Arc::new(match result {
            Ok(outbound) => outbound,
            Err(error) => Outbound::Deferred(unavailable_outbound(&id, config, &error, events)),
        });
        if is_default {
            default = Some(outbound);
        } else {
            named.insert(id, outbound);
        }
    }

    if let Some(config) = packet_tunnel_config {
        #[cfg(feature = "wireguard")]
        {
            let _ = tun;
            let mode =
                foxcore_outbound::OutboundMode::from_config(config.clone(), dialer.clone()).await;
            let tunnel = match mode {
                Ok(foxcore_outbound::OutboundMode::PacketTunnel(tunnel)) => tunnel,
                // Unreachable by construction, and an invariant violation
                // rather than a build failure: a profile that took this arm
                // would mean `is_packet_tunnel` and `from_config` disagree.
                Ok(foxcore_outbound::OutboundMode::Proxy(_)) => {
                    return Err(io::Error::other(
                        "a WireGuard profile must build a packet tunnel, never a proxy",
                    ));
                }
                Err(error) => {
                    // The stand-in is an unavailable entry, *not* the `direct`
                    // placeholder: with no tunnel there is no `packet_tunnel`
                    // flag to make the flow engine refuse the placeholder, and
                    // a direct default would put every VPN app's traffic on the
                    // open network. Everything else — the stack, DNS, Tor, I2P
                    // and per-app `direct` rules — runs.
                    let deferred = unavailable_outbound("default", config, &error, events);
                    let placeholder = Arc::new(Outbound::Deferred(deferred));
                    let registry = OutboundRegistry::new(placeholder, named)?;
                    registry.set_interruption_sink(interruption.clone());
                    return Ok((registry, None));
                }
            };
            let placeholder = Arc::new(Outbound::direct(dialer));
            // Marked, not merely built: this entry dials on a protected socket
            // outside the tunnel, and everything that can reach `default` — the
            // flow engine, the DNS interceptor, the LAN and control proxies —
            // has to refuse it rather than each deciding for itself.
            let registry = OutboundRegistry::new(placeholder, named)?.with_packet_tunnel_primary();
            registry.set_interruption_sink(interruption.clone());
            return Ok((registry, Some(tunnel)));
        }
        #[cfg(not(feature = "wireguard"))]
        {
            let _ = config;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard support is not compiled into this FoxCore build",
            ));
        }
    }

    let registry = OutboundRegistry::new(
        default.ok_or_else(|| io::Error::other("default outbound task did not complete"))?,
        named,
    )?;
    registry.set_interruption_sink(interruption.clone());
    Ok((registry, None))
}

/// File a build failure as a registry entry and say so.
///
/// The event is published here, at start, rather than left for the first
/// refused flow to imply. A lane that is down and quiet is the failure mode
/// this core has already paid for three times.
fn unavailable_outbound(
    id: &str,
    config: OutboundConfig,
    error: &io::Error,
    events: &EventSink,
) -> foxcore_outbound::DeferredOutbound {
    let kind = foxcore_outbound::OutboundKind::of(&config);
    let error = io::Error::new(error.kind(), format!("outbound '{id}' failed: {error}"));
    let deferred = foxcore_outbound::DeferredOutbound::new(id, kind, config, &error);
    events.emit_with(|| CoreEvent::OutboundUnavailable {
        id: id.to_owned(),
        kind: kind.name().to_owned(),
        reason: deferred.reason(),
        message: error.to_string(),
        attempts: deferred.attempts(),
    });
    deferred
}

/// Try again to build the outbounds that were not there at start.
///
/// Returns the ids that came up. Everything about this path is off the flow
/// path on purpose: a flow routed to a lane that is down is refused
/// immediately, and never waits for — or starts — a build. There is no timer
/// and no background loop either. Attempts happen when the app reports
/// something that could plausibly have changed the answer: a network change, a
/// policy reload, or an explicit call.
///
/// One attempt per entry at a time, latched inside the entry itself, so a phone
/// flipping between Wi-Fi and mobile a dozen times cannot stack a dozen Tor
/// bootstraps. Entries whose failure cannot be fixed by retrying — a malformed
/// key, a protocol this build does not carry — are skipped rather than
/// hammered.
pub(crate) async fn retry_deferred_outbounds(
    outbounds: Arc<OutboundRegistry>,
    dialer: ProtectedDialer,
    handshake_timeout_ms: u64,
    events: EventSink,
) -> Vec<String> {
    let mut attempts = tokio::task::JoinSet::new();
    for deferred in outbounds.deferred() {
        if !deferred.is_retryable() || !deferred.begin_attempt() {
            continue;
        }
        let dialer = dialer.clone();
        let events = events.clone();
        attempts.spawn(async move {
            let config = deferred.config();
            let kind = deferred.kind();
            match create_outbound(
                config,
                dialer,
                handshake_timeout_ms,
                deferred.interruption_sink(),
            )
            .await
            {
                Ok(outbound) => {
                    let attempts = deferred.resolve(outbound);
                    events.emit_with(|| CoreEvent::OutboundRestored {
                        id: deferred.id().to_owned(),
                        kind: kind.name().to_owned(),
                        attempts,
                    });
                    Some(deferred.id().to_owned())
                }
                Err(error) => {
                    let (reason, changed) = deferred.record_failure(&error);
                    // Only a *different* class is news. A bootstrap that times
                    // out on every network change for an hour is one piece of
                    // news, and the queue it would otherwise fill is shared
                    // with the events that are.
                    if changed {
                        events.emit_with(|| CoreEvent::OutboundUnavailable {
                            id: deferred.id().to_owned(),
                            kind: kind.name().to_owned(),
                            reason,
                            message: error.to_string(),
                            attempts: deferred.attempts(),
                        });
                    }
                    None
                }
            }
        });
    }
    let mut restored = Vec::new();
    while let Some(joined) = attempts.join_next().await {
        // A panicked attempt leaves its entry latched and unavailable, which is
        // the safe direction: the lane keeps refusing rather than being retried
        // by whatever state the panic left behind.
        if let Ok(Some(id)) = joined {
            restored.push(id);
        }
    }
    restored.sort_unstable();
    restored
}
