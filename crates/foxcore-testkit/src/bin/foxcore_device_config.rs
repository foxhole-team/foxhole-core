#![forbid(unsafe_code)]

//! Turn one subscription profile into an `EngineConfig` a device harness can run.
//!
//! Reads a link/subscription body on stdin, writes one config document on
//! stdout. The document contains credentials, so the caller is responsible for
//! where it lands — this binary never touches the filesystem and never logs the
//! config. Progress goes to stderr and names protocols only.
//!
//! Two things it does that a hand-written config forgets:
//!
//! * fills `server_ip` when the endpoint is a domain, by resolving it *before*
//!   the tun exists. A domain endpoint without `server_ip` makes the core's
//!   bootstrap DNS query travel through the tun it is trying to bring up, and
//!   the start fails ten seconds later with nothing pointing at the cause;
//! * round-trips the result through `EngineConfig`, so a document that the core
//!   would refuse fails here rather than on a phone.

use std::env;
use std::io::{self, Read};
use std::net::ToSocketAddrs;

use foxcore_api::{EngineConfig, PolicyConfig};
use foxcore_link::{ProfileScheme, import_first_profile_by_scheme};

const MAX_INPUT_BYTES: u64 = 1024 * 1024 + 1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let selector = arguments
        .next()
        .ok_or("usage: foxcore-device-config <protocol|policy [protocol]>")?;

    // The policy document carries no profile, so it reads nothing and is the one
    // output of this binary that is safe to keep around. It still has to know
    // which kind of profile it will be reloaded onto: a reload replaces the DNS
    // policy of a generation whose outbound is already fixed, and fake-IP on a
    // packet tunnel is refused there for the same reason it is refused at start.
    if selector == "policy" {
        let profile = arguments.next().unwrap_or_else(|| "proxy".into());
        println!(
            "{}",
            serde_json::to_string_pretty(&policy_document(&profile)?)?
        );
        return Ok(());
    }

    let mut body = String::new();
    io::stdin()
        .take(MAX_INPUT_BYTES)
        .read_to_string(&mut body)?;

    let scheme = scheme_for(&selector)?;
    let profile = import_first_profile_by_scheme(&body, scheme)
        .map_err(|error| format!("import failed for {selector}: {error}"))?;

    let mut outbound = serde_json::to_value(&profile.outbound)?;
    let resolved = fill_server_ip(&mut outbound)?;
    eprintln!("device_config protocol={selector} server_ip_resolved={resolved}");

    let document = engine_document(&selector, outbound)?;
    let rendered = serde_json::to_string_pretty(&document)?;
    // Refuse here rather than on the phone: `deny_unknown_fields` and the
    // cross-field rules mean a config can be well-formed JSON and still be
    // rejected at start, which on a device looks like a broken core.
    //
    // Through `parse`, not `from_value`: deserialization checks the shape and
    // nothing else, so every cross-field rule this comment claimed to cover was
    // in fact unchecked — including the one that catches the fake-IP WireGuard
    // document the harness previously generated.
    EngineConfig::parse(&rendered)
        .map_err(|error| format!("generated config is not a valid EngineConfig: {error}"))?;
    println!("{rendered}");
    Ok(())
}

fn scheme_for(selector: &str) -> Result<ProfileScheme, Box<dyn std::error::Error>> {
    match selector {
        "vless" => Ok(ProfileScheme::Vless),
        "vmess" => Ok(ProfileScheme::Vmess),
        "hysteria2" => Ok(ProfileScheme::Hysteria2),
        "trojan" => Ok(ProfileScheme::Trojan),
        "shadowsocks" => Ok(ProfileScheme::Shadowsocks),
        "naive" => Ok(ProfileScheme::Naive),
        "wireguard" => Ok(ProfileScheme::Wireguard),
        "socks" => Ok(ProfileScheme::Socks),
        "http" => Ok(ProfileScheme::Http),
        "anytls" => Ok(ProfileScheme::AnyTls),
        _ => Err("protocol selector is not supported".into()),
    }
}

/// Resolve the endpoint host on the host machine and pin it into the config.
fn fill_server_ip(outbound: &mut serde_json::Value) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(object) = outbound.as_object_mut() else {
        return Ok(false);
    };
    if object.contains_key("server_ip") {
        return Ok(false);
    }
    let Some(server) = object.get("server").and_then(|value| value.as_str()) else {
        return Ok(false);
    };
    if server.parse::<std::net::IpAddr>().is_ok() {
        return Ok(false);
    }
    let port = object
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(443) as u16;
    let address = (server, port)
        .to_socket_addrs()
        .map_err(|_| "endpoint host did not resolve")?
        .next()
        .ok_or("endpoint host resolved to nothing")?;
    object.insert(
        "server_ip".into(),
        serde_json::Value::String(address.ip().to_string()),
    );
    Ok(true)
}

/// Which DNS mode a profile of this kind can actually carry.
///
/// A packet tunnel has no userspace stack in its path, so nothing restores a
/// name from a synthetic address: a clearnet flow would be sealed with a
/// destination out of the fake-IP pool and sent to a peer that routes none of
/// it. The core refuses that combination at start; the harness would otherwise
/// hand the phone a document that cannot start, which reads as a broken build.
///
/// `real_ip` costs the harness nothing on an L3 profile — the blocklist still
/// intercepts, because the upstream and the advertise address are what build
/// the interceptor — and it is the mode exercised by device acceptance.
fn dns_mode(selector: &str) -> &'static str {
    if selector == "wireguard" {
        "real_ip"
    } else {
        "fake_ip"
    }
}

/// The device config around one outbound.
///
/// The DNS block is not decoration: the blocklist entries are what the harness's
/// resolve probes assert against, and `fake_ip` is required before an `.i2p`
/// route is even accepted.
fn engine_document(
    selector: &str,
    outbound: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let tun_ipv4 = env::var("FOXCORE_DEVICE_TUN_IPV4").unwrap_or_else(|_| "10.0.0.2".into());
    let mtu: u16 = env::var("FOXCORE_DEVICE_MTU")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1400);
    let resolver = env::var("FOXCORE_DEVICE_DNS").unwrap_or_else(|_| "1.1.1.1:53".into());

    let mut document = serde_json::json!({
        "schema_version": 1,
        "outbound": outbound,
        "tun": {"mtu": mtu, "ipv4": tun_ipv4},
        "dns": {
            "advertise": "1.1.1.1",
            "mode": dns_mode(selector),
            "route": "primary",
            "upstreams": [{"type": "udp", "address": resolver}],
            "blocklist": {
                "exact": ["example.net"],
                "suffixes": ["example.org"]
            }
        },
        "traffic": traffic_policy()
    });

    // The overlays are the one thing a packet-tunnel profile cannot be given:
    // they need fake-IP to keep the name inside the core, and fake-IP is what
    // this profile cannot carry. Saying so here beats emitting a document the
    // core refuses and letting the scenario blame the phone.
    if dns_mode(selector) != "fake_ip"
        && (env::var_os("FOXCORE_DEVICE_I2P").is_some()
            || env::var_os("FOXCORE_DEVICE_TOR_DIR").is_some())
    {
        return Err(format!(
            "{selector} is an L3 packet tunnel, and .onion/.i2p routing needs \
             dns.mode='fake_ip' that it cannot carry: run the overlay scenario on a \
             proxy profile"
        )
        .into());
    }

    // The I2P adapter is a named outbound plus an `.i2p` route; the core checks
    // that the endpoint is loopback and the DNS mode is fake-IP, so both have to
    // be right here or the config is refused rather than silently downgraded.
    let mut outbounds = Vec::new();
    let mut routes = Vec::new();
    if env::var_os("FOXCORE_DEVICE_I2P").is_some() {
        let socks =
            env::var("FOXCORE_DEVICE_I2P_SOCKS").unwrap_or_else(|_| "127.0.0.1:4447".into());
        outbounds.push(serde_json::json!({
            "id": "i2p",
            "outbound": {"type": "i2p", "socks_address": socks}
        }));
        routes.push(serde_json::json!({
            "domain_suffixes": [".i2p"], "action": {"type": "i2p"}
        }));
    }
    // Tor needs writable state and cache directories; the app's own files dir is
    // the only place on Android that is reliably both.
    if let Ok(dir) = env::var("FOXCORE_DEVICE_TOR_DIR") {
        outbounds.push(serde_json::json!({
            "id": "tor",
            "outbound": {
                "type": "tor",
                "state_dir": format!("{dir}/state"),
                "cache_dir": format!("{dir}/cache"),
                "bootstrap_timeout_s": 180
            }
        }));
        routes.push(serde_json::json!({
            "domain_suffixes": [".onion"], "action": {"type": "tor"}
        }));
    }
    if !outbounds.is_empty() {
        document["outbounds"] = serde_json::Value::Array(outbounds);
        document["routes"] = serde_json::Value::Array(routes);
    }
    Ok(document)
}

fn traffic_policy() -> serde_json::Value {
    let mut policy = serde_json::Map::new();
    policy.insert("default_action".into(), serde_json::json!("vpn"));
    if let Some(value) = flag("FOXCORE_DEVICE_TOR_ENABLED") {
        policy.insert("tor_enabled".into(), serde_json::json!(value));
    }
    if let Some(value) = flag("FOXCORE_DEVICE_I2P_ENABLED") {
        policy.insert("i2p_enabled".into(), serde_json::json!(value));
    }
    if let Some(true) = flag("FOXCORE_DEVICE_KILL_SWITCH") {
        policy.insert("kill_switch".into(), serde_json::json!(true));
    }
    // Turning a continuity flag off never selects a weaker route: it stops the
    // core where it would have healed itself and holds the lane blocked until
    // the app answers. That is the half worth testing, so it needs to be
    // settable from the harness.
    let mut continuity = serde_json::Map::new();
    for (variable, field) in [
        ("FOXCORE_DEVICE_SEAMLESS_RECONNECT", "seamless_reconnect"),
        ("FOXCORE_DEVICE_SEAMLESS_FAILOVER", "seamless_failover"),
        (
            "FOXCORE_DEVICE_SEAMLESS_NETWORK_SWITCH",
            "seamless_network_switch",
        ),
        (
            "FOXCORE_DEVICE_SPLIT_TUNNEL_ON_VPN_FAILURE",
            "split_tunnel_on_vpn_failure",
        ),
    ] {
        if let Some(value) = flag(variable) {
            continuity.insert(field.into(), serde_json::json!(value));
        }
    }
    if let Ok(timeout) = env::var("FOXCORE_DEVICE_CONFIRMATION_TIMEOUT_MS")
        && let Ok(timeout) = timeout.parse::<u64>()
    {
        continuity.insert("confirmation_timeout_ms".into(), serde_json::json!(timeout));
    }
    if !continuity.is_empty() {
        policy.insert("continuity".into(), serde_json::Value::Object(continuity));
    }
    serde_json::Value::Object(policy)
}

fn flag(name: &str) -> Option<bool> {
    match env::var(name).ok()?.as_str() {
        "1" | "true" | "on" => Some(true),
        "0" | "false" | "off" => Some(false),
        _ => None,
    }
}

/// A standalone `PolicyConfig` for `nativeReloadPolicy`, so the Tor/I2P gates
/// and the kill switch can be flipped without rebuilding the tun.
///
/// The DNS block is repeated rather than omitted because a reload *replaces* the
/// policy wholesale instead of merging it: a policy that leaves DNS out does not
/// keep the previous resolver, it drops it.
fn policy_document(profile: &str) -> Result<PolicyConfig, Box<dyn std::error::Error>> {
    let resolver = env::var("FOXCORE_DEVICE_DNS").unwrap_or_else(|_| "1.1.1.1:53".into());
    let mut document = serde_json::json!({
        "dns": {
            "advertise": "1.1.1.1",
            "mode": dns_mode(profile),
            "route": "primary",
            "upstreams": [{"type": "udp", "address": resolver}],
            "blocklist": {"exact": ["example.net"], "suffixes": ["example.org"]}
        },
        "traffic": traffic_policy()
    });
    if env::var_os("FOXCORE_DEVICE_I2P").is_some() {
        document["routes"] = serde_json::json!([
            {"domain_suffixes": [".i2p"], "action": {"type": "i2p"}}
        ]);
    }
    Ok(serde_json::from_value(document)?)
}
