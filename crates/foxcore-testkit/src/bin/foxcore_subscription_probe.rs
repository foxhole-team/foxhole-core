#![forbid(unsafe_code)]

//! Subscription import probe.
//!
//! Prints protocol kinds and counters, never a line of the subscription itself:
//! a subscription line *is* a credential.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read};

use foxcore_api::OutboundConfig;
use foxcore_link::{import_subscription_partial, inspect_subscription};

const MAX_INPUT_BYTES: u64 = 1024 * 1024 + 1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = String::new();
    io::stdin()
        .take(MAX_INPUT_BYTES)
        .read_to_string(&mut body)?;
    if body.len() >= MAX_INPUT_BYTES as usize {
        return Err("subscription response exceeds 1 MiB".into());
    }

    let argument = env::args().nth(1);
    if argument.as_deref() == Some("--inspect") {
        let shapes = inspect_subscription(&body)?;
        println!(
            "subscription_shape profiles={} shapes={}",
            shapes.len(),
            shapes
                .into_iter()
                .map(|shape| shape.label())
                .collect::<Vec<_>>()
                .join(",")
        );
        return Ok(());
    }

    // The lenient import, matching what the app's JNI path calls. The strict one
    // let a single `tg://` support link reject every server in a paid
    // subscription — observed on the owner's own list, ten lines, nine servers.
    let import = match import_subscription_partial(&body) {
        Ok(import) => import,
        Err(error) => {
            if let Ok(shapes) = inspect_subscription(&body) {
                eprintln!(
                    "subscription_shape profiles={} shapes={}",
                    shapes.len(),
                    shapes
                        .into_iter()
                        .map(|shape| shape.label())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            return Err(error.into());
        }
    };
    let protocols: Vec<_> = import
        .profiles
        .iter()
        .map(|profile| protocol_name(&profile.outbound))
        .collect();

    // Dropped lines are counted and named by scheme, never quoted. Silence here
    // would read as "the provider only sent eight servers".
    let mut dropped_schemes: BTreeMap<&str, usize> = BTreeMap::new();
    for line in &import.rejected {
        *dropped_schemes
            .entry(line.scheme.as_deref().unwrap_or("unknown"))
            .or_default() += 1;
    }
    let dropped_summary = dropped_schemes
        .iter()
        .map(|(scheme, count)| format!("{scheme}x{count}"))
        .collect::<Vec<_>>()
        .join(",");

    // Reasons go to stderr, so stdout stays one machine-readable line. They are
    // safe to print — `LinkError` is written not to echo its input — and without
    // them a dropped `wireguard://` is indistinguishable from a dropped `tg://`,
    // which is the difference between an advert and a lost server.
    for line in &import.rejected {
        eprintln!(
            "subscription_dropped index={} scheme={} reason=\"{}\"",
            line.index,
            line.scheme.as_deref().unwrap_or("unknown"),
            line.reason
        );
    }

    if let Some(expected) = argument {
        let expected: Vec<_> = expected
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect();
        if protocols != expected {
            return Err(format!(
                "protocol shape changed: expected {}, received {}",
                expected.join(","),
                protocols.join(",")
            )
            .into());
        }
    }

    println!(
        "subscription_ok profiles={} protocols={} dropped={} dropped_schemes={}",
        import.profiles.len(),
        protocols.join(","),
        import.rejected.len(),
        if dropped_summary.is_empty() {
            "none"
        } else {
            &dropped_summary
        }
    );
    Ok(())
}

fn protocol_name(outbound: &OutboundConfig) -> &'static str {
    match outbound {
        OutboundConfig::Direct(_) => "direct",
        OutboundConfig::Vless(_) => "vless",
        OutboundConfig::Vmess(_) => "vmess",
        OutboundConfig::Hysteria2(_) => "hysteria2",
        OutboundConfig::Tuic(_) => "tuic",
        OutboundConfig::Trojan(_) => "trojan",
        OutboundConfig::Shadowsocks(_) => "shadowsocks",
        OutboundConfig::I2p(_) => "i2p",
        OutboundConfig::Tor(_) => "tor",
        OutboundConfig::Wireguard(_) => "wireguard",
        OutboundConfig::Selector(_) => "selector",
        OutboundConfig::Socks(_) => "socks",
        OutboundConfig::Http(_) => "http",
        OutboundConfig::Naive(_) => "naive",
        OutboundConfig::AnyTls(_) => "anytls",
        OutboundConfig::ShadowTls(_) => "shadowtls",
    }
}
