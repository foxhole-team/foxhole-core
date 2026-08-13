//! D14: the DNS filter must not depend on which transport asked the name.
//!
//! It did. The interceptor is entered on `destination.port == 53`, which is a
//! statement about a transport rather than about a question, and Android's
//! opportunistic Private DNS — the *default*, shown as "Automatic" — probes DoT
//! on 853 against the resolver addresses the link advertises. Through a VPN
//! that is `dns.advertise`, ours. On a Pixel 7 Pro the probe succeeded, every
//! query afterwards went to 853, and the blocklist, the rule sets, the overlay
//! gates and fake-IP saw nothing. One variable was changed to prove it:
//!
//! ```text
//! private_dns_mode=opportunistic   RESOLVED, dns_blocked=0, 1652/408 ms
//! private_dns_mode=off             UnknownHostException, dns_blocked=2, 11/8 ms
//! ```
//!
//! Device acceptance reproduced it. Not a leak — those queries went inside the tunnel — which
//! is why nothing about it had a symptom.
//!
//! Asserted through the serialized forms rather than through the Rust enums.
//! That is deliberate twice over: the JSON is what `nativeDrainEvents` and
//! `nativeStats` actually hand the application, and a test written against the
//! variants would stop *compiling* on the build before the fix instead of
//! failing on it.

mod tunlab;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxcore_api::{CoreEvent, DnsBlocklistConfig, DnsConfig, EventSink, RuntimeConfig};
use foxcore_tun::FlowMetrics;
use tunlab::Lab;

/// The address the profile hands `VpnService.Builder`. Everything about this
/// refusal is keyed on it: it is the one address in the document that reaches
/// the platform.
const ADVERTISED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 53);
/// Somebody else's resolver, on the same port. Ordinary traffic.
const FOREIGN: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
const DOT_PORT: u16 = 853;

/// The device's own configuration shape: `real_ip`, a blocklist, and an
/// advertised address — the one `d7191ec` now requires, and the one that made
/// D14 reachable.
fn filtering_dns() -> DnsConfig {
    DnsConfig {
        advertise: Some(ADVERTISED.to_string()),
        blocklist: DnsBlocklistConfig {
            suffixes: vec!["ads.example".to_owned()],
            ..DnsBlocklistConfig::default()
        },
        ..DnsConfig::default()
    }
}

fn recording() -> (EventSink, Arc<Mutex<Vec<CoreEvent>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let sink = EventSink::new(move |event| {
        recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event);
    });
    (sink, seen)
}

fn reasons(seen: &Arc<Mutex<Vec<CoreEvent>>>) -> Vec<String> {
    seen.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter_map(|event| {
            let value = serde_json::to_value(event).ok()?;
            Some(value.get("reason")?.as_str()?.to_owned())
        })
        .collect()
}

fn counter(metrics: &FlowMetrics, field: &str) -> u64 {
    serde_json::to_value(metrics.snapshot())
        .ok()
        .and_then(|value| value.get(field).and_then(serde_json::Value::as_u64))
        .unwrap_or_default()
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dot_probe_at_our_own_resolver_is_refused_in_band_and_named() {
    let metrics = Arc::new(FlowMetrics::default());
    let (sink, seen) = recording();
    let mut lab = Lab::start_with(tunlab::engine_with_dns(
        metrics.clone(),
        RuntimeConfig::default(),
        filtering_dns(),
        EventSink::none(),
        sink,
    ));

    lab.open_to(ADVERTISED, DOT_PORT).await;

    // In band and at once. The stack has already answered the SYN by the time
    // the engine decides, so what the prober gets is a close on the connection
    // it was about to speak TLS on — and that is the whole difference between
    // this and dropping the packet: Android bounds the DoT connect at
    // `kDotConnectTimeoutMs`, 127 seconds by default, so a black hole costs the
    // device that long before it falls back, while a close costs a round trip.
    assert!(
        lab.closed_within(Duration::from_secs(5)).await,
        "the probe has to be refused on the connection, not left to time out: a \
         silent drop is 127 seconds of no DNS at all before Android gives up on \
         DoT and asks again in the clear"
    );

    assert_eq!(
        reasons(&seen),
        vec!["dns_encrypted_bypass".to_owned()],
        "a refusal the application cannot name is a refusal it will report as a \
         network fault; this is the one flow in the core whose absence had no \
         symptom at all, so it does not get to be a silent drop"
    );
    assert_eq!(
        counter(&metrics, "dns_encrypted_bypass"),
        1,
        "and it needs a counter of its own: folding it into `dns_blocked` would \
         put 'names blocked' on a screen for a device that blocked no name — \
         nothing was withheld here, a transport was"
    );
    assert_eq!(
        counter(&metrics, "dns_blocked"),
        0,
        "no name was refused: the query has not even been asked yet"
    );
    assert_eq!(
        counter(&metrics, "dial_errors"),
        0,
        "and this is a decision, not a network failure — counting it as one is \
         the mistake D7 was"
    );

    lab.stop().await;
}

/// The other half of the rule, and the reason it is written against the
/// advertised address rather than against the port: DoT to somebody else's
/// resolver is ordinary traffic and stays ordinary. A gate on 853 alone would
/// break every application that speaks encrypted DNS for itself, which is the
/// opposite of what this profile is for.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dot_to_a_resolver_we_never_advertised_is_ordinary_traffic() {
    let metrics = Arc::new(FlowMetrics::default());
    let (sink, seen) = recording();
    let mut lab = Lab::start_with(tunlab::engine_with_dns(
        metrics.clone(),
        RuntimeConfig::default(),
        filtering_dns(),
        EventSink::none(),
        sink,
    ));

    lab.open_to(FOREIGN, DOT_PORT).await;
    // Long enough for the refusal above to have happened twice over. What this
    // flow does next is the dialer's business and the network's; what it must
    // not be is refused.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        reasons(&seen).is_empty(),
        "9.9.9.9:853 is not this core's resolver and nothing about it bypasses \
         anything: {:?}",
        reasons(&seen)
    );
    assert_eq!(
        counter(&metrics, "dns_encrypted_bypass"),
        0,
        "the rule is about the address we advertised, not about the port"
    );

    lab.stop().await;
}

/// And the same address on the same port, in a profile that advertised nothing.
///
/// A document without `dns.advertise` never told the platform where to resolve,
/// so there is no address here that can be *ours* — the refusal has nothing to
/// key on and must not fire. This is what keeps the gate from becoming a
/// hard-coded block on port 853.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_advertised_resolver_nothing_on_853_is_ours_to_refuse() {
    let metrics = Arc::new(FlowMetrics::default());
    let (sink, seen) = recording();
    let mut lab = Lab::start_with(tunlab::engine_with_dns(
        metrics.clone(),
        RuntimeConfig::default(),
        DnsConfig::default(),
        EventSink::none(),
        sink,
    ));

    lab.open_to(ADVERTISED, DOT_PORT).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        reasons(&seen).is_empty(),
        "nothing was advertised, so nothing on 853 is this resolver: {:?}",
        reasons(&seen)
    );
    assert_eq!(counter(&metrics, "dns_encrypted_bypass"), 0);

    lab.stop().await;
}
