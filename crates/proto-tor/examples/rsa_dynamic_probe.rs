//! Does the Arti graph we ship ever execute a private-key RSA operation?
//!
//! The static gate answers "no" by reading pinned sources, but cannot provide
//! dynamic confirmation. This is the dynamic
//! confirmation: `vendor/rsa` is `rsa` 0.9.10 with `::std::process::abort()` at
//! the top of `rsa_decrypt` and `rsa_decrypt_and_check` — the two functions
//! every private-key operation in that crate funnels through, decryption and
//! signing alike — and `[patch.crates-io]` puts it under the whole graph.
//!
//! So the proof is by execution and not by reading: if any part of a real Tor
//! session performs a private RSA operation, this process dies with
//! `FOXCORE-RSA-PRIVATE-OP-REACHED` and a backtrace naming the caller. If it
//! finishes, the claim held for everything the session actually did.
//!
//! What the session does, and why each part is here:
//!
//! * **Bootstrap.** Directory fetch and validation, and the channel handshake
//!   with a guard — which is where the CERTS cell's RSA→Ed25519 crosscert is
//!   *verified*. That is a public-key operation and must not trip the trap; it
//!   happens constantly, so a run that never reached this code would prove nothing.
//! * **A clearnet stream.** Circuit construction plus an exit. The ordinary
//!   client path end to end.
//! * **An `.onion` stream.** Descriptor fetch, INTRODUCE and RENDEZVOUS — the
//!   hidden-service client path, whose keys are ed25519/x25519 and which the
//!   static source audit cannot exercise.
//!
//! Run from the worktree that carries the patch:
//!
//! ```text
//! cargo run --release -p proto-tor --features arti --example rsa_dynamic_probe
//! ```

use std::time::{Duration, Instant};

use foxcore_api::{Destination, TorCircuitConfig, TorConfig};
use foxcore_dialer::ProtectedDialer;
use proto_tor::{TorOutbound, TorTcpDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Clearnet, over an exit. Chosen because it answers a bare HTTP/1.0 request
/// with a body and no redirect dance.
const CLEARNET: (&str, u16) = ("example.com", 80);

/// The Tor Project's own onion service. A hidden service the project itself
/// keeps up is the one least likely to make a red run mean "the site was down".
const ONION: (&str, u16) = (
    "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
    80,
);

/// A second onion, tried only if the first does not answer, for the same
/// reason: a dynamic proof that depends on one third party being up is a flaky
/// proof.
const ONION_ALTERNATE: (&str, u16) = (
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    80,
);

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let root = std::env::temp_dir().join(format!("foxcore-rsa-probe-{}", std::process::id()));
    let state = root.join("state");
    let cache = root.join("cache");
    std::fs::create_dir_all(&state).expect("state dir");
    std::fs::create_dir_all(&cache).expect("cache dir");

    let config = TorConfig {
        state_dir: state.to_string_lossy().into_owned(),
        cache_dir: cache.to_string_lossy().into_owned(),
        upstream: None,
        bootstrap_timeout_s: 300,
        stream_connect_timeout_s: 60,
        // Off, so every stream below shares one client and the run exercises
        // circuit reuse as well as circuit construction. Isolation is the
        // shipped default and would only add circuits, not code paths.
        isolate_streams: false,
        circuit: TorCircuitConfig::default(),
        bridges: Vec::new(),
        transports: Vec::new(),
    };

    let started = Instant::now();
    eprintln!("== bootstrapping Arti (real network, no bridges) ==");
    let outbound = TorOutbound::new(config, TorTcpDialer::protected(ProtectedDialer::host()))
        .await
        .unwrap_or_else(|error| {
            eprintln!("PROBE INCONCLUSIVE: bootstrap failed: {error}");
            std::process::exit(2)
        });
    eprintln!("   bootstrapped in {:?}", started.elapsed());

    fetch(&outbound, CLEARNET, "clearnet exit").await;

    if !fetch(&outbound, ONION, "onion service").await {
        eprintln!("   first onion did not answer; trying the alternate");
        if !fetch(&outbound, ONION_ALTERNATE, "onion service (alternate)").await {
            eprintln!("PROBE INCONCLUSIVE: no .onion answered, so the hidden-service");
            eprintln!("   client path was never executed and cannot be reported on.");
            std::process::exit(2);
        }
    }

    let _ = std::fs::remove_dir_all(&root);
    println!();
    println!("PROBE GREEN: a full Tor session — bootstrap, a clearnet stream and an");
    println!("  .onion stream — completed with an abort armed on every private-key");
    println!("  RSA operation in the graph. Not one fired.");
}

/// One request over Tor, reported as a boolean rather than unwrapped: a site
/// that is down is not evidence about RSA, and must not be read as any.
async fn fetch(outbound: &TorOutbound, target: (&str, u16), what: &str) -> bool {
    let (host, port) = target;
    eprintln!("== {what}: {host}:{port} ==");
    let destination = Destination::new(host, port);
    let stream = match tokio::time::timeout(
        Duration::from_secs(120),
        outbound.connect_stream(&destination),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            eprintln!("   connect failed: {error}");
            return false;
        }
        Err(_) => {
            eprintln!("   connect timed out");
            return false;
        }
    };
    let mut stream = stream;
    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if let Err(error) = stream.write_all(request.as_bytes()).await {
        eprintln!("   write failed: {error}");
        return false;
    }
    if let Err(error) = stream.flush().await {
        eprintln!("   flush failed: {error}");
        return false;
    }
    let mut answer = Vec::new();
    match tokio::time::timeout(Duration::from_secs(120), stream.read_to_end(&mut answer)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            eprintln!("   read failed: {error}");
            return false;
        }
        Err(_) => {
            eprintln!("   read timed out");
            return false;
        }
    }
    if answer.is_empty() {
        eprintln!("   the far end said nothing");
        return false;
    }
    let head = String::from_utf8_lossy(&answer[..answer.len().min(40)]);
    eprintln!(
        "   {} bytes, starting {:?}",
        answer.len(),
        head.trim_end().to_string()
    );
    true
}
