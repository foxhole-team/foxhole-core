//! The flow the core was killing by itself, and the timer that was doing it.
//!
//! Found on the device, not here: a push channel through the tunnel died at
//! **sixty seconds**, every time, and `flow_idle_timeouts` was zero for every
//! one of them. The core's own TCP idle window is an hour
//! (`RuntimeConfig::tcp_idle_timeout_s`), so the core was not the one closing
//! them — the stack underneath was.
//!
//! `ipstack 1.0.0` armed a sixty-second session timer inside `poll_read` and
//! answered it with an RST. Two things made that invisible and fatal at once:
//!
//! * The stack answers TCP keepalives itself, in its session task. An empty ACK
//!   never reaches `poll_read`, so a connection whose *only* liveness is a
//!   keepalive — which is what a push channel is — resets that timer never.
//! * The RST came back through `copy_bidirectional` as
//!   `ErrorKind::TimedOut`, and `flow.rs::is_ordinary_end` counts `TimedOut` as
//!   an ordinary end. No counter, no event, no log. Earlier measurement had
//!   already shown the timer *never* fires where it is wanted; the
//!   device found the other half, that it fires where it must not.
//!
//! The fork deletes the timer — see `TcpConfig` — and this is the proof, which
//! costs the wall-clock minute it is about. There is no cheaper one: the number
//! under test was a hard-coded constant, so a shorter window cannot stand in for
//! it, and a paused clock cannot drive a socketpair. It runs in its own binary
//! so the rest of the suite overlaps it.

use std::sync::Arc;
use std::time::Duration;

use foxcore_api::RuntimeConfig;
use foxcore_tun::{FlowMetrics, FlowSnapshot};

mod tunlab;

/// Just past the sixty seconds the deleted timer used to allow, and long enough
/// that a session dying at exactly sixty is unambiguous.
const PAST_THE_OLD_TIMER: Duration = Duration::from_secs(70);
/// What a phone actually sends. Real intervals are 15 minutes on cellular and
/// 28–29 on Wi-Fi; the point of the value here is only that it is far enough
/// apart that the connection is silent for most of the run, and that no
/// keepalive lands near sixty seconds to muddy the result.
const KEEPALIVE_EVERY: Duration = Duration::from_secs(25);

/// A listener that accepts and then says nothing at all — a push channel with
/// no push in it, which is the state such a connection is in almost always.
async fn silent_listener() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("bind a silent listener");
    let port = listener.local_addr().expect("local address").port();
    let serving = tokio::spawn(async move {
        let mut accepted = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            accepted.push(stream);
        }
    });
    (port, serving)
}

/// A connection whose only liveness is an empty ACK has to outlive the minute.
#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_alive_only_on_keepalives_outlives_the_stacks_old_minute() {
    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = tunlab::Lab::start(metrics.clone(), RuntimeConfig::default());
    let (port, serving) = silent_listener().await;
    lab.open(port).await;

    // A TCP keepalive is an empty segment one byte behind the left edge of the
    // window — that is what makes the peer answer it, and what makes the stack
    // answer it *itself* rather than waking anything above.
    let mut closed_after = None;
    let started = tokio::time::Instant::now();
    let mut next_keepalive = started + KEEPALIVE_EVERY;
    while started.elapsed() < PAST_THE_OLD_TIMER {
        let until = next_keepalive.min(started + PAST_THE_OLD_TIMER);
        if let Some(seen) = lab.next_segment(until).await
            && seen.flags & (tunlab::FLAG_FIN | tunlab::FLAG_RST) != 0
        {
            closed_after = Some(started.elapsed());
            break;
        }
        if tokio::time::Instant::now() >= next_keepalive {
            lab.keepalive().await;
            next_keepalive += KEEPALIVE_EVERY;
        }
    }

    let snapshot: FlowSnapshot = metrics.snapshot();
    lab.stop().await;
    serving.abort();

    assert!(
        closed_after.is_none(),
        "the core closed a live push channel after {:?}. That is the stack's own \
         session timer, which the fork deletes: the application's keepalives are \
         answered by the stack and never reach `poll_read`, so the timer it arms \
         there measures nothing about whether the connection is alive",
        closed_after.unwrap_or_default()
    );
    assert_eq!(
        snapshot.flow_idle_timeouts, 0,
        "and nothing may have been reclaimed as idle either — the core's own \
         window is an hour"
    );
    assert_eq!(
        snapshot.active_flows, 1,
        "the flow has to still be there, not merely un-mourned"
    );
}
