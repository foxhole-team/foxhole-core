//! TCP idle-timeout and failed-relay cleanup regressions.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxcore_api::{CoreEvent, EventSink, RuntimeConfig};
use foxcore_tun::{FlowMetrics, FlowSnapshot};

mod tunlab;

const IDLE_S: u64 = 5;

fn runtime() -> RuntimeConfig {
    RuntimeConfig {
        idle_timeout_s: IDLE_S,
        tcp_idle_timeout_s: IDLE_S,
        ..RuntimeConfig::default()
    }
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_established_flow_that_moves_nothing_is_closed_towards_the_app() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();
    // Accept the connection before measuring its idle lifetime.
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = tunlab::Lab::start(metrics.clone(), runtime());
    lab.open(port).await;

    // Allow the timeout sampler and a busy test host extra time.
    let closed = lab.closed_within(Duration::from_secs(30)).await;
    lab.stop().await;
    silent.abort();

    let snapshot: FlowSnapshot = metrics.snapshot();
    assert!(
        closed,
        "a TCP flow that has passed no bytes for its idle window must be closed \
         towards the app; without it the flow slot is held until the generation \
         ends and the application sees an established connection that never answers"
    );
    assert_eq!(
        snapshot.flow_idle_timeouts, 1,
        "and the close has to be attributable: this is the core reclaiming an \
         idle flow, not the network failing one"
    );
    assert_eq!(
        snapshot.flow_errors, 0,
        "an idle timeout is the mechanism working, not an error"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reclaiming_an_idle_flow_is_not_reported_as_a_block() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let seen: Arc<Mutex<Vec<CoreEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = seen.clone();
    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = tunlab::Lab::start_with(tunlab::engine_with_events(
        metrics.clone(),
        runtime(),
        EventSink::none(),
        EventSink::new(move |event| recorder.lock().expect("recorder").push(event)),
    ));
    lab.open(port).await;

    let closed = lab.closed_within(Duration::from_secs(30)).await;
    lab.stop().await;
    silent.abort();

    assert!(closed, "the flow has to have been reclaimed at all");
    assert_eq!(
        metrics.snapshot().flow_idle_timeouts,
        1,
        "and reclaimed by the idle clock rather than by something else"
    );
    let events = seen.lock().expect("recorder");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, CoreEvent::Blocked { .. })),
        "an idle timeout produced a Blocked event: {events:?}\n\
         Nothing was refused here. Do not add a persisted reason for this — a \
         variant added to that dictionary cannot be removed without an explicit \
         migration and rollback decision."
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_whose_only_liveness_is_an_empty_ack_outlives_the_udp_window() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();
    // Hold a quiet but live push channel.
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = tunlab::Lab::start(
        metrics.clone(),
        RuntimeConfig {
            idle_timeout_s: IDLE_S,
            ..RuntimeConfig::default()
        },
    );
    lab.open(port).await;

    // Keepalives span more than twice the UDP timeout.
    let mut closed = false;
    for _ in 0..9 {
        // The stack handles an empty ACK without waking the relay.
        lab.send(tunlab::FLAG_ACK, &[]).await;
        if lab.closed_within(Duration::from_millis(1_500)).await {
            closed = true;
            break;
        }
    }
    lab.stop().await;
    silent.abort();

    let snapshot: FlowSnapshot = metrics.snapshot();
    assert!(
        !closed,
        "a connection whose only liveness is a keepalive was closed inside the \
         UDP idle window; the TCP relay must take `tcp_idle_timeout_s`, because \
         the stack absorbs those keepalives and five minutes of \"silence\" is \
         an ordinary state for a push channel"
    );
    assert_eq!(
        snapshot.flow_idle_timeouts, 0,
        "and nothing was reclaimed: the flow is alive, it is merely quiet"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_fails_after_it_started_is_closed_towards_the_app() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();
    let rude = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept the relay's dial");
        let mut stream = stream;
        let mut byte = [0_u8; 1];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await;
        // Zero linger makes the peer close with RST.
        #[allow(deprecated)]
        let _ = stream.set_linger(Some(Duration::ZERO));
        drop(stream);
    });

    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = tunlab::Lab::start(metrics.clone(), runtime());
    lab.open(port).await;
    lab.send(tunlab::FLAG_ACK | tunlab::FLAG_PSH, b"x").await;

    // A prompt close must come from relay failure, not idle timeout.
    let closed = lab.closed_within(Duration::from_secs(3)).await;
    lab.stop().await;
    let _ = rude.await;

    let snapshot: FlowSnapshot = metrics.snapshot();
    assert_eq!(
        snapshot.flow_idle_timeouts, 0,
        "this flow failed, it did not go idle"
    );
    assert!(
        closed,
        "a relay that fails after it started must be closed towards the app; \
         the counter was always right and the application still saw an \
         established connection that never answers"
    );
}
