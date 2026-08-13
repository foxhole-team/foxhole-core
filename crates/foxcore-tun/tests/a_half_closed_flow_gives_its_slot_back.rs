//! Regression tests for releasing half-closed flow slots.
//!
//! Socketpair timing uses the real `HALF_CLOSED_TIMEOUT` clock.

use std::sync::Arc;
use std::time::Duration;

use foxcore_api::RuntimeConfig;
use foxcore_tun::{FlowMetrics, FlowSnapshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod tunlab;

const IDLE_S: u64 = 300;

const WITHIN: Duration = Duration::from_secs(45);

const WATCH: Duration = Duration::from_secs(16);

fn runtime(tcp_idle_timeout_s: u64) -> RuntimeConfig {
    RuntimeConfig {
        tcp_idle_timeout_s,
        ..RuntimeConfig::default()
    }
}

async fn active_flows_reach(
    metrics: &FlowMetrics,
    flows: u64,
    within: Duration,
) -> Option<Duration> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < within {
        if metrics.snapshot().active_flows == flows {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

async fn closes_after_the_request() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("bind a far end");
    let port = listener.local_addr().expect("local address").port();
    let serving = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept the relay's dial");
        let mut byte = [0_u8; 1];
        let _ = stream.read(&mut byte).await;
        drop(stream);
        // Keep retry dials from failing on a closed port.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (port, serving)
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_whose_far_end_closed_gives_its_slot_back_without_waiting_for_the_idle_window() {
    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = tunlab::Lab::start(metrics.clone(), runtime(IDLE_S));
    let (port, serving) = closes_after_the_request().await;
    lab.open(port).await;
    // Establish the relay before the far end closes.
    lab.send(tunlab::FLAG_ACK | tunlab::FLAG_PSH, b"x").await;
    assert!(
        active_flows_reach(&metrics, 1, Duration::from_secs(10))
            .await
            .is_some(),
        "the flow never opened, so nothing below is a verdict about its lifetime"
    );
    // Keep the application half open after acknowledging the peer's FIN.
    assert!(
        lab.acknowledge_close_within(Duration::from_secs(10)).await,
        "the core has to pass the far end's close on to the application; \
         without that FIN there is no half-closed connection to measure"
    );

    let released = active_flows_reach(&metrics, 0, WITHIN).await;

    let snapshot: FlowSnapshot = metrics.snapshot();
    lab.stop().await;
    serving.abort();

    assert!(
        released.is_some(),
        "the far end closed and the flow kept its slot for the whole of {WITHIN:?}. \
         `copy_bidirectional` ends only when both directions do, so a peer that \
         sent FIN while the application holds its half open charges one of \
         `max_tcp_flows` — and one `CLOSE_WAIT` descriptor — to a connection \
         that can never carry anything again, until `tcp_idle_timeout_s` \
         ({IDLE_S} s here, an hour on a device) expires. On the Pixel that was \
         77 of them in thirty minutes, none of which cleared. Snapshot: \
         {snapshot:?}"
    );
    assert_eq!(
        snapshot.flow_half_closed_timeouts, 1,
        "and it has to be attributable to the half-closed window rather than to \
         something that happened to end the flow"
    );
    assert_eq!(
        snapshot.flow_idle_timeouts,
        0,
        "the idle window is {IDLE_S} s and the flow was reclaimed in {:?}; if \
         this moved, the test is measuring the wrong clock",
        released.unwrap_or_default()
    );
    assert_eq!(
        snapshot.flow_errors, 0,
        "a far end that closes normally is not a failure, and reclaiming the \
         flow it left behind is the mechanism working"
    );
}

async fn half_closes_and_keeps_reading() -> (
    u16,
    Arc<std::sync::atomic::AtomicU64>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};

    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("bind a far end");
    let port = listener.local_addr().expect("local address").port();
    let received = Arc::new(AtomicU64::new(0));
    let counting = received.clone();
    let serving = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept the relay's dial");
        // Send FIN while retaining the read half.
        stream.shutdown().await.expect("half-close the far end");
        let mut buffer = [0_u8; 64];
        while let Ok(read) = stream.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            counting.fetch_add(read as u64, Ordering::Relaxed);
        }
    });
    (port, received, serving)
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_half_open_flow_that_is_still_carrying_data_is_not_cut() {
    use std::sync::atomic::Ordering;

    let metrics = Arc::new(FlowMetrics::default());
    // Minimum accepted timeout keeps this regression test short.
    let mut lab = tunlab::Lab::start(metrics.clone(), runtime(5));
    let (port, received, serving) = half_closes_and_keeps_reading().await;
    lab.open(port).await;
    assert!(
        active_flows_reach(&metrics, 1, Duration::from_secs(10))
            .await
            .is_some(),
        "the flow never opened, so nothing below is a verdict about its lifetime"
    );
    // Acknowledge FIN without closing this side.
    assert!(
        lab.acknowledge_close_within(Duration::from_secs(10)).await,
        "the far end half-closed and the application was never told"
    );

    // Keep traffic moving and drain the finite socketpair buffer.
    let started = tokio::time::Instant::now();
    let mut reset_after = None;
    while started.elapsed() < WATCH && reset_after.is_none() {
        lab.send(tunlab::FLAG_ACK | tunlab::FLAG_PSH, b"y").await;
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Some(seen) = lab.next_segment(until).await {
            if seen.flags & tunlab::FLAG_RST != 0 {
                reset_after = Some(started.elapsed());
                break;
            }
        }
    }

    let snapshot: FlowSnapshot = metrics.snapshot();
    let carried = received.load(Ordering::Relaxed);
    lab.stop().await;
    serving.abort();

    assert!(
        carried >= WATCH.as_secs(),
        "the far end received {carried} bytes of the {} this test sent, so the \
         half-open direction was not actually carrying data and the verdict \
         below means nothing",
        WATCH.as_secs()
    );
    assert_eq!(
        snapshot.flow_half_closed_timeouts, 0,
        "a half-open connection that is still carrying data was reclaimed after \
         {carried} bytes. Half-open is legitimate TCP: the peer stopped sending, \
         it did not stop listening, and the window has to be reset by traffic \
         the way the idle window is"
    );
    assert_eq!(
        snapshot.flow_idle_timeouts, 0,
        "and the idle clock must not have taken it either"
    );
    assert_eq!(
        snapshot.active_flows, 1,
        "the flow has to still be there, not merely un-mourned"
    );
    assert!(
        reset_after.is_none(),
        "the application was reset after {:?} while its writes were still being \
         delivered to the far end",
        reset_after.unwrap_or_default()
    );
}
