//! Flow-limit refusal regressions for TCP, UDP, and event reporting.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxcore_api::{BlockReason, CoreEvent, EventSink, IpTransport, RuntimeConfig};
use foxcore_tun::{FlowEngine, FlowMetrics, TunDevice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

mod tunlab;

use tunlab::{FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, Seen};

const HOLDER: u16 = 49_152;
const REFUSED: u16 = 49_153;

const SOON: Duration = Duration::from_secs(5);

struct Wire {
    app: tokio::net::UnixDatagram,
    cancel: CancellationToken,
    running: tokio::task::JoinHandle<io::Result<()>>,
    _tun_fd_owner: foxcore_tun::TunFdOwner,
}

impl Wire {
    fn start(engine: FlowEngine) -> Self {
        let (app, device) = UnixDatagram::pair().expect("socketpair");
        app.set_nonblocking(true).expect("nonblocking");
        let app = tokio::net::UnixDatagram::from_std(app).expect("register the app side");
        let (device, tun_fd_owner) =
            TunDevice::from_owned_fd(OwnedFd::from(device)).expect("wrap the device side");
        let cancel = CancellationToken::new();
        let engine_cancel = cancel.clone();
        let running = tokio::spawn(async move { engine.run(device, 1500, engine_cancel).await });
        Self {
            app,
            cancel,
            running,
            _tun_fd_owner: tun_fd_owner,
        }
    }

    async fn send(
        &self,
        client_port: u16,
        destination_port: u16,
        flags: u8,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) {
        let packet = tunlab::segment_from(
            client_port,
            tunlab::SERVER,
            destination_port,
            flags,
            sequence,
            acknowledgement,
            payload,
        );
        self.app.send(&packet).await.expect("inject a segment");
    }

    async fn send_datagram(&self, client_port: u16, destination_port: u16, payload: &[u8]) {
        let packet = tunlab::datagram_from(client_port, tunlab::SERVER, destination_port, payload);
        self.app.send(&packet).await.expect("inject a datagram");
    }

    /// Return the first matching segment for one client port.
    async fn watch(
        &self,
        client_port: u16,
        within: Duration,
        wanted: impl Fn(&Seen) -> bool,
    ) -> Option<Seen> {
        let deadline = tokio::time::Instant::now() + within;
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match tokio::time::timeout_at(deadline, self.app.recv(&mut buffer)).await {
                Ok(Ok(read)) if read != 0 => read,
                _ => return None,
            };
            if let Some(seen) = tunlab::tcp_for_port(&buffer[..read], client_port)
                && wanted(&seen)
            {
                return Some(seen);
            }
        }
    }

    /// Open a connection and return the next acknowledgement.
    async fn handshake(&self, client_port: u16, destination_port: u16, sequence: u32) -> u32 {
        self.send(client_port, destination_port, FLAG_SYN, sequence, 0, &[])
            .await;
        let seen = self
            .watch(client_port, SOON, |seen| {
                seen.flags & FLAG_SYN != 0 && seen.flags & FLAG_ACK != 0
            })
            .await
            .expect("the stack must answer the SYN");
        let acknowledgement = seen.sequence.wrapping_add(1);
        self.send(
            client_port,
            destination_port,
            FLAG_ACK,
            sequence.wrapping_add(1),
            acknowledgement,
            &[],
        )
        .await;
        acknowledgement
    }

    async fn stop(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.running).await;
    }
}

#[derive(Clone, Default)]
struct Blocks(Arc<Mutex<Vec<(BlockReason, IpTransport)>>>);

impl Blocks {
    fn sink(&self) -> EventSink {
        let seen = self.0.clone();
        EventSink::new(move |event| {
            if let CoreEvent::Blocked {
                reason, transport, ..
            } = event
                && let Ok(mut seen) = seen.lock()
            {
                seen.push((reason, transport));
            }
        })
    }

    fn contains(&self, reason: BlockReason, transport: IpTransport) -> bool {
        self.0
            .lock()
            .map(|seen| seen.contains(&(reason, transport)))
            .unwrap_or(false)
    }

    fn all(&self) -> Vec<(BlockReason, IpTransport)> {
        self.0.lock().map(|seen| seen.clone()).unwrap_or_default()
    }
}

async fn settles(within: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ready()
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_flow_refused_for_want_of_a_slot_is_reset_rather_than_abandoned() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let blocks = Blocks::default();
    let runtime = RuntimeConfig {
        max_tcp_flows: 1,
        ..RuntimeConfig::default()
    };
    let engine =
        tunlab::engine_with_events(metrics.clone(), runtime, EventSink::none(), blocks.sink());
    let wire = Wire::start(engine);

    // Accepting the far end proves the only permit is held.
    let holder_ack = wire.handshake(HOLDER, port, 1_000).await;
    let (mut far_end, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the holder's dial has to complete")
        .expect("accept the holder");

    wire.send(REFUSED, port, FLAG_SYN, 5_000, 0, &[]).await;
    let reset = wire
        .watch(REFUSED, SOON, |seen| seen.flags & FLAG_RST != 0)
        .await;

    assert!(
        reset.is_some(),
        "a connection refused for want of a slot has to be reset. Dropping the \
         stream sends nothing at all, and the application is left holding a \
         connection that completed and will never answer"
    );
    assert!(
        settles(SOON, || metrics.snapshot().rejected_flows == 1).await,
        "exactly one flow was refused, and it has to be counted as one: {:?}",
        metrics.snapshot().rejected_flows
    );
    assert!(
        blocks.contains(BlockReason::FlowLimit, IpTransport::Tcp),
        "and it has to be named. `RuntimeConfig` documents this ceiling as \
         visible through BlockReason::FlowLimit, which nothing in the tree \
         emitted: {:?}",
        blocks.all()
    );

    wire.send(
        HOLDER,
        port,
        FLAG_ACK | FLAG_PSH,
        1_001,
        holder_ack,
        b"alive",
    )
    .await;
    let mut arrived = [0_u8; 5];
    tokio::time::timeout(SOON, far_end.read_exact(&mut arrived))
        .await
        .expect("the established flow has to keep carrying traffic")
        .expect("read what the holder sent");
    assert_eq!(&arrived, b"alive");

    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_datagram_refused_for_want_of_a_slot_is_dropped_without_opening_anything() {
    let far_end = tokio::net::UdpSocket::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that keeps the holder alive");
    let port = far_end.local_addr().expect("local address").port();
    let metrics = Arc::new(FlowMetrics::default());
    let blocks = Blocks::default();
    let runtime = RuntimeConfig {
        max_udp_flows: 1,
        ..RuntimeConfig::default()
    };
    let engine =
        tunlab::engine_with_events(metrics.clone(), runtime, EventSink::none(), blocks.sink());
    let wire = Wire::start(engine);

    wire.send_datagram(HOLDER, port, b"first").await;
    let mut arrived = [0_u8; 5];
    tokio::time::timeout(SOON, far_end.recv_from(&mut arrived))
        .await
        .expect("the holder's datagram has to reach the far end")
        .expect("receive the holder's datagram");
    assert_eq!(&arrived, b"first");
    assert!(
        settles(SOON, || {
            let snapshot = metrics.snapshot();
            snapshot.udp_flows_opened == 1 && snapshot.active_flows == 1
        })
        .await,
        "the first datagram has to hold the one slot before the second can be \
         refused by it: {:?}",
        metrics.snapshot()
    );

    wire.send_datagram(REFUSED, port, b"second").await;
    assert!(
        settles(SOON, || metrics.snapshot().rejected_flows == 1).await,
        "the second datagram has to be refused: {:?}",
        metrics.snapshot()
    );
    assert!(
        blocks.contains(BlockReason::FlowLimit, IpTransport::Udp),
        "and named, for the same reason as the TCP arm: {:?}",
        blocks.all()
    );
    assert_eq!(
        metrics.snapshot().udp_flows_opened,
        1,
        "a refused datagram must not open a flow. The stream is dropped \
         unread, which takes its session straight back out of the stack's \
         table"
    );

    wire.stop().await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_slot_comes_back_when_the_flow_holding_it_ends() {
    let listener = tokio::net::TcpListener::bind((tunlab::SERVER, 0))
        .await
        .expect("a far end that accepts");
    let port = listener.local_addr().expect("local address").port();

    let metrics = Arc::new(FlowMetrics::default());
    let runtime = RuntimeConfig {
        max_tcp_flows: 1,
        ..RuntimeConfig::default()
    };
    let wire = Wire::start(tunlab::engine(metrics.clone(), runtime));

    wire.handshake(HOLDER, port, 1_000).await;
    let (mut far_end, _) = tokio::time::timeout(SOON, listener.accept())
        .await
        .expect("the holder's dial has to complete")
        .expect("accept the holder");

    wire.send(REFUSED, port, FLAG_SYN, 5_000, 0, &[]).await;
    assert!(
        wire.watch(REFUSED, SOON, |seen| seen.flags & FLAG_RST != 0)
            .await
            .is_some(),
        "the second connection is refused while the slot is held"
    );

    // Close both relay directions before expecting the permit back.
    far_end.shutdown().await.expect("close the far end");
    drop(far_end);
    let closing = wire
        .watch(HOLDER, SOON, |seen| seen.flags & FLAG_FIN != 0)
        .await
        .expect("the core has to pass the far end's close on to the app");
    wire.send(
        HOLDER,
        port,
        FLAG_ACK | FLAG_FIN,
        1_001,
        closing.sequence.wrapping_add(1),
        &[],
    )
    .await;
    assert!(
        settles(SOON, || metrics.snapshot().flows_closed >= 1).await,
        "the holder has to have finished before the slot can be free: {:?}",
        metrics.snapshot()
    );

    wire.send(REFUSED + 1, port, FLAG_SYN, 9_000, 0, &[]).await;
    let answered = wire
        .watch(REFUSED + 1, SOON, |seen| {
            seen.flags & (FLAG_SYN | FLAG_RST) != 0
        })
        .await
        .expect("the stack answers every SYN one way or the other");
    assert_eq!(
        answered.flags & FLAG_RST,
        0,
        "with the slot given back, the next connection has to be served rather \
         than refused: a ceiling that latches is a tunnel that stays broken"
    );

    wire.stop().await;
}
