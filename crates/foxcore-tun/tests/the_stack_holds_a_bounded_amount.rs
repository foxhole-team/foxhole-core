//! Session-table and accept-queue capacity regressions.
//!
//! Capacity refusal applies only to new work; established sessions remain live.

use std::time::Duration;

use foxcore_tun::netstack::{FlowStack, StackFlow, TcpConfig, TcpFlow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod tunlab;

use tunlab::{FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, Seen};

const MTU: u16 = 1500;
const PORT: u16 = 8080;
const SOON: Duration = Duration::from_secs(5);

struct Bench {
    app: tokio::net::UnixDatagram,
    stack: FlowStack,
    _tun_fd_owner: foxcore_tun::TunFdOwner,
}

impl Bench {
    fn with_sessions(max_sessions: usize) -> Self {
        let (app, stack, tun_fd_owner) = tunlab::stack_over_socketpair_limited(MTU, max_sessions);
        Self {
            app,
            stack,
            _tun_fd_owner: tun_fd_owner,
        }
    }

    fn with_tcp(max_sessions: usize, tcp_config: TcpConfig) -> Self {
        let (app, stack, tun_fd_owner) =
            tunlab::stack_over_socketpair_limited_with_tcp(MTU, max_sessions, tcp_config);
        Self {
            app,
            stack,
            _tun_fd_owner: tun_fd_owner,
        }
    }

    async fn send(
        &self,
        client_port: u16,
        flags: u8,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) {
        let packet = tunlab::segment_from(
            client_port,
            tunlab::SERVER,
            PORT,
            flags,
            sequence,
            acknowledgement,
            payload,
        );
        tokio::time::timeout(SOON, async {
            loop {
                match self.app.send(&packet).await {
                    Ok(_) => return,
                    // The socketpair standing in for the TUN has a finite
                    // datagram buffer. A busy-path test may briefly fill that
                    // host buffer even though the stack is still draining it.
                    Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                        self.drain();
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("inject a segment: {error}"),
                }
            }
        })
        .await
        .expect("the stack must keep draining the test TUN");
    }

    /// Drain the finite socketpair buffer.
    fn drain(&self) {
        let mut buffer = [0_u8; 4096];
        while self.app.try_recv(&mut buffer).is_ok() {}
    }

    async fn await_resets(&self, client_ports: &[u16]) {
        let mut pending = client_ports.to_vec();
        let mut buffer = [0_u8; 4096];
        let deadline = tokio::time::Instant::now() + SOON;
        while !pending.is_empty() {
            let read = tokio::time::timeout_at(deadline, self.app.recv(&mut buffer))
                .await
                .unwrap_or_else(|_| panic!("dropped sessions were not reset: {pending:?}"))
                .expect("read the tun");
            pending.retain(|port| {
                !tunlab::tcp_for_port(&buffer[..read], *port)
                    .is_some_and(|segment| segment.flags & FLAG_RST != 0)
            });
        }
    }

    /// Collect segments for one client port until the deadline.
    async fn collect(&self, client_port: u16, within: Duration) -> Vec<Seen> {
        let deadline = tokio::time::Instant::now() + within;
        let mut buffer = [0_u8; 4096];
        let mut seen = Vec::new();
        loop {
            let read = match tokio::time::timeout_at(deadline, self.app.recv(&mut buffer)).await {
                Ok(Ok(read)) if read != 0 => read,
                _ => return seen,
            };
            if let Some(segment) = tunlab::tcp_for_port(&buffer[..read], client_port) {
                seen.push(segment);
            }
        }
    }

    /// Open a session and return its stream and next acknowledgement.
    async fn establish(&mut self, client_port: u16, sequence: u32) -> (TcpFlow, u32) {
        self.send(client_port, FLAG_SYN, sequence, 0, &[]).await;
        let mut buffer = [0_u8; 4096];
        let deadline = tokio::time::Instant::now() + SOON;
        let acknowledgement = loop {
            let read = tokio::time::timeout_at(deadline, self.app.recv(&mut buffer))
                .await
                .expect("the stack must answer the SYN in time")
                .expect("read the tun");
            if let Some(segment) = tunlab::tcp_for_port(&buffer[..read], client_port)
                && segment.flags & FLAG_SYN != 0
                && segment.flags & FLAG_ACK != 0
            {
                break segment.sequence.wrapping_add(1);
            }
        };
        self.send(
            client_port,
            FLAG_ACK,
            sequence.wrapping_add(1),
            acknowledgement,
            &[],
        )
        .await;
        let accepted = tokio::time::timeout(SOON, self.stack.accept())
            .await
            .expect("the stream has to reach accept()")
            .expect("accept the stream");
        let StackFlow::Tcp(stream) = accepted else {
            panic!("a TCP segment has to produce a TCP stream");
        };
        (stream, acknowledgement)
    }
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_session_table_refuses_the_new_and_keeps_carrying_the_established() {
    const CAPACITY: usize = 3;
    const ESTABLISHED: u16 = 40_000;
    const REFUSED: u16 = 40_003;

    let mut bench = Bench::with_sessions(CAPACITY);

    let (mut established, established_ack) = bench.establish(ESTABLISHED, 1_000).await;
    let (_second, _) = bench.establish(ESTABLISHED + 1, 2_000).await;
    let (_third, _) = bench.establish(ESTABLISHED + 2, 3_000).await;

    // Send before refusal to verify the established session survives it.
    bench
        .send(
            ESTABLISHED,
            FLAG_ACK | FLAG_PSH,
            1_001,
            established_ack,
            b"still here",
        )
        .await;

    bench.send(REFUSED, FLAG_SYN, 9_000, 0, &[]).await;

    let mut arrived = [0_u8; 10];
    tokio::time::timeout(SOON, established.read_exact(&mut arrived))
        .await
        .expect("a full table must not stall a session that is already up")
        .expect("read the established session");
    assert_eq!(
        &arrived, b"still here",
        "the packet path of a live session is the one thing no limit may touch: \
         a dropped segment there is packet loss to the peer, and a peer that \
         sees packet loss waits out a retransmission timeout"
    );

    let answers = bench.collect(REFUSED, Duration::from_millis(500)).await;
    assert!(
        answers.iter().any(|segment| segment.flags & FLAG_RST != 0),
        "a SYN a full stack cannot serve has to be reset. In silence the peer \
         spends its whole SYN schedule — 1, 3, 7, 15, 31 seconds on Linux — on \
         a stack that decided in microseconds: {answers:?}"
    );
    assert!(
        answers.iter().all(|segment| segment.flags & FLAG_SYN == 0),
        "and refused before any session exists, not accepted and then torn \
         down: a SYN|ACK here would mean the stack built exactly what it said \
         it had no room for: {answers:?}"
    );

    // Drop queues an actor command; the wire reset confirms it was processed.
    drop(_second);
    drop(_third);
    bench
        .await_resets(&[ESTABLISHED + 1, ESTABLISHED + 2])
        .await;
    let (_recovered, _) = bench.establish(REFUSED + 1, 11_000).await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn time_wait_releases_its_slot_while_unrelated_packets_keep_the_actor_busy() {
    const FIRST: u16 = 40_100;
    const SECOND: u16 = 40_101;

    let mut bench = Bench::with_sessions(1);
    let (mut first, _acknowledgement) = bench.establish(FIRST, 1_000).await;
    let closing = tokio::spawn(async move { first.shutdown().await });

    let deadline = tokio::time::Instant::now() + SOON;
    let fin = loop {
        let packets = bench.collect(FIRST, Duration::from_millis(50)).await;
        if let Some(fin) = packets
            .into_iter()
            .find(|packet| packet.flags & FLAG_FIN != 0)
        {
            break fin;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a graceful shutdown must put a FIN on the wire"
        );
    };
    bench
        .send(
            FIRST,
            FLAG_ACK | FLAG_FIN,
            1_001,
            fin.sequence.wrapping_add(1),
            &[],
        )
        .await;

    // Invalid IP is deliberate: it keeps the biased TUN-read branch ready but
    // produces no reply. A TCP miss would emit one RST per packet and turn this
    // into a test of the macOS UnixDatagram receive buffer instead of the
    // actor's deadline bookkeeping.
    let noise = [0xff_u8; 64];
    let busy_until = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut packets = 0_usize;
    while !closing.is_finished() && tokio::time::Instant::now() < busy_until {
        // Keep at least one full read budget queued across the cooperative
        // yield, so the timer arm at the bottom of the biased select cannot be
        // the thing that makes the test pass.
        for _ in 0..256 {
            match bench.app.try_send(&noise) {
                Ok(_) => {
                    packets += 1;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    break;
                }
                Err(error) => panic!("inject unrelated traffic: {error}"),
            }
        }
        tokio::task::yield_now().await;
    }

    assert!(packets > 100, "the actor was not kept continuously busy");
    tokio::time::timeout(Duration::from_millis(100), closing)
        .await
        .expect("TIME_WAIT expired but the shutdown waiter was never released")
        .expect("join graceful shutdown")
        .expect("graceful shutdown");
    // The kernel-side datagram buffer is finite; give the actor one bounded
    // window to drain the last raw packets before injecting the recovery SYN.
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        matches!(
            tokio::time::timeout(SOON, bench.stack.accept()).await,
            Ok(Ok(StackFlow::UnknownNetwork(_)))
        ),
        "the raw traffic never reached the actor's bounded accept path"
    );

    let (_recovered, _) = bench.establish(SECOND, 2_000).await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resetting_a_half_open_handshake_releases_its_reserved_slot() {
    const HALF_OPEN: u16 = 40_200;
    const RECOVERED: u16 = 40_201;

    let mut bench = Bench::with_sessions(1);
    bench.send(HALF_OPEN, FLAG_SYN, 1_000, 0, &[]).await;
    let syn_ack = bench
        .collect(HALF_OPEN, Duration::from_millis(100))
        .await
        .into_iter()
        .find(|packet| packet.flags & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK))
        .expect("the reserved socket must answer the SYN");
    bench
        .send(
            HALF_OPEN,
            FLAG_RST | FLAG_ACK,
            1_001,
            syn_ack.sequence.wrapping_add(1),
            &[],
        )
        .await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let (_recovered, _) = bench.establish(RECOVERED, 2_000).await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_half_open_handshake_expires_and_releases_its_slot() {
    const ABANDONED: u16 = 40_300;
    const RECOVERED: u16 = 40_301;

    let mut tcp = TcpConfig::default();
    tcp.handshake_timeout = Duration::from_millis(100);
    let mut bench = Bench::with_tcp(1, tcp);
    bench.send(ABANDONED, FLAG_SYN, 1_000, 0, &[]).await;
    assert!(
        bench
            .collect(ABANDONED, Duration::from_millis(50))
            .await
            .iter()
            .any(|packet| packet.flags & FLAG_SYN != 0),
        "the first flow was never half open"
    );
    assert!(
        bench
            .collect(ABANDONED, Duration::from_millis(500))
            .await
            .iter()
            .any(|packet| packet.flags & FLAG_RST != 0),
        "an abandoned handshake must be reset when its reservation expires"
    );

    let (_recovered, _) = bench.establish(RECOVERED, 2_000).await;
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_datagram_at_a_full_table_allocates_no_session() {
    const CAPACITY: usize = 2;
    const HOLDER: u16 = 41_000;
    const DATAGRAM: u16 = 41_002;

    let mut bench = Bench::with_sessions(CAPACITY);
    let (_first, _) = bench.establish(HOLDER, 1_000).await;
    let (second, _) = bench.establish(HOLDER + 1, 2_000).await;

    let datagram = tunlab::datagram_from(DATAGRAM, tunlab::SERVER, 53, b"who?");
    bench.app.send(&datagram).await.expect("inject a datagram");

    assert!(
        tokio::time::timeout(Duration::from_millis(500), bench.stack.accept())
            .await
            .is_err(),
        "a datagram that arrives at a full table must not become a session. \
         Anything that reached accept() here would be a UDP session the stack \
         had just said it had no room for"
    );

    // A released slot accepts the next datagram session.
    drop(second);
    let recovered = tokio::time::timeout(SOON, async {
        loop {
            bench.app.send(&datagram).await.expect("inject a datagram");
            if let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_millis(200), bench.stack.accept()).await
            {
                return stream;
            }
        }
    })
    .await
    .expect("the table has to take a datagram again once a slot is free");
    assert!(
        matches!(recovered, StackFlow::Udp(_)),
        "and it has to be the datagram's own session"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accept_queue_nobody_drains_stops_growing() {
    const CAPACITY: usize = 8;
    const FLOOD: usize = 200;

    let mut bench = Bench::with_sessions(CAPACITY);

    let junk = vec![0xFF_u8; 64];
    let mut offered = 0;
    while offered < FLOOD {
        match bench.app.send(&junk).await {
            Ok(_) => offered += 1,
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("inject junk: {error}"),
        }
    }
    // Let the stack process the flood before draining the queue.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut held = 0;
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(200), bench.stack.accept()).await
    {
        held += 1;
        assert!(
            held <= CAPACITY,
            "the accept queue handed over more than it is allowed to hold: \
             {held} of {offered} junk packets, for a queue of {CAPACITY}"
        );
    }

    println!("junk flood: {offered} offered, {held} held");
    assert!(
        held > 0,
        "the flood has to have reached the queue at all, or the bound below is \
         untested"
    );
    assert!(
        held <= CAPACITY,
        "what the stack holds for a consumer that never arrives has to be \
         bounded by the queue, not by the sender's patience: {held} held of \
         {offered} offered"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_established_session_is_not_charged_for_its_own_traffic() {
    const CAPACITY: usize = 2;
    const BUSY: u16 = 42_000;
    const SEGMENTS: u32 = 64;

    let mut bench = Bench::with_sessions(CAPACITY);
    let (mut stream, acknowledgement) = bench.establish(BUSY, 1_000).await;

    let payload = b"0123456789abcdef";
    let mut sequence = 1_001_u32;
    let mut sent = 0_usize;
    for segment in 0..SEGMENTS {
        bench
            .send(
                BUSY,
                FLAG_ACK | FLAG_PSH,
                sequence,
                acknowledgement,
                payload,
            )
            .await;
        sequence = sequence.wrapping_add(payload.len() as u32);
        sent += payload.len();
        // Drain continuously so receive-window backpressure is out of scope.
        let mut buffer = vec![0_u8; payload.len()];
        tokio::time::timeout(SOON, stream.read_exact(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("segment {segment} of a live session was never delivered"))
            .expect("read the busy session");
        assert_eq!(&buffer, payload);
        bench.drain();
    }

    assert_eq!(sent, SEGMENTS as usize * payload.len());
    stream
        .write_all(b"and back")
        .await
        .expect("the session has to still be writable");
}
