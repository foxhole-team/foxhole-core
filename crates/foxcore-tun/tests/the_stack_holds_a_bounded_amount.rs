//! Session-table and accept-queue capacity regressions.
//!
//! Capacity refusal applies only to new work; established sessions remain live.

use std::time::Duration;

use foxcore_tun::ipstack::{IpStack, IpStackStream, IpStackTcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod tunlab;

use tunlab::{FLAG_ACK, FLAG_PSH, FLAG_RST, FLAG_SYN, Seen};

const MTU: u16 = 1500;
const PORT: u16 = 8080;
const SOON: Duration = Duration::from_secs(5);

struct Bench {
    app: tokio::net::UnixDatagram,
    stack: IpStack,
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
        self.app.send(&packet).await.expect("inject a segment");
    }

    /// Drain the finite socketpair buffer.
    fn drain(&self) {
        let mut buffer = [0_u8; 4096];
        while self.app.try_recv(&mut buffer).is_ok() {}
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
    async fn establish(&mut self, client_port: u16, sequence: u32) -> (IpStackTcpStream, u32) {
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
        let IpStackStream::Tcp(stream) = accepted else {
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

    // Releasing a slot must clear the refusal condition.
    drop(_second);
    drop(_third);
    let (_recovered, _) = bench.establish(REFUSED + 1, 11_000).await;
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
        matches!(recovered, IpStackStream::Udp(_)),
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
