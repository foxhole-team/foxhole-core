//! A TCP sender the test controls, and a link that can be made bad.
//!
//! Everything P7.4 claims is a claim about what one *conformant* peer gets out
//! of this stack: a sender that ignored the advertised window would prove
//! nothing about backpressure, and a sender that could not retransmit would
//! measure the loss arms as "the link broke" instead of as a throughput number.
//! So this is a real sender — window-limited, cumulative-ACK driven, with a
//! retransmission timer and a persist timer — and small enough to read.
//!
//! It is deliberately *not* the stack under test. The two directions are
//! written by different code with different bugs, which is the only reason a
//! measurement taken with it says anything.
//!
//! The impairments are applied here, on the injection path, rather than by
//! `netem`: the netem lab needs a Linux container and a cross-built
//! `foxcore-soak`, and the arms it runs measure the whole data plane. What is
//! being compared across this fork is narrower and can be measured exactly —
//! how fast bytes cross the stack's receive path when the link under them
//! drops, reorders, delays or shrinks. Absolute numbers from a debug build over
//! a socketpair are a lower bound, not a device characteristic; the comparison
//! before and after is the measurement.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use super::{FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, IPV4_HEADER, Seen, TCP_HEADER};

/// What a link does to the packets crossing it.
///
/// Applied symmetrically — to segments going towards the stack and to the
/// stack's replies coming back — because a one-sided impairment measures a
/// different network than the one anybody has. That is the same reasoning
/// `scripts/netem-lab.sh` gives for applying `tc` to both containers' egress.
#[derive(Debug, Clone, Copy)]
pub struct Link {
    /// Fraction of packets dropped, per mille, in each direction.
    pub loss_per_mille: u32,
    /// Fraction of packets held back one position, per mille.
    pub reorder_per_mille: u32,
    /// One-way delay applied to every packet.
    pub delay: Duration,
    /// Largest payload one segment may carry.
    pub mss: usize,
}

impl Link {
    pub const DEFAULT_MSS: usize = 1500 - IPV4_HEADER - TCP_HEADER;

    pub fn clean() -> Self {
        Link {
            loss_per_mille: 0,
            reorder_per_mille: 0,
            delay: Duration::ZERO,
            mss: Self::DEFAULT_MSS,
        }
    }

    pub fn loss(per_cent: u32) -> Self {
        Link {
            loss_per_mille: per_cent * 10,
            ..Self::clean()
        }
    }

    pub fn reorder(per_cent: u32) -> Self {
        Link {
            reorder_per_mille: per_cent * 10,
            delay: Duration::from_millis(2),
            ..Self::clean()
        }
    }

    pub fn delay(delay: Duration) -> Self {
        Link {
            delay,
            ..Self::clean()
        }
    }

    pub fn mtu(mtu: usize) -> Self {
        Link {
            mss: mtu - IPV4_HEADER - TCP_HEADER,
            ..Self::clean()
        }
    }
}

/// A deterministic 32-bit PRNG.
///
/// xorshift, seeded per run, so an arm that behaves differently on the third
/// run is a real finding rather than a different dice roll. `rand` is not a
/// dev-dependency of this crate and a loss arm does not need a good generator —
/// it needs a repeatable one.
struct Dice(u32);

impl Dice {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }

    /// True with probability `per_mille / 1000`.
    fn hits(&mut self, per_mille: u32) -> bool {
        per_mille != 0 && self.next() % 1000 < per_mille
    }
}

/// What one run of [`Sender::push`] saw.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pushed {
    /// Highest byte the stack acknowledged, counted from the first data byte.
    pub acknowledged: usize,
    /// Narrowest window the stack advertised after the handshake.
    pub smallest_window: u16,
    pub largest_window: u16,
    /// How long the sender spent blocked with nothing it was allowed to send.
    pub blocked: Duration,
    pub elapsed: Duration,
    /// Segments the sender put on the link, retransmissions included.
    pub segments: usize,
    pub retransmits: usize,
    /// Zero-window probes sent. Nonzero means the stack closed its window and
    /// the sender obeyed.
    pub probes: usize,
}

impl Pushed {
    pub fn megabytes_per_second(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.acknowledged as f64 / 1e6 / self.elapsed.as_secs_f64()
    }
}

/// One TCP connection, driven from the application's side of a tun.
pub struct Sender {
    app: std::sync::Arc<tokio::net::UnixDatagram>,
    /// Where segments go when the link has a delay: a queue with a release time
    /// per packet, drained by one task.
    ///
    /// Sleeping inline before each `send` would not be a delay, it would be a
    /// rate limit of one packet per delay — a 100 ms link would carry ten
    /// packets a second and the arm would measure the harness. Release times
    /// are monotonic because the delay is constant, so one task sleeping until
    /// each packet's own time gives a pipelined delay that keeps order.
    delayed: Option<tokio::sync::mpsc::UnboundedSender<(Instant, Vec<u8>)>>,
    server: std::net::Ipv4Addr,
    port: u16,
    /// Sequence number of the first data byte.
    base: u32,
    acknowledgement: u32,
    window: u16,
    link: Link,
    dice: Dice,
    /// The packet the link is holding back so the next one overtakes it.
    held: VecDeque<Vec<u8>>,
}

/// Retransmission timeout. Well below anything a socketpair needs, because the
/// only reason a segment is missing here is that the link dropped it.
const RTO: Duration = Duration::from_millis(60);
/// How long the sender waits on a closed window before it probes. A real stack
/// starts at its RTO and doubles; the whole point of the fork's window update
/// is that this timer should almost never fire, so a short one makes a test
/// that depends on the probe cheap and a test that depends on the update
/// honest.
const PERSIST: Duration = Duration::from_millis(40);

impl Sender {
    /// Open a connection and complete the handshake, returning the sender and
    /// the window the SYN|ACK offered.
    pub async fn connect(
        app: tokio::net::UnixDatagram,
        server: std::net::Ipv4Addr,
        port: u16,
        link: Link,
        seed: u32,
    ) -> std::io::Result<Sender> {
        let app = std::sync::Arc::new(app);
        // The whole round trip is applied on the injection path rather than
        // half on each: an RTT is what a sender's timers see, and splitting it
        // would need a second queue to measure the same thing.
        let delayed = (!link.delay.is_zero()).then(|| {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
            let socket = app.clone();
            tokio::spawn(async move {
                while let Some((at, packet)) = rx.recv().await {
                    tokio::time::sleep_until(at).await;
                    send_now(&socket, &packet).await;
                }
            });
            tx
        });
        let mut sender = Sender {
            app,
            delayed,
            server,
            port,
            base: 1_000,
            acknowledgement: 0,
            window: 0,
            link,
            dice: Dice(seed | 1),
            held: VecDeque::new(),
        };
        sender.emit(FLAG_SYN, sender.base, &[]).await;
        sender.base = sender.base.wrapping_add(1);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let Some(seen) = sender.receive(deadline).await else {
                return Err(std::io::Error::other("the stack never answered the SYN"));
            };
            if seen.flags & FLAG_SYN != 0 && seen.flags & FLAG_ACK != 0 {
                sender.acknowledgement = seen.sequence.wrapping_add(1);
                sender.window = seen.window;
                sender.emit(FLAG_ACK, sender.base, &[]).await;
                return Ok(sender);
            }
        }
    }

    /// Whether the stack has answered a SYN at all.
    ///
    /// Separate from [`Sender::connect`] because "no answer within the window"
    /// is a *result* for the deferred-handshake tests, not a failure.
    pub async fn syn_answered_within(
        app: &tokio::net::UnixDatagram,
        packet: &[u8],
        within: Duration,
    ) -> Option<Seen> {
        app.send(packet).await.expect("inject the SYN");
        let deadline = Instant::now() + within;
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match tokio::time::timeout_at(deadline, app.recv(&mut buffer)).await {
                Ok(Ok(read)) if read != 0 => read,
                _ => return None,
            };
            if let Some(seen) = super::tcp_for_client(&buffer[..read]) {
                return Some(seen);
            }
        }
    }

    /// Offer `budget` bytes, obeying every window the stack advertises, and
    /// stop when they are all acknowledged or `within` has passed.
    pub async fn push(&mut self, budget: usize, within: Duration) -> Pushed {
        let payload = vec![0xA5_u8; self.link.mss];
        let mut result = Pushed {
            smallest_window: u16::MAX,
            ..Pushed::default()
        };
        // Left edge of the send window and the highest byte handed to the link.
        let (mut acked, mut sent) = (0_usize, 0_usize);
        let started = Instant::now();
        let deadline = started + within;
        let mut sent_at = Instant::now();
        let mut blocked_since: Option<Instant> = None;

        while acked < budget && Instant::now() < deadline {
            let mut moved = false;
            while sent < budget && (sent - acked) + self.link.mss <= usize::from(self.window) {
                let len = self.link.mss.min(budget - sent);
                self.emit(
                    FLAG_ACK | FLAG_PSH,
                    self.base.wrapping_add(sent as u32),
                    &payload[..len],
                )
                .await;
                sent += len;
                result.segments += 1;
                moved = true;
            }
            if moved {
                sent_at = Instant::now();
                if let Some(since) = blocked_since.take() {
                    result.blocked += since.elapsed();
                }
            } else if blocked_since.is_none() {
                blocked_since = Some(Instant::now());
            }

            // Wait for an ACK, but never past the moment one of the timers is
            // due — the sender has to act on silence, which is the whole
            // difference between a harness and a script.
            let timer = if self.window == 0 { PERSIST } else { RTO };
            let wake = (sent_at + timer).min(deadline);
            let Some(seen) = self.receive(wake).await else {
                if Instant::now() >= deadline {
                    break;
                }
                if self.window == 0 && sent < budget {
                    // Persist: one byte the receiver is entitled to refuse,
                    // sent to make it say what its window is now. It counts as
                    // sent, because it is a real byte of the stream — a probe
                    // the receiver *accepts* advances the acknowledgement, and a
                    // sender that did not expect that would read the answer to
                    // its own question as an acknowledgement of data it never
                    // sent.
                    self.emit(
                        FLAG_ACK | FLAG_PSH,
                        self.base.wrapping_add(sent as u32),
                        &payload[..1],
                    )
                    .await;
                    sent += 1;
                    result.probes += 1;
                } else if sent > acked {
                    // Go back N: rewind to the left edge and let the window
                    // refill from there on the next turn. This stack
                    // acknowledges cumulatively, so the harness does not need
                    // to be cleverer than that — and it must not be dumber
                    // either: resending one segment per timeout and leaving
                    // `sent` where it was leaves the window full of data the
                    // receiver already has, which stalls the transfer for
                    // reasons that belong to the harness.
                    sent = acked;
                    result.retransmits += 1;
                }
                sent_at = Instant::now();
                continue;
            };
            if seen.flags & (FLAG_FIN | FLAG_RST) != 0 {
                break;
            }
            if seen.flags & FLAG_ACK == 0 {
                continue;
            }
            if std::env::var_os("FOXCORE_SENDER_TRACE").is_some() {
                eprintln!(
                    "  ack {:>8} window {:>6} (sent {sent}, acked {acked})",
                    seen.acknowledgement.wrapping_sub(self.base),
                    seen.window
                );
            }
            self.window = seen.window;
            result.smallest_window = result.smallest_window.min(seen.window);
            result.largest_window = result.largest_window.max(seen.window);
            let progress = seen.acknowledgement.wrapping_sub(self.base) as usize;
            if progress > acked && progress <= sent {
                acked = progress;
                sent_at = Instant::now();
            }
            // A window update against a sender that had given up on this round
            // has to restart it, and `sent` is what decides whether there is
            // anything to send.
            if self.window > 0 && sent < budget {
                sent = sent.max(acked);
            }
        }

        if let Some(since) = blocked_since {
            result.blocked += since.elapsed();
        }
        result.acknowledged = acked;
        result.elapsed = started.elapsed();
        result
    }

    /// Put one segment on the link, with whatever the link does to it.
    async fn emit(&mut self, flags: u8, sequence: u32, payload: &[u8]) {
        let packet = super::segment_to(
            self.server,
            self.port,
            flags,
            sequence,
            self.acknowledgement,
            payload,
        );
        if self.dice.hits(self.link.loss_per_mille) {
            return;
        }
        if self.dice.hits(self.link.reorder_per_mille) {
            // Held until the next one has gone out, which is what "reordered"
            // means when there is only one queue.
            self.held.push_back(packet);
            return;
        }
        self.release(packet).await;
        while let Some(held) = self.held.pop_front() {
            self.release(held).await;
        }
    }

    async fn release(&self, packet: Vec<u8>) {
        match &self.delayed {
            Some(queue) => {
                let _ = queue.send((Instant::now() + self.link.delay * 2, packet));
            }
            None => send_now(&self.app, &packet).await,
        }
    }

    /// The next segment the stack sends to our client port, or `None` at the
    /// deadline.
    ///
    /// Loss applies here too — an impairment that only ate the sender's
    /// segments would be a different network from the one anybody has, and it
    /// is the one that flatters a receiver. Delay does not: the whole round
    /// trip is already applied on the injection path, and charging it twice
    /// would make the arm's name wrong.
    async fn receive(&mut self, deadline: Instant) -> Option<Seen> {
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match tokio::time::timeout_at(deadline, self.app.recv(&mut buffer)).await {
                Ok(Ok(read)) if read != 0 => read,
                _ => return None,
            };
            let Some(seen) = super::tcp_for_client(&buffer[..read]) else {
                continue;
            };
            if self.dice.hits(self.link.loss_per_mille) {
                continue;
            }
            return Some(seen);
        }
    }

    /// Close the connection from the application's side.
    pub async fn finish(&mut self, sent: usize) {
        self.emit(
            FLAG_ACK | FLAG_FIN,
            self.base.wrapping_add(sent as u32),
            &[],
        )
        .await;
    }
}

async fn send_now(socket: &tokio::net::UnixDatagram, packet: &[u8]) {
    loop {
        match socket.send(packet).await {
            Ok(_) => return,
            // The socketpair standing in for the tun is a fixed-size datagram
            // buffer, and a full window's burst can fill it before the stack
            // drains it. That is the pipe being small, not the stack pushing
            // back — a real driver would have queued the frame — so it is
            // retried rather than counted as loss.
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("inject a segment: {error}"),
        }
    }
}
