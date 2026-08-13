//! The tun ingress: one reader, one writer, two destinations.
//!
//! Packets are classified before anything terminates them, so `vpn` traffic can
//! stay at L3 in the packet tunnel while `direct`/`tor`/`block` still reach the
//! userspace stack. The stack keeps believing it owns a device — it is handed a
//! [`StackDevice`] instead of the tun, which is the same interface carrying only
//! the packets that were routed to it.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::BytesMut;
use foxcore_trafficmap::{PacketAccounting, PacketKey};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};

use crate::arena::PacketArena;
use crate::split::{FlowKey, PacketDecision, PacketRoute, PacketSplitter};

/// Where a classified packet can go.
pub struct IngressChannels {
    pub to_tunnel: mpsc::Sender<BytesMut>,
    pub to_stack: mpsc::Sender<BytesMut>,
    /// Counts what went each way. In packet-tunnel mode the stack side should
    /// only ever see DNS, overlay names and protocols without ports, so a
    /// growing `split_to_stack` says the split is sending user traffic to a
    /// stack that cannot carry it.
    pub metrics: std::sync::Arc<crate::FlowMetrics>,
    /// The 5-tuple table the L3 path counts through. Reads are wait-free, so
    /// this costs the packet path a lookup and two relaxed atomics — nothing
    /// here waits for a consumer.
    pub accounting: Arc<PacketAccounting>,
}

/// Read classified packets off the tun and hand each to its destination.
///
/// `decide` is consulted once per flow — the splitter caches the verdict — and
/// is where identity resolution and the policy snapshot are read. A packet whose
/// destination channel is gone ends the loop: that generation is over, and
/// continuing would mean dropping traffic in silence.
///
/// Deciding is awaited inline, so the first packet of a new flow waits for the
/// owner lookup and packets behind it wait with it. That is deliberate: the
/// alternative is to drop the packet and answer later, and dropping a SYN buys
/// a retransmit timeout on every new connection — far worse than one bounded
/// Binder call. The cost is bounded by the attribution timeout the caller
/// applies, and it is paid once per flow, not once per packet.
pub async fn classify<F, Fut>(
    mut from_tun: mpsc::Receiver<BytesMut>,
    mut splitter: PacketSplitter,
    decide: F,
    channels: IngressChannels,
    cancel: CancellationToken,
) where
    F: Fn(FlowKey) -> Fut,
    Fut: Future<Output = PacketDecision>,
{
    let started = Instant::now();
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => return,
            packet = from_tun.recv() => match packet {
                Some(packet) => packet,
                None => return,
            },
        };
        let now_ms = started.elapsed().as_millis() as u64;
        // Something that is not an IP packet at all is dropped rather than
        // guessed at; the tun should never produce one.
        let Some(key) = FlowKey::from_packet(&packet) else {
            continue;
        };
        let route = match splitter.lookup(&key, now_ms) {
            Some(route) => route,
            None => {
                let decision = tokio::select! {
                    _ = cancel.cancelled() => return,
                    decision = decide(key) => decision,
                };
                let route = decision.route;
                splitter.insert(key, decision, now_ms);
                route
            }
        };
        let destination = match route {
            PacketRoute::Tunnel => {
                channels.metrics.split_to_tunnel();
                // The only place the tunnel's uplink bytes can be attributed to
                // an app: past this point the packet is sealed and there is no
                // stream to wrap. Without it a live L3 tunnel reports zero
                // per-app traffic and the app draws it as idle (D4).
                channels
                    .accounting
                    .count_up(&PacketKey::from(key), packet.len() as u64);
                &channels.to_tunnel
            }
            PacketRoute::Stack => {
                channels.metrics.split_to_stack();
                &channels.to_stack
            }
            // Blocked is silent by design: the flow is denied, and answering
            // would tell the application which policy stopped it.
            PacketRoute::Block => {
                channels.metrics.split_blocked();
                continue;
            }
        };
        if destination.send(packet).await.is_err() {
            return;
        }
    }
}

/// A device the userspace stack can own, carrying only the packets the split
/// routed to it.
///
/// Reads come from the ingress classifier, writes go to the one task that owns
/// the tun file descriptor — the packet tunnel writes to the same task, and a
/// single writer is what keeps two sources from interleaving inside one packet.
pub struct StackDevice {
    inbox: mpsc::Receiver<BytesMut>,
    outbox: PollSender<BytesMut>,
    /// Where a packet the stack wrote is copied to. The copy is forced by
    /// `AsyncWrite` — the stack hands over a borrowed slice — but the
    /// allocation that used to come with it is not; see [`PacketArena`].
    replies: PacketArena,
}

impl StackDevice {
    /// `mtu` sizes the reply buffer only. It is a hint, not a limit: `copy_in`
    /// keeps every byte the stack wrote whatever this says, because a device
    /// that silently truncated a write would put half a packet on the tun.
    pub fn new(inbox: mpsc::Receiver<BytesMut>, outbox: mpsc::Sender<BytesMut>, mtu: u16) -> Self {
        Self {
            inbox,
            outbox: PollSender::new(outbox),
            replies: PacketArena::new(usize::from(mtu)),
        }
    }
}

impl AsyncRead for StackDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.inbox.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                // A tun read truncates to the caller's buffer; mirroring that is
                // honest, and the stack always reads with at least an MTU.
                let length = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..length]);
                Poll::Ready(Ok(()))
            }
            // The ingress is gone: report end of file so the stack unwinds
            // instead of parking forever on a dead generation.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for StackDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // One write is one packet: the stack never splits a datagram across
        // calls, and the writer task must not have to reassemble one.
        //
        // The reservation comes first and the copy second, so a `Pending` here
        // never leaves a packet's worth of the arena's chunk handed out to
        // nobody.
        let this = self.get_mut();
        match this.outbox.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let packet = this.replies.copy_in(buf);
                this.outbox
                    .send_item(packet)
                    .map_err(|_| io::Error::other("tun writer is gone"))?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::other("tun writer is gone"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    use super::*;

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn the_stack_device_delivers_one_whole_packet_per_read() {
        let (to_stack, stack_inbox) = mpsc::channel(4);
        let (tun_writer, _tun_outbox) = mpsc::channel(4);
        let mut device = StackDevice::new(stack_inbox, tun_writer, 1500);

        to_stack.send(BytesMut::from(&[1, 2, 3][..])).await.unwrap();
        to_stack.send(BytesMut::from(&[4, 5][..])).await.unwrap();

        let mut buffer = [0_u8; 64];
        assert_eq!(device.read(&mut buffer).await.unwrap(), 3);
        assert_eq!(&buffer[..3], &[1, 2, 3]);
        assert_eq!(
            device.read(&mut buffer).await.unwrap(),
            2,
            "packet boundaries must survive the hand-off, or the stack reparses garbage"
        );
        assert_eq!(&buffer[..2], &[4, 5]);
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn what_the_stack_writes_is_handed_to_the_single_tun_writer() {
        let (_to_stack, stack_inbox) = mpsc::channel(4);
        let (tun_writer, mut tun_outbox) = mpsc::channel(4);
        let mut device = StackDevice::new(stack_inbox, tun_writer, 1500);

        device.write_all(&[9, 9, 9]).await.unwrap();

        assert_eq!(tun_outbox.recv().await.unwrap(), vec![9, 9, 9]);
    }

    /// A UDP/IPv4 packet whose destination port is the only thing under test.
    fn udp_packet(destination_port: u16) -> BytesMut {
        let mut packet = BytesMut::zeroed(28);
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    fn by_port() -> impl Fn(FlowKey) -> std::future::Ready<PacketDecision> + Send + 'static {
        |key| {
            std::future::ready(PacketDecision::new(match key.destination_port {
                443 => PacketRoute::Tunnel,
                9 => PacketRoute::Block,
                _ => PacketRoute::Stack,
            }))
        }
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn each_packet_goes_to_the_destination_its_flow_was_decided_for() {
        let (to_ingress, from_tun) = mpsc::channel(8);
        let (to_tunnel, mut tunnel_inbox) = mpsc::channel(8);
        let (to_stack, mut stack_inbox) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(classify(
            from_tun,
            PacketSplitter::new(64, 30_000),
            by_port(),
            IngressChannels {
                to_tunnel,
                to_stack,
                metrics: Arc::new(crate::FlowMetrics::default()),
                accounting: Arc::new(PacketAccounting::default()),
            },
            cancel.clone(),
        ));

        to_ingress.send(udp_packet(443)).await.unwrap();
        to_ingress.send(udp_packet(80)).await.unwrap();

        assert_eq!(tunnel_inbox.recv().await.unwrap(), udp_packet(443));
        assert_eq!(
            stack_inbox.recv().await.unwrap(),
            udp_packet(80),
            "a flow the policy did not send to the tunnel must still reach the stack"
        );

        cancel.cancel();
        task.await.unwrap();
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn a_blocked_flow_reaches_neither_destination() {
        let (to_ingress, from_tun) = mpsc::channel(8);
        let (to_tunnel, mut tunnel_inbox) = mpsc::channel(8);
        let (to_stack, mut stack_inbox) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(classify(
            from_tun,
            PacketSplitter::new(64, 30_000),
            by_port(),
            IngressChannels {
                to_tunnel,
                to_stack,
                metrics: Arc::new(crate::FlowMetrics::default()),
                accounting: Arc::new(PacketAccounting::default()),
            },
            cancel.clone(),
        ));

        to_ingress.send(udp_packet(9)).await.unwrap();
        // A packet that does follow is the only way to know the blocked one was
        // dropped rather than merely still in flight.
        to_ingress.send(udp_packet(80)).await.unwrap();

        assert_eq!(stack_inbox.recv().await.unwrap(), udp_packet(80));
        assert!(
            tunnel_inbox.try_recv().is_err(),
            "a blocked packet must not leak into the tunnel"
        );

        cancel.cancel();
        task.await.unwrap();
    }

    /// D4, found on device: L3 packets never reach the userspace stack, so
    /// nothing wrapped them in a counting stream and the app drew a live
    /// WireGuard tunnel as idle with no per-app traffic at all. The split is
    /// the only place that knows both the owning app and that this flow stays
    /// at L3, so it is where the row is opened and the uplink counted.
    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn tunnelled_packets_are_attributed_to_the_app_that_sent_them() {
        use foxcore_api::IpTransport;
        use foxcore_trafficmap::{FlowLane, FlowRoute, TrafficMap};

        let map = Arc::new(TrafficMap::default());
        let accounting = map.tunnel().clone();
        let (to_ingress, from_tun) = mpsc::channel(8);
        let (to_tunnel, mut tunnel_inbox) = mpsc::channel(8);
        let (to_stack, _stack_inbox) = mpsc::channel(8);
        let cancel = CancellationToken::new();

        let opened = map.clone();
        let task = tokio::spawn(classify(
            from_tun,
            PacketSplitter::new(64, 30_000),
            move |key: FlowKey| {
                let map = opened.clone();
                async move {
                    let flow = map.open(
                        IpTransport::Udp,
                        key.destination.to_string(),
                        key.destination_port,
                        FlowRoute::new(FlowLane::Vpn, "wireguard"),
                        vec!["com.example".to_owned()],
                        Some(10_123),
                    );
                    PacketDecision::with_flow(
                        PacketRoute::Tunnel,
                        flow.bind_packet_flow(PacketKey::from(key)),
                    )
                }
            },
            IngressChannels {
                to_tunnel,
                to_stack,
                metrics: Arc::new(crate::FlowMetrics::default()),
                accounting: accounting.clone(),
            },
            cancel.clone(),
        ));

        let packet = udp_packet(443);
        to_ingress.send(packet.clone()).await.unwrap();
        assert_eq!(tunnel_inbox.recv().await.unwrap(), packet);

        // What the relay does when the peer answers: the same tuple, reversed.
        let key = FlowKey::from_packet(&packet).unwrap();
        assert!(accounting.count_down(&PacketKey::from(key).reversed(), 512));

        let snapshot = map.snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].bytes_up, packet.len() as u64);
        assert_eq!(snapshot.connections[0].bytes_down, 512);
        assert_eq!(
            snapshot.packages[0].package, "com.example",
            "a tunnelled byte with no owner is a byte the split screen cannot place"
        );
        assert_eq!(snapshot.lanes[0].lane, FlowLane::Vpn);
        assert_eq!(snapshot.lanes[0].bytes_down, 512);

        cancel.cancel();
        task.await.unwrap();
    }

    /// Found on device: `revoke_flows` cancelled the row's token, reported the
    /// flow revoked and changed nothing — the split kept routing its packets
    /// into the tunnel on a decision nobody stood behind any more. A WireGuard
    /// flow that keeps sending never goes idle, so the idle timer, which was the
    /// only thing that reached a cached decision, never reached this one.
    ///
    /// The same shape covers a reload and a kill switch: both replace the policy
    /// snapshot and cancel the old token, which is the other half of `is_void`.
    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn a_revoked_l3_flow_is_decided_again_rather_than_kept_on_its_route() {
        use foxcore_api::IpTransport;
        use foxcore_trafficmap::{FlowLane, FlowRoute, RevokeTarget, TrafficMap};

        let map = Arc::new(TrafficMap::default());
        let (to_ingress, from_tun) = mpsc::channel(8);
        let (to_tunnel, mut tunnel_inbox) = mpsc::channel(8);
        let (to_stack, mut stack_inbox) = mpsc::channel(8);
        let cancel = CancellationToken::new();

        // Flipped between the two packets: the second decision has to be a
        // *new* one, and this is what tells a re-decision apart from a replay
        // of the first answer.
        let blocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let opened = map.clone();
        let policy = blocked.clone();
        let task = tokio::spawn(classify(
            from_tun,
            PacketSplitter::new(64, 30_000),
            move |key: FlowKey| {
                let map = opened.clone();
                let policy = policy.clone();
                async move {
                    if policy.load(std::sync::atomic::Ordering::SeqCst) {
                        return PacketDecision::new(PacketRoute::Stack);
                    }
                    let flow = map.open(
                        IpTransport::Udp,
                        key.destination.to_string(),
                        key.destination_port,
                        FlowRoute::new(FlowLane::Vpn, "wireguard"),
                        vec!["com.example".to_owned()],
                        Some(10_123),
                    );
                    PacketDecision::with_flow(
                        PacketRoute::Tunnel,
                        flow.bind_packet_flow(PacketKey::from(key)),
                    )
                }
            },
            IngressChannels {
                to_tunnel,
                to_stack,
                metrics: Arc::new(crate::FlowMetrics::default()),
                accounting: map.tunnel().clone(),
            },
            cancel.clone(),
        ));

        let packet = udp_packet(443);
        to_ingress.send(packet.clone()).await.unwrap();
        assert_eq!(tunnel_inbox.recv().await.unwrap(), packet);

        assert_eq!(
            map.revoke(&RevokeTarget::All {}),
            1,
            "the row the split opened is the one revoke is counting"
        );
        blocked.store(true, std::sync::atomic::Ordering::SeqCst);

        to_ingress.send(packet.clone()).await.unwrap();
        // Bounded, because the regression this guards *is* a packet that never
        // arrives here: it goes to the tunnel instead, and a bare `recv` would
        // report that as a suite that never finishes rather than a test that
        // failed.
        let after_revoke = tokio::time::timeout(std::time::Duration::from_secs(5), stack_inbox.recv())
            .await
            .expect("the packet after a revoke must be decided again, not routed on the answer the revoke was supposed to end")
            .unwrap();
        assert_eq!(after_revoke, packet);
        assert!(
            tunnel_inbox.try_recv().is_err(),
            "nothing may follow the revoked flow into the tunnel"
        );
        assert!(
            map.snapshot().connections.is_empty(),
            "dropping the decision drops its handle, and the row closes with it"
        );

        cancel.cancel();
        task.await.unwrap();
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn a_closed_ingress_reads_as_end_of_file_rather_than_hanging() {
        let (to_stack, stack_inbox) = mpsc::channel::<BytesMut>(4);
        let (tun_writer, _tun_outbox) = mpsc::channel(4);
        let mut device = StackDevice::new(stack_inbox, tun_writer, 1500);
        drop(to_stack);

        let mut buffer = [0_u8; 64];
        assert_eq!(
            device.read(&mut buffer).await.unwrap(),
            0,
            "a shut-down generation must let the stack finish, not block it forever"
        );
    }
}
