use crate::ipstack::{
    IpStackError, PacketSender, SessionPacketSender, TTL, UDP_SESSION_QUEUE_DEPTH,
    packet::{IpHeader, NetworkPacket, TransportHeader},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::Sleep,
};

/// A UDP stream in the IP stack.
///
/// This type represents a UDP connection and implements `AsyncRead` and `AsyncWrite`
/// for bidirectional data transfer. UDP streams have a configurable timeout and
/// automatically handle packet fragmentation based on MTU.
///
#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: mpsc::Sender<NetworkPacket>,
    stream_receiver: mpsc::Receiver<NetworkPacket>,
    queue_drops: Arc<AtomicU64>,
    up_pkt_sender: PacketSender,
    first_payload: Option<Vec<u8>>,
    timeout: Pin<Box<Sleep>>,
    timeout_interval: Duration,
    mtu: u16,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
}

pub(crate) struct UdpStreamConfig {
    pub(crate) mtu: u16,
    pub(crate) timeout_interval: Duration,
    pub(crate) queue_drops: Arc<AtomicU64>,
}

impl IpStackUdpStream {
    pub(crate) fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: Vec<u8>,
        up_pkt_sender: PacketSender,
        config: UdpStreamConfig,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        let (stream_sender, stream_receiver) =
            mpsc::channel::<NetworkPacket>(UDP_SESSION_QUEUE_DEPTH);
        let deadline = tokio::time::Instant::now() + config.timeout_interval;
        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            queue_drops: config.queue_drops,
            up_pkt_sender,
            first_payload: Some(payload),
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval: config.timeout_interval,
            mtu: config.mtu,
            destroy_messenger,
        }
    }

    pub(crate) fn stream_sender(&self) -> SessionPacketSender {
        SessionPacketSender::udp(self.stream_sender.clone(), self.queue_drops.clone())
    }

    fn create_rev_packet(&self, ttl: u8, mut payload: Vec<u8>) -> std::io::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (self.dst_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, dst.octets(), src.octets())
                    .map_err(IpStackError::from)?;
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);
                payload.truncate(line_buffer as usize);
                ip_h.set_payload_len(payload.len() + UHS)
                    .map_err(IpStackError::from)?;
                let udp_header = UdpHeader::with_ipv4_checksum(
                    self.dst_addr.port(),
                    self.src_addr.port(),
                    &ip_h,
                    &payload,
                )
                .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: ttl,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);

                payload.truncate(line_buffer as usize);

                ip_h.payload_length = (payload.len() + UHS) as u16;
                let udp_header = UdpHeader::with_ipv6_checksum(
                    self.dst_addr.port(),
                    self.src_addr.port(),
                    &ip_h,
                    &payload,
                )
                .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            _ => unreachable!(),
        }
    }

    /// The largest datagram this stream can put on the tun as one packet.
    ///
    /// `create_rev_packet` builds option-less headers, so the only variable is
    /// the address family: 20 bytes of IPv4 or 40 of IPv6, plus the 8-byte UDP
    /// header. At the Android MTU of 1400 that is 1372 bytes for IPv4.
    pub fn max_payload(&self) -> usize {
        const UDP_HEADER: usize = 8;
        const IPV4_HEADER: usize = 20;
        const IPV6_HEADER: usize = 40;
        let ip_header = match self.dst_addr.ip() {
            std::net::IpAddr::V4(_) => IPV4_HEADER,
            std::net::IpAddr::V6(_) => IPV6_HEADER,
        };
        usize::from(self.mtu).saturating_sub(ip_header + UDP_HEADER)
    }

    /// Returns the local socket address of the UDP stream.
    ///
    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    /// Returns the remote socket address of the UDP stream.
    ///
    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout_interval;
        self.timeout.as_mut().reset(deadline);
    }
}

impl AsyncRead for IpStackUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Both reads clamp to `buf.remaining()`. That used to be described here
        // as the only thing standing between a 64 KiB caller buffer and a panic
        // in `put_slice`; the clamps are the reason there is no panic, and both
        // callers now size their buffer to the MTU, which is the most a
        // datagram assembled from a tun packet can carry anyway.
        if let Some(p) = self.first_payload.take() {
            let length = p.len().min(buf.remaining());
            buf.put_slice(&p[..length]);
            return std::task::Poll::Ready(Ok(()));
        }
        if matches!(self.timeout.as_mut().poll(cx), std::task::Poll::Ready(_)) {
            return std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }

        self.reset_timeout();

        match self.stream_receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(p)) => {
                if let Some(payload) = p.payload {
                    let length = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..length]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for IpStackUdpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.reset_timeout();
        // A datagram is atomic, and this used to be the one place that forgot
        // it. `create_rev_packet` clamps the payload to the MTU, and returning
        // the clamped length told `write_all` that part of the message was
        // still unsent — so it sent the remainder as a **second datagram** with
        // the same ports. A DNS answer over 1372 bytes (DNSSEC, a large TXT, an
        // EDNS0 buffer of 4096) reached the resolver as two fragments of a
        // message that has no fragmentation, and the domain simply failed to
        // resolve. Refusing is the honest answer: `EMSGSIZE` is what a real UDP
        // socket returns here, and the DNS interceptor answers with the
        // truncation bit set so the client retries over TCP, which it serves.
        let limit = self.max_payload();
        if buf.len() > limit {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "datagram of {} bytes exceeds the {limit}-byte MTU",
                    buf.len()
                ),
            )));
        }
        let packet = self.create_rev_packet(TTL, buf.to_vec())?;
        self.up_pkt_sender
            .send(packet)
            .or(Err(std::io::ErrorKind::UnexpectedEof))?;
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for IpStackUdpStream {
    fn drop(&mut self) {
        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    use super::{IpStackUdpStream, UdpStreamConfig};
    use crate::ipstack::{SessionPacketDelivery, UDP_SESSION_QUEUE_DEPTH};

    const MTU: u16 = 1400;
    /// 1400 minus a 20-byte IPv4 header and an 8-byte UDP header.
    const IPV4_LIMIT: usize = 1372;

    fn stream() -> (
        IpStackUdpStream,
        mpsc::UnboundedReceiver<super::NetworkPacket>,
    ) {
        let (up_tx, up_rx) = mpsc::unbounded_channel();
        let src: SocketAddr = "10.0.0.2:53000".parse().expect("source address");
        let dst: SocketAddr = "10.0.0.1:53".parse().expect("destination address");
        let stream = IpStackUdpStream::new(
            src,
            dst,
            Vec::new(),
            up_tx,
            UdpStreamConfig {
                mtu: MTU,
                timeout_interval: Duration::from_secs(30),
                queue_drops: Arc::new(AtomicU64::new(0)),
            },
            None,
        );
        (stream, up_rx)
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn the_limit_is_the_mtu_less_both_headers() {
        let (stream, _rx) = stream();
        assert_eq!(stream.max_payload(), IPV4_LIMIT);
    }

    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn a_datagram_that_fits_goes_out_whole_and_once() {
        let (mut stream, mut rx) = stream();
        let payload = vec![7_u8; IPV4_LIMIT];

        stream
            .write_all(&payload)
            .await
            .expect("write the datagram");

        let packet = rx.try_recv().expect("one packet on the tun");
        assert_eq!(
            packet.payload.as_ref().map(Vec::len),
            Some(IPV4_LIMIT),
            "the payload was clamped even though it fitted"
        );
        assert!(rx.try_recv().is_err(), "one datagram must be one packet");
    }

    /// The defect this file carried: `poll_write` reported the clamped length,
    /// so `write_all` sent the tail as a second datagram with the same ports.
    /// A DNS answer over the limit reached the client as two fragments of a
    /// message that cannot be fragmented.
    #[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
    #[tokio::test]
    async fn an_oversized_datagram_is_refused_rather_than_cut_in_two() {
        let (mut stream, mut rx) = stream();
        let payload = vec![7_u8; IPV4_LIMIT + 200];

        let error = stream
            .write_all(&payload)
            .await
            .expect_err("an oversized datagram must not be accepted");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            rx.try_recv().is_err(),
            "nothing may reach the tun: half a datagram is worse than none"
        );
    }

    /// A local application can enqueue packets faster than an outbound accepts
    /// them. Before the bounded sender this loop had no failure point at all:
    /// every packet allocated another channel node until Android killed the VPN
    /// process for memory.
    #[tokio::test]
    async fn a_stalled_udp_flow_has_a_fixed_queue_and_counts_every_overflow() {
        let (stream, _rx) = stream();
        let sender = stream.stream_sender();
        let drops = stream.queue_drops.clone();

        for index in 0..UDP_SESSION_QUEUE_DEPTH {
            let packet = stream
                .create_rev_packet(64, vec![u8::try_from(index).unwrap_or_default()])
                .expect("test datagram");
            assert_eq!(
                sender.send(packet),
                SessionPacketDelivery::Delivered,
                "the configured queue depth must remain usable"
            );
        }

        const OVERFLOW: u64 = 7;
        for _ in 0..OVERFLOW {
            let packet = stream
                .create_rev_packet(64, vec![0xff])
                .expect("overflow datagram");
            assert_eq!(
                sender.send(packet),
                SessionPacketDelivery::Dropped,
                "a full UDP queue must drop without allocating another entry"
            );
        }
        assert_eq!(drops.load(Ordering::Relaxed), OVERFLOW);
    }
}
