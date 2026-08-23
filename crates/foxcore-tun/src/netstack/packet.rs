use crate::netstack::error::StackError;
use etherparse::{Ipv4Header, Ipv6Header, NetSlice, SlicedPacket, TcpHeader, UdpHeader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Maximum IPv4-options plus TCP-options header pair.
const MAX_HEADER_LEN: usize = 60 + 60;

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub struct NetworkTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: bool,
}

impl NetworkTuple {
    pub fn new(src: SocketAddr, dst: SocketAddr, tcp: bool) -> Self {
        NetworkTuple { src, dst, tcp }
    }
}

impl std::fmt::Display for NetworkTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tcp = if self.tcp { "TCP" } else { "UDP" };
        write!(f, "{} {} -> {}", tcp, self.src, self.dst)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum IpHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

#[derive(Debug, Clone)]
pub(crate) enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub(crate) ip: IpHeader,
    pub(crate) transport: TransportHeader,
    pub(crate) payload: Option<Vec<u8>>,
}

impl NetworkPacket {
    pub fn parse(buf: &[u8]) -> Result<Self, StackError> {
        let p = SlicedPacket::from_ip(buf).map_err(|_| StackError::InvalidPacket)?;
        let ip = p.net.ok_or(StackError::InvalidPacket)?;

        let (ip, ip_payload) = match ip {
            NetSlice::Ipv4(ip) => (
                IpHeader::Ipv4(ip.header().to_header()),
                ip.payload().payload,
            ),
            NetSlice::Ipv6(ip) => (
                IpHeader::Ipv6(ip.header().to_header()),
                ip.payload().payload,
            ),
            NetSlice::Arp(_) => return Err(StackError::UnsupportedTransportProtocol),
        };
        let (transport, payload) = match p.transport {
            Some(etherparse::TransportSlice::Tcp(h)) => {
                (TransportHeader::Tcp(h.to_header()), h.payload())
            }
            Some(etherparse::TransportSlice::Udp(u)) => {
                (TransportHeader::Udp(u.to_header()), u.payload())
            }
            _ => (TransportHeader::Unknown, ip_payload),
        };
        let payload = if payload.is_empty() {
            None
        } else {
            Some(payload.to_vec())
        };

        Ok(NetworkPacket {
            ip,
            transport,
            payload,
        })
    }
    pub(crate) fn transport_header(&self) -> &TransportHeader {
        &self.transport
    }
    pub fn src_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.source_port,
            TransportHeader::Tcp(tcp) => tcp.source_port,
            _ => 0,
        };
        match &self.ip {
            IpHeader::Ipv4(ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.source)), port),
            IpHeader::Ipv6(ip) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.source)), port),
        }
    }
    pub fn dst_addr(&self) -> SocketAddr {
        let port = match &self.transport {
            TransportHeader::Udp(udp) => udp.destination_port,
            TransportHeader::Tcp(tcp) => tcp.destination_port,
            _ => 0,
        };
        match &self.ip {
            IpHeader::Ipv4(ip) => SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.destination)), port),
            IpHeader::Ipv6(ip) => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip.destination)), port),
        }
    }
    pub fn network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.src_addr(),
            dst: self.dst_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    pub fn reverse_network_tuple(&self) -> NetworkTuple {
        NetworkTuple {
            src: self.dst_addr(),
            dst: self.src_addr(),
            tcp: matches!(self.transport, TransportHeader::Tcp(_)),
        }
    }
    #[cfg(test)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, StackError> {
        let mut buf = Vec::new();
        self.write_to(&mut buf)?;
        Ok(buf)
    }

    /// Append serialized headers and payload to a reusable caller-owned buffer.
    pub fn write_to(&self, buf: &mut Vec<u8>) -> Result<(), StackError> {
        let payload_len = self.payload.as_ref().map_or(0, Vec::len);
        buf.reserve(MAX_HEADER_LEN + payload_len);
        match self.ip {
            IpHeader::Ipv4(ref ip) => ip.write(buf)?,
            IpHeader::Ipv6(ref ip) => ip.write(buf)?,
        }
        match self.transport {
            TransportHeader::Tcp(ref h) => h.write(buf)?,
            TransportHeader::Udp(ref h) => h.write(buf)?,
            _ => {}
        };

        if let Some(payload) = &self.payload {
            buf.extend_from_slice(payload);
        }
        Ok(())
    }
    pub fn ttl(&self) -> u8 {
        match &self.ip {
            IpHeader::Ipv4(ip) => ip.time_to_live,
            IpHeader::Ipv6(ip) => ip.hop_limit,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use criterion::Criterion;
    use rand::random;
    use std::time::Duration;

    fn create_raw_packet(mtu: usize) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ipv4(random(), random(), random())
            .tcp(random(), random(), random(), random())
            .fin()
            .psh()
            .ack(random());

        let payload_len = mtu - builder.size(0);
        assert_eq!(mtu, builder.size(payload_len));
        let payload: Vec<u8> = (0..payload_len).map(|_| random()).collect();

        let mut buf = Vec::new();
        builder.write(&mut buf, &payload[..]).unwrap();
        assert_eq!(mtu, buf.len());
        buf
    }

    fn create_packet(mtu: usize) -> NetworkPacket {
        let packet = create_raw_packet(mtu);
        NetworkPacket::parse(packet.as_slice()).unwrap()
    }

    fn benchmarks(c: &mut Criterion) {
        for mtu in [64, 1500, 4096, 16384, 65515] {
            let buf = create_raw_packet(mtu);
            c.bench_function(format!("decode_mtu_{mtu}").as_str(), |b| {
                b.iter(|| {
                    let packet = std::hint::black_box(&buf[..]);
                    let _packet = NetworkPacket::parse(packet).unwrap();
                })
            });
        }

        for mtu in [64, 1500, 4096, 16384, 65515] {
            let packet = create_packet(mtu);
            c.bench_function(format!("encode_mtu_{mtu}").as_str(), |b| {
                b.iter(|| {
                    let packet = std::hint::black_box(&packet);
                    let _packet = packet.to_bytes();
                })
            });
        }
    }

    #[test]
    fn bench() {
        // `cargo test --profile bench -j1 -- --nocapture bench -- <benchmark_filter>
        // This workaround allows benchmarking private interfaces with `criterion` in stable rust.
        let args: Vec<String> = std::env::args().collect();
        let filter = args
            .windows(3)
            .filter(|p| p.len() >= 2 && p[0].ends_with("bench") && p[1] == "--")
            .map(|s| s.get(2).unwrap_or(&"".to_string()).clone())
            .next();
        let filter = match filter {
            Some(f) => f,
            None => return,
        };
        let profile_time = args
            .windows(2)
            .filter(|p| p.len() == 2 && p[0] == "--profile-time")
            .map(|s| s[1].as_str())
            .next();

        let mut c = Criterion::default()
            .with_output_color(true)
            .without_plots()
            .with_filter(filter)
            .warm_up_time(Duration::from_secs_f32(0.5))
            .measurement_time(Duration::from_secs_f32(0.5))
            .profile_time(profile_time.map(|s| Duration::from_secs_f32(s.parse().unwrap())));

        benchmarks(&mut c);

        Criterion::default().final_summary();
    }
}
