use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub(crate) use self::smoltcp_tcp::TcpControl;
pub use self::smoltcp_tcp::{TcpConfig, TcpFlow};
pub use self::udp::DatagramFlow;
pub(crate) use self::udp::UdpStreamConfig;
pub use self::unknown::UnknownTransport;

mod smoltcp_tcp;
mod udp;
mod unknown;

/// A network stream accepted by the IP stack.
///
/// This enum represents different types of network streams that can be accepted from the TUN device.
/// Each variant provides appropriate abstractions for handling specific protocol types.
///
/// # Variants
///
/// * `Tcp` - A TCP connection stream implementing `AsyncRead` + `AsyncWrite`
/// * `Udp` - A UDP stream implementing `AsyncRead` + `AsyncWrite`
/// * `UnknownTransport` - A stream for unknown transport layer protocols (e.g., ICMP, IGMP)
/// * `UnknownNetwork` - Raw network layer packets that couldn't be parsed
pub enum StackFlow {
    /// A TCP connection stream.
    Tcp(TcpFlow),
    /// A SYN refused before a socket was allocated.
    TcpRefused { local: SocketAddr, peer: SocketAddr },
    /// A UDP stream.
    Udp(DatagramFlow),
    /// A stream for unknown transport protocols.
    UnknownTransport(UnknownTransport),
    /// Raw network packets that couldn't be parsed.
    UnknownNetwork(Vec<u8>),
}

impl StackFlow {
    /// Returns the local socket address for this stream.
    ///
    /// For TCP and UDP streams, this returns the source address of the connection.
    /// For unknown transport and network streams, this returns an unspecified address.
    ///
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            StackFlow::Tcp(tcp) => tcp.local_addr(),
            StackFlow::TcpRefused { local, .. } => *local,
            StackFlow::Udp(udp) => udp.local_addr(),
            StackFlow::UnknownNetwork(_) => {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            }
            StackFlow::UnknownTransport(unknown) => match unknown.src_addr() {
                IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
                IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            },
        }
    }

    /// Returns the remote socket address for this stream.
    ///
    /// For TCP and UDP streams, this returns the destination address of the connection.
    /// For unknown transport and network streams, this returns an unspecified address.
    ///
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            StackFlow::Tcp(tcp) => tcp.peer_addr(),
            StackFlow::TcpRefused { peer, .. } => *peer,
            StackFlow::Udp(udp) => udp.peer_addr(),
            StackFlow::UnknownNetwork(_) => {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            }
            StackFlow::UnknownTransport(unknown) => match unknown.dst_addr() {
                IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 0)),
                IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            },
        }
    }
}
