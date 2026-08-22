use crate::netstack::{
    RawPacketSender, StackError, TTL,
    packet::{IpHeader, NetworkPacket, TransportHeader},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header};
use std::net::IpAddr;

/// A stream for unknown transport layer protocols.
///
/// This type handles network packets with transport protocols that are not TCP or UDP
/// (e.g., ICMP, IGMP, ESP, etc.). It provides methods to inspect the packet details
/// and send responses.
///
pub struct UnknownTransport {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    payload: Vec<u8>,
    protocol: IpNumber,
    mtu: u16,
    packet_sender: RawPacketSender,
}

impl UnknownTransport {
    pub(crate) fn new(
        src_addr: IpAddr,
        dst_addr: IpAddr,
        payload: Vec<u8>,
        ip: &IpHeader,
        mtu: u16,
        packet_sender: RawPacketSender,
    ) -> Self {
        let protocol = match ip {
            IpHeader::Ipv4(ip) => ip.protocol,
            IpHeader::Ipv6(ip) => ip.next_header,
        };
        UnknownTransport {
            src_addr,
            dst_addr,
            payload,
            protocol,
            mtu,
            packet_sender,
        }
    }

    /// Returns the source IP address of the packet.
    ///
    pub fn src_addr(&self) -> IpAddr {
        self.src_addr
    }

    /// Returns the destination IP address of the packet.
    ///
    pub fn dst_addr(&self) -> IpAddr {
        self.dst_addr
    }

    /// Returns the payload of the packet.
    ///
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the IP protocol number of the packet.
    ///
    pub fn ip_protocol(&self) -> IpNumber {
        self.protocol
    }

    /// Send a response packet.
    ///
    /// Payloads above the MTU are refused; this stack does not synthesize IP
    /// fragments.
    ///
    pub fn send(&self, mut payload: Vec<u8>) -> std::io::Result<()> {
        let packet = self.create_rev_packet(&mut payload)?;
        self.packet_sender.send(packet)
    }

    /// Create a reverse packet for sending a response.
    ///
    /// This method creates a packet with swapped source and destination addresses,
    /// suitable for sending responses to received packets.
    ///
    pub fn create_rev_packet(&self, payload: &mut Vec<u8>) -> std::io::Result<NetworkPacket> {
        match (self.dst_addr, self.src_addr) {
            (std::net::IpAddr::V4(dst), std::net::IpAddr::V4(src)) => {
                let mut ip_h = Ipv4Header::new(0, TTL, self.protocol, dst.octets(), src.octets())
                    .map_err(StackError::from)?;
                let line_buffer = self.mtu.saturating_sub(ip_h.header_len() as u16);

                let p = take_payload_within_mtu(payload, line_buffer)?;
                ip_h.set_payload_len(p.len()).map_err(StackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Unknown,
                    payload: Some(p),
                })
            }
            (std::net::IpAddr::V6(dst), std::net::IpAddr::V6(src)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: self.protocol,
                    hop_limit: TTL,
                    source: dst.octets(),
                    destination: src.octets(),
                };
                let line_buffer = self.mtu.saturating_sub(ip_h.header_len() as u16);
                let p = take_payload_within_mtu(payload, line_buffer)?;
                ip_h.set_payload_length(p.len()).map_err(StackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Unknown,
                    payload: Some(p),
                })
            }
            _ => Err(StackError::InvalidPacket.into()),
        }
    }
}

fn take_payload_within_mtu(payload: &mut Vec<u8>, limit: u16) -> std::io::Result<Vec<u8>> {
    if payload.len() > usize::from(limit) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "response of {} bytes exceeds the {limit}-byte MTU payload",
                payload.len()
            ),
        ));
    }
    Ok(std::mem::take(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn transport(
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: IpNumber,
        mtu: u16,
    ) -> (UnknownTransport, mpsc::Receiver<NetworkPacket>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            UnknownTransport {
                src_addr,
                dst_addr,
                payload: Vec::new(),
                protocol,
                mtu,
                packet_sender: RawPacketSender::new(sender),
            },
            receiver,
        )
    }

    #[test]
    fn ipv6_response_preserves_the_transport_protocol() {
        let (transport, _receiver) = transport(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            IpNumber::IPV6_ICMP,
            1280,
        );
        let mut payload = vec![1, 2, 3];

        let packet = transport.create_rev_packet(&mut payload).unwrap();
        let IpHeader::Ipv6(header) = packet.ip else {
            panic!("expected IPv6 response");
        };
        assert_eq!(header.next_header, IpNumber::IPV6_ICMP);
    }

    #[test]
    fn oversized_raw_response_is_refused_without_partial_packets() {
        let (transport, mut receiver) = transport(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            IpNumber::ICMP,
            1280,
        );

        assert_eq!(
            transport.send(vec![0; 1261]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
