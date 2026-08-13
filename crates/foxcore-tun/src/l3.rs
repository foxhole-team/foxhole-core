//! Address translation for the L3 packet-tunnel path.
//!
//! Android hands the tun one address, and a WireGuard peer assigns another. The
//! packet tunnel is a single client with a single address on each side, so the
//! mapping is 1:1 and stateless: rewrite the source on the way out, the
//! destination on the way back, and repair the checksums incrementally.
//!
//! Doing it here rather than by terminating connections is what keeps a second
//! userspace TCP stack out of the L3 path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;
const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const PROTOCOL_ICMPV6: u8 = 58;
const IPV4_MIN_HEADER: usize = 20;
const IPV4_CHECKSUM: usize = 10;
const IPV4_PROTOCOL: usize = 9;
const IPV4_SOURCE: usize = 12;
const IPV4_DESTINATION: usize = 16;
const IPV6_HEADER: usize = 40;
const IPV6_NEXT_HEADER: usize = 6;
const IPV6_SOURCE: usize = 8;
const IPV6_DESTINATION: usize = 24;

/// Stateless 1:1 rewrite between the tun address and the packet tunnel's
/// interface address, one pair per family.
///
/// A family the tunnel has no address for is refused rather than passed
/// through: sending a packet the peer cannot answer is a silent black hole, and
/// sending it untranslated would leak the tun's own address.
pub struct AddressTranslator {
    v4: Option<(Ipv4Addr, Ipv4Addr)>,
    v6: Option<(Ipv6Addr, Ipv6Addr)>,
}

/// Why the translator would not touch a packet.
///
/// The two causes are different problems with different fixes, and telling them
/// apart is the whole diagnostic value: `NoMappingForFamily` means the peer
/// assigned no address of that family, `ForeignAddress` means the address on
/// the tun is not the one the engine was configured with. Both used to be a
/// bare `false` that the relay dropped in silence (D10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationRefusal {
    /// The tunnel has no address of this packet's family, so there is nothing
    /// to rewrite to. Every packet of that family is lost until the profile
    /// gains one.
    NoMappingForFamily,
    /// The address in the packet is not the one this translator maps. Outbound,
    /// that means the tun is carrying an address the engine config does not
    /// know about — the platform put something else on the interface.
    ForeignAddress,
    /// Not a packet this code can parse at all.
    Malformed,
}

/// Which end of the mapping a packet field currently holds.
#[derive(Clone, Copy)]
enum Direction {
    /// Leaving the tun: the source is the tun address and becomes the peer's.
    ToTunnel,
    /// Arriving from the peer: the destination is the tunnel address and
    /// becomes the tun's.
    ToTun,
}

impl AddressTranslator {
    /// Build from `(tun_address, tunnel_address)` pairs. The last pair for a
    /// family wins, which keeps construction from a config list total.
    pub fn new(pairs: impl IntoIterator<Item = (IpAddr, IpAddr)>) -> Self {
        let mut translator = Self { v4: None, v6: None };
        for pair in pairs {
            match pair {
                (IpAddr::V4(tun), IpAddr::V4(peer)) => translator.v4 = Some((tun, peer)),
                (IpAddr::V6(tun), IpAddr::V6(peer)) => translator.v6 = Some((tun, peer)),
                // A mixed pair is a configuration error, not something to guess at.
                _ => {}
            }
        }
        translator
    }

    /// Rewrite an outbound packet's source from the tun address to the tunnel
    /// address. Returns `false` when the packet is not ours to translate, and
    /// the caller must drop it — a packet with a foreign source has no business
    /// inside this tunnel.
    pub fn to_tunnel(&self, packet: &mut [u8]) -> bool {
        self.rewrite(packet, Direction::ToTunnel).is_ok()
    }

    /// Restore an inbound packet's destination to the tun address.
    pub fn to_tun(&self, packet: &mut [u8]) -> bool {
        self.rewrite(packet, Direction::ToTun).is_ok()
    }

    /// [`Self::to_tunnel`], reporting why it refused.
    pub fn to_tunnel_checked(&self, packet: &mut [u8]) -> Result<(), TranslationRefusal> {
        self.rewrite(packet, Direction::ToTunnel)
    }

    /// [`Self::to_tun`], reporting why it refused.
    pub fn to_tun_checked(&self, packet: &mut [u8]) -> Result<(), TranslationRefusal> {
        self.rewrite(packet, Direction::ToTun)
    }

    /// Whether anything can be translated at all.
    ///
    /// A translator with no pairs accepts nothing, so a tunnel built on one
    /// drops every packet the user sends while looking perfectly alive —
    /// handshakes and keepalives never reach the translator. The caller refuses
    /// to start instead.
    pub fn is_empty(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }

    fn rewrite(&self, packet: &mut [u8], direction: Direction) -> Result<(), TranslationRefusal> {
        match packet.first().map(|first| first >> 4) {
            Some(IPV4_VERSION) => self.rewrite_v4(packet, direction),
            Some(IPV6_VERSION) => self.rewrite_v6(packet, direction),
            _ => Err(TranslationRefusal::Malformed),
        }
    }

    fn rewrite_v4(
        &self,
        packet: &mut [u8],
        direction: Direction,
    ) -> Result<(), TranslationRefusal> {
        let Some((tun, peer)) = self.v4 else {
            return Err(TranslationRefusal::NoMappingForFamily);
        };
        let Some(header_len) = ipv4_header_len(packet) else {
            return Err(TranslationRefusal::Malformed);
        };
        let (offset, expected, replacement) = match direction {
            Direction::ToTunnel => (IPV4_SOURCE, tun, peer),
            Direction::ToTun => (IPV4_DESTINATION, peer, tun),
        };
        let old = expected.octets();
        let new = replacement.octets();
        if packet[offset..offset + 4] != old {
            return Err(TranslationRefusal::ForeignAddress);
        }
        packet[offset..offset + 4].copy_from_slice(&new);

        let header_checksum = read_u16(packet, IPV4_CHECKSUM);
        write_u16(
            packet,
            IPV4_CHECKSUM,
            update_checksum(header_checksum, &old, &new),
        );
        update_transport_checksum(
            packet,
            header_len,
            packet_protocol_v4(packet),
            usize::from(fragment_offset(packet)) * 8,
            &old,
            &new,
        );
        Ok(())
    }

    fn rewrite_v6(
        &self,
        packet: &mut [u8],
        direction: Direction,
    ) -> Result<(), TranslationRefusal> {
        let Some((tun, peer)) = self.v6 else {
            return Err(TranslationRefusal::NoMappingForFamily);
        };
        if packet.len() < IPV6_HEADER {
            return Err(TranslationRefusal::Malformed);
        }
        let (offset, expected, replacement) = match direction {
            Direction::ToTunnel => (IPV6_SOURCE, tun, peer),
            Direction::ToTun => (IPV6_DESTINATION, peer, tun),
        };
        let old = expected.octets();
        let new = replacement.octets();
        if packet[offset..offset + 16] != old {
            return Err(TranslationRefusal::ForeignAddress);
        }
        packet[offset..offset + 16].copy_from_slice(&new);

        // IPv6 has no header checksum. Extension headers are not walked: the
        // next header must be the transport itself, otherwise the checksum is
        // left alone and the packet is still delivered unmodified beyond the
        // address swap.
        update_transport_checksum(packet, IPV6_HEADER, packet[IPV6_NEXT_HEADER], 0, &old, &new);
        Ok(())
    }
}

fn packet_protocol_v4(packet: &[u8]) -> u8 {
    packet[IPV4_PROTOCOL]
}

/// Length of the IPv4 header, or `None` for anything this path must not touch.
fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    let first = *packet.first()?;
    if first >> 4 != IPV4_VERSION {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    (header_len >= IPV4_MIN_HEADER && packet.len() >= header_len).then_some(header_len)
}

/// TCP and UDP fold the addresses into a pseudo-header, so a rewritten address
/// invalidates their checksum too. The checksum field can live in a later IPv4
/// fragment (a minimum-sized first TCP fragment carries only the ports), so the
/// field offset is translated into this fragment instead of assuming it is in
/// the first one. ICMPv4 does not cover the pseudo-header.
fn update_transport_checksum(
    packet: &mut [u8],
    header_len: usize,
    protocol: u8,
    fragment_payload_offset: usize,
    old: &[u8],
    new: &[u8],
) {
    let checksum_offset: usize = match protocol {
        PROTOCOL_TCP => 16,
        PROTOCOL_UDP => 6,
        // ICMPv6, unlike ICMPv4, does cover the pseudo-header.
        PROTOCOL_ICMPV6 => 2,
        // ICMPv4's checksum covers only the ICMP message.
        PROTOCOL_ICMP => return,
        // An unknown upper layer — including an IPv6 extension header — has no
        // checksum this code may claim to fix.
        _ => return,
    };
    let Some(relative_offset) = checksum_offset.checked_sub(fragment_payload_offset) else {
        return;
    };
    let Some(offset) = header_len.checked_add(relative_offset) else {
        return;
    };
    if packet.len() < offset + 2 {
        return;
    }
    let current = read_u16(packet, offset);
    // A zero UDP checksum means "not computed" and must stay that way.
    if protocol == PROTOCOL_UDP && current == 0 {
        return;
    }
    let updated = update_checksum(current, old, new);
    // In UDP an all-zero checksum is the "absent" marker, so the equivalent
    // 0xffff encoding is used instead.
    let updated = if protocol == PROTOCOL_UDP && updated == 0 {
        0xffff
    } else {
        updated
    };
    write_u16(packet, offset, updated);
}

fn fragment_offset(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff
}

/// RFC 1624 incremental update: `HC' = ~(~HC + ~m + m')`.
fn update_checksum(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (old_word, new_word) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        sum += u32::from(!u16::from_be_bytes([old_word[0], old_word[1]]));
        sum += u32::from(u16::from_be_bytes([new_word[0], new_word[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn read_u16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

fn write_u16(packet: &mut [u8], offset: usize, value: u16) {
    packet[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TUN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const PEER_V4: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
    const REMOTE_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    /// RFC 1071 one's-complement sum, computed from scratch. The production code
    /// updates checksums incrementally, so this is an independent check.
    fn internet_checksum(parts: &[&[u8]]) -> u16 {
        let mut sum = 0_u32;
        let mut odd_carry: Option<u8> = None;
        for part in parts {
            let mut bytes = *part;
            if let Some(high) = odd_carry.take()
                && let Some((low, rest)) = bytes.split_first()
            {
                sum += u32::from(u16::from_be_bytes([high, *low]));
                bytes = rest;
            }
            let mut chunks = bytes.chunks_exact(2);
            for chunk in &mut chunks {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
            if let [last] = chunks.remainder() {
                odd_carry = Some(*last);
            }
        }
        if let Some(high) = odd_carry {
            sum += u32::from(u16::from_be_bytes([high, 0]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A UDP/IPv4 datagram with both checksums filled in correctly.
    fn udp_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let header_checksum = internet_checksum(&[&packet[..20]]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let pseudo = [
            source.octets().as_slice(),
            destination.octets().as_slice(),
            &[0, 17],
            &(udp_len as u16).to_be_bytes(),
        ]
        .concat();
        let udp_checksum = internet_checksum(&[&pseudo, &packet[20..]]);
        packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
        packet
    }

    fn header_checksum_is_valid(packet: &[u8]) -> bool {
        internet_checksum(&[&packet[..20]]) == 0
    }

    fn udp_checksum_is_valid(packet: &[u8]) -> bool {
        let udp_len = packet.len() - 20;
        let pseudo = [
            &packet[12..16],
            &packet[16..20],
            &[0, 17][..],
            &(udp_len as u16).to_be_bytes(),
        ]
        .concat();
        internet_checksum(&[&pseudo, &packet[20..]]) == 0
    }

    fn translator() -> AddressTranslator {
        AddressTranslator::new([(TUN_V4.into(), PEER_V4.into())])
    }

    const TUN_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const PEER_V6: Ipv6Addr = Ipv6Addr::new(0xfd08, 0, 0, 0, 0, 0, 0, 2);
    const REMOTE_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 0x1946);

    /// A UDP/IPv6 datagram with a valid checksum. IPv6 has no header checksum,
    /// but UDP's is mandatory there.
    fn udp_packet_v6(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut packet = vec![0_u8; 40 + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());

        packet[40..42].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let pseudo = [
            source.octets().as_slice(),
            destination.octets().as_slice(),
            &(udp_len as u32).to_be_bytes(),
            &[0, 0, 0, 17],
        ]
        .concat();
        let checksum = internet_checksum(&[&pseudo, &packet[40..]]);
        packet[46..48].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn udp_checksum_v6_is_valid(packet: &[u8]) -> bool {
        let udp_len = packet.len() - 40;
        let pseudo = [
            &packet[8..24],
            &packet[24..40],
            &(udp_len as u32).to_be_bytes()[..],
            &[0, 0, 0, 17],
        ]
        .concat();
        internet_checksum(&[&pseudo, &packet[40..]]) == 0
    }

    #[test]
    fn an_ipv6_packet_is_translated_and_its_pseudo_header_checksum_repaired() {
        let translator = AddressTranslator::new([(TUN_V6.into(), PEER_V6.into())]);
        let mut packet = udp_packet_v6(TUN_V6, REMOTE_V6, b"hello v6");
        assert!(udp_checksum_v6_is_valid(&packet));

        assert!(translator.to_tunnel(&mut packet));

        assert_eq!(&packet[8..24], &PEER_V6.octets());
        assert!(
            udp_checksum_v6_is_valid(&packet),
            "IPv6 UDP checksums are mandatory, so a stale one drops the packet at the peer"
        );
    }

    #[test]
    fn a_family_the_tunnel_has_no_address_for_is_refused() {
        let v4_only = AddressTranslator::new([(TUN_V4.into(), PEER_V4.into())]);
        let mut packet = udp_packet_v6(TUN_V6, REMOTE_V6, b"no v6 here");

        assert!(
            !v4_only.to_tunnel(&mut packet),
            "a tunnel without a v6 address must refuse v6 rather than send it untranslated"
        );
    }

    #[test]
    fn an_outbound_packet_takes_the_tunnel_address_and_keeps_its_checksums() {
        let mut packet = udp_packet(TUN_V4, REMOTE_V4, b"hello wireguard");
        assert!(header_checksum_is_valid(&packet));
        assert!(udp_checksum_is_valid(&packet));

        assert!(translator().to_tunnel(&mut packet));

        assert_eq!(&packet[12..16], &PEER_V4.octets());
        assert_eq!(&packet[16..20], &REMOTE_V4.octets());
        assert!(
            header_checksum_is_valid(&packet),
            "the IPv4 header checksum must be repaired after the rewrite"
        );
        assert!(
            udp_checksum_is_valid(&packet),
            "the UDP checksum covers the addresses through the pseudo-header"
        );
    }

    #[test]
    fn an_inbound_packet_is_restored_to_the_tun_address() {
        let mut packet = udp_packet(REMOTE_V4, PEER_V4, b"reply");

        assert!(translator().to_tun(&mut packet));

        assert_eq!(&packet[16..20], &TUN_V4.octets());
        assert!(header_checksum_is_valid(&packet));
        assert!(udp_checksum_is_valid(&packet));
    }

    #[test]
    fn a_packet_from_an_unexpected_address_is_refused_rather_than_rewritten() {
        let stranger = Ipv4Addr::new(192, 168, 1, 5);
        let mut packet = udp_packet(stranger, REMOTE_V4, b"not ours");

        assert!(
            !translator().to_tunnel(&mut packet),
            "only the tun's own address may enter the tunnel; anything else is a leak"
        );
        assert_eq!(&packet[12..16], &stranger.octets());
    }
}
