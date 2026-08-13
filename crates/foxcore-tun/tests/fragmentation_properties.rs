//! Property tests for IPv4 fragments on the tun path.
//!
//! FoxCore does not reassemble: the L3 path rewrites addresses on each fragment
//! and forwards it, and the split decision is taken per fragment. That makes
//! fragmentation an input dimension no example-based test can cover — the shape
//! of the *first* fragment silently decides whether the transport checksum is
//! repaired, and every non-first fragment reaches the classifier stripped of the
//! ports the policy is written in terms of.
//!
//! These tests therefore ask two separate things: does fragmenting a datagram
//! change what the translator produces (it must not), and what exactly does a
//! hostile fragment stream get out of the classifier (pinned, not endorsed).

use std::net::{IpAddr, Ipv4Addr};

use foxcore_tun::{AddressTranslator, FlowKey, PacketRoute, PacketSplitter};
use proptest::prelude::*;

const TUN: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

const IPV4_HEADER: usize = 20;
const MORE_FRAGMENTS: u16 = 0x2000;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// RFC 1071 one's-complement sum computed from scratch, so the incremental
/// updates in the production path are checked against different arithmetic.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn protocol(self) -> u8 {
        match self {
            Self::Tcp => PROTOCOL_TCP,
            Self::Udp => PROTOCOL_UDP,
        }
    }

    fn header_len(self) -> usize {
        match self {
            Self::Tcp => 20,
            Self::Udp => 8,
        }
    }

    /// Offset of the checksum field inside the transport header.
    fn checksum_field(self) -> usize {
        match self {
            Self::Tcp => 16,
            Self::Udp => 6,
        }
    }
}

/// A whole IPv4 datagram with both checksums correct, ready to be fragmented.
fn datagram(
    transport: Transport,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let transport_len = transport.header_len() + payload.len();
    let total_len = IPV4_HEADER + transport_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = transport.protocol();
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());

    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    if transport == Transport::Tcp {
        // Data offset 5, no options; ACK set so the header is not obviously junk.
        packet[32] = 0x50;
        packet[33] = 0x10;
    } else {
        packet[24..26].copy_from_slice(&(transport_len as u16).to_be_bytes());
    }
    packet[IPV4_HEADER + transport.header_len()..].copy_from_slice(payload);

    let header_checksum = internet_checksum(&[&packet[..IPV4_HEADER]]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let pseudo = [
        source.octets().as_slice(),
        destination.octets().as_slice(),
        &[0, transport.protocol()],
        &(transport_len as u16).to_be_bytes(),
    ]
    .concat();
    let checksum = internet_checksum(&[&pseudo, &packet[IPV4_HEADER..]]);
    // In UDP a transmitted zero means "no checksum was computed", so a sender
    // whose sum comes out zero must put 0xffff on the wire instead (RFC 768).
    // Writing the zero made this builder emit a datagram that declares itself
    // unchecked, which the translator then correctly refuses to touch — and the
    // assertion below, which demands a valid checksum, failed on the product for
    // doing the right thing. Found by this property test on a payload whose sum
    // happened to be zero.
    let checksum = match transport {
        Transport::Udp if checksum == 0 => 0xffff,
        _ => checksum,
    };
    let field = IPV4_HEADER + transport.checksum_field();
    packet[field..field + 2].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Split at `cuts` (byte offsets into the IP payload, each a multiple of eight),
/// producing the fragment series a router would emit.
fn fragment(whole: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let payload = &whole[IPV4_HEADER..];
    let mut boundaries: Vec<usize> = cuts
        .iter()
        .copied()
        .filter(|cut| *cut > 0 && *cut < payload.len())
        .collect();
    boundaries.sort_unstable();
    boundaries.dedup();
    boundaries.push(payload.len());

    let mut fragments = Vec::new();
    let mut start = 0;
    for end in boundaries {
        let mut piece = whole[..IPV4_HEADER].to_vec();
        piece.extend_from_slice(&payload[start..end]);
        let total_len = (IPV4_HEADER + (end - start)) as u16;
        piece[2..4].copy_from_slice(&total_len.to_be_bytes());
        let more = if end < payload.len() {
            MORE_FRAGMENTS
        } else {
            0
        };
        piece[6..8].copy_from_slice(&(more | (start as u16 / 8)).to_be_bytes());
        piece[10..12].copy_from_slice(&[0, 0]);
        let checksum = internet_checksum(&[&piece[..IPV4_HEADER]]);
        piece[10..12].copy_from_slice(&checksum.to_be_bytes());
        fragments.push(piece);
        start = end;
    }
    fragments
}

fn translator() -> AddressTranslator {
    AddressTranslator::new([(IpAddr::V4(TUN), IpAddr::V4(PEER))])
}

fn transport_strategy() -> impl Strategy<Value = Transport> {
    prop_oneof![Just(Transport::Tcp), Just(Transport::Udp)]
}

/// Cuts are generated in eight-byte units because IPv4 encodes the fragment
/// offset in units of eight; anything else is not a fragmentation a router can
/// produce, and testing it would prove nothing about the real input space.
fn cuts_strategy() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(1_usize..64, 0..8)
        .prop_map(|units| units.into_iter().map(|unit| unit * 8).collect())
}

/// Proptest's own defaults, except for the two that keep this file out of Miri.
///
/// This is the one test binary in the crate the interpreter can run at all —
/// everything else here needs tokio's I/O driver, and Miri implements no
/// kqueue — and it is also the one most worth running: header arithmetic over
/// borrowed slices, offsets computed from attacker-shaped input, and a
/// checksum walked two different ways. Provenance and out-of-bounds reads are
/// exactly what an interpreter sees and an assertion does not.
///
/// What stopped it was harness machinery, not the property. Failure persistence
/// resolves `.proptest-regressions` against the working directory, and `getcwd`
/// is not available under Miri's isolation — which aborts the whole binary on
/// the first case. And 256 interpreted cases per property is minutes of wall
/// clock apiece; sixteen still crosses every branch this strategy generates,
/// while the native run keeps the full count and the regression file.
fn config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if cfg!(miri) {
        config.cases = 16;
        config.failure_persistence = None;
    }
    config
}

proptest! {
    #![proptest_config(config())]

    /// Fragmentation is a transport-invisible transformation: whatever the
    /// translator does to a whole datagram, it must do to the fragments of that
    /// datagram, or the peer reassembles a packet the sender never wrote.
    #[test]
    fn fragmenting_a_datagram_does_not_change_what_the_translator_produces(
        transport in transport_strategy(),
        source_port in 1_u16..65535,
        destination_port in 1_u16..65535,
        payload in prop::collection::vec(any::<u8>(), 0..300),
        cuts in cuts_strategy(),
    ) {
        let original = datagram(transport, TUN, REMOTE, source_port, destination_port, &payload);

        let mut whole = original.clone();
        prop_assert!(translator().to_tunnel(&mut whole));

        let mut reassembled = Vec::new();
        for mut piece in fragment(&original, &cuts) {
            prop_assert!(
                translator().to_tunnel(&mut piece),
                "every fragment carries the tun's source address and must be translated"
            );
            prop_assert_eq!(
                internet_checksum(&[&piece[..IPV4_HEADER]]),
                0,
                "the header checksum of a translated fragment must still verify"
            );
            reassembled.extend_from_slice(&piece[IPV4_HEADER..]);
        }

        prop_assert_eq!(
            reassembled,
            whole[IPV4_HEADER..].to_vec(),
            "fragmented and unfragmented translation of the same datagram diverged"
        );
    }

    /// Same guarantee on the return path, where the destination is rewritten.
    #[test]
    fn fragmenting_an_inbound_datagram_does_not_change_what_the_translator_produces(
        transport in transport_strategy(),
        source_port in 1_u16..65535,
        destination_port in 1_u16..65535,
        payload in prop::collection::vec(any::<u8>(), 0..300),
        cuts in cuts_strategy(),
    ) {
        let original = datagram(transport, REMOTE, PEER, source_port, destination_port, &payload);

        let mut whole = original.clone();
        prop_assert!(translator().to_tun(&mut whole));

        let mut reassembled = Vec::new();
        for mut piece in fragment(&original, &cuts) {
            prop_assert!(translator().to_tun(&mut piece));
            reassembled.extend_from_slice(&piece[IPV4_HEADER..]);
        }

        prop_assert_eq!(reassembled, whole[IPV4_HEADER..].to_vec());
    }

    /// UDP alone, to separate "fragmentation is handled" from the TCP defect the
    /// test above records. UDP's checksum sits inside the first eight payload
    /// bytes, so the smallest legal first fragment still carries it.
    #[test]
    fn a_fragmented_udp_datagram_survives_translation_at_every_fragment_size(
        source_port in 1_u16..65535,
        destination_port in 1_u16..65535,
        payload in prop::collection::vec(any::<u8>(), 0..300),
        cuts in cuts_strategy(),
    ) {
        let original = datagram(Transport::Udp, TUN, REMOTE, source_port, destination_port, &payload);
        let mut whole = original.clone();
        prop_assert!(translator().to_tunnel(&mut whole));

        let mut reassembled = Vec::new();
        for mut piece in fragment(&original, &cuts) {
            prop_assert!(translator().to_tunnel(&mut piece));
            reassembled.extend_from_slice(&piece[IPV4_HEADER..]);
        }
        prop_assert_eq!(reassembled, whole[IPV4_HEADER..].to_vec());

        let transport_len = whole.len() - IPV4_HEADER;
        let pseudo = [
            PEER.octets().as_slice(),
            REMOTE.octets().as_slice(),
            &[0, PROTOCOL_UDP],
            &(transport_len as u16).to_be_bytes(),
        ]
        .concat();
        prop_assert_eq!(
            internet_checksum(&[&pseudo, &whole[IPV4_HEADER..]]),
            0,
            "the peer verifies this checksum after reassembly and drops the datagram if it is stale"
        );
    }

    /// Overlapping, reordered, duplicated and truncated fragments are what an
    /// evasion tool emits. Nothing here may panic — a panic on the tun reader is
    /// the whole VPN going down — and the classifier table must stay bounded no
    /// matter how many distinct-looking fragments arrive.
    #[test]
    fn a_hostile_fragment_stream_neither_panics_nor_grows_the_classifier(
        headers in prop::collection::vec(
            (
                any::<u8>(),          // version and IHL nibble
                any::<u16>(),         // total length, deliberately inconsistent
                any::<u16>(),         // flags and fragment offset
                prop_oneof![Just(0_u8), Just(1), Just(6), Just(17), Just(58), any::<u8>()],
                prop::collection::vec(any::<u8>(), 0..80),
                0_usize..64,          // truncation point
            ),
            1..64,
        ),
    ) {
        let mut splitter = PacketSplitter::new(8, 30_000);
        for (first, total_len, flags, protocol, body, truncate) in headers {
            let mut packet = vec![0_u8; IPV4_HEADER];
            packet[0] = first;
            packet[2..4].copy_from_slice(&total_len.to_be_bytes());
            packet[6..8].copy_from_slice(&flags.to_be_bytes());
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&TUN.octets());
            packet[16..20].copy_from_slice(&REMOTE.octets());
            packet.extend_from_slice(&body);
            packet.truncate(packet.len().saturating_sub(truncate).max(1));

            let length_before = packet.len();
            let _ = translator().to_tunnel(&mut packet);
            let _ = translator().to_tun(&mut packet);
            let _ = FlowKey::from_packet(&packet);
            let _ = splitter.route(&packet, 0, |_| PacketRoute::Tunnel);

            prop_assert_eq!(
                packet.len(),
                length_before,
                "translation is in place and must never resize the packet"
            );
            prop_assert!(
                splitter.len() <= 8,
                "a fragment flood must not grow the split table past its capacity, got {}",
                splitter.len()
            );
        }
    }

    /// Pinned, not endorsed. `FlowKey` gives every non-first fragment port zero,
    /// so all non-first fragments between one address pair on one protocol share
    /// a single 5-tuple — and therefore a single cached split decision, for the
    /// whole idle timeout. See the crate-level note in the result of this suite.
    #[test]
    fn non_first_fragments_of_unrelated_flows_share_one_split_decision(
        first_port in 1_u16..30000,
        second_port in 30001_u16..65535,
        payload in prop::collection::vec(any::<u8>(), 16..200),
    ) {
        let allowed = datagram(Transport::Udp, TUN, REMOTE, first_port, 443, &payload);
        let other = datagram(Transport::Udp, TUN, REMOTE, second_port, 443, &payload);
        let allowed_tail = fragment(&allowed, &[8]).remove(1);
        let other_tail = fragment(&other, &[8]).remove(1);

        prop_assert_eq!(
            FlowKey::from_packet(&allowed_tail),
            FlowKey::from_packet(&other_tail),
            "two unrelated flows must be distinguishable, yet their non-first fragments are not"
        );

        let mut splitter = PacketSplitter::new(64, 30_000);
        prop_assert_eq!(
            splitter.route(&allowed_tail, 0, |_| PacketRoute::Tunnel),
            PacketRoute::Tunnel
        );
        let mut decided_again = false;
        let inherited = splitter.route(&other_tail, 0, |_| {
            decided_again = true;
            PacketRoute::Block
        });
        prop_assert!(
            !decided_again,
            "the second flow was decided on its own merits, so this pin is stale and can be deleted"
        );
        prop_assert_eq!(
            inherited,
            PacketRoute::Tunnel,
            "the second flow's fragments inherit the first flow's verdict"
        );
    }
}
