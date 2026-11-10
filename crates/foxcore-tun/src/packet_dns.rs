//! Scoped DNS observations and no-cache replies from the authenticated packet-tunnel path.
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use foxcore_dns::{DnsCache, DnsIdentity};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use tokio_util::sync::CancellationToken;

use crate::flow::FlowPolicyStore;
use crate::packet_dns_ttl::{RewriteError, TcpResponseRewriter, uncacheable_udp_response};
use crate::split::FlowKey;

const MAX_FLOWS: usize = 128;
const MAX_RESOLVERS: usize = 128;
const MAX_QUERY_BYTES: usize = 4_096;
const MAX_QUERIES: usize = 16;
const QUERY_LIFETIME: Duration = Duration::from_secs(15);
const FLOW_IDLE: Duration = Duration::from_secs(60);

#[cfg_attr(test, derive(Default))]
pub(crate) struct PacketDnsTracker {
    policy: Option<Arc<FlowPolicyStore>>,
    resolvers: Mutex<ResolverHistory>,
    flows: Mutex<HashMap<FlowKey, Session>>,
}
#[derive(Default)]
struct ResolverHistory {
    addresses: HashSet<IpAddr>,
    refused: bool,
}
struct Scope {
    current: Vec<IpAddr>,
    known: HashSet<IpAddr>,
    authority: Option<[u8; 32]>,
    requires_identity: bool,
    blocked: bool,
    wildcard: bool,
}
struct Session {
    authority: [u8; 32],
    identity: Option<DnsIdentity>,
    cache: Arc<DnsCache>,
    revoked: CancellationToken,
    touched: Instant,
    pending: HashMap<u16, (Option<Vec<u8>>, Instant)>,
    uplink: Stream,
    downlink: TcpResponseRewriter,
    response_refused: bool,
}
#[derive(Default)]
struct Stream {
    next: Option<u32>,
    bytes: Vec<u8>,
    recent: VecDeque<u8>,
    refused: bool,
}
struct Frame<'a> {
    key: FlowKey,
    payload: &'a [u8],
    payload_offset: usize,
    transport_offset: usize,
    version: u8,
    tcp: Option<(u32, bool, bool, bool)>,
}

impl PacketDnsTracker {
    pub(crate) fn for_policy(policy: Arc<FlowPolicyStore>) -> Self {
        Self {
            policy: Some(policy),
            resolvers: Mutex::default(),
            flows: Mutex::default(),
        }
    }

    fn scope(&self) -> Scope {
        let Some(policy) = &self.policy else {
            return Scope {
                current: Vec::new(),
                known: HashSet::new(),
                authority: Some([0; 32]),
                requires_identity: false,
                blocked: false,
                wildcard: true,
            };
        };
        let snapshot = policy.current.load_full();
        let current = snapshot.dns_config.packet_resolvers.clone();
        let mut history = self.resolvers.lock().unwrap_or_else(|e| e.into_inner());
        for address in &current {
            if !history.addresses.contains(address) && history.addresses.len() >= MAX_RESOLVERS {
                history.refused = true;
                break;
            }
            history.addresses.insert(*address);
        }
        Scope {
            current,
            known: history.addresses.clone(),
            authority: policy.packet_dns_authority(&snapshot),
            requires_identity: snapshot.routes.requires_domain_hints()
                || snapshot.routes.requires_identity(),
            blocked: history.refused
                || snapshot.routes.kill_switch()
                || snapshot.revocation.is_cancelled(),
            wildcard: false,
        }
    }

    fn live(&self, key: &FlowKey, session: &Session) -> bool {
        if session.revoked.is_cancelled() || session.touched.elapsed() >= FLOW_IDLE {
            return false;
        }
        let Some(policy) = &self.policy else {
            return true;
        };
        let current = policy.current.load_full();
        !current.routes.kill_switch()
            && !current.revocation.is_cancelled()
            && current
                .dns_config
                .packet_resolvers
                .contains(&key.destination)
            && policy.packet_dns_authority(&current) == Some(session.authority)
            && (session.identity.is_some()
                || !(current.routes.requires_domain_hints() || current.routes.requires_identity()))
    }

    pub(crate) fn register(
        &self,
        key: FlowKey,
        identity: impl Into<Option<DnsIdentity>>,
        cache: Arc<DnsCache>,
        revoked: CancellationToken,
    ) -> bool {
        let identity = identity.into();
        let scope = self.scope();
        if scope.blocked
            || revoked.is_cancelled()
            || (scope.requires_identity && identity.is_none())
            || key.destination_port != 53
            || !matches!(key.protocol, 6 | 17)
            || (!scope.wildcard && !scope.current.contains(&key.destination))
        {
            return false;
        }
        let Some(authority) = scope.authority else {
            return false;
        };
        let now = Instant::now();
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        flows.retain(|_, session| {
            !session.revoked.is_cancelled() && now.duration_since(session.touched) < FLOW_IDLE
        });
        if let Some(session) = flows.get_mut(&key)
            && session.authority == authority
            && session.identity == identity
            && Arc::ptr_eq(&session.cache, &cache)
            && !session.revoked.is_cancelled()
        {
            session.touched = now;
            return true;
        }
        if !flows.contains_key(&key) && flows.len() >= MAX_FLOWS {
            return false;
        }
        flows.insert(
            key,
            Session {
                authority,
                identity,
                cache,
                revoked,
                touched: now,
                pending: HashMap::new(),
                uplink: Stream::default(),
                downlink: TcpResponseRewriter::default(),
                response_refused: false,
            },
        );
        true
    }

    pub(crate) fn query(&self, packet: &[u8]) -> bool {
        let Some(resolver) = resolver_candidate(packet, false) else {
            return true;
        };
        let scope = self.scope();
        if !scope.wildcard && !scope.current.contains(&resolver) && !scope.known.contains(&resolver)
        {
            return true;
        }
        if scope.blocked {
            return false;
        }
        let Some(frame) = frame(packet) else {
            return false;
        };
        let key = frame.key;
        let now = Instant::now();
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = flows.get_mut(&key) else {
            return false;
        };
        if scope.authority != Some(session.authority) || !self.live(&key, session) {
            return false;
        }
        if frame.tcp.is_some_and(|(_, _, _, rst)| rst) {
            flows.remove(&key);
            return true;
        }
        if frame.tcp.is_some_and(|(_, syn, _, _)| syn) {
            session.pending.clear();
            session.downlink.reset();
            session.response_refused = false;
        }
        session.touched = now;
        session.pending.retain(|_, (_, expiry)| *expiry > now);
        let messages = match frame.tcp {
            Some((sequence, syn, _, _)) => session.uplink.messages(sequence, syn, frame.payload),
            None => vec![frame.payload.to_vec()],
        };
        if session.uplink.refused {
            return false;
        }
        for message in messages {
            if !valid_query(&message) {
                if frame.tcp.is_some() {
                    session.uplink.refused = true;
                }
                return false;
            }
            let id = u16::from_be_bytes([message[0], message[1]]);
            if let Some((query, expiry)) = session.pending.get_mut(&id) {
                if query.as_ref() != Some(&message) {
                    *query = None;
                    if frame.tcp.is_some() {
                        session.uplink.refused = true;
                    }
                    return false;
                }
                *expiry = now + QUERY_LIFETIME;
            } else {
                if session.pending.len() >= MAX_QUERIES {
                    if frame.tcp.is_some() {
                        session.uplink.refused = true;
                    }
                    return false;
                }
                session
                    .pending
                    .insert(id, (Some(message), now + QUERY_LIFETIME));
            }
        }
        self.live(&key, session)
    }

    /// Runs only after peer authentication and TUN address restoration; false drops the packet.
    pub(crate) fn response_for_tun(&self, packet: &mut BytesMut) -> bool {
        let Some(resolver) = resolver_candidate(packet, true) else {
            return true;
        };
        let scope = self.scope();
        if !scope.wildcard && !scope.current.contains(&resolver) && !scope.known.contains(&resolver)
        {
            return true;
        }
        if scope.blocked {
            return false;
        }
        let Some(frame) = frame(packet) else {
            return false;
        };
        let key = FlowKey {
            source: frame.key.destination,
            destination: frame.key.source,
            source_port: frame.key.destination_port,
            destination_port: frame.key.source_port,
            protocol: frame.key.protocol,
        };
        let incoming_key = frame.key;
        let tcp = frame.tcp;
        let payload_offset = frame.payload_offset;
        let transport_offset = frame.transport_offset;
        let version = frame.version;
        let original_payload = frame.payload.to_vec();
        let now = Instant::now();
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let Some(session) = flows.get_mut(&key) else {
            return false;
        };
        if scope.authority != Some(session.authority)
            || !self.live(&key, session)
            || session.response_refused
            || session.downlink.refused()
        {
            return false;
        }
        if tcp.is_some_and(|(_, _, _, rst)| rst) {
            flows.remove(&key);
            return true;
        }
        session.pending.retain(|_, (_, expiry)| *expiry > now);
        let mut payload = original_payload.clone();
        let originals = if let Some((sequence, syn, _, _)) = tcp {
            match session.downlink.rewrite(sequence, syn, &mut payload) {
                Ok(messages) => messages,
                Err(_) => return false,
            }
        } else {
            vec![original_payload.clone()]
        };
        let mut paired = Vec::new();
        let mut ids = HashSet::new();
        for original in originals {
            let Some(id) = original.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
                session.response_refused |= tcp.is_some();
                return false;
            };
            let Some((Some(query), _)) = session.pending.get(&id) else {
                session.response_refused |= tcp.is_some();
                return false;
            };
            if !ids.insert(id) || !paired_question(query, &original) {
                session.response_refused |= tcp.is_some();
                return false;
            }
            if tcp.is_none() {
                payload = match uncacheable_udp_response(&original) {
                    Ok(rewritten) => rewritten,
                    Err(RewriteError::Truncated) => match safe_truncated(query, &original) {
                        Some(answer) => answer,
                        None => return false,
                    },
                    Err(_) => return false,
                };
            }
            paired.push((id, query.clone(), original));
        }
        let Some(rewritten) = rewrite_packet(
            packet,
            incoming_key,
            version,
            transport_offset,
            payload_offset,
            &payload,
        ) else {
            session.response_refused |= tcp.is_some();
            return false;
        };
        if !self.live(&key, session) {
            return false;
        }
        for (id, query, original) in paired {
            if let Some(identity) = &session.identity {
                session.cache.learn_packet_route_hints(
                    session.authority,
                    &query,
                    &original,
                    identity,
                );
            }
            if original[2] & 2 == 0 {
                session.pending.remove(&id);
            }
        }
        session.touched = now;
        *packet = rewritten;
        if tcp.is_some_and(|(_, _, fin, _)| fin) {
            flows.remove(&key);
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn response(&self, packet: &[u8]) {
        let mut packet = BytesMut::from(packet);
        self.response_for_tun(&mut packet);
    }
}

fn resolver_candidate(packet: &[u8], response: bool) -> Option<IpAddr> {
    let (source, destination, protocol, offset, fragmented) = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let source = IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap());
            let destination = IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap());
            let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
            (
                source,
                destination,
                packet[9],
                usize::from(packet[0] & 15) * 4,
                fragment,
            )
        }
        Some(6) if packet.len() >= 40 => {
            let source = IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
            let destination = IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            (source, destination, packet[6], 40, false)
        }
        _ => return None,
    };
    let resolver = if response { source } else { destination };
    if fragmented || matches!(protocol, 0 | 43 | 44 | 50 | 51 | 60) {
        return Some(resolver);
    }
    if !matches!(protocol, 6 | 17) {
        return None;
    }
    if offset < 20 || offset + 4 > packet.len() {
        return Some(resolver);
    }
    let at = offset + if response { 0 } else { 2 };
    (u16::from_be_bytes([packet[at], packet[at + 1]]) == 53).then_some(resolver)
}

fn question(message: &[u8]) -> Option<(usize, Vec<u8>)> {
    if message.len() < 12 || message[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12;
    let mut canonical = Vec::new();
    loop {
        let length = usize::from(*message.get(at)?);
        if length > 63 {
            return None;
        }
        canonical.push(length as u8);
        at += 1;
        if at - 12 + length > 255 {
            return None;
        }
        if length == 0 {
            break;
        }
        for byte in message.get(at..at + length)? {
            canonical.push(byte.to_ascii_lowercase());
        }
        at += length;
    }
    canonical.extend_from_slice(message.get(at..at + 4)?);
    Some((at + 4, canonical))
}

fn valid_query(message: &[u8]) -> bool {
    if !(12..=MAX_QUERY_BYTES).contains(&message.len())
        || message[2] & 0xfe != 0
        || message[3] & !0x30 != 0
        || message[6..10] != [0; 4]
    {
        return false;
    }
    let Some((mut at, _)) = question(message) else {
        return false;
    };
    let count = u16::from_be_bytes([message[10], message[11]]);
    if count > 1 {
        return false;
    }
    for _ in 0..count {
        if message.get(at) != Some(&0) {
            return false;
        }
        at += 1;
        let Some(header) = message.get(at..at + 10) else {
            return false;
        };
        if u16::from_be_bytes([header[0], header[1]]) != 41 {
            return false;
        }
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        at += 10 + length;
        if at > message.len() {
            return false;
        }
    }
    at == message.len()
}

fn paired_question(query: &[u8], response: &[u8]) -> bool {
    if response.len() < 12
        || response[0..2] != query[0..2]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != 0
    {
        return false;
    }
    matches!((question(query), question(response)), (Some((_, a)), Some((_, b))) if a == b)
}

fn safe_truncated(query: &[u8], response: &[u8]) -> Option<Vec<u8>> {
    if !valid_query(query) || !paired_question(query, response) || response[2] & 2 == 0 {
        return None;
    }
    let (end, _) = question(query)?;
    let mut result = response[..12].to_vec();
    result[2] |= 0x82;
    result[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    result.extend_from_slice(&query[12..end]);
    if let Some(opt) = truncated_opt(response)? {
        result[11] = 1;
        result.extend_from_slice(&opt);
    }
    Some(result)
}

fn truncated_opt(response: &[u8]) -> Option<Option<Vec<u8>>> {
    let additional = u16::from_be_bytes([response[10], response[11]]);
    let mut complete = response.to_vec();
    complete[2] &= !2;
    match uncacheable_udp_response(&complete) {
        Ok(_) => {}
        Err(RewriteError::UnsupportedAuthentication) => return None,
        Err(_) if additional != 0 => return None,
        Err(_) => return Some(None),
    }
    if additional == 0 {
        return Some(None);
    }
    let (mut at, _) = question(response)?;
    let mut opt = None;
    for (section, count) in [
        u16::from_be_bytes([response[6], response[7]]),
        u16::from_be_bytes([response[8], response[9]]),
        additional,
    ]
    .into_iter()
    .enumerate()
    {
        for _ in 0..count {
            let name = at;
            at = encoded_name_end(response, at)?;
            let header = response.get(at..at + 10)?;
            let kind = u16::from_be_bytes([header[0], header[1]]);
            let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
            if kind == 41 {
                if section != 2 || opt.is_some() || at != name + 1 || response[name] != 0 {
                    return None;
                }
                // Keep extended RCODE/version/flags; dropping OPT could forge NoError.
                let mut record = response.get(name..at + 10)?.to_vec();
                let len = record.len();
                record[len - 2..].fill(0);
                opt = Some(record);
            }
            at = at.checked_add(10 + length)?;
            if at > response.len() {
                return None;
            }
        }
    }
    (at == response.len()).then_some(opt)
}

fn encoded_name_end(message: &[u8], mut at: usize) -> Option<usize> {
    let start = at;
    loop {
        let length = *message.get(at)?;
        match length {
            0 => return Some(at + 1),
            1..=63 => {
                at = at.checked_add(usize::from(length) + 1)?;
                if at - start >= 255 || at > message.len() {
                    return None;
                }
            }
            0xc0..=0xff => {
                message.get(at + 1)?;
                return Some(at + 2);
            }
            _ => return None,
        }
    }
}

fn rewrite_packet(
    original: &[u8],
    key: FlowKey,
    version: u8,
    transport_offset: usize,
    payload_offset: usize,
    payload: &[u8],
) -> Option<BytesMut> {
    let length = payload_offset.checked_add(payload.len())?;
    if (version == 4 && length > u16::MAX as usize)
        || (version == 6 && length.checked_sub(40)? > u16::MAX as usize)
    {
        return None;
    }
    let mut packet = BytesMut::from(original.get(..payload_offset)?);
    packet.extend_from_slice(payload);
    match version {
        4 => {
            let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
            ip.set_total_len(length as u16);
            ip.fill_checksum();
        }
        6 => {
            let mut ip = Ipv6Packet::new_unchecked(&mut packet[..]);
            ip.set_payload_len((length - 40) as u16);
        }
        _ => return None,
    }
    let source = IpAddress::from(key.source);
    let destination = IpAddress::from(key.destination);
    match key.protocol {
        17 => {
            let mut udp = UdpPacket::new_unchecked(&mut packet[transport_offset..]);
            udp.set_len((8 + payload.len()) as u16);
            udp.fill_checksum(&source, &destination);
        }
        6 => {
            if length != original.len() {
                return None;
            }
            let mut tcp = TcpPacket::new_unchecked(&mut packet[transport_offset..]);
            tcp.fill_checksum(&source, &destination);
        }
        _ => return None,
    }
    Some(packet)
}

impl Stream {
    fn messages(&mut self, sequence: u32, syn: bool, payload: &[u8]) -> Vec<Vec<u8>> {
        if syn {
            // A new TCP handshake replaces any previous transaction on the tuple.
            self.next = Some(sequence.wrapping_add(1));
            self.bytes.clear();
            self.recent.clear();
            self.refused = false;
        }
        if self.refused || payload.is_empty() {
            return Vec::new();
        }
        let sequence = sequence.wrapping_add(u32::from(syn));
        let Some(next) = self.next else {
            self.refused = true;
            return Vec::new();
        };
        let offset = next.wrapping_sub(sequence) as i32;
        // Retransmissions may overlap already observed bytes; gaps never create a partial binding.
        if offset < 0 {
            self.refused = true;
            self.bytes.clear();
            return Vec::new();
        }
        let skip = offset as usize;
        let overlap = skip.min(payload.len());
        // Verify old and partially overlapping retransmissions before forwarding.
        if skip > self.recent.len()
            || !self
                .recent
                .iter()
                .skip(self.recent.len() - skip)
                .take(overlap)
                .copied()
                .eq(payload[..overlap].iter().copied())
        {
            self.refused = true;
            self.bytes.clear();
            return Vec::new();
        }
        if skip >= payload.len() {
            return Vec::new();
        }
        let fresh = &payload[skip..];
        if self.bytes.len() + fresh.len() > MAX_QUERY_BYTES + 2 {
            self.refused = true;
            self.bytes.clear();
            return Vec::new();
        }
        self.next = Some(next.wrapping_add(fresh.len() as u32));
        self.bytes.extend_from_slice(fresh);
        self.recent.extend(fresh);
        while self.recent.len() > 4_096 {
            self.recent.pop_front();
        }
        let mut result = Vec::new();
        while self.bytes.len() >= 2 {
            let size = usize::from(u16::from_be_bytes([self.bytes[0], self.bytes[1]]));
            if !(12..=MAX_QUERY_BYTES).contains(&size) {
                self.refused = true;
                self.bytes.clear();
                break;
            }
            if self.bytes.len() < size + 2 {
                break;
            }
            result.push(self.bytes[2..size + 2].to_vec());
            self.bytes.drain(..size + 2);
        }
        result
    }
}

fn frame(packet: &[u8]) -> Option<Frame<'_>> {
    let (source, destination, protocol, payload, transport_offset, version) =
        match packet.first()? >> 4 {
            4 => {
                let ip = Ipv4Packet::new_checked(packet).ok()?;
                if !ip.verify_checksum()
                    || ip.more_frags()
                    || ip.frag_offset() != 0
                    || usize::from(ip.total_len()) != packet.len()
                {
                    return None;
                }
                (
                    IpAddress::Ipv4(ip.src_addr()),
                    IpAddress::Ipv4(ip.dst_addr()),
                    ip.next_header(),
                    ip.payload(),
                    usize::from(ip.header_len()),
                    4,
                )
            }
            6 => {
                let ip = Ipv6Packet::new_checked(packet).ok()?;
                // Extension/fragment headers are not guessed through.
                if 40 + usize::from(ip.payload_len()) != packet.len() {
                    return None;
                }
                (
                    IpAddress::Ipv6(ip.src_addr()),
                    IpAddress::Ipv6(ip.dst_addr()),
                    ip.next_header(),
                    ip.payload(),
                    40,
                    6,
                )
            }
            _ => return None,
        };
    let mut key = FlowKey {
        source: source.into(),
        destination: destination.into(),
        source_port: 0,
        destination_port: 0,
        protocol: 0,
    };
    match protocol {
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload).ok()?;
            if usize::from(udp.len()) != payload.len() {
                return None;
            }
            if (matches!(source, IpAddress::Ipv6(_)) && udp.checksum() == 0)
                || !udp.verify_checksum(&source, &destination)
            {
                return None;
            }
            key.source_port = udp.src_port();
            key.destination_port = udp.dst_port();
            key.protocol = 17;
            Some(Frame {
                key,
                payload: udp.payload(),
                payload_offset: transport_offset + 8,
                transport_offset,
                version,
                tcp: None,
            })
        }
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload).ok()?;
            if !tcp.verify_checksum(&source, &destination) {
                return None;
            }
            key.source_port = tcp.src_port();
            key.destination_port = tcp.dst_port();
            key.protocol = 6;
            Some(Frame {
                key,
                payload: tcp.payload(),
                payload_offset: transport_offset + usize::from(tcp.header_len()),
                transport_offset,
                version,
                tcp: Some((tcp.seq_number().0 as u32, tcp.syn(), tcp.fin(), tcp.rst())),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
        bytes
    }
    fn answer(query: &[u8]) -> Vec<u8> {
        let mut bytes = query.to_vec();
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
        bytes
    }
    fn udp(payload: &[u8], response: bool) -> Vec<u8> {
        let (src, dst, sport, dport) = if response {
            ([10, 8, 0, 1], [10, 0, 0, 2], 53, 44000)
        } else {
            ([10, 0, 0, 2], [10, 8, 0, 1], 44000, 53)
        };
        let builder = PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
        let mut bytes = Vec::new();
        builder.write(&mut bytes, payload).unwrap();
        bytes
    }
    #[test]
    fn packet_dns_answers_require_query_identity_resolver_and_live_policy() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(32));
        let owner = DnsIdentity::new(10001, vec!["app".into()]);
        let other = DnsIdentity::new(10002, vec!["app2".into()]);
        let query = query(7, "a.org");
        let answer = answer(&query);
        let request = udp(&query, false);
        let response = udp(&answer, true);
        let key = FlowKey::from_packet(&request).unwrap();
        let token = CancellationToken::new();
        tracker.register(key, owner.clone(), cache.clone(), token.clone());
        tracker.response(&response);
        assert!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .is_none()
        );
        tracker.query(&request);
        let mut wrong = response.clone();
        wrong[12] = 11;
        tracker.response(&wrong);
        assert!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .is_none()
        );
        tracker.response(&response);
        assert_eq!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .unwrap(),
            ["a.org"]
        );
        assert!(
            cache
                .packet_route_hints([0; 32], &other, "203.0.113.9".parse().unwrap())
                .is_none()
        );
        let fresh = Arc::new(DnsCache::new(32));
        tracker.register(key, owner.clone(), fresh.clone(), token.clone());
        tracker.query(&request);
        token.cancel();
        tracker.response(&response);
        assert!(
            fresh
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .is_none()
        );
    }
    #[test]
    fn packet_dns_reused_tuple_and_ambiguous_transaction_cannot_grant_permission() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(32));
        let first = DnsIdentity::new(1, vec![]);
        let second = DnsIdentity::new(2, vec![]);
        let query = query(7, "a.org");
        let request = udp(&query, false);
        let key = FlowKey::from_packet(&request).unwrap();
        tracker.register(key, first, cache.clone(), CancellationToken::new());
        tracker.query(&request);
        tracker.register(key, second.clone(), cache.clone(), CancellationToken::new());
        tracker.response(&udp(&answer(&query), true));
        assert!(
            cache
                .packet_route_hints([0; 32], &second, "203.0.113.9".parse().unwrap())
                .is_none()
        );
        tracker.query(&request);
        tracker.query(&udp(&super::tests::query(7, "b.com"), false));
        tracker.response(&udp(&answer(&query), true));
        assert!(
            cache
                .packet_route_hints([0; 32], &second, "203.0.113.9".parse().unwrap())
                .is_none()
        );
    }
    #[test]
    fn packet_dns_ipv6_requires_a_valid_transport_checksum() {
        let query = query(9, "a.org");
        let source = "fd00::2".parse::<std::net::Ipv6Addr>().unwrap();
        let resolver = "fd00::53".parse::<std::net::Ipv6Addr>().unwrap();
        let mut request = Vec::new();
        PacketBuilder::ipv6(source.octets(), resolver.octets(), 64)
            .udp(44000, 53)
            .write(&mut request, &query)
            .unwrap();
        let mut response = Vec::new();
        PacketBuilder::ipv6(resolver.octets(), source.octets(), 64)
            .udp(53, 44000)
            .write(&mut response, &answer(&query))
            .unwrap();
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let owner = DnsIdentity::new(1, vec![]);
        tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            owner.clone(),
            cache.clone(),
            CancellationToken::new(),
        );
        tracker.query(&request);
        let mut invalid = response.clone();
        invalid[46] = 0;
        invalid[47] = 0;
        tracker.response(&invalid);
        assert!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .is_none()
        );
        tracker.response(&response);
        assert_eq!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .unwrap(),
            ["a.org"]
        );
        let mut corrupt = response;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(frame(&corrupt).is_none());
    }

    #[test]
    fn packet_dns_tcp_framing_handles_segmentation_retransmission_and_refuses_gaps() {
        let mut stream = Stream::default();
        let message = query(8, "a.org");
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&message);
        assert!(stream.messages(100, true, &[]).is_empty());
        assert!(stream.messages(101, false, &framed[..5]).is_empty());
        assert!(stream.messages(101, false, &framed[..5]).is_empty());
        assert_eq!(
            stream.messages(106, false, &framed[5..]),
            vec![message.clone()]
        );
        stream.messages(200, true, &[]);
        stream.messages(202, false, &framed);
        assert!(stream.messages(201, false, &framed).is_empty());
        assert!(stream.refused);
        let mut stream = Stream::default();
        stream.messages(100, true, &[]);
        stream.messages(101, false, &framed[..5]);
        assert_eq!(stream.messages(103, false, &framed[2..]), vec![message]);
        let mut stream = Stream::default();
        stream.messages(100, true, &[]);
        stream.messages(101, false, &framed[..5]);
        let mut conflicting = framed[2..].to_vec();
        conflicting[0] ^= 1;
        assert!(stream.messages(103, false, &conflicting).is_empty());
        assert!(stream.refused);
    }

    #[test]
    fn packet_dns_tun_reply_has_zero_wire_ttl_valid_checksums_and_original_uid_fact() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let owner = DnsIdentity::new(1, vec![]);
        let q = query(17, "MiXeD.Example");
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            owner.clone(),
            cache.clone(),
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let original = answer(&q);
        let mut reply = BytesMut::from(udp(&original, true).as_slice());
        assert!(tracker.response_for_tun(&mut reply));
        let rewritten = frame(&reply).expect("valid rewritten IP and UDP checksum");
        assert_eq!(
            &rewritten.payload[rewritten.payload.len() - 10..rewritten.payload.len() - 6],
            &[0; 4]
        );
        assert_eq!(
            &original[original.len() - 10..original.len() - 6],
            &60_u32.to_be_bytes()
        );
        assert_eq!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .unwrap(),
            ["mixed.example"]
        );
        assert!(
            cache
                .route_hints(&owner, "203.0.113.9".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn packet_dns_original_zero_ttl_is_not_promoted_to_a_binding() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let owner = DnsIdentity::new(1, vec![]);
        let q = query(7, "a.org");
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            owner.clone(),
            cache.clone(),
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut original = answer(&q);
        let at = original.len() - 10;
        original[at..at + 4].fill(0);
        let mut reply = BytesMut::from(udp(&original, true).as_slice());
        assert!(tracker.response_for_tun(&mut reply));
        assert!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn packet_dns_truncated_udp_uses_original_question_case_lengths_and_rcode() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let q = query(7, "MiXeD.Example");
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            None,
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut truncated = answer(&q);
        truncated[2] |= 2;
        truncated[3] = 0x85;
        truncated.truncate(q.len() + 3);
        let mut reply = BytesMut::from(udp(&truncated, true).as_slice());
        assert!(tracker.response_for_tun(&mut reply));
        let frame = frame(&reply).expect("normalized lengths and checksums");
        assert_eq!(frame.payload.len(), q.len());
        assert_eq!(&frame.payload[12..], &q[12..]);
        assert_eq!(frame.payload[3] & 15, 5);
        assert_eq!(frame.payload[2] & 0x82, 0x82);
        assert_eq!(&frame.payload[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn packet_dns_untracked_expired_or_corrupt_selected_reply_is_dropped() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let q = query(7, "a.org");
        let request = udp(&q, false);
        let key = FlowKey::from_packet(&request).unwrap();
        let response = udp(&answer(&q), true);
        assert!(!tracker.response_for_tun(&mut BytesMut::from(response.as_slice())));
        assert!(tracker.register(
            key,
            DnsIdentity::new(1, vec![]),
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        tracker
            .flows
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .pending
            .get_mut(&7)
            .unwrap()
            .1 = Instant::now() - Duration::from_secs(1);
        assert!(!tracker.response_for_tun(&mut BytesMut::from(response.as_slice())));
        assert!(tracker.query(&request));
        let mut corrupt = response.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(!tracker.response_for_tun(&mut BytesMut::from(corrupt.as_slice())));
        assert!(tracker.response_for_tun(&mut BytesMut::from(response.as_slice())));
    }

    fn tcp(payload: &[u8], sequence: u32, syn: bool, response: bool) -> Vec<u8> {
        let (src, dst, sport, dport) = if response {
            ([10, 8, 0, 1], [10, 0, 0, 2], 53, 44000)
        } else {
            ([10, 0, 0, 2], [10, 8, 0, 1], 44000, 53)
        };
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp(sport, dport, sequence, 32768);
        let mut packet = Vec::new();
        if syn {
            builder.syn().write(&mut packet, payload).unwrap();
        } else {
            builder.ack(1).write(&mut packet, payload).unwrap();
        }
        packet
    }

    fn tcp_wire(message: &[u8]) -> Vec<u8> {
        let mut bytes = (message.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(message);
        bytes
    }

    #[test]
    fn packet_dns_tcp_learning_precedes_zero_ttl_forward_and_retransmit_keeps_checksum() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let owner = DnsIdentity::new(1, vec![]);
        let syn = tcp(&[], 100, true, false);
        let key = FlowKey::from_packet(&syn).unwrap();
        assert!(tracker.register(key, owner.clone(), cache.clone(), CancellationToken::new()));
        assert!(tracker.query(&syn));
        let q = query(7, "a.org");
        assert!(tracker.query(&tcp(&tcp_wire(&q), 101, false, false)));
        assert!(
            tracker.response_for_tun(&mut BytesMut::from(tcp(&[], 500, true, true).as_slice()))
        );
        let original = tcp(&tcp_wire(&answer(&q)), 501, false, true);
        let mut response = BytesMut::from(original.as_slice());
        assert!(tracker.response_for_tun(&mut response));
        let framed = frame(&response).expect("valid TCP checksum").payload;
        assert_eq!(&framed[framed.len() - 10..framed.len() - 6], &[0; 4]);
        assert!(
            cache
                .packet_route_hints([0; 32], &owner, "203.0.113.9".parse().unwrap())
                .is_some()
        );
        let mut retry = BytesMut::from(original.as_slice());
        assert!(tracker.response_for_tun(&mut retry));
        assert_eq!(retry, response);
    }

    #[test]
    fn packet_dns_rejected_tcp_reply_cannot_escape_on_exact_retransmission() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let syn = tcp(&[], 100, true, false);
        let key = FlowKey::from_packet(&syn).unwrap();
        assert!(tracker.register(
            key,
            DnsIdentity::new(1, vec![]),
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&syn));
        let q = query(7, "a.org");
        assert!(tracker.query(&tcp(&tcp_wire(&q), 101, false, false)));
        assert!(
            tracker.response_for_tun(&mut BytesMut::from(tcp(&[], 500, true, true).as_slice()))
        );
        let wrong = tcp(
            &tcp_wire(&answer(&query(99, "other.org"))),
            501,
            false,
            true,
        );
        assert!(!tracker.response_for_tun(&mut BytesMut::from(wrong.as_slice())));
        assert!(!tracker.response_for_tun(&mut BytesMut::from(wrong.as_slice())));
    }

    #[test]
    fn packet_dns_compressed_query_is_explicitly_refused_before_outbound() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let mut q = query(7, "a.org");
        q[12..14].copy_from_slice(&[0xc0, 12]);
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            DnsIdentity::new(1, vec![]),
            cache,
            CancellationToken::new()
        ));
        assert!(!tracker.query(&request));
    }

    fn managed_policy(resolver: IpAddr) -> Arc<FlowPolicyStore> {
        let direct = Arc::new(foxcore_outbound::Outbound::direct(
            foxcore_dialer::ProtectedDialer::host(),
        ));
        Arc::new(
            FlowPolicyStore::new(
                1,
                foxcore_route::RouteTable::compile(Vec::new(), foxcore_api::RouteAction::Direct),
                foxcore_api::DnsConfig {
                    packet_resolvers: vec![resolver],
                    ..Default::default()
                },
                Arc::new(foxcore_outbound::OutboundRegistry::single(direct.clone())),
                direct,
                Arc::new(crate::FlowMetrics::default()),
                foxcore_api::EventSink::none(),
            )
            .unwrap()
            .with_packet_dns_peer([1; 32]),
        )
    }

    #[test]
    fn managed_packet_dns_without_identity_rewrites_but_does_not_learn() {
        let policy = managed_policy("10.8.0.1".parse().unwrap());
        let cache = policy.current.load().dns.clone();
        let tracker = PacketDnsTracker::for_policy(policy.clone());
        let q = query(7, "a.org");
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            None,
            cache.clone(),
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut response = BytesMut::from(udp(&answer(&q), true).as_slice());
        assert!(tracker.response_for_tun(&mut response));
        let frame = frame(&response).unwrap();
        assert_eq!(
            &frame.payload[frame.payload.len() - 10..frame.payload.len() - 6],
            &[0; 4]
        );
        let authority = policy.packet_dns_authority(&policy.current.load()).unwrap();
        assert!(
            cache
                .packet_route_hints(
                    authority,
                    &DnsIdentity::new(1, vec![]),
                    "203.0.113.9".parse().unwrap()
                )
                .is_none()
        );
    }

    #[test]
    fn packet_dns_historical_resolver_stays_refusal_only_after_reload_and_session_removal() {
        let policy = managed_policy("10.8.0.1".parse().unwrap());
        let cache = policy.current.load().dns.clone();
        let tracker = PacketDnsTracker::for_policy(policy.clone());
        let q = query(7, "a.org");
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            None,
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut config = policy.current.load().dns_config.clone();
        config.packet_resolvers = vec!["10.8.0.2".parse().unwrap()];
        policy
            .reload(
                None,
                foxcore_route::RouteTable::compile(Vec::new(), foxcore_api::RouteAction::Direct),
                config,
            )
            .unwrap();
        tracker.flows.lock().unwrap().clear();
        let mut old_reply = BytesMut::from(udp(&answer(&q), true).as_slice());
        assert!(!tracker.response_for_tun(&mut old_reply));
        let mut other = Vec::new();
        PacketBuilder::ipv4([10, 8, 0, 99], [10, 0, 0, 2], 64)
            .udp(53, 44000)
            .write(&mut other, &answer(&q))
            .unwrap();
        let mut never_selected = BytesMut::from(other.as_slice());
        assert!(tracker.response_for_tun(&mut never_selected));
        assert_eq!(never_selected.as_ref(), other);
    }

    #[test]
    fn packet_dns_resolver_history_capacity_refuses_new_tracking_before_outbound() {
        let policy = managed_policy("10.8.0.1".parse().unwrap());
        let tracker = PacketDnsTracker::for_policy(policy.clone());
        let mut key = FlowKey::from_packet(&udp(&query(7, "a.org"), false)).unwrap();
        assert!(tracker.register(
            key,
            None,
            policy.current.load().dns.clone(),
            CancellationToken::new()
        ));
        let mut refused = false;
        for index in 1..=150 {
            let resolver = IpAddr::from([10, 9, 0, index]);
            let mut config = policy.current.load().dns_config.clone();
            config.packet_resolvers = vec![resolver];
            policy
                .reload(
                    None,
                    foxcore_route::RouteTable::compile(
                        Vec::new(),
                        foxcore_api::RouteAction::Direct,
                    ),
                    config,
                )
                .unwrap();
            tracker.flows.lock().unwrap().clear();
            key.destination = resolver;
            if !tracker.register(
                key,
                None,
                policy.current.load().dns.clone(),
                CancellationToken::new(),
            ) {
                refused = true;
                let mut request = Vec::new();
                PacketBuilder::ipv4([10, 0, 0, 2], [10, 9, 0, index], 64)
                    .udp(44000, 53)
                    .write(&mut request, &query(7, "a.org"))
                    .unwrap();
                assert!(!tracker.query(&request));
                break;
            }
        }
        assert!(
            refused,
            "finite historical endpoint tracking must fail closed"
        );
    }

    #[test]
    fn packet_dns_ipv6_rewrite_keeps_mandatory_udp_checksum_and_blocks_extensions() {
        let q = query(7, "a.org");
        let src = "fd00::2".parse::<std::net::Ipv6Addr>().unwrap();
        let dns = "fd00::53".parse::<std::net::Ipv6Addr>().unwrap();
        let mut request = Vec::new();
        PacketBuilder::ipv6(src.octets(), dns.octets(), 64)
            .udp(44000, 53)
            .write(&mut request, &q)
            .unwrap();
        let mut response = Vec::new();
        PacketBuilder::ipv6(dns.octets(), src.octets(), 64)
            .udp(53, 44000)
            .write(&mut response, &answer(&q))
            .unwrap();
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            None,
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut extension = BytesMut::from(response.as_slice());
        extension[6] = 44;
        assert!(!tracker.response_for_tun(&mut extension));
        let mut rewritten = BytesMut::from(response.as_slice());
        assert!(tracker.response_for_tun(&mut rewritten));
        assert_ne!(&rewritten[46..48], &[0, 0]);
        let frame = frame(&rewritten).expect("mandatory rewritten UDP checksum verifies");
        assert_eq!(
            &frame.payload[frame.payload.len() - 10..frame.payload.len() - 6],
            &[0; 4]
        );
    }

    fn with_opt(mut message: Vec<u8>, pseudo_ttl: u32) -> Vec<u8> {
        message[11] = 1;
        message.extend_from_slice(&[0, 0, 41, 4, 208]);
        message.extend_from_slice(&pseudo_ttl.to_be_bytes());
        message.extend_from_slice(&[0, 0]);
        message
    }

    #[test]
    fn packet_dns_tc_preserves_extended_error_instead_of_forging_noerror() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let base = query(7, "MiXeD.Example");
        let q = with_opt(base.clone(), 0);
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            None,
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut response = base;
        response[2] = 0x83;
        response[3] = 0x80;
        let response = with_opt(response, 0x0100_8000);
        let mut packet = BytesMut::from(udp(&response, true).as_slice());
        assert!(tracker.response_for_tun(&mut packet));
        let payload = frame(&packet).unwrap().payload;
        assert_eq!(&payload[10..12], &[0, 1]);
        assert_eq!(
            &payload[payload.len() - 6..payload.len() - 2],
            &0x0100_8000_u32.to_be_bytes()
        );
        assert_eq!(payload[3] & 15, 0);
    }

    #[test]
    fn packet_dns_tc_refuses_undetermined_extended_rcode_in_incomplete_additional_section() {
        let tracker = PacketDnsTracker::default();
        let cache = Arc::new(DnsCache::new(8));
        let base = query(7, "a.org");
        let q = with_opt(base.clone(), 0);
        let request = udp(&q, false);
        assert!(tracker.register(
            FlowKey::from_packet(&request).unwrap(),
            None,
            cache,
            CancellationToken::new()
        ));
        assert!(tracker.query(&request));
        let mut response = base;
        response[2] = 0x83;
        response[3] = 0x80;
        response[11] = 1;
        response.extend_from_slice(&[0, 0, 41]);
        assert!(!tracker.response_for_tun(&mut BytesMut::from(udp(&response, true).as_slice())));
    }
}
