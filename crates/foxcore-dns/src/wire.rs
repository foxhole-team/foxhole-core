use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::consts::{DNS_HEADER_LEN, MAX_POINTER_JUMPS, RECORD_OPT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub domain: String,
    pub record_type: u16,
    pub class: u16,
}

pub(crate) struct ParsedQuestion {
    pub(crate) question: DnsQuestion,
    pub(crate) question_end: usize,
}

pub(crate) fn parse_question(packet: &[u8]) -> Option<ParsedQuestion> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || question_count != 1 {
        return None;
    }
    let mut offset = DNS_HEADER_LEN;
    let domain = read_name(packet, &mut offset)?;
    let record_type = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
    let class = u16::from_be_bytes([*packet.get(offset + 2)?, *packet.get(offset + 3)?]);
    let question_end = offset.checked_add(4)?;
    Some(ParsedQuestion {
        question: DnsQuestion {
            domain,
            record_type,
            class,
        },
        question_end,
    })
}

pub(crate) fn query_key(packet: &[u8]) -> Option<Vec<u8>> {
    parse_question(packet)?;
    let mut key = packet.to_vec();
    key[..2].fill(0);
    Some(key)
}

pub(crate) struct ResponseMetadata {
    pub(crate) min_ttl: u32,
    pub(crate) ttl_fields: Vec<(usize, u32)>,
    pub(crate) negative: bool,
}

pub(crate) fn response_metadata(query: &[u8], response: &[u8]) -> Option<ResponseMetadata> {
    // The transaction ID first, because everything below it can be copied by
    // anyone who saw the question. Matching the question, QR and opcode only
    // says the packet is *shaped* like the answer; the ID is the one field that
    // says it answers the query this resolver actually sent. Without it a host
    // on the same Wi-Fi races the upstream with its own A record, the forgery
    // is served to the application, retained for up to `MAX_TTL`, and
    // `observe_response` folds it into the IP→name map that domain routing
    // rules are matched through — so one spoofed datagram outlives the flow it
    // was aimed at and quietly re-labels addresses for the whole session.
    //
    // Every transport the interceptor has reaches here with the ID intact. UDP,
    // TCP and DoT echo the query's; DoH normalises it to zero on the wire and
    // `restore_transaction_id` restores the caller's before caching.
    if query.first_chunk::<2>()? != response.first_chunk::<2>()? {
        return None;
    }
    let query_question = parse_question(query)?.question;
    if response.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return None;
    }
    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
    let authority_count = u16::from_be_bytes([response[8], response[9]]) as usize;
    let additional_count = u16::from_be_bytes([response[10], response[11]]) as usize;
    if question_count != 1 {
        return None;
    }
    let mut offset = DNS_HEADER_LEN;
    let response_domain = read_name(response, &mut offset)?;
    let response_type = u16::from_be_bytes([*response.get(offset)?, *response.get(offset + 1)?]);
    let response_class =
        u16::from_be_bytes([*response.get(offset + 2)?, *response.get(offset + 3)?]);
    offset = offset.checked_add(4)?;
    if response_domain != query_question.domain
        || response_type != query_question.record_type
        || response_class != query_question.class
    {
        return None;
    }

    let record_count = answer_count
        .checked_add(authority_count)?
        .checked_add(additional_count)?;
    let mut ttl_fields = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..record_count {
        let _ = read_name(response, &mut offset)?;
        if offset.checked_add(10)? > response.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let ttl_offset = offset + 4;
        let ttl = u32::from_be_bytes([
            response[ttl_offset],
            response[ttl_offset + 1],
            response[ttl_offset + 2],
            response[ttl_offset + 3],
        ]);
        let data_len = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset = offset.checked_add(10)?.checked_add(data_len)?;
        if offset > response.len() {
            return None;
        }
        if record_type != RECORD_OPT {
            min_ttl = min_ttl.min(ttl);
            ttl_fields.push((ttl_offset, ttl));
        }
    }
    let rcode = flags & 0x000f;
    let negative = rcode == 3 || answer_count == 0;
    if ttl_fields.is_empty() {
        min_ttl = 0;
    }
    Some(ResponseMetadata {
        min_ttl,
        ttl_fields,
        negative,
    })
}

pub(crate) struct AddressAnswer {
    pub(crate) domain: String,
    pub(crate) address: IpAddr,
    pub(crate) ttl: u32,
}

pub(crate) fn parse_addresses(packet: &[u8]) -> Option<Vec<AddressAnswer>> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    let question_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if question_count == 0 {
        return None;
    }

    let mut offset = DNS_HEADER_LEN;
    let mut query_domain = None;
    for index in 0..question_count {
        let name = read_name(packet, &mut offset)?;
        if index == 0 {
            query_domain = Some(name);
        }
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }
    let query_domain = query_domain?;
    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let _answer_name = read_name(packet, &mut offset)?;
        if offset.checked_add(10)? > packet.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let data_len = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        let end = offset.checked_add(data_len)?;
        let data = packet.get(offset..end)?;
        offset = end;
        if class != 1 {
            continue;
        }
        let address = match (record_type, data) {
            (1, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            (28, octets) if octets.len() == 16 => {
                let octets: [u8; 16] = octets.try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => continue,
        };
        answers.push(AddressAnswer {
            domain: query_domain.clone(),
            address,
            ttl,
        });
    }
    Some(answers)
}

fn read_name(packet: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut position = *offset;
    let mut jumped = false;
    let mut jumps = 0;
    let mut wire_len = 0;
    loop {
        let length = *packet.get(position)?;
        if length & 0xc0 == 0xc0 {
            let second = *packet.get(position + 1)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= packet.len() || jumps >= MAX_POINTER_JUMPS {
                return None;
            }
            if !jumped {
                *offset = position + 2;
                jumped = true;
            }
            position = pointer;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        position += 1;
        if length == 0 {
            if !jumped {
                *offset = position;
            }
            break;
        }
        let length = usize::from(length);
        wire_len += length + 1;
        if length > 63 || wire_len > 255 {
            return None;
        }
        let end = position.checked_add(length)?;
        let label = std::str::from_utf8(packet.get(position..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        position = end;
    }
    Some(labels.join("."))
}
