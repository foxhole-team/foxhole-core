use crate::consts::DNS_HEADER_LEN;
use crate::wire::{parse_question, read_name};

pub fn http_query(query: &[u8]) -> Option<(u16, Vec<u8>)> {
    parse_question(query)?;
    let transaction_id = u16::from_be_bytes([query[0], query[1]]);
    let mut normalized = query.to_vec();
    normalized[..2].fill(0);
    Some((transaction_id, normalized))
}

pub fn restore_transaction_id(response: &mut [u8], transaction_id: u16) -> bool {
    if response.len() < DNS_HEADER_LEN || response[2] & 0x80 == 0 {
        return false;
    }
    response[..2].copy_from_slice(&transaction_id.to_be_bytes());
    true
}

/// RFC 9250 uses stream identity instead of the caller's transaction ID.
pub fn doq_query(query: &[u8]) -> Option<(u16, Vec<u8>)> {
    if !(DNS_HEADER_LEN..=usize::from(u16::MAX)).contains(&query.len()) {
        return None;
    }
    let (transaction_id, wire) = http_query(query)?;
    doq_message_allowed(&wire).then_some((transaction_id, wire))
}

pub fn restore_doq_response(response: &mut [u8], transaction_id: u16) -> bool {
    doq_message_allowed(response) && restore_transaction_id(response, transaction_id)
}

fn doq_message_allowed(packet: &[u8]) -> bool {
    fn validate(packet: &[u8]) -> Option<()> {
        if !(DNS_HEADER_LEN..=usize::from(u16::MAX)).contains(&packet.len())
            || packet[..2] != [0, 0]
            || u16::from_be_bytes([packet[4], packet[5]]) != 1
        {
            return None;
        }
        let mut offset = DNS_HEADER_LEN;
        read_name(packet, &mut offset)?;
        offset = offset.checked_add(4)?;
        packet.get(..offset)?;
        let answers = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
        let authority = usize::from(u16::from_be_bytes([packet[8], packet[9]]));
        let additional = usize::from(u16::from_be_bytes([packet[10], packet[11]]));
        let before_additional = answers.checked_add(authority)?;
        let count = before_additional.checked_add(additional)?;
        let mut saw_opt = false;
        for index in 0..count {
            let owner = read_name(packet, &mut offset)?;
            let header = packet.get(offset..offset.checked_add(10)?)?;
            let record_type = u16::from_be_bytes([header[0], header[1]]);
            let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
            offset += 10;
            let end = offset.checked_add(length)?;
            let data = packet.get(offset..end)?;
            if record_type == 41 {
                if index < before_additional || !owner.is_empty() || saw_opt {
                    return None;
                }
                saw_opt = true;
                let mut option = 0usize;
                while option < data.len() {
                    let header = data.get(option..option.checked_add(4)?)?;
                    let code = u16::from_be_bytes([header[0], header[1]]);
                    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
                    option = option.checked_add(4)?.checked_add(length)?;
                    data.get(..option)?;
                    // RFC 9250 §5.5.2 prohibits TCP Keepalive (RFC 7828: 11).
                    // Padding (RFC 7830: 12), including arbitrary bytes, stays valid.
                    if code == 11 {
                        return None;
                    }
                }
            }
            offset = end;
        }
        (offset == packet.len()).then_some(())
    }
    validate(packet).is_some()
}

pub fn servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    empty_response(query, 0x0002)
}

/// NXDOMAIN for a locally blocked name.
///
/// A block must not answer SERVFAIL: resolvers and apps treat SERVFAIL as a
/// transient failure, retry, and some fall back to a hardcoded resolver — which
/// would defeat the block. NXDOMAIN is a definitive answer.
pub fn nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    empty_response(query, 0x0003)
}

/// NOERROR with the truncation bit, for an answer that cannot fit in one UDP
/// datagram on this link.
///
/// This is the answer RFC 1035 §4.2.1 defines for exactly this situation, and
/// it is the reason the interceptor also serves DNS over TCP: a client that
/// sees TC retries there. The alternative the stack used to take — sending the
/// answer as two datagrams — is not truncation, it is corruption, because a DNS
/// message has no fragmentation and the second half arrives as a malformed
/// message of its own.
pub fn truncated_response(query: &[u8]) -> Option<Vec<u8>> {
    let mut response = empty_response(query, 0x0000)?;
    // TC is 0x0200 in the flags word, which lives big-endian at bytes 2 and 3.
    response[2] |= 0x02;
    Some(response)
}

/// NOERROR with no answer records: "the name is fine, this type is not here".
///
/// Distinct from NXDOMAIN on purpose — a client told the *name* does not exist
/// may stop asking for its A record too, which is the record fake-IP has to be
/// asked for.
pub(crate) fn nodata_response(query: &[u8]) -> Option<Vec<u8>> {
    empty_response(query, 0x0000)
}

fn empty_response(query: &[u8], rcode: u16) -> Option<Vec<u8>> {
    let parsed = parse_question(query)?;
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags = 0x8000 | 0x0080 | (request_flags & 0x0110) | rcode;
    let mut response = Vec::with_capacity(parsed.question_end);
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[DNS_HEADER_LEN..parsed.question_end]);
    Some(response)
}

#[cfg(test)]
mod doq_tests {
    use super::*;
    use crate::tests::query;

    fn with_opt(code: u16, data: &[u8]) -> Vec<u8> {
        let mut message = query(1, 0x4242);
        message[10..12].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        message.extend_from_slice(&(u16::try_from(data.len()).unwrap() + 4).to_be_bytes());
        message.extend_from_slice(&code.to_be_bytes());
        message.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        message.extend_from_slice(data);
        message
    }

    #[test]
    fn doq_normalizes_and_restores_ids_without_changing_the_message() {
        let original = query(1, 0x4242);
        let (id, mut wire) = doq_query(&original).unwrap();
        assert_eq!(id, 0x4242);
        assert_eq!(&wire[..2], &[0, 0]);
        assert_eq!(&wire[2..], &original[2..]);
        wire[2] |= 0x80;
        assert!(restore_doq_response(&mut wire, id));
        assert_eq!(&wire[..2], &original[..2]);
    }

    #[test]
    fn doq_refuses_tcp_keepalive_11_and_accepts_arbitrary_padding_12() {
        for data in [Vec::new(), vec![0, 10]] {
            let mut query = with_opt(11, &data);
            assert!(doq_query(&query).is_none());
            query[..2].fill(0);
            query[2] |= 0x80;
            assert!(!restore_doq_response(&mut query, 0x4242));
        }
        for data in [Vec::new(), vec![0, 255, 128, 1]] {
            let query = with_opt(12, &data);
            let (id, mut wire) = doq_query(&query).unwrap();
            wire[2] |= 0x80;
            assert!(restore_doq_response(&mut wire, id));
            assert_eq!(&wire[query.len() - data.len()..], data.as_slice());
        }
    }

    #[test]
    fn doq_rejects_malformed_options_trailing_data_and_nonzero_response_ids() {
        let good = with_opt(12, &[1, 2]);
        let mut truncated = good.clone();
        truncated.pop();
        assert!(doq_query(&truncated).is_none());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(doq_query(&trailing).is_none());
        let mut option_length = good.clone();
        let length_at = option_length.len() - 4;
        option_length[length_at..length_at + 2].copy_from_slice(&100u16.to_be_bytes());
        assert!(doq_query(&option_length).is_none());
        let mut cycle = good.clone();
        let owner = query(1, 0x4242).len();
        cycle[owner..owner + 2].copy_from_slice(&[0xc0, u8::try_from(owner).unwrap()]);
        assert!(doq_query(&cycle).is_none());
        let mut response = good;
        response[2] |= 0x80;
        assert!(!restore_doq_response(&mut response, 0x4242));
    }

    #[test]
    fn doq_does_not_interpret_answer_data_as_an_edns_option() {
        let (_, mut response) = doq_query(&query(1, 0x4242)).unwrap();
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 0, 11, 0, 0]);
        assert!(restore_doq_response(&mut response, 0x4242));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::RECORD_AAAA;
    use crate::tests::query;

    /// A client that sees TC retries over TCP, which this interceptor serves.
    /// A client that sees a second datagram instead sees a malformed message.
    #[test]
    fn a_truncated_answer_sets_tc_and_keeps_the_question() {
        let query = query(1, 0x4242);

        let response = truncated_response(&query).expect("a truncation reply");

        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x8000, 0x8000, "must be a response");
        assert_eq!(flags & 0x0200, 0x0200, "TC must be set");
        assert_eq!(flags & 0x000f, 0, "rcode must stay NOERROR");
        assert_eq!(&response[..2], &query[..2], "transaction id must match");
        assert_eq!(
            u16::from_be_bytes([response[4], response[5]]),
            1,
            "the question must be echoed back"
        );
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            0,
            "a truncated answer carries no records"
        );
    }

    #[test]
    fn creates_bounded_servfail_for_valid_query() {
        let query = query(RECORD_AAAA, 0xbeef);
        let response = servfail_response(&query).unwrap();
        assert_eq!(&response[..2], &[0xbe, 0xef]);
        assert_eq!(response[3] & 0x0f, 2);
        assert_eq!(response.len(), query.len());
    }
}
