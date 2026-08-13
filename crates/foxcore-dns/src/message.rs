use crate::consts::DNS_HEADER_LEN;
use crate::wire::parse_question;

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
