//! Bounded DNS TTL rewriting. The caller owns response authentication and per-UID learning.
use std::collections::VecDeque;

const MAX_MESSAGE: usize = 65_535;
const MAX_WIRE: usize = MAX_MESSAGE + 2;
const MAX_RANGES: usize = MAX_WIRE / 11 + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RewriteError {
    Malformed,
    Truncated,
    UnsupportedAuthentication,
    Gap,
    ConflictingRetransmission,
    Capacity,
    Refused,
}

/// A truncated UDP response needs a safe TC answer built from the paired query.
pub(crate) fn uncacheable_udp_response(original_dns: &[u8]) -> Result<Vec<u8>, RewriteError> {
    if !(12..=MAX_MESSAGE).contains(&original_dns.len()) {
        return Err(RewriteError::Malformed);
    }
    if original_dns[2] & 0x80 == 0 || original_dns[2] & 0x78 != 0 {
        return Err(RewriteError::Malformed);
    }
    if original_dns[2] & 2 != 0 {
        return Err(RewriteError::Truncated);
    }
    let mut cursor = MessageCursor::new(original_dns.len());
    let mut rewritten = original_dns.to_vec();
    for (index, byte) in original_dns.iter().copied().enumerate() {
        if cursor.feed(byte, &|at| original_dns.get(at).copied())? {
            rewritten[index] = 0;
        }
    }
    cursor.finish()?;
    Ok(rewritten)
}

#[derive(Clone, Copy)]
enum Stage {
    Header,
    Name {
        question: bool,
        remaining: u8,
        expanded: u16,
    },
    Pointer {
        question: bool,
        expanded: u16,
        high: u8,
        at: usize,
    },
    Question {
        remaining: u8,
    },
    Record {
        offset: u8,
        kind: u16,
        data_length: u16,
    },
    Data {
        remaining: u16,
    },
    Done,
}

struct MessageCursor {
    length: usize,
    position: usize,
    questions: u16,
    records: usize,
    stage: Stage,
}

impl MessageCursor {
    fn new(length: usize) -> Self {
        Self {
            length,
            position: 0,
            questions: 0,
            records: 0,
            stage: Stage::Header,
        }
    }

    fn name(question: bool) -> Stage {
        Stage::Name {
            question,
            remaining: 0,
            expanded: 0,
        }
    }

    fn after_name(question: bool) -> Stage {
        if question {
            Stage::Question { remaining: 4 }
        } else {
            Stage::Record {
                offset: 0,
                kind: 0,
                data_length: 0,
            }
        }
    }

    fn after_record(&mut self) -> Result<Stage, RewriteError> {
        self.records = self.records.checked_sub(1).ok_or(RewriteError::Malformed)?;
        Ok(if self.records == 0 {
            Stage::Done
        } else {
            Self::name(false)
        })
    }

    fn feed<F: Fn(usize) -> Option<u8>>(
        &mut self,
        byte: u8,
        read: &F,
    ) -> Result<bool, RewriteError> {
        if self.position >= self.length {
            return Err(RewriteError::Malformed);
        }
        let mut zero = false;
        self.stage = match self.stage {
            Stage::Header if self.position < 11 => Stage::Header,
            Stage::Header => {
                let flags = read(2).ok_or(RewriteError::Malformed)?;
                if flags & 0x80 == 0 || flags & 0x78 != 0 {
                    return Err(RewriteError::Malformed);
                }
                if flags & 2 != 0 {
                    return Err(RewriteError::Truncated);
                }
                self.questions = word(read, 4)?;
                if self.questions > 1 {
                    return Err(RewriteError::Malformed);
                }
                self.records = usize::from(word(read, 6)?)
                    + usize::from(word(read, 8)?)
                    + usize::from(word(read, 10)?);
                let minimum = 12 + usize::from(self.questions) * 5 + self.records * 11;
                if minimum > self.length || self.records > MAX_RANGES {
                    return Err(RewriteError::Malformed);
                }
                if self.questions != 0 {
                    Self::name(true)
                } else if self.records != 0 {
                    Self::name(false)
                } else {
                    Stage::Done
                }
            }
            Stage::Name {
                question,
                remaining,
                expanded,
            } if remaining > 0 => Stage::Name {
                question,
                remaining: remaining - 1,
                expanded,
            },
            Stage::Name {
                question, expanded, ..
            } => match byte {
                0 => {
                    if expanded >= 255 {
                        return Err(RewriteError::Malformed);
                    }
                    Self::after_name(question)
                }
                1..=63 => {
                    let expanded = expanded + u16::from(byte) + 1;
                    if expanded >= 255 {
                        return Err(RewriteError::Malformed);
                    }
                    Stage::Name {
                        question,
                        remaining: byte,
                        expanded,
                    }
                }
                0xc0..=0xff => Stage::Pointer {
                    question,
                    expanded,
                    high: byte & 0x3f,
                    at: self.position,
                },
                _ => return Err(RewriteError::Malformed),
            },
            Stage::Pointer {
                question,
                expanded,
                high,
                at,
            } => {
                let target = (usize::from(high) << 8) | usize::from(byte);
                checked_suffix(read, target, at, expanded)?;
                Self::after_name(question)
            }
            Stage::Question { remaining } => {
                if remaining > 1 {
                    Stage::Question {
                        remaining: remaining - 1,
                    }
                } else {
                    self.questions = self
                        .questions
                        .checked_sub(1)
                        .ok_or(RewriteError::Malformed)?;
                    if self.questions != 0 {
                        Self::name(true)
                    } else if self.records != 0 {
                        Self::name(false)
                    } else {
                        Stage::Done
                    }
                }
            }
            Stage::Record {
                offset,
                mut kind,
                mut data_length,
            } => {
                match offset {
                    0 => kind = u16::from(byte) << 8,
                    1 => {
                        kind |= u16::from(byte);
                        if matches!(kind, 24 | 250) {
                            return Err(RewriteError::UnsupportedAuthentication);
                        }
                    }
                    4..=7 => zero = kind != 41,
                    8 => data_length = u16::from(byte) << 8,
                    9 => data_length |= u16::from(byte),
                    _ => {}
                }
                if offset < 9 {
                    Stage::Record {
                        offset: offset + 1,
                        kind,
                        data_length,
                    }
                } else {
                    if usize::from(data_length) > self.length - self.position - 1 {
                        return Err(RewriteError::Malformed);
                    }
                    if data_length == 0 {
                        self.after_record()?
                    } else {
                        Stage::Data {
                            remaining: data_length,
                        }
                    }
                }
            }
            Stage::Data { remaining } => {
                if remaining > 1 {
                    Stage::Data {
                        remaining: remaining - 1,
                    }
                } else {
                    self.after_record()?
                }
            }
            Stage::Done => return Err(RewriteError::Malformed),
        };
        self.position += 1;
        Ok(zero)
    }

    fn finish(&self) -> Result<(), RewriteError> {
        if self.position == self.length && matches!(self.stage, Stage::Done) {
            Ok(())
        } else {
            Err(RewriteError::Malformed)
        }
    }
}

fn word<F: Fn(usize) -> Option<u8>>(read: &F, at: usize) -> Result<u16, RewriteError> {
    Ok(u16::from_be_bytes([
        read(at).ok_or(RewriteError::Malformed)?,
        read(at + 1).ok_or(RewriteError::Malformed)?,
    ]))
}

fn checked_suffix<F: Fn(usize) -> Option<u8>>(
    read: &F,
    mut at: usize,
    mut bound: usize,
    mut expanded: u16,
) -> Result<(), RewriteError> {
    for _ in 0..128 {
        if at < 12 || at >= bound {
            return Err(RewriteError::Malformed);
        }
        let byte = read(at).ok_or(RewriteError::Malformed)?;
        match byte {
            0 => {
                return if expanded < 255 {
                    Ok(())
                } else {
                    Err(RewriteError::Malformed)
                };
            }
            1..=63 => {
                expanded += u16::from(byte) + 1;
                if expanded >= 255 || at + 1 + usize::from(byte) > bound {
                    return Err(RewriteError::Malformed);
                }
                at += 1 + usize::from(byte);
            }
            0xc0..=0xff => {
                if at + 1 >= bound {
                    return Err(RewriteError::Malformed);
                }
                let low = read(at + 1).ok_or(RewriteError::Malformed)?;
                let target = (usize::from(byte & 0x3f) << 8) | usize::from(low);
                bound = at;
                at = target;
            }
            _ => return Err(RewriteError::Malformed),
        }
    }
    Err(RewriteError::Capacity)
}

pub(crate) struct TcpResponseRewriter {
    history: VecDeque<u8>,
    history_start: u64,
    next: u64,
    origin: Option<u32>,
    saw_syn: bool,
    frame_start: u64,
    prefix: u8,
    length_high: u8,
    cursor: Option<MessageCursor>,
    ttl_ranges: VecDeque<(u64, u64)>,
    refused: bool,
}

impl Default for TcpResponseRewriter {
    fn default() -> Self {
        Self {
            history: VecDeque::with_capacity(MAX_WIRE),
            history_start: 0,
            next: 0,
            origin: None,
            saw_syn: false,
            frame_start: 0,
            prefix: 0,
            length_high: 0,
            cursor: None,
            ttl_ranges: VecDeque::with_capacity(MAX_RANGES),
            refused: false,
        }
    }
}

impl TcpResponseRewriter {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn refused(&self) -> bool {
        self.refused
    }

    /// Completed originals must be authenticated/learned before the caller forwards `payload`.
    /// Every error poisons this stream; the caller must discard the payload on error.
    pub(crate) fn rewrite(
        &mut self,
        sequence: u32,
        syn: bool,
        payload: &mut [u8],
    ) -> Result<Vec<Vec<u8>>, RewriteError> {
        if self.refused {
            return Err(RewriteError::Refused);
        }
        let result = self.rewrite_inner(sequence, syn, payload);
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    fn rewrite_inner(
        &mut self,
        sequence: u32,
        syn: bool,
        payload: &mut [u8],
    ) -> Result<Vec<Vec<u8>>, RewriteError> {
        if payload.len() > MAX_WIRE {
            return Err(RewriteError::Capacity);
        }
        if payload.is_empty() && !syn {
            return Ok(Vec::new());
        }
        let data_sequence = sequence.wrapping_add(u32::from(syn));
        match self.origin {
            None => {
                self.origin = Some(data_sequence);
                self.saw_syn = syn;
            }
            Some(origin) if syn && (!self.saw_syn || origin != data_sequence) => {
                return Err(RewriteError::ConflictingRetransmission);
            }
            _ => {}
        }
        let expected = self
            .origin
            .ok_or(RewriteError::Malformed)?
            .wrapping_add(self.next as u32);
        let delta = data_sequence.wrapping_sub(expected) as i32;
        if delta > 0 {
            return Err(RewriteError::Gap);
        }
        let behind = if delta < 0 {
            u64::from(expected.wrapping_sub(data_sequence))
        } else {
            0
        };
        if behind > self.next || behind > self.history.len() as u64 {
            return Err(RewriteError::ConflictingRetransmission);
        }
        let start = self.next - behind;
        let overlap = usize::try_from(behind)
            .map_err(|_| RewriteError::Capacity)?
            .min(payload.len());
        for (index, byte) in payload[..overlap].iter().enumerate() {
            let at = usize::try_from(start + index as u64 - self.history_start)
                .map_err(|_| RewriteError::Capacity)?;
            if self.history.get(at) != Some(byte) {
                return Err(RewriteError::ConflictingRetransmission);
            }
        }
        // Locate the first relevant TTL range once, even for tiny late retransmissions.
        let (mut low, mut high) = (0, self.ttl_ranges.len());
        while low < high {
            let middle = low + (high - low) / 2;
            if self.ttl_ranges[middle].1 <= start {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut range = low;
        for (index, byte) in payload[..overlap].iter_mut().enumerate() {
            let at = start + index as u64;
            while self.ttl_ranges.get(range).is_some_and(|r| r.1 <= at) {
                range += 1;
            }
            if self
                .ttl_ranges
                .get(range)
                .is_some_and(|r| r.0 <= at && at < r.1)
            {
                *byte = 0;
            }
        }
        let mut completed = Vec::new();
        let mut completed_bytes = 0;
        for byte in &mut payload[overlap..] {
            let original = *byte;
            let at = self.next;
            if self.history.len() == MAX_WIRE {
                if self.history_start >= self.frame_start {
                    return Err(RewriteError::Capacity);
                }
                self.history.pop_front();
                self.history_start += 1;
            }
            self.history.push_back(original);
            self.next = self.next.checked_add(1).ok_or(RewriteError::Capacity)?;
            while self
                .ttl_ranges
                .front()
                .is_some_and(|r| r.1 <= self.history_start)
            {
                self.ttl_ranges.pop_front();
            }
            if self.prefix == 0 {
                self.frame_start = at;
                self.length_high = original;
                self.prefix = 1;
            } else if self.prefix == 1 {
                let length = (usize::from(self.length_high) << 8) | usize::from(original);
                if !(12..=MAX_MESSAGE).contains(&length) {
                    return Err(RewriteError::Malformed);
                }
                self.cursor = Some(MessageCursor::new(length));
                self.prefix = 2;
            } else {
                let message_start = self.frame_start + 2;
                let history = &self.history;
                let history_start = self.history_start;
                let cursor = self.cursor.as_mut().ok_or(RewriteError::Malformed)?;
                let zero = cursor.feed(original, &|offset| {
                    let position = message_start
                        .checked_add(offset as u64)?
                        .checked_sub(history_start)?;
                    history.get(usize::try_from(position).ok()?).copied()
                })?;
                if zero {
                    *byte = 0;
                    if !self
                        .ttl_ranges
                        .back()
                        .is_some_and(|r| r.0 <= at && at < r.1)
                    {
                        if self.ttl_ranges.len() >= MAX_RANGES {
                            return Err(RewriteError::Capacity);
                        }
                        self.ttl_ranges.push_back((at, at + 4));
                    }
                }
                if cursor.position == cursor.length {
                    cursor.finish()?;
                    completed_bytes += cursor.length;
                    if completed_bytes > MAX_WIRE {
                        return Err(RewriteError::Capacity);
                    }
                    let first = usize::try_from(message_start - self.history_start)
                        .map_err(|_| RewriteError::Capacity)?;
                    completed.push(
                        self.history
                            .range(first..first + cursor.length)
                            .copied()
                            .collect(),
                    );
                    self.cursor = None;
                    self.prefix = 0;
                    self.frame_start = self.next;
                }
            }
        }
        Ok(completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(ttl: u32) -> (Vec<u8>, usize) {
        let mut bytes = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(b"\x07example\x03org\0\0\x01\0\x01");
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        let at = bytes.len();
        bytes.extend_from_slice(&ttl.to_be_bytes());
        bytes.extend_from_slice(&[0, 4, 203, 0, 113, 7]);
        (bytes, at)
    }

    fn framed(message: &[u8]) -> Vec<u8> {
        let mut result = (message.len() as u16).to_be_bytes().to_vec();
        result.extend_from_slice(message);
        result
    }

    #[test]
    fn udp_lowers_only_wire_ttl_and_preserves_original() {
        let (original, at) = answer(60);
        let rewritten = uncacheable_udp_response(&original).unwrap();
        assert_eq!(&rewritten[at..at + 4], &[0; 4]);
        assert_eq!(&original[at..at + 4], &60_u32.to_be_bytes());
        let mut expected = original;
        expected[at..at + 4].fill(0);
        assert_eq!(rewritten, expected);
    }

    #[test]
    fn tcp_returns_original_before_caller_forwards_mutated_payload() {
        let (original, at) = answer(60);
        let mut payload = framed(&original);
        let mut stream = TcpResponseRewriter::default();
        let completed = stream.rewrite(100, false, &mut payload).unwrap();
        assert_eq!(completed, vec![original]);
        assert_eq!(&payload[at + 2..at + 6], &[0; 4]);
    }

    fn append_record(message: &mut Vec<u8>, kind: u16, ttl: u32, data: &[u8]) -> usize {
        message.extend_from_slice(&[0xc0, 12]);
        message.extend_from_slice(&kind.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        let at = message.len();
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&(data.len() as u16).to_be_bytes());
        message.extend_from_slice(data);
        at
    }

    #[test]
    fn udp_all_sections_lower_real_ttls_but_preserve_opt_and_rrsig_rdata() {
        let (mut original, first) = answer(60);
        original[7] = 2;
        original[9] = 1;
        original[11] = 2;
        let cname = append_record(&mut original, 5, 300, b"\x03cdn\x07example\x03org\0");
        let soa = append_record(&mut original, 6, 900, &[0; 22]);
        original.extend_from_slice(&[0, 0, 41, 16, 0]);
        let opt = original.len();
        original.extend_from_slice(&0x0100_8000_u32.to_be_bytes());
        original.extend_from_slice(&[0, 4, 0, 8, 0, 0]);
        let signature_data = [0, 1, 8, 2, 0, 0, 1, 44, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7];
        let signature = append_record(&mut original, 46, 90, &signature_data);
        let mut expected = original.clone();
        for at in [first, cname, soa, signature] {
            expected[at..at + 4].fill(0);
        }
        let rewritten = uncacheable_udp_response(&original).unwrap();
        assert_eq!(rewritten, expected);
        assert_eq!(&rewritten[opt..opt + 4], &0x0100_8000_u32.to_be_bytes());
        assert_eq!(&rewritten[signature + 6..], &signature_data);
    }

    #[test]
    fn udp_authentication_records_are_explicitly_refused() {
        for kind in [24, 250] {
            let (mut original, _) = answer(60);
            original[11] = 1;
            append_record(&mut original, kind, 60, &[0; 24]);
            assert_eq!(
                uncacheable_udp_response(&original),
                Err(RewriteError::UnsupportedAuthentication)
            );
        }
    }

    #[test]
    fn udp_truncated_answer_requests_safe_tc_replacement_even_with_incomplete_rr() {
        let (mut original, at) = answer(60);
        original[2] |= 2;
        original.truncate(at + 1);
        assert_eq!(
            uncacheable_udp_response(&original),
            Err(RewriteError::Truncated)
        );
    }

    #[test]
    fn udp_names_lengths_counts_and_trailing_bytes_are_checked() {
        let (original, at) = answer(60);
        let mut cases = Vec::new();
        let mut extra = original.clone();
        extra.push(0);
        cases.push(extra);
        let mut long_data = original.clone();
        long_data[at + 4..at + 6].copy_from_slice(&999_u16.to_be_bytes());
        cases.push(long_data);
        let mut count = original.clone();
        count[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        cases.push(count);
        let mut reserved_label = original.clone();
        reserved_label[12] = 64;
        cases.push(reserved_label);
        let mut cycle = original.clone();
        cycle[12..14].copy_from_slice(&[0xc0, 12]);
        cases.push(cycle);
        let mut forward = original.clone();
        forward[12..14].copy_from_slice(&[0xc0, 20]);
        cases.push(forward);
        for length in 0..12 {
            cases.push(original[..length].to_vec());
        }
        for message in cases {
            assert!(
                uncacheable_udp_response(&message).is_err(),
                "invalid message was accepted"
            );
        }
    }

    #[test]
    fn tcp_every_single_byte_split_rewrites_ttl_before_returning_data() {
        let (original, at) = answer(0x0102_0304);
        let wire = framed(&original);
        let mut stream = TcpResponseRewriter::default();
        let mut output = Vec::new();
        let mut completed = Vec::new();
        for (index, byte) in wire.iter().enumerate() {
            let mut part = [*byte];
            completed.extend(
                stream
                    .rewrite(100 + index as u32, false, &mut part)
                    .unwrap(),
            );
            output.push(part[0]);
        }
        let mut expected = wire;
        expected[at + 2..at + 6].fill(0);
        assert_eq!(output, expected);
        assert_eq!(completed, vec![original]);
    }

    #[test]
    fn tcp_all_two_chunk_boundaries_preserve_original_frames() {
        let (original, at) = answer(60);
        let wire = framed(&original);
        for split in 0..=wire.len() {
            let mut stream = TcpResponseRewriter::default();
            let mut first = wire[..split].to_vec();
            let mut last = wire[split..].to_vec();
            let mut completed = stream.rewrite(100, false, &mut first).unwrap();
            completed.extend(
                stream
                    .rewrite(100 + split as u32, false, &mut last)
                    .unwrap(),
            );
            first.extend(last);
            let mut expected = wire.clone();
            expected[at + 2..at + 6].fill(0);
            assert_eq!(first, expected, "split={split}");
            assert_eq!(completed, vec![original.clone()], "split={split}");
        }
    }

    #[test]
    fn tcp_coalesced_messages_keep_length_prefixes_and_return_originals_in_order() {
        let (first, at) = answer(60);
        let (last, last_at) = answer(90);
        let mut payload = framed(&first);
        let boundary = payload.len();
        payload.extend(framed(&last));
        let mut expected = payload.clone();
        expected[at + 2..at + 6].fill(0);
        expected[boundary + last_at + 2..boundary + last_at + 6].fill(0);
        assert_eq!(
            TcpResponseRewriter::default()
                .rewrite(10, false, &mut payload)
                .unwrap(),
            vec![first, last]
        );
        assert_eq!(payload, expected);
    }

    #[test]
    fn tcp_exact_and_partial_retransmissions_never_restore_positive_ttl_or_relearn() {
        let (original, at) = answer(60);
        let wire = framed(&original);
        let first_len = at + 4;
        let mut stream = TcpResponseRewriter::default();
        let mut first = wire[..first_len].to_vec();
        assert!(stream.rewrite(100, false, &mut first).unwrap().is_empty());
        let start = at + 3;
        let mut rest = wire[start..].to_vec();
        assert_eq!(
            stream
                .rewrite(100 + start as u32, false, &mut rest)
                .unwrap(),
            vec![original]
        );
        let mut retry = wire.clone();
        assert!(stream.rewrite(100, false, &mut retry).unwrap().is_empty());
        let mut expected = wire;
        expected[at + 2..at + 6].fill(0);
        assert_eq!(retry, expected);
        assert_eq!(rest, expected[start..]);
    }

    #[test]
    fn tcp_sequence_wrap_and_syn_sequence_consumption_are_supported() {
        let (original, _) = answer(60);
        let wire = framed(&original);
        let initial = u32::MAX - 10;
        let mut stream = TcpResponseRewriter::default();
        assert!(stream.rewrite(initial, true, &mut []).unwrap().is_empty());
        let mut first = wire[..20].to_vec();
        stream
            .rewrite(initial.wrapping_add(1), false, &mut first)
            .unwrap();
        let mut rest = wire[20..].to_vec();
        assert_eq!(
            stream
                .rewrite(initial.wrapping_add(21), false, &mut rest)
                .unwrap(),
            vec![original]
        );
    }

    #[test]
    fn tcp_gap_or_changed_overlap_is_sticky_fail_closed_until_explicit_reset() {
        let (original, _) = answer(60);
        let wire = framed(&original);
        for conflict in [false, true] {
            let mut stream = TcpResponseRewriter::default();
            stream
                .rewrite(100, false, &mut wire[..20].to_vec())
                .unwrap();
            let mut next = if conflict {
                wire[10..].to_vec()
            } else {
                wire[20..].to_vec()
            };
            if conflict {
                next[0] ^= 1;
            }
            let seq = if conflict { 110 } else { 121 };
            let error = if conflict {
                RewriteError::ConflictingRetransmission
            } else {
                RewriteError::Gap
            };
            assert_eq!(stream.rewrite(seq, false, &mut next), Err(error));
            assert!(stream.refused());
            assert_eq!(
                stream.rewrite(120, false, &mut wire[20..].to_vec()),
                Err(RewriteError::Refused)
            );
            stream.reset();
            assert_eq!(
                stream.rewrite(500, false, &mut wire.clone()).unwrap(),
                vec![original.clone()]
            );
        }
    }

    #[test]
    fn tcp_drops_out_of_window_retransmission_and_oversize_input() {
        let mut stream = TcpResponseRewriter::default();
        let message = vec![0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let wire = framed(&message);
        for index in 0..5000 {
            assert_eq!(
                stream
                    .rewrite(index * wire.len() as u32, false, &mut wire.clone())
                    .unwrap(),
                vec![message.clone()]
            );
        }
        assert_eq!(
            stream.rewrite(0, false, &mut wire.clone()),
            Err(RewriteError::ConflictingRetransmission)
        );
        let mut stream = TcpResponseRewriter::default();
        assert_eq!(
            stream.rewrite(0, false, &mut vec![0; 65_538]),
            Err(RewriteError::Capacity)
        );
        assert!(stream.refused());
    }

    #[test]
    fn tcp_maximum_dns_frame_remains_bounded_and_returns_its_original() {
        let (mut original, at) = answer(60);
        original.truncate(at + 4);
        let data_length = 65_535 - original.len() - 2;
        original[at - 4..at - 2].copy_from_slice(&65000_u16.to_be_bytes());
        original.extend_from_slice(&(data_length as u16).to_be_bytes());
        original.resize(65_535, 42);
        let wire = framed(&original);
        let mut stream = TcpResponseRewriter::default();
        let mut completed = Vec::new();
        let mut rewritten = Vec::new();
        for (index, part) in wire.chunks(509).enumerate() {
            let mut part = part.to_vec();
            completed.extend(
                stream
                    .rewrite((index * 509) as u32, false, &mut part)
                    .unwrap(),
            );
            rewritten.extend(part);
        }
        assert_eq!(completed, vec![original]);
        assert_eq!(&rewritten[at + 2..at + 6], &[0; 4]);
    }

    #[test]
    fn tcp_refuses_truncated_or_authenticated_dns_before_message_completion() {
        let (mut truncated, _) = answer(60);
        truncated[2] |= 2;
        let (mut signed, _) = answer(60);
        signed[11] = 1;
        append_record(&mut signed, 250, 60, &[0; 24]);
        for (message, error) in [
            (truncated, RewriteError::Truncated),
            (signed, RewriteError::UnsupportedAuthentication),
        ] {
            let mut stream = TcpResponseRewriter::default();
            assert_eq!(stream.rewrite(0, false, &mut framed(&message)), Err(error));
            assert!(stream.refused());
        }
    }

    #[test]
    fn tcp_opt_pseudo_ttl_and_rrsig_original_ttl_survive_single_byte_streaming() {
        let (mut original, at) = answer(60);
        original[11] = 2;
        original.extend_from_slice(&[0, 0, 41, 16, 0]);
        let opt = original.len();
        original.extend_from_slice(&0x0100_8000_u32.to_be_bytes());
        original.extend_from_slice(&[0, 0]);
        let signature_data = [0, 1, 8, 2, 0, 0, 1, 44, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7];
        let signature = append_record(&mut original, 46, 90, &signature_data);
        let wire = framed(&original);
        let mut stream = TcpResponseRewriter::default();
        let mut result = Vec::new();
        let mut originals = Vec::new();
        for (offset, byte) in wire.iter().enumerate() {
            let mut part = [*byte];
            originals.extend(stream.rewrite(offset as u32, false, &mut part).unwrap());
            result.extend(part);
        }
        assert_eq!(originals, vec![original.clone()]);
        let mut expected = framed(&original);
        expected[at + 2..at + 6].fill(0);
        expected[signature + 2..signature + 6].fill(0);
        assert_eq!(result, expected);
        assert_eq!(&result[opt + 2..opt + 6], &0x0100_8000_u32.to_be_bytes());
        assert_eq!(&result[signature + 8..], &signature_data);
    }

    #[test]
    fn udp_original_zero_ttl_stays_zero_without_manufacturing_an_expiry() {
        let (original, _) = answer(0);
        assert_eq!(uncacheable_udp_response(&original).unwrap(), original);
    }

    #[test]
    fn bounded_malformed_variations_do_not_panic_or_modify_the_original() {
        let (original, _) = answer(60);
        for index in 0..original.len() {
            for byte in [0, 1, 63, 64, 127, 192, 255] {
                let mut candidate = original.clone();
                candidate[index] = byte;
                let before = candidate.clone();
                let _ = uncacheable_udp_response(&candidate);
                assert_eq!(candidate, before);
                let mut stream = TcpResponseRewriter::default();
                let _ = stream.rewrite(0, false, &mut framed(&candidate));
            }
        }
    }
}
