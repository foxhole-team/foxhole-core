use std::collections::BTreeMap;
use std::io;
use std::ops::RangeInclusive;

use bytes::BytesMut;
use md5::{Digest as _, Md5};
use rand::Rng;

use crate::codec::{CMD_WASTE, HEADER_LEN, encode_frame, invalid};

pub(crate) const DEFAULT_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000\n";

const MAX_SCHEME_BYTES: usize = 16 * 1024;
const MAX_PACKET_INDEX: usize = 63;
const MAX_STEPS: usize = 32;
const MAX_TLS_PLAINTEXT: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Range(RangeInclusive<usize>),
    Check,
}

#[derive(Debug, Clone)]
pub(crate) struct PaddingScheme {
    canonical: String,
    stop: usize,
    packets: BTreeMap<usize, Vec<Step>>,
}

impl PaddingScheme {
    pub(crate) fn default_scheme() -> io::Result<Self> {
        Self::parse(DEFAULT_SCHEME)
    }

    pub(crate) fn parse(value: &str) -> io::Result<Self> {
        if value.is_empty() || value.len() > MAX_SCHEME_BYTES {
            return Err(invalid("AnyTLS padding scheme has an invalid size"));
        }
        let mut stop = None;
        let mut packets = BTreeMap::new();
        for line in value.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("AnyTLS padding scheme line has no '='"))?;
            if key == "stop" {
                if stop.is_some() {
                    return Err(invalid("AnyTLS padding scheme repeats stop"));
                }
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| invalid("AnyTLS padding stop is not an integer"))?;
                if parsed == 0 || parsed > MAX_PACKET_INDEX + 1 {
                    return Err(invalid("AnyTLS padding stop is out of range"));
                }
                stop = Some(parsed);
                continue;
            }
            let packet = key
                .parse::<usize>()
                .map_err(|_| invalid("AnyTLS padding packet index is not an integer"))?;
            if packet > MAX_PACKET_INDEX || packets.contains_key(&packet) {
                return Err(invalid(
                    "AnyTLS padding packet index is repeated or out of range",
                ));
            }
            let mut steps = Vec::new();
            for token in value.split(',') {
                let token = token.trim();
                if token == "c" {
                    steps.push(Step::Check);
                } else {
                    let (minimum, maximum) = token
                        .split_once('-')
                        .ok_or_else(|| invalid("AnyTLS padding range has no '-'"))?;
                    let minimum = minimum
                        .parse::<usize>()
                        .map_err(|_| invalid("AnyTLS padding minimum is not an integer"))?;
                    let maximum = maximum
                        .parse::<usize>()
                        .map_err(|_| invalid("AnyTLS padding maximum is not an integer"))?;
                    if minimum == 0 || minimum > maximum || maximum > MAX_TLS_PLAINTEXT {
                        return Err(invalid("AnyTLS padding range is invalid"));
                    }
                    steps.push(Step::Range(minimum..=maximum));
                }
                if steps.len() > MAX_STEPS {
                    return Err(invalid("AnyTLS padding packet has too many steps"));
                }
            }
            if steps.is_empty() || !matches!(steps.first(), Some(Step::Range(_))) {
                return Err(invalid(
                    "AnyTLS padding packet must start with a size range",
                ));
            }
            packets.insert(packet, steps);
        }
        let stop = stop.ok_or_else(|| invalid("AnyTLS padding scheme has no stop"))?;
        if packets.keys().any(|packet| *packet >= stop) {
            return Err(invalid(
                "AnyTLS padding packet index must be lower than stop",
            ));
        }
        Ok(Self {
            canonical: value.to_owned(),
            stop,
            packets,
        })
    }

    pub(crate) fn md5_hex(&self) -> String {
        let digest = Md5::digest(self.canonical.as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(crate) fn auth_padding_length<R>(&self, rng: &mut R) -> usize
    where
        R: Rng,
    {
        self.packets
            .get(&0)
            .and_then(|steps| steps.first())
            .and_then(|step| match step {
                Step::Range(range) => Some(rng.random_range(range.clone())),
                Step::Check => None,
            })
            .unwrap_or(0)
    }

    /// Split one logical session write into TLS plaintext writes.
    pub(crate) fn packet_chunks<R>(
        &self,
        packet_index: usize,
        payload: &[u8],
        rng: &mut R,
    ) -> io::Result<Vec<BytesMut>>
    where
        R: Rng,
    {
        if packet_index >= self.stop {
            return Ok(vec![BytesMut::from(payload)]);
        }
        let Some(steps) = self.packets.get(&packet_index) else {
            return Ok(vec![BytesMut::from(payload)]);
        };
        let mut offset = 0usize;
        let mut chunks = Vec::new();
        for step in steps {
            match step {
                Step::Check if offset == payload.len() => break,
                Step::Check => continue,
                Step::Range(range) => {
                    let target = rng.random_range(range.clone());
                    let remaining = payload.len().saturating_sub(offset);
                    let take = remaining.min(target);
                    // A Waste frame needs a complete seven-byte header.
                    // Sending a shorter naked gap would corrupt framing, so
                    // this packet is slightly short instead.
                    let add_waste = take < target && target.saturating_sub(take) >= HEADER_LEN;
                    let mut chunk = BytesMut::with_capacity(target.max(take));
                    chunk.extend_from_slice(&payload[offset..offset + take]);
                    offset += take;
                    if add_waste {
                        let waste_data = target - chunk.len() - HEADER_LEN;
                        let padding = vec![0_u8; waste_data];
                        encode_frame(CMD_WASTE, 0, &padding, &mut chunk)?;
                    }
                    if !chunk.is_empty() {
                        chunks.push(chunk);
                    }
                }
            }
        }
        if offset < payload.len() {
            chunks.push(BytesMut::from(&payload[offset..]));
        }
        if chunks.is_empty() {
            chunks.push(BytesMut::new());
        }
        Ok(chunks)
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;

    #[test]
    fn built_in_scheme_has_stable_digest() {
        let scheme = PaddingScheme::default_scheme().unwrap();
        assert_eq!(scheme.md5_hex(), "305fc37916c150b282ecb61e9ee141d7");
        let mut rng = SmallRng::seed_from_u64(1);
        assert_eq!(scheme.auth_padding_length(&mut rng), 30);
    }

    #[test]
    fn update_parser_rejects_unbounded_values() {
        assert!(PaddingScheme::parse("stop=65\n0=1-1\n").is_err());
        assert!(PaddingScheme::parse("stop=2\n0=1-20000\n").is_err());
        assert!(PaddingScheme::parse("0=1-1\n").is_err());
    }

    #[test]
    fn packet_chunks_are_valid_frame_boundaries() {
        let scheme = PaddingScheme::parse("stop=2\n1=20-20\n").unwrap();
        let mut rng = SmallRng::seed_from_u64(2);
        let chunks = scheme.packet_chunks(1, b"abc", &mut rng).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 20);
        assert_eq!(&chunks[0][..3], b"abc");
        assert_eq!(chunks[0][3], CMD_WASTE);
    }

    #[test]
    fn a_gap_smaller_than_a_frame_header_never_underflows() {
        let scheme = PaddingScheme::parse("stop=2\n1=10-10\n").unwrap();
        let mut rng = SmallRng::seed_from_u64(3);
        let chunks = scheme.packet_chunks(1, b"123456789", &mut rng).unwrap();
        assert_eq!(chunks, [BytesMut::from(&b"123456789"[..])]);
    }
}
