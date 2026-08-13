use std::time::Duration;

pub(crate) const DNS_HEADER_LEN: usize = 12;
pub(crate) const MAX_POINTER_JUMPS: usize = 32;
pub(crate) const MAX_TTL: u32 = 24 * 60 * 60;
pub(crate) const STALE_TTL: Duration = Duration::from_secs(5 * 60);
/// How often `fake_domain` runs a full expiry sweep. Expiry is otherwise lazy, so
/// the per-flow cost stays O(1) instead of scanning the whole fake-IP map.
pub(crate) const FAKE_SWEEP_INTERVAL: u64 = 256;
pub(crate) const RECORD_A: u16 = 1;
pub(crate) const RECORD_AAAA: u16 = 28;
pub(crate) const RECORD_OPT: u16 = 41;
/// The two record types that carry address hints inside them (RFC 9460
/// `ipv4hint`/`ipv6hint`), which is what makes them a fake-IP bypass rather than
/// just another question the interceptor does not synthesize.
pub(crate) const RECORD_SVCB: u16 = 64;
pub(crate) const RECORD_HTTPS: u16 = 65;
pub(crate) const CLASS_IN: u16 = 1;
