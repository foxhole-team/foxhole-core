//! Bounded domain blocklist shared by the DNS gateway and the route table.
//!
//! Entries are compiled into one finite-state transducer keyed by the name with
//! its labels reversed, so `ads.example.com` is stored as `com.example.ads`. A
//! *suffix* entry blocks that label path and everything under it; an *exact*
//! entry blocks only the name itself. Lookup normalises into a stack buffer and
//! walks the automaton byte by byte, so it performs no heap allocation on the
//! DNS hot path (final.txt §21).
//!
//! **Why an FST and not the trie this used to be.** The previous structure held
//! a `HashMap` per node and a `String` per label, which measured at ~224 bytes
//! per domain. A real blocklist is hundreds of thousands of names — OISD Big is
//! ~707k — which put it at ~150 MiB of heap inside a `VpnService` process. That
//! is not "heavy", it is an OOM kill, and it meant the product could not load
//! any list people actually use. The same corpus in an FST measures ~15 bytes
//! per domain, because the automaton shares suffixes as well as prefixes.
//!
//! The value stored against each key is a bitmask: two flag bits for how the
//! entry matches, and one bit per category. Carrying the category here rather
//! than in a second lookup is what lets a refusal say *which rule set* refused —
//! the security journal records that, and it costs about a byte per domain.

use std::collections::BTreeMap;
use std::sync::Arc;

use foxcore_api::DnsCategory;
use fst::Map;
use fst::raw::Output;

use crate::ruleset::RuleSetArtifact;

/// Longest legal DNS name, plus room for a trailing dot.
pub(crate) const MAX_DOMAIN_BYTES: usize = 255;

/// The entry blocks only the exact name it was compiled from.
pub(crate) const FLAG_EXACT: u64 = 1 << 0;
/// The entry blocks its own name and every name beneath it.
pub(crate) const FLAG_SUFFIX: u64 = 1 << 1;
/// Category bits start here. One bit per category keeps a domain that appears in
/// several lists honest about all of them.
pub(crate) const CATEGORY_SHIFT: u32 = 8;

pub(crate) fn category_bit(category: DnsCategory) -> u64 {
    1 << (CATEGORY_SHIFT + category as u32)
}

/// Why a name was refused: how it matched, and which rule sets claim it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockVerdict {
    flags: u64,
}

impl BlockVerdict {
    /// The categories that claim this name, most significant first by
    /// declaration order. Empty when the entry came from an uncategorised list.
    pub fn categories(self) -> impl Iterator<Item = DnsCategory> {
        [
            DnsCategory::Malicious,
            DnsCategory::Telemetry,
            DnsCategory::Trackers,
            DnsCategory::Ads,
        ]
        .into_iter()
        .filter(move |category| self.flags & category_bit(*category) != 0)
    }

    /// The single category to report. `Malicious` outranks the rest: when a name
    /// is on both a malware list and an ad list, the user needs to be told the
    /// worse thing.
    pub fn category(self) -> Option<DnsCategory> {
        self.categories().next()
    }
}

/// One categorised or uncategorised group of entries to compile.
#[derive(Debug, Clone, Default)]
pub struct BlocklistSource<'a> {
    pub category: Option<DnsCategory>,
    pub exact: &'a [String],
    pub suffixes: &'a [String],
}

#[derive(Debug, Default)]
pub struct DomainBlocklist {
    /// One compact automaton for inline rules and one per verified update
    /// artifact. Keeping them separate avoids rebuilding a multi-megabyte FST
    /// every time a signed list is atomically replaced.
    maps: Vec<Arc<Map<Vec<u8>>>>,
    /// Exception maps are checked first. A signed allow rule is deliberately
    /// fail-open for that name only; it cannot alter routing or execute code.
    allow_maps: Vec<Arc<Map<Vec<u8>>>>,
    entries: usize,
}

impl DomainBlocklist {
    /// Compile uncategorised entries. Kept for callers that have no categories.
    pub fn compile(exact: &[String], suffixes: &[String]) -> Self {
        Self::compile_sources(&[BlocklistSource {
            category: None,
            exact,
            suffixes,
        }])
    }

    /// Compile every group into one automaton.
    ///
    /// A name that appears in several groups keeps the union of their flags, so
    /// listing a domain as both exact and suffix, or in two categories, does not
    /// lose either fact.
    pub fn compile_sources(sources: &[BlocklistSource<'_>]) -> Self {
        // Built through a `BTreeMap` because an FST demands its keys in
        // lexicographic order and refuses duplicates. This is the compile path,
        // not the lookup path, so the transient cost buys the permanent saving.
        let mut keys: BTreeMap<String, u64> = BTreeMap::new();
        let mut entries = 0;
        for source in sources {
            let category = source.category.map(category_bit).unwrap_or(0);
            for (names, flag) in [(source.exact, FLAG_EXACT), (source.suffixes, FLAG_SUFFIX)] {
                for name in names {
                    let mut buf = [0u8; MAX_DOMAIN_BYTES];
                    let Some(key) = reversed_key(name, &mut buf) else {
                        continue;
                    };
                    *keys.entry(key.to_owned()).or_insert(0) |= flag | category;
                    entries += 1;
                }
            }
        }
        let Some(map) = compile_map(&keys) else {
            return Self::default();
        };
        Self {
            maps: vec![Arc::new(map)],
            allow_maps: Vec::new(),
            entries,
        }
    }

    /// Attach a small, configuration-owned exception list.
    ///
    /// Signed artifact exceptions and these dynamic user exceptions share the
    /// same lookup-first semantics, so a bypass can never be shadowed by a
    /// larger downloaded list.
    pub fn with_allowlist(mut self, exact: &[String], suffixes: &[String]) -> Self {
        let mut keys: BTreeMap<String, u64> = BTreeMap::new();
        for (names, flag) in [(exact, FLAG_EXACT), (suffixes, FLAG_SUFFIX)] {
            for name in names {
                let mut buf = [0_u8; MAX_DOMAIN_BYTES];
                let Some(key) = reversed_key(name, &mut buf) else {
                    continue;
                };
                *keys.entry(key.to_owned()).or_insert(0) |= flag;
            }
        }
        if let Some(map) = compile_map(&keys) {
            self.allow_maps.push(Arc::new(map));
        }
        self
    }

    /// Attach already parsed signed rule-set artifacts without recompiling
    /// their FST payloads. The caller decides whether a bundle is an embedded
    /// trust root or has passed `ruleset::verify_rule_set`.
    pub fn with_rule_sets(mut self, rule_sets: Vec<RuleSetArtifact>) -> Self {
        for rule_set in rule_sets {
            self.entries = self.entries.saturating_add(rule_set.block_entries);
            if rule_set.block_entries > 0 {
                self.maps.push(rule_set.block);
            }
            if rule_set.allow_entries > 0 {
                self.allow_maps.push(rule_set.allow);
            }
        }
        self
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    pub fn len(&self) -> usize {
        self.entries
    }

    /// True when `domain` is blocked. Allocation-free.
    pub fn blocks(&self, domain: &str) -> bool {
        self.lookup(domain).is_some()
    }

    /// The verdict for `domain`, carrying which rule sets claim it.
    ///
    /// Walks the automaton one byte at a time, checking at each label boundary
    /// whether a suffix entry ends there. That boundary check is what keeps this
    /// a name match and not a substring one: `nottracker.net` must not match an
    /// entry for `tracker.net`.
    pub fn lookup(&self, domain: &str) -> Option<BlockVerdict> {
        let mut buf = [0u8; MAX_DOMAIN_BYTES];
        let key = reversed_key(domain, &mut buf)?;
        if self
            .allow_maps
            .iter()
            .any(|map| lookup_map(map, key).is_some())
        {
            return None;
        }
        let flags = self
            .maps
            .iter()
            .filter_map(|map| lookup_map(map, key))
            .fold(0, |combined, flags| combined | flags);
        (flags != 0).then_some(BlockVerdict { flags })
    }
}

fn compile_map(keys: &BTreeMap<String, u64>) -> Option<Map<Vec<u8>>> {
    if keys.is_empty() {
        return None;
    }
    let mut builder = fst::MapBuilder::memory();
    for (key, value) in keys {
        // The only way this fails is out-of-order insertion, and a `BTreeMap`
        // cannot produce that.
        builder.insert(key, *value).ok()?;
    }
    builder
        .into_inner()
        .ok()
        .and_then(|bytes| Map::new(bytes).ok())
}

fn lookup_map(map: &Map<Vec<u8>>, key: &str) -> Option<u64> {
    let fst = map.as_fst();
    let mut node = fst.root();
    let mut output = Output::zero();
    let mut matched = 0;
    for byte in key.as_bytes() {
        // A separator means the labels consumed so far form a whole name.
        if *byte == b'.' && node.is_final() {
            let flags = output.cat(node.final_output()).value();
            if flags & FLAG_SUFFIX != 0 {
                matched |= flags;
            }
        }
        let Some(index) = node.find_input(*byte) else {
            return (matched != 0).then_some(matched);
        };
        let transition = node.transition(index);
        output = output.cat(transition.out);
        node = fst.node(transition.addr);
    }
    if node.is_final() {
        let flags = output.cat(node.final_output()).value();
        if flags & (FLAG_EXACT | FLAG_SUFFIX) != 0 {
            matched |= flags;
        }
    }
    (matched != 0).then_some(matched)
}

/// Lowercase `domain` into `buf` with its labels reversed, trimming root dots.
///
/// `None` when the name is empty, over-long, or not ASCII (DNS names on the wire
/// are punycode ASCII). Reversing here is what turns "blocked suffix" into
/// "stored key is a prefix of the query at a label boundary", which is the one
/// shape an ordered automaton can answer without scanning.
pub(crate) fn reversed_key<'a>(
    domain: &str,
    buf: &'a mut [u8; MAX_DOMAIN_BYTES],
) -> Option<&'a str> {
    let trimmed = domain.trim_matches('.');
    if trimmed.is_empty() || trimmed.len() > MAX_DOMAIN_BYTES || !trimmed.is_ascii() {
        return None;
    }
    let mut written = 0;
    for label in trimmed.rsplit('.').filter(|label| !label.is_empty()) {
        if written > 0 {
            buf[written] = b'.';
            written += 1;
        }
        for byte in label.bytes() {
            buf[written] = byte.to_ascii_lowercase();
            written += 1;
        }
    }
    if written == 0 {
        return None;
    }
    std::str::from_utf8(&buf[..written]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffixes(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn empty_blocklist_blocks_nothing() {
        let list = DomainBlocklist::compile(&[], &[]);
        assert!(list.is_empty());
        assert!(!list.blocks("anything.example"));
    }

    #[test]
    fn exact_entries_match_only_the_whole_name() {
        let list = DomainBlocklist::compile(&["ads.example.com".to_string()], &[]);
        assert!(list.blocks("ads.example.com"));
        // Case and a trailing root dot are normalised away.
        assert!(list.blocks("ADS.Example.COM."));
        // An exact entry must not leak onto parents or children.
        assert!(!list.blocks("example.com"));
        assert!(!list.blocks("img.ads.example.com"));
    }

    #[test]
    fn suffix_entries_cover_the_name_and_everything_under_it() {
        let list = DomainBlocklist::compile(&[], &["tracker.net".to_string()]);
        assert!(list.blocks("tracker.net"));
        assert!(list.blocks("a.b.tracker.net"));
        // Label boundaries are respected — this is not a substring match.
        assert!(!list.blocks("nottracker.net"));
        assert!(!list.blocks("tracker.net.example.com"));
    }

    #[test]
    fn leading_dots_and_bad_input_are_tolerated() {
        let list = DomainBlocklist::compile(&[], &[".ads.example.".to_string()]);
        assert!(list.blocks("x.ads.example"));
        assert_eq!(list.len(), 1);

        let oversized = "a".repeat(MAX_DOMAIN_BYTES + 10);
        assert!(!list.blocks(&oversized));
        assert!(!list.blocks(""));
    }

    #[test]
    fn a_verdict_names_the_rule_set_that_refused() {
        let ads = suffixes(&["ads.example"]);
        let malware = suffixes(&["evil.example"]);
        let list = DomainBlocklist::compile_sources(&[
            BlocklistSource {
                category: Some(DnsCategory::Ads),
                exact: &[],
                suffixes: &ads,
            },
            BlocklistSource {
                category: Some(DnsCategory::Malicious),
                exact: &[],
                suffixes: &malware,
            },
        ]);

        assert_eq!(
            list.lookup("x.ads.example")
                .and_then(BlockVerdict::category),
            Some(DnsCategory::Ads)
        );
        assert_eq!(
            list.lookup("evil.example").and_then(BlockVerdict::category),
            Some(DnsCategory::Malicious)
        );
        assert_eq!(list.lookup("clean.example"), None);
    }

    #[test]
    fn a_name_on_two_lists_keeps_both_and_reports_the_worse_one() {
        let names = suffixes(&["both.example"]);
        let list = DomainBlocklist::compile_sources(&[
            BlocklistSource {
                category: Some(DnsCategory::Ads),
                exact: &[],
                suffixes: &names,
            },
            BlocklistSource {
                category: Some(DnsCategory::Malicious),
                exact: &[],
                suffixes: &names,
            },
        ]);

        let verdict = list.lookup("both.example").unwrap();
        assert_eq!(
            verdict.categories().collect::<Vec<_>>(),
            vec![DnsCategory::Malicious, DnsCategory::Ads],
            "a domain on several lists must not lose any of them"
        );
        assert_eq!(
            verdict.category(),
            Some(DnsCategory::Malicious),
            "the user needs to be told the worse thing"
        );
    }

    #[test]
    fn an_uncategorised_entry_reports_no_category_rather_than_a_guess() {
        let list = DomainBlocklist::compile(&[], &["plain.example".to_string()]);
        let verdict = list.lookup("plain.example").unwrap();
        assert_eq!(verdict.category(), None);
    }

    #[test]
    fn the_same_name_as_exact_and_suffix_keeps_both_meanings() {
        let names = suffixes(&["dual.example"]);
        let list = DomainBlocklist::compile_sources(&[BlocklistSource {
            category: None,
            exact: &names,
            suffixes: &names,
        }]);
        assert!(list.blocks("dual.example"));
        assert!(
            list.blocks("under.dual.example"),
            "the suffix meaning must survive being merged with the exact one"
        );
    }

    #[test]
    fn a_longer_name_that_merely_starts_the_same_is_not_blocked() {
        let list = DomainBlocklist::compile(&[], &["example.com".to_string()]);
        // Reversed keys make this the interesting case: "com.example" is a
        // prefix of "com.exampleextra" as a byte string, and only the label
        // boundary check keeps it from matching.
        assert!(!list.blocks("exampleextra.com"));
        assert!(list.blocks("sub.example.com"));
    }

    #[test]
    fn a_verified_exception_overrides_its_parent_suffix_only() {
        let mut block_builder = fst::MapBuilder::memory();
        block_builder
            .insert("com.example", FLAG_SUFFIX | category_bit(DnsCategory::Ads))
            .unwrap();
        let mut allow_builder = fst::MapBuilder::memory();
        allow_builder
            .insert("com.example.safe", FLAG_SUFFIX)
            .unwrap();
        let rule_set = RuleSetArtifact {
            block: Map::new(block_builder.into_inner().unwrap())
                .unwrap()
                .into(),
            allow: Map::new(allow_builder.into_inner().unwrap())
                .unwrap()
                .into(),
            block_entries: 1,
            allow_entries: 1,
            source_sha256: [0; 32],
        };
        let list = DomainBlocklist::default().with_rule_sets(vec![rule_set]);

        assert!(list.blocks("ads.example.com"));
        assert!(!list.blocks("safe.example.com"));
        assert!(!list.blocks("child.safe.example.com"));
        assert!(list.blocks("unsafe.example.com"));
    }
}
