use super::*;
use serde::{Deserialize, Serialize};

const CATEGORIES: [DnsCategory; 4] = [
    DnsCategory::Malicious,
    DnsCategory::Telemetry,
    DnsCategory::Trackers,
    DnsCategory::Ads,
];

// Field order is canonical key order; large feeds never become a second Value tree.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CategorizedManifest {
    artifact: ArtifactMetadata,
    categories: Vec<DnsCategory>,
    compatibility: Compatibility,
    expires_at_unix: u64,
    format: String,
    generated_at_unix: u64,
    key_sha256: String,
    name: String,
    schema: u32,
    sequence: u64,
    sources: Vec<Source>,
    tagged_input_sha256: String,
    tiers: Tiers,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tiers {
    malicious: MaliciousTier,
    trackers: TrackerTier,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum TrackerTier {
    Normal,
    Pro,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum MaliciousTier {
    Medium,
    Full,
}

impl Tiers {
    fn name(&self) -> String {
        let trackers = match self.trackers {
            TrackerTier::Normal => "normal",
            TrackerTier::Pro => "pro",
        };
        let malicious = match self.malicious {
            MaliciousTier::Medium => "medium",
            MaliciousTier::Full => "full",
        };
        format!("foxhole-dns-categories-{trackers}-{malicious}")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Source {
    categories: Vec<DnsCategory>,
    commit: String,
    id: String,
    inputs: Vec<SourceInput>,
    license: String,
    repo: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CategoryCounts {
    ads: u64,
    malicious: u64,
    telemetry: u64,
    trackers: u64,
}

impl CategoryCounts {
    fn values(&self) -> [u64; 4] {
        [self.malicious, self.telemetry, self.trackers, self.ads]
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactMetadata {
    allow_entries: u64,
    block_entries: u64,
    category_entries: CategoryCounts,
    file: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Compatibility {
    category_schema: u32,
    core_schema: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaggedInput {
    allow_suffixes: Vec<String>,
    block: Vec<TaggedDomain>,
    categories: Vec<DnsCategory>,
    schema: u32,
    sources: Vec<Source>,
    tiers: Tiers,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaggedDomain {
    categories: Vec<DnsCategory>,
    domain: String,
}

pub(super) fn compile(bytes: &[u8]) -> Result<CompiledRuleSetArtifact, RuleSetBuildError> {
    if bytes.is_empty() || bytes.len() > MAX_TAGGED_INPUT_BYTES {
        return Err(RuleSetBuildError::TooLarge);
    }
    let input: TaggedInput =
        serde_json::from_slice(bytes).map_err(|_| RuleSetBuildError::InvalidDomain)?;
    if !canonical_matches(&input, bytes) || input.schema != 1 {
        return Err(RuleSetBuildError::InvalidDomain);
    }
    let available =
        category_mask(&input.categories).map_err(|_| RuleSetBuildError::InvalidDomain)?;
    validate_sources(&input.sources, available).map_err(|_| RuleSetBuildError::InvalidDomain)?;
    if input.block.is_empty()
        || input.block.len() > MAX_RULE_ENTRIES
        || input.allow_suffixes.len() > MAX_RULE_ENTRIES
    {
        return Err(RuleSetBuildError::TooLarge);
    }
    let mut keys = BTreeMap::new();
    let mut previous = None;
    let mut used = 0;
    for block in &input.block {
        if !valid_domain(&block.domain)
            || previous.is_some_and(|last: &str| last >= block.domain.as_str())
        {
            return Err(RuleSetBuildError::InvalidDomain);
        }
        previous = Some(block.domain.as_str());
        let mask =
            category_mask(&block.categories).map_err(|_| RuleSetBuildError::InvalidDomain)?;
        if mask & !available != 0 {
            return Err(RuleSetBuildError::InvalidDomain);
        }
        used |= mask;
        let mut buffer = [0; MAX_DOMAIN_BYTES];
        let key =
            reversed_key(&block.domain, &mut buffer).ok_or(RuleSetBuildError::InvalidDomain)?;
        keys.insert(key.to_owned(), FLAG_SUFFIX | mask);
    }
    if used != available {
        return Err(RuleSetBuildError::InvalidDomain);
    }
    let mut previous = None;
    for domain in &input.allow_suffixes {
        if !valid_domain(domain) || previous.is_some_and(|last: &str| last >= domain.as_str()) {
            return Err(RuleSetBuildError::InvalidDomain);
        }
        previous = Some(domain.as_str());
    }
    let mut builder = MapBuilder::memory();
    for (key, flags) in keys {
        builder
            .insert(key, flags)
            .map_err(|_| RuleSetBuildError::BuildFailed)?;
    }
    let block = CompiledMap {
        bytes: builder
            .into_inner()
            .map_err(|_| RuleSetBuildError::BuildFailed)?,
        entries: input.block.len(),
    };
    let allow = compile_suffix_map(&input.allow_suffixes, 0)?;
    assemble_artifact(bytes, block, allow)
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty() && domain.len() <= 253 && valid_reversed_domain(domain.as_bytes())
}

fn canonical_matches(value: &impl Serialize, expected: &[u8]) -> bool {
    use std::io::Write;
    let mut writer = CanonicalComparison {
        expected,
        position: 0,
    };
    serde_json::to_writer(&mut writer, value).is_ok()
        && writer.write_all(b"\n").is_ok()
        && writer.position == expected.len()
}

struct CanonicalComparison<'a> {
    expected: &'a [u8],
    position: usize,
}

impl std::io::Write for CanonicalComparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("canonical JSON position overflow"))?;
        if !bytes.is_ascii() || self.expected.get(self.position..end) != Some(bytes) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "noncanonical JSON",
            ));
        }
        self.position = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, RuleSetError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| RuleSetError::InvalidManifest)?;
    if !bytes.is_ascii() {
        return Err(RuleSetError::InvalidManifest);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn ascii_text(value: &str, max: usize) -> bool {
    valid_text(value, max) && value.is_ascii()
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn category_mask(categories: &[DnsCategory]) -> Result<u64, RuleSetError> {
    if categories.is_empty() || categories.len() > CATEGORIES.len() {
        return Err(RuleSetError::InvalidManifest);
    }
    let mut mask = 0;
    let mut previous = None;
    for category in categories {
        let index = *category as u32;
        if previous.is_some_and(|last| last >= index) {
            return Err(RuleSetError::InvalidManifest);
        }
        previous = Some(index);
        mask |= category_bit(*category);
    }
    Ok(mask)
}

fn validate_sources(sources: &[Source], available: u64) -> Result<(), RuleSetError> {
    if sources.is_empty() || sources.len() > 16 {
        return Err(RuleSetError::InvalidManifest);
    }
    let mut previous_id = None;
    let mut supplied = 0;
    for source in sources {
        if !ascii_text(&source.id, 128)
            || !source
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || !ascii_text(&source.repo, 2048)
            || !source.repo.starts_with("https://")
            || source.repo[8..].is_empty()
            || source
                .repo
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'@' | b'#' | b'\\'))
            || !lower_hex(&source.commit, 40)
            || !ascii_text(&source.license, 128)
            || source.inputs.is_empty()
            || source.inputs.len() > 16
            || previous_id.is_some_and(|previous: &str| previous >= source.id.as_str())
        {
            return Err(RuleSetError::InvalidManifest);
        }
        previous_id = Some(source.id.as_str());
        let categories = category_mask(&source.categories)?;
        if categories & !available != 0 {
            return Err(RuleSetError::InvalidManifest);
        }
        supplied |= categories;
        let mut previous_path = None;
        for input in &source.inputs {
            if !ascii_text(&input.path, 256)
                || !valid_relative_path(&input.path)
                || input
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || !lower_hex(&input.sha256, 64)
                || previous_path.is_some_and(|previous: &str| previous >= input.path.as_str())
            {
                return Err(RuleSetError::InvalidManifest);
            }
            previous_path = Some(input.path.as_str());
        }
    }
    if supplied != available {
        return Err(RuleSetError::InvalidManifest);
    }
    Ok(())
}

pub(super) fn artifact_categories(artifact: &RuleSetArtifact) -> Result<[u64; 4], RuleSetError> {
    artifact
        .categorized_counts
        .ok_or(RuleSetError::InvalidArtifact)
}

pub(super) fn available_mask(counts: [u64; 4]) -> u64 {
    CATEGORIES
        .iter()
        .enumerate()
        .filter(|(index, _)| counts[*index] > 0)
        .fold(0, |mask, (_, category)| mask | category_bit(*category))
}

pub(super) fn verify(
    bytes: &[u8],
    key: &[u8],
    artifact_bytes: &[u8],
    policy: RuleSetVerificationPolicy<'_>,
) -> Result<VerifiedRuleSet, RuleSetError> {
    let manifest: CategorizedManifest =
        serde_json::from_slice(bytes).map_err(|_| RuleSetError::InvalidManifest)?;
    if !canonical_matches(&manifest, bytes) {
        return Err(RuleSetError::InvalidManifest);
    }
    if manifest.schema != 3
        || manifest.format != RULE_SET_FORMAT
        || manifest.compatibility.core_schema != CORE_SCHEMA
        || manifest.compatibility.category_schema != 1
    {
        return Err(RuleSetError::UnsupportedManifest);
    }
    if manifest.name != policy.expected_name
        || manifest.name != manifest.tiers.name()
        || manifest.artifact.file != "dns-categories.fhds"
    {
        return Err(RuleSetError::WrongIdentity);
    }
    let available = category_mask(&manifest.categories)?;
    validate_sources(&manifest.sources, available)?;
    if manifest.sequence == 0 || manifest.sequence < policy.minimum_sequence {
        return Err(RuleSetError::Rollback);
    }
    if manifest.generated_at_unix > policy.now_unix_s.saturating_add(policy.max_future_skew_s) {
        return Err(RuleSetError::FutureManifest);
    }
    let validity = manifest
        .expires_at_unix
        .checked_sub(manifest.generated_at_unix)
        .ok_or(RuleSetError::ExpiredManifest)?;
    if policy.now_unix_s >= manifest.expires_at_unix
        || validity == 0
        || validity > policy.max_validity_s
    {
        return Err(RuleSetError::ExpiredManifest);
    }
    if !lower_hex(&manifest.key_sha256, 64) || encode_hex(&sha256(key)) != manifest.key_sha256 {
        return Err(RuleSetError::WrongKey);
    }
    if manifest.artifact.size != artifact_bytes.len() as u64
        || !lower_hex(&manifest.artifact.sha256, 64)
        || encode_hex(&sha256(artifact_bytes)) != manifest.artifact.sha256
        || manifest.artifact.block_entries > MAX_RULE_ENTRIES as u64
        || manifest.artifact.allow_entries > MAX_RULE_ENTRIES as u64
        || !lower_hex(&manifest.tagged_input_sha256, 64)
    {
        return Err(RuleSetError::ArtifactMismatch);
    }
    let mut artifact = parse_artifact(artifact_bytes)?;
    let counts = artifact_categories(&artifact)?;
    if artifact.block_entries as u64 != manifest.artifact.block_entries
        || artifact.allow_entries as u64 != manifest.artifact.allow_entries
        || encode_hex(&artifact.source_sha256) != manifest.tagged_input_sha256
        || counts != manifest.artifact.category_entries.values()
        || CATEGORIES.iter().enumerate().any(|(index, category)| {
            (counts[index] > 0) != (available & category_bit(*category) != 0)
        })
    {
        return Err(RuleSetError::ArtifactMismatch);
    }
    artifact.categorized_available_mask = Some(available);
    Ok(VerifiedRuleSet {
        metadata: VerifiedRuleSetMetadata {
            name: manifest.name,
            sequence: manifest.sequence,
            generated_at_unix: manifest.generated_at_unix,
            expires_at_unix: manifest.expires_at_unix,
            source_commit: manifest.sources[0].commit.clone(),
            block_entries: artifact.block_entries,
            allow_entries: artifact.allow_entries,
            artifact_sha256: sha256(artifact_bytes),
            public_key_sha256: sha256(key),
            categorized_manifest_sha256: Some(sha256(bytes)),
        },
        artifact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainBlocklist;

    #[test]
    fn canonical_comparison_requires_exact_ascii_bytes_and_one_newline() {
        let value = serde_json::json!({"escaped":"quote\"backslash\\", "integer":u64::MAX});
        let bytes = include_bytes!("../../tests/fixtures/categories/escape-u64.json");
        assert!(canonical_matches(&value, bytes));
        assert!(!canonical_matches(&value, &bytes[..bytes.len() - 1]));
        let mut extra = bytes.to_vec();
        extra.push(b'\n');
        assert!(!canonical_matches(&value, &extra));
        assert!(!canonical_matches(
            &serde_json::json!({"label":"é"}),
            b"{\"label\":\"\\u00e9\"}\n"
        ));
    }

    #[test]
    fn shared_ascii_escaping_unsigned_integer_and_tagged_golden_bytes_match() {
        let golden = include_bytes!("../../tests/fixtures/categories/escape-u64.json");
        assert_eq!(
            canonical_json(&serde_json::json!({"escaped":"quote\"backslash\\","integer":u64::MAX}))
                .unwrap(),
            golden
        );
        let manifest_bytes =
            include_bytes!("../../tests/fixtures/categories/manifest3-normal-medium.json");
        let manifest: CategorizedManifest = serde_json::from_slice(manifest_bytes).unwrap();
        assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
        let tagged = include_bytes!("../../tests/fixtures/categories/tagged1-normal-medium.json");
        let compiled = compile(tagged).unwrap();
        let parsed = parse_trusted_categorized_rule_set(
            "foxhole-dns-categories-normal-medium",
            &compiled.bytes,
        )
        .unwrap();
        assert_eq!(parsed.source_sha256(), sha256(tagged));
        assert_eq!(artifact_categories(&parsed).unwrap(), [1, 1, 1, 1]);
        let selected = parsed
            .select_categories(Some(&[DnsCategory::Telemetry]))
            .unwrap();
        let list = DomainBlocklist::default().with_rule_sets(vec![selected]);
        assert!(!list.blocks("ads.owned.invalid"));
        assert_eq!(
            list.lookup("telemetry.owned.invalid").unwrap().category(),
            Some(DnsCategory::Telemetry)
        );
        let off = DomainBlocklist::default()
            .with_rule_sets(vec![parsed.select_categories(Some(&[])).unwrap()]);
        assert!(!off.blocks("malicious.owned.invalid"));
    }

    #[test]
    fn tagged_compiler_refuses_ambiguous_and_noncanonical_sources() {
        let bytes = include_bytes!("../../tests/fixtures/categories/tagged1-normal-medium.json");
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        for index in 0..7 {
            let mut changed = value.clone();
            match index {
                0 => changed["block"][0]["match"] = serde_json::json!("exact"),
                1 => changed["block"][0]["categories"] = serde_json::json!(["unknown"]),
                2 => changed["block"][1]["domain"] = changed["block"][0]["domain"].clone(),
                3 => changed["sources"][0]["inputs"][0]["path"] = serde_json::json!("../escape"),
                4 => changed["sources"][0]["commit"] = serde_json::json!("not-immutable"),
                5 => changed["tiers"]["trackers"] = serde_json::json!("unknown"),
                6 => changed["block"][0]["domain"] = serde_json::json!("UPPER.invalid"),
                _ => unreachable!(),
            }
            assert!(
                compile(&canonical_json(&changed).unwrap()).is_err(),
                "accepted malformed variant {index}"
            );
        }
        let mut duplicate = b"{\"schema\":1,".to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        assert!(compile(&duplicate).is_err());
        assert!(compile(&bytes[..bytes.len() - 1]).is_err());
    }
}
