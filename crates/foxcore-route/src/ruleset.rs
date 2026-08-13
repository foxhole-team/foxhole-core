//! Signed, non-executable DNS rule-set bundles.
//!
//! The update channel signs the exact manifest bytes with ECDSA P-256. The
//! manifest binds a compact FST artifact by size and SHA-256; the artifact
//! header binds the upstream input digest and exact entry counts. Verification
//! also enforces expiry and a caller-owned monotonic sequence floor, so a valid
//! old release cannot be replayed as a downgrade.

use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::sync::Arc;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ParsedPublicKey};
use foxcore_api::DnsCategory;
use fst::{Map, MapBuilder, Streamer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::{FLAG_EXACT, FLAG_SUFFIX, MAX_DOMAIN_BYTES, category_bit, reversed_key};

pub const RULE_SET_FORMAT: &str = "foxhole-dns-fst-v1";
pub const RULE_SET_MAGIC: [u8; 8] = *b"FHDNS1\0\0";
pub const RULE_SET_HEADER_LEN: usize = 80;

const MANIFEST_SCHEMA: u32 = 2;
const CORE_SCHEMA: u32 = 1;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 256;
pub const MAX_PUBLIC_KEY_BYTES: usize = 4 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_RULE_ENTRIES: usize = 5_000_000;
const SHA256_HEX_LEN: usize = 64;

/// Freshness and identity constraints supplied by the trusted application.
#[derive(Debug, Clone, Copy)]
pub struct RuleSetVerificationPolicy<'a> {
    pub expected_name: &'a str,
    pub minimum_sequence: u64,
    pub now_unix_s: u64,
    pub max_future_skew_s: u64,
    pub max_validity_s: u64,
}

impl<'a> RuleSetVerificationPolicy<'a> {
    pub fn new(expected_name: &'a str, minimum_sequence: u64, now_unix_s: u64) -> Self {
        Self {
            expected_name,
            minimum_sequence,
            now_unix_s,
            max_future_skew_s: 10 * 60,
            max_validity_s: 31 * 24 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRuleSetMetadata {
    pub name: String,
    pub sequence: u64,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub source_commit: String,
    pub block_entries: usize,
    pub allow_entries: usize,
    pub artifact_sha256: [u8; 32],
    pub public_key_sha256: [u8; 32],
}

#[derive(Clone)]
pub struct VerifiedRuleSet {
    metadata: VerifiedRuleSetMetadata,
    artifact: RuleSetArtifact,
}

impl std::fmt::Debug for VerifiedRuleSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRuleSet")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl VerifiedRuleSet {
    pub fn metadata(&self) -> &VerifiedRuleSetMetadata {
        &self.metadata
    }

    pub fn into_artifact(self) -> RuleSetArtifact {
        self.artifact
    }

    pub fn artifact(&self) -> &RuleSetArtifact {
        &self.artifact
    }
}

/// Parsed FST data. External bytes should normally reach this type only through
/// `verify_rule_set`; the unsigned parser is reserved for bytes embedded in the
/// signed application package itself.
#[derive(Clone)]
pub struct RuleSetArtifact {
    pub(crate) block: Arc<Map<Vec<u8>>>,
    pub(crate) allow: Arc<Map<Vec<u8>>>,
    pub(crate) block_entries: usize,
    pub(crate) allow_entries: usize,
    pub(crate) source_sha256: [u8; 32],
}

/// Owned bytes supplied by the trusted host through a non-JSON bootstrap or
/// update API. `name` selects a pinned trust policy; it is never trusted as the
/// manifest identity until signature verification succeeds.
#[derive(Debug, Clone)]
pub struct RuleSetBundle {
    pub name: String,
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    pub artifact: Vec<u8>,
}

/// Rule-set bytes whose trust comes from the signed application package.
///
/// This type deliberately has no public constructor. A downloaded file must
/// remain a [`RuleSetBundle`] and pass signature, freshness and rollback
/// verification; only platform bootstrap code at the APK trust boundary may
/// create this value.
#[derive(Debug, Clone)]
pub struct TrustedRuleSetBundle {
    pub name: String,
    pub(crate) artifact: Vec<u8>,
}

impl TrustedRuleSetBundle {
    pub fn from_signed_package(name: String, artifact: Vec<u8>) -> Self {
        Self { name, artifact }
    }

    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.name, self.artifact)
    }
}

/// Reproducible output of the host-side DNS list compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRuleSetArtifact {
    pub bytes: Vec<u8>,
    pub block_entries: usize,
    pub allow_entries: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleSetBuildError {
    #[error("rule-set source or output exceeds its hard size limit")]
    TooLarge,
    #[error("rule-set contains an invalid DNS name")]
    InvalidDomain,
    #[error("rule-set FST could not be built")]
    BuildFailed,
}

impl RuleSetArtifact {
    pub fn block_entries(&self) -> usize {
        self.block_entries
    }

    pub fn allow_entries(&self) -> usize {
        self.allow_entries
    }

    pub fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleSetError {
    #[error("rule-set input exceeds its hard size limit")]
    TooLarge,
    #[error("rule-set input is empty or truncated")]
    Truncated,
    #[error("rule-set manifest signature is invalid")]
    InvalidSignature,
    #[error("rule-set manifest JSON is invalid")]
    InvalidManifest,
    #[error("rule-set manifest schema or format is unsupported")]
    UnsupportedManifest,
    #[error("rule-set manifest identity does not match the configured source")]
    WrongIdentity,
    #[error("rule-set manifest was generated too far in the future")]
    FutureManifest,
    #[error("rule-set manifest is expired or has an invalid validity window")]
    ExpiredManifest,
    #[error("rule-set manifest sequence is below the accepted floor")]
    Rollback,
    #[error("rule-set public key does not match the signed manifest")]
    WrongKey,
    #[error("rule-set artifact size or SHA-256 does not match the manifest")]
    ArtifactMismatch,
    #[error("rule-set artifact header or FST payload is invalid")]
    InvalidArtifact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    name: String,
    format: String,
    sequence: u64,
    generated_at_unix: u64,
    expires_at_unix: u64,
    key_sha256: String,
    source: ManifestSource,
    artifact: ManifestArtifact,
    compatibility: ManifestCompatibility,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSource {
    name: String,
    repo: String,
    commit: String,
    license: String,
    input_path: String,
    input_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestArtifact {
    file: String,
    size: u64,
    sha256: String,
    block_entries: u64,
    allow_entries: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestCompatibility {
    core_schema: u32,
}

/// Verify a downloaded update and parse its FST maps.
///
/// `public_key` accepts either RFC 5280 SubjectPublicKeyInfo DER (what OpenSSL
/// emits for `pkey -pubout -outform DER`) or a SEC1 uncompressed P-256 point.
pub fn verify_rule_set(
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    artifact_bytes: &[u8],
    policy: RuleSetVerificationPolicy<'_>,
) -> Result<VerifiedRuleSet, RuleSetError> {
    validate_input_sizes(manifest_bytes, signature, public_key, artifact_bytes)?;

    let key = ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .map_err(|_| RuleSetError::WrongKey)?;
    key.verify_sig(manifest_bytes, signature)
        .map_err(|_| RuleSetError::InvalidSignature)?;

    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| RuleSetError::InvalidManifest)?;
    validate_manifest(&manifest, public_key, artifact_bytes, policy)?;

    let artifact = parse_artifact(artifact_bytes)?;
    let block_entries =
        usize::try_from(manifest.artifact.block_entries).map_err(|_| RuleSetError::TooLarge)?;
    let allow_entries =
        usize::try_from(manifest.artifact.allow_entries).map_err(|_| RuleSetError::TooLarge)?;
    if artifact.block_entries != block_entries
        || artifact.allow_entries != allow_entries
        || encode_hex(&artifact.source_sha256) != manifest.source.input_sha256
    {
        return Err(RuleSetError::ArtifactMismatch);
    }
    let artifact_sha256 = sha256(artifact_bytes);
    Ok(VerifiedRuleSet {
        metadata: VerifiedRuleSetMetadata {
            name: manifest.name,
            sequence: manifest.sequence,
            generated_at_unix: manifest.generated_at_unix,
            expires_at_unix: manifest.expires_at_unix,
            source_commit: manifest.source.commit,
            block_entries,
            allow_entries,
            artifact_sha256,
            public_key_sha256: sha256(public_key),
        },
        artifact,
    })
}

/// Parse a rule set that is already covered by the application package's
/// signature. Never use this for downloaded bytes.
pub fn parse_trusted_embedded_rule_set(bytes: &[u8]) -> Result<RuleSetArtifact, RuleSetError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(RuleSetError::TooLarge);
    }
    parse_artifact(bytes)
}

/// Compile normalized DNS suffixes into the same bounded artifact parsed by
/// the Android data plane.
///
/// This is a host/build-time API. It deliberately accepts the exact upstream
/// bytes separately from the parsed names so the artifact header binds the
/// reproducible source digest rather than a lossy normalized representation.
pub fn compile_rule_set_artifact(
    source_bytes: &[u8],
    block_suffixes: &[String],
    allow_suffixes: &[String],
    category: Option<DnsCategory>,
) -> Result<CompiledRuleSetArtifact, RuleSetBuildError> {
    if source_bytes.len() > MAX_ARTIFACT_BYTES
        || block_suffixes.len() > MAX_RULE_ENTRIES
        || allow_suffixes.len() > MAX_RULE_ENTRIES
    {
        return Err(RuleSetBuildError::TooLarge);
    }
    let category_flag = category.map(category_bit).unwrap_or(0);
    let block = compile_suffix_map(block_suffixes, category_flag)?;
    let allow = compile_suffix_map(allow_suffixes, 0)?;
    let output_len = RULE_SET_HEADER_LEN
        .checked_add(block.bytes.len())
        .and_then(|value| value.checked_add(allow.bytes.len()))
        .ok_or(RuleSetBuildError::TooLarge)?;
    if output_len > MAX_ARTIFACT_BYTES {
        return Err(RuleSetBuildError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(output_len);
    bytes.extend_from_slice(&RULE_SET_MAGIC);
    bytes.extend_from_slice(&(block.entries as u64).to_be_bytes());
    bytes.extend_from_slice(&(allow.entries as u64).to_be_bytes());
    bytes.extend_from_slice(&(block.bytes.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&(allow.bytes.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&sha256(source_bytes));
    bytes.extend_from_slice(&[0_u8; 8]);
    bytes.extend_from_slice(&block.bytes);
    bytes.extend_from_slice(&allow.bytes);
    Ok(CompiledRuleSetArtifact {
        bytes,
        block_entries: block.entries,
        allow_entries: allow.entries,
    })
}

struct CompiledMap {
    bytes: Vec<u8>,
    entries: usize,
}

fn compile_suffix_map(
    domains: &[String],
    category_flag: u64,
) -> Result<CompiledMap, RuleSetBuildError> {
    let mut entries = BTreeMap::<String, u64>::new();
    for domain in domains {
        let mut buffer = [0_u8; MAX_DOMAIN_BYTES];
        let key = reversed_key(domain, &mut buffer).ok_or(RuleSetBuildError::InvalidDomain)?;
        *entries.entry(key.to_owned()).or_default() |= FLAG_SUFFIX | category_flag;
    }
    let mut builder = MapBuilder::memory();
    for (key, value) in &entries {
        builder
            .insert(key, *value)
            .map_err(|_| RuleSetBuildError::BuildFailed)?;
    }
    let bytes = builder
        .into_inner()
        .map_err(|_| RuleSetBuildError::BuildFailed)?;
    Ok(CompiledMap {
        bytes,
        entries: entries.len(),
    })
}

fn validate_input_sizes(
    manifest: &[u8],
    signature: &[u8],
    public_key: &[u8],
    artifact: &[u8],
) -> Result<(), RuleSetError> {
    if manifest.is_empty() || signature.is_empty() || public_key.is_empty() || artifact.is_empty() {
        return Err(RuleSetError::Truncated);
    }
    if manifest.len() > MAX_MANIFEST_BYTES
        || signature.len() > MAX_SIGNATURE_BYTES
        || public_key.len() > MAX_PUBLIC_KEY_BYTES
        || artifact.len() > MAX_ARTIFACT_BYTES
    {
        return Err(RuleSetError::TooLarge);
    }
    Ok(())
}

fn validate_manifest(
    manifest: &Manifest,
    public_key: &[u8],
    artifact: &[u8],
    policy: RuleSetVerificationPolicy<'_>,
) -> Result<(), RuleSetError> {
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.format != RULE_SET_FORMAT
        || manifest.compatibility.core_schema != CORE_SCHEMA
    {
        return Err(RuleSetError::UnsupportedManifest);
    }
    if manifest.name != policy.expected_name
        || !valid_text(&manifest.name, 128)
        || !valid_source(&manifest.source)
        || !valid_artifact_name(&manifest.artifact.file)
    {
        return Err(RuleSetError::WrongIdentity);
    }
    if manifest.sequence < policy.minimum_sequence {
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
    if encode_hex(&sha256(public_key)) != manifest.key_sha256 {
        return Err(RuleSetError::WrongKey);
    }
    let artifact_size =
        usize::try_from(manifest.artifact.size).map_err(|_| RuleSetError::TooLarge)?;
    if artifact_size != artifact.len()
        || encode_hex(&sha256(artifact)) != manifest.artifact.sha256
        || manifest.artifact.block_entries > MAX_RULE_ENTRIES as u64
        || manifest.artifact.allow_entries > MAX_RULE_ENTRIES as u64
    {
        return Err(RuleSetError::ArtifactMismatch);
    }
    Ok(())
}

fn valid_source(source: &ManifestSource) -> bool {
    valid_text(&source.name, 128)
        && source.repo.starts_with("https://")
        && valid_text(&source.repo, 2048)
        && valid_text(&source.commit, 128)
        && valid_text(&source.license, 64)
        && valid_relative_path(&source.input_path)
        && decode_hex_32(&source.input_sha256).is_some()
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

fn valid_relative_path(value: &str) -> bool {
    if value.is_empty() || value.len() > 1024 || value.contains('\\') {
        return false;
    }
    Path::new(value)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_artifact_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_artifact(bytes: &[u8]) -> Result<RuleSetArtifact, RuleSetError> {
    if bytes.len() < RULE_SET_HEADER_LEN || bytes[..8] != RULE_SET_MAGIC {
        return Err(RuleSetError::InvalidArtifact);
    }
    if bytes[72..RULE_SET_HEADER_LEN].iter().any(|byte| *byte != 0) {
        return Err(RuleSetError::InvalidArtifact);
    }
    let block_entries = read_usize(&bytes[8..16])?;
    let allow_entries = read_usize(&bytes[16..24])?;
    let block_len = read_usize(&bytes[24..32])?;
    let allow_len = read_usize(&bytes[32..40])?;
    if block_entries > MAX_RULE_ENTRIES || allow_entries > MAX_RULE_ENTRIES {
        return Err(RuleSetError::TooLarge);
    }
    let block_end = RULE_SET_HEADER_LEN
        .checked_add(block_len)
        .ok_or(RuleSetError::TooLarge)?;
    let allow_end = block_end
        .checked_add(allow_len)
        .ok_or(RuleSetError::TooLarge)?;
    if allow_end != bytes.len() {
        return Err(RuleSetError::InvalidArtifact);
    }
    let mut source_sha256 = [0_u8; 32];
    source_sha256.copy_from_slice(&bytes[40..72]);
    let block = Arc::new(
        Map::new(bytes[RULE_SET_HEADER_LEN..block_end].to_vec())
            .map_err(|_| RuleSetError::InvalidArtifact)?,
    );
    let allow = Arc::new(
        Map::new(bytes[block_end..allow_end].to_vec())
            .map_err(|_| RuleSetError::InvalidArtifact)?,
    );
    validate_map(&block, block_entries, true)?;
    validate_map(&allow, allow_entries, false)?;
    Ok(RuleSetArtifact {
        block,
        allow,
        block_entries,
        allow_entries,
        source_sha256,
    })
}

fn validate_map(
    map: &Map<Vec<u8>>,
    expected_entries: usize,
    block: bool,
) -> Result<(), RuleSetError> {
    if map.len() != expected_entries {
        return Err(RuleSetError::InvalidArtifact);
    }
    let category_mask = [
        DnsCategory::Malicious,
        DnsCategory::Telemetry,
        DnsCategory::Trackers,
        DnsCategory::Ads,
    ]
    .into_iter()
    .fold(0, |mask, category| mask | category_bit(category));
    let allowed_flags = FLAG_EXACT | FLAG_SUFFIX | if block { category_mask } else { 0 };
    let mut stream = map.stream();
    while let Some((key, value)) = stream.next() {
        if !valid_reversed_domain(key)
            || value & (FLAG_EXACT | FLAG_SUFFIX) == 0
            || value & !allowed_flags != 0
        {
            return Err(RuleSetError::InvalidArtifact);
        }
    }
    Ok(())
}

fn valid_reversed_domain(key: &[u8]) -> bool {
    if key.is_empty() || key.len() >= MAX_DOMAIN_BYTES || !key.is_ascii() {
        return false;
    }
    key.split(|byte| *byte == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
    })
}

fn read_usize(bytes: &[u8]) -> Result<usize, RuleSetError> {
    let value = u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| RuleSetError::InvalidArtifact)?,
    );
    usize::try_from(value).map_err(|_| RuleSetError::TooLarge)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != SHA256_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use fst::MapBuilder;
    use serde_json::json;

    use super::*;

    fn map(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut builder = MapBuilder::memory();
        for (key, value) in entries {
            builder.insert(key, *value).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn artifact() -> Vec<u8> {
        let source_sha256 = [7_u8; 32];
        let block = map(&[(
            "com.example.ads",
            FLAG_SUFFIX | category_bit(DnsCategory::Ads),
        )]);
        let allow = map(&[("com.example.ads.safe", FLAG_SUFFIX)]);
        let mut bytes = Vec::with_capacity(RULE_SET_HEADER_LEN + block.len() + allow.len());
        bytes.extend_from_slice(&RULE_SET_MAGIC);
        bytes.extend_from_slice(&1_u64.to_be_bytes());
        bytes.extend_from_slice(&1_u64.to_be_bytes());
        bytes.extend_from_slice(&(block.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(allow.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&source_sha256);
        bytes.extend_from_slice(&[0_u8; 8]);
        bytes.extend_from_slice(&block);
        bytes.extend_from_slice(&allow);
        bytes
    }

    fn signed_bundle(
        artifact: &[u8],
    ) -> (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        RuleSetVerificationPolicy<'static>,
    ) {
        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let manifest = serde_json::to_vec(&json!({
            "schema": 2,
            "name": "foxhole-adguard-dns",
            "format": RULE_SET_FORMAT,
            "sequence": 7,
            "generated_at_unix": 1_000,
            "expires_at_unix": 2_000,
            "key_sha256": encode_hex(&sha256(&public_key)),
            "source": {
                "name": "AdGuardSDNSFilter",
                "repo": "https://github.com/AdguardTeam/AdGuardSDNSFilter",
                "commit": "0123456789abcdef",
                "license": "GPL-3.0",
                "input_path": "Filters/filter.txt",
                "input_sha256": encode_hex(&[7_u8; 32])
            },
            "artifact": {
                "file": "adguard-dns-filter.fhds",
                "size": artifact.len(),
                "sha256": encode_hex(&sha256(artifact)),
                "block_entries": 1,
                "allow_entries": 1
            },
            "compatibility": { "core_schema": 1 }
        }))
        .unwrap();
        let signature = key_pair
            .sign(&SystemRandom::new(), &manifest)
            .unwrap()
            .as_ref()
            .to_vec();
        (
            manifest,
            signature,
            public_key,
            RuleSetVerificationPolicy::new("foxhole-adguard-dns", 6, 1_500),
        )
    }

    #[test]
    fn verifies_signature_freshness_hashes_and_fst_payloads() {
        let artifact = artifact();
        let (manifest, signature, public_key, policy) = signed_bundle(&artifact);
        let verified =
            verify_rule_set(&manifest, &signature, &public_key, &artifact, policy).unwrap();
        assert_eq!(verified.metadata().sequence, 7);
        assert_eq!(verified.metadata().block_entries, 1);
        assert_eq!(verified.metadata().allow_entries, 1);
        assert_eq!(verified.artifact.source_sha256(), [7_u8; 32]);
    }

    #[test]
    fn refuses_tampering_rollback_and_expiry() {
        let artifact = artifact();
        let (manifest, signature, public_key, policy) = signed_bundle(&artifact);

        let mut tampered_manifest = manifest.clone();
        tampered_manifest.push(b' ');
        assert_eq!(
            verify_rule_set(
                &tampered_manifest,
                &signature,
                &public_key,
                &artifact,
                policy
            )
            .unwrap_err(),
            RuleSetError::InvalidSignature
        );

        let mut rollback = policy;
        rollback.minimum_sequence = 8;
        assert_eq!(
            verify_rule_set(&manifest, &signature, &public_key, &artifact, rollback).unwrap_err(),
            RuleSetError::Rollback
        );

        let mut expired = policy;
        expired.now_unix_s = 2_000;
        assert_eq!(
            verify_rule_set(&manifest, &signature, &public_key, &artifact, expired).unwrap_err(),
            RuleSetError::ExpiredManifest
        );
    }
}
