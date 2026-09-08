use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, RwLock};

use aws_lc_rs::digest;
use serde_json::Value;

use super::hello_profile::{
    CHROME_ALPN_PROTOCOLS, CHROME_ECH_GREASE, CipherSuiteSlot, EchGreaseShapeData,
    ExtensionSlotData, GreaseSlot, GroupSlot, HelloProfile, HelloProfileData, KeyShareSlot,
    RealityHelloProfile, VersionSlot, ext,
};
use super::reality_key_exchange::NamedGroup;
use super::reality_tls13_messages::INITIAL_RECORD_VERSION;

const SUPPORTED_SCHEMA: u64 = 1;

static INSTALLED: RwLock<Option<InstalledTables>> = RwLock::new(None);

struct InstalledTables {
    document_digest: [u8; 32],
    profiles: Vec<Option<Arc<OwnedProfile>>>,
}

pub(super) enum Profile {
    Compiled(&'static HelloProfile),
    Installed(Arc<OwnedProfile>),
}

impl Profile {
    pub(super) fn with_profile<R>(&self, body: impl FnOnce(&HelloProfileData<'_>) -> R) -> R {
        match self {
            Self::Compiled(profile) => body(profile),
            Self::Installed(profile) => profile.with_profile(body),
        }
    }
}

pub(super) fn table_for(profile: RealityHelloProfile) -> Profile {
    let Ok(guard) = INSTALLED.read() else {
        return Profile::Compiled(profile.table());
    };
    guard
        .as_ref()
        .and_then(|installed| {
            slot_index(profile).and_then(|index| installed.profiles[index].clone())
        })
        .map(Profile::Installed)
        .unwrap_or_else(|| Profile::Compiled(profile.table()))
}

pub fn install_fingerprint_tables(document: &[u8]) -> io::Result<usize> {
    install_into(&INSTALLED, document)
}

fn install_into(registry: &RwLock<Option<InstalledTables>>, document: &[u8]) -> io::Result<usize> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(refuse("is larger than any table document this build reads"));
    }
    let document_digest = sha256(document);
    let mut guard = registry
        .write()
        .map_err(|_| refuse("table registry is poisoned"))?;
    if let Some(installed) = guard.as_ref()
        && installed.document_digest == document_digest
    {
        return Ok(installed.profiles.iter().flatten().count());
    }

    let parsed = parse_document(document)?;
    let replaced = parsed.iter().flatten().count();
    if replaced == 0 {
        return Err(refuse(
            "carries no table for any profile this build implements",
        ));
    }

    *guard = Some(InstalledTables {
        document_digest,
        profiles: parsed,
    });
    Ok(replaced)
}

pub fn clear_fingerprint_tables() {
    if let Ok(mut guard) = INSTALLED.write() {
        *guard = None;
    }
}

pub fn using_downloaded_fingerprint_tables() -> bool {
    INSTALLED
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|installed| installed.profiles.len()))
        .is_some()
}

fn slot_index(profile: RealityHelloProfile) -> Option<usize> {
    RealityHelloProfile::ALL
        .iter()
        .position(|candidate| *candidate == profile)
}

fn parse_document(document: &[u8]) -> io::Result<Vec<Option<Arc<OwnedProfile>>>> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(refuse("is larger than any table document this build reads"));
    }
    let root: Value = serde_json::from_slice(document)
        .map_err(|error| refuse(&format!("is not valid JSON: {error}")))?;
    let root = root
        .as_object()
        .ok_or_else(|| refuse("is not a JSON object"))?;

    match root.get("schema").and_then(Value::as_u64) {
        Some(SUPPORTED_SCHEMA) => {}
        Some(other) => {
            return Err(refuse(&format!(
                "declares schema {other}; this build reads schema {SUPPORTED_SCHEMA}"
            )));
        }
        None => return Err(refuse("declares no schema")),
    }

    let entries = root
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("carries no profiles array"))?;

    let mut slots = vec![None; RealityHelloProfile::ALL.len()];
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or_else(|| refuse("has a profile entry that is not an object"))?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("has a profile entry with no name"))?;
        if seen.insert(name, ()).is_some() {
            return Err(refuse(&format!("names the profile {name} twice")));
        }
        let Some(profile) = profile_named(name) else {
            continue;
        };
        let fingerprint = entry
            .get("fingerprint")
            .ok_or_else(|| refuse(&format!("profile {name} carries no fingerprint table")))?;
        verify_declared_digest(name, entry.get("fingerprint_sha256"), fingerprint)?;
        let table = build_profile(profile, fingerprint)?;
        let index = slot_index(profile).ok_or_else(|| refuse("profile is not in ALL"))?;
        slots[index] = Some(Arc::new(table));
    }
    Ok(slots)
}

const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

fn profile_named(name: &str) -> Option<RealityHelloProfile> {
    RealityHelloProfile::ALL
        .iter()
        .copied()
        .find(|profile| profile.table().name == name)
}

fn verify_declared_digest(name: &str, declared: Option<&Value>, table: &Value) -> io::Result<()> {
    let declared = declared
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(&format!("profile {name} declares no fingerprint_sha256")))?;
    let canonical = canonical_json(table);
    if !canonical.is_ascii() {
        return Err(refuse(&format!(
            "profile {name} contains non-ASCII, so its digest would depend on an escaping \
             convention"
        )));
    }
    let derived = hex(&sha256(canonical.as_bytes()));
    if derived != declared.to_ascii_lowercase() {
        return Err(refuse(&format!(
            "profile {name} hashes to {derived} but declares {declared}"
        )));
    }
    Ok(())
}

pub(super) struct OwnedProfile {
    name: &'static str,
    cipher_suites: Vec<CipherSuiteSlot>,
    extensions: Vec<OwnedExtension>,
    permute_extensions: bool,
    ech_grease: OwnedEchShape,
    reuse_classical_key_share: bool,
}

struct OwnedEchShape {
    suites: Vec<(u16, u16)>,
    payload_lens: Vec<usize>,
}

impl OwnedEchShape {
    fn as_borrowed(&self) -> EchGreaseShapeData<'_> {
        EchGreaseShapeData {
            suites: &self.suites,
            payload_lens: &self.payload_lens,
        }
    }
}

enum OwnedExtension {
    Constant { extension_type: u16, body: Vec<u8> },
    Grease { slot: GreaseSlot, body: Vec<u8> },
    ServerName,
    SupportedGroups(Vec<GroupSlot>),
    KeyShare(Vec<KeyShareSlot>),
    Alpn,
    SupportedVersions(Vec<VersionSlot>),
    EchGrease,
    Padding,
}

impl OwnedExtension {
    fn as_borrowed(&self) -> ExtensionSlotData<'_> {
        match self {
            Self::Constant {
                extension_type,
                body,
            } => ExtensionSlotData::Constant {
                extension_type: *extension_type,
                body,
            },
            Self::Grease { slot, body } => ExtensionSlotData::Grease { slot: *slot, body },
            Self::ServerName => ExtensionSlotData::ServerName,
            Self::SupportedGroups(groups) => ExtensionSlotData::SupportedGroups(groups),
            Self::KeyShare(shares) => ExtensionSlotData::KeyShare(shares),
            Self::Alpn => ExtensionSlotData::Alpn,
            Self::SupportedVersions(versions) => ExtensionSlotData::SupportedVersions(versions),
            Self::EchGrease => ExtensionSlotData::EchGrease,
            Self::Padding => ExtensionSlotData::Padding,
        }
    }
}

impl OwnedProfile {
    fn with_profile<R>(&self, body: impl FnOnce(&HelloProfileData<'_>) -> R) -> R {
        let extensions: Vec<_> = self
            .extensions
            .iter()
            .map(OwnedExtension::as_borrowed)
            .collect();
        body(&HelloProfileData {
            name: self.name,
            cipher_suites: &self.cipher_suites,
            extensions: &extensions,
            permute_extensions: self.permute_extensions,
            ech_grease: self.ech_grease.as_borrowed(),
            reuse_classical_key_share: self.reuse_classical_key_share,
        })
    }
}

fn build_profile(profile: RealityHelloProfile, table: &Value) -> io::Result<OwnedProfile> {
    let name = profile.table().name;
    let table = table
        .as_object()
        .ok_or_else(|| refuse(&format!("profile {name} fingerprint is not an object")))?;
    let field = |key: &str| -> io::Result<&Value> {
        table
            .get(key)
            .ok_or_else(|| refuse(&format!("profile {name} carries no {key}")))
    };

    require_frozen(name, "legacy_version", field("legacy_version")?, 0x0303)?;
    require_frozen(
        name,
        "record_layer_version.initial_client_hello",
        field("record_layer_version")?
            .get("initial_client_hello")
            .ok_or_else(|| refuse(&format!("profile {name} carries no record_layer_version")))?,
        u16::from_be_bytes(INITIAL_RECORD_VERSION),
    )?;
    if field("legacy_session_id_bytes")?.as_u64() != Some(32) {
        return Err(refuse(&format!(
            "profile {name} asks for a legacy session id this build does not write"
        )));
    }
    let compression: Vec<u16> =
        code_points(name, "compression_methods", field("compression_methods")?)?;
    if compression != [0x00] {
        return Err(refuse(&format!(
            "profile {name} asks for a compression method this build does not write"
        )));
    }
    let alpn: Vec<&str> = field("alpn")?
        .as_array()
        .ok_or_else(|| refuse(&format!("profile {name} alpn is not a list")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| refuse(&format!("profile {name} has a non-string ALPN protocol")))
        })
        .collect::<io::Result<_>>()?;
    if alpn != CHROME_ALPN_PROTOCOLS {
        return Err(refuse(&format!(
            "profile {name} asks for an ALPN list this build does not write"
        )));
    }

    let cipher_suites = build_cipher_suites(name, field("cipher_suites")?)?;
    let groups = build_groups(name, field("supported_groups")?)?;
    let key_shares = build_key_shares(name, field("key_shares")?)?;
    let versions = build_versions(name, field("supported_versions")?)?;
    let signature_algorithms = length_prefixed(code_points(
        name,
        "signature_algorithms",
        field("signature_algorithms")?,
    )?);

    let extensions = build_extensions(
        name,
        field("extension_order")?,
        &groups,
        &key_shares,
        &versions,
        &signature_algorithms,
    )?;

    let has_ech_slot = extensions
        .iter()
        .any(|slot| matches!(slot, OwnedExtension::EchGrease));
    let ech_grease = match table.get("ech_grease") {
        Some(Value::Null) | None => {
            if has_ech_slot {
                return Err(refuse(&format!(
                    "profile {name} sends an ECH GREASE extension but declares no ech_grease shape"
                )));
            }
            OwnedEchShape {
                suites: CHROME_ECH_GREASE.suites.to_vec(),
                payload_lens: CHROME_ECH_GREASE.payload_lens.to_vec(),
            }
        }
        Some(shape) => build_ech_grease(name, shape)?,
    };

    let built = OwnedProfile {
        name,
        cipher_suites,
        extensions,
        permute_extensions: table
            .get("permute_extensions")
            .and_then(Value::as_bool)
            .ok_or_else(|| refuse(&format!("profile {name} does not say whether it permutes")))?,
        ech_grease,
        reuse_classical_key_share: !matches!(
            table.get("key_share_reuse"),
            None | Some(Value::Null)
        ),
    };
    built.with_profile(|profile| profile.validate())?;
    Ok(built)
}

fn build_cipher_suites(name: &str, value: &Value) -> io::Result<Vec<CipherSuiteSlot>> {
    entries(name, "cipher_suites", value)?
        .iter()
        .map(|entry| match role(name, "cipher_suites", entry)? {
            "grease" => Ok(CipherSuiteSlot::Grease),
            "negotiable" => Ok(CipherSuiteSlot::Negotiable(entry_code_point(
                name,
                "cipher_suites",
                entry,
            )?)),
            "decorative" => Ok(CipherSuiteSlot::Decorative(entry_code_point(
                name,
                "cipher_suites",
                entry,
            )?)),
            other => Err(refuse(&format!(
                "profile {name} gives a cipher suite the unknown role {other}"
            ))),
        })
        .collect()
}

fn build_groups(name: &str, value: &Value) -> io::Result<Vec<GroupSlot>> {
    entries(name, "supported_groups", value)?
        .iter()
        .map(|entry| match entry.get("value").and_then(Value::as_str) {
            Some("GREASE") => Ok(GroupSlot::Grease),
            _ => {
                let id = entry_code_point(name, "supported_groups", entry)?;
                NamedGroup::from_id(id).map(GroupSlot::Group).ok_or_else(|| {
                    refuse(&format!(
                        "profile {name} names group 0x{id:04x}, which this build has no name for"
                    ))
                })
            }
        })
        .collect()
}

fn build_key_shares(name: &str, value: &Value) -> io::Result<Vec<KeyShareSlot>> {
    entries(name, "key_shares", value)?
        .iter()
        .map(|entry| match entry.get("value").and_then(Value::as_str) {
            Some("GREASE") => Ok(KeyShareSlot::Grease),
            _ => {
                let id = entry_code_point(name, "key_shares", entry)?;
                NamedGroup::from_id(id)
                    .map(KeyShareSlot::Group)
                    .ok_or_else(|| {
                        refuse(&format!(
                            "profile {name} sends a share for 0x{id:04x}, which this build has no \
                             name for"
                        ))
                    })
            }
        })
        .collect()
}

fn build_versions(name: &str, value: &Value) -> io::Result<Vec<VersionSlot>> {
    entries(name, "supported_versions", value)?
        .iter()
        .map(|entry| match entry.get("value").and_then(Value::as_str) {
            Some("GREASE") => Ok(VersionSlot::Grease),
            _ => Ok(VersionSlot::Version(entry_code_point(
                name,
                "supported_versions",
                entry,
            )?)),
        })
        .collect()
}

fn build_extensions(
    name: &str,
    value: &Value,
    groups: &[GroupSlot],
    key_shares: &[KeyShareSlot],
    versions: &[VersionSlot],
    signature_algorithms: &[u8],
) -> io::Result<Vec<OwnedExtension>> {
    let entries = entries(name, "extension_order", value)?;
    let mut grease_seen = 0_usize;
    let mut slots = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if entry.get("order").and_then(Value::as_u64) != Some(index as u64 + 1) {
            return Err(refuse(&format!(
                "profile {name} extension_order is not 1-based dense at position {index}"
            )));
        }
        let declared = entry
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse(&format!("profile {name} has an extension with no type")))?;
        let body = entry
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse(&format!("profile {name} has an extension with no body")))?;

        if declared == "GREASE" {
            let slot = match grease_seen {
                0 => GreaseSlot::Extension1,
                1 => GreaseSlot::Extension2,
                _ => {
                    return Err(refuse(&format!(
                        "profile {name} carries more than two GREASE extensions"
                    )));
                }
            };
            grease_seen += 1;
            slots.push(OwnedExtension::Grease {
                slot,
                body: hex_body(name, body)?,
            });
            continue;
        }

        let extension_type = hex16(name, declared)?;
        let slot = match (extension_type, body) {
            (ext::SERVER_NAME, "per_connection") => OwnedExtension::ServerName,
            (ext::SUPPORTED_GROUPS, "table") => OwnedExtension::SupportedGroups(groups.to_vec()),
            (ext::KEY_SHARE, "per_connection") => OwnedExtension::KeyShare(key_shares.to_vec()),
            (ext::ALPN, "table") => OwnedExtension::Alpn,
            (ext::SUPPORTED_VERSIONS, "table") => {
                OwnedExtension::SupportedVersions(versions.to_vec())
            }
            (ext::SIGNATURE_ALGORITHMS, "table") => OwnedExtension::Constant {
                extension_type,
                body: signature_algorithms.to_vec(),
            },
            (ext::ENCRYPTED_CLIENT_HELLO, "per_connection_grease") => OwnedExtension::EchGrease,
            (ext::PADDING, "conditional") => OwnedExtension::Padding,
            (_, other) => OwnedExtension::Constant {
                extension_type,
                body: hex_body(name, other)?,
            },
        };
        slots.push(slot);
    }
    Ok(slots)
}

const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

fn build_ech_grease(name: &str, value: &Value) -> io::Result<OwnedEchShape> {
    let kdf = match value.get("kdf").and_then(Value::as_str) {
        Some("HKDF-SHA256") => HPKE_KDF_HKDF_SHA256,
        other => {
            return Err(refuse(&format!(
                "profile {name} asks for ECH GREASE KDF {other:?}, which this build does not send"
            )));
        }
    };
    let aeads: Vec<&str> = match (value.get("aead"), value.get("aead_candidates")) {
        (Some(Value::String(single)), None) => vec![single.as_str()],
        (None, Some(Value::Array(candidates))) => candidates
            .iter()
            .map(|entry| {
                entry.as_str().ok_or_else(|| {
                    refuse(&format!("profile {name} has a non-string ECH GREASE AEAD"))
                })
            })
            .collect::<io::Result<_>>()?,
        _ => {
            return Err(refuse(&format!(
                "profile {name} must name exactly one of aead or aead_candidates"
            )));
        }
    };
    let suites = aeads
        .into_iter()
        .map(|aead| match aead {
            "AES-128-GCM" => Ok((kdf, HPKE_AEAD_AES_128_GCM)),
            "ChaCha20-Poly1305" => Ok((kdf, HPKE_AEAD_CHACHA20_POLY1305)),
            other => Err(refuse(&format!(
                "profile {name} asks for ECH GREASE AEAD {other}, which this build does not send"
            ))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if suites.is_empty() {
        return Err(refuse(&format!(
            "profile {name} offers no ECH GREASE suite"
        )));
    }

    let payload_lens = value
        .get("payload_lengths")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            refuse(&format!(
                "profile {name} declares no ECH GREASE payload lengths"
            ))
        })?
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .filter(|length| *length > 0 && *length <= MAX_ECH_GREASE_PAYLOAD)
                .map(|length| length as usize)
                .ok_or_else(|| {
                    refuse(&format!(
                        "profile {name} declares an ECH GREASE payload length this build will not \
                         send"
                    ))
                })
        })
        .collect::<io::Result<Vec<_>>>()?;
    if payload_lens.is_empty() {
        return Err(refuse(&format!(
            "profile {name} declares an empty ECH GREASE payload length list"
        )));
    }

    Ok(OwnedEchShape {
        suites,
        payload_lens,
    })
}

const MAX_ECH_GREASE_PAYLOAD: u64 = super::hello_profile::MAX_ECH_GREASE_PLAINTEXT as u64;

fn entries<'a>(name: &str, field: &str, value: &'a Value) -> io::Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| refuse(&format!("profile {name} {field} is not a list")))
}

fn role<'a>(name: &str, field: &str, entry: &'a Value) -> io::Result<&'a str> {
    entry
        .get("role")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(&format!("profile {name} has a {field} entry with no role")))
}

fn entry_code_point(name: &str, field: &str, entry: &Value) -> io::Result<u16> {
    let text = entry
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(&format!("profile {name} has a {field} entry with no value")))?;
    hex16(name, text)
}

fn code_points(name: &str, field: &str, value: &Value) -> io::Result<Vec<u16>> {
    entries(name, field, value)?
        .iter()
        .map(|entry| match entry {
            Value::String(text) => hex16(name, text),
            Value::Array(pair) => pair
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| refuse(&format!("profile {name} has an unreadable {field} entry")))
                .and_then(|text| hex16(name, text)),
            _ => Err(refuse(&format!(
                "profile {name} has an unreadable {field} entry"
            ))),
        })
        .collect()
}

fn length_prefixed(values: Vec<u16>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 2);
    out.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

fn require_frozen(name: &str, field: &str, value: &Value, expected: u16) -> io::Result<()> {
    let text = value
        .as_str()
        .ok_or_else(|| refuse(&format!("profile {name} {field} is not a code point")))?;
    if hex16(name, text)? != expected {
        return Err(refuse(&format!(
            "profile {name} asks for {field} 0x{expected:04x} to change, which is not a table field"
        )));
    }
    Ok(())
}

fn hex16(name: &str, text: &str) -> io::Result<u16> {
    let digits = text.strip_prefix("0x").ok_or_else(|| {
        refuse(&format!(
            "profile {name} code point {text} is not 0x-prefixed"
        ))
    })?;
    u16::from_str_radix(digits, 16)
        .map_err(|_| refuse(&format!("profile {name} code point {text} is not hex")))
}

fn hex_body(name: &str, text: &str) -> io::Result<Vec<u8>> {
    let digits: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err(refuse(&format!(
            "profile {name} has an extension body with an odd number of hex digits"
        )));
    }
    if digits.len() / 2 > MAX_CONSTANT_BODY_BYTES {
        return Err(refuse(&format!(
            "profile {name} has an extension body longer than any this build writes"
        )));
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16).map_err(|_| {
                refuse(&format!(
                    "profile {name} has an extension body that is not hex: {text}"
                ))
            })
        })
        .collect()
}

const MAX_CONSTANT_BODY_BYTES: usize = 512;

fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    append_canonical(value, &mut out);
    out
}

fn append_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                append_canonical(&map[*key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                append_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let computed = digest::digest(&digest::SHA256, bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(computed.as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn refuse(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("REALITY fingerprint table document {message}"),
    )
}

#[cfg(test)]
mod tests {
    use super::super::hello_profile::ExtensionSlot;
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn fingerprints_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fingerprints")
    }

    fn committed_document() -> Value {
        let mut files: Vec<PathBuf> = fs::read_dir(fingerprints_dir())
            .expect("fingerprints directory")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        files.sort();
        let profiles: Vec<Value> = files
            .iter()
            .map(|path| {
                serde_json::from_str(&fs::read_to_string(path).expect("read")).expect("json")
            })
            .collect();
        assert!(!profiles.is_empty(), "no committed vectors to read");
        serde_json::json!({
            "schema": 1,
            "generated_at": "2026-08-17T00:00:00Z",
            "profiles": profiles,
        })
    }

    fn committed_profiles(document: &Value) -> Vec<RealityHelloProfile> {
        document["profiles"]
            .as_array()
            .expect("profiles")
            .iter()
            .filter_map(|entry| profile_named(entry["name"].as_str().expect("name")))
            .collect()
    }

    fn parse(document: &Value) -> io::Result<Vec<Option<Arc<OwnedProfile>>>> {
        parse_document(document.to_string().as_bytes())
    }

    fn refusal(document: &Value) -> String {
        match parse(document) {
            Ok(_) => panic!("document was accepted; it must be refused"),
            Err(error) => error.to_string(),
        }
    }

    fn table_of(
        slots: &[Option<Arc<OwnedProfile>>],
        profile: RealityHelloProfile,
    ) -> Option<&Arc<OwnedProfile>> {
        slots[slot_index(profile).expect("index")].as_ref()
    }

    fn rehash(mut document: Value) -> Value {
        for entry in document["profiles"].as_array_mut().expect("profiles") {
            let canonical = canonical_json(&entry["fingerprint"]);
            entry["fingerprint_sha256"] = Value::String(hex(&sha256(canonical.as_bytes())));
        }
        document
    }

    fn edited(name: &str, edit: impl Fn(&mut Value)) -> Value {
        let mut document = committed_document();
        let entry = document["profiles"]
            .as_array_mut()
            .expect("profiles")
            .iter_mut()
            .find(|entry| entry["name"] == name)
            .unwrap_or_else(|| panic!("no committed vector for {name}"));
        edit(&mut entry["fingerprint"]);
        rehash(document)
    }

    fn a_covered_profile() -> (RealityHelloProfile, &'static str) {
        let document = committed_document();
        let profile = *committed_profiles(&document)
            .first()
            .expect("at least one committed vector matches a compiled profile");
        (profile, profile.table().name)
    }

    #[test]
    fn every_committed_table_loads_back_to_the_compiled_one() {
        let document = committed_document();
        let covered = committed_profiles(&document);
        let slots = parse(&document).expect("committed document must load");
        assert_eq!(slots.iter().flatten().count(), covered.len());
        for profile in covered {
            let built_in = profile.table();
            let loaded = table_of(&slots, profile).expect("table");
            loaded.with_profile(|loaded| {
                assert_eq!(loaded.name, built_in.name);
                assert_eq!(
                    loaded.cipher_suites, built_in.cipher_suites,
                    "{}: cipher suites",
                    built_in.name
                );
                assert_eq!(
                    loaded.extensions, built_in.extensions,
                    "{}: extensions",
                    built_in.name
                );
                assert_eq!(
                    loaded.permute_extensions, built_in.permute_extensions,
                    "{}: permutation",
                    built_in.name
                );
                assert_eq!(
                    loaded.ech_grease, built_in.ech_grease,
                    "{}: ECH GREASE shape",
                    built_in.name
                );
                assert_eq!(
                    loaded.reuse_classical_key_share, built_in.reuse_classical_key_share,
                    "{}: key share reuse",
                    built_in.name
                );
            });
        }
    }

    #[test]
    fn rejected_updates_and_retired_tables_have_bounded_ownership() {
        let registry = RwLock::new(None);
        let mut document = committed_document();
        document["profiles"].as_array_mut().unwrap().truncate(1);
        let encoded = serde_json::to_vec(&document).unwrap();
        install_into(&registry, &encoded).unwrap();
        let profile = registry
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .profiles
            .iter()
            .flatten()
            .next()
            .unwrap()
            .clone();
        let old = Arc::downgrade(&profile);
        let mut invalid = document.clone();
        invalid["profiles"]
            .as_array_mut()
            .unwrap()
            .push(document["profiles"][0].clone());
        let invalid = serde_json::to_vec(&invalid).unwrap();
        for _ in 0..1_000 {
            assert!(install_into(&registry, &invalid).is_err());
        }
        assert_eq!(Arc::strong_count(&profile), 2);
        for revision in 0..64 {
            document["revision"] = Value::from(revision);
            install_into(&registry, &serde_json::to_vec(&document).unwrap()).unwrap();
        }
        assert_eq!(Arc::strong_count(&profile), 1);
        profile.with_profile(|profile| profile.validate()).unwrap();
        *registry.write().unwrap() = None;
        drop(profile);
        assert!(old.upgrade().is_none());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    install_into(&registry, &encoded).unwrap();
                });
            }
        });
        let guard = registry.read().unwrap();
        for profile in guard.as_ref().unwrap().profiles.iter().flatten() {
            assert_eq!(Arc::strong_count(profile), 1);
        }
    }

    #[test]
    fn a_changed_body_reaches_the_loaded_table() {
        let (profile, name) = a_covered_profile();
        let document = edited(name, |fingerprint| {
            let slot = fingerprint["extension_order"]
                .as_array_mut()
                .expect("extension_order")
                .iter_mut()
                .find(|entry| entry["type"] == "0xff01")
                .expect("renegotiation_info");
            slot["body"] = Value::String("0000".to_owned());
        });
        let slots = parse(&document).expect("re-hashed document must load");
        let loaded = table_of(&slots, profile).expect("table");
        loaded.with_profile(|loaded| {
            assert!(
                loaded.extensions.contains(&ExtensionSlot::Constant {
                    extension_type: ext::RENEGOTIATION_INFO,
                    body: &[0x00, 0x00],
                }),
                "{name}: the downloaded body is what the table carries"
            );
            assert_ne!(
                loaded.extensions,
                profile.table().extensions,
                "{name}: a changed table must not be silently replaced by the built-in one"
            );
        });
    }

    #[test]
    fn a_profile_whose_digest_does_not_cover_it_drops_the_whole_document() {
        let (_, name) = a_covered_profile();
        let mut document = committed_document();
        let entry = document["profiles"]
            .as_array_mut()
            .expect("profiles")
            .iter_mut()
            .find(|entry| entry["name"] == name)
            .expect("entry");
        entry["fingerprint"]["permute_extensions"] = Value::Bool(
            !entry["fingerprint"]["permute_extensions"]
                .as_bool()
                .expect("bool"),
        );
        let error = refusal(&document);
        assert!(error.contains("hashes to"), "{error}");
    }

    #[test]
    fn a_name_this_build_does_not_implement_is_ignored_rather_than_invented() {
        let document = committed_document();
        let covered = committed_profiles(&document);
        let dropped = *covered.first().expect("a covered profile");
        let mut renamed = document;
        renamed["profiles"]
            .as_array_mut()
            .expect("profiles")
            .iter_mut()
            .find(|entry| entry["name"] == dropped.table().name)
            .expect("entry")["name"] = Value::String("chrome_999".to_owned());
        let slots = parse(&renamed).expect("an unknown name is data, not an error");
        assert_eq!(
            slots.iter().flatten().count(),
            covered.len() - 1,
            "the unknown name must not have created a table"
        );
        assert!(
            table_of(&slots, dropped).is_none(),
            "{} keeps its built-in table",
            dropped.table().name
        );
    }

    #[test]
    fn ech_payload_cannot_exceed_the_client_hello_buffer() {
        let document = edited("chrome_151", |fingerprint| {
            fingerprint["ech_grease"]["payload_lengths"] = serde_json::json!([225]);
        });
        assert!(refusal(&document).contains("payload length"));
    }

    #[test]
    fn a_table_that_asks_for_a_frozen_field_is_refused() {
        let (_, name) = a_covered_profile();
        let cases: Vec<(Value, &str)> = vec![
            (
                edited(name, |fingerprint| {
                    fingerprint["legacy_version"] = Value::String("0x0304".to_owned());
                }),
                "legacy_version",
            ),
            (
                edited(name, |fingerprint| {
                    fingerprint["legacy_session_id_bytes"] = Value::from(0);
                }),
                "legacy session id",
            ),
            (
                edited(name, |fingerprint| {
                    fingerprint["alpn"] = serde_json::json!(["h3"]);
                }),
                "ALPN list",
            ),
            (
                edited(name, |fingerprint| {
                    fingerprint["compression_methods"] = serde_json::json!(["0x01"]);
                }),
                "compression method",
            ),
            (
                edited(name, |fingerprint| {
                    fingerprint["record_layer_version"]["initial_client_hello"] =
                        Value::String("0x0303".to_owned());
                }),
                "record_layer_version",
            ),
        ];
        for (document, expected) in cases {
            let error = refusal(&document);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_table_that_cannot_produce_a_hello_is_refused() {
        let (_, name) = a_covered_profile();
        let document = edited(name, |fingerprint| {
            let slots = fingerprint["extension_order"]
                .as_array_mut()
                .expect("extension_order");
            slots.retain(|entry| entry["type"] != "0x0033");
            for (index, entry) in slots.iter_mut().enumerate() {
                entry["order"] = Value::from(index as u64 + 1);
            }
        });
        let error = refusal(&document);
        assert!(error.contains("key_share"), "{error}");
    }

    #[test]
    fn a_table_offering_an_unimplemented_suite_as_negotiable_is_refused() {
        let (_, name) = a_covered_profile();
        let document = edited(name, |fingerprint| {
            for entry in fingerprint["cipher_suites"]
                .as_array_mut()
                .expect("ciphers")
            {
                if entry["role"] == "decorative" {
                    entry["role"] = Value::String("negotiable".to_owned());
                    break;
                }
            }
        });
        let error = refusal(&document);
        assert!(error.contains("does not implement it"), "{error}");
    }

    #[test]
    fn an_unreadable_extension_body_is_refused() {
        let (_, name) = a_covered_profile();
        let document = edited(name, |fingerprint| {
            fingerprint["extension_order"]
                .as_array_mut()
                .expect("extension_order")
                .iter_mut()
                .find(|entry| entry["type"] == "0xff01")
                .expect("renegotiation_info")["body"] =
                Value::String("whatever the client likes".to_owned());
        });
        let error = refusal(&document);
        assert!(error.contains("not hex"), "{error}");
    }

    #[test]
    fn malformed_documents_are_refused_whole() {
        for document in [
            Value::String("not json".to_owned()),
            serde_json::json!([]),
            serde_json::json!({"profiles": []}),
            serde_json::json!({"schema": 2, "profiles": []}),
            serde_json::json!({"schema": 1}),
        ] {
            let _ = refusal(&document);
        }
        assert!(parse_document(b"not json at all").is_err());
        let document = committed_document().to_string();
        assert!(parse_document(&document.as_bytes()[..document.len() / 2]).is_err());
    }

    #[test]
    fn a_document_with_no_profile_this_build_implements_installs_nothing() {
        let mut document = committed_document();
        for (index, entry) in document["profiles"]
            .as_array_mut()
            .expect("profiles")
            .iter_mut()
            .enumerate()
        {
            entry["name"] = Value::String(format!("opera_{index}"));
        }
        let error = install_fingerprint_tables(document.to_string().as_bytes())
            .expect_err("a document naming nothing we implement installs nothing")
            .to_string();
        assert!(error.contains("no table for any profile"), "{error}");
    }

    #[test]
    fn installing_the_committed_document_is_a_no_op_on_the_bytes() {
        let document = committed_document();
        let covered = committed_profiles(&document);
        let document = document.to_string();
        let installed = install_fingerprint_tables(document.as_bytes()).expect("install");
        assert_eq!(installed, covered.len());
        for profile in RealityHelloProfile::ALL {
            let in_effect = table_for(*profile);
            in_effect.with_profile(|in_effect| {
                assert_eq!(in_effect.extensions, profile.table().extensions);
                assert_eq!(in_effect.cipher_suites, profile.table().cipher_suites);
            });
        }
        install_fingerprint_tables(document.as_bytes()).expect("re-install");
        assert!(using_downloaded_fingerprint_tables());
    }

    #[test]
    fn a_refused_document_leaves_the_built_in_tables_in_place() {
        assert!(install_fingerprint_tables(b"{").is_err());
        for profile in RealityHelloProfile::ALL {
            table_for(*profile)
                .with_profile(|loaded| assert_eq!(loaded.name, profile.table().name));
        }
    }

    #[test]
    fn the_canonical_form_matches_the_pipeline() {
        let value: Value =
            serde_json::from_str(r#"{"b":1,"a":[2,{"d":null,"c":"x"}],"e":true}"#).expect("json");
        assert_eq!(
            canonical_json(&value),
            r#"{"a":[2,{"c":"x","d":null}],"b":1,"e":true}"#
        );
    }
}
