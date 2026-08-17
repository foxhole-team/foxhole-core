//! The tap for the signed ClientHello table feed.
//!
//! [`fingerprint_vector`](super::fingerprint_vector) called this "the seam a
//! signed fingerprint feed would later arrive through". This is that seam, from
//! the other side: the same JSON the repository commits under `fingerprints/`,
//! read at runtime and turned into the very same [`HelloProfile`] values the
//! binary already carries.
//!
//! Three properties hold it in place, and none of them is a comment:
//!
//! * **The generator never crosses the network.** What arrives is a table of
//!   code points, orders and constant bodies. Every one of them lands in a slot
//!   this binary already knows how to encode; a byte the vocabulary below has no
//!   variant for is a refusal, not an extension point.
//! * **The feed cannot name a profile the binary does not implement.** Entries
//!   are matched against [`RealityHelloProfile::ALL`] by name and anything else
//!   is ignored. There is no path from a downloaded string to a new profile, a
//!   new refusal, or a lifted one — those live in `foxcore-link` and in the
//!   config enum, which this module cannot reach.
//! * **A table is installed whole or not at all.** Parsing builds every profile
//!   in the document before anything is published; the first malformed byte
//!   drops the *entire* document and leaves whatever was in effect — in the
//!   worst case the built-in tables, which are always a complete set. There is
//!   no state in which a connection sends half a parrot.
//!
//! The digest each entry declares is re-derived here as well. It proves nothing
//! against an attacker holding the signing key — the signature is checked before
//! these bytes ever reach the core — but it does prove the table is the exact
//! one the publishing pipeline hashed, rather than one assembled afterwards by
//! someone with push access. A rewritten parrot is not a data error; it is a
//! distinguishable client.

use std::collections::BTreeMap;
use std::io;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use aws_lc_rs::digest;
use serde_json::Value;

use super::hello_profile::{
    CHROME_ALPN_PROTOCOLS, CHROME_ECH_GREASE, CipherSuiteSlot, EchGreaseShape, ExtensionSlot,
    GreaseSlot, GroupSlot, HelloProfile, KeyShareSlot, RealityHelloProfile, VersionSlot, ext,
};
use super::reality_key_exchange::NamedGroup;
use super::reality_tls13_messages::INITIAL_RECORD_VERSION;

/// The document schema this build reads. A feed that bumps it is telling us it
/// changed shape, and the honest answer is the built-in tables until this
/// binary is updated to match.
const SUPPORTED_SCHEMA: u64 = 1;

/// An installed document is held for the life of the process, so each distinct
/// one costs memory that is never returned. Re-installing the *same* document
/// is free (see [`install_fingerprint_tables`]); this caps how many genuinely
/// different ones a single process will take, which turns an unbounded leak
/// into a bounded one no realistic update cadence can reach.
const MAX_DISTINCT_INSTALLS: usize = 32;

/// What is currently in effect, indexed the way [`RealityHelloProfile::ALL`] is
/// ordered. `None` in a slot means that profile keeps its built-in table.
static INSTALLED: RwLock<Option<InstalledTables>> = RwLock::new(None);

static DISTINCT_INSTALLS: AtomicUsize = AtomicUsize::new(0);

struct InstalledTables {
    /// SHA-256 of the whole document, so re-installing an identical one neither
    /// leaks nor churns the lock.
    document_digest: [u8; 32],
    profiles: Vec<Option<&'static HelloProfile>>,
}

/// The table that writes this profile's bytes: the downloaded one when a
/// verified document is in effect and carries it, the built-in one otherwise.
///
/// Deliberately infallible. Every path out of here returns a complete table,
/// because the alternative a caller would have to handle — "no fingerprint" —
/// is not a fallback, it is a connection that stands out from every browser on
/// the network.
pub(super) fn table_for(profile: RealityHelloProfile) -> &'static HelloProfile {
    let Ok(guard) = INSTALLED.read() else {
        // A poisoned lock means some other thread panicked mid-install. The
        // built-in set is always right, so it is also the right answer here.
        return profile.table();
    };
    guard
        .as_ref()
        .and_then(|installed| slot_index(profile).and_then(|index| installed.profiles[index]))
        .unwrap_or_else(|| profile.table())
}

/// Install a table document that has already passed signature verification.
///
/// Returns how many of this build's profiles the document replaced. An error
/// changes nothing: whatever was in effect stays in effect, and a process that
/// has never installed anything keeps the built-in tables.
///
/// The caller is the only party that can establish *provenance* (who signed it)
/// and *freshness* (that it is not a replayed older set). Everything else — the
/// schema, the digests, the vocabulary, and whether each table can actually
/// produce a hello — is re-established here, because "the app checked it" is not
/// a property this crate can verify.
pub fn install_fingerprint_tables(document: &[u8]) -> io::Result<usize> {
    let document_digest = sha256(document);
    if let Ok(guard) = INSTALLED.read()
        && let Some(installed) = guard.as_ref()
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

    // Counted before publishing so a burst of distinct documents cannot race
    // past the cap; a rejected install has already returned above.
    if DISTINCT_INSTALLS.fetch_add(1, Ordering::SeqCst) >= MAX_DISTINCT_INSTALLS {
        DISTINCT_INSTALLS.fetch_sub(1, Ordering::SeqCst);
        return Err(refuse(
            "has already taken as many distinct table documents as one process will hold",
        ));
    }

    let mut guard = INSTALLED
        .write()
        .map_err(|_| refuse("table registry is poisoned"))?;
    *guard = Some(InstalledTables {
        document_digest,
        profiles: parsed,
    });
    Ok(replaced)
}

/// Drop any installed document and go back to the built-in tables.
///
/// The app calls this when the feed is turned off or its stored document stops
/// reading back cleanly. It cannot fail: the built-in set needs nothing.
pub fn clear_fingerprint_tables() {
    if let Ok(mut guard) = INSTALLED.write() {
        *guard = None;
    }
}

/// Whether a downloaded document is currently writing the bytes.
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

// ----------------------------------------------------------------- document

/// Parse the whole document, or fail without publishing anything.
fn parse_document(document: &[u8]) -> io::Result<Vec<Option<&'static HelloProfile>>> {
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

    let mut slots: Vec<Option<&'static HelloProfile>> = vec![None; RealityHelloProfile::ALL.len()];
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
        // A name this build has no table for is data about some other build,
        // not an instruction to grow one. Skipped, never invented.
        let Some(profile) = profile_named(name) else {
            continue;
        };
        let fingerprint = entry
            .get("fingerprint")
            .ok_or_else(|| refuse(&format!("profile {name} carries no fingerprint table")))?;
        verify_declared_digest(name, entry.get("fingerprint_sha256"), fingerprint)?;
        let table = build_profile(profile, fingerprint)?;
        let index = slot_index(profile).ok_or_else(|| refuse("profile is not in ALL"))?;
        slots[index] = Some(table);
    }
    Ok(slots)
}

/// 4 MiB, the same ceiling the app's downloader enforces. The committed set is
/// under 100 KiB; anything at this size is not a table.
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

// ------------------------------------------------------------------ profile

fn build_profile(profile: RealityHelloProfile, table: &Value) -> io::Result<&'static HelloProfile> {
    // The name is the *compiled* one, not a leaked copy of the document's
    // string. Every error a hello raises therefore names a profile this build
    // implements, and no downloaded byte can appear in a diagnostic as if it
    // were one of ours.
    let name = profile.table().name;
    let table = table
        .as_object()
        .ok_or_else(|| refuse(&format!("profile {name} fingerprint is not an object")))?;
    let field = |key: &str| -> io::Result<&Value> {
        table
            .get(key)
            .ok_or_else(|| refuse(&format!("profile {name} carries no {key}")))
    };

    // Fields the generator does not read from a table, and therefore may not be
    // told to change. Refusing a document that disagrees is the difference
    // between "the feed supplies values" and "the feed supplies values we
    // silently ignore".
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

    let cipher_suites = leak(build_cipher_suites(name, field("cipher_suites")?)?);
    let groups = leak(build_groups(name, field("supported_groups")?)?);
    let key_shares = leak(build_key_shares(name, field("key_shares")?)?);
    let versions = leak(build_versions(name, field("supported_versions")?)?);
    let signature_algorithms = leak(length_prefixed(code_points(
        name,
        "signature_algorithms",
        field("signature_algorithms")?,
    )?));

    let extensions = leak(build_extensions(
        name,
        field("extension_order")?,
        groups,
        key_shares,
        versions,
        signature_algorithms,
    )?);

    let has_ech_slot = extensions
        .iter()
        .any(|slot| matches!(slot, ExtensionSlot::EchGrease));
    let ech_grease = match table.get("ech_grease") {
        Some(Value::Null) | None => {
            if has_ech_slot {
                return Err(refuse(&format!(
                    "profile {name} sends an ECH GREASE extension but declares no ech_grease shape"
                )));
            }
            // Unused by a profile with no ECH GREASE slot; the built-in tables
            // carry the Chrome shape in the same position for the same reason.
            CHROME_ECH_GREASE
        }
        Some(shape) => build_ech_grease(name, shape)?,
    };

    let built = HelloProfile {
        name,
        cipher_suites,
        extensions,
        permute_extensions: table
            .get("permute_extensions")
            .and_then(Value::as_bool)
            .ok_or_else(|| refuse(&format!("profile {name} does not say whether it permutes")))?,
        ech_grease,
        // Presence *is* the statement: the field is an object explaining the
        // rule, and no table has ever carried it set to false.
        reuse_classical_key_share: !matches!(
            table.get("key_share_reuse"),
            None | Some(Value::Null)
        ),
    };
    // The same gate every built-in table passes on every hello. A downloaded
    // table that cannot produce a hello must fail here, where the answer is
    // "keep the built-in one", not at dial time where it is a dead connection.
    built.validate()?;
    Ok(Box::leak(Box::new(built)))
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

/// The extension list, in table order, with each slot resolved to the one thing
/// this build knows how to encode there.
fn build_extensions(
    name: &str,
    value: &Value,
    groups: &'static [GroupSlot],
    key_shares: &'static [KeyShareSlot],
    versions: &'static [VersionSlot],
    signature_algorithms: &'static [u8],
) -> io::Result<Vec<ExtensionSlot>> {
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
            slots.push(ExtensionSlot::Grease {
                slot,
                body: leak(hex_body(name, body)?),
            });
            continue;
        }

        let extension_type = hex16(name, declared)?;
        let slot = match (extension_type, body) {
            (ext::SERVER_NAME, "per_connection") => ExtensionSlot::ServerName,
            (ext::SUPPORTED_GROUPS, "table") => ExtensionSlot::SupportedGroups(groups),
            (ext::KEY_SHARE, "per_connection") => ExtensionSlot::KeyShare(key_shares),
            (ext::ALPN, "table") => ExtensionSlot::Alpn,
            (ext::SUPPORTED_VERSIONS, "table") => ExtensionSlot::SupportedVersions(versions),
            (ext::SIGNATURE_ALGORITHMS, "table") => ExtensionSlot::Constant {
                extension_type,
                body: signature_algorithms,
            },
            (ext::ENCRYPTED_CLIENT_HELLO, "per_connection_grease") => ExtensionSlot::EchGrease,
            (ext::PADDING, "conditional") => ExtensionSlot::Padding,
            // Anything else has to be a constant blob, and a constant blob has
            // to be hex. A body naming a rule this build does not implement is
            // refused rather than approximated with the bytes next to it.
            (_, other) => ExtensionSlot::Constant {
                extension_type,
                body: leak(hex_body(name, other)?),
            },
        };
        slots.push(slot);
    }
    Ok(slots)
}

/// HPKE KDF id, RFC 9180 §7.2.
const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
/// HPKE AEAD ids, RFC 9180 §7.3.
const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

fn build_ech_grease(name: &str, value: &Value) -> io::Result<EchGreaseShape> {
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

    Ok(EchGreaseShape {
        suites: leak(suites),
        payload_lens: leak(payload_lens),
    })
}

/// No browser GREASEs an ECH payload anywhere near this; the bound is here so a
/// table cannot ask for a hello megabytes long.
const MAX_ECH_GREASE_PAYLOAD: u64 = 1024;

// -------------------------------------------------------------------- bytes

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

/// `signature_algorithms` and `compression_methods` are lists of code points,
/// spelled either as bare strings or as `[value, name]` pairs.
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

/// A `uint16` list length followed by the list, which is how both
/// `signature_algorithms` and `delegated_credentials` are framed.
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

/// `"0x1301"`, exactly as the files spell every code point.
fn hex16(name: &str, text: &str) -> io::Result<u16> {
    let digits = text.strip_prefix("0x").ok_or_else(|| {
        refuse(&format!(
            "profile {name} code point {text} is not 0x-prefixed"
        ))
    })?;
    u16::from_str_radix(digits, 16)
        .map_err(|_| refuse(&format!("profile {name} code point {text} is not hex")))
}

/// A constant extension body: hex pairs, with whitespace allowed between the
/// groups a reviewer reads.
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

/// Chrome's longest constant body is under 40 bytes. The cap keeps a table from
/// describing a hello no browser could send.
const MAX_CONSTANT_BODY_BYTES: usize = 512;

/// JSON with sorted keys and no whitespace: the convention the files document
/// in `fingerprint_sha256_covers`, and the one the publishing pipeline hashes.
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

/// Owned data promoted to the `'static` the table types require.
///
/// A table lives for the life of the process by construction — a connection
/// holds `&'static HelloProfile` across await points — so the allocation is
/// never returned. That is what [`MAX_DISTINCT_INSTALLS`] bounds.
fn leak<T: 'static>(values: Vec<T>) -> &'static [T] {
    Box::leak(values.into_boxed_slice())
}

fn refuse(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("REALITY fingerprint table document {message}"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn fingerprints_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fingerprints")
    }

    /// Every committed vector, wrapped the way the signed feed carries them.
    ///
    /// Read from the directory rather than a hard-coded list so a profile added
    /// to the repository is covered here the day it lands, instead of the day
    /// someone remembers to extend a list.
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

    /// The profiles the committed set actually covers. A build can implement
    /// more (a table landing before its vector does); those simply keep their
    /// built-in table, which is the behaviour this module promises.
    fn committed_profiles(document: &Value) -> Vec<RealityHelloProfile> {
        document["profiles"]
            .as_array()
            .expect("profiles")
            .iter()
            .filter_map(|entry| profile_named(entry["name"].as_str().expect("name")))
            .collect()
    }

    fn parse(document: &Value) -> io::Result<Vec<Option<&'static HelloProfile>>> {
        parse_document(document.to_string().as_bytes())
    }

    /// `HelloProfile` is deliberately not `Debug` — it is a table, not a
    /// diagnostic — so a refusal is read for its message rather than unwrapped.
    fn refusal(document: &Value) -> String {
        match parse(document) {
            Ok(_) => panic!("document was accepted; it must be refused"),
            Err(error) => error.to_string(),
        }
    }

    fn table_of(
        slots: &[Option<&'static HelloProfile>],
        profile: RealityHelloProfile,
    ) -> Option<&'static HelloProfile> {
        slots[slot_index(profile).expect("index")]
    }

    /// Re-derive every profile digest, so a test can edit a table and still
    /// present a self-consistent document.
    fn rehash(mut document: Value) -> Value {
        for entry in document["profiles"].as_array_mut().expect("profiles") {
            let canonical = canonical_json(&entry["fingerprint"]);
            entry["fingerprint_sha256"] = Value::String(hex(&sha256(canonical.as_bytes())));
        }
        document
    }

    /// Edit one profile's table in place and re-hash the document around it.
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

    /// A profile the committed set covers, for the tests that need to point at
    /// one without caring which build is current.
    fn a_covered_profile() -> (RealityHelloProfile, &'static str) {
        let document = committed_document();
        let profile = *committed_profiles(&document)
            .first()
            .expect("at least one committed vector matches a compiled profile");
        (profile, profile.table().name)
    }

    /// The load-bearing test: a table that arrived as bytes reproduces, slot for
    /// slot, the table the binary was compiled with.
    ///
    /// This is what makes the feed safe to switch on. If the JSON and the Rust
    /// ever disagree, the downloaded set would send a hello nobody sends —
    /// which is the failure the whole mechanism exists to avoid, and it fails
    /// here rather than on someone's connection.
    #[test]
    fn every_committed_table_loads_back_to_the_compiled_one() {
        let document = committed_document();
        let covered = committed_profiles(&document);
        let slots = parse(&document).expect("committed document must load");
        assert_eq!(slots.iter().flatten().count(), covered.len());
        for profile in covered {
            let built_in = profile.table();
            let loaded = table_of(&slots, profile).expect("table");
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
        }
    }

    /// A table really does supply the bytes: change one and the loaded profile
    /// changes with it.
    #[test]
    fn a_changed_body_reaches_the_loaded_table() {
        let (profile, name) = a_covered_profile();
        let document = edited(name, |fingerprint| {
            // `renegotiation_info` is one byte in every table, and none of the
            // structural checks depend on its value.
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
        // One key_share extension is a ClientHello; zero is not, and
        // `HelloProfile::validate` is what says so.
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

    /// A cipher suite the build cannot negotiate, offered as if it could. The
    /// hello would complete and then fail on the ServerHello; refusing the
    /// table says so at load time instead.
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

    /// An extension body that is neither hex nor a rule this build implements.
    /// Approximating it with the bytes next to it would be a silent lie.
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
        // Truncation: the front half of a valid document.
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

    /// Installing the committed set changes no bytes — it is the same table —
    /// so this is safe to run beside every other test in the binary.
    #[test]
    fn installing_the_committed_document_is_a_no_op_on_the_bytes() {
        let document = committed_document();
        let covered = committed_profiles(&document);
        let document = document.to_string();
        let installed = install_fingerprint_tables(document.as_bytes()).expect("install");
        assert_eq!(installed, covered.len());
        for profile in RealityHelloProfile::ALL {
            let in_effect = table_for(*profile);
            assert_eq!(in_effect.extensions, profile.table().extensions);
            assert_eq!(in_effect.cipher_suites, profile.table().cipher_suites);
        }
        // Re-installing the identical document must not leak a second copy.
        let before = DISTINCT_INSTALLS.load(Ordering::SeqCst);
        install_fingerprint_tables(document.as_bytes()).expect("re-install");
        assert_eq!(DISTINCT_INSTALLS.load(Ordering::SeqCst), before);
        assert!(using_downloaded_fingerprint_tables());
    }

    #[test]
    fn a_refused_document_leaves_the_built_in_tables_in_place() {
        assert!(install_fingerprint_tables(b"{").is_err());
        for profile in RealityHelloProfile::ALL {
            assert_eq!(table_for(*profile).name, profile.table().name);
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
