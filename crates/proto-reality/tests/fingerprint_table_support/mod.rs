//! Shared scaffolding for the two table-feed integration tests.
//!
//! They are two test *binaries* on purpose: `install_fingerprint_tables`
//! publishes into a process-global registry, so a test that installs a modified
//! table and a test that asserts nothing is installed cannot share a process.
//! Everything they both need lives here rather than being written twice.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use proto_reality::{RealityHelloProfile, wrap_reality};
use serde_json::Value;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};

/// A REALITY public key that belongs to nobody. The hello's shape does not
/// depend on which server it is aimed at.
pub const PUBLIC_KEY: [u8; 32] = [0x2a; 32];
pub const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// `renegotiation_info`. One byte in every committed table, and nothing
/// structural depends on its value — so changing it isolates the one question
/// these tests ask: do the downloaded bytes reach the socket?
pub const RENEGOTIATION_INFO: u16 = 0xff01;
pub const KEY_SHARE: u16 = 0x0033;
pub const SUPPORTED_VERSIONS: u16 = 0x002b;

/// Every committed vector, wrapped the way the signed feed carries them.
pub fn committed_document() -> Value {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fingerprints");
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
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
            serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("json")
        })
        .collect();
    assert!(!profiles.is_empty(), "no committed vectors to read");
    serde_json::json!({
        "schema": 1,
        "generated_at": "2026-08-17T00:00:00Z",
        "profiles": profiles,
    })
}

/// Rewrite every profile's `renegotiation_info` body, which is the marker these
/// tests look for on the wire.
pub fn with_marked_renegotiation_info(mut document: Value, body: &str) -> Value {
    for entry in document["profiles"].as_array_mut().expect("profiles") {
        let slot = entry["fingerprint"]["extension_order"]
            .as_array_mut()
            .expect("extension_order")
            .iter_mut()
            .find(|slot| slot["type"] == "0xff01")
            .expect("every table carries renegotiation_info");
        slot["body"] = Value::String(body.to_owned());
    }
    document
}

/// Re-derive every profile digest, so an edited table can still be presented as
/// a self-consistent document. Skipping this is itself a test case.
pub fn rehash(mut document: Value) -> Value {
    use aws_lc_rs::digest;
    use std::fmt::Write as _;

    for entry in document["profiles"].as_array_mut().expect("profiles") {
        let canonical = canonical_json(&entry["fingerprint"]);
        let computed = digest::digest(&digest::SHA256, canonical.as_bytes());
        let hex = computed
            .as_ref()
            .iter()
            .fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            });
        entry["fingerprint_sha256"] = Value::String(hex);
    }
    document
}

/// Sorted keys, no whitespace: the form the publishing pipeline hashes.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        Value::String((*key).clone()),
                        canonical_json(&map[*key])
                    )
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", body.join(","))
        }
        other => other.to_string(),
    }
}

/// Dial a local listener with REALITY and return the first record's body: the
/// ClientHello, exactly as it left the socket.
///
/// The listener answers nothing, so the handshake cannot complete. That is not
/// a limitation — the hello is written before the first byte comes back, and it
/// is the only thing under test here.
pub async fn client_hello_on_the_wire(profile: RealityHelloProfile) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let observer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut header = [0_u8; 5];
        socket.read_exact(&mut header).await.expect("record header");
        assert_eq!(header[0], 0x16, "the first record is a handshake record");
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0_u8; length];
        socket.read_exact(&mut body).await.expect("record body");
        body
    });

    let stream = TcpStream::connect(address).await.expect("connect");
    let _ = wrap_reality(
        stream,
        PUBLIC_KEY,
        SHORT_ID,
        "example.com".to_owned(),
        profile.into(),
        Duration::from_millis(750),
    )
    .await;
    observer.await.expect("observer")
}

/// Where the extension block starts in a ClientHello handshake message.
fn extensions_range(hello: &[u8]) -> (usize, usize) {
    // handshake header (4) + legacy_version (2) + random (32)
    let mut cursor = 4 + 2 + 32;
    cursor += 1 + hello[cursor] as usize; // legacy_session_id
    cursor += 2 + u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize; // cipher_suites
    cursor += 1 + hello[cursor] as usize; // compression_methods
    let length = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    (cursor + 2, cursor + 2 + length)
}

/// Every extension type the hello carries, in the order it was written.
pub fn extension_types(hello: &[u8]) -> Vec<u16> {
    let (mut cursor, end) = extensions_range(hello);
    let mut types = Vec::new();
    while cursor + 4 <= end {
        types.push(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 4 + u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]) as usize;
    }
    types
}

/// The body of the first extension of this type, if the hello carries one.
pub fn extension_body(hello: &[u8], wanted: u16) -> Option<Vec<u8>> {
    let (mut cursor, end) = extensions_range(hello);
    while cursor + 4 <= end {
        let extension_type = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]);
        let length = u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]) as usize;
        if extension_type == wanted {
            return Some(hello[cursor + 4..cursor + 4 + length].to_vec());
        }
        cursor += 4 + length;
    }
    None
}

/// RFC 8701 reserves sixteen `0xωaωa` points. They are drawn per connection, so
/// two hellos from the same table never agree on them and a comparison across
/// connections has to leave them out.
pub fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

/// The hello's extension types with the GREASE ones removed, sorted — what two
/// connections from the same table must agree on even when the profile permutes.
pub fn stable_extension_types(hello: &[u8]) -> Vec<u16> {
    let mut types: Vec<u16> = extension_types(hello)
        .into_iter()
        .filter(|value| !is_grease(*value))
        .collect();
    types.sort_unstable();
    types
}

/// A hello that is still a hello: it names a key share and a version list, so a
/// fallback assertion says "the built-in table is writing" rather than merely
/// "some bytes went out".
pub fn assert_is_a_complete_client_hello(label: &str, hello: &[u8]) {
    let types = extension_types(hello);
    assert!(
        types.contains(&KEY_SHARE) && types.contains(&SUPPORTED_VERSIONS),
        "{label}: the hello must still carry a key share and a version list"
    );
}
