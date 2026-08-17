//! Replays recorded reference-implementation handshakes through this client.
//!
//! `fixtures/vless-encryption/vectors.json` was produced by running the
//! upstream Go client and server (`XTLS/Xray-core`, `proxy/vless/encryption`,
//! verbatim apart from redirecting every source of randomness to a recorded
//! stream) against each other over loopback TCP. For each connection it holds
//! the complete transcript in both directions plus the client-side ephemeral
//! values that never reach the wire.
//!
//! So the assertion available here is the strongest one short of a live server:
//! *given the same ephemerals, this client must emit the same bytes the
//! reference client emitted, and must recover the plaintext the reference
//! server sent.* That covers the framing, the padding layout, the relay
//! chaining, the appearance modes, both AEADs, the nonce schedule, every BLAKE3
//! context, and the 0-RTT ticket cache.
//!
//! What it does not cover is stated plainly: the KEM primitives themselves are
//! supplied by the test, so this proves nothing about whether `aws-lc-rs` and
//! Go agree on ML-KEM-768 and X25519. See the report.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use foxcore_transport::BoxStream;
use proto_vless::encryption::{
    ClientInstance, HandshakeCrypto, NfsPublicKey, NfsShare, PfsOffer, XorMode, parse_encryption,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const VECTORS: &str = include_str!("../../../fixtures/vless-encryption/vectors.json");

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(bytes);
    out
}

// ---------------------------------------------------------------------------
// A stream that answers with a recorded script and records what it is told.

#[derive(Clone, Default)]
struct Written(Arc<Mutex<Vec<u8>>>);

impl Written {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

struct ScriptedStream {
    inbound: Vec<u8>,
    read_pos: usize,
    written: Written,
}

impl ScriptedStream {
    fn new(inbound: Vec<u8>) -> (Self, Written) {
        let written = Written::default();
        (
            Self {
                inbound,
                read_pos: 0,
                written: written.clone(),
            },
            written,
        )
    }
}

impl AsyncRead for ScriptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let available = &self.inbound[self.read_pos..];
        let take = available.len().min(buf.remaining());
        buf.put_slice(&available[..take]);
        self.read_pos += take;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.0.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// The recorded ephemerals, played back in place of live randomness.

struct ScriptedCrypto {
    iv: Vec<u8>,
    shares: VecDeque<(Vec<u8>, [u8; 32])>,
    pfs_public: Vec<u8>,
    pfs_answer: Vec<u8>,
    mlkem_shared: [u8; 32],
    x25519_shared: [u8; 32],
}

impl HandshakeCrypto for ScriptedCrypto {
    fn fill_random(&mut self, out: &mut [u8]) -> io::Result<()> {
        assert_eq!(out.len(), self.iv.len(), "only the IV is drawn this way");
        out.copy_from_slice(&self.iv);
        Ok(())
    }

    /// The oracle ran with `crypto.RandBetween` pinned to its low end, so every
    /// probability check fires and every length is `from`.
    fn rand_between(&mut self, from: u32, _to: u32) -> u32 {
        from
    }

    fn nfs_share(&mut self, _peer: &NfsPublicKey) -> io::Result<NfsShare> {
        let (wire, shared_secret) = self.shares.pop_front().expect("a recorded share per hop");
        Ok(NfsShare {
            wire,
            shared_secret,
        })
    }

    fn pfs_offer(&mut self) -> io::Result<Box<dyn PfsOffer>> {
        Ok(Box::new(ScriptedOffer {
            public: self.pfs_public.clone(),
            expected_answer: self.pfs_answer.clone(),
            mlkem_shared: self.mlkem_shared,
            x25519_shared: self.x25519_shared,
        }))
    }
}

struct ScriptedOffer {
    public: Vec<u8>,
    expected_answer: Vec<u8>,
    mlkem_shared: [u8; 32],
    x25519_shared: [u8; 32],
}

impl PfsOffer for ScriptedOffer {
    fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    fn derive(self: Box<Self>, answer: &[u8]) -> io::Result<[u8; 64]> {
        // This is where the server hello's decryption is checked. Upstream
        // seals this one message under the all-FF nonce rather than the
        // counter, so a client that used the counter here reaches this
        // assertion with 1120 bytes of garbage.
        assert_eq!(
            answer,
            self.expected_answer.as_slice(),
            "client decrypted the server's forward-secret block incorrectly"
        );
        let mut key = [0_u8; 64];
        key[..32].copy_from_slice(&self.mlkem_shared);
        key[32..].copy_from_slice(&self.x25519_shared);
        Ok(key)
    }
}

// ---------------------------------------------------------------------------

struct Case {
    name: String,
    spec: String,
    use_aes: bool,
    conns: Vec<Value>,
}

fn cases() -> Vec<Case> {
    let root: Value = serde_json::from_str(VECTORS).expect("vectors.json parses");
    root["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .map(|case| {
            let mode = match case["xor_mode"].as_u64().unwrap() {
                0 => "native",
                1 => "xorpub",
                2 => "random",
                other => panic!("unknown xor mode {other}"),
            };
            let rtt = if case["zero_rtt"].as_bool().unwrap() {
                "0rtt"
            } else {
                "1rtt"
            };
            let padding = case["client_padding"].as_str().unwrap();
            let keys: Vec<&str> = case["nfs_public_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| key.as_str().unwrap())
                .collect();
            let mut spec = format!("mlkem768x25519plus.{mode}.{rtt}");
            if !padding.is_empty() {
                spec.push('.');
                spec.push_str(padding);
            }
            spec.push('.');
            spec.push_str(&keys.join("."));
            Case {
                name: case["name"].as_str().unwrap().to_string(),
                spec,
                use_aes: case["use_aes"].as_bool().unwrap(),
                conns: case["conns"].as_array().unwrap().clone(),
            }
        })
        .collect()
}

fn scripted_crypto(conn: &Value) -> ScriptedCrypto {
    let wires = conn["share_wires"].as_array().unwrap();
    let secrets = conn["share_secrets"].as_array().unwrap();
    let shares = wires
        .iter()
        .zip(secrets)
        .map(|(wire, secret)| {
            (
                unhex(wire.as_str().unwrap()),
                array32(&unhex(secret.as_str().unwrap())),
            )
        })
        .collect();
    ScriptedCrypto {
        iv: unhex(conn["iv"].as_str().unwrap()),
        shares,
        pfs_public: unhex(conn["pfs_public_key"].as_str().unwrap()),
        pfs_answer: unhex(conn["pfs_answer"].as_str().unwrap()),
        mlkem_shared: {
            let raw = unhex(conn["mlkem_shared"].as_str().unwrap());
            if raw.is_empty() {
                [0; 32]
            } else {
                array32(&raw)
            }
        },
        x25519_shared: {
            let raw = unhex(conn["x25519_shared"].as_str().unwrap());
            if raw.is_empty() {
                [0; 32]
            } else {
                array32(&raw)
            }
        },
    }
}

/// Run one recorded connection. Returns the bytes this client wrote.
async fn replay(client: &ClientInstance, conn: &Value, use_aes: bool, label: &str) -> Vec<u8> {
    let expected_out = unhex(conn["client_to_server"].as_str().unwrap());
    let inbound = unhex(conn["server_to_client"].as_str().unwrap());
    let client_payload = unhex(conn["client_payload"].as_str().unwrap());
    let server_payload = unhex(conn["server_payload"].as_str().unwrap());

    let (stream, written) = ScriptedStream::new(inbound);
    let mut crypto = scripted_crypto(conn);
    let mut encrypted = client
        .handshake_with_cipher(Box::new(stream) as BoxStream, &mut crypto, use_aes)
        .await
        .unwrap_or_else(|error| panic!("{label}: handshake failed: {error}"));

    // Fail at the handshake boundary rather than at the end, so a framing bug
    // points at the flight that produced it.
    let after_handshake = written.bytes();
    assert!(
        expected_out.starts_with(&after_handshake),
        "{label}: handshake bytes diverge from the reference client at byte {}",
        after_handshake
            .iter()
            .zip(&expected_out)
            .position(|(a, b)| a != b)
            .map_or(after_handshake.len(), |index| index)
    );

    encrypted.write_all(&client_payload).await.unwrap();
    encrypted.flush().await.unwrap();
    assert_eq!(
        written.bytes(),
        expected_out,
        "{label}: full client transcript diverges from the reference client"
    );

    let mut received = vec![0_u8; server_payload.len()];
    encrypted
        .read_exact(&mut received)
        .await
        .unwrap_or_else(|error| panic!("{label}: reading the server payload failed: {error}"));
    assert_eq!(
        received, server_payload,
        "{label}: server payload did not decrypt to the reference plaintext"
    );
    written.bytes()
}

#[tokio::test]
async fn every_recorded_handshake_reproduces_byte_for_byte() {
    let cases = cases();
    assert!(cases.len() >= 12, "fixture lost cases");
    for case in &cases {
        let params = parse_encryption(&case.spec)
            .unwrap_or_else(|error| panic!("{}: spec did not parse: {error}", case.name));
        let client = ClientInstance::new(params);
        // Connections share one instance on purpose: the second one is only
        // 0-RTT because the first one populated the ticket cache.
        for conn in &case.conns {
            let kind = conn["kind"].as_str().unwrap();
            replay(
                &client,
                conn,
                case.use_aes,
                &format!("{} [{kind}]", case.name),
            )
            .await;
        }
    }
}

/// 0-RTT is not a separate code path being exercised in isolation: the second
/// connection can only reproduce its recorded bytes if the ticket and forward
/// secret cached by the first are exactly what the reference client cached.
#[tokio::test]
async fn zero_rtt_reuses_the_ticket_the_first_connection_cached() {
    let cases = cases();
    let mut checked = 0;
    for case in &cases {
        if case.conns.len() < 2 {
            continue;
        }
        let params = parse_encryption(&case.spec).unwrap();
        let client = ClientInstance::new(params);
        replay(&client, &case.conns[0], case.use_aes, &case.name).await;

        let second = &case.conns[1];
        assert_eq!(second["kind"].as_str().unwrap(), "0rtt");
        // The recorded 0-RTT flight is far shorter than a 1-RTT one, so a
        // client that silently fell back would fail this before the bytes.
        let expected = unhex(second["client_to_server"].as_str().unwrap());
        assert!(
            expected.len() < 2000,
            "{}: second connection is not a 0-RTT flight",
            case.name
        );
        replay(&client, second, case.use_aes, &case.name).await;
        checked += 1;
    }
    assert!(checked >= 4, "expected several 0-RTT cases, saw {checked}");
}

/// Without a cached ticket the client must perform the full exchange. Feeding
/// the *second* connection's script to a fresh instance has to fail, because a
/// fresh instance sends a 1-RTT hello and the script answers a 0-RTT one.
#[tokio::test]
async fn zero_rtt_is_not_used_without_a_cached_ticket() {
    let case = cases()
        .into_iter()
        .find(|case| case.name == "native_0rtt_x25519_aes")
        .expect("case present");
    let params = parse_encryption(&case.spec).unwrap();
    let client = ClientInstance::new(params);
    let conn = &case.conns[1];

    let (stream, written) = ScriptedStream::new(unhex(conn["server_to_client"].as_str().unwrap()));
    let mut crypto = scripted_crypto(&case.conns[0]);
    let result = client
        .handshake_with_cipher(Box::new(stream) as BoxStream, &mut crypto, case.use_aes)
        .await;
    assert!(
        result.is_err(),
        "a fresh instance accepted a 0-RTT server script"
    );
    let expected_zero_rtt = unhex(conn["client_to_server"].as_str().unwrap());
    assert_ne!(
        written.bytes(),
        expected_zero_rtt,
        "a fresh instance emitted the 0-RTT flight"
    );
}

// ---------------------------------------------------------------------------
// Negative controls.
//
// Every assertion above is "these bytes match". That is only worth something if
// the inputs actually reach the bytes, so each of these breaks exactly one
// input and requires the comparison to notice.

async fn replay_expecting_divergence(
    case: &Case,
    conn: &Value,
    mut crypto: ScriptedCrypto,
) -> bool {
    let params = parse_encryption(&case.spec).unwrap();
    let client = ClientInstance::new(params);
    let expected_out = unhex(conn["client_to_server"].as_str().unwrap());
    let (stream, written) = ScriptedStream::new(unhex(conn["server_to_client"].as_str().unwrap()));
    let handshake = client
        .handshake_with_cipher(Box::new(stream) as BoxStream, &mut crypto, case.use_aes)
        .await;
    let Ok(mut encrypted) = handshake else {
        return true;
    };
    let payload = unhex(conn["client_payload"].as_str().unwrap());
    if encrypted.write_all(&payload).await.is_err() {
        return true;
    }
    if written.bytes() != expected_out {
        return true;
    }
    let server_payload = unhex(conn["server_payload"].as_str().unwrap());
    let mut received = vec![0_u8; server_payload.len()];
    encrypted.read_exact(&mut received).await.is_err() || received != server_payload
}

fn first_case(name: &str) -> Case {
    cases().into_iter().find(|case| case.name == name).unwrap()
}

/// `nfsKey` must reach the client hello. If it did not, the sealed length and
/// the sealed forward-secret block would be identical no matter which server
/// the profile named.
#[tokio::test]
async fn a_wrong_nfs_secret_changes_the_client_hello() {
    let case = first_case("native_1rtt_x25519_aes");
    let conn = case.conns[0].clone();
    let mut crypto = scripted_crypto(&conn);
    crypto.shares[0].1[0] ^= 0x01;
    assert!(
        replay_expecting_divergence(&case, &conn, crypto).await,
        "flipping one bit of nfsKey produced an identical transcript"
    );
}

/// `unitedKey` is `pfsKey ‖ nfsKey`. Breaking the ML-KEM half must break the
/// data records, which is the property that makes recording traffic today and
/// breaking X25519 later insufficient.
#[tokio::test]
async fn a_wrong_ml_kem_secret_breaks_the_data_records() {
    let case = first_case("native_1rtt_x25519_aes");
    let conn = case.conns[0].clone();
    let mut crypto = scripted_crypto(&conn);
    crypto.mlkem_shared[0] ^= 0x01;
    assert!(
        replay_expecting_divergence(&case, &conn, crypto).await,
        "flipping one bit of the ML-KEM secret left the records intact"
    );
}

/// And the X25519 half, independently — so neither can be silently dropped from
/// the concatenation.
#[tokio::test]
async fn a_wrong_x25519_secret_breaks_the_data_records() {
    let case = first_case("native_1rtt_x25519_aes");
    let conn = case.conns[0].clone();
    let mut crypto = scripted_crypto(&conn);
    crypto.x25519_shared[31] ^= 0x80;
    assert!(
        replay_expecting_divergence(&case, &conn, crypto).await,
        "flipping one bit of the X25519 secret left the records intact"
    );
}

/// The IV keys `nfsAEAD` and every relay mask, so it cannot be cosmetic.
#[tokio::test]
async fn a_wrong_iv_changes_the_client_hello() {
    let case = first_case("random_1rtt_x25519_aes");
    let conn = case.conns[0].clone();
    let mut crypto = scripted_crypto(&conn);
    crypto.iv[0] ^= 0x01;
    assert!(
        replay_expecting_divergence(&case, &conn, crypto).await,
        "flipping one bit of the IV produced an identical transcript"
    );
}

/// The appearance mode has to be applied, not merely parsed. Replaying a
/// `random` vector under `native` — same keys, same ephemerals — must diverge,
/// both in the masked relay bytes and in the record headers.
#[tokio::test]
async fn appearance_modes_are_not_interchangeable() {
    let recorded = first_case("random_1rtt_x25519_aes");
    let conn = recorded.conns[0].clone();
    for substitute in ["native", "xorpub"] {
        let spec = recorded
            .spec
            .replace(".random.", &format!(".{substitute}."));
        assert_ne!(spec, recorded.spec);
        let case = Case {
            name: format!("random-as-{substitute}"),
            spec,
            use_aes: recorded.use_aes,
            conns: vec![conn.clone()],
        };
        assert!(
            replay_expecting_divergence(&case, &conn, scripted_crypto(&conn)).await,
            "a {substitute} client reproduced a random-mode transcript"
        );
    }
    // The reverse direction too: xorpub and native differ only in whether the
    // relay material is masked, which is the easiest thing to leave unwired.
    let recorded = first_case("xorpub_1rtt_x25519_aes");
    let conn = recorded.conns[0].clone();
    let case = Case {
        name: "xorpub-as-native".into(),
        spec: recorded.spec.replace(".xorpub.", ".native."),
        use_aes: recorded.use_aes,
        conns: vec![conn.clone()],
    };
    assert!(
        replay_expecting_divergence(&case, &conn, scripted_crypto(&conn)).await,
        "a native client reproduced an xorpub transcript"
    );
}

/// The two AEADs are chosen locally, not negotiated, so the vectors must be
/// sensitive to that choice: a ChaCha20-Poly1305 client cannot reproduce an
/// AES-256-GCM transcript.
#[tokio::test]
async fn the_aead_choice_changes_the_transcript() {
    let recorded = first_case("native_1rtt_x25519_aes");
    let conn = recorded.conns[0].clone();
    let case = Case {
        name: "aes-as-chacha".into(),
        spec: recorded.spec.clone(),
        use_aes: false,
        conns: vec![conn.clone()],
    };
    assert!(
        replay_expecting_divergence(&case, &conn, scripted_crypto(&conn)).await,
        "a ChaCha20-Poly1305 client reproduced an AES-256-GCM transcript"
    );
}

/// Relay chaining binds each hop to the next. Dropping a hop, or reordering
/// them, must not still produce the recorded bytes.
#[tokio::test]
async fn relay_chains_are_order_sensitive() {
    let recorded = first_case("native_1rtt_relay3_aes");
    let conn = recorded.conns[0].clone();
    let params = parse_encryption(&recorded.spec).unwrap();
    assert_eq!(params.nfs_keys.len(), 3, "fixture is a three-hop chain");

    let fields: Vec<&str> = recorded.spec.split('.').collect();
    let (head, keys) = fields.split_at(3);
    let mut swapped = keys.to_vec();
    swapped.swap(1, 2);
    let spec = format!("{}.{}", head.join("."), swapped.join("."));
    assert_ne!(spec, recorded.spec);

    let case = Case {
        name: "relay-swapped".into(),
        spec,
        use_aes: recorded.use_aes,
        conns: vec![conn.clone()],
    };
    // The shares are replayed in hop order, so swapping the configured keys
    // changes only the per-hop masks and the next-hop hashes — exactly the
    // binding that is supposed to make a relay irreplaceable.
    assert!(
        replay_expecting_divergence(&case, &conn, scripted_crypto(&conn)).await,
        "reordering the relay chain reproduced the recorded transcript"
    );
}

/// Guards the negative controls themselves: the harness above reports
/// divergence, so it must report agreement when nothing is broken.
#[tokio::test]
async fn the_divergence_harness_agrees_with_an_untouched_replay() {
    let case = first_case("native_1rtt_x25519_aes");
    let conn = case.conns[0].clone();
    assert!(
        !replay_expecting_divergence(&case, &conn, scripted_crypto(&conn)).await,
        "an untouched replay was reported as diverging, so the negative controls prove nothing"
    );
}

/// The appearance mode must not leak into the parse of a well-formed profile.
#[test]
fn every_fixture_spec_round_trips_through_the_parser() {
    for case in cases() {
        let params =
            parse_encryption(&case.spec).unwrap_or_else(|error| panic!("{}: {error}", case.name));
        let expected = match case.spec.split('.').nth(1).unwrap() {
            "native" => XorMode::Native,
            "xorpub" => XorMode::XorPub,
            _ => XorMode::Random,
        };
        assert_eq!(params.xor_mode, expected, "{}", case.name);
        assert_eq!(
            params.zero_rtt,
            case.spec.contains(".0rtt."),
            "{}",
            case.name
        );
    }
}

/// The path a client hits when its cached ticket has aged out of the server's
/// map: the server cannot authenticate anything, so it replies with a stream of
/// noise rather than an error it would have to authenticate. The client has to
/// recognise that, drop the session, and fall back — otherwise it retries 0-RTT
/// against a server that will never accept it again.
///
/// Neither the recorded transcripts nor the live run reach this: both only ever
/// present a ticket the server still knows.
#[tokio::test]
async fn a_rejected_ticket_drops_the_session_and_falls_back_to_1_rtt() {
    let case = first_case("native_0rtt_x25519_aes");
    let params = parse_encryption(&case.spec).unwrap();
    let client = ClientInstance::new(params);

    // First connection negotiates and caches a ticket.
    replay(&client, &case.conns[0], case.use_aes, &case.name).await;

    // Second connection presents it and is answered with noise. Upstream sends
    // 1279..=2279 random bytes; what matters is that no five of them at the
    // front decode as a record header.
    let noise: Vec<u8> = (0..1600).map(|i| (i as u32 % 253 + 1) as u8).collect();
    let (stream, written) = ScriptedStream::new(noise);
    let mut crypto = scripted_crypto(&case.conns[1]);
    let mut encrypted = client
        .handshake_with_cipher(Box::new(stream) as BoxStream, &mut crypto, case.use_aes)
        .await
        .expect("the 0-RTT flight is written without waiting for the server");
    assert!(
        written.bytes().len() < 2000,
        "the second connection was not a 0-RTT flight"
    );

    encrypted.write_all(b"request").await.unwrap();
    let mut buffer = [0_u8; 16];
    let error = encrypted
        .read(&mut buffer)
        .await
        .expect_err("noise was accepted as a record");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset,
        "a rejected ticket must be distinguishable from a corrupt stream: {error}"
    );

    // And the session is gone, so the next connection pays for a full exchange.
    let (stream, written) = ScriptedStream::new(Vec::new());
    let mut crypto = scripted_crypto(&case.conns[0]);
    let _ = client
        .handshake_with_cipher(Box::new(stream) as BoxStream, &mut crypto, case.use_aes)
        .await;
    let expected_1rtt = unhex(case.conns[0]["client_to_server"].as_str().unwrap());
    let handshake_prefix = expected_1rtt.len() - 5 - 16 - 54;
    assert_eq!(
        written.bytes(),
        expected_1rtt[..handshake_prefix],
        "after a rejected ticket the client did not fall back to a full 1-RTT exchange"
    );
}
