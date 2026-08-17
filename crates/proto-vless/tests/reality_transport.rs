//! REALITY under a stream transport, from share link to socket.
//!
//! The two gates this covers used to sit in three places — the link parser, the
//! config validator and `VlessOutbound::new` — and between them a
//! `security=reality&type=grpc&fp=qq` node could not be imported at all. Parsing
//! is the cheap half of the claim; the expensive half is that the profile the
//! parser emits is one the outbound will actually build and dial, with REALITY
//! on the socket and the carrier above it rather than the other way round.
//!
//! Everything here is synthetic: `example.net`, `198.51.100.0/24`, a nil-ish
//! UUID and a public key of repeated bytes.

use std::time::Duration;

use foxcore_api::{Destination, EngineConfig, OutboundConfig, StreamTransportConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_link::import_link;
use proto_vless::VlessOutbound;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// A REALITY public key that decodes to 32 bytes and belongs to nobody.
const PUBLIC_KEY: &str = "t2ZQZgVX0h9ItHCmYzVQIWLPYs2N9v0lBjTsLpEhAXQ";
const UUID: &str = "d0cf0001-0000-4000-8000-000000000000";
const SNI: &str = "reality.example.net";

/// The share link the provider writes, pointed at a local listener.
///
/// The host stays a name so the profile is the shape a subscription carries;
/// `server_ip` is what redirects the dial, exactly as it would for a node whose
/// address the provider pins.
fn link(port: u16, transport: &str) -> String {
    format!(
        "vless://{UUID}@example.net:{port}\
         ?encryption=none&security=reality&sni={SNI}&fp=qq\
         &pbk={PUBLIC_KEY}&sid=aabb&server_ip=127.0.0.1&{transport}#node"
    )
}

/// Import, validate as an engine config, and build the outbound.
///
/// The middle step is not decoration: `EngineConfig::parse` runs
/// `OutboundConfig::validate`, which is the second of the three gates.
async fn outbound_from(link_text: &str) -> (VlessOutbound, OutboundConfig, Vec<String>) {
    let imported = import_link(link_text).expect("link must import");
    let dropped = imported
        .dropped
        .iter()
        .map(|option| option.option.clone())
        .collect::<Vec<_>>();

    let engine = format!(
        r#"{{"schema_version":1,"outbound":{},"tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}}}"#,
        serde_json::to_string(&imported.outbound).unwrap()
    );
    EngineConfig::parse(&engine).expect("imported profile must validate as an engine config");

    let OutboundConfig::Vless(config) = imported.outbound.clone() else {
        panic!("profile must be VLESS");
    };
    let outbound = VlessOutbound::new(config, ProtectedDialer::host())
        .await
        .expect("outbound must build");
    (outbound, imported.outbound, dropped)
}

/// The measured node: REALITY, gRPC, `fp=qq`.
///
/// The listener answers nothing and hangs up, so the dial cannot complete — the
/// point is *which* layer speaks first. A TLS 1.3 ClientHello carrying the
/// REALITY SNI means the handshake ran on the TCP socket; an HTTP/2 preface
/// would have meant gRPC was underneath REALITY instead of inside it, which is
/// the bug a parse-only fix would have shipped.
#[tokio::test]
async fn a_reality_grpc_link_builds_an_outbound_that_speaks_reality_first() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let link_text = link(port, "type=grpc&serviceName=fox&mode=gun");

    let (outbound, config, dropped) = outbound_from(&link_text).await;
    // `fp=qq` used to be substituted with Chrome and reported. QQ Browser 11.1
    // is a real table now, so the link is honoured and nothing is dropped.
    assert!(dropped.is_empty(), "fp=qq is implemented: {dropped:?}");
    let OutboundConfig::Vless(vless) = &config else {
        panic!("profile must be VLESS");
    };
    assert!(vless.reality.is_some());
    assert!(!vless.tls.enabled);
    assert!(matches!(
        vless.transport,
        StreamTransportConfig::Grpc { .. }
    ));

    let dial = tokio::spawn(async move {
        outbound
            .connect_stream(&Destination::new("origin.example", 80))
            .await
            .map(|_| ())
    });

    let (mut server, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the outbound must dial")
        .unwrap();

    let mut first = vec![0_u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(10), server.read(&mut first))
        .await
        .expect("the outbound must send something")
        .unwrap();
    first.truncate(read);

    assert!(read > 5, "expected a ClientHello, got {read} bytes");
    // TLS record: handshake content type, a legacy record version, then the
    // ClientHello handshake type. The record version is deliberately not
    // pinned here — it belongs to the parrot, not to this composition.
    assert_eq!(first[0], 0x16, "not a TLS handshake record");
    assert_eq!(first[1], 0x03, "not a TLS handshake record");
    assert_eq!(first[5], 0x01, "not a ClientHello");
    assert!(
        !first.starts_with(b"PRI * HTTP/2.0"),
        "gRPC spoke before REALITY did"
    );
    // The SNI the link asked for is in those bytes, in the clear, which is what
    // makes the record a REALITY hello for this server rather than any hello.
    assert!(
        first
            .windows(SNI.len())
            .any(|window| window == SNI.as_bytes()),
        "the ClientHello does not carry the REALITY SNI"
    );

    // Hanging up mid-handshake must surface as a REALITY failure: the layer
    // that owns the socket at this point is REALITY, not gRPC.
    drop(server);
    let error = tokio::time::timeout(Duration::from_secs(20), dial)
        .await
        .expect("the dial must finish")
        .unwrap()
        .expect_err("a server that says nothing cannot complete a handshake");
    assert!(
        error.to_string().contains("REALITY"),
        "expected a REALITY handshake error, got: {error}"
    );
}

/// The same claim for the other carriers, minus the wire assertions: a link
/// that imports must also produce an outbound that builds. `VlessOutbound::new`
/// was the last of the three gates and the one a parse-only fix would have
/// left standing.
#[tokio::test]
async fn reality_builds_an_outbound_under_every_stream_transport() {
    for transport in [
        "type=tcp",
        "type=grpc&serviceName=fox&mode=gun",
        "type=ws&path=%2Fws",
        "type=httpupgrade&path=%2Fup",
    ] {
        let link_text = link(443, transport);
        let (_outbound, _config, dropped) = outbound_from(&link_text).await;
        assert!(dropped.is_empty(), "for {transport}: {dropped:?}");
    }
}

/// gRPC over a **completed** REALITY stream.
///
/// The test above proves ordering: REALITY speaks first, gRPC does not jump the
/// queue. It cannot prove the part that matters once a node is real — that
/// after the handshake finishes, the carrier above REALITY gets a byte stream
/// it can frame on, and that what reaches the server is gRPC and not garbage.
/// Nothing in-tree could prove that, because there was no REALITY server to
/// finish a handshake with; `proto-reality`'s server constructors were
/// `#[cfg(test)]`-private to their own crate.
///
/// `proto_reality::testkit` is that server. It completes a real TLS 1.3
/// handshake — ServerHello, EncryptedExtensions, the HMAC certificate REALITY
/// authenticates with, CertificateVerify, Finished — against the unmodified
/// client, which verifies every one of those and refuses if any is wrong. So
/// reaching the assertions below is itself the proof that the handshake was
/// genuine: a broken server cannot get this far.
///
/// Synthetic throughout: the server's private key is a fixed byte pattern and
/// the public key handed to the client is derived from it.
#[tokio::test]
async fn grpc_frames_cross_a_completed_reality_stream() {
    use proto_reality::testkit::RealityTestServer;

    // A REALITY keypair that belongs to nobody.
    const SERVER_PRIVATE: [u8; 32] = [0x4a; 32];
    let server = RealityTestServer::new(SERVER_PRIVATE, SNI);
    let public_key = server.public_key().expect("public key");
    let encoded = base64_url_nopad(&public_key);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let link_text = format!(
        "vless://{UUID}@example.net:{port}\
         ?encryption=none&security=reality&sni={SNI}&fp=chrome\
         &pbk={encoded}&sid=aabb&server_ip=127.0.0.1\
         &type=grpc&serviceName=fox&mode=gun#node"
    );

    let (outbound, _config, _dropped) = outbound_from(&link_text).await;

    let dial = tokio::spawn(async move {
        outbound
            .connect_stream(&Destination::new("origin.example", 80))
            .await
            .map(|_| ())
    });

    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the outbound must dial")
        .unwrap();

    let handshake = tokio::time::timeout(Duration::from_secs(20), server.handshake(&mut socket))
        .await
        .expect("the handshake must not hang");
    let mut session = match handshake {
        Ok(session) => session,
        Err(error) => {
            let client = tokio::time::timeout(Duration::from_secs(5), dial).await;
            panic!("server side: {error:?}; client side: {client:?}");
        }
    };

    // The parrot's first three bytes, observed on a real dial rather than only
    // in a unit test. 0x0301 is what BoringSSL and uTLS put on an initial
    // ClientHello record; this client used to send 0x0303.
    let header = session.initial_record_header();
    assert_eq!(
        [header[1], header[2]],
        proto_reality::testkit::observed_initial_record_version(),
        "the initial ClientHello record header is not what the parrot promises"
    );
    assert_eq!(&header[..3], &[0x16, 0x03, 0x01]);

    // Past this point the client has verified the HMAC certificate, the
    // CertificateVerify signature and the server Finished. Whatever it writes
    // now is the carrier's, and the carrier is gRPC.
    let first = tokio::time::timeout(Duration::from_secs(20), session.read(&mut socket))
        .await
        .expect("the carrier must send something after the handshake")
        .expect("application data must decrypt");

    // gRPC-over-HTTP/2 ("gun" mode) opens with the HTTP/2 connection preface.
    // That it arrives *inside* the REALITY record layer — it decrypted — is the
    // whole claim: the carrier is above REALITY, not beside it.
    assert!(
        first.starts_with(b"PRI * HTTP/2.0\r\n"),
        "expected an HTTP/2 preface inside the REALITY stream, got {:?}",
        &first[..first.len().min(32)]
    );

    dial.abort();
}

/// base64url without padding, which is how a share link spells a REALITY key.
fn base64_url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let indices = [n >> 18 & 63, n >> 12 & 63, n >> 6 & 63, n & 63];
        for (position, index) in indices.iter().enumerate() {
            if position <= chunk.len() {
                out.push(ALPHABET[*index as usize] as char);
            }
        }
    }
    out
}
