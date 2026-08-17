//! `fp=firefox` all the way to the socket.
//!
//! The whole point of a parrot is that the bytes are somebody else's. A profile
//! that asks for Firefox and sends Chrome is not a smaller version of the right
//! answer — it is a client that claims one population and joins another, and
//! nothing between the link and the socket notices, because every layer in
//! between is happy to carry a name it never checks.
//!
//! So this test does not check a name. It dials, reads the first record off the
//! wire, and asks the hello what it is: Firefox sends `record_size_limit` and
//! `delegated_credentials` and no GREASE at all; the Chromium family sends
//! `session_ticket`, `application_settings`, and brackets its extension list
//! with a GREASE pair. Two disjoint sets, both visible to anything on the path.
//!
//! Both directions are asserted, and that matters more than it looks: the
//! version of this code being fixed answered *every* profile with Chrome, so a
//! test that only pinned Chrome's markers would have passed against it.
//!
//! Everything is synthetic: `example.net`, `198.51.100.0/24`, a nil-ish UUID
//! and a public key of repeated bytes.

use std::time::Duration;

use foxcore_api::{Destination, EngineConfig, OutboundConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_link::import_link;
use proto_vless::VlessOutbound;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

/// A REALITY public key that decodes to 32 bytes and belongs to nobody.
const PUBLIC_KEY: &str = "t2ZQZgVX0h9ItHCmYzVQIWLPYs2N9v0lBjTsLpEhAXQ";
const UUID: &str = "d0cf0001-0000-4000-8000-000000000000";
const SNI: &str = "reality.example.net";

// Extensions that separate the two families. Not a hash: a JA3 would move with
// Chrome's per-connection permutation, and a JA4 would have to be regenerated
// every time a table is refreshed. These code points are what the profiles
// themselves are made of.
const SESSION_TICKET: u16 = 0x0023;
const DELEGATED_CREDENTIALS: u16 = 0x0022;
const RECORD_SIZE_LIMIT: u16 = 0x001c;
const APPLICATION_SETTINGS: u16 = 0x44cd;
const APPLICATION_SETTINGS_OLD: u16 = 0x4469;

fn link(port: u16, fingerprint: &str) -> String {
    format!(
        "vless://{UUID}@example.net:{port}\
         ?encryption=none&security=reality&sni={SNI}&fp={fingerprint}\
         &pbk={PUBLIC_KEY}&sid=aabb&server_ip=127.0.0.1#node"
    )
}

/// The FoxCore engine config the Android app writes for a REALITY node.
///
/// Spelled out rather than imported so this test states the *contract* between
/// the two repositories: the app's translator emits `reality.fingerprint` as
/// one of these canonical names, and this is what the core does with it. The
/// app's `FoxCoreRealityFingerprintTest` asserts the other half — that
/// `fp=firefox` reaches this field as `firefox_148` rather than as `chrome`.
fn app_engine_config(port: u16, fingerprint: &str) -> String {
    format!(
        r#"{{"schema_version":1,
            "outbound":{{"type":"vless","server":"example.net","server_ip":"127.0.0.1",
              "port":{port},"uuid":"{UUID}","packet_encoding":"none",
              "transport":{{"type":"raw"}},"tls":{{"enabled":false}},
              "reality":{{"server_name":"{SNI}","public_key":"{PUBLIC_KEY}",
                "short_id":"aabb","fingerprint":"{fingerprint}"}}}},
            "tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}}}"#
    )
}

/// Dial a local listener with the profile and return the ClientHello body.
async fn client_hello_from(config: OutboundConfig, listener: TcpListener) -> Vec<u8> {
    let OutboundConfig::Vless(vless) = config else {
        panic!("profile must be VLESS");
    };
    let outbound = VlessOutbound::new(vless, ProtectedDialer::host())
        .await
        .expect("outbound must build");

    let dial = tokio::spawn(async move {
        let _ = outbound
            .connect_stream(&Destination::new("origin.example", 80))
            .await;
    });

    let (mut server, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the outbound must dial")
        .expect("accept");
    let mut record = vec![0_u8; 8192];
    let read = tokio::time::timeout(Duration::from_secs(10), server.read(&mut record))
        .await
        .expect("the outbound must send something")
        .expect("read");
    record.truncate(read);
    drop(server);
    let _ = tokio::time::timeout(Duration::from_secs(20), dial).await;

    assert_eq!(record[0], 0x16, "not a TLS handshake record");
    assert_eq!(record[5], 0x01, "not a ClientHello");
    assert!(
        record
            .windows(SNI.len())
            .any(|window| window == SNI.as_bytes()),
        "the ClientHello does not carry the REALITY SNI"
    );
    record[5..].to_vec()
}

/// Every extension type the hello carries.
fn extension_types(hello: &[u8]) -> Vec<u16> {
    let mut cursor = 4 + 2 + 32;
    cursor += 1 + hello[cursor] as usize;
    cursor += 2 + u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 1 + hello[cursor] as usize;
    let end = cursor + 2 + u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
    cursor += 2;
    let mut types = Vec::new();
    while cursor + 4 <= end {
        types.push(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
        cursor += 4 + u16::from_be_bytes([hello[cursor + 2], hello[cursor + 3]]) as usize;
    }
    types
}

fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

/// The hello is Firefox's: its two signature extensions are present, the
/// Chromium ones are not, and there is no GREASE anywhere. Firefox is the
/// sharpest case in the table set precisely because it shares nothing with the
/// profile this code used to substitute.
fn assert_is_firefox(label: &str, hello: &[u8]) {
    let types = extension_types(hello);
    assert!(
        types.contains(&RECORD_SIZE_LIMIT) && types.contains(&DELEGATED_CREDENTIALS),
        "{label}: a Firefox hello carries record_size_limit and delegated_credentials: {types:04x?}"
    );
    assert!(
        !types.contains(&APPLICATION_SETTINGS) && !types.contains(&APPLICATION_SETTINGS_OLD),
        "{label}: application_settings is a Chromium extension: {types:04x?}"
    );
    assert!(
        !types.iter().copied().any(is_grease),
        "{label}: Firefox GREASEs nothing: {types:04x?}"
    );
}

/// The hello is Chrome's, which is the control: without it, a test could pass
/// by sending Firefox to everybody.
fn assert_is_chrome(label: &str, hello: &[u8]) {
    let types = extension_types(hello);
    assert!(
        types.contains(&SESSION_TICKET),
        "{label}: a Chrome hello carries session_ticket: {types:04x?}"
    );
    assert!(
        types.contains(&APPLICATION_SETTINGS) || types.contains(&APPLICATION_SETTINGS_OLD),
        "{label}: a Chrome hello carries application_settings: {types:04x?}"
    );
    assert!(
        !types.contains(&RECORD_SIZE_LIMIT),
        "{label}: record_size_limit is Firefox's: {types:04x?}"
    );
    assert_eq!(
        types
            .iter()
            .copied()
            .filter(|value| is_grease(*value))
            .count(),
        2,
        "{label}: Chrome brackets its extension list with a GREASE pair: {types:04x?}"
    );
}

/// A share link asking for Firefox produces a Firefox ClientHello.
#[tokio::test]
async fn a_firefox_link_puts_a_firefox_hello_on_the_wire() {
    for (fingerprint, check) in [
        ("firefox", assert_is_firefox as fn(&str, &[u8])),
        ("firefox_148", assert_is_firefox),
        ("chrome", assert_is_chrome),
        ("chrome_133", assert_is_chrome),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let imported = import_link(&link(port, fingerprint)).expect("link must import");
        let engine = format!(
            r#"{{"schema_version":1,"outbound":{},"tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}}}"#,
            serde_json::to_string(&imported.outbound).expect("serialise")
        );
        EngineConfig::parse(&engine).expect("imported profile must validate");

        let hello = client_hello_from(imported.outbound, listener).await;
        check(&format!("fp={fingerprint}"), &hello);
    }
}

/// The other half of the app's chain: the engine config the Android translator
/// writes reaches the wire as the profile it names.
#[tokio::test]
async fn the_engine_config_the_app_writes_reaches_the_wire_as_that_profile() {
    for (fingerprint, check) in [
        ("firefox_148", assert_is_firefox as fn(&str, &[u8])),
        ("chrome_133", assert_is_chrome),
        ("chrome_131", assert_is_chrome),
        ("qq_11_1", assert_is_chrome),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let config = EngineConfig::parse(&app_engine_config(port, fingerprint))
            .expect("the app's engine config must validate");

        let hello = client_hello_from(config.outbound, listener).await;
        check(&format!("reality.fingerprint={fingerprint}"), &hello);
    }
}

/// A name the core does not implement is refused by the config, not rounded to
/// the nearest table.
///
/// `randomized` is deliberately absent from this list: it names a uTLS
/// *generator*, and whether this build has one is a separate question from
/// whether a name is honoured. `360` and `android` are here permanently — they
/// are TLS 1.2 parrots with no `key_share` extension, so REALITY cannot derive
/// its authentication key from them at all.
#[tokio::test]
async fn an_unimplemented_profile_name_is_refused_by_the_config() {
    for fingerprint in ["chrome_999", "360", "android", "hellogolang"] {
        assert!(
            EngineConfig::parse(&app_engine_config(443, fingerprint)).is_err(),
            "reality.fingerprint={fingerprint} must not parse"
        );
    }
}
