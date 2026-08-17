//! Live interoperability against a real VLESS Encryption server.
//!
//! Ignored by default: it needs a server, which CI does not have. It exists
//! because it covers the one thing the recorded vectors deliberately cannot —
//! the vectors supply the KEM results, so they prove nothing about whether
//! `aws-lc-rs` and the reference implementation's `crypto/mlkem` and
//! `crypto/ecdh` agree, nor about the real randomness path.
//!
//! Run it against an Xray server, or against the upstream `encryption` package
//! wrapped in a TCP echo server:
//!
//! ```text
//! FOXCORE_VLESS_ENCRYPTION_SERVER=127.0.0.1:9000 \
//! FOXCORE_VLESS_ENCRYPTION_SPEC='mlkem768x25519plus.random.0rtt.<base64 key>' \
//!   cargo test -p proto-vless --test encryption_interop -- --ignored --nocapture
//! ```
//!
//! The peer must echo whatever it is sent inside the encrypted stream.

use foxcore_transport::BoxStream;
use proto_vless::encryption::{ClientInstance, LiveCrypto, parse_encryption};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
#[ignore = "needs a live VLESS Encryption echo server; see the module comment"]
async fn interoperates_with_a_live_server() {
    let address = std::env::var("FOXCORE_VLESS_ENCRYPTION_SERVER")
        .expect("set FOXCORE_VLESS_ENCRYPTION_SERVER=host:port");
    let spec = std::env::var("FOXCORE_VLESS_ENCRYPTION_SPEC")
        .expect("set FOXCORE_VLESS_ENCRYPTION_SPEC to the client's encryption= value");

    let params = parse_encryption(&spec).expect("spec parses");
    let zero_rtt = params.zero_rtt;
    let client = ClientInstance::new(params);

    // Twice on one instance: the second connection is 0-RTT when the server
    // issued a ticket, which is the path that cannot be exercised at all
    // without a peer that keeps session state.
    for attempt in 1..=2 {
        let tcp = TcpStream::connect(&address)
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: connect failed: {error}"));
        let mut stream = client
            .handshake(Box::new(tcp) as BoxStream, &mut LiveCrypto)
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: handshake failed: {error}"));

        // Long enough to cross the 8192-byte record boundary, so the framing
        // loop and not just the handshake is exercised.
        let payload: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        stream
            .write_all(&payload)
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: write failed: {error}"));
        stream.flush().await.unwrap();

        let mut echoed = vec![0_u8; payload.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: read failed: {error}"));
        assert_eq!(echoed, payload, "attempt {attempt}: echo mismatch");
        println!("attempt {attempt}: {} bytes round-tripped", payload.len());
    }
    if zero_rtt {
        println!("0-RTT requested; the second connection reused the server's ticket");
    }
}
