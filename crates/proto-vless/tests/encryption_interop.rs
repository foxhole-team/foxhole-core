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

    for attempt in 1..=2 {
        let tcp = TcpStream::connect(&address)
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: connect failed: {error}"));
        let mut stream = client
            .handshake(Box::new(tcp) as BoxStream, &mut LiveCrypto)
            .await
            .unwrap_or_else(|error| panic!("attempt {attempt}: handshake failed: {error}"));

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
