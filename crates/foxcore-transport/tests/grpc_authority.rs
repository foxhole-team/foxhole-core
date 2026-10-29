use std::time::Duration;

use base64::Engine as _;
use foxcore_api::{EngineConfig, OutboundConfig, StreamTransportConfig, TlsConfig};
use foxcore_transport::{establish_stream, wrap_stream_transport};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

// No new enum fields: this fixture compiles against the original baseline and
// observes the actual TLS ClientHello and decrypted HTTP/2 request separately.
fn transport(authority: Option<&str>) -> StreamTransportConfig {
    let authority = authority
        .map(|value| format!(",\"authority\":\"{value}\""))
        .unwrap_or_default();
    let config = format!(
        r#"{{"schema_version":1,"outbound":{{"type":"vless","server":"origin.example","port":443,"uuid":"d0cf0001-0000-4000-8000-000000000000","transport":{{"type":"grpc","service_name":"fox"{authority}}}}},"tun":{{"mtu":1400,"ipv4":"10.0.0.1"}}}}"#
    );
    let OutboundConfig::Vless(outbound) = EngineConfig::parse(&config).unwrap().outbound else {
        unreachable!()
    };
    outbound.transport
}

async fn observe_tls_authority(authority: Option<&str>) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        foxcore_transport::ensure_process_crypto_provider().unwrap();
        let generated = rcgen::generate_simple_self_signed(vec!["tls.example".into()]).unwrap();
        let certificate = generated.cert.der().clone();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server = tokio::spawn(async move {
            let secured = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config))
                .accept(server_io)
                .await
                .unwrap();
            assert_eq!(
                secured.get_ref().1.server_name(),
                Some("tls.example"),
                "authority must not replace TLS SNI"
            );
            assert_eq!(
                secured.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice()),
                "gRPC must override an HTTP/1-only profile ALPN"
            );
            let mut connection = h2::server::handshake(secured).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().scheme_str(), Some("https"));
            let authority = request.uri().authority().unwrap().as_str().to_owned();
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .header("grpc-status", "0")
                .body(())
                .unwrap();
            let _send = respond.send_response(response, true).unwrap();
            while connection.accept().await.is_some() {}
            drop(request);
            authority
        });
        let tls = TlsConfig {
            enabled: true,
            server_name: Some("tls.example".into()),
            insecure: false,
            pinned_certificate_sha256: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(Sha256::digest(certificate.as_ref())),
            ),
            alpn: vec!["http/1.1".into()],
            ..TlsConfig::default()
        };
        let mut stream = establish_stream(
            client_io,
            &tls,
            &transport(authority),
            "origin.example",
            8443,
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert!(reply.is_empty());
        drop(stream);
        server.await.unwrap()
    })
    .await
    .expect("TLS authority fixture did not settle")
}

#[tokio::test]
async fn grpc_authority_defaults_to_tls_name_without_replacing_alpn_or_sni() {
    assert_eq!(observe_tls_authority(None).await, "tls.example");
}

#[tokio::test]
async fn grpc_explicit_authority_preserves_the_distinct_verified_tls_name() {
    assert_eq!(
        observe_tls_authority(Some("front.example:7443")).await,
        "front.example:7443"
    );
}

#[tokio::test]
async fn grpc_plaintext_ip_authority_includes_port_and_ipv6_brackets() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (server_name, expected) in [
            ("192.0.2.1", "192.0.2.1:8443"),
            ("2001:db8::1", "[2001:db8::1]:8443"),
            ("origin.example", "origin.example"),
        ] {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let expected = expected.to_owned();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.uri().scheme_str(), Some("http"));
                assert_eq!(request.uri().authority().unwrap().as_str(), expected);
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "0")
                    .body(())
                    .unwrap();
                let _send = respond.send_response(response, true).unwrap();
                while connection.accept().await.is_some() {}
                drop(request);
            });
            let mut stream =
                wrap_stream_transport(client_io, &transport(None), server_name, 8443, false)
                    .await
                    .unwrap();
            stream.read_to_end(&mut Vec::new()).await.unwrap();
            drop(stream);
            server.await.unwrap();
        }
    })
    .await
    .expect("IP authority fixture did not settle")
}

#[tokio::test]
async fn grpc_long_valid_dns_authority_and_port_reach_h2_with_tls_name_unchanged() {
    let domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(domain.len(), 253);
    let expected = format!("{domain}:65535");
    assert_eq!(observe_tls_authority(Some(&expected)).await, expected);
}
