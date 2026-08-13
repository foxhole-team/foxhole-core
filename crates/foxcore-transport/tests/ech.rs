//! Encrypted Client Hello, checked on the wire rather than on the API.
//!
//! Every claim ECH makes is a claim about bytes an observer sees, so these
//! tests read the ClientHello off a socket instead of asking rustls what it
//! believes it sent. The two that matter:
//!
//!   * `ech.mode = "required"` must put the ECH config's *public* name in the
//!     SNI and must not leave `tls.server_name` anywhere in the plaintext;
//!   * `ech.mode = "grease_plaintext_sni"` must put a real ECH extension on the
//!     wire *and* the real name in the clear — the field is named after the
//!     second half, and this is what makes that name honest.
//!
//! Plus the fail-closed rule, against a real TLS server that does not speak
//! ECH: the connection is refused, not downgraded.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use foxcore_api::{EchConfig, TlsConfig};
use foxcore_transport::wrap_tls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

/// One draft-18 ECH config: X25519 / HKDF-SHA256 / AES-128-GCM, public name
/// `public.example`. Fixed bytes rather than a generated list, so a change in
/// how rustls parses one shows up here as a failure and not as a new vector.
const ECH_CONFIG_LIST: &str =
    "AEH+DQA9AQAgACAgISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA==";

/// The `encrypted_client_hello` extension type, draft-18: 0xfe0d.
const ECH_EXTENSION_TYPE: [u8; 2] = [0xfe, 0x0d];

const INNER_NAME: &str = "hidden.example";
const PUBLIC_NAME: &str = "public.example";

fn tls(ech: Option<EchConfig>) -> TlsConfig {
    TlsConfig {
        enabled: true,
        server_name: Some(INNER_NAME.to_owned()),
        insecure: true,
        ech,
        ..TlsConfig::default()
    }
}

/// Dial `wrap_tls` at a socket that only listens, and hand back the first
/// flight of bytes the client wrote — the ClientHello record.
async fn client_hello(tls: TlsConfig) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = tokio::spawn(async move {
        let socket = TcpStream::connect(address).await.unwrap();
        // The handshake cannot finish — nothing answers — so the result is
        // deliberately dropped. What is under test is what went out.
        let _ = wrap_tls(socket, &tls, INNER_NAME).await;
    });

    let (mut socket, _) = listener.accept().await.unwrap();
    let mut hello = vec![0_u8; 16 * 1024];
    let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut hello))
        .await
        .expect("client wrote no ClientHello")
        .unwrap();
    hello.truncate(read);
    drop(socket);
    let _ = client.await;
    hello
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn ech_required_sends_the_public_name_and_hides_the_real_one() {
    let hello = client_hello(tls(Some(EchConfig::Required {
        config_list: ECH_CONFIG_LIST.to_owned(),
    })))
    .await;

    assert!(
        contains(&hello, &ECH_EXTENSION_TYPE),
        "an ech=required ClientHello must carry the ECH extension"
    );
    assert!(
        contains(&hello, PUBLIC_NAME.as_bytes()),
        "the outer SNI must be the public name from the ECH config"
    );
    assert!(
        !contains(&hello, INNER_NAME.as_bytes()),
        "the profile's server_name must not appear in the plaintext ClientHello — \
         that is the entire point of ECH"
    );
}

#[tokio::test]
async fn grease_puts_an_ech_extension_on_the_wire_and_the_sni_in_the_clear() {
    let hello = client_hello(tls(Some(EchConfig::GreasePlaintextSni))).await;

    assert!(
        contains(&hello, &ECH_EXTENSION_TYPE),
        "GREASE exists to make a ClientHello without ECH look like one with it"
    );
    assert!(
        contains(&hello, INNER_NAME.as_bytes()),
        "GREASE encrypts nothing; the field is called grease_plaintext_sni \
         because the name really is in the clear"
    );
}

#[tokio::test]
async fn a_profile_without_ech_sends_neither_the_extension_nor_a_cover_name() {
    let hello = client_hello(tls(None)).await;

    assert!(!contains(&hello, &ECH_EXTENSION_TYPE));
    assert!(contains(&hello, INNER_NAME.as_bytes()));
    assert!(!contains(&hello, PUBLIC_NAME.as_bytes()));
}

/// A TLS 1.3 server with a self-signed certificate and no ECH support — which
/// is what every server that has not deployed ECH looks like.
fn server_config() -> Arc<rustls::ServerConfig> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec![PUBLIC_NAME.to_owned()]).unwrap();
    let certificate = params.self_signed(&key_pair).unwrap();
    let chain = vec![CertificateDer::from(certificate.der().to_vec())];
    let key = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap(),
    )
}

async fn dial_local_server(tls: TlsConfig) -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config());
        // Whatever the server makes of the offer is its business; the
        // assertions are all on the client side.
        let _ = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await;
    });
    let socket = TcpStream::connect(address).await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), wrap_tls(socket, &tls, INNER_NAME))
        .await
        .expect("the handshake never settled")
        .map(|_| ());
    server.abort();
    outcome
}

#[tokio::test]
async fn ech_required_refuses_a_server_that_does_not_speak_it() {
    // The certificate is not trusted and `insecure` is on, so the only thing
    // that can refuse this connection is the ECH rule.
    let error = dial_local_server(tls(Some(EchConfig::Required {
        config_list: ECH_CONFIG_LIST.to_owned(),
    })))
    .await
    .expect_err(
        "a server that does not accept ECH must be refused, not fallen back to: \
         falling back is how the SNI this profile is hiding ends up on the wire",
    );
    assert_ne!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "the refusal has to come from the ECH rule, not from the clock: {error}"
    );

    // The same profile without the ECH block is the control: this server and
    // this client complete an ordinary handshake, so the failure above is
    // about ECH and nothing else.
    dial_local_server(tls(None))
        .await
        .expect("a profile without ECH must still connect to the same server");
}

#[tokio::test]
async fn grease_still_completes_an_ordinary_handshake() {
    // GREASE must not cost connectivity — a server that ignores the extension
    // has to finish the handshake exactly as it would without it. Otherwise
    // "blend into the background" would mean "fail against half of it".
    dial_local_server(tls(Some(EchConfig::GreasePlaintextSni)))
        .await
        .expect("a GREASE ECH extension must not break a server that ignores it");
}
