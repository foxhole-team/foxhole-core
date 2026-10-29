use super::*;
use foxcore_api::TlsFingerprint;
use rustls::compress::{CertCompressor, CompressionFailed, CompressionLevel};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{ClientConnection, HandshakeKind, ServerConfig, ServerConnection};
use std::io::{Cursor, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

fn profile() -> TlsConfig {
    TlsConfig {
        enabled: true,
        server_name: Some("owned.example".into()),
        fingerprint: Some(TlsFingerprint::Chrome151),
        alpn: vec!["http/1.1".into()],
        ..TlsConfig::default()
    }
}

fn first_flight(tls: &TlsConfig) -> Vec<u8> {
    let config = rustls_client_config(tls).unwrap();
    let mut client =
        ClientConnection::new(config, ServerName::try_from("owned.example").unwrap()).unwrap();
    let mut output = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut output).unwrap();
    }
    output
}

fn hello_extensions(wire: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let body = &wire[5..];
    let mut at = 39 + usize::from(body[38]);
    let size = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    at += 2 + size;
    at += 1 + usize::from(body[at]);
    at += 2;
    let mut result = Vec::new();
    while at < body.len() {
        let id = u16::from_be_bytes([body[at], body[at + 1]]);
        let size = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
        result.push((id, body[at + 4..at + 4 + size].to_vec()));
        at += 4 + size;
    }
    result
}

#[test]
fn chrome_wire_matches_the_independent_captured_vector_with_explicit_h1_alpn() {
    let wire = first_flight(&profile());
    let hello = crate::ja::parse(&wire[5..]);
    assert_eq!(
        crate::ja::ja4(&hello).0,
        "t13d1516h1_8daaf6152771_806a8c22fdea"
    );
    assert_eq!(hello.alpn, ["http/1.1"]);
    assert_eq!(
        hello
            .ciphers
            .iter()
            .copied()
            .filter(|n| !crate::ja::is_grease(*n))
            .collect::<Vec<_>>(),
        [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ]
    );
    assert_eq!(
        hello.signature_algorithms,
        [
            0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
        ]
    );
    assert!(crate::ja::is_grease(hello.groups[0]));
    assert!(crate::ja::is_grease(hello.ciphers[0]));
    let extensions = hello_extensions(&wire);
    let share = &extensions.iter().find(|(id, _)| *id == 51).unwrap().1;
    assert_eq!(u16::from_be_bytes([share[2], share[3]]), hello.groups[0]);
    assert_eq!(&share[4..7], &[0, 1, 0]);
    assert!(crate::ja::is_grease(extensions.first().unwrap().0));
    assert!(crate::ja::is_grease(extensions.last().unwrap().0));
    assert_ne!(extensions.first().unwrap().0, extensions.last().unwrap().0);
    assert_eq!(
        extensions.iter().find(|(id, _)| *id == 27).unwrap().1,
        [2, 0, 2]
    );
    let ech = &extensions.iter().find(|(id, _)| *id == 0xfe0d).unwrap().1;
    assert_eq!(&ech[..5], &[0, 0, 1, 0, 1]);
    assert_eq!(&ech[6..8], &[0, 32]);
    assert!([186, 218, 250, 282].contains(&ech.len()));
}

#[test]
fn stock_tls_stays_distinct_and_the_chrome_config_has_its_own_cache() {
    let chrome = profile();
    let mut stock = chrome.clone();
    stock.fingerprint = None;
    let a = rustls_client_config(&chrome).unwrap();
    let b = rustls_client_config(&stock).unwrap();
    assert!(!Arc::ptr_eq(&a, &b));
    let hello = crate::ja::parse(&first_flight(&stock)[5..]);
    assert!(!hello.extensions.contains(&27));
    assert!(!hello.extensions.contains(&0x44cd));
    assert!(!hello.extensions.contains(&0xfe0d));
}

#[test]
fn explicit_requirements_are_refused_instead_of_erased() {
    let mut values = Vec::new();
    let mut tls = profile();
    tls.ech = Some(EchConfig::GreasePlaintextSni);
    values.push(tls);
    let mut tls = profile();
    tls.max_version = Some(TlsVersion::Tls12);
    values.push(tls);
    let mut tls = profile();
    tls.curve_preferences = vec![CurveGroup::X25519];
    values.push(tls);
    for tls in values {
        assert!(rustls_client_config(&tls).is_err());
    }
}

fn fixture(
    expired: bool,
    force_hrr: bool,
    compressor: Option<&'static dyn CertCompressor>,
    bad_signature: bool,
) -> (Arc<RootCertStore>, Arc<ServerConfig>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["owned.example".into()]).unwrap();
    if expired {
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if force_hrr {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1];
    }
    let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth();
    let mut server = if bad_signature {
        let real = rustls::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)
            .unwrap();
        builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
            vec![der],
            Arc::new(BadKey(real)),
        ))))
    } else {
        builder.with_single_cert(vec![der], key).unwrap()
    };
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.cert_compressors = compressor.into_iter().collect();
    server.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    (Arc::new(roots), Arc::new(server))
}

fn pump(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<Vec<Vec<u8>>, rustls::Error> {
    let mut hellos = Vec::new();
    for _ in 0..32 {
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        let mut at = 0;
        while at + 5 <= wire.len() {
            let size = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
            if wire[at] == 22 && wire[at + 5] == 1 {
                hellos.push(wire[at..at + 5 + size].to_vec());
            }
            at += 5 + size;
        }
        if !wire.is_empty() {
            server.read_tls(&mut Cursor::new(wire)).unwrap();
            server.process_new_packets()?;
        }
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).unwrap();
        }
        if !wire.is_empty() {
            client.read_tls(&mut Cursor::new(wire)).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(hellos);
        }
    }
    Err(rustls::Error::General(
        "bounded own TLS fixture did not settle".into(),
    ))
}

fn client(roots: Arc<RootCertStore>, name: &'static str) -> ClientConnection {
    let config = build_client_config_with_roots(&profile(), None, roots).unwrap();
    ClientConnection::new(config, ServerName::try_from(name).unwrap()).unwrap()
}

#[test]
fn verified_tls_delivers_application_bytes_and_keeps_http1_alpn() {
    let (roots, config) = fixture(false, false, None, false);
    let mut client = client(roots, "owned.example");
    let mut server = ServerConnection::new(config).unwrap();
    pump(&mut client, &mut server).unwrap();
    assert_eq!(client.alpn_protocol(), Some(b"http/1.1".as_slice()));
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    client
        .writer()
        .write_all(b"owned authenticated application")
        .unwrap();
    pump(&mut client, &mut server).unwrap();
    let mut received = vec![0u8; b"owned authenticated application".len()];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(received.as_slice(), b"owned authenticated application");
}

#[test]
fn wrong_hostname_unknown_root_expiry_and_bad_certificate_verify_fail_closed() {
    for case in 0..4 {
        let (roots, config) = fixture(case == 2, false, None, case == 3);
        let roots = if case == 1 {
            fixture(false, false, None, false).0
        } else {
            roots
        };
        let name = if case == 0 {
            "wrong.example"
        } else {
            "owned.example"
        };
        let mut client = client(roots, name);
        let mut server = ServerConnection::new(config).unwrap();
        assert!(
            pump(&mut client, &mut server).is_err(),
            "negative case {case}"
        );
    }
}

#[test]
fn hello_retry_reuses_grease_and_permutation_and_negotiates_the_real_retry_group() {
    let (roots, config) = fixture(false, true, None, false);
    let mut client = client(roots, "owned.example");
    let mut server = ServerConnection::new(config).unwrap();
    let hellos = pump(&mut client, &mut server).unwrap();
    assert_eq!(hellos.len(), 2);
    let first = hello_extensions(&hellos[0]);
    let second = hello_extensions(&hellos[1]);
    assert_eq!(
        first.iter().map(|(id, _)| id).collect::<Vec<_>>(),
        second.iter().map(|(id, _)| id).collect::<Vec<_>>()
    );
    assert_eq!(
        first.iter().find(|(id, _)| *id == 0xfe0d),
        second.iter().find(|(id, _)| *id == 0xfe0d)
    );
    let shares = &second.iter().find(|(id, _)| *id == 51).unwrap().1;
    assert_eq!(u16::from_be_bytes([shares[7], shares[8]]), 0x0017);
}

#[test]
fn resumption_keeps_the_shaped_transcript_and_psk_binder_last() {
    let (roots, server_config) = fixture(false, false, None, false);
    let config = build_client_config_with_roots(&profile(), None, roots).unwrap();
    for index in 0..2 {
        let mut client = ClientConnection::new(
            config.clone(),
            ServerName::try_from("owned.example").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(server_config.clone()).unwrap();
        let hellos = pump(&mut client, &mut server).unwrap();
        if index == 1 {
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(hello_extensions(&hellos[0]).last().unwrap().0, 41);
        }
    }
}

static COMPRESSED: AtomicUsize = AtomicUsize::new(0);
#[derive(Debug)]
struct LiteralBrotli;
impl CertCompressor for LiteralBrotli {
    fn compress(&self, input: Vec<u8>, _: CompressionLevel) -> Result<Vec<u8>, CompressionFailed> {
        if input.is_empty() || input.len() > 65536 {
            return Err(CompressionFailed);
        }
        // RFC7932: WBITS22, one uncompressed meta-block, then an empty final block.
        let header = 0x80000bu32 | (((input.len() - 1) as u32) << 7);
        let mut output = header.to_le_bytes()[..3].to_vec();
        output.extend(input);
        output.push(3);
        COMPRESSED.fetch_add(1, Ordering::SeqCst);
        Ok(output)
    }
    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Brotli
    }
}
static LITERAL_BROTLI: LiteralBrotli = LiteralBrotli;

#[test]
fn an_actual_brotli_certificate_handshake_is_verified() {
    let before = COMPRESSED.load(Ordering::SeqCst);
    let (roots, config) = fixture(false, false, Some(&LITERAL_BROTLI), false);
    let mut client = client(roots, "owned.example");
    let mut server = ServerConnection::new(config).unwrap();
    pump(&mut client, &mut server).unwrap();
    assert!(COMPRESSED.load(Ordering::SeqCst) > before);
}

#[test]
fn brotli_decompression_refuses_trailing_truncated_and_wrong_size_output() {
    let config = rustls_client_config(&profile()).unwrap();
    let decoder = config.cert_decompressors[0];
    let valid = [0x0b, 0x02, 0x80, b'h', b'e', b'l', b'l', b'o', 3];
    let mut output = [0u8; 5];
    decoder.decompress(&valid, &mut output).unwrap();
    assert_eq!(&output, b"hello");
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert!(decoder.decompress(&trailing, &mut output).is_err());
    assert!(
        decoder
            .decompress(&valid[..valid.len() - 1], &mut output)
            .is_err()
    );
    assert!(decoder.decompress(&valid, &mut [0u8; 4]).is_err());
    assert!(decoder.decompress(&valid, &mut [0u8; 6]).is_err());
}

#[derive(Debug)]
struct BadKey(Arc<dyn SigningKey>);
impl SigningKey for BadKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(BadSigner(signer)) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }
}
#[derive(Debug)]
struct BadSigner(Box<dyn Signer>);
impl Signer for BadSigner {
    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;
        signature[0] ^= 1;
        Ok(signature)
    }
}

#[derive(Debug)]
struct UnadvertisedEd25519(Arc<dyn SigningKey>);
impl SigningKey for UnadvertisedEd25519 {
    fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0.choose_scheme(&[SignatureScheme::ED25519])
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }
}

#[test]
fn a_valid_but_unadvertised_signature_is_refused_only_for_the_opt_in_profile() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["owned.example".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = cert.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let roots = Arc::new(roots);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::try_from(key.serialize_der()).unwrap())
        .unwrap();
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
            vec![der],
            Arc::new(UnadvertisedEd25519(key)),
        ))));
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server = Arc::new(server);
    let mut stock = profile();
    stock.fingerprint = None;
    let stock = build_client_config_with_roots(&stock, None, roots.clone()).unwrap();
    let mut stock =
        ClientConnection::new(stock, ServerName::try_from("owned.example").unwrap()).unwrap();
    let mut peer = ServerConnection::new(server.clone()).unwrap();
    pump(&mut stock, &mut peer).unwrap();
    let mut chrome = client(roots, "owned.example");
    let mut peer = ServerConnection::new(server).unwrap();
    assert!(
        pump(&mut chrome, &mut peer).is_err(),
        "a valid Ed25519 signature is absent from the Chrome151 offer"
    );
}

#[test]
fn chrome_rejects_the_upstream_large_window_brotli_regression() {
    let config = rustls_client_config(&profile()).unwrap();
    config.cert_decompressors[0]
        .decompress(&[0x11, 0xd0], &mut [])
        .unwrap_err();
}
