use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use foxcore_api::{CurveGroup, EchConfig, TlsConfig, TlsVersion};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchGreaseConfig, EchMode, EchStatus};
use rustls::crypto::hpke::{Hpke, HpkePublicKey};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::BoxStream;
use crate::splice::{InnerCodec, RecordLayer};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Plaintext buffered between the relay task and the application end.
const SPLICED_BUFFER_CAPACITY: usize = 64 * 1024;

pub async fn wrap_tls<S>(
    stream: S,
    tls: &TlsConfig,
    default_server_name: &str,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    wrap_tls_with_alpn(stream, tls, default_server_name, None).await
}

/// Like [`wrap_tls`], but `alpn_override` (when `Some`) replaces the configured
/// ALPN list — used to force `h2` under gRPC/HTTP2 stream transports.
pub(crate) async fn wrap_tls_with_alpn<S>(
    stream: S,
    tls: &TlsConfig,
    default_server_name: &str,
    alpn_override: Option<&[&str]>,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if !tls.enabled {
        return Ok(Box::new(stream));
    }

    let config = rustls_client_config_alpn(tls, alpn_override)?;

    let server_name = tls
        .server_name
        .as_deref()
        .unwrap_or(default_server_name)
        .to_owned();
    let server_name = ServerName::try_from(server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let stream = tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    enforce_ech(tls, stream.get_ref().1)?;
    Ok(Box::new(stream))
}

/// Like [`wrap_tls`], but the connection is driven by the splicing relay so an
/// inner codec can take the socket over mid-stream.
///
/// TLS 1.3 is required, and refused rather than downgraded: the handover only
/// makes sense when the outer records the peer stops sending are 1.3 records —
/// under 1.2 the inner stream would be exposed on a different record shape than
/// the one the observer has been watching.
pub async fn wrap_tls_spliced<S, C>(
    stream: S,
    tls: &TlsConfig,
    default_server_name: &str,
    codec: C,
) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: InnerCodec,
{
    if !tls.enabled {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a spliced stream requires TLS",
        ));
    }
    let config = rustls_client_config_alpn(tls, None)?;
    let server_name = tls
        .server_name
        .as_deref()
        .unwrap_or(default_server_name)
        .to_owned();
    let server_name = ServerName::try_from(server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let stream = tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

    enforce_ech(tls, stream.get_ref().1)?;
    let (socket, connection) = stream.into_inner();
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a spliced stream requires an outer TLS 1.3 handshake",
        ));
    }
    Ok(Box::new(crate::splice::spawn_relay(
        socket,
        RustlsRecordLayer(connection),
        codec,
        SPLICED_BUFFER_CAPACITY,
    )))
}

/// [`RecordLayer`] over a completed `rustls` client handshake.
struct RustlsRecordLayer(rustls::ClientConnection);

impl RecordLayer for RustlsRecordLayer {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.0.read_tls(rd)
    }

    fn process_new_packets(&mut self) -> io::Result<()> {
        self.0
            .process_new_packets()
            .map(|_| ())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        use std::io::BufRead as _;
        let mut reader = self.0.reader();
        loop {
            match reader.fill_buf() {
                Ok([]) => return Ok(true),
                Ok(available) => {
                    let count = available.len();
                    out.extend_from_slice(available);
                    reader.consume(count);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            }
        }
    }

    fn write_plaintext(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        self.0.writer().write_all(data)
    }

    fn write_tls(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        while self.0.wants_write() {
            let before = out.len();
            self.0.write_tls(out)?;
            if out.len() == before {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TLS record writer made no progress",
                ));
            }
        }
        Ok(())
    }

    fn send_close_notify(&mut self) {
        self.0.send_close_notify();
    }
}

pub fn rustls_client_config(tls: &TlsConfig) -> io::Result<Arc<ClientConfig>> {
    rustls_client_config_alpn(tls, None)
}

pub(crate) fn rustls_client_config_alpn(
    tls: &TlsConfig,
    alpn_override: Option<&[&str]>,
) -> io::Result<Arc<ClientConfig>> {
    let alpn_key: Option<Vec<String>> =
        alpn_override.map(|list| list.iter().map(|value| (*value).to_owned()).collect());
    if let Some(cached) = cached_client_config(tls, alpn_key.as_deref()) {
        return Ok(cached);
    }
    let config = build_client_config(tls, alpn_override)?;
    store_client_config(tls, alpn_key, &config);
    Ok(config)
}

/// One built config per distinct profile, rather than one per dial.
///
/// Two reasons, and the second is the one a user feels. Building a config
/// clones the whole webpki root store — roughly 150 trust anchors, several
/// allocations each — and rebuilds the verifier, and that ran on every single
/// connection.
///
/// And rustls keeps its TLS session cache *inside* `ClientConfig`. A fresh
/// config per dial therefore meant resumption could never happen: every
/// connection paid a full handshake and the extra round trip with it. On a
/// mobile link that is the difference between a page that opens and a page that
/// hesitates.
///
/// Keyed by the whole `TlsConfig` plus the ALPN override, so an insecure
/// profile, a pinned profile and an ECH profile never share one — `TlsConfig`
/// is only `PartialEq`, not `Hash`, and a handful of profiles is few enough
/// that a linear scan is cheaper than teaching it to hash.
struct CachedClientConfig {
    tls: TlsConfig,
    alpn: Option<Vec<String>>,
    config: Arc<ClientConfig>,
}

/// Small on purpose: a device runs a handful of profiles, and an unbounded
/// cache keyed by config would be a slow leak on a subscription that rotates.
const MAX_CACHED_CLIENT_CONFIGS: usize = 8;

static CLIENT_CONFIG_CACHE: OnceLock<std::sync::Mutex<Vec<CachedClientConfig>>> = OnceLock::new();

fn client_config_cache() -> &'static std::sync::Mutex<Vec<CachedClientConfig>> {
    CLIENT_CONFIG_CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn cached_client_config(tls: &TlsConfig, alpn: Option<&[String]>) -> Option<Arc<ClientConfig>> {
    let cache = client_config_cache().lock().ok()?;
    cache
        .iter()
        .find(|entry| entry.tls == *tls && entry.alpn.as_deref() == alpn)
        .map(|entry| Arc::clone(&entry.config))
}

fn store_client_config(tls: &TlsConfig, alpn: Option<Vec<String>>, config: &Arc<ClientConfig>) {
    let Ok(mut cache) = client_config_cache().lock() else {
        return;
    };
    if cache
        .iter()
        .any(|entry| entry.tls == *tls && entry.alpn == alpn)
    {
        return;
    }
    if cache.len() >= MAX_CACHED_CLIENT_CONFIGS {
        cache.remove(0);
    }
    cache.push(CachedClientConfig {
        tls: tls.clone(),
        alpn,
        config: Arc::clone(config),
    });
}

/// The webpki root store, cloned once for the process rather than per config.
fn webpki_roots_store() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    Arc::clone(ROOTS.get_or_init(|| {
        Arc::new(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }))
}

fn build_client_config(
    tls: &TlsConfig,
    alpn_override: Option<&[&str]>,
) -> io::Result<Arc<ClientConfig>> {
    let roots = webpki_roots_store();
    let provider = crypto_provider(tls)?;
    // `builder_with_provider`, not `builder`. `builder` asks rustls for the
    // *process* default provider, and rustls can only derive one when exactly
    // one of its `ring` / `aws-lc-rs` features is on. The moment ECH put the
    // second one in the build, that call became a panic on every TLS dial —
    // `Could not automatically determine the process-level CryptoProvider` —
    // in a library whose whole job is TLS dials. Naming the provider is not a
    // workaround for that; it is what the code should always have done, since
    // the provider the verifier uses and the provider the handshake uses were
    // never meant to be two decisions.
    let base = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|error| io::Error::other(format!("TLS verifier: {error}")))?;
    let expected_pin = tls
        .pinned_spki_sha256
        .as_deref()
        .map(decode_pin)
        .transpose()?;
    let verifier = ConfiguredVerifier {
        base,
        insecure: tls.insecure,
        expected_pin,
    };

    let versions = protocol_versions(tls);
    let builder = ClientConfig::builder_with_provider(provider);
    // `with_ech` selects TLS 1.3 on its own — ECH exists nowhere else — so the
    // two arms are alternatives rather than steps. `TlsConfig::validate`
    // refuses a profile that pinned `max_version` to 1.2 and also asked for
    // ECH, so nothing silently loses that argument here.
    let builder = match &tls.ech {
        Some(ech) => builder
            .with_ech(ech_mode(ech)?)
            .map_err(|error| io::Error::other(format!("TLS ECH: {error}")))?,
        None => builder
            .with_protocol_versions(&versions)
            .map_err(|error| io::Error::other(format!("TLS protocol versions: {error}")))?,
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = match alpn_override {
        Some(protocols) => protocols.iter().map(|p| p.as_bytes().to_vec()).collect(),
        None if tls.alpn.is_empty() => DEFAULT_ALPN
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
        None => tls
            .alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
    };

    Ok(Arc::new(config))
}

/// Translate the profile's ECH block into the mode rustls takes.
///
/// The HPKE suites come from the `aws-lc-rs` provider because that is the only
/// place rustls implements HPKE. Since [`crypto_provider`] moved to the same
/// provider, that is no longer a split: one provider serves the handshake, the
/// verifier and ECH. What ECH costs this core is measured rather than assumed.
fn ech_mode(ech: &EchConfig) -> io::Result<EchMode> {
    use rustls::crypto::aws_lc_rs::hpke::{
        ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128,
    };

    match ech {
        EchConfig::Required { config_list } => {
            let bytes = STANDARD
                .decode(config_list)
                .or_else(|_| URL_SAFE_NO_PAD.decode(config_list))
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid ECH config list base64: {error}"),
                    )
                })?;
            // A list that does not parse, or that names no suite this build
            // has, fails the outbound. It must not fall through to an ordinary
            // handshake: the profile asked for ECH precisely so the SNI would
            // not be readable, and a quiet downgrade sends it readable.
            let config = rustls::client::EchConfig::new(
                EchConfigListBytes::from(bytes),
                ALL_SUPPORTED_SUITES,
            )
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unusable ECH config list: {error}"),
                )
            })?;
            Ok(EchMode::Enable(config))
        }
        EchConfig::GreasePlaintextSni => {
            let suite: &'static dyn Hpke = DH_KEM_X25519_HKDF_SHA256_AES_128;
            Ok(EchMode::Grease(EchGreaseConfig::new(
                suite,
                grease_placeholder_key(suite)?.clone(),
            )))
        }
    }
}

/// The fake recipient key the GREASE extension is "encrypted" to.
///
/// Generated once and reused. It is a public key nobody holds the private half
/// of, and rustls draws a fresh ephemeral for every handshake regardless, so a
/// new one per dial would buy nothing and cost a key generation on the dial
/// path.
///
/// X25519 with AES-128-GCM on purpose: that is the suite the browsers sending
/// real ECH use, and therefore the one whose 32-byte `enc` field does not make
/// our GREASE stand out from theirs — which is the only thing GREASE is for.
fn grease_placeholder_key(suite: &'static dyn Hpke) -> io::Result<&'static HpkePublicKey> {
    static KEY: OnceLock<Result<HpkePublicKey, String>> = OnceLock::new();
    KEY.get_or_init(|| {
        suite
            .generate_key_pair()
            .map(|(public, _private)| public)
            .map_err(|error| error.to_string())
    })
    .as_ref()
    .map_err(|error| io::Error::other(format!("ECH GREASE key: {error}")))
}

/// Refuse a finished handshake that did not end with ECH accepted.
///
/// rustls already sends a fatal `ech_required` alert and errors when a *server*
/// rejects an offer, so against a live peer this arm does not fire — the error
/// that surfaces is rustls' `ServerRejectedEncryptedClientHello`.
///
/// It still catches the other way of losing ECH, and that one was reproduced
/// rather than imagined: point the config builder somewhere that drops the
/// mode while the profile still says `required`, and the handshake succeeds
/// with `NotOffered` and the real SNI on the wire. Nothing else in this crate
/// notices. That is the shape a refactor produces, which is why the check is
/// on the profile's demand and not on the connection's belief.
fn enforce_ech(tls: &TlsConfig, connection: &rustls::ClientConnection) -> io::Result<()> {
    let Some(EchConfig::Required { .. }) = &tls.ech else {
        return Ok(());
    };
    match connection.ech_status() {
        EchStatus::Accepted => Ok(()),
        status => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the server did not accept Encrypted Client Hello ({status:?})"),
        )),
    }
}

/// The versions the handshake may negotiate, narrowed by the profile.
///
/// Absent bounds mean the core's own range rather than rustls' — a profile that
/// says nothing must not silently get a different range when the library's
/// default changes.
fn protocol_versions(tls: &TlsConfig) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let min = tls.min_version.unwrap_or(TlsVersion::Tls12);
    let max = tls.max_version.unwrap_or(TlsVersion::Tls13);
    [
        (TlsVersion::Tls12, &rustls::version::TLS12),
        (TlsVersion::Tls13, &rustls::version::TLS13),
    ]
    .into_iter()
    .filter(|(version, _)| *version >= min && *version <= max)
    .map(|(_, supported)| supported)
    .collect()
}

/// Build the crypto provider, reordering key-exchange groups when the profile
/// pins them.
///
/// A pinned group the provider does not have is an error, not a silent drop:
/// the setting exists to shape the ClientHello, and a ClientHello missing a
/// group the profile named is a different fingerprint than the one requested.
///
/// # Why `aws_lc_rs` and not `ring`
///
/// The `aws-lc-rs` feature was already in this crate's dependency list — it is
/// where rustls implements HPKE, and therefore ECH — while the handshake itself
/// still ran on `ring`. Two providers were linked and only the weaker one was
/// used for the part that shows on the wire. `ring` has no ML-KEM, so every
/// rustls ClientHello this core sent offered `x25519` where a current browser
/// offers `X25519MLKEM768` first: a 1216-byte key share missing from a hello
/// that is otherwise trying not to stand out. `aws_lc_rs` has the hybrid group
/// and puts it in the default order, so the whole rustls path gains it here
/// rather than one outbound at a time.
fn crypto_provider(tls: &TlsConfig) -> io::Result<Arc<rustls::crypto::CryptoProvider>> {
    let base = rustls::crypto::aws_lc_rs::default_provider();

    let mut wanted: Vec<CurveGroup> = tls.curve_preferences.clone();
    if wanted.is_empty() {
        wanted = vec![
            CurveGroup::X25519MlKem768,
            CurveGroup::X25519,
            CurveGroup::Secp256r1,
            CurveGroup::Secp384r1,
        ];
    } else if !wanted.contains(&CurveGroup::X25519MlKem768)
        && !tls.allow_classical_only_key_exchange
    {
        wanted.insert(0, CurveGroup::X25519MlKem768);
    }

    let mut kx_groups = Vec::with_capacity(wanted.len());
    for curve in &wanted {
        let named = match curve {
            CurveGroup::X25519 => rustls::NamedGroup::X25519,
            CurveGroup::Secp256r1 => rustls::NamedGroup::secp256r1,
            CurveGroup::Secp384r1 => rustls::NamedGroup::secp384r1,
            CurveGroup::X25519MlKem768 => rustls::NamedGroup::X25519MLKEM768,
        };
        let group = base
            .kx_groups
            .iter()
            .find(|group| group.name() == named)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("TLS curve {curve:?} is not available in this build"),
                )
            })?;
        kx_groups.push(*group);
    }
    Ok(Arc::new(rustls::crypto::CryptoProvider {
        kx_groups,
        ..base
    }))
}

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

fn decode_pin(encoded: &str) -> io::Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid SPKI pin base64: {error}"),
            )
        })?;
    bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SPKI SHA-256 pin must decode to 32 bytes",
        )
    })
}

struct ConfiguredVerifier {
    base: Arc<WebPkiServerVerifier>,
    insecure: bool,
    expected_pin: Option<[u8; 32]>,
}

impl fmt::Debug for ConfiguredVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfiguredVerifier")
            .field("insecure", &self.insecure)
            .field("has_pin", &self.expected_pin.is_some())
            .finish()
    }
}

impl ServerCertVerifier for ConfiguredVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = self.expected_pin {
            let (_, certificate) = X509Certificate::from_der(end_entity.as_ref())
                .map_err(|_| rustls::Error::General("invalid X.509 certificate".into()))?;
            let actual: [u8; 32] =
                Sha256::digest(certificate.tbs_certificate.subject_pki.raw).into();
            if actual == expected {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(rustls::Error::General(
                "server certificate SPKI pin mismatch".into(),
            ));
        }
        if self.insecure {
            return Ok(ServerCertVerified::assertion());
        }
        self.base
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_profile_gets_one_config_so_resumption_has_somewhere_to_live() {
        // rustls keeps its session cache inside ClientConfig. A config built
        // per dial means every connection is a full handshake and an extra
        // round trip that nothing ever saves. Pointer identity is the property
        // that matters, not equality: resumption only works if the *same*
        // config object comes back.
        let profile = tls(|config| config.server_name = Some("example.invalid".to_owned()));
        let first = rustls_client_config(&profile).expect("first config");
        let second = rustls_client_config(&profile).expect("second config");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn profiles_that_verify_differently_never_share_a_config() {
        // The cache key is the whole TlsConfig. If it were anything narrower,
        // an insecure or differently pinned profile could be served a verifier
        // that was built for another one — a cache that silently downgrades
        // certificate checking is worse than no cache.
        let strict = tls(|config| config.server_name = Some("strict.invalid".to_owned()));
        let insecure = tls(|config| {
            config.server_name = Some("strict.invalid".to_owned());
            config.insecure = true;
        });
        let pinned = tls(|config| {
            config.server_name = Some("strict.invalid".to_owned());
            config.pinned_spki_sha256 = Some(STANDARD.encode([3_u8; 32]));
        });

        let strict_config = rustls_client_config(&strict).expect("strict");
        let insecure_config = rustls_client_config(&insecure).expect("insecure");
        let pinned_config = rustls_client_config(&pinned).expect("pinned");

        assert!(!Arc::ptr_eq(&strict_config, &insecure_config));
        assert!(!Arc::ptr_eq(&strict_config, &pinned_config));
        assert!(!Arc::ptr_eq(&insecure_config, &pinned_config));
    }

    #[test]
    fn an_alpn_override_is_part_of_the_key() {
        let profile = tls(|config| config.server_name = Some("alpn.invalid".to_owned()));
        let plain = rustls_client_config(&profile).expect("plain");
        let overridden = rustls_client_config_alpn(&profile, Some(&["h2"])).expect("overridden");
        assert!(!Arc::ptr_eq(&plain, &overridden));
        assert_eq!(overridden.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn the_cache_stays_bounded_when_profiles_rotate() {
        // A subscription that rotates server names must not turn the cache into
        // a slow leak.
        for index in 0..(MAX_CACHED_CLIENT_CONFIGS * 3) {
            let profile =
                tls(|config| config.server_name = Some(format!("rotate-{index}.invalid")));
            rustls_client_config(&profile).expect("config");
        }
        let cached = client_config_cache().lock().expect("cache").len();
        assert!(
            cached <= MAX_CACHED_CLIENT_CONFIGS,
            "cache grew to {cached}"
        );
    }

    #[test]
    fn pin_must_be_sha256_length() {
        assert!(decode_pin("aW52YWxpZA==").is_err());
        let valid = STANDARD.encode([7_u8; 32]);
        assert_eq!(decode_pin(&valid).unwrap(), [7_u8; 32]);
    }

    fn tls(configure: impl FnOnce(&mut TlsConfig)) -> TlsConfig {
        let mut config = TlsConfig {
            enabled: true,
            ..TlsConfig::default()
        };
        configure(&mut config);
        config
    }

    #[test]
    fn a_pinned_version_narrows_the_handshake_in_both_directions() {
        let names = |config: &TlsConfig| {
            protocol_versions(config)
                .into_iter()
                .map(|version| version.version)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            names(&tls(|_| {})),
            vec![
                rustls::ProtocolVersion::TLSv1_2,
                rustls::ProtocolVersion::TLSv1_3
            ],
            "a profile that says nothing gets the core's own range"
        );
        assert_eq!(
            names(&tls(|config| config.min_version = Some(TlsVersion::Tls13))),
            vec![rustls::ProtocolVersion::TLSv1_3]
        );
        assert_eq!(
            names(&tls(|config| config.max_version = Some(TlsVersion::Tls12))),
            vec![rustls::ProtocolVersion::TLSv1_2],
            "a profile pinned to 1.2 must not be handed a 1.3 handshake"
        );
    }

    #[test]
    fn pinned_curves_reach_the_client_hello_in_the_order_asked_for() {
        // Wire order is pinned; the hybrid group is prepended unless explicitly
        // disabled by policy.
        let config = tls(|config| {
            config.curve_preferences = vec![CurveGroup::Secp256r1, CurveGroup::X25519];
        });
        let provider = crypto_provider(&config).unwrap();
        assert_eq!(
            provider
                .kx_groups
                .iter()
                .map(|group| group.name())
                .collect::<Vec<_>>(),
            vec![
                rustls::NamedGroup::X25519MLKEM768,
                rustls::NamedGroup::secp256r1,
                rustls::NamedGroup::X25519
            ]
        );

        let untouched = crypto_provider(&tls(|_| {})).unwrap();
        assert!(
            untouched.kx_groups.len() > 1,
            "an empty list must leave the provider's own order alone"
        );
    }

    /// The reason the provider moved off `ring`.
    ///
    /// A ClientHello with no post-quantum key share is, by now, the odd one
    /// out: Chrome, Firefox and the large CDNs all offer X25519MLKEM768.
    /// `ring` cannot produce one at all, so this is not a preference — it is
    /// whether the group exists in the build.
    ///
    /// Where rustls puts it in the list is rustls' decision, not this core's:
    /// `crypto_provider` leaves the provider's own order alone unless a profile
    /// pins curves, and `CurveGroup` has no name for the hybrid to pin it with.
    /// A browser puts it first; rustls currently puts it last. The shape of a
    /// rustls hello belongs to rustls, and
    /// closing it is what `proto-reality`'s own hello is for.
    #[test]
    fn the_default_provider_offers_the_hybrid_post_quantum_group() {
        let provider = crypto_provider(&tls(|_| {})).unwrap();
        let names: Vec<rustls::NamedGroup> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert!(
            names.contains(&rustls::NamedGroup::X25519MLKEM768),
            "no X25519MLKEM768 in {names:?}; the ring provider has none"
        );
    }

    /// One draft-18 config: X25519 / HKDF-SHA256 / AES-128-GCM.
    const ECH_CONFIG_LIST: &str = "AEH+DQA9AQAgACAgISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA==";
    /// The same list with the KEM id changed to 0x0099, which no HPKE provider
    /// implements.
    const ECH_CONFIG_LIST_UNKNOWN_KEM: &str = "AEH+DQA9AQCZACAgISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA==";

    #[test]
    fn a_config_list_this_build_cannot_use_fails_the_outbound() {
        assert!(matches!(
            ech_mode(&EchConfig::Required {
                config_list: ECH_CONFIG_LIST.to_owned()
            }),
            Ok(EchMode::Enable(_))
        ));
        assert!(matches!(
            ech_mode(&EchConfig::GreasePlaintextSni),
            Ok(EchMode::Grease(_))
        ));

        // Each of these used to have an obvious "just carry on without ECH"
        // answer, and each of them would send the SNI the profile is hiding.
        for broken in [
            "not base64 at all !!",
            "AAAA",                      // parses as base64, not as a list
            ECH_CONFIG_LIST_UNKNOWN_KEM, // a list with no suite we have
        ] {
            let error = ech_mode(&EchConfig::Required {
                config_list: broken.to_owned(),
            })
            .expect_err("an unusable ECH config must fail the outbound");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "{broken}: {error}"
            );
        }
    }

    #[test]
    fn only_an_accepted_ech_offer_is_a_finished_handshake() {
        // Driven through a real `ClientConnection` rather than a table of
        // statuses, so that neutering `enforce_ech` fails this test instead of
        // leaving a tautology behind. A connection that has not handshaken has
        // status `Offered` at most, never `Accepted` — which is the shape of
        // every outcome the rule has to refuse.
        let connection = |tls: &TlsConfig| {
            rustls::ClientConnection::new(
                rustls_client_config(tls).unwrap(),
                ServerName::try_from("hidden.example").unwrap(),
            )
            .unwrap()
        };

        let required = tls(|config| {
            config.ech = Some(EchConfig::Required {
                config_list: ECH_CONFIG_LIST.to_owned(),
            })
        });
        let live = connection(&required);
        assert_ne!(live.ech_status(), EchStatus::Accepted);
        let error = enforce_ech(&required, &live)
            .expect_err("an offer that was never accepted is not a finished handshake");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        // The other two modes have nothing to enforce: GREASE promises no
        // encryption, and a profile without `ech` never asked.
        let grease = tls(|config| config.ech = Some(EchConfig::GreasePlaintextSni));
        assert_eq!(connection(&grease).ech_status(), EchStatus::Grease);
        enforce_ech(&grease, &connection(&grease)).unwrap();
        let plain = tls(|_| {});
        enforce_ech(&plain, &connection(&plain)).unwrap();
    }

    #[test]
    fn ech_takes_the_version_range_out_of_the_profile_s_hands() {
        // rustls' `with_ech` replaces the negotiated range with TLS 1.3 alone
        // and does not consult `protocol_versions` at all — which is why a
        // profile that pins `max_version = 1.2` *and* asks for ECH is refused
        // in foxcore-api rather than quietly given a 1.3 handshake here. The
        // config builds, and that is the point: nothing in this crate would
        // have stopped it.
        assert!(
            rustls_client_config(&tls(|config| {
                config.min_version = Some(TlsVersion::Tls12);
                config.max_version = Some(TlsVersion::Tls12);
                config.ech = Some(EchConfig::GreasePlaintextSni);
            }))
            .is_ok()
        );
    }

    #[test]
    fn alpn_override_forces_h2_over_config() {
        let tls = TlsConfig::default();
        let forced = rustls_client_config_alpn(&tls, Some(&["h2"])).unwrap();
        assert_eq!(forced.alpn_protocols, vec![b"h2".to_vec()]);
        let normal = rustls_client_config_alpn(&tls, None).unwrap();
        assert_eq!(
            normal.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
