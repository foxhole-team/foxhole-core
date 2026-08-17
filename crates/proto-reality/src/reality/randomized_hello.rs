//! uTLS' `randomized` fingerprint, as a generator rather than a table.
//!
//! Every other profile in this crate is a transcription: a fixed list of code
//! points that reproduces one browser build byte for byte. `randomized` is not
//! that. In uTLS it is `generateRandomizedSpec` in `u_parrots.go`, driven by a
//! 32-byte PRNG seed and a vector of weights (`DefaultWeights` in
//! `u_common.go`), and it draws a *fresh* ClientHello for every connection.
//! Answering `fp=randomized` with a constant table would be claiming a
//! randomized fingerprint while sending a fixed one, which is the one lie this
//! whole mechanism exists to avoid — so until this module existed the name was
//! refused outright.
//!
//! # What uTLS actually draws
//!
//! The draw is bounded, and the bounds are the interesting part. Nothing here
//! invents a code point: every value comes out of a closed vocabulary that uTLS
//! fixes in source.
//!
//! * **Cipher suites.** The universe is Go's `cipherSuites` table — the same 22
//!   TLS 1.0–1.2 suites `crypto/tls` implements — plus the three TLS 1.3
//!   suites. `shuffledCiphers` tags each legacy suite with a random number and
//!   then sorts by `(isObsolete, tag)`, where "obsolete" means the suite is not
//!   flagged `suiteTLS12`. So the order inside each half is random but every
//!   modern suite precedes every legacy one — a browser-shaped ordering, not a
//!   uniform shuffle. The three TLS 1.3 suites are shuffled among themselves
//!   and prepended, RC4 is then dropped (TLS 1.3 forbids it), and finally
//!   `removeRandomCiphers` deletes entries with probability
//!   `0.4 * i / len` — increasing towards the tail, and **never index 0**.
//! * **Extensions.** Five are unconditional: `server_name`, `session_ticket`,
//!   `signature_algorithms`, `ec_point_formats`, `supported_groups`. Four more
//!   become unconditional on the TLS 1.3 branch: `key_share`,
//!   `psk_key_exchange_modes`, `supported_versions` and `padding`. The rest are
//!   weighted coins: ALPN 0.7, `status_request` 0.74, `signed_certificate_
//!   timestamp` 0.46, `renegotiation_info` 0.75, `extended_master_secret` 0.77,
//!   and `application_settings` 0.33 — the last of which uTLS may only draw
//!   when ALPN is present, because ALPS is meaningless without it. The finished
//!   list is then shuffled.
//! * **Signature algorithms.** A fixed base of six, plus `ecdsa_sha1` (0.63),
//!   `ecdsa_secp521r1_sha512` (0.59) and `rsa_pss_rsae_sha256` (0.51, forced on
//!   the TLS 1.3 branch because RFC 8446 makes PSS mandatory), which in turn
//!   drags in `rsa_pss_rsae_sha384` and `_sha512` together (0.9). Then
//!   shuffled.
//! * **Groups.** `x25519` (forced on the TLS 1.3 branch), then `secp256r1` and
//!   `secp384r1` always, then `secp521r1` at 0.46. Not shuffled.
//! * **No GREASE, no ECH, no certificate compression, no `pre_shared_key`.**
//!   The generator emits none of them, so neither does this port.
//!
//! # Where this port deliberately differs, and why
//!
//! Two of uTLS' draws produce a hello REALITY cannot use at all. They are not
//! "less good" outcomes; they are handshakes that cannot happen:
//!
//! * **`TLSVersMax_Set_VersionTLS13` is 0.4 upstream — here it is forced.**
//!   Six draws in ten, uTLS caps the hello at TLS 1.2, which means no
//!   `supported_versions` and no `key_share` extension at all. REALITY derives
//!   its authentication key from the client's `x25519` key share, so a hello
//!   without one carries no REALITY handshake by arithmetic. The coin is still
//!   flipped and then discarded, so the shape of the port matches the shape of
//!   the original; only the outcome is pinned.
//! * **`FirstKeyShare_Set_CurveP256` is 0.25 upstream — here it is forced off.**
//!   That draw replaces the single `x25519` share with a `secp256r1` one (uTLS
//!   sends exactly one share and says so in a comment). The REALITY server
//!   reads the *flat* `x25519` share out of the ClientHello; a P-256-only hello
//!   would leave it nothing to read. Same treatment: flipped, discarded.
//!
//! One cosmetic difference: uTLS shuffles `padding` along with everything else,
//! so it can land mid-list. Here it is moved back to last after the shuffle.
//! The executor requires it — the padding length is a function of every byte
//! before it — and no browser sends padding anywhere but last, so this is the
//! more plausible of the two anyway.
//!
//! The bit source is not uTLS'. Upstream seeds SHAKE256 from a 32-byte seed
//! (inherited from Psiphon's PRNG) so that a recorded seed reproduces a
//! recorded hello. Nothing here needs to reproduce *uTLS'* bytes — there is no
//! shared seed to interoperate with — so the source is injected instead
//! ([`RandomizedHello::draw`] takes the RNG), which is what lets the property
//! tests below run thousands of deterministic draws. The weighted-coin
//! arithmetic is uTLS' own: `f = int63 / i64::MAX; f > 1 - weight`.

use rand::RngCore;

use super::hello_profile::{
    APPLICATION_SETTINGS_BODY, CHROME_ECH_GREASE, CipherSuiteSlot, EC_POINT_FORMATS_BODY,
    ExtensionSlotData, GroupSlot, HelloProfileData, KeyShareSlot, PSK_KEY_EXCHANGE_MODES_BODY,
    RENEGOTIATION_INFO_BODY, STATUS_REQUEST_BODY, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3, VersionSlot,
    ext,
};
use super::reality_key_exchange::NamedGroup;

/// The name a refusal or a diagnostic uses for a generated hello.
pub const PROFILE_NAME: &str = "randomized";

// ------------------------------------------------------------- the weights

/// uTLS' `DefaultWeights`, `u_common.go`. Named individually rather than as a
/// struct: nothing here lets a caller supply its own vector, because a weight
/// vector chosen per deployment would be a fingerprint of the deployment.
mod weights {
    pub const APPEND_ALPN: f64 = 0.7;
    /// Flipped and discarded — see the module docs.
    pub const TLS_VERS_MAX_TLS13: f64 = 0.4;
    pub const REMOVE_RANDOM_CIPHERS: f64 = 0.4;
    pub const APPEND_ECDSA_SHA1: f64 = 0.63;
    pub const APPEND_ECDSA_P521_SHA512: f64 = 0.59;
    pub const APPEND_PSS_SHA256: f64 = 0.51;
    pub const APPEND_PSS_SHA384_SHA512: f64 = 0.9;
    pub const APPEND_X25519: f64 = 0.71;
    pub const APPEND_P521: f64 = 0.46;
    pub const APPEND_PADDING: f64 = 0.62;
    pub const APPEND_STATUS: f64 = 0.74;
    pub const APPEND_SCT: f64 = 0.46;
    pub const APPEND_RENEG: f64 = 0.75;
    pub const APPEND_EMS: f64 = 0.77;
    /// Flipped and discarded — see the module docs.
    pub const FIRST_KEY_SHARE_P256: f64 = 0.25;
    pub const APPEND_ALPS: f64 = 0.33;
}

// ------------------------------------------------------- the drawn universe

/// The three TLS 1.3 suites, in `defaultCipherSuitesTLS13` order.
pub const TLS13_CIPHER_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// Go's `cipherSuites` table: every TLS 1.0–1.2 suite `crypto/tls` implements,
/// in source order, with uTLS' obsolescence bit.
///
/// `true` means the suite carries no `suiteTLS12` flag, which is what
/// `sortableCiphers.Less` sorts to the back. The distinction is the whole
/// reason the shuffle stays plausible: CBC-SHA1, 3DES and RC4 can be present,
/// but never ahead of an AEAD suite.
pub const LEGACY_CIPHER_SUITES: [(u16, bool); 22] = [
    (0xcca8, false), // ECDHE_RSA_CHACHA20_POLY1305
    (0xcca9, false), // ECDHE_ECDSA_CHACHA20_POLY1305
    (0xc02f, false), // ECDHE_RSA_AES_128_GCM_SHA256
    (0xc02b, false), // ECDHE_ECDSA_AES_128_GCM_SHA256
    (0xc030, false), // ECDHE_RSA_AES_256_GCM_SHA384
    (0xc02c, false), // ECDHE_ECDSA_AES_256_GCM_SHA384
    (0xc027, false), // ECDHE_RSA_AES_128_CBC_SHA256
    (0xc013, true),  // ECDHE_RSA_AES_128_CBC_SHA
    (0xc023, false), // ECDHE_ECDSA_AES_128_CBC_SHA256
    (0xc009, true),  // ECDHE_ECDSA_AES_128_CBC_SHA
    (0xc014, true),  // ECDHE_RSA_AES_256_CBC_SHA
    (0xc00a, true),  // ECDHE_ECDSA_AES_256_CBC_SHA
    (0x009c, false), // RSA_AES_128_GCM_SHA256
    (0x009d, false), // RSA_AES_256_GCM_SHA384
    (0x003c, false), // RSA_AES_128_CBC_SHA256
    (0x002f, true),  // RSA_AES_128_CBC_SHA
    (0x0035, true),  // RSA_AES_256_CBC_SHA
    (0xc012, true),  // ECDHE_RSA_3DES_EDE_CBC_SHA
    (0x000a, true),  // RSA_3DES_EDE_CBC_SHA
    (0x0005, true),  // RSA_RC4_128_SHA
    (0xc011, true),  // ECDHE_RSA_RC4_128_SHA
    (0xc007, true),  // ECDHE_ECDSA_RC4_128_SHA
];

/// The three RC4 suites TLS 1.3 forbids, dropped by `removeRC4Ciphers`.
pub const RC4_CIPHER_SUITES: [u16; 3] = [0x0005, 0xc011, 0xc007];

/// `sigAndHashAlgos`, the six uTLS always appends before any coin.
const BASE_SIGNATURE_ALGORITHMS: [u16; 6] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0201, // rsa_pkcs1_sha1
    0x0601, // rsa_pkcs1_sha512
];

/// Every scheme the generator may add to the six above.
///
/// The draw pushes these one at a time rather than reading them from here, so
/// only the property tests consume the list — as the *closure* of what may
/// appear on the wire, which is what "bounded" means concretely.
#[cfg(test)]
pub const OPTIONAL_SIGNATURE_ALGORITHMS: [u16; 5] = [
    0x0203, // ecdsa_sha1
    0x0603, // ecdsa_secp521r1_sha512
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
];

/// `rsa_pss_rsae_sha256`. RFC 8446 §4.2.3 makes PSS mandatory in TLS 1.3, and
/// uTLS forces it on that branch.
pub const PSS_RSAE_SHA256: u16 = 0x0804;

/// The four versions `makeSupportedVersions(VersionTLS10, VersionTLS13)`
/// produces, highest first.
const SUPPORTED_VERSIONS: [VersionSlot; 4] = [
    VersionSlot::Version(TLS_1_3),
    VersionSlot::Version(TLS_1_2),
    VersionSlot::Version(TLS_1_1),
    VersionSlot::Version(TLS_1_0),
];

// ------------------------------------------------------------- the draw RNG

/// uTLS' `prng` helpers over an injected byte source.
struct Draw<'r> {
    rng: &'r mut dyn RngCore,
}

impl Draw<'_> {
    /// uTLS' `FlipWeightedCoin`: `f := Int63()/MaxInt64; return f > 1.0-weight`.
    ///
    /// Note that even a weight of 1.0 is not quite certain upstream — `f` can
    /// be exactly 0. Nothing in this module relies on that: what has to be
    /// certain is forced outright instead of being flipped with weight 1.
    fn flip(&mut self, weight: f64) -> bool {
        let int63 = self.rng.next_u64() >> 1;
        let value = int63 as f64 / i64::MAX as f64;
        value > 1.0 - weight
    }

    /// Uniform in `0..bound`, by rejection. `bound` must be non-zero.
    fn below(&mut self, bound: u64) -> u64 {
        // 2^64 mod bound, computed without overflowing.
        let threshold = (u64::MAX - bound + 1) % bound;
        loop {
            let value = self.rng.next_u64();
            if value >= threshold {
                return value % bound;
            }
        }
    }

    /// Go's `rand.Shuffle`: descending Fisher-Yates.
    fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let target = self.below(index as u64 + 1) as usize;
            values.swap(index, target);
        }
    }

    /// Go's `rand.Perm`.
    fn perm(&mut self, len: usize) -> Vec<usize> {
        let mut out = vec![0_usize; len];
        for index in 1..len {
            let target = self.below(index as u64 + 1) as usize;
            out[index] = out[target];
            out[target] = index;
        }
        out
    }
}

// ---------------------------------------------------------------- the draw

/// One extension the generator may place. The vocabulary is closed: a slot
/// this enum has no variant for cannot appear in a generated hello.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    ServerName,
    SessionTicket,
    SignatureAlgorithms,
    EcPointFormats,
    SupportedGroups,
    Alpn,
    StatusRequest,
    SignedCertificateTimestamp,
    RenegotiationInfo,
    ExtendedMasterSecret,
    KeyShare,
    PskKeyExchangeModes,
    SupportedVersions,
    ApplicationSettings,
    Padding,
}

/// One connection's draw.
///
/// Held by the connection for the life of the handshake, because the
/// ServerHello has to be checked against the *same* hello that went out —
/// re-drawing at validation time would compare a ServerHello against a
/// ClientHello nobody sent.
pub struct RandomizedHello {
    cipher_suites: Vec<CipherSuiteSlot>,
    signature_algorithms_body: Vec<u8>,
    supported_groups: Vec<GroupSlot>,
    key_shares: Vec<KeyShareSlot>,
    layout: Vec<Slot>,
}

impl RandomizedHello {
    /// Draw one hello. Mirrors `generateRandomizedSpec`, TLS 1.3 branch only.
    pub fn draw(rng: &mut dyn RngCore) -> Self {
        let mut draw = Draw { rng };

        // `helloRandomized` decides ALPN by coin; `helloRandomizedALPN` and
        // `helloRandomizedNoALPN` pin it. Xray maps `fp=randomized` to the
        // first of the three, so that is what this is.
        let with_alpn = draw.flip(weights::APPEND_ALPN);

        // uTLS decides the version cap here. REALITY cannot use the TLS 1.2
        // branch (module docs), so the coin is flipped for shape and dropped.
        let _tls_vers_max_tls13 = draw.flip(weights::TLS_VERS_MAX_TLS13);

        let cipher_suites = draw_cipher_suites(&mut draw);
        let signature_algorithms_body = draw_signature_algorithms(&mut draw);
        let supported_groups = draw_supported_groups(&mut draw);

        // uTLS: one key share, `x25519` unless the P-256 coin comes up. That
        // coin is flipped and dropped — REALITY reads the flat x25519 share.
        let _first_key_share_p256 = draw.flip(weights::FIRST_KEY_SHARE_P256);
        let key_shares = vec![KeyShareSlot::Group(NamedGroup::X25519)];

        let mut layout = vec![
            Slot::ServerName,
            Slot::SessionTicket,
            Slot::SignatureAlgorithms,
            Slot::EcPointFormats,
            Slot::SupportedGroups,
        ];
        if with_alpn {
            layout.push(Slot::Alpn);
        }
        // Upstream: `flip(padding) || TLSVersMax == 1.3`. The TLS 1.3 branch
        // makes it unconditional; the coin is still consumed, as in Go, where
        // `||` evaluates its left side first.
        let _append_padding = draw.flip(weights::APPEND_PADDING);
        layout.push(Slot::Padding);
        if draw.flip(weights::APPEND_STATUS) {
            layout.push(Slot::StatusRequest);
        }
        if draw.flip(weights::APPEND_SCT) {
            layout.push(Slot::SignedCertificateTimestamp);
        }
        if draw.flip(weights::APPEND_RENEG) {
            layout.push(Slot::RenegotiationInfo);
        }
        if draw.flip(weights::APPEND_EMS) {
            layout.push(Slot::ExtendedMasterSecret);
        }
        layout.push(Slot::KeyShare);
        layout.push(Slot::PskKeyExchangeModes);
        layout.push(Slot::SupportedVersions);
        // ALPS is TLS 1.3-only and draft-vvv-tls-alps-01 §3 allows it only
        // beside an ALPN extension, so uTLS gates it on `WithALPN`. Upstream
        // draws it from a seed salted with "ALPS" purely so that an older
        // recorded seed still reproduces its old hello; there is no recorded
        // seed here, so it comes off the same stream.
        if with_alpn && draw.flip(weights::APPEND_ALPS) {
            layout.push(Slot::ApplicationSettings);
        }

        draw.shuffle(&mut layout);
        // Padding back to the end: its length is a function of every byte
        // before it, and no browser puts it anywhere else.
        let padding_at = layout
            .iter()
            .position(|slot| *slot == Slot::Padding)
            .expect("padding is always drawn on the TLS 1.3 branch");
        let padding = layout.remove(padding_at);
        layout.push(padding);

        Self {
            cipher_suites,
            signature_algorithms_body,
            supported_groups,
            key_shares,
            layout,
        }
    }

    /// Run `body` against this draw rendered as a profile.
    ///
    /// A closure rather than a returned value: the profile borrows the vectors
    /// above *and* a slot list built on the stack from them, which is a shape
    /// a return type cannot express without making the struct self-referential.
    pub fn with_profile<R>(&self, body: impl FnOnce(&HelloProfileData<'_>) -> R) -> R {
        let extensions: Vec<ExtensionSlotData<'_>> =
            self.layout.iter().map(|slot| self.encode(*slot)).collect();
        let profile = HelloProfileData {
            name: PROFILE_NAME,
            cipher_suites: &self.cipher_suites,
            extensions: &extensions,
            // The draw already fixed the order. Permuting again would be a
            // second, differently-distributed shuffle on top of uTLS'.
            permute_extensions: false,
            // Inert: the generator draws no ECH GREASE slot, so nothing reads
            // this. It is not optional in the struct, and the Chrome shape is
            // the one every other profile that does not send ECH also carries.
            ech_grease: CHROME_ECH_GREASE,
            reuse_classical_key_share: false,
        };
        body(&profile)
    }

    fn encode(&self, slot: Slot) -> ExtensionSlotData<'_> {
        match slot {
            Slot::ServerName => ExtensionSlotData::ServerName,
            Slot::SessionTicket => ExtensionSlotData::Constant {
                extension_type: ext::SESSION_TICKET,
                body: &[],
            },
            Slot::SignatureAlgorithms => ExtensionSlotData::Constant {
                extension_type: ext::SIGNATURE_ALGORITHMS,
                body: &self.signature_algorithms_body,
            },
            Slot::EcPointFormats => ExtensionSlotData::Constant {
                extension_type: ext::EC_POINT_FORMATS,
                body: EC_POINT_FORMATS_BODY,
            },
            Slot::SupportedGroups => ExtensionSlotData::SupportedGroups(&self.supported_groups),
            Slot::Alpn => ExtensionSlotData::Alpn,
            Slot::StatusRequest => ExtensionSlotData::Constant {
                extension_type: ext::STATUS_REQUEST,
                body: STATUS_REQUEST_BODY,
            },
            Slot::SignedCertificateTimestamp => ExtensionSlotData::Constant {
                extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
                body: &[],
            },
            Slot::RenegotiationInfo => ExtensionSlotData::Constant {
                extension_type: ext::RENEGOTIATION_INFO,
                body: RENEGOTIATION_INFO_BODY,
            },
            Slot::ExtendedMasterSecret => ExtensionSlotData::Constant {
                extension_type: ext::EXTENDED_MASTER_SECRET,
                body: &[],
            },
            Slot::KeyShare => ExtensionSlotData::KeyShare(&self.key_shares),
            Slot::PskKeyExchangeModes => ExtensionSlotData::Constant {
                extension_type: ext::PSK_KEY_EXCHANGE_MODES,
                body: PSK_KEY_EXCHANGE_MODES_BODY,
            },
            Slot::SupportedVersions => ExtensionSlotData::SupportedVersions(&SUPPORTED_VERSIONS),
            // uTLS' `ApplicationSettingsExtension` writes 17513 (0x4469), the
            // older of the two ALPS code points. The Chrome 133 table moved to
            // 0x44cd; the generator did not follow it.
            Slot::ApplicationSettings => ExtensionSlotData::Constant {
                extension_type: ext::APPLICATION_SETTINGS_OLD,
                body: APPLICATION_SETTINGS_BODY,
            },
            Slot::Padding => ExtensionSlotData::Padding,
        }
    }
}

/// `shuffledCiphers` + the TLS 1.3 prefix + `removeRC4Ciphers` +
/// `removeRandomCiphers`, in uTLS' order.
fn draw_cipher_suites(draw: &mut Draw<'_>) -> Vec<CipherSuiteSlot> {
    // `shuffledCiphers`: a random tag per suite, then a sort that puts every
    // non-obsolete suite first and orders within each half by tag.
    let tags = draw.perm(LEGACY_CIPHER_SUITES.len());
    let mut legacy: Vec<(bool, usize, u16)> = LEGACY_CIPHER_SUITES
        .iter()
        .zip(&tags)
        .map(|((id, obsolete), tag)| (*obsolete, *tag, *id))
        .collect();
    legacy.sort_unstable();

    let mut tls13 = TLS13_CIPHER_SUITES;
    draw.shuffle(&mut tls13);

    let mut suites: Vec<u16> = tls13.to_vec();
    suites.extend(
        legacy
            .into_iter()
            .map(|(_, _, id)| id)
            .filter(|id| !RC4_CIPHER_SUITES.contains(id)),
    );

    // `removeRandomCiphers`: never index 0, and the probability rises towards
    // the tail.
    //
    // uTLS removes in place and steps `i` back after each removal, so the index
    // in the weight is the candidate's position in the *shrinking* slice while
    // the divisor stays the starting length. `kept.len()` is exactly that
    // position — everything before it has already been kept — so this consumes
    // one coin per suite at the weights Go uses, rather than the slightly
    // harsher ones an original-index port would give.
    let total = suites.len() as f64;
    let mut kept: Vec<u16> = Vec::with_capacity(suites.len());
    for id in suites {
        let index = kept.len();
        let remove = index > 0 && draw.flip(weights::REMOVE_RANDOM_CIPHERS * index as f64 / total);
        if !remove {
            kept.push(id);
        }
    }

    kept.into_iter()
        .map(|id| {
            if TLS13_CIPHER_SUITES.contains(&id) {
                CipherSuiteSlot::Negotiable(id)
            } else {
                CipherSuiteSlot::Decorative(id)
            }
        })
        .collect()
}

/// The `signature_algorithms` body: the six-scheme base plus the drawn
/// additions, shuffled, with the two-byte list length in front.
fn draw_signature_algorithms(draw: &mut Draw<'_>) -> Vec<u8> {
    let mut schemes = BASE_SIGNATURE_ALGORITHMS.to_vec();
    if draw.flip(weights::APPEND_ECDSA_SHA1) {
        schemes.push(0x0203);
    }
    if draw.flip(weights::APPEND_ECDSA_P521_SHA512) {
        schemes.push(0x0603);
    }
    // `flip(...) || TLSVersMax == 1.3`: forced here, coin still consumed.
    let _append_pss = draw.flip(weights::APPEND_PSS_SHA256);
    schemes.push(PSS_RSAE_SHA256);
    if draw.flip(weights::APPEND_PSS_SHA384_SHA512) {
        // uTLS: "these usually go together".
        schemes.push(0x0805);
        schemes.push(0x0806);
    }
    draw.shuffle(&mut schemes);

    let mut body = Vec::with_capacity(2 + schemes.len() * 2);
    body.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
    for scheme in schemes {
        body.extend_from_slice(&scheme.to_be_bytes());
    }
    body
}

/// `curveIDs`: `x25519` first (forced on the TLS 1.3 branch), then P-256 and
/// P-384 unconditionally, then P-521 by coin. uTLS does not shuffle these.
fn draw_supported_groups(draw: &mut Draw<'_>) -> Vec<GroupSlot> {
    let _append_x25519 = draw.flip(weights::APPEND_X25519);
    let mut groups = vec![
        GroupSlot::Group(NamedGroup::X25519),
        GroupSlot::Group(NamedGroup::Secp256r1),
        GroupSlot::Group(NamedGroup::Secp384r1),
    ];
    if draw.flip(weights::APPEND_P521) {
        groups.push(GroupSlot::Group(NamedGroup::Secp521r1));
    }
    groups
}

// ------------------------------------------------------- the seeded source

/// A reproducible byte source for the draw.
///
/// SplitMix64, the same generator [`super::hello_profile`] uses to drive the
/// Chrome extension permutation. Not cryptographic and not meant to be: a
/// shipped connection seeds [`RandomizedHello::draw`] from the OS, and this
/// exists so a test can ask for *that same draw* again. It is compiled only
/// into test builds for exactly that reason — a pinned seed in a shipped build
/// would be a constant fingerprint under a randomized name.
#[cfg(any(test, feature = "testkit"))]
pub struct SeededDraws(u64);

#[cfg(any(test, feature = "testkit"))]
impl SeededDraws {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}

#[cfg(any(test, feature = "testkit"))]
impl RngCore for SeededDraws {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&word[..len]);
        }
    }
}

#[cfg(test)]
mod tests;
