use rand::RngCore;

use super::hello_profile::{
    APPLICATION_SETTINGS_BODY, CHROME_ECH_GREASE, CipherSuiteSlot, EC_POINT_FORMATS_BODY,
    ExtensionSlotData, GroupSlot, HelloProfileData, KeyShareSlot, PSK_KEY_EXCHANGE_MODES_BODY,
    RENEGOTIATION_INFO_BODY, STATUS_REQUEST_BODY, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3, VersionSlot,
    ext,
};
use super::reality_key_exchange::NamedGroup;

pub const PROFILE_NAME: &str = "randomized";

mod weights {
    pub const APPEND_ALPN: f64 = 0.7;
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
    pub const FIRST_KEY_SHARE_P256: f64 = 0.25;
    pub const APPEND_ALPS: f64 = 0.33;
}

pub const TLS13_CIPHER_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

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

pub const RC4_CIPHER_SUITES: [u16; 3] = [0x0005, 0xc011, 0xc007];

const BASE_SIGNATURE_ALGORITHMS: [u16; 6] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0201, // rsa_pkcs1_sha1
    0x0601, // rsa_pkcs1_sha512
];

#[cfg(test)]
pub const OPTIONAL_SIGNATURE_ALGORITHMS: [u16; 5] = [
    0x0203, // ecdsa_sha1
    0x0603, // ecdsa_secp521r1_sha512
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
];

pub const PSS_RSAE_SHA256: u16 = 0x0804;

const SUPPORTED_VERSIONS: [VersionSlot; 4] = [
    VersionSlot::Version(TLS_1_3),
    VersionSlot::Version(TLS_1_2),
    VersionSlot::Version(TLS_1_1),
    VersionSlot::Version(TLS_1_0),
];

struct Draw<'r> {
    rng: &'r mut dyn RngCore,
}

impl Draw<'_> {
    /// uTLS' `FlipWeightedCoin`: `f := Int63()/MaxInt64; return f > 1.0-weight`.
    fn flip(&mut self, weight: f64) -> bool {
        let int63 = self.rng.next_u64() >> 1;
        let value = int63 as f64 / i64::MAX as f64;
        value > 1.0 - weight
    }

    fn below(&mut self, bound: u64) -> u64 {
        let threshold = (u64::MAX - bound + 1) % bound;
        loop {
            let value = self.rng.next_u64();
            if value >= threshold {
                return value % bound;
            }
        }
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let target = self.below(index as u64 + 1) as usize;
            values.swap(index, target);
        }
    }

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

pub struct RandomizedHello {
    cipher_suites: Vec<CipherSuiteSlot>,
    signature_algorithms_body: Vec<u8>,
    supported_groups: Vec<GroupSlot>,
    key_shares: Vec<KeyShareSlot>,
    layout: Vec<Slot>,
}

impl RandomizedHello {
    pub fn draw(rng: &mut dyn RngCore) -> Self {
        let mut draw = Draw { rng };

        let with_alpn = draw.flip(weights::APPEND_ALPN);

        let _tls_vers_max_tls13 = draw.flip(weights::TLS_VERS_MAX_TLS13);

        let cipher_suites = draw_cipher_suites(&mut draw);
        let signature_algorithms_body = draw_signature_algorithms(&mut draw);
        let supported_groups = draw_supported_groups(&mut draw);

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
        if with_alpn && draw.flip(weights::APPEND_ALPS) {
            layout.push(Slot::ApplicationSettings);
        }

        draw.shuffle(&mut layout);
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

    pub fn with_profile<R>(&self, body: impl FnOnce(&HelloProfileData<'_>) -> R) -> R {
        let extensions: Vec<ExtensionSlotData<'_>> =
            self.layout.iter().map(|slot| self.encode(*slot)).collect();
        let profile = HelloProfileData {
            name: PROFILE_NAME,
            cipher_suites: &self.cipher_suites,
            extensions: &extensions,
            permute_extensions: false,
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
            Slot::ApplicationSettings => ExtensionSlotData::Constant {
                extension_type: ext::APPLICATION_SETTINGS_OLD,
                body: APPLICATION_SETTINGS_BODY,
            },
            Slot::Padding => ExtensionSlotData::Padding,
        }
    }
}

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
