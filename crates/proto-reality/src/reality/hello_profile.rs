//! The ClientHello parrot, as a table.
//!
//! What used to be here was a hand-written literal that claimed to imitate
//! Chrome and imitated nothing: six extensions in a fixed order, no GREASE, no
//! padding, one key-exchange group. Anything that looks at a TLS fingerprint
//! saw a client that exists nowhere else on the internet — which is the exact
//! opposite of what REALITY is for.
//!
//! A profile is an ordered list of slots. Each slot is either a constant blob
//! (bytes that are identical on every connection anywhere) or a builder that
//! needs the session: the SNI, the key shares, ALPN, the per-connection GREASE
//! values, the ECH GREASE payload, the padding length. Adding a browser build
//! means adding a table, not editing a function.
//!
//! # Sources
//!
//! Versioned tables come from uTLS; current Chrome and Firefox tables use
//! first-party captures until upstream catches up. The import script verifies
//! every uTLS-derived profile.
//!
//! * **GREASE values** — BoringSSL's `ssl_get_grease_value`: a seed byte is
//!   masked to `(byte & 0xf0) | 0x0a` and then repeated into both halves of the
//!   `uint16`, giving `0xωaωa`. The values are per *index*, not per hello, and
//!   they are stable for the life of the connection precisely so that "the same
//!   group [can] be advertised in both `supported_groups` and `key_shares`" and
//!   so a second hello for a HelloRetryRequest is identical.
//! * **Two GREASE extensions** — the first is empty, the last carries a single
//!   zero byte, and their values must differ (BoringSSL flips a bit when the
//!   seed collides). Both keep their position when the rest is permuted.
//! * **Extension permutation** — Chrome 110+ turns on BoringSSL's
//!   `SSL_set_permute_extensions`. Everything except GREASE, padding and
//!   `pre_shared_key` is shuffled per connection. A profile that always emitted
//!   the same order would be the odd one out.
//! * **Padding** — RFC 7685, in BoringSSL's shape: pad only when the hello is
//!   between 0x100 and 0x1ff bytes long, and pad it to exactly 512. With an
//!   ML-KEM key share the hello is far past that, so the rule fires on nothing
//!   Chrome 133 sends — which is also why it has to be a rule and not a
//!   constant.
//! * **ECH GREASE** — draft-ietf-tls-esni §6.2: a random `config_id`, a
//!   supported HPKE symmetric suite, a *real* HPKE encapsulated key in `enc`,
//!   and `L + 16` random payload bytes. BoringSSL's candidates are
//!   HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305, and payload lengths
//!   128/160/192/224.

use std::io;

use rand::RngCore;

use super::common::{HELLO_SESSION_ID_LEN, VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR};
use super::reality_cipher_suite::CipherSuite;
use super::reality_key_exchange::NamedGroup;

/// Which hello a connection writes.
///
/// Mirrors `foxcore_api::RealityFingerprint`, which cannot be named here — this
/// crate does not depend on the config crate, and should not start to just to
/// share two variants.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RealityHelloProfile {
    #[default]
    Chrome151,
    Chrome133,
    Chrome131,
    Edge85,
    Safari263,
    Ios14,
    Qq111,
    Firefox153,
    Firefox148,
}

impl RealityHelloProfile {
    pub fn table(self) -> &'static HelloProfile {
        match self {
            Self::Chrome151 => &CHROME_151,
            Self::Chrome133 => &CHROME_133,
            Self::Chrome131 => &CHROME_131,
            Self::Edge85 => &EDGE_85,
            Self::Safari263 => &SAFARI_26_3,
            Self::Ios14 => &IOS_14,
            Self::Qq111 => &QQ_11_1,
            Self::Firefox153 => &FIREFOX_153,
            Self::Firefox148 => &FIREFOX_148,
        }
    }

    pub const ALL: &'static [Self] = &[
        Self::Chrome151,
        Self::Chrome133,
        Self::Chrome131,
        Self::Edge85,
        Self::Safari263,
        Self::Ios14,
        Self::Qq111,
        Self::Firefox153,
        Self::Firefox148,
    ];
}

// ---------------------------------------------------------------- GREASE

/// Which GREASE value a slot draws from.
///
/// BoringSSL keeps one seed byte per index for the life of a connection. Two
/// slots that share an index are *meant* to carry the same value: the GREASE
/// entry in `supported_groups` and the one in `key_share` are the same group,
/// and a client that put two different values there would be advertising a
/// group it did not send a share for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GreaseSlot {
    Cipher,
    Group,
    Version,
    Extension1,
    Extension2,
}

impl GreaseSlot {
    const fn index(self) -> usize {
        match self {
            Self::Cipher => 0,
            Self::Group => 1,
            Self::Version => 2,
            Self::Extension1 => 3,
            Self::Extension2 => 4,
        }
    }
}

/// One connection's GREASE seed: one byte per [`GreaseSlot`].
#[derive(Clone, Copy, Debug)]
pub struct GreaseValues {
    seed: [u8; 5],
}

impl GreaseValues {
    pub fn random(rng: &mut impl RngCore) -> Self {
        let mut seed = [0_u8; 5];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Deterministic constructor, so a test can assert the shape of the bytes
    /// instead of asserting that something random happened.
    pub const fn from_seed(mut seed: [u8; 5]) -> Self {
        // BoringSSL: the two fake extensions must not collide, or the hello
        // carries the same unknown extension type twice, which no browser does.
        if seed[GreaseSlot::Extension1.index()] & 0xf0
            == seed[GreaseSlot::Extension2.index()] & 0xf0
        {
            seed[GreaseSlot::Extension2.index()] ^= 0x10;
        }
        Self { seed }
    }

    /// `0xωaωa`: the high nibble varies, the low nibble is always `a`, and the
    /// byte is repeated. The repetition is part of the shape — a value that is
    /// merely "reserved-looking" but not of this form is not GREASE.
    pub const fn value(&self, slot: GreaseSlot) -> u16 {
        let byte = (self.seed[slot.index()] & 0xf0) | 0x0a;
        u16::from_be_bytes([byte, byte])
    }
}

/// Every GREASE value RFC 8701 reserves. Only tests need the set — production
/// code produces GREASE, it never has to recognise it.
#[cfg(test)]
const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Whether `value` is one of the sixteen reserved GREASE points.
#[cfg(test)]
pub fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

// ------------------------------------------------------------ cipher suites

/// One entry of the profile's `cipher_suites`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CipherSuiteSlot {
    Grease,
    /// A TLS 1.3 suite that is offered *and* implemented. The id must resolve
    /// through [`CipherSuite::from_id`]; [`HelloProfile::validate`] refuses a
    /// table where it does not, so an unknown suite is a construction error
    /// here rather than a surprise arriving from a server.
    Negotiable(u16),
    /// A TLS 1.2 suite offered because Chrome offers it. This client speaks
    /// only TLS 1.3, so one of these being selected is a refusal, never a
    /// downgrade. It must *not* resolve through `CipherSuite::from_id` — that
    /// would mean the two tables disagree about what is implemented.
    Decorative(u16),
}

// -------------------------------------------------------------- extensions

/// A `supported_groups` entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupSlot {
    Grease,
    Group(NamedGroup),
}

/// A `key_share` entry. Only groups this build executes may appear.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyShareSlot {
    Grease,
    Group(NamedGroup),
}

/// A `supported_versions` entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionSlot {
    Grease,
    Version(u16),
}

pub const TLS_1_3: u16 = 0x0304;
pub const TLS_1_2: u16 = 0x0303;
pub const TLS_1_1: u16 = 0x0302;
pub const TLS_1_0: u16 = 0x0301;

/// Extension body borrowed from a static table or a per-connection randomized
/// profile; generic encoders must preserve this lifetime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtensionSlotData<'a> {
    /// Bytes that are the same on every connection from every client running
    /// this profile. Type and body are both frozen.
    Constant {
        extension_type: u16,
        body: &'a [u8],
    },
    /// A GREASE extension. The type is the connection's GREASE value for the
    /// slot; the body is frozen (empty for the first, one zero byte for the
    /// last).
    Grease {
        slot: GreaseSlot,
        body: &'a [u8],
    },
    ServerName,
    SupportedGroups(&'a [GroupSlot]),
    KeyShare(&'a [KeyShareSlot]),
    Alpn,
    SupportedVersions(&'a [VersionSlot]),
    EchGrease,
    /// RFC 7685. Emits nothing unless the finished hello lands in the window
    /// BoringSSL pads; see [`boring_padding`].
    Padding,
}

pub type ExtensionSlot = ExtensionSlotData<'static>;

impl ExtensionSlotData<'_> {
    /// Chrome permutes its extensions per connection. GREASE keeps its position
    /// (first and last), padding must be last because its length depends on
    /// everything before it, and `pre_shared_key` — which this client never
    /// sends — would have to be last for the same reason.
    const fn position_is_pinned(&self) -> bool {
        matches!(self, Self::Grease { .. } | Self::Padding)
    }
}

// ----------------------------------------------------------------- profile

/// An ordered ClientHello shape.
///
/// See [`ExtensionSlotData`] for why this carries a lifetime: the transcribed
/// tables are all `'static` and use the [`HelloProfile`] alias, while the
pub struct HelloProfileData<'a> {
    /// Name used in errors, so a refusal says which table produced the hello.
    pub name: &'a str,
    pub cipher_suites: &'a [CipherSuiteSlot],
    pub extensions: &'a [ExtensionSlotData<'a>],
    /// Chrome 110+ shuffles the non-pinned extensions on every connection.
    pub permute_extensions: bool,
    pub ech_grease: EchGreaseShapeData<'a>,
    pub reuse_classical_key_share: bool,
}

pub type HelloProfile = HelloProfileData<'static>;

impl HelloProfileData<'_> {
    /// The TLS 1.3 suites this profile may actually negotiate.
    ///
    /// This is the list a ServerHello is checked against. It is derived from
    /// the same table that writes the wire bytes, so "offered" and
    /// "implemented" cannot drift apart.
    pub fn negotiable_cipher_suites(&self) -> Vec<CipherSuite> {
        self.cipher_suites
            .iter()
            .filter_map(|slot| match slot {
                CipherSuiteSlot::Negotiable(id) => CipherSuite::from_id(*id),
                _ => None,
            })
            .collect()
    }

    /// The groups the profile sends a key share for, in table order.
    pub fn key_share_groups(&self) -> Vec<NamedGroup> {
        self.extensions
            .iter()
            .filter_map(|slot| match slot {
                ExtensionSlotData::KeyShare(entries) => Some(entries),
                _ => None,
            })
            .flat_map(|entries| entries.iter())
            .filter_map(|entry| match entry {
                KeyShareSlot::Group(group) => Some(*group),
                KeyShareSlot::Grease => None,
            })
            .collect()
    }

    /// Everything about a table that must be true before it can produce bytes.
    ///
    /// Called on every hello rather than only in tests: it is a handful of
    /// comparisons over a `const` slice next to two elliptic-curve operations,
    /// and a table edit that silently offers an unimplemented cipher is exactly
    /// the failure this is here to make impossible.
    pub fn validate(&self) -> io::Result<()> {
        let refuse = |message: String| {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("REALITY hello profile {}: {message}", self.name),
            ))
        };

        let mut negotiable = 0_usize;
        for slot in self.cipher_suites {
            match slot {
                CipherSuiteSlot::Grease => {}
                CipherSuiteSlot::Negotiable(id) => {
                    if CipherSuite::from_id(*id).is_none() {
                        return refuse(format!(
                            "offers cipher suite 0x{id:04x} as negotiable, but this build does \
                             not implement it"
                        ));
                    }
                    negotiable += 1;
                }
                CipherSuiteSlot::Decorative(id) => {
                    if CipherSuite::from_id(*id).is_some() {
                        return refuse(format!(
                            "lists implemented cipher suite 0x{id:04x} as decoration; a suite \
                             this build can negotiate must be marked negotiable"
                        ));
                    }
                }
            }
        }
        if negotiable == 0 {
            return refuse("offers no cipher suite this build can negotiate".to_owned());
        }

        let mut key_share_extensions = 0_usize;
        let mut padding_slots = 0_usize;
        let mut supported_groups: Option<&[GroupSlot]> = None;
        let mut grease_extension_slots = Vec::new();
        for (position, slot) in self.extensions.iter().enumerate() {
            match slot {
                ExtensionSlotData::Padding => {
                    padding_slots += 1;
                    if position + 1 != self.extensions.len() {
                        return refuse(
                            "puts padding somewhere other than last; its length is a function of \
                             every byte before it"
                                .to_owned(),
                        );
                    }
                }
                ExtensionSlotData::Grease { slot, .. } => grease_extension_slots.push(*slot),
                ExtensionSlotData::SupportedGroups(groups) => supported_groups = Some(groups),
                ExtensionSlotData::KeyShare(entries) => {
                    key_share_extensions += 1;
                    for entry in *entries {
                        if let KeyShareSlot::Group(group) = entry
                            && !group.is_executable()
                        {
                            return refuse(format!(
                                "sends a {} key share, which this build cannot complete",
                                group.name()
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        if padding_slots > 1 {
            return refuse("has more than one padding slot".to_owned());
        }
        if key_share_extensions != 1 {
            return refuse(format!(
                "has {key_share_extensions} key_share extensions; exactly one is a ClientHello"
            ));
        }
        // Two GREASE extensions, or none at all. Chrome, Edge, Safari, iOS and
        // QQ all bracket their extension list with a pair; Firefox GREASEs
        // nothing. One is neither, and would be a client that exists nowhere.
        if !grease_extension_slots.is_empty()
            && grease_extension_slots != [GreaseSlot::Extension1, GreaseSlot::Extension2]
        {
            return refuse(
                "must carry either no GREASE extension or exactly two, extension1 first and \
                 extension2 last"
                    .to_owned(),
            );
        }

        // Every group with a key share must also be advertised, or the hello
        // says "here is a share for a group I do not support".
        let groups = supported_groups.unwrap_or(&[]);
        for group in self.key_share_groups() {
            if !groups.contains(&GroupSlot::Group(group)) {
                return refuse(format!(
                    "sends a {} key share without listing the group in supported_groups",
                    group.name()
                ));
            }
        }

        Ok(())
    }
}

// -------------------------------------------------------- ECH GREASE inputs

/// HPKE KDF id, RFC 9180 §7.2.
const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
/// HPKE AEAD id, RFC 9180 §7.3.
const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;

/// The HPKE suite the ECH GREASE extension advertises.
///
/// One suite, not a random pick between two. BoringSSL's `setup_ech_grease`
const ECH_GREASE_SUITE: (u16, u16) = (HPKE_KDF_HKDF_SHA256, HPKE_AEAD_AES_128_GCM);

const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EchGreaseShapeData<'a> {
    pub suites: &'a [(u16, u16)],
    pub payload_lens: &'a [usize],
}

pub type EchGreaseShape = EchGreaseShapeData<'static>;

pub const CHROME_ECH_GREASE: EchGreaseShape = EchGreaseShape {
    suites: &[ECH_GREASE_SUITE],
    payload_lens: &[128, 160, 192, 224],
};

pub const FIREFOX_ECH_GREASE: EchGreaseShape = EchGreaseShape {
    suites: &[
        (HPKE_KDF_HKDF_SHA256, HPKE_AEAD_AES_128_GCM),
        (HPKE_KDF_HKDF_SHA256, HPKE_AEAD_CHACHA20_POLY1305),
    ],
    payload_lens: &[223],
};

/// AEAD ciphertext expansion for both candidate suites.
const ECH_GREASE_TAG_LEN: usize = 16;

pub(super) const MAX_ECH_GREASE_PLAINTEXT: usize = 224;
const MAX_ECH_GREASE_PAYLOAD: usize = MAX_ECH_GREASE_PLAINTEXT + ECH_GREASE_TAG_LEN;

/// Everything the ECH GREASE extension needs that must not repeat between
/// connections.
///
/// `enc` is a real X25519 public key rather than 32 random bytes: a genuine ECH
/// offer carries an HPKE encapsulated key there, and a value off the curve is
/// exactly the kind of tell GREASE exists to avoid. It is generated per
/// connection, not once per process — the field is visible to every observer,
/// and a constant would correlate every connection this build ever makes.
#[derive(Clone)]
pub struct EchGreaseParams {
    pub enc: [u8; 32],
    config_id: u8,
    suite: (u16, u16),
    payload_len: usize,
    payload: [u8; MAX_ECH_GREASE_PAYLOAD],
}

impl EchGreaseParams {
    pub fn new(enc: [u8; 32], rng: &mut impl RngCore) -> Self {
        Self::with_shape(enc, CHROME_ECH_GREASE, rng)
    }

    pub fn with_shape(
        enc: [u8; 32],
        shape: EchGreaseShapeData<'_>,
        rng: &mut impl RngCore,
    ) -> Self {
        let mut chooser = [0_u8; 3];
        rng.fill_bytes(&mut chooser);
        let mut payload = [0_u8; MAX_ECH_GREASE_PAYLOAD];
        rng.fill_bytes(&mut payload);
        Self {
            enc,
            config_id: chooser[0],
            suite: shape.suites[usize::from(chooser[1]) % shape.suites.len()],
            payload_len: shape.payload_lens[usize::from(chooser[2]) % shape.payload_lens.len()],
            payload,
        }
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        let (kdf, aead) = self.suite;
        let payload_len = self.payload_len + ECH_GREASE_TAG_LEN;
        // draft-ietf-tls-esni: ECHClientHello with type = outer(0).
        out.push(0x00);
        out.extend_from_slice(&kdf.to_be_bytes());
        out.extend_from_slice(&aead.to_be_bytes());
        out.push(self.config_id);
        out.extend_from_slice(&(self.enc.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&(payload_len as u16).to_be_bytes());
        out.extend_from_slice(&self.payload[..payload_len]);
    }
}

// ----------------------------------------------------------------- session

/// The per-connection values the builders need.
pub struct HelloSession<'a> {
    pub client_random: &'a [u8; 32],
    pub session_id: &'a [u8; HELLO_SESSION_ID_LEN],
    pub server_name: &'a str,
    pub alpn_protocols: &'a [&'a str],
    /// One entry per group the profile's `key_share` names, in table order.
    pub key_shares: &'a [(NamedGroup, Vec<u8>)],
    pub grease: GreaseValues,
    pub ech_grease: EchGreaseParams,
    /// Drives the extension permutation. Held by the session rather than drawn
    /// inside the builder so a test can pin an order.
    pub permutation_seed: u64,
}

impl HelloSession<'_> {
    fn key_share(&self, group: NamedGroup) -> io::Result<&[u8]> {
        self.key_shares
            .iter()
            .find(|(candidate, _)| *candidate == group)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "REALITY hello profile names a {} key share the session did not generate",
                        group.name()
                    ),
                )
            })
    }
}

// ---------------------------------------------------------------- encoding

/// Extension code points this profile writes. TLS 1.3 registry values.
pub(super) mod ext {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
    pub const PADDING: u16 = 0x0015;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const RECORD_SIZE_LIMIT: u16 = 0x001c;
    pub const DELEGATED_CREDENTIALS: u16 = 0x0022;
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub const KEY_SHARE: u16 = 0x0033;
    /// `application_settings`, the code point Chrome 131 and earlier used.
    pub const APPLICATION_SETTINGS_OLD: u16 = 0x4469;
    /// `application_settings`, the code point Chrome 132+ moved to.
    pub const APPLICATION_SETTINGS: u16 = 0x44cd;
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

fn write_extension(out: &mut Vec<u8>, extension_type: u16, body: &[u8]) -> io::Result<()> {
    let length = u16::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("REALITY ClientHello extension 0x{extension_type:04x} exceeds 65535 bytes"),
        )
    })?;
    out.extend_from_slice(&extension_type.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

impl ExtensionSlotData<'_> {
    /// Append this slot's wire bytes. Padding writes nothing here: its length
    /// depends on the finished hello, so the executor emits it separately.
    pub fn encode(&self, session: &HelloSession<'_>, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Padding => Ok(()),
            Self::Constant {
                extension_type,
                body,
            } => write_extension(out, *extension_type, body),
            Self::Grease { slot, body } => write_extension(out, session.grease.value(*slot), body),
            Self::ServerName => {
                let name = session.server_name.as_bytes();
                let name_len = u16::try_from(name.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "REALITY SNI is too long")
                })?;
                let mut body = Vec::with_capacity(5 + name.len());
                body.extend_from_slice(&(name_len + 3).to_be_bytes());
                body.push(0x00); // host_name
                body.extend_from_slice(&name_len.to_be_bytes());
                body.extend_from_slice(name);
                write_extension(out, ext::SERVER_NAME, &body)
            }
            Self::SupportedGroups(groups) => {
                let mut body = Vec::with_capacity(2 + groups.len() * 2);
                body.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
                for group in *groups {
                    let id = match group {
                        GroupSlot::Grease => session.grease.value(GreaseSlot::Group),
                        GroupSlot::Group(group) => group.id(),
                    };
                    body.extend_from_slice(&id.to_be_bytes());
                }
                write_extension(out, ext::SUPPORTED_GROUPS, &body)
            }
            Self::KeyShare(entries) => {
                let mut list = Vec::new();
                for entry in *entries {
                    let (id, share): (u16, &[u8]) = match entry {
                        // BoringSSL's GREASE key share is one zero byte, not an
                        // empty one: a zero-length key_exchange is illegal.
                        KeyShareSlot::Grease => (session.grease.value(GreaseSlot::Group), &[0x00]),
                        KeyShareSlot::Group(group) => (group.id(), session.key_share(*group)?),
                    };
                    let share_len = u16::try_from(share.len()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "REALITY key share exceeds 65535 bytes",
                        )
                    })?;
                    list.extend_from_slice(&id.to_be_bytes());
                    list.extend_from_slice(&share_len.to_be_bytes());
                    list.extend_from_slice(share);
                }
                let list_len = u16::try_from(list.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "REALITY key share list exceeds 65535 bytes",
                    )
                })?;
                let mut body = Vec::with_capacity(2 + list.len());
                body.extend_from_slice(&list_len.to_be_bytes());
                body.extend_from_slice(&list);
                write_extension(out, ext::KEY_SHARE, &body)
            }
            Self::Alpn => {
                let mut list = Vec::new();
                for protocol in session.alpn_protocols {
                    let bytes = protocol.as_bytes();
                    let length = u8::try_from(bytes.len()).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "REALITY ALPN protocol exceeds 255 bytes",
                        )
                    })?;
                    list.push(length);
                    list.extend_from_slice(bytes);
                }
                let list_len = u16::try_from(list.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "REALITY ALPN list exceeds 65535 bytes",
                    )
                })?;
                let mut body = Vec::with_capacity(2 + list.len());
                body.extend_from_slice(&list_len.to_be_bytes());
                body.extend_from_slice(&list);
                write_extension(out, ext::ALPN, &body)
            }
            Self::SupportedVersions(versions) => {
                let mut body = Vec::with_capacity(1 + versions.len() * 2);
                body.push((versions.len() * 2) as u8);
                for version in *versions {
                    let value = match version {
                        VersionSlot::Grease => session.grease.value(GreaseSlot::Version),
                        VersionSlot::Version(version) => *version,
                    };
                    body.extend_from_slice(&value.to_be_bytes());
                }
                write_extension(out, ext::SUPPORTED_VERSIONS, &body)
            }
            Self::EchGrease => {
                let mut body = Vec::with_capacity(64 + MAX_ECH_GREASE_PAYLOAD);
                session.ech_grease.write_body(&mut body);
                write_extension(out, ext::ENCRYPTED_CLIENT_HELLO, &body)
            }
        }
    }
}

/// RFC 7685 padding, in BoringSSL's shape.
///
/// `unpadded_len` is the length of the whole ClientHello handshake message —
/// its four-byte header included — with every extension but this one written.
/// Returns the number of zero bytes the padding extension carries, or `None`
/// when no padding extension is written at all.
///
/// The window exists because of TLS terminators that mishandle hellos of
/// 256..511 bytes; outside it BoringSSL emits nothing, not a zero-length
/// extension. A Chrome 133 hello carries a 1216-byte key share and is never in
/// the window — which is precisely why this is a rule that runs and not a
/// number someone measured once.
pub fn boring_padding(unpadded_len: usize) -> Option<usize> {
    if !(0x100..0x200).contains(&unpadded_len) {
        return None;
    }
    let deficit = 0x200 - unpadded_len;
    // The extension's own four-byte header counts towards the target, so the
    // body is the deficit minus that header. Under five bytes of deficit there
    // is no room for a header plus a body, and BoringSSL pads by one byte
    // rather than overshoot 512.
    Some(if deficit > 4 { deficit - 4 } else { 1 })
}

/// Write the padding extension for a hello of `unpadded_len` bytes.
pub fn write_padding(out: &mut Vec<u8>, unpadded_len: usize) -> io::Result<()> {
    match boring_padding(unpadded_len) {
        Some(length) => {
            out.extend_from_slice(&ext::PADDING.to_be_bytes());
            out.extend_from_slice(&(length as u16).to_be_bytes());
            out.resize(out.len() + length, 0);
            Ok(())
        }
        None => Ok(()),
    }
}

/// The order the extensions go out in.
///
/// Returns indices into `extensions`. Pinned slots keep their position; the
/// rest are permuted with a seeded Fisher-Yates so the result is reproducible
/// from the session.
pub fn extension_order(profile: &HelloProfileData<'_>, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..profile.extensions.len()).collect();
    if !profile.permute_extensions {
        return order;
    }
    let movable: Vec<usize> = order
        .iter()
        .copied()
        .filter(|index| !profile.extensions[*index].position_is_pinned())
        .collect();
    if movable.len() < 2 {
        return order;
    }
    let mut shuffled = movable.clone();
    let mut rng = SplitMix64(seed);
    for position in (1..shuffled.len()).rev() {
        let target = (rng.next() % (position as u64 + 1)) as usize;
        shuffled.swap(position, target);
    }
    for (slot, value) in movable.iter().zip(shuffled) {
        order[*slot] = value;
    }
    order
}

/// SplitMix64. Small, seedable and not a cryptographic generator — the seed
/// comes from the OS, and all this has to do is spread it over a permutation.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

// ------------------------------------------------------------ the profiles

/// `signature_algorithms`, the eight schemes Chrome offers, in Chrome's order.
const CHROME_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x10, // list length
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x05, 0x01, // rsa_pkcs1_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x06, 0x01, // rsa_pkcs1_sha512
];

const CHROME_151_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x16, // list length
    0x09, 0x04, // mldsa44
    0x09, 0x05, // mldsa65
    0x09, 0x06, // mldsa87
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x05, 0x01, // rsa_pkcs1_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x06, 0x01, // rsa_pkcs1_sha512
];

// Shared with the randomized generator to keep extension bytes identical.
/// `status_request`: OCSP, empty responder list, empty request extensions.
pub(super) const STATUS_REQUEST_BODY: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x00];
/// `ec_point_formats`: uncompressed only.
pub(super) const EC_POINT_FORMATS_BODY: &[u8] = &[0x01, 0x00];
/// `renegotiation_info`: an empty `renegotiated_connection`.
pub(super) const RENEGOTIATION_INFO_BODY: &[u8] = &[0x00];
/// `psk_key_exchange_modes`: `psk_dhe_ke` only.
pub(super) const PSK_KEY_EXCHANGE_MODES_BODY: &[u8] = &[0x01, 0x01];
/// `compress_certificate`: brotli (2) only.
///
/// Offered because Chrome offers it. This client does not implement RFC 8879,
/// so a server that answers with a CompressedCertificate is refused by name in
/// the handshake reader rather than silently mis-parsed.
const COMPRESS_CERTIFICATE_BODY: &[u8] = &[0x02, 0x00, 0x02];
/// `application_settings`: one protocol, `h2`.
pub(super) const APPLICATION_SETTINGS_BODY: &[u8] = &[0x00, 0x03, 0x02, b'h', b'2'];

const APPLE_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x14, // list length
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x08, 0x05, // rsa_pss_rsae_sha384 (again -- see above)
    0x05, 0x01, // rsa_pkcs1_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x06, 0x01, // rsa_pkcs1_sha512
    0x02, 0x01, // rsa_pkcs1_sha1
];

const IOS_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x16, // list length
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x02, 0x03, // ecdsa_sha1
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x08, 0x05, // rsa_pss_rsae_sha384 (again)
    0x05, 0x01, // rsa_pkcs1_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x06, 0x01, // rsa_pkcs1_sha512
    0x02, 0x01, // rsa_pkcs1_sha1
];

const COMPRESS_CERTIFICATE_ZLIB_BODY: &[u8] = &[0x02, 0x00, 0x01];

const CHROME_CIPHER_SUITES: &[CipherSuiteSlot] = &[
    CipherSuiteSlot::Grease,
    CipherSuiteSlot::Negotiable(0x1301), // TLS_AES_128_GCM_SHA256
    CipherSuiteSlot::Negotiable(0x1302), // TLS_AES_256_GCM_SHA384
    CipherSuiteSlot::Negotiable(0x1303), // TLS_CHACHA20_POLY1305_SHA256
    CipherSuiteSlot::Decorative(0xc02b), // ECDHE_ECDSA_AES_128_GCM_SHA256
    CipherSuiteSlot::Decorative(0xc02f), // ECDHE_RSA_AES_128_GCM_SHA256
    CipherSuiteSlot::Decorative(0xc02c), // ECDHE_ECDSA_AES_256_GCM_SHA384
    CipherSuiteSlot::Decorative(0xc030), // ECDHE_RSA_AES_256_GCM_SHA384
    CipherSuiteSlot::Decorative(0xcca9), // ECDHE_ECDSA_CHACHA20_POLY1305
    CipherSuiteSlot::Decorative(0xcca8), // ECDHE_RSA_CHACHA20_POLY1305
    CipherSuiteSlot::Decorative(0xc013), // ECDHE_RSA_AES_128_CBC_SHA
    CipherSuiteSlot::Decorative(0xc014), // ECDHE_RSA_AES_256_CBC_SHA
    CipherSuiteSlot::Decorative(0x009c), // RSA_AES_128_GCM_SHA256
    CipherSuiteSlot::Decorative(0x009d), // RSA_AES_256_GCM_SHA384
    CipherSuiteSlot::Decorative(0x002f), // RSA_AES_128_CBC_SHA
    CipherSuiteSlot::Decorative(0x0035), // RSA_AES_256_CBC_SHA
];

const CHROME_SUPPORTED_GROUPS: &[GroupSlot] = &[
    GroupSlot::Grease,
    GroupSlot::Group(NamedGroup::X25519MlKem768),
    GroupSlot::Group(NamedGroup::X25519),
    // Named because Chrome names them. This build sends no share for either and
    // refuses a ServerHello that selects one — see `validate_server_hello`.
    GroupSlot::Group(NamedGroup::Secp256r1),
    GroupSlot::Group(NamedGroup::Secp384r1),
];

const CHROME_KEY_SHARES: &[KeyShareSlot] = &[
    KeyShareSlot::Grease,
    KeyShareSlot::Group(NamedGroup::X25519MlKem768),
    KeyShareSlot::Group(NamedGroup::X25519),
];

const CHROME_SUPPORTED_VERSIONS: &[VersionSlot] = &[
    VersionSlot::Grease,
    VersionSlot::Version(TLS_1_3),
    // Chrome offers 1.2. This client speaks only 1.3 and refuses a server that
    // takes the offer; see the version lock in `validate_server_hello`.
    VersionSlot::Version(TLS_1_2),
];

macro_rules! chrome_extensions {
    ($application_settings:expr, $signature_algorithms:expr) => {
        &[
            ExtensionSlot::Grease {
                slot: GreaseSlot::Extension1,
                body: &[],
            },
            ExtensionSlot::ServerName,
            ExtensionSlot::Constant {
                extension_type: ext::EXTENDED_MASTER_SECRET,
                body: &[],
            },
            ExtensionSlot::Constant {
                extension_type: ext::RENEGOTIATION_INFO,
                body: RENEGOTIATION_INFO_BODY,
            },
            ExtensionSlot::SupportedGroups(CHROME_SUPPORTED_GROUPS),
            ExtensionSlot::Constant {
                extension_type: ext::EC_POINT_FORMATS,
                body: EC_POINT_FORMATS_BODY,
            },
            ExtensionSlot::Constant {
                extension_type: ext::SESSION_TICKET,
                body: &[],
            },
            ExtensionSlot::Alpn,
            ExtensionSlot::Constant {
                extension_type: ext::STATUS_REQUEST,
                body: STATUS_REQUEST_BODY,
            },
            ExtensionSlot::Constant {
                extension_type: ext::SIGNATURE_ALGORITHMS,
                body: $signature_algorithms,
            },
            ExtensionSlot::Constant {
                extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
                body: &[],
            },
            ExtensionSlot::KeyShare(CHROME_KEY_SHARES),
            ExtensionSlot::Constant {
                extension_type: ext::PSK_KEY_EXCHANGE_MODES,
                body: PSK_KEY_EXCHANGE_MODES_BODY,
            },
            ExtensionSlot::SupportedVersions(CHROME_SUPPORTED_VERSIONS),
            ExtensionSlot::Constant {
                extension_type: ext::COMPRESS_CERTIFICATE,
                body: COMPRESS_CERTIFICATE_BODY,
            },
            ExtensionSlot::Constant {
                extension_type: $application_settings,
                body: APPLICATION_SETTINGS_BODY,
            },
            ExtensionSlot::EchGrease,
            ExtensionSlot::Grease {
                slot: GreaseSlot::Extension2,
                body: &[0x00],
            },
            ExtensionSlot::Padding,
        ]
    };
}

pub static CHROME_151: HelloProfile = HelloProfile {
    name: "chrome_151",
    cipher_suites: CHROME_CIPHER_SUITES,
    extensions: chrome_extensions!(ext::APPLICATION_SETTINGS, CHROME_151_SIGNATURE_ALGORITHMS),
    permute_extensions: true,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

pub static CHROME_133: HelloProfile = HelloProfile {
    name: "chrome_133",
    cipher_suites: CHROME_CIPHER_SUITES,
    extensions: chrome_extensions!(ext::APPLICATION_SETTINGS, CHROME_SIGNATURE_ALGORITHMS),
    permute_extensions: true,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

pub static CHROME_131: HelloProfile = HelloProfile {
    name: "chrome_131",
    cipher_suites: CHROME_CIPHER_SUITES,
    extensions: chrome_extensions!(ext::APPLICATION_SETTINGS_OLD, CHROME_SIGNATURE_ALGORITHMS),
    permute_extensions: true,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

const CHROMIUM_FORK_CIPHER_SUITES: &[CipherSuiteSlot] = CHROME_CIPHER_SUITES;

const CHROMIUM_FORK_SUPPORTED_GROUPS: &[GroupSlot] = &[
    GroupSlot::Grease,
    GroupSlot::Group(NamedGroup::X25519),
    GroupSlot::Group(NamedGroup::Secp256r1),
    GroupSlot::Group(NamedGroup::Secp384r1),
];

const CHROMIUM_FORK_KEY_SHARES: &[KeyShareSlot] = &[
    KeyShareSlot::Grease,
    KeyShareSlot::Group(NamedGroup::X25519),
];

const CHROMIUM_FORK_SUPPORTED_VERSIONS: &[VersionSlot] = &[
    VersionSlot::Grease,
    VersionSlot::Version(TLS_1_3),
    VersionSlot::Version(TLS_1_2),
    VersionSlot::Version(TLS_1_1),
    VersionSlot::Version(TLS_1_0),
];

pub static EDGE_85: HelloProfile = HelloProfile {
    name: "edge_85",
    cipher_suites: CHROMIUM_FORK_CIPHER_SUITES,
    extensions: &[
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension1,
            body: &[],
        },
        ExtensionSlot::ServerName,
        ExtensionSlot::Constant {
            extension_type: ext::EXTENDED_MASTER_SECRET,
            body: &[],
        },
        ExtensionSlot::Constant {
            extension_type: ext::RENEGOTIATION_INFO,
            body: RENEGOTIATION_INFO_BODY,
        },
        ExtensionSlot::SupportedGroups(CHROMIUM_FORK_SUPPORTED_GROUPS),
        ExtensionSlot::Constant {
            extension_type: ext::EC_POINT_FORMATS,
            body: EC_POINT_FORMATS_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SESSION_TICKET,
            body: &[],
        },
        ExtensionSlot::Alpn,
        ExtensionSlot::Constant {
            extension_type: ext::STATUS_REQUEST,
            body: STATUS_REQUEST_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNATURE_ALGORITHMS,
            body: CHROME_SIGNATURE_ALGORITHMS,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
            body: &[],
        },
        ExtensionSlot::KeyShare(CHROMIUM_FORK_KEY_SHARES),
        ExtensionSlot::Constant {
            extension_type: ext::PSK_KEY_EXCHANGE_MODES,
            body: PSK_KEY_EXCHANGE_MODES_BODY,
        },
        ExtensionSlot::SupportedVersions(CHROMIUM_FORK_SUPPORTED_VERSIONS),
        ExtensionSlot::Constant {
            extension_type: ext::COMPRESS_CERTIFICATE,
            body: COMPRESS_CERTIFICATE_BODY,
        },
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension2,
            body: &[0x00],
        },
        ExtensionSlot::Padding,
    ],
    permute_extensions: false,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

pub static QQ_11_1: HelloProfile = HelloProfile {
    name: "qq_11_1",
    cipher_suites: CHROMIUM_FORK_CIPHER_SUITES,
    extensions: &[
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension1,
            body: &[],
        },
        ExtensionSlot::ServerName,
        ExtensionSlot::Constant {
            extension_type: ext::EXTENDED_MASTER_SECRET,
            body: &[],
        },
        ExtensionSlot::Constant {
            extension_type: ext::RENEGOTIATION_INFO,
            body: RENEGOTIATION_INFO_BODY,
        },
        ExtensionSlot::SupportedGroups(CHROMIUM_FORK_SUPPORTED_GROUPS),
        ExtensionSlot::Constant {
            extension_type: ext::EC_POINT_FORMATS,
            body: EC_POINT_FORMATS_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SESSION_TICKET,
            body: &[],
        },
        ExtensionSlot::Alpn,
        ExtensionSlot::Constant {
            extension_type: ext::STATUS_REQUEST,
            body: STATUS_REQUEST_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNATURE_ALGORITHMS,
            body: CHROME_SIGNATURE_ALGORITHMS,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
            body: &[],
        },
        ExtensionSlot::KeyShare(CHROMIUM_FORK_KEY_SHARES),
        ExtensionSlot::Constant {
            extension_type: ext::PSK_KEY_EXCHANGE_MODES,
            body: PSK_KEY_EXCHANGE_MODES_BODY,
        },
        ExtensionSlot::SupportedVersions(CHROMIUM_FORK_SUPPORTED_VERSIONS),
        ExtensionSlot::Constant {
            extension_type: ext::COMPRESS_CERTIFICATE,
            body: COMPRESS_CERTIFICATE_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::APPLICATION_SETTINGS_OLD,
            body: APPLICATION_SETTINGS_BODY,
        },
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension2,
            body: &[0x00],
        },
        ExtensionSlot::Padding,
    ],
    permute_extensions: false,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

const SAFARI_CIPHER_SUITES: &[CipherSuiteSlot] = &[
    CipherSuiteSlot::Grease,
    CipherSuiteSlot::Negotiable(0x1302), // TLS_AES_256_GCM_SHA384
    CipherSuiteSlot::Negotiable(0x1303), // TLS_CHACHA20_POLY1305_SHA256
    CipherSuiteSlot::Negotiable(0x1301), // TLS_AES_128_GCM_SHA256
    CipherSuiteSlot::Decorative(0xc02c),
    CipherSuiteSlot::Decorative(0xc02b),
    CipherSuiteSlot::Decorative(0xcca9),
    CipherSuiteSlot::Decorative(0xc030),
    CipherSuiteSlot::Decorative(0xc02f),
    CipherSuiteSlot::Decorative(0xcca8),
    CipherSuiteSlot::Decorative(0xc00a),
    CipherSuiteSlot::Decorative(0xc009),
    CipherSuiteSlot::Decorative(0xc014),
    CipherSuiteSlot::Decorative(0xc013),
    CipherSuiteSlot::Decorative(0x009d),
    CipherSuiteSlot::Decorative(0x009c),
    CipherSuiteSlot::Decorative(0x0035),
    CipherSuiteSlot::Decorative(0x002f),
    CipherSuiteSlot::Decorative(0xc008), // ECDHE_ECDSA_3DES_EDE_CBC_SHA
    CipherSuiteSlot::Decorative(0xc012), // ECDHE_RSA_3DES_EDE_CBC_SHA
    CipherSuiteSlot::Decorative(0x000a), // RSA_3DES_EDE_CBC_SHA
];

const APPLE_SUPPORTED_GROUPS: &[GroupSlot] = &[
    GroupSlot::Grease,
    GroupSlot::Group(NamedGroup::X25519MlKem768),
    GroupSlot::Group(NamedGroup::X25519),
    GroupSlot::Group(NamedGroup::Secp256r1),
    GroupSlot::Group(NamedGroup::Secp384r1),
    GroupSlot::Group(NamedGroup::Secp521r1),
];

const SAFARI_KEY_SHARES: &[KeyShareSlot] = &[
    KeyShareSlot::Grease,
    KeyShareSlot::Group(NamedGroup::X25519MlKem768),
    KeyShareSlot::Group(NamedGroup::X25519),
];

const SAFARI_SUPPORTED_VERSIONS: &[VersionSlot] = &[
    VersionSlot::Grease,
    VersionSlot::Version(TLS_1_3),
    VersionSlot::Version(TLS_1_2),
];

pub static SAFARI_26_3: HelloProfile = HelloProfile {
    name: "safari_26_3",
    cipher_suites: SAFARI_CIPHER_SUITES,
    extensions: &[
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension1,
            body: &[],
        },
        ExtensionSlot::ServerName,
        ExtensionSlot::Constant {
            extension_type: ext::EXTENDED_MASTER_SECRET,
            body: &[],
        },
        ExtensionSlot::Constant {
            extension_type: ext::RENEGOTIATION_INFO,
            body: RENEGOTIATION_INFO_BODY,
        },
        ExtensionSlot::SupportedGroups(APPLE_SUPPORTED_GROUPS),
        ExtensionSlot::Constant {
            extension_type: ext::EC_POINT_FORMATS,
            body: EC_POINT_FORMATS_BODY,
        },
        ExtensionSlot::Alpn,
        ExtensionSlot::Constant {
            extension_type: ext::STATUS_REQUEST,
            body: STATUS_REQUEST_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNATURE_ALGORITHMS,
            body: APPLE_SIGNATURE_ALGORITHMS,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
            body: &[],
        },
        ExtensionSlot::KeyShare(SAFARI_KEY_SHARES),
        ExtensionSlot::Constant {
            extension_type: ext::PSK_KEY_EXCHANGE_MODES,
            body: PSK_KEY_EXCHANGE_MODES_BODY,
        },
        ExtensionSlot::SupportedVersions(SAFARI_SUPPORTED_VERSIONS),
        ExtensionSlot::Constant {
            extension_type: ext::COMPRESS_CERTIFICATE,
            body: COMPRESS_CERTIFICATE_ZLIB_BODY,
        },
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension2,
            body: &[0x00],
        },
    ],
    permute_extensions: false,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

const IOS_CIPHER_SUITES: &[CipherSuiteSlot] = &[
    CipherSuiteSlot::Grease,
    CipherSuiteSlot::Negotiable(0x1301),
    CipherSuiteSlot::Negotiable(0x1302),
    CipherSuiteSlot::Negotiable(0x1303),
    CipherSuiteSlot::Decorative(0xc02c),
    CipherSuiteSlot::Decorative(0xc02b),
    CipherSuiteSlot::Decorative(0xcca9),
    CipherSuiteSlot::Decorative(0xc030),
    CipherSuiteSlot::Decorative(0xc02f),
    CipherSuiteSlot::Decorative(0xcca8),
    CipherSuiteSlot::Decorative(0xc024),
    CipherSuiteSlot::Decorative(0xc023),
    CipherSuiteSlot::Decorative(0xc00a),
    CipherSuiteSlot::Decorative(0xc009),
    CipherSuiteSlot::Decorative(0xc028),
    CipherSuiteSlot::Decorative(0xc027),
    CipherSuiteSlot::Decorative(0xc014),
    CipherSuiteSlot::Decorative(0xc013),
    CipherSuiteSlot::Decorative(0x009d),
    CipherSuiteSlot::Decorative(0x009c),
    CipherSuiteSlot::Decorative(0x003d),
    CipherSuiteSlot::Decorative(0x003c),
    CipherSuiteSlot::Decorative(0x0035),
    CipherSuiteSlot::Decorative(0x002f),
    CipherSuiteSlot::Decorative(0xc008),
    CipherSuiteSlot::Decorative(0xc012),
    CipherSuiteSlot::Decorative(0x000a),
];

const IOS_SUPPORTED_GROUPS: &[GroupSlot] = &[
    GroupSlot::Grease,
    GroupSlot::Group(NamedGroup::X25519),
    GroupSlot::Group(NamedGroup::Secp256r1),
    GroupSlot::Group(NamedGroup::Secp384r1),
    GroupSlot::Group(NamedGroup::Secp521r1),
];

pub static IOS_14: HelloProfile = HelloProfile {
    name: "ios_14",
    cipher_suites: IOS_CIPHER_SUITES,
    extensions: &[
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension1,
            body: &[],
        },
        ExtensionSlot::ServerName,
        ExtensionSlot::Constant {
            extension_type: ext::EXTENDED_MASTER_SECRET,
            body: &[],
        },
        ExtensionSlot::Constant {
            extension_type: ext::RENEGOTIATION_INFO,
            body: RENEGOTIATION_INFO_BODY,
        },
        ExtensionSlot::SupportedGroups(IOS_SUPPORTED_GROUPS),
        ExtensionSlot::Constant {
            extension_type: ext::EC_POINT_FORMATS,
            body: EC_POINT_FORMATS_BODY,
        },
        ExtensionSlot::Alpn,
        ExtensionSlot::Constant {
            extension_type: ext::STATUS_REQUEST,
            body: STATUS_REQUEST_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNATURE_ALGORITHMS,
            body: IOS_SIGNATURE_ALGORITHMS,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
            body: &[],
        },
        ExtensionSlot::KeyShare(CHROMIUM_FORK_KEY_SHARES),
        ExtensionSlot::Constant {
            extension_type: ext::PSK_KEY_EXCHANGE_MODES,
            body: PSK_KEY_EXCHANGE_MODES_BODY,
        },
        ExtensionSlot::SupportedVersions(CHROMIUM_FORK_SUPPORTED_VERSIONS),
        ExtensionSlot::Grease {
            slot: GreaseSlot::Extension2,
            body: &[0x00],
        },
        ExtensionSlot::Padding,
    ],
    permute_extensions: false,
    ech_grease: CHROME_ECH_GREASE,
    reuse_classical_key_share: false,
};

const FIREFOX_CIPHER_SUITES: &[CipherSuiteSlot] = &[
    CipherSuiteSlot::Negotiable(0x1301), // TLS_AES_128_GCM_SHA256
    CipherSuiteSlot::Negotiable(0x1303), // TLS_CHACHA20_POLY1305_SHA256
    CipherSuiteSlot::Negotiable(0x1302), // TLS_AES_256_GCM_SHA384
    CipherSuiteSlot::Decorative(0xc02b),
    CipherSuiteSlot::Decorative(0xc02f),
    CipherSuiteSlot::Decorative(0xcca9),
    CipherSuiteSlot::Decorative(0xcca8),
    CipherSuiteSlot::Decorative(0xc02c),
    CipherSuiteSlot::Decorative(0xc030),
    CipherSuiteSlot::Decorative(0xc00a),
    CipherSuiteSlot::Decorative(0xc009),
    CipherSuiteSlot::Decorative(0xc013),
    CipherSuiteSlot::Decorative(0xc014),
    CipherSuiteSlot::Decorative(0x009c),
    CipherSuiteSlot::Decorative(0x009d),
    CipherSuiteSlot::Decorative(0x002f),
    CipherSuiteSlot::Decorative(0x0035),
];

const FIREFOX_SUPPORTED_GROUPS: &[GroupSlot] = &[
    GroupSlot::Group(NamedGroup::X25519MlKem768),
    GroupSlot::Group(NamedGroup::X25519),
    GroupSlot::Group(NamedGroup::Secp256r1),
    GroupSlot::Group(NamedGroup::Secp384r1),
    GroupSlot::Group(NamedGroup::Secp521r1),
    GroupSlot::Group(NamedGroup::Ffdhe2048),
    GroupSlot::Group(NamedGroup::Ffdhe3072),
];

const FIREFOX_KEY_SHARES: &[KeyShareSlot] = &[
    KeyShareSlot::Group(NamedGroup::X25519MlKem768),
    KeyShareSlot::Group(NamedGroup::X25519),
    KeyShareSlot::Group(NamedGroup::Secp256r1),
];

const FIREFOX_SUPPORTED_VERSIONS: &[VersionSlot] =
    &[VersionSlot::Version(TLS_1_3), VersionSlot::Version(TLS_1_2)];

const FIREFOX_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x16, // list length
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x06, 0x03, // ecdsa_secp521r1_sha512
    0x08, 0x04, // rsa_pss_rsae_sha256
    0x08, 0x05, // rsa_pss_rsae_sha384
    0x08, 0x06, // rsa_pss_rsae_sha512
    0x04, 0x01, // rsa_pkcs1_sha256
    0x05, 0x01, // rsa_pkcs1_sha384
    0x06, 0x01, // rsa_pkcs1_sha512
    0x02, 0x03, // ecdsa_sha1
    0x02, 0x01, // rsa_pkcs1_sha1
];

const FIREFOX_DELEGATED_CREDENTIALS_BODY: &[u8] = &[
    0x00, 0x08, // list length
    0x04, 0x03, // ecdsa_secp256r1_sha256
    0x05, 0x03, // ecdsa_secp384r1_sha384
    0x06, 0x03, // ecdsa_secp521r1_sha512
    0x02, 0x03, // ecdsa_sha1
];

const FIREFOX_RECORD_SIZE_LIMIT_BODY: &[u8] = &[0x40, 0x01];

const FIREFOX_COMPRESS_CERTIFICATE_BODY: &[u8] = &[0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];

pub static FIREFOX_148: HelloProfile = HelloProfile {
    name: "firefox_148",
    cipher_suites: FIREFOX_CIPHER_SUITES,
    extensions: &[
        ExtensionSlot::ServerName,
        ExtensionSlot::Constant {
            extension_type: ext::EXTENDED_MASTER_SECRET,
            body: &[],
        },
        ExtensionSlot::Constant {
            extension_type: ext::RENEGOTIATION_INFO,
            body: RENEGOTIATION_INFO_BODY,
        },
        ExtensionSlot::SupportedGroups(FIREFOX_SUPPORTED_GROUPS),
        ExtensionSlot::Constant {
            extension_type: ext::EC_POINT_FORMATS,
            body: EC_POINT_FORMATS_BODY,
        },
        ExtensionSlot::Alpn,
        ExtensionSlot::Constant {
            extension_type: ext::STATUS_REQUEST,
            body: STATUS_REQUEST_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::DELEGATED_CREDENTIALS,
            body: FIREFOX_DELEGATED_CREDENTIALS_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
            body: &[],
        },
        ExtensionSlot::KeyShare(FIREFOX_KEY_SHARES),
        ExtensionSlot::SupportedVersions(FIREFOX_SUPPORTED_VERSIONS),
        ExtensionSlot::Constant {
            extension_type: ext::SIGNATURE_ALGORITHMS,
            body: FIREFOX_SIGNATURE_ALGORITHMS,
        },
        ExtensionSlot::Constant {
            extension_type: ext::RECORD_SIZE_LIMIT,
            body: FIREFOX_RECORD_SIZE_LIMIT_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::COMPRESS_CERTIFICATE,
            body: FIREFOX_COMPRESS_CERTIFICATE_BODY,
        },
        ExtensionSlot::EchGrease,
    ],
    permute_extensions: false,
    ech_grease: FIREFOX_ECH_GREASE,
    reuse_classical_key_share: true,
};

const FIREFOX_153_CIPHER_SUITES: &[CipherSuiteSlot] = &[
    CipherSuiteSlot::Negotiable(0x1301), // TLS_AES_128_GCM_SHA256
    CipherSuiteSlot::Negotiable(0x1303), // TLS_CHACHA20_POLY1305_SHA256
    CipherSuiteSlot::Negotiable(0x1302), // TLS_AES_256_GCM_SHA384
    CipherSuiteSlot::Decorative(0xc02b),
    CipherSuiteSlot::Decorative(0xc02f),
    CipherSuiteSlot::Decorative(0xcca9),
    CipherSuiteSlot::Decorative(0xcca8),
    CipherSuiteSlot::Decorative(0xc02c),
    CipherSuiteSlot::Decorative(0xc030),
    CipherSuiteSlot::Decorative(0xc00a),
    CipherSuiteSlot::Decorative(0xc013),
    CipherSuiteSlot::Decorative(0xc014),
    CipherSuiteSlot::Decorative(0x009c),
    CipherSuiteSlot::Decorative(0x009d),
    CipherSuiteSlot::Decorative(0x002f),
    CipherSuiteSlot::Decorative(0x0035),
];

pub static FIREFOX_153: HelloProfile = HelloProfile {
    name: "firefox_153",
    cipher_suites: FIREFOX_153_CIPHER_SUITES,
    extensions: &[
        ExtensionSlot::ServerName,
        ExtensionSlot::Constant {
            extension_type: ext::EXTENDED_MASTER_SECRET,
            body: &[],
        },
        ExtensionSlot::Constant {
            extension_type: ext::RENEGOTIATION_INFO,
            body: RENEGOTIATION_INFO_BODY,
        },
        ExtensionSlot::SupportedGroups(FIREFOX_SUPPORTED_GROUPS),
        ExtensionSlot::Constant {
            extension_type: ext::EC_POINT_FORMATS,
            body: EC_POINT_FORMATS_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SESSION_TICKET,
            body: &[],
        },
        ExtensionSlot::Alpn,
        ExtensionSlot::Constant {
            extension_type: ext::STATUS_REQUEST,
            body: STATUS_REQUEST_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::DELEGATED_CREDENTIALS,
            body: FIREFOX_DELEGATED_CREDENTIALS_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::SIGNED_CERTIFICATE_TIMESTAMP,
            body: &[],
        },
        ExtensionSlot::KeyShare(FIREFOX_KEY_SHARES),
        ExtensionSlot::SupportedVersions(FIREFOX_SUPPORTED_VERSIONS),
        ExtensionSlot::Constant {
            extension_type: ext::SIGNATURE_ALGORITHMS,
            body: FIREFOX_SIGNATURE_ALGORITHMS,
        },
        ExtensionSlot::Constant {
            extension_type: ext::PSK_KEY_EXCHANGE_MODES,
            body: PSK_KEY_EXCHANGE_MODES_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::RECORD_SIZE_LIMIT,
            body: FIREFOX_RECORD_SIZE_LIMIT_BODY,
        },
        ExtensionSlot::Constant {
            extension_type: ext::COMPRESS_CERTIFICATE,
            body: FIREFOX_COMPRESS_CERTIFICATE_BODY,
        },
        ExtensionSlot::EchGrease,
    ],
    permute_extensions: false,
    ech_grease: FIREFOX_ECH_GREASE,
    reuse_classical_key_share: true,
};

pub const CHROME_ALPN_PROTOCOLS: &[&str] = &["h2", "http/1.1"];

/// Legacy `compression_methods`: null only.
pub const COMPRESSION_METHODS: &[u8] = &[0x01, 0x00];

/// `legacy_version` in the ClientHello body, always TLS 1.2 in TLS 1.3.
pub const LEGACY_VERSION: [u8; 2] = [VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR];

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_grease() -> GreaseValues {
        GreaseValues::from_seed([0x00, 0x1f, 0x2c, 0x30, 0x4d])
    }

    #[test]
    fn grease_values_have_the_repeated_byte_shape() {
        let grease = seeded_grease();
        for slot in [
            GreaseSlot::Cipher,
            GreaseSlot::Group,
            GreaseSlot::Version,
            GreaseSlot::Extension1,
            GreaseSlot::Extension2,
        ] {
            let value = grease.value(slot);
            let [high, low] = value.to_be_bytes();
            assert_eq!(high, low, "GREASE repeats the byte: {value:#06x}");
            assert_eq!(low & 0x0f, 0x0a, "the low nibble is always a: {value:#06x}");
            assert!(is_grease(value), "{value:#06x} is not a reserved point");
        }
        assert_eq!(grease.value(GreaseSlot::Cipher), 0x0a0a);
        assert_eq!(grease.value(GreaseSlot::Group), 0x1a1a);
        assert_eq!(grease.value(GreaseSlot::Version), 0x2a2a);
        assert_eq!(grease.value(GreaseSlot::Extension1), 0x3a3a);
        assert_eq!(grease.value(GreaseSlot::Extension2), 0x4a4a);
    }

    #[test]
    fn the_two_grease_extensions_never_collide() {
        // Same high nibble in both extension seeds: BoringSSL flips a bit
        // rather than send the same unknown extension type twice.
        let grease = GreaseValues::from_seed([0, 0, 0, 0x70, 0x7f]);
        assert_ne!(
            grease.value(GreaseSlot::Extension1),
            grease.value(GreaseSlot::Extension2)
        );
        for high in 0..16_u8 {
            let seed = [0, 0, 0, high << 4, high << 4];
            let grease = GreaseValues::from_seed(seed);
            assert_ne!(
                grease.value(GreaseSlot::Extension1),
                grease.value(GreaseSlot::Extension2),
                "collision at high nibble {high:#x}"
            );
        }
    }

    #[test]
    fn every_shipped_profile_validates() {
        for profile in [&CHROME_133, &CHROME_131] {
            profile.validate().unwrap_or_else(|error| {
                panic!("{} does not validate: {error}", profile.name);
            });
            assert_eq!(profile.negotiable_cipher_suites().len(), 3);
            assert_eq!(
                profile.key_share_groups(),
                vec![NamedGroup::X25519MlKem768, NamedGroup::X25519]
            );
        }
    }

    #[test]
    fn a_profile_offering_an_unimplemented_cipher_is_refused() {
        // The whole point of the reconciliation: a table edit that offers a
        // suite `CipherSuite::from_id` does not know fails here, not on a
        // ServerHello months later.
        static BAD: HelloProfile = HelloProfile {
            name: "test_bad_cipher",
            cipher_suites: &[CipherSuiteSlot::Negotiable(0x1304)],
            extensions: &[],
            permute_extensions: false,
            ech_grease: CHROME_ECH_GREASE,
            reuse_classical_key_share: false,
        };
        let error = BAD.validate().expect_err("0x1304 is not implemented");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("0x1304"), "{error}");

        static ALSO_BAD: HelloProfile = HelloProfile {
            name: "test_decorative_but_implemented",
            cipher_suites: &[
                CipherSuiteSlot::Negotiable(0x1301),
                CipherSuiteSlot::Decorative(0x1303),
            ],
            extensions: &[],
            permute_extensions: false,
            ech_grease: CHROME_ECH_GREASE,
            reuse_classical_key_share: false,
        };
        let error = ALSO_BAD
            .validate()
            .expect_err("a suite this build implements must not be marked decoration");
        assert!(error.to_string().contains("0x1303"), "{error}");
    }

    #[test]
    fn a_profile_sending_an_unexecutable_key_share_is_refused() {
        static BAD: HelloProfile = HelloProfile {
            name: "test_bad_group",
            cipher_suites: &[CipherSuiteSlot::Negotiable(0x1301)],
            extensions: &[ExtensionSlot::KeyShare(&[KeyShareSlot::Group(
                NamedGroup::Secp384r1,
            )])],
            permute_extensions: false,
            ech_grease: CHROME_ECH_GREASE,
            reuse_classical_key_share: false,
        };
        let error = BAD.validate().expect_err("secp384r1 shares are not sent");
        assert!(error.to_string().contains("secp384r1"), "{error}");
    }

    #[test]
    fn padding_only_fires_inside_the_boring_window() {
        assert_eq!(boring_padding(0xff), None);
        assert_eq!(boring_padding(0x200), None);
        assert_eq!(boring_padding(1700), None, "a hello with an ML-KEM share");
        // 0x100 short of the target: 256 bytes of deficit, four of which are
        // the extension header.
        assert_eq!(boring_padding(0x100), Some(0x100 - 4));
        assert_eq!(boring_padding(0x1f0), Some(16 - 4));
        // Not enough room for a header: one byte rather than an overshoot.
        assert_eq!(boring_padding(0x1ff), Some(1));
        assert_eq!(boring_padding(0x1fc), Some(1));

        // And the emitted extension is exactly that many zero bytes.
        let mut out = Vec::new();
        write_padding(&mut out, 0x1f0).unwrap();
        assert_eq!(&out[..2], &ext::PADDING.to_be_bytes());
        assert_eq!(u16::from_be_bytes([out[2], out[3]]) as usize, 12);
        assert_eq!(out.len(), 4 + 12);
        assert!(out[4..].iter().all(|byte| *byte == 0));

        let mut nothing = Vec::new();
        write_padding(&mut nothing, 1700).unwrap();
        assert!(nothing.is_empty(), "no zero-length padding extension");
    }

    #[test]
    fn permutation_keeps_grease_and_padding_where_they_are() {
        let profile = &CHROME_133;
        let pinned: Vec<usize> = profile
            .extensions
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.position_is_pinned())
            .map(|(index, _)| index)
            .collect();
        assert_eq!(pinned.len(), 3, "two GREASE slots and padding");

        let mut orders = std::collections::HashSet::new();
        for seed in 0..64_u64 {
            let order = extension_order(profile, seed);
            assert_eq!(order.len(), profile.extensions.len());
            let unique: std::collections::HashSet<usize> = order.iter().copied().collect();
            assert_eq!(
                unique.len(),
                order.len(),
                "the permutation must be a bijection"
            );
            for index in &pinned {
                assert_eq!(order[*index], *index, "pinned slot {index} moved");
            }
            orders.insert(order);
        }
        assert!(
            orders.len() > 1,
            "a permutation that never permutes is a fixed order with extra steps"
        );
    }

    #[test]
    fn ech_grease_body_matches_the_draft_shape() {
        let mut rng = rand::rng();
        let params = EchGreaseParams::new([0x5a_u8; 32], &mut rng);
        let mut body = Vec::new();
        params.write_body(&mut body);

        assert_eq!(body[0], 0x00, "ECHClientHello.type = outer");
        let kdf = u16::from_be_bytes([body[1], body[2]]);
        let aead = u16::from_be_bytes([body[3], body[4]]);
        assert_eq!((kdf, aead), ECH_GREASE_SUITE);
        let enc_len = u16::from_be_bytes([body[6], body[7]]) as usize;
        assert_eq!(enc_len, 32);
        assert_eq!(&body[8..8 + 32], &[0x5a_u8; 32]);
        let payload_len = u16::from_be_bytes([body[40], body[41]]) as usize;
        assert!(
            CHROME_ECH_GREASE
                .payload_lens
                .iter()
                .any(|candidate| candidate + ECH_GREASE_TAG_LEN == payload_len),
            "payload {payload_len} is not a candidate length plus the AEAD tag"
        );
        assert_eq!(body.len(), 42 + payload_len);
    }

    #[test]
    fn the_two_chrome_profiles_differ_only_in_the_alps_code_point() {
        let points = |profile: &HelloProfile| -> Vec<u16> {
            profile
                .extensions
                .iter()
                .map(|slot| match slot {
                    ExtensionSlot::Constant { extension_type, .. } => *extension_type,
                    _ => 0xffff,
                })
                .collect()
        };
        let a = points(&CHROME_133);
        let b = points(&CHROME_131);
        let differences: Vec<(u16, u16)> = a
            .iter()
            .zip(&b)
            .filter(|(x, y)| x != y)
            .map(|(x, y)| (*x, *y))
            .collect();
        assert_eq!(
            differences,
            vec![(ext::APPLICATION_SETTINGS, ext::APPLICATION_SETTINGS_OLD)]
        );
    }
}
