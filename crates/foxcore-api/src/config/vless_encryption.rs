//! The `encryption=` grammar.
//!
//! Upstream (`infra/conf/vless.go`, client branch):
//!
//! ```text
//! mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>[.<padding>...].<key>[.<key>...]
//! ```
//!
//! Every field is dot-separated. The first three are fixed. What follows is a
//! run of padding parameters — recognised purely by being shorter than 20
//! characters — and then one or more base64url keys, each decoding to 32 bytes
//! (an X25519 public key) or 1184 bytes (an ML-KEM-768 encapsulation key).
//! More than one key is a relay chain; the last entry is the server itself.
//!
//! The parser's job here is to be *specific*. A profile carrying a variant this
//! client does not implement has to be refused by name — `mlkem1024x448plus`,
//! or a fourth appearance mode — so the operator can read what happened,
//! rather than being told "VLESS encryption must be none".

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The only key-exchange suite upstream defines. The name is deliberately
/// open-ended (`plus`) so further exchanges can be added later; a client that
/// does not know the suite must refuse it rather than guess.
pub const VLESS_ENCRYPTION_SUITE: &str = "mlkem768x25519plus";

/// X25519 public key, RFC 7748.
pub const VLESS_ENCRYPTION_X25519_KEY_LEN: usize = 32;
/// ML-KEM-768 encapsulation key, FIPS 203.
pub const VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN: usize = 1184;
/// ML-KEM-768 ciphertext, FIPS 203.
pub const VLESS_ENCRYPTION_ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 shared secret, FIPS 203.
pub const VLESS_ENCRYPTION_ML_KEM_768_SECRET_LEN: usize = 32;

/// Upstream classifies a field as a padding parameter rather than a key purely
/// by length. Reproduced exactly: a shorter token is padding, anything from 20
/// characters up must be a key.
const PADDING_FIELD_MAX_LEN: usize = 20;

/// `ParsePadding`: the first length parameter must be able to hold an 18-byte
/// encrypted length plus a 17-byte minimum AEAD payload.
const MIN_FIRST_PADDING: u32 = 18 + 17;

/// `ParsePadding`: the encrypted padding length is a `u16`, so the sum of the
/// per-chunk maxima cannot exceed what that can describe.
const MAX_TOTAL_PADDING: u64 = 18 + 65535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessEncryptionError {
    /// A well-formed value naming something this client does not implement.
    Unsupported(String),
    /// A value that does not parse at all.
    Invalid(String),
}

impl fmt::Display for VlessEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for VlessEncryptionError {}

impl VlessEncryptionError {
    /// True when the value parses but names a variant this build does not
    /// implement, as opposed to being malformed. Callers use this to say which
    /// of the two happened rather than collapsing both into "bad profile".
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }
}

/// How much of the connection is made to look like random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessEncryptionMode {
    /// Nothing is masked: X25519 public keys and ML-KEM ciphertexts keep their
    /// own shape, and every record carries a TLS 1.3 `23 03 03 len` header.
    Native = 0,
    /// The public key material in `ivAndRelays` is masked, record headers are
    /// not.
    XorPub = 1,
    /// Public key material and every record header are masked, so the whole
    /// connection is indistinguishable from random bytes.
    Random = 2,
}

/// One relay hop's long-term public key. The last entry of a chain is the
/// server. The variant also decides the hop's wire size: an X25519 hop puts a
/// 32-byte ephemeral public key on the wire, an ML-KEM hop a 1088-byte
/// ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessEncryptionKey {
    X25519([u8; VLESS_ENCRYPTION_X25519_KEY_LEN]),
    MlKem768(Box<[u8; VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN]>),
}

impl VlessEncryptionKey {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::X25519(key) => key.as_slice(),
            Self::MlKem768(key) => key.as_slice(),
        }
    }

    /// Bytes this hop contributes to `ivAndRelays` before the 32-byte link to
    /// the next hop.
    pub fn relay_len(&self) -> usize {
        match self {
            Self::X25519(_) => VLESS_ENCRYPTION_X25519_KEY_LEN,
            Self::MlKem768(_) => VLESS_ENCRYPTION_ML_KEM_768_CIPHERTEXT_LEN,
        }
    }
}

/// A `probability-from-to` triple. `probability` is compared against a fresh
/// draw from `0..=100`, so 100 always fires and 0 fires one time in 101.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlessEncryptionPaddingRange {
    pub probability: u32,
    pub from: u32,
    pub to: u32,
}

/// 1-RTT padding schedule: alternating length and gap parameters, lengths at
/// even positions. Empty means upstream's default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VlessEncryptionPadding {
    pub lens: Vec<VlessEncryptionPaddingRange>,
    pub gaps: Vec<VlessEncryptionPaddingRange>,
}

impl VlessEncryptionPadding {
    /// `CreatPadding`'s fallback: 100% of 111..=1111 bytes, then 75% of a
    /// 0..=111 ms gap, then 50% of a further 0..=3333 bytes.
    pub fn resolved(
        &self,
    ) -> (
        Vec<VlessEncryptionPaddingRange>,
        Vec<VlessEncryptionPaddingRange>,
    ) {
        if self.lens.is_empty() {
            return (
                vec![
                    VlessEncryptionPaddingRange {
                        probability: 100,
                        from: 111,
                        to: 1111,
                    },
                    VlessEncryptionPaddingRange {
                        probability: 50,
                        from: 0,
                        to: 3333,
                    },
                ],
                vec![VlessEncryptionPaddingRange {
                    probability: 75,
                    from: 0,
                    to: 111,
                }],
            );
        }
        (self.lens.clone(), self.gaps.clone())
    }
}

/// A parsed client `encryption=` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessEncryptionParams {
    pub xor_mode: VlessEncryptionMode,
    /// `0rtt` — reuse a ticket across connections when the server issued one.
    pub zero_rtt: bool,
    pub padding: VlessEncryptionPadding,
    /// Relay chain, in the order the client walks it. Never empty; the last
    /// entry is the server.
    pub nfs_keys: Vec<VlessEncryptionKey>,
    /// The padding sub-string exactly as written, for round-tripping a profile
    /// back out to a share link without re-serialising the numbers.
    pub padding_spec: String,
}

impl VlessEncryptionParams {
    /// `RelaysLength`: every hop contributes its wire material plus a 32-byte
    /// binding to the next hop; the last hop has no next hop.
    pub fn relays_len(&self) -> usize {
        let mut total = 0;
        for key in &self.nfs_keys {
            total += key.relay_len() + 32;
        }
        total - 32
    }
}

/// Parse a client-side `encryption=` value.
///
/// `none` (and the empty string) are *not* handled here — they mean "no
/// encryption layer" and are the caller's business.
pub fn parse_vless_encryption(spec: &str) -> Result<VlessEncryptionParams, VlessEncryptionError> {
    let fields: Vec<&str> = spec.split('.').collect();
    // suite, mode, rtt, and at least one key.
    if fields.len() < 4 {
        return Err(VlessEncryptionError::Invalid(format!(
            "VLESS encryption '{spec}' needs at least suite.mode.rtt.key"
        )));
    }
    if fields[0] != VLESS_ENCRYPTION_SUITE {
        return Err(VlessEncryptionError::Unsupported(format!(
            "VLESS encryption key exchange '{}' is not implemented; this client implements '{VLESS_ENCRYPTION_SUITE}'",
            fields[0]
        )));
    }
    let xor_mode = match fields[1] {
        "native" => VlessEncryptionMode::Native,
        "xorpub" => VlessEncryptionMode::XorPub,
        "random" => VlessEncryptionMode::Random,
        other => {
            return Err(VlessEncryptionError::Unsupported(format!(
                "VLESS encryption appearance mode '{other}' is not implemented; this client implements 'native', 'xorpub' and 'random'"
            )));
        }
    };
    let zero_rtt = match fields[2] {
        "1rtt" => false,
        "0rtt" => true,
        other => {
            return Err(VlessEncryptionError::Unsupported(format!(
                "VLESS encryption RTT mode '{other}' is not implemented; this client implements '1rtt' and '0rtt'"
            )));
        }
    };

    // Padding parameters run in front of the keys and are told apart from them
    // by length alone, exactly as upstream does it.
    let rest = &fields[3..];
    let padding_field_count = rest
        .iter()
        .take_while(|field| field.len() < PADDING_FIELD_MAX_LEN)
        .count();
    let (padding_fields, key_fields) = rest.split_at(padding_field_count);
    if key_fields.is_empty() {
        return Err(VlessEncryptionError::Invalid(format!(
            "VLESS encryption '{spec}' carries no server key"
        )));
    }
    // A short field after the keys have started is not padding — upstream's
    // byte arithmetic would slice the string at the wrong offset, so refusing
    // is the only reading that cannot silently disagree with the server.
    if let Some(stray) = key_fields
        .iter()
        .find(|field| field.len() < PADDING_FIELD_MAX_LEN)
    {
        return Err(VlessEncryptionError::Invalid(format!(
            "VLESS encryption field '{stray}' is too short to be a key and padding parameters must precede keys"
        )));
    }

    let padding_spec = padding_fields.join(".");
    let padding = parse_vless_encryption_padding(&padding_spec)?;

    let mut nfs_keys = Vec::with_capacity(key_fields.len());
    for field in key_fields {
        let decoded = URL_SAFE_NO_PAD.decode(field).map_err(|_| {
            VlessEncryptionError::Invalid("VLESS encryption key is not valid base64url".into())
        })?;
        match decoded.len() {
            VLESS_ENCRYPTION_X25519_KEY_LEN => {
                let mut key = [0_u8; VLESS_ENCRYPTION_X25519_KEY_LEN];
                key.copy_from_slice(&decoded);
                nfs_keys.push(VlessEncryptionKey::X25519(key));
            }
            VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN => {
                let mut key = Box::new([0_u8; VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN]);
                key.copy_from_slice(&decoded);
                nfs_keys.push(VlessEncryptionKey::MlKem768(key));
            }
            other => {
                return Err(VlessEncryptionError::Invalid(format!(
                    "VLESS encryption key decodes to {other} bytes; expected {VLESS_ENCRYPTION_X25519_KEY_LEN} (X25519) or {VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN} (ML-KEM-768)"
                )));
            }
        }
    }

    Ok(VlessEncryptionParams {
        xor_mode,
        zero_rtt,
        padding,
        nfs_keys,
        padding_spec,
    })
}

/// `ParsePadding`. Even-indexed fields are lengths, odd-indexed are gaps in
/// milliseconds.
pub fn parse_vless_encryption_padding(
    spec: &str,
) -> Result<VlessEncryptionPadding, VlessEncryptionError> {
    let mut params = VlessEncryptionPadding::default();
    if spec.is_empty() {
        return Ok(params);
    }
    let mut max_len: u64 = 0;
    for (index, field) in spec.split('.').enumerate() {
        let parts: Vec<&str> = field.split('-').collect();
        // Upstream requires at least three parts and ignores any beyond the
        // third. A negative number cannot survive this split, so unsigned
        // parsing rejects exactly what upstream rejects.
        if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
            return Err(VlessEncryptionError::Invalid(format!(
                "VLESS encryption padding parameter '{field}' is not probability-from-to"
            )));
        }
        let mut values = [0_u32; 3];
        for (slot, text) in values.iter_mut().zip(parts.iter().take(3)) {
            *slot = text.parse::<u32>().map_err(|_| {
                VlessEncryptionError::Invalid(format!(
                    "VLESS encryption padding parameter '{field}' is not a number"
                ))
            })?;
        }
        let range = VlessEncryptionPaddingRange {
            probability: values[0],
            from: values[1],
            to: values[2],
        };
        if index == 0
            && (range.probability < 100
                || range.from < MIN_FIRST_PADDING
                || range.to < MIN_FIRST_PADDING)
        {
            return Err(VlessEncryptionError::Invalid(format!(
                "VLESS encryption first padding length must be certain and at least {MIN_FIRST_PADDING} bytes"
            )));
        }
        if index % 2 == 0 {
            max_len += u64::from(range.from.max(range.to));
            params.lens.push(range);
        } else {
            params.gaps.push(range);
        }
    }
    if max_len > MAX_TOTAL_PADDING {
        return Err(VlessEncryptionError::Invalid(format!(
            "VLESS encryption total padding length must not exceed {MAX_TOTAL_PADDING}"
        )));
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic X25519 public key: 32 bytes, base64url, no padding.
    const X25519_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn mlkem_key() -> String {
        use base64::Engine as _;
        URL_SAFE_NO_PAD.encode(vec![7_u8; VLESS_ENCRYPTION_ML_KEM_768_KEY_LEN])
    }

    fn spec(tail: &str) -> String {
        format!("mlkem768x25519plus.native.1rtt.{tail}")
    }

    #[test]
    fn parses_the_documented_shapes() {
        for mode in ["native", "xorpub", "random"] {
            for rtt in ["0rtt", "1rtt"] {
                let value = format!("mlkem768x25519plus.{mode}.{rtt}.{X25519_KEY}");
                let params = parse_vless_encryption(&value).expect(&value);
                assert_eq!(params.nfs_keys.len(), 1);
                assert_eq!(params.zero_rtt, rtt == "0rtt");
                assert_eq!(
                    params.xor_mode,
                    match mode {
                        "native" => VlessEncryptionMode::Native,
                        "xorpub" => VlessEncryptionMode::XorPub,
                        _ => VlessEncryptionMode::Random,
                    }
                );
            }
        }
    }

    #[test]
    fn accepts_either_key_type_and_a_relay_chain() {
        let single = parse_vless_encryption(&spec(&mlkem_key())).unwrap();
        assert!(matches!(
            single.nfs_keys[0],
            VlessEncryptionKey::MlKem768(_)
        ));
        // One hop contributes its own wire material plus a 32-byte binding to
        // the next; the last hop has nothing to bind to.
        assert_eq!(
            single.relays_len(),
            VLESS_ENCRYPTION_ML_KEM_768_CIPHERTEXT_LEN
        );

        let chain =
            parse_vless_encryption(&spec(&format!("{}.{X25519_KEY}.{X25519_KEY}", mlkem_key())))
                .unwrap();
        assert_eq!(chain.nfs_keys.len(), 3);
        assert_eq!(
            chain.relays_len(),
            VLESS_ENCRYPTION_ML_KEM_768_CIPHERTEXT_LEN + 32 + 32 + 32 + 32
        );
    }

    #[test]
    fn accepts_padding_parameters_before_the_keys() {
        let params =
            parse_vless_encryption(&spec(&format!("100-40-40.100-5-5.100-60-60.{X25519_KEY}")))
                .unwrap();
        assert_eq!(params.padding.lens.len(), 2);
        assert_eq!(params.padding.gaps.len(), 1);
        assert_eq!(params.padding.gaps[0].to, 5);
        assert_eq!(params.padding_spec, "100-40-40.100-5-5.100-60-60");
    }

    #[test]
    fn an_absent_padding_spec_resolves_to_the_documented_default() {
        let params = parse_vless_encryption(&spec(X25519_KEY)).unwrap();
        let (lens, gaps) = params.padding.resolved();
        assert_eq!(
            (lens[0].probability, lens[0].from, lens[0].to),
            (100, 111, 1111)
        );
        assert_eq!(
            (gaps[0].probability, gaps[0].from, gaps[0].to),
            (75, 0, 111)
        );
        assert_eq!(
            (lens[1].probability, lens[1].from, lens[1].to),
            (50, 0, 3333)
        );
    }

    /// The point of this parser. Each of these is a *well-formed* value naming
    /// something this build does not implement, and each error has to say which
    /// one — a caller importing a subscription drops the node and keeps the
    /// rest, and the operator needs to know why.
    #[test]
    fn unsupported_variants_are_refused_by_name() {
        for (value, needle) in [
            (
                format!("mlkem1024x448plus.native.1rtt.{X25519_KEY}"),
                "mlkem1024x448plus",
            ),
            (
                format!("mlkem768x25519plus.chameleon.1rtt.{X25519_KEY}"),
                "chameleon",
            ),
            (
                format!("mlkem768x25519plus.native.2rtt.{X25519_KEY}"),
                "2rtt",
            ),
        ] {
            let error = parse_vless_encryption(&value).unwrap_err();
            assert!(
                error.is_unsupported(),
                "{value} should be unsupported, not malformed: {error}"
            );
            assert!(
                error.to_string().contains(needle),
                "error for {value} does not name '{needle}': {error}"
            );
        }
    }

    /// Malformed values are a different answer from unsupported ones, so a
    /// caller can tell "your server speaks something newer" from "this link is
    /// corrupt".
    #[test]
    fn malformed_values_are_invalid_rather_than_unsupported() {
        let short_key = {
            use base64::Engine as _;
            URL_SAFE_NO_PAD.encode([0_u8; 31])
        };
        for value in [
            "mlkem768x25519plus.native.1rtt".to_string(),
            "mlkem768x25519plus.native".to_string(),
            spec("not!valid!base64!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            spec(&short_key),
            // padding parameters must precede the keys, because upstream slices
            // the string by their combined length
            format!("mlkem768x25519plus.native.1rtt.{X25519_KEY}.100-40-40"),
        ] {
            let error = parse_vless_encryption(&value).unwrap_err();
            assert!(
                !error.is_unsupported(),
                "{value} should be malformed, not unsupported: {error}"
            );
        }
    }

    #[test]
    fn padding_rules_match_upstream() {
        // First length must be certain and at least 35 bytes.
        assert!(parse_vless_encryption_padding("99-40-40").is_err());
        assert!(parse_vless_encryption_padding("100-34-40").is_err());
        assert!(parse_vless_encryption_padding("100-40-34").is_err());
        assert!(parse_vless_encryption_padding("100-35-35").is_ok());
        // Not a probability-from-to triple.
        assert!(parse_vless_encryption_padding("100-40").is_err());
        assert!(parse_vless_encryption_padding("100--40-40").is_err());
        // Negative numbers cannot survive the split, so they read as malformed.
        assert!(parse_vless_encryption_padding("100-40-40.-5-1-2").is_err());
        // The encrypted padding length is a u16.
        assert!(parse_vless_encryption_padding("100-40-40.100-0-0.100-65536-65536").is_err());
    }

    /// Negative control for the tests above: they assert that specific values
    /// are refused, which is only meaningful if the parser accepts anything at
    /// all and if the two error kinds are actually distinguishable.
    #[test]
    fn the_parser_is_not_simply_refusing_everything() {
        assert!(parse_vless_encryption(&spec(X25519_KEY)).is_ok());
        assert!(parse_vless_encryption_padding("").is_ok());
        assert!(
            VlessEncryptionError::Unsupported(String::new()).is_unsupported()
                && !VlessEncryptionError::Invalid(String::new()).is_unsupported(),
            "the two error kinds are not distinguishable"
        );
    }
}
