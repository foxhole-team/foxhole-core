use super::*;
use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_spki_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// Narrow the handshake to a version range. Absent means the core's own
    /// range, which is what a profile that says nothing should get.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<TlsVersion>,
    /// Key-exchange groups, most preferred first. A profile pins these to shape
    /// its ClientHello; an empty list means hybrid-first, see
    /// [`Self::allow_classical_only_key_exchange`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub curve_preferences: Vec<CurveGroup>,
    /// Permit a key exchange with no post-quantum group in it.
    ///
    /// `false`, and the default matters more than the flag. `curve_preferences`
    /// *replaces* the provider's group list rather than reordering it, so a
    /// profile that named `["x25519"]` to shape its hello used to silently drop
    /// `X25519MLKEM768` and negotiate a classical-only key exchange. That is a
    /// downgrade against a harvest-now-decrypt-later adversary, arriving as a
    /// side effect of a cosmetic setting, which is the worst way for it to
    /// arrive.
    ///
    /// So the hybrid is now prepended to any preference list that omits it, and
    /// dropping it takes saying so here. A profile that sets this is making a
    /// visible, reviewable choice; one that forgets the group keeps its
    /// post-quantum protection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_classical_only_key_exchange: bool,
    /// Encrypted Client Hello. Absent means the SNI travels in the clear, which
    /// is what every profile written before this field did and still does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<EchConfig>,
}

/// Encrypted Client Hello (draft-ietf-tls-esni-18), client side.
///
/// Two modes, and deliberately not three. There is no `optional` that tries ECH
/// and continues without it, because on this library "continuing" is not a
/// weaker version of the same connection: when a server rejects ECH, rustls has
/// verified the certificate against the **public name** from the ECH config,
/// not against `tls.server_name`. Carrying on would mean talking to whatever
/// answers for the cover domain while the profile believes it reached its
/// proxy. A genuine fallback is a second dial without ECH — a different
/// connection, and one the operator can ask for by writing a profile without
/// `ech` in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EchConfig {
    /// The ClientHello is encrypted or the connection does not happen.
    ///
    /// `config_list` is the server's `ECHConfigList`, base64 — the same bytes
    /// the `ech` parameter of an `HTTPS` DNS record carries. A list that does
    /// not parse, or that offers no HPKE suite this build has, fails the
    /// outbound rather than downgrading it.
    Required { config_list: String },
    /// No config list: send a GREASE ECH extension so that *not* having ECH
    /// does not itself stand out from the browsers that do.
    ///
    /// The name is the whole warning. GREASE encrypts nothing: this is random
    /// filler shaped like an ECH extension, and **the real SNI goes out in the
    /// clear** exactly as it would with no `ech` field at all. It is here as an
    /// anti-ossification measure and as cover traffic, never as a substitute
    /// for [`EchConfig::Required`].
    GreasePlaintextSni,
}

impl EchConfig {
    /// The base64 `ECHConfigList` this mode carries, if any.
    pub fn config_list(&self) -> Option<&str> {
        match self {
            Self::Required { config_list } => Some(config_list),
            Self::GreasePlaintextSni => None,
        }
    }
}

/// Why ECH is refused on the two QUIC protocols.
///
/// Not "not implemented yet" hedging: the fail-closed rule this core applies to
/// ECH is *the handshake ended with the server having accepted it*, and the
/// QUIC stack hands back a connection, not a `rustls::ClientConnection`, so
/// there is nothing to ask. Shipping ECH there would mean shipping a promise
/// with no check behind it.
pub(super) const ECH_NOT_OVER_QUIC: &str = "tls.ech is not available over QUIC: the QUIC connection reports no ECH status, so acceptance cannot be enforced";

/// Why ECH is refused under ShadowTLS.
///
/// Structural, and it will not be fixed by finishing anything. ShadowTLS v3
/// authenticates by overwriting four bytes inside the ClientHello's legacy
/// session id *after* the record has been produced. Those bytes are inside the
/// `ClientHelloOuterAAD` that ECH seals the inner hello against, so the server
/// could never open it: every such handshake would be an ECH rejection, which
/// under this core's fail-closed rule is a refused connection. Refusing the
/// profile says the same thing at load time instead of at dial time.
pub(super) const ECH_NOT_UNDER_SHADOWTLS: &str = "tls.ech cannot be used with ShadowTLS: its v3 client-hello signature rewrites the session id that ECH seals as additional data";

/// An `ECHConfigList` larger than this is not a config, it is a payload.
/// draft-18 caps the list itself at 2^16-1 bytes; a real one for a single host
/// is under 200.
const MAX_ECH_CONFIG_LIST_BYTES: usize = 4096;

/// The versions the core will speak. Older ones are absent on purpose: a
/// profile asking for TLS 1.0 or 1.1 is asking for a broken handshake, and the
/// honest answer is to refuse the profile rather than negotiate one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

/// Key-exchange group names as the profile writes them.
///
/// A closed set: an unknown curve must fail the profile, because silently
/// dropping it would produce a different ClientHello than the one asked for —
/// which for a profile that pins curves to look like a browser is the whole
/// point of the setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CurveGroup {
    X25519,
    Secp256r1,
    Secp384r1,
    /// The post-quantum hybrid, draft-ietf-tls-ecdhe-mlkem.
    ///
    /// Nameable because `curve_preferences` *replaces* the provider's group
    /// list rather than reordering it: without this variant, any profile that
    /// set `curve_preferences` at all silently dropped the PQ group and sent a
    /// classical-only hello. Chrome offers it first, so a profile that wants to
    /// look like Chrome names it first.
    #[serde(rename = "x25519mlkem768", alias = "X25519MLKEM768")]
    X25519MlKem768,
}

impl std::hash::Hash for CurveGroup {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

impl TlsConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled
            && (self.server_name.is_some()
                || self.insecure
                || self.pinned_spki_sha256.is_some()
                || !self.alpn.is_empty()
                || self.min_version.is_some()
                || self.max_version.is_some()
                || !self.curve_preferences.is_empty()
                || self.ech.is_some())
        {
            return Err(ConfigError::Invalid(
                "TLS options require tls.enabled=true".into(),
            ));
        }
        if self
            .server_name
            .as_deref()
            .is_some_and(|server_name| server_name.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "tls.server_name must not be empty".into(),
            ));
        }
        if self
            .alpn
            .iter()
            .any(|protocol| protocol.is_empty() || protocol.len() > u8::MAX as usize)
        {
            return Err(ConfigError::Invalid(
                "each TLS ALPN protocol must contain 1..=255 bytes".into(),
            ));
        }
        if let Some(pin) = &self.pinned_spki_sha256 {
            validate_spki_pin(pin)?;
        }
        if let (Some(min), Some(max)) = (self.min_version, self.max_version)
            && min > max
        {
            return Err(ConfigError::Invalid(
                "tls.min_version must not exceed tls.max_version".into(),
            ));
        }
        let mut seen = HashSet::with_capacity(self.curve_preferences.len());
        for curve in &self.curve_preferences {
            if !seen.insert(*curve) {
                return Err(ConfigError::Invalid(
                    "tls.curve_preferences must not repeat a group".into(),
                ));
            }
        }
        if let Some(ech) = &self.ech {
            // ECH exists only in TLS 1.3. A profile that pinned the handshake
            // to 1.2 and also asked for ECH has asked for two things that
            // cannot both happen, and the honest answer is to say so here
            // rather than to quietly win one of them: rustls' `with_ech`
            // narrows the version range to 1.3 on its own, so the profile
            // would get a 1.3 handshake it explicitly forbade.
            if self.max_version == Some(TlsVersion::Tls12) {
                return Err(ConfigError::Invalid(
                    "tls.ech requires TLS 1.3, but tls.max_version pins 1.2".into(),
                ));
            }
            if let Some(config_list) = ech.config_list() {
                validate_ech_config_list(config_list)?;
            }
        }
        Ok(())
    }

    /// Refuse ECH for a protocol whose own wire format is not compatible with
    /// it.
    ///
    /// A separate method rather than a flag on the struct because the reason
    /// differs per protocol and the operator has to read it: "not implemented"
    /// and "cannot work here" call for different next steps.
    pub(super) fn reject_ech(&self, reason: &str) -> Result<(), ConfigError> {
        if self.ech.is_some() {
            return Err(ConfigError::Invalid(reason.into()));
        }
        Ok(())
    }
}

fn validate_ech_config_list(encoded: &str) -> Result<(), ConfigError> {
    if encoded.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "tls.ech.config_list must not be empty".into(),
        ));
    }
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| ConfigError::Invalid("tls.ech.config_list is not valid base64".into()))?;
    // The list is a `uint16` length followed by that many bytes; anything
    // shorter than the length prefix plus one empty config is not a list.
    if decoded.len() < 2 {
        return Err(ConfigError::Invalid(
            "tls.ech.config_list is too short to be an ECHConfigList".into(),
        ));
    }
    if decoded.len() > MAX_ECH_CONFIG_LIST_BYTES {
        return Err(ConfigError::Invalid(format!(
            "tls.ech.config_list must decode to at most {MAX_ECH_CONFIG_LIST_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(super) fn validate_spki_pin(pin: &str) -> Result<(), ConfigError> {
    let decoded = STANDARD
        .decode(pin)
        .or_else(|_| URL_SAFE_NO_PAD.decode(pin))
        .map_err(|_| ConfigError::Invalid("SPKI SHA-256 pin is not valid base64".into()))?;
    if decoded.len() != 32 {
        return Err(ConfigError::Invalid(
            "SPKI SHA-256 pin must decode to 32 bytes".into(),
        ));
    }
    Ok(())
}
