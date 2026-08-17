//! Key exchange groups the REALITY hello offers, and the two it executes.
//!
//! The hello is a parrot, so it names the groups Chrome names. Executing one is
//! a different promise: only `x25519` and `X25519MLKEM768` are implemented, and
//! a ServerHello that selects anything else is refused rather than guessed at.
//!
//! # Why the hybrid does not touch REALITY authentication
//!
//! REALITY's authentication key comes from an ECDH between the client's
//! `x25519` *key share* and the server's REALITY public key — a key pair that
//! has nothing to do with the TLS key exchange and is never sent. The server
//! reads the share straight out of the ClientHello: it looks for group
//! `x25519` with a 32-byte share first, and only falls back to the last 32
//! bytes of an `X25519MLKEM768` share when no plain one is present
//! (XTLS/REALITY `tls.go`). This client always sends both, so the plain share
//! is the one the server uses, whichever group it then negotiates for TLS.
//!
//! # Wire format, and the direction implementations get wrong
//!
//! From draft-ietf-tls-ecdhe-mlkem (§3.1, §3.2):
//!
//! * `X25519MLKEM768` (0x11ec) — client share is `ML-KEM-768 encapsulation key
//!   ‖ X25519 public`, 1184 + 32 = 1216 bytes; server share is `ML-KEM
//!   ciphertext ‖ X25519 public`, 1088 + 32 = 1120 bytes; the shared secret is
//!   `ML-KEM secret ‖ X25519 secret`, 32 + 32 = 64 bytes.
//! * `SecP256r1MLKEM768` (0x11eb) puts the *ECDHE* half first in every one of
//!   those three, which is the reverse of the above.
//!
//! Only the X25519 variant is implemented here, but the reversal is the reason
//! the concatenation order is asserted by a test rather than left to a comment.

use std::io;

use aws_lc_rs::agreement;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
use rand::RngCore;
use zeroize::Zeroize;

/// Length of an X25519 public key or shared secret.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation key, FIPS 203.
pub const ML_KEM_768_ENCAPSULATION_KEY_LEN: usize = 1184;
/// ML-KEM-768 ciphertext, FIPS 203.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 shared secret, FIPS 203.
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

/// Uncompressed P-256 point, SEC1: `0x04 ‖ X ‖ Y`.
pub const P256_PUBLIC_LEN: usize = 65;

/// Client `key_share` for `X25519MLKEM768`: `ek ‖ x25519_pub`.
pub const X25519MLKEM768_CLIENT_SHARE_LEN: usize = ML_KEM_768_ENCAPSULATION_KEY_LEN + X25519_LEN;
/// Server `key_share` for `X25519MLKEM768`: `ct ‖ x25519_pub`.
pub const X25519MLKEM768_SERVER_SHARE_LEN: usize = ML_KEM_768_CIPHERTEXT_LEN + X25519_LEN;
/// Shared secret for `X25519MLKEM768`: `ml_kem_ss ‖ x25519_ss`.
pub const X25519MLKEM768_SHARED_SECRET_LEN: usize = ML_KEM_768_SHARED_SECRET_LEN + X25519_LEN;

/// A TLS named group this build can put a name to.
///
/// Naming one is not the same as executing it: [`NamedGroup::is_executable`]
/// answers that, and it is the set the profile table is checked against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NamedGroup {
    Secp256r1,
    Secp384r1,
    /// Named by the Safari and iOS tables. Never executed: no share is sent for
    /// it and a server that selects it is refused by name.
    Secp521r1,
    /// Finite-field groups Firefox names in `supported_groups`. Never executed;
    /// no share is sent and a server selecting one is refused by name.
    Ffdhe2048,
    Ffdhe3072,
    X25519,
    X25519MlKem768,
}

impl NamedGroup {
    /// IANA `supported_groups` code point.
    pub const fn id(self) -> u16 {
        match self {
            Self::Secp256r1 => 0x0017,
            Self::Secp384r1 => 0x0018,
            Self::Secp521r1 => 0x0019,
            Self::Ffdhe2048 => 0x0100,
            Self::Ffdhe3072 => 0x0101,
            Self::X25519 => 0x001d,
            // draft-ietf-tls-ecdhe-mlkem §5.
            Self::X25519MlKem768 => 0x11ec,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0017 => Some(Self::Secp256r1),
            0x0018 => Some(Self::Secp384r1),
            0x0019 => Some(Self::Secp521r1),
            0x0100 => Some(Self::Ffdhe2048),
            0x0101 => Some(Self::Ffdhe3072),
            0x001d => Some(Self::X25519),
            0x11ec => Some(Self::X25519MlKem768),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Secp256r1 => "secp256r1",
            Self::Secp384r1 => "secp384r1",
            Self::Secp521r1 => "secp521r1",
            Self::Ffdhe2048 => "ffdhe2048",
            Self::Ffdhe3072 => "ffdhe3072",
            Self::X25519 => "x25519",
            Self::X25519MlKem768 => "X25519MLKEM768",
        }
    }

    /// Whether this client can complete a handshake on the group, as opposed to
    /// merely listing it in `supported_groups` because Chrome does.
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::X25519 | Self::X25519MlKem768 | Self::Secp256r1)
    }
}

/// The client's private key exchange material for one connection.
///
/// One `x25519` key pair for the plain share — the one REALITY authenticates
/// against — and, when the profile offers the hybrid, a second, independent
/// `x25519` pair next to an ML-KEM-768 decapsulation key. The two `x25519`
/// pairs are independent on purpose: BoringSSL generates a separate ephemeral
/// per key share, and reusing one public key in both shares would be visible
/// on the wire as 32 bytes repeated inside a 1216-byte field.
pub struct ClientKeyExchange {
    x25519_private: [u8; X25519_LEN],
    x25519_public: [u8; X25519_LEN],
    hybrid: Option<HybridKeyExchange>,
    p256: Option<P256KeyExchange>,
}

/// A P-256 ephemeral, for the one profile that sends a P-256 share.
///
/// `agreement::PrivateKey` is not `Clone` and cannot be re-derived from bytes
/// for this curve the way X25519 can, so the key itself is held.
struct P256KeyExchange {
    private: agreement::PrivateKey,
    public: Vec<u8>,
}

struct HybridKeyExchange {
    ml_kem: DecapsulationKey<aws_lc_rs::kem::AlgorithmId>,
    /// `ek`, cached because `key_bytes()` re-encodes on every call and the
    /// value is needed twice (hello and, in tests, the share assertions).
    ml_kem_encapsulation_key: Vec<u8>,
    x25519_private: [u8; X25519_LEN],
    x25519_public: [u8; X25519_LEN],
}

impl Drop for ClientKeyExchange {
    fn drop(&mut self) {
        self.x25519_private.zeroize();
    }
}

impl Drop for HybridKeyExchange {
    fn drop(&mut self) {
        self.x25519_private.zeroize();
    }
}

impl ClientKeyExchange {
    /// Generate the private material for `groups`.
    ///
    /// `groups` is the profile's key-share list. A group that is not executable
    /// never reaches here — the profile table refuses to name one in
    /// `key_share` — so an unexpected entry is a construction error, not a
    /// runtime surprise.
    pub fn generate(groups: &[NamedGroup]) -> io::Result<Self> {
        Self::generate_with_reuse(groups, false)
    }

    /// `reuse_classical` makes the standalone `x25519` share carry the *same*
    /// public key as the X25519 half of the hybrid share.
    ///
    /// Chrome generates the two independently, and reusing one there would be
    /// 32 bytes visibly repeated inside a 1216-byte field. Firefox does the
    /// opposite: uTLS' `ReuseHybridAndClassicalKeyShares` marks the pair so
    /// that one classical key backs both entries, and a Firefox parrot that
    /// sent two different keys would be as wrong as a Chrome one that sent the
    /// same key twice. So it is per profile, not a global rule.
    pub fn generate_with_reuse(groups: &[NamedGroup], reuse_classical: bool) -> io::Result<Self> {
        let mut rng = rand::rng();

        let mut hybrid = None;
        let mut p256 = None;
        for group in groups {
            match group {
                NamedGroup::X25519 => {}
                NamedGroup::X25519MlKem768 => {
                    if hybrid.is_none() {
                        hybrid = Some(HybridKeyExchange::generate(&mut rng)?);
                    }
                }
                NamedGroup::Secp256r1 => {
                    if p256.is_none() {
                        p256 = Some(P256KeyExchange::generate()?);
                    }
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "REALITY hello profile asks for a {} key share this build cannot execute",
                            other.name()
                        ),
                    ));
                }
            }
        }

        // The reused case takes the hybrid's classical scalar so both shares
        // carry one public key. Without a hybrid there is nothing to reuse.
        let (x25519_private, x25519_public) = match (reuse_classical, hybrid.as_ref()) {
            (true, Some(hybrid)) => (hybrid.x25519_private, hybrid.x25519_public),
            _ => {
                let mut private = [0_u8; X25519_LEN];
                rng.fill_bytes(&mut private);
                let public = x25519_public_key(&private)?;
                (private, public)
            }
        };

        Ok(Self {
            x25519_private,
            x25519_public,
            hybrid,
            p256,
        })
    }

    /// The private scalar REALITY authenticates with. This is the scalar behind
    /// the plain `x25519` key share, which is the one the REALITY server reads.
    pub fn reality_private_key(&self) -> &[u8; X25519_LEN] {
        &self.x25519_private
    }

    /// Wire bytes of the `key_share` entry for `group`.
    pub fn share_bytes(&self, group: NamedGroup) -> Option<Vec<u8>> {
        match group {
            NamedGroup::X25519 => Some(self.x25519_public.to_vec()),
            NamedGroup::Secp256r1 => self.p256.as_ref().map(|p256| p256.public.clone()),
            NamedGroup::X25519MlKem768 => self.hybrid.as_ref().map(|hybrid| {
                // draft-ietf-tls-ecdhe-mlkem §3.1: ek first, X25519 second.
                let mut share = Vec::with_capacity(X25519MLKEM768_CLIENT_SHARE_LEN);
                share.extend_from_slice(&hybrid.ml_kem_encapsulation_key);
                share.extend_from_slice(&hybrid.x25519_public);
                share
            }),
            _ => None,
        }
    }

    /// Complete the exchange against the server's share.
    ///
    /// Returns the TLS 1.3 `(EC)DHE` input to the key schedule: 32 bytes for
    /// `x25519`, 64 for the hybrid.
    pub fn complete(&self, server_share: &ServerKeyShare) -> io::Result<Vec<u8>> {
        match server_share {
            ServerKeyShare::X25519(peer) => Ok(x25519_agree(&self.x25519_private, peer)?.to_vec()),
            ServerKeyShare::Secp256r1(peer) => {
                let p256 = self.p256.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "REALITY server answered with secp256r1, which this hello did not offer a \
                         share for",
                    )
                })?;
                Ok(p256.agree(peer.as_slice())?.to_vec())
            }
            ServerKeyShare::X25519MlKem768 {
                ml_kem_ciphertext,
                x25519,
            } => {
                let hybrid = self.hybrid.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "REALITY server answered with X25519MLKEM768, which this hello did not offer a share for",
                    )
                })?;
                let ml_kem_secret = hybrid
                    .ml_kem
                    .decapsulate(Ciphertext::from(ml_kem_ciphertext.as_slice()))
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "REALITY ML-KEM-768 decapsulation failed",
                        )
                    })?;
                let mut ecdh_secret = x25519_agree(&hybrid.x25519_private, x25519)?;

                // draft-ietf-tls-ecdhe-mlkem §3.2: for X25519MLKEM768 the
                // ML-KEM secret comes first. SecP256r1MLKEM768 is the other way
                // round; getting this backwards produces a handshake that fails
                // at the server's Finished with no hint as to why.
                let mut secret = Vec::with_capacity(X25519MLKEM768_SHARED_SECRET_LEN);
                secret.extend_from_slice(ml_kem_secret.as_ref());
                secret.extend_from_slice(&ecdh_secret);
                ecdh_secret.zeroize();
                if secret.len() != X25519MLKEM768_SHARED_SECRET_LEN {
                    secret.zeroize();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "REALITY hybrid shared secret has an unexpected length",
                    ));
                }
                Ok(secret)
            }
        }
    }
}

impl HybridKeyExchange {
    fn generate(rng: &mut impl RngCore) -> io::Result<Self> {
        let ml_kem = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| io::Error::other("failed to generate an ML-KEM-768 key"))?;
        let ml_kem_encapsulation_key = ml_kem
            .encapsulation_key()
            .and_then(|key| key.key_bytes().map(|bytes| bytes.as_ref().to_vec()))
            .map_err(|_| io::Error::other("failed to encode the ML-KEM-768 encapsulation key"))?;
        if ml_kem_encapsulation_key.len() != ML_KEM_768_ENCAPSULATION_KEY_LEN {
            return Err(io::Error::other(
                "ML-KEM-768 encapsulation key has an unexpected length",
            ));
        }
        let mut x25519_private = [0_u8; X25519_LEN];
        rng.fill_bytes(&mut x25519_private);
        let x25519_public = x25519_public_key(&x25519_private)?;
        Ok(Self {
            ml_kem,
            ml_kem_encapsulation_key,
            x25519_private,
            x25519_public,
        })
    }
}

/// The server's `key_share`, parsed into the group it actually selected.
///
/// This used to be a bare `[u8; 32]`, which could only ever mean `x25519` and
/// silently made every other group look like a parse failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerKeyShare {
    X25519([u8; X25519_LEN]),
    /// Uncompressed SEC1 point. Only the Firefox profile offers a P-256 share,
    /// so only that profile can reach this arm.
    Secp256r1(Box<[u8; P256_PUBLIC_LEN]>),
    X25519MlKem768 {
        ml_kem_ciphertext: Box<[u8; ML_KEM_768_CIPHERTEXT_LEN]>,
        x25519: [u8; X25519_LEN],
    },
}

/// A fresh X25519 public key with no use for the private half.
///
/// The ECH GREASE extension's `enc` field is an HPKE encapsulated key in a real
/// offer, so a random 32 bytes would be off the curve and distinguishable. It
/// is drawn per connection rather than once per process: `enc` is in the clear,
/// and a constant would let one observer link every connection this build makes.
pub fn random_x25519_public_key() -> io::Result<[u8; X25519_LEN]> {
    let mut private = [0_u8; X25519_LEN];
    rand::rng().fill_bytes(&mut private);
    let public = x25519_public_key(&private);
    private.zeroize();
    public
}

impl P256KeyExchange {
    fn generate() -> io::Result<Self> {
        let private = agreement::PrivateKey::generate(&agreement::ECDH_P256)
            .map_err(|_| io::Error::other("failed to generate a P-256 key"))?;
        let public = private
            .compute_public_key()
            .map_err(|_| io::Error::other("failed to compute a P-256 public key"))?;
        let public = public.as_ref().to_vec();
        if public.len() != P256_PUBLIC_LEN {
            return Err(io::Error::other(
                "P-256 public key is not an uncompressed SEC1 point",
            ));
        }
        Ok(Self { private, public })
    }

    fn agree(&self, peer: &[u8]) -> io::Result<[u8; 32]> {
        let peer_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer);
        let mut secret = [0_u8; 32];
        agreement::agree(
            &self.private,
            peer_key,
            io::Error::new(io::ErrorKind::InvalidData, "REALITY P-256 agreement failed"),
            |material| {
                if material.len() != 32 {
                    return Err(io::Error::other("P-256 produced an unexpected secret"));
                }
                secret.copy_from_slice(material);
                Ok(())
            },
        )?;
        Ok(secret)
    }
}

fn x25519_public_key(private: &[u8; X25519_LEN]) -> io::Result<[u8; X25519_LEN]> {
    let key = agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .map_err(|_| io::Error::other("failed to create an X25519 key"))?;
    let public = key
        .compute_public_key()
        .map_err(|_| io::Error::other("failed to compute an X25519 public key"))?;
    let mut bytes = [0_u8; X25519_LEN];
    let encoded = public.as_ref();
    if encoded.len() != X25519_LEN {
        return Err(io::Error::other(
            "X25519 public key has an unexpected length",
        ));
    }
    bytes.copy_from_slice(encoded);
    Ok(bytes)
}

fn x25519_agree(
    private: &[u8; X25519_LEN],
    peer: &[u8; X25519_LEN],
) -> io::Result<[u8; X25519_LEN]> {
    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .map_err(|_| io::Error::other("failed to create an X25519 key"))?;
    let peer_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
    let mut secret = [0_u8; X25519_LEN];
    agreement::agree(
        &private_key,
        peer_key,
        io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY X25519 agreement failed",
        ),
        |material| {
            if material.len() != X25519_LEN {
                return Err(io::Error::other("X25519 produced an unexpected secret"));
            }
            secret.copy_from_slice(material);
            Ok(())
        },
    )?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};

    #[test]
    fn group_code_points_match_the_iana_registry() {
        // draft-ietf-tls-ecdhe-mlkem §5 and RFC 8446 appendix B.3.1.4.
        assert_eq!(NamedGroup::Secp256r1.id(), 0x0017);
        assert_eq!(NamedGroup::Secp384r1.id(), 0x0018);
        assert_eq!(NamedGroup::X25519.id(), 0x001d);
        assert_eq!(NamedGroup::X25519MlKem768.id(), 0x11ec);
        for group in [
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::X25519,
            NamedGroup::X25519MlKem768,
        ] {
            assert_eq!(NamedGroup::from_id(group.id()), Some(group));
        }
        // 0x11eb is SecP256r1MLKEM768, which this build does not execute and
        // therefore must not be able to name into an executable group.
        assert_eq!(NamedGroup::from_id(0x11eb), None);
    }

    /// Three executable groups, and the rest are names only.
    ///
    /// `Secp256r1` joined the first list when the Firefox table arrived: that
    /// profile sends a real P-256 key share, so the client has to be able to
    /// complete one. Everything else here is named in `supported_groups`
    /// because a browser names it, and a ServerHello selecting one is refused.
    #[test]
    fn only_the_implemented_groups_are_executable() {
        assert!(NamedGroup::X25519.is_executable());
        assert!(NamedGroup::X25519MlKem768.is_executable());
        assert!(NamedGroup::Secp256r1.is_executable());

        assert!(!NamedGroup::Secp384r1.is_executable());
        assert!(!NamedGroup::Secp521r1.is_executable());
        assert!(!NamedGroup::Ffdhe2048.is_executable());
        assert!(!NamedGroup::Ffdhe3072.is_executable());
    }

    /// A P-256 share is real key material, not a filled-in constant.
    #[test]
    fn the_p256_share_is_an_uncompressed_sec1_point() {
        let exchange = ClientKeyExchange::generate(&[NamedGroup::X25519, NamedGroup::Secp256r1])
            .expect("P-256 shares are generated");
        let share = exchange
            .share_bytes(NamedGroup::Secp256r1)
            .expect("a P-256 share was asked for");
        assert_eq!(share.len(), P256_PUBLIC_LEN);
        assert_eq!(share[0], 0x04, "SEC1 uncompressed point marker");

        // Two connections must not reuse a key.
        let other = ClientKeyExchange::generate(&[NamedGroup::Secp256r1]).unwrap();
        assert_ne!(share, other.share_bytes(NamedGroup::Secp256r1).unwrap());
    }

    /// Firefox repeats one classical key in both shares; Chrome must not.
    #[test]
    fn classical_key_share_reuse_is_per_profile() {
        let groups = [NamedGroup::X25519MlKem768, NamedGroup::X25519];

        let reused = ClientKeyExchange::generate_with_reuse(&groups, true).unwrap();
        let hybrid = reused.share_bytes(NamedGroup::X25519MlKem768).unwrap();
        let flat = reused.share_bytes(NamedGroup::X25519).unwrap();
        assert_eq!(
            &hybrid[ML_KEM_768_ENCAPSULATION_KEY_LEN..],
            flat.as_slice(),
            "with reuse the standalone share must repeat the hybrid's classical half"
        );

        let independent = ClientKeyExchange::generate_with_reuse(&groups, false).unwrap();
        let hybrid = independent.share_bytes(NamedGroup::X25519MlKem768).unwrap();
        let flat = independent.share_bytes(NamedGroup::X25519).unwrap();
        assert_ne!(
            &hybrid[ML_KEM_768_ENCAPSULATION_KEY_LEN..],
            flat.as_slice(),
            "without reuse the two shares must be independent keys"
        );
    }

    #[test]
    fn the_hybrid_client_share_is_encapsulation_key_then_x25519() {
        let exchange =
            ClientKeyExchange::generate(&[NamedGroup::X25519, NamedGroup::X25519MlKem768]).unwrap();
        let share = exchange
            .share_bytes(NamedGroup::X25519MlKem768)
            .expect("the hybrid share must exist when the group was asked for");
        assert_eq!(share.len(), X25519MLKEM768_CLIENT_SHARE_LEN);
        assert_eq!(share.len(), 1216);

        // Length alone proves nothing — swapping the halves is still 1216
        // bytes, and ML-KEM encapsulation keys have no self-describing header
        // to reject the wrong window with. So the head is asserted by using it:
        // it has to encapsulate, and the resulting ciphertext has to be one
        // this exchange can decapsulate. That the *tail* is the X25519 half,
        // and that the secrets concatenate in the draft's order, is asserted
        // end to end by `the_hybrid_shared_secret_is_ml_kem_then_x25519`.
        let head = &share[..ML_KEM_768_ENCAPSULATION_KEY_LEN];
        let (ciphertext, _) = EncapsulationKey::new(&ML_KEM_768, head)
            .expect("the first 1184 bytes must parse as an ML-KEM-768 encapsulation key")
            .encapsulate()
            .expect("and must encapsulate");
        assert_eq!(ciphertext.as_ref().len(), ML_KEM_768_CIPHERTEXT_LEN);

        // And the plain share is a different key pair from the hybrid's X25519
        // half — one repeated 32-byte window inside the hello would be visible.
        let plain = exchange.share_bytes(NamedGroup::X25519).unwrap();
        assert_eq!(plain.len(), X25519_LEN);
        assert_ne!(&share[ML_KEM_768_ENCAPSULATION_KEY_LEN..], plain.as_slice());
    }

    #[test]
    fn the_hybrid_shared_secret_is_ml_kem_then_x25519() {
        let exchange = ClientKeyExchange::generate(&[NamedGroup::X25519MlKem768]).unwrap();
        let client_share = exchange.share_bytes(NamedGroup::X25519MlKem768).unwrap();

        // Stand in for the server: encapsulate to the client's ek and run an
        // X25519 of our own.
        let encapsulation_key = EncapsulationKey::new(
            &ML_KEM_768,
            &client_share[..ML_KEM_768_ENCAPSULATION_KEY_LEN],
        )
        .unwrap();
        let (ciphertext, server_ml_kem_secret) = encapsulation_key.encapsulate().unwrap();
        assert_eq!(ciphertext.as_ref().len(), ML_KEM_768_CIPHERTEXT_LEN);

        let server_private = [0x37_u8; X25519_LEN];
        let server_public = x25519_public_key(&server_private).unwrap();
        let expected_ecdh = x25519_agree(
            &server_private,
            client_share[ML_KEM_768_ENCAPSULATION_KEY_LEN..]
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let mut ml_kem_ciphertext = Box::new([0_u8; ML_KEM_768_CIPHERTEXT_LEN]);
        ml_kem_ciphertext.copy_from_slice(ciphertext.as_ref());
        let secret = exchange
            .complete(&ServerKeyShare::X25519MlKem768 {
                ml_kem_ciphertext,
                x25519: server_public,
            })
            .unwrap();

        assert_eq!(secret.len(), X25519MLKEM768_SHARED_SECRET_LEN);
        assert_eq!(secret.len(), 64);
        assert_eq!(
            &secret[..ML_KEM_768_SHARED_SECRET_LEN],
            server_ml_kem_secret.as_ref(),
            "X25519MLKEM768 puts the ML-KEM secret first; SecP256r1MLKEM768 is the reverse"
        );
        assert_eq!(&secret[ML_KEM_768_SHARED_SECRET_LEN..], &expected_ecdh);
    }

    #[test]
    fn the_plain_group_still_agrees_byte_for_byte() {
        let exchange = ClientKeyExchange::generate(&[NamedGroup::X25519]).unwrap();
        let client_public: [u8; X25519_LEN] = exchange
            .share_bytes(NamedGroup::X25519)
            .unwrap()
            .try_into()
            .unwrap();
        let server_private = [0x11_u8; X25519_LEN];
        let server_public = x25519_public_key(&server_private).unwrap();

        let ours = exchange
            .complete(&ServerKeyShare::X25519(server_public))
            .unwrap();
        let theirs = x25519_agree(&server_private, &client_public).unwrap();
        assert_eq!(ours.as_slice(), &theirs);

        // The share REALITY authenticates against is this same key pair.
        assert_eq!(
            x25519_public_key(exchange.reality_private_key()).unwrap(),
            client_public
        );
    }

    #[test]
    fn a_hybrid_answer_without_a_hybrid_offer_is_refused() {
        let exchange = ClientKeyExchange::generate(&[NamedGroup::X25519]).unwrap();
        let error = exchange
            .complete(&ServerKeyShare::X25519MlKem768 {
                ml_kem_ciphertext: Box::new([0_u8; ML_KEM_768_CIPHERTEXT_LEN]),
                x25519: [0_u8; X25519_LEN],
            })
            .expect_err("a group we sent no share for cannot be completed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_group_this_build_cannot_execute_is_a_construction_error() {
        // `expect_err` would need `Debug` on a type that holds private key
        // material, and a `Debug` that prints it is worse than a match.
        let Err(error) = ClientKeyExchange::generate(&[NamedGroup::Secp384r1]) else {
            panic!("secp384r1 shares are not implemented and must not be generated");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        // The finite-field groups Firefox names are the same kind of refusal.
        let Err(error) = ClientKeyExchange::generate(&[NamedGroup::Ffdhe2048]) else {
            panic!("ffdhe2048 shares are not implemented and must not be generated");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
