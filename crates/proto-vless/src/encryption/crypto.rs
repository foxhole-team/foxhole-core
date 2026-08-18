use std::io;

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::{agreement, kem};
use zeroize::Zeroize;

use super::params::{
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN, ML_KEM_768_SHARED_SECRET_LEN,
    NfsPublicKey, X25519_LEN,
};

pub const PFS_KEY_LEN: usize = ML_KEM_768_SHARED_SECRET_LEN + X25519_LEN;
pub const PFS_OFFER_LEN: usize = ML_KEM_768_ENCAPSULATION_KEY_LEN + X25519_LEN;
pub const PFS_ANSWER_LEN: usize = ML_KEM_768_CIPHERTEXT_LEN + X25519_LEN;

pub struct NfsShare {
    pub wire: Vec<u8>,
    pub shared_secret: [u8; 32],
}

pub trait PfsOffer: Send {
    fn public_bytes(&self) -> &[u8];
    fn derive(self: Box<Self>, answer: &[u8]) -> io::Result<[u8; PFS_KEY_LEN]>;
}

pub trait HandshakeCrypto: Send {
    fn fill_random(&mut self, out: &mut [u8]) -> io::Result<()>;
    fn rand_between(&mut self, from: u32, to: u32) -> u32;
    fn nfs_share(&mut self, peer: &NfsPublicKey) -> io::Result<NfsShare>;
    fn pfs_offer(&mut self) -> io::Result<Box<dyn PfsOffer>>;
}

pub struct LiveCrypto;

impl HandshakeCrypto for LiveCrypto {
    fn fill_random(&mut self, out: &mut [u8]) -> io::Result<()> {
        getrandom::fill(out).map_err(|_| io::Error::other("operating system RNG failed"))
    }

    fn rand_between(&mut self, from: u32, to: u32) -> u32 {
        if from >= to {
            return from;
        }
        let span = u64::from(to - from) + 1;
        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_err() {
            return from;
        }
        from + ((u64::from_be_bytes(bytes) >> 1) % span) as u32
    }

    fn nfs_share(&mut self, peer: &NfsPublicKey) -> io::Result<NfsShare> {
        match peer {
            NfsPublicKey::X25519(peer) => {
                let mut private = [0_u8; X25519_LEN];
                self.fill_random(&mut private)?;
                let public = x25519_public_key(&private)?;
                let secret = x25519_agree(&private, peer);
                private.zeroize();
                Ok(NfsShare {
                    wire: public.to_vec(),
                    shared_secret: secret?,
                })
            }
            NfsPublicKey::MlKem768(peer) => {
                let key = EncapsulationKey::new(&ML_KEM_768, peer.as_slice()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "VLESS encryption ML-KEM-768 encapsulation key was rejected",
                    )
                })?;
                let (ciphertext, shared) = key.encapsulate().map_err(|_| {
                    io::Error::other("VLESS encryption ML-KEM-768 encapsulation failed")
                })?;
                let ciphertext = ciphertext.as_ref();
                if ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
                    return Err(io::Error::other(
                        "VLESS encryption ML-KEM-768 ciphertext has an unexpected length",
                    ));
                }
                Ok(NfsShare {
                    wire: ciphertext.to_vec(),
                    shared_secret: shared_secret_32(shared.as_ref())?,
                })
            }
        }
    }

    fn pfs_offer(&mut self) -> io::Result<Box<dyn PfsOffer>> {
        let ml_kem = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| io::Error::other("VLESS encryption ML-KEM-768 keygen failed"))?;
        let encapsulation_key = ml_kem
            .encapsulation_key()
            .map_err(|_| io::Error::other("VLESS encryption ML-KEM-768 public key failed"))?;
        let encapsulation_key = encapsulation_key
            .key_bytes()
            .map_err(|_| io::Error::other("VLESS encryption ML-KEM-768 public key failed"))?;
        let mut x25519_private = [0_u8; X25519_LEN];
        self.fill_random(&mut x25519_private)?;
        let x25519_public = x25519_public_key(&x25519_private)?;

        let mut public = Vec::with_capacity(PFS_OFFER_LEN);
        public.extend_from_slice(encapsulation_key.as_ref());
        public.extend_from_slice(&x25519_public);
        if public.len() != PFS_OFFER_LEN {
            return Err(io::Error::other(
                "VLESS encryption forward-secret offer has an unexpected length",
            ));
        }
        Ok(Box::new(LivePfsOffer {
            ml_kem,
            x25519_private,
            public,
        }))
    }
}

struct LivePfsOffer {
    ml_kem: DecapsulationKey<kem::AlgorithmId>,
    x25519_private: [u8; X25519_LEN],
    public: Vec<u8>,
}

impl Drop for LivePfsOffer {
    fn drop(&mut self) {
        self.x25519_private.zeroize();
    }
}

impl PfsOffer for LivePfsOffer {
    fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    fn derive(self: Box<Self>, answer: &[u8]) -> io::Result<[u8; PFS_KEY_LEN]> {
        if answer.len() != PFS_ANSWER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS encryption server forward-secret answer has the wrong length",
            ));
        }
        let ml_kem_secret = self
            .ml_kem
            .decapsulate(Ciphertext::from(&answer[..ML_KEM_768_CIPHERTEXT_LEN]))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS encryption ML-KEM-768 decapsulation failed",
                )
            })?;
        let mut peer = [0_u8; X25519_LEN];
        peer.copy_from_slice(&answer[ML_KEM_768_CIPHERTEXT_LEN..]);
        let x25519_secret = x25519_agree(&self.x25519_private, &peer)?;

        let mut pfs_key = [0_u8; PFS_KEY_LEN];
        pfs_key[..ML_KEM_768_SHARED_SECRET_LEN]
            .copy_from_slice(&shared_secret_32(ml_kem_secret.as_ref())?);
        pfs_key[ML_KEM_768_SHARED_SECRET_LEN..].copy_from_slice(&x25519_secret);
        Ok(pfs_key)
    }
}

fn shared_secret_32(material: &[u8]) -> io::Result<[u8; 32]> {
    if material.len() != 32 {
        return Err(io::Error::other(
            "VLESS encryption shared secret has an unexpected length",
        ));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(material);
    Ok(secret)
}

fn x25519_public_key(private: &[u8; X25519_LEN]) -> io::Result<[u8; X25519_LEN]> {
    let key = agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .map_err(|_| io::Error::other("VLESS encryption X25519 key was rejected"))?;
    let public = key
        .compute_public_key()
        .map_err(|_| io::Error::other("VLESS encryption X25519 public key failed"))?;
    let encoded = public.as_ref();
    if encoded.len() != X25519_LEN {
        return Err(io::Error::other(
            "VLESS encryption X25519 public key has an unexpected length",
        ));
    }
    let mut bytes = [0_u8; X25519_LEN];
    bytes.copy_from_slice(encoded);
    Ok(bytes)
}

fn x25519_agree(
    private: &[u8; X25519_LEN],
    peer: &[u8; X25519_LEN],
) -> io::Result<[u8; X25519_LEN]> {
    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, private)
        .map_err(|_| io::Error::other("VLESS encryption X25519 key was rejected"))?;
    let peer_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer);
    let mut secret = [0_u8; X25519_LEN];
    agreement::agree(
        &private_key,
        peer_key,
        io::Error::new(
            io::ErrorKind::InvalidData,
            "VLESS encryption X25519 agreement failed",
        ),
        |material| {
            if material.len() != X25519_LEN {
                return Err(io::Error::other(
                    "VLESS encryption X25519 produced an unexpected secret",
                ));
            }
            secret.copy_from_slice(material);
            Ok(())
        },
    )?;
    Ok(secret)
}
