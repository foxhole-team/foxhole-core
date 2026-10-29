//! Opt-in Chromium151 shape from FoxCore's independently captured chrome_151 vector.
//! Encoding remains inside rustls: binders, transcript hashes and records see the same bytes.

use crate::client::ClientConfig;
use crate::common_state::Protocol;
use crate::compress::{CertDecompressor, DecompressionFailed};
use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, ProtocolVersion, SignatureScheme,
};
use crate::error::Error;
use crate::msgs::base::PayloadU8;
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, ClientSessionTicket, KeyShareEntry,
};
use alloc::vec;
use alloc::vec::Vec;
use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};

const SIGNATURES: [u16; 11] = [
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const CIPHERS: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const GROUPS: [u16; 4] = [0x11ec, 0x001d, 0x0017, 0x0018];
const EXTENSIONS: [u16; 16] = [
    0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 0x44cd, 0xfe0d,
];

pub(crate) fn signature_allowed(scheme: SignatureScheme) -> bool {
    SIGNATURES.contains(&u16::from(scheme))
}

fn refuse(message: &str) -> Error {
    Error::General(message.into())
}

pub(super) fn configure(config: &mut ClientConfig) -> Result<(), Error> {
    if config.ech_mode.is_some() || config.enable_early_data || config.send_ticket_request.is_some()
    {
        return Err(refuse(
            "Chrome151 cannot discard ECH, early-data or ticket-request requirements",
        ));
    }
    if !config.supports_version(ProtocolVersion::TLSv1_2, Protocol::Tcp)
        || !config.supports_version(ProtocolVersion::TLSv1_3, Protocol::Tcp)
    {
        return Err(refuse(
            "Chrome151 requires its TLS1.2 and TLS1.3 version offer",
        ));
    }
    let groups: Vec<_> = config
        .provider
        .kx_groups
        .iter()
        .map(|group| u16::from(group.name()))
        .collect();
    if groups != GROUPS {
        return Err(refuse(
            "Chrome151 requires its exact hybrid-first group order",
        ));
    }
    if config.alpn_protocols.is_empty()
        || config
            .alpn_protocols
            .iter()
            .any(|protocol| protocol != b"h2" && protocol != b"http/1.1")
    {
        return Err(refuse("Chrome151 supports explicit h2/http/1.1 ALPN only"));
    }
    let schemes = config.verifier.supported_verify_schemes();
    if SIGNATURES
        .iter()
        .any(|scheme| !schemes.contains(&SignatureScheme::from(*scheme)))
    {
        return Err(refuse(
            "Chrome151 requires verification for every advertised signature, including ML-DSA",
        ));
    }
    config.cert_decompressors = vec![&CHROME_BROTLI];
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct ChromeExtensions {
    grease: [u16; 5],
    permutation: u64,
    ech: Vec<u8>,
}

impl ChromeExtensions {
    pub(super) fn new(config: &ClientConfig) -> Result<Self, Error> {
        let mut random = [0u8; 16];
        config.provider.secure_random.fill(&mut random)?;
        if random[3] & 0xf0 == random[4] & 0xf0 {
            random[4] ^= 0x10;
        }
        let grease = core::array::from_fn(|index| {
            let byte = (random[index] & 0xf0) | 0x0a;
            u16::from_be_bytes([byte, byte])
        });
        let permutation = u64::from_be_bytes(random[5..13].try_into().unwrap());
        let x25519 = config
            .provider
            .kx_groups
            .iter()
            .find(|group| group.name() == NamedGroup::X25519)
            .ok_or_else(|| refuse("Chrome151 ECH GREASE requires X25519"))?
            .start()?;
        let enc = x25519.pub_key();
        if enc.len() != 32 {
            return Err(refuse("Chrome151 ECH GREASE key is not X25519"));
        }
        let payload_len = [128usize, 160, 192, 224][usize::from(random[14]) % 4] + 16;
        let mut payload = vec![0u8; payload_len];
        config.provider.secure_random.fill(&mut payload)?;
        let mut ech = vec![0, 0, 1, 0, 1, random[13], 0, 32];
        ech.extend_from_slice(enc);
        ech.extend_from_slice(&(payload_len as u16).to_be_bytes());
        ech.extend_from_slice(&payload);
        Ok(Self {
            grease,
            permutation,
            ech,
        })
    }

    pub(super) fn apply(
        &self,
        hello: &mut ClientHelloPayload,
        schemes: &[SignatureScheme],
    ) -> Result<(), Error> {
        if hello.server_name.is_none() || hello.protocols.is_none() {
            return Err(refuse("Chrome151 requires DNS SNI and explicit ALPN"));
        }
        if SIGNATURES
            .iter()
            .any(|scheme| !schemes.contains(&SignatureScheme::from(*scheme)))
        {
            return Err(refuse("Chrome151 signature verifier changed"));
        }
        let allowed = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 27, 44, 41];
        if hello
            .collect_used()
            .iter()
            .any(|id| !allowed.contains(&u16::from(*id)))
        {
            return Err(refuse("Chrome151 cannot discard a configured extension"));
        }
        hello.cipher_suites = core::iter::once(self.grease[0])
            .chain(CIPHERS)
            .map(CipherSuite::from)
            .collect();
        hello.signature_schemes = Some(SIGNATURES.into_iter().map(SignatureScheme::from).collect());
        let mut groups = vec![NamedGroup::from(self.grease[1])];
        groups.extend(GROUPS.into_iter().map(NamedGroup::from));
        hello.named_groups = Some(groups);
        let shares = hello
            .key_shares
            .as_mut()
            .ok_or_else(|| refuse("Chrome151 has no authenticated key share"))?;
        shares.insert(
            0,
            KeyShareEntry::new(NamedGroup::from(self.grease[1]), &[0]),
        );
        hello.renegotiation_info = Some(PayloadU8::new(Vec::new()));
        if hello.session_ticket.is_none() {
            hello.session_ticket = Some(ClientSessionTicket::Request);
        }
        if hello.certificate_compression_algorithms.as_deref()
            != Some(&[CertificateCompressionAlgorithm::Brotli])
        {
            return Err(refuse(
                "Chrome151 Brotli certificate decompressor unavailable",
            ));
        }
        hello.chrome = Some(self.clone());
        Ok(())
    }

    pub(crate) fn order(&self, native: Vec<ExtensionType>) -> Vec<ExtensionType> {
        let psk = native.contains(&ExtensionType::from(41));
        let extras: Vec<_> = native
            .into_iter()
            .map(u16::from)
            .filter(|id| !EXTENSIONS.contains(id) && *id != 41)
            .collect();
        let mut middle: Vec<u16> = EXTENSIONS.to_vec();
        // Cookie/PSK are added only by rustls' real HRR/resumption state.
        middle.retain(|id| *id != 41);
        let mut state = self.permutation;
        for index in (1..middle.len()).rev() {
            state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d049bb133111eb);
            mixed ^= mixed >> 31;
            middle.swap(index, (mixed % ((index + 1) as u64)) as usize);
        }
        middle.extend(extras);
        let mut order = vec![ExtensionType::from(self.grease[3])];
        order.extend(middle.into_iter().map(ExtensionType::from));
        order.push(ExtensionType::from(self.grease[4]));
        if psk {
            order.push(ExtensionType::from(41));
        }
        order
    }

    pub(crate) fn encode_special(
        &self,
        id: ExtensionType,
        extensions: &ClientExtensions<'_>,
        output: &mut Vec<u8>,
    ) -> bool {
        let number = u16::from(id);
        let body = if number == self.grease[3] {
            Some(Vec::new())
        } else if number == self.grease[4] {
            Some(vec![0])
        } else if number == 18 {
            Some(Vec::new())
        } else if number == 0x44cd {
            Some(vec![0, 3, 2, b'h', b'2'])
        } else if number == 0xfe0d {
            Some(self.ech.clone())
        } else if number == 43 {
            let versions = extensions
                .supported_versions
                .as_ref()
                .expect("Chrome151 has versions");
            let mut raw = vec![0];
            raw.extend_from_slice(&self.grease[2].to_be_bytes());
            if versions.tls13 {
                raw.extend_from_slice(&0x0304u16.to_be_bytes());
            }
            if versions.tls12 {
                raw.extend_from_slice(&0x0303u16.to_be_bytes());
            }
            raw[0] = (raw.len() - 1) as u8;
            Some(raw)
        } else {
            None
        };
        if let Some(body) = body {
            output.extend_from_slice(&number.to_be_bytes());
            output.extend_from_slice(&(body.len() as u16).to_be_bytes());
            output.extend_from_slice(&body);
            true
        } else {
            false
        }
    }
}

// The strict decompressor is the upstream rustls0.23.46 implementation, enabled
// only for the opt-in profile instead of changing global compression defaults.
#[derive(Debug)]
struct ChromeBrotli;
static CHROME_BROTLI: ChromeBrotli = ChromeBrotli;
impl CertDecompressor for ChromeBrotli {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let mut state = BrotliState::new_strict(
            StandardAlloc::default(),
            StandardAlloc::default(),
            StandardAlloc::default(),
        );
        let (mut available_in, mut input_offset) = (input.len(), 0);
        let (mut available_out, mut output_offset, mut total_out) = (output.len(), 0, 0);
        match BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut output_offset,
            output,
            &mut total_out,
            &mut state,
        ) {
            BrotliResult::ResultSuccess if available_out == 0 && available_in == 0 => Ok(()),
            _ => Err(DecompressionFailed),
        }
    }
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Brotli
    }
}
