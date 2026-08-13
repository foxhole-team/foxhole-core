#![forbid(unsafe_code)]

mod crypto;
mod stream;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use foxcore_api::{Destination, VmessCipher, VmessConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream, datagram_channel, establish_stream};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::crypto::{aes128_encrypt_block, aes128_gcm_seal, crc32, fnv1a, kdf, md5, sha256};
use crate::stream::{DataCryptor, DataSession, LengthMask, relay_datagrams, wrap_data_stream};

const VMESS_UUID_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const OPTION_CHUNK_STREAM: u8 = 0x01;
const OPTION_CHUNK_MASKING: u8 = 0x04;
const HEADER_TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct VmessOutbound {
    config: Arc<VmessConfig>,
    dialer: ProtectedDialer,
}

impl VmessOutbound {
    pub async fn new(config: VmessConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        if config.alter_id != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VMess legacy alter_id is not supported",
            ));
        }
        parse_uuid(config.uuid.expose()).map_err(invalid)?;
        dialer
            .resolve_server_addresses(&config.server, config.port, config.server_ip)
            .await?;
        Ok(Self {
            config: Arc::new(config),
            dialer,
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let mut stream = establish_stream(
            tcp,
            &self.config.tls,
            &self.config.transport,
            &self.config.server,
            self.config.port,
        )
        .await?;

        let request = build_request(&self.config, destination, COMMAND_TCP)?;
        stream.write_all(&request.wire).await?;
        stream.flush().await?;
        Ok(wrap_data_stream(stream, request.session))
    }

    /// One VMess stream per destination, the way `command = UDP` is defined:
    /// the target lives in the request header, so the server sees a symmetric
    /// NAT and every destination needs its own session.
    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let mut stream = establish_stream(
            tcp,
            &self.config.tls,
            &self.config.transport,
            &self.config.server,
            self.config.port,
        )
        .await?;

        let request = build_request(&self.config, destination, COMMAND_UDP)?;
        stream.write_all(&request.wire).await?;
        stream.flush().await?;

        let (session, mut channels) = datagram_channel(64);
        let destination = destination.clone();
        tokio::spawn(async move {
            let _ = relay_datagrams(
                stream,
                destination,
                request.session,
                &mut channels.uplink,
                channels.downlink,
                channels.cancel,
            )
            .await;
        });
        Ok(session)
    }
}

struct BuiltRequest {
    wire: Zeroizing<Vec<u8>>,
    session: DataSession,
}

fn build_request(
    config: &VmessConfig,
    destination: &Destination,
    command: u8,
) -> io::Result<BuiltRequest> {
    let uuid = Zeroizing::new(parse_uuid(config.uuid.expose()).map_err(invalid)?);
    let mut instruction_material = Zeroizing::new(Vec::with_capacity(16 + VMESS_UUID_MAGIC.len()));
    instruction_material.extend_from_slice(uuid.as_ref());
    instruction_material.extend_from_slice(VMESS_UUID_MAGIC);
    let instruction_key = Zeroizing::new(md5(&instruction_material));

    let auth_id = build_auth_id(&instruction_key)?;
    let mut header = vec![0_u8; 34];
    header[0] = 1;
    random_fill(&mut header[1..34])?;
    let mut request_iv = Zeroizing::new([0_u8; 16]);
    request_iv.copy_from_slice(&header[1..17]);
    let mut request_key = Zeroizing::new([0_u8; 16]);
    request_key.copy_from_slice(&header[17..33]);
    let response_authentication = header[33];

    let response_iv_hash = Zeroizing::new(sha256(request_iv.as_ref()));
    let response_key_hash = Zeroizing::new(sha256(request_key.as_ref()));
    let mut response_iv = Zeroizing::new([0_u8; 16]);
    response_iv.copy_from_slice(&response_iv_hash[..16]);
    let mut response_key = Zeroizing::new([0_u8; 16]);
    response_key.copy_from_slice(&response_key_hash[..16]);

    let effective_cipher = match config.cipher {
        VmessCipher::Auto => VmessCipher::Chacha20Poly1305,
        cipher => cipher,
    };
    let encryption_method = match effective_cipher {
        VmessCipher::Aes128Gcm => 3,
        VmessCipher::Chacha20Poly1305 => 4,
        VmessCipher::None => 5,
        // Normalized immediately above; kept as a value rather than a panic
        // because the release profile aborts, and a header builder must not be
        // able to end the process.
        VmessCipher::Auto => 4,
    };
    header.push(OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING);
    let mut random_byte = [0_u8; 1];
    random_fill(&mut random_byte)?;
    let padding_len = random_byte[0] & 0x0f;
    header.push((padding_len << 4) | encryption_method);
    header.push(0);
    header.push(command);
    encode_destination(destination, &mut header)?;
    if padding_len > 0 {
        let start = header.len();
        header.resize(start + usize::from(padding_len), 0);
        random_fill(&mut header[start..])?;
    }
    header.extend_from_slice(&fnv1a(&header).to_be_bytes());

    let mut connection_nonce = [0_u8; 8];
    random_fill(&mut connection_nonce)?;
    let length_key = Zeroizing::new(kdf(
        instruction_key.as_ref(),
        &[b"VMess Header AEAD Key_Length", &auth_id, &connection_nonce],
    ));
    let length_nonce = Zeroizing::new(kdf(
        instruction_key.as_ref(),
        &[
            b"VMess Header AEAD Nonce_Length",
            &auth_id,
            &connection_nonce,
        ],
    ));
    let header_len =
        u16::try_from(header.len()).map_err(|_| invalid("VMess request header exceeds u16"))?;
    let mut encrypted_length = header_len.to_be_bytes();
    let length_tag = aes128_gcm_seal(
        &length_key[..16],
        &length_nonce[..12],
        &auth_id,
        &mut encrypted_length,
    )
    .map_err(|_| io::Error::other("VMess header length encryption failed"))?;

    let header_key = Zeroizing::new(kdf(
        instruction_key.as_ref(),
        &[b"VMess Header AEAD Key", &auth_id, &connection_nonce],
    ));
    let header_nonce = Zeroizing::new(kdf(
        instruction_key.as_ref(),
        &[b"VMess Header AEAD Nonce", &auth_id, &connection_nonce],
    ));
    let header_tag = aes128_gcm_seal(
        &header_key[..16],
        &header_nonce[..12],
        &auth_id,
        &mut header,
    )
    .map_err(|_| io::Error::other("VMess request header encryption failed"))?;

    let mut wire = Zeroizing::new(Vec::with_capacity(
        auth_id.len() + 2 + HEADER_TAG_LEN + connection_nonce.len() + header.len() + HEADER_TAG_LEN,
    ));
    wire.extend_from_slice(&auth_id);
    wire.extend_from_slice(&encrypted_length);
    wire.extend_from_slice(&length_tag);
    wire.extend_from_slice(&connection_nonce);
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&header_tag);

    let outgoing = DataCryptor::new(effective_cipher, &request_key, &request_iv)?;
    let incoming = DataCryptor::new(effective_cipher, &response_key, &response_iv)?;
    let outgoing_mask = LengthMask::new(&request_iv);
    let incoming_mask = LengthMask::new(&response_iv);

    Ok(BuiltRequest {
        wire,
        session: DataSession {
            outgoing,
            incoming,
            outgoing_mask,
            incoming_mask,
            response_key,
            response_iv,
            response_authentication,
        },
    })
}

fn build_auth_id(instruction_key: &[u8; 16]) -> io::Result<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before Unix epoch"))?
        .as_secs();
    let mut random = [0_u8; 5];
    random_fill(&mut random)?;
    // The reference sends the current second unmodified and the server rejects
    // anything more than 120 s away. Jittering across that whole window put a
    // slice of connections outside it for any client with clock skew, and bought
    // nothing: the timestamp travels inside an AES block no observer can read.
    let timestamp = now;
    let mut auth_id = [0_u8; 16];
    auth_id[..8].copy_from_slice(&timestamp.to_be_bytes());
    auth_id[8..12].copy_from_slice(&random[1..]);
    let checksum = crc32(&auth_id[..12]).to_be_bytes();
    auth_id[12..].copy_from_slice(&checksum);
    let auth_key = Zeroizing::new(kdf(instruction_key, &[b"AES Auth ID Encryption"]));
    let mut block_key = Zeroizing::new([0_u8; 16]);
    block_key.copy_from_slice(&auth_key[..16]);
    aes128_encrypt_block(&block_key, &mut auth_id);
    Ok(auth_id)
}

fn encode_destination(destination: &Destination, output: &mut Vec<u8>) -> io::Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            output.push(3);
            output.extend_from_slice(&address.octets());
        }
        None => {
            let domain = destination.host.as_bytes();
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(invalid(
                    "VMess destination domain length is outside 1..=255",
                ));
            }
            output.push(2);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain);
        }
    }
    Ok(())
}

fn random_fill(output: &mut [u8]) -> io::Result<()> {
    getrandom::fill(output).map_err(|_| io::Error::other("operating system RNG failed"))
}

pub fn parse_uuid(value: &str) -> Result<[u8; 16], String> {
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 {
        return Err(format!(
            "bad UUID length ({} hex characters)",
            compact.len()
        ));
    }
    let mut uuid = [0_u8; 16];
    for (index, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|_| "bad UUID hex".to_owned())?;
    }
    Ok(uuid)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use foxcore_api::{StreamTransportConfig, TlsConfig};

    fn config(cipher: VmessCipher) -> VmessConfig {
        VmessConfig {
            server: "vmess.example".into(),
            port: 443,
            server_ip: None,
            uuid: foxcore_api::SecretString::new("d0cf0001-0000-4000-8000-000000000000"),
            alter_id: 0,
            cipher,
            transport: StreamTransportConfig::Raw,
            tls: TlsConfig::default(),
        }
    }

    #[test]
    fn parses_uuid_with_or_without_hyphens() {
        let canonical = parse_uuid("d0cf0001-0000-4000-8000-000000000000").unwrap();
        let compact = parse_uuid("d0cf0001000040008000000000000000").unwrap();
        assert_eq!(canonical, compact);
    }

    #[test]
    fn builds_bounded_aead_request_for_every_modern_cipher() {
        for cipher in [
            VmessCipher::Auto,
            VmessCipher::Aes128Gcm,
            VmessCipher::Chacha20Poly1305,
            VmessCipher::None,
        ] {
            let request = build_request(
                &config(cipher),
                &Destination::new("example.com", 443),
                COMMAND_TCP,
            )
            .unwrap();
            assert!((90..=400).contains(&request.wire.len()));
            assert_ne!(&request.wire[..16], &[0_u8; 16]);
        }
    }

    #[test]
    fn rejects_oversized_domain_without_allocating_wire_buffers() {
        let destination = Destination::new("a".repeat(256), 443);
        assert!(build_request(&config(VmessCipher::Auto), &destination, COMMAND_TCP).is_err());
    }

    #[test]
    fn the_response_direction_is_keyed_by_sha256_not_md5() {
        // A golden vector on the one derivation the whole downlink depends on.
        // Getting this wrong looks exactly like "the server never answers".
        let request_key = [0x11_u8; 16];
        let request_iv = [0x22_u8; 16];
        assert_eq!(
            &sha256(&request_key)[..16],
            &[
                0xb8, 0xf1, 0x2e, 0xa8, 0xc9, 0xa9, 0x5d, 0x4b, 0x46, 0x41, 0xb0, 0x3d, 0x9f, 0xa5,
                0xa7, 0x1a
            ]
        );
        assert_eq!(
            &sha256(&request_iv)[..16],
            &[
                0x3d, 0xc3, 0x0f, 0xba, 0xc8, 0x41, 0x7f, 0x76, 0x94, 0x3e, 0x9c, 0x10, 0xe1, 0x5e,
                0xea, 0xcb
            ]
        );
    }
}

/// A server that follows the reference wire format, written out here rather
/// than borrowed from the client, so the test pins the format instead of
/// agreeing with whatever the client happens to do.
#[cfg(test)]
mod udp_wire_tests {
    use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
    use aes_gcm::{Aes128Gcm, Nonce, Tag};
    use bytes::Bytes;
    use foxcore_api::{StreamTransportConfig, TlsConfig};
    use foxcore_transport::{BoxStream, Datagram};
    use sha3::Shake128;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::crypto::aes128_gcm_open;

    const UUID: &str = "d0cf0001-0000-4000-8000-000000000000";

    fn config() -> VmessConfig {
        VmessConfig {
            server: "vmess.example".into(),
            port: 443,
            server_ip: None,
            uuid: foxcore_api::SecretString::new(UUID),
            alter_id: 0,
            cipher: VmessCipher::Aes128Gcm,
            transport: StreamTransportConfig::Raw,
            tls: TlsConfig::default(),
        }
    }

    struct Mask(Box<dyn XofReader + Send>);

    impl Mask {
        fn new(iv: &[u8; 16]) -> Self {
            let mut shake = Shake128::default();
            shake.update(iv);
            Self(Box::new(shake.finalize_xof()))
        }

        fn next(&mut self) -> u16 {
            let mut bytes = [0_u8; 2];
            self.0.read(&mut bytes);
            u16::from_be_bytes(bytes)
        }
    }

    fn chunk_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        nonce[2..].copy_from_slice(&iv[2..12]);
        nonce
    }

    fn seal(key: &[u8; 16], iv: &[u8; 16], counter: u16, payload: &[u8]) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(key).unwrap();
        let mut buffer = payload.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&chunk_nonce(iv, counter)),
                b"",
                &mut buffer,
            )
            .unwrap();
        buffer.extend_from_slice(&tag);
        buffer
    }

    fn open(key: &[u8; 16], iv: &[u8; 16], counter: u16, frame: &[u8]) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(key).unwrap();
        let (body, tag) = frame.split_at(frame.len() - 16);
        let mut buffer = body.to_vec();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&chunk_nonce(iv, counter)),
                b"",
                &mut buffer,
                Tag::from_slice(tag),
            )
            .unwrap();
        buffer
    }

    /// Decode a client request header the way a VMess inbound does.
    async fn read_request<R: tokio::io::AsyncRead + Unpin>(
        wire: &mut R,
    ) -> (u8, [u8; 16], [u8; 16], u8) {
        let command_key = {
            let uuid = parse_uuid(UUID).unwrap();
            let mut material = uuid.to_vec();
            material.extend_from_slice(VMESS_UUID_MAGIC);
            md5(&material)
        };

        let mut auth_id = [0_u8; 16];
        wire.read_exact(&mut auth_id).await.unwrap();
        let mut length = [0_u8; 2 + HEADER_TAG_LEN];
        wire.read_exact(&mut length).await.unwrap();
        let mut nonce = [0_u8; 8];
        wire.read_exact(&mut nonce).await.unwrap();

        let length_key = kdf(
            &command_key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
        );
        let length_nonce = kdf(
            &command_key,
            &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
        );
        let tag: [u8; HEADER_TAG_LEN] = length[2..].try_into().unwrap();
        aes128_gcm_open(
            &length_key[..16],
            &length_nonce[..12],
            &auth_id,
            &mut length[..2],
            &tag,
        )
        .expect("the inbound must be able to open the request length");
        let header_len = usize::from(u16::from_be_bytes([length[0], length[1]]));

        let mut header = vec![0_u8; header_len + HEADER_TAG_LEN];
        wire.read_exact(&mut header).await.unwrap();
        let header_key = kdf(&command_key, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
        let header_nonce = kdf(
            &command_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
        );
        let tag: [u8; HEADER_TAG_LEN] = header[header_len..].try_into().unwrap();
        header.truncate(header_len);
        aes128_gcm_open(
            &header_key[..16],
            &header_nonce[..12],
            &auth_id,
            &mut header,
            &tag,
        )
        .expect("the inbound must be able to open the request header");

        let mut request_iv = [0_u8; 16];
        request_iv.copy_from_slice(&header[1..17]);
        let mut request_key = [0_u8; 16];
        request_key.copy_from_slice(&header[17..33]);
        (header[37], request_key, request_iv, header[33])
    }

    #[tokio::test]
    async fn a_udp_session_keeps_one_datagram_per_chunk_in_both_directions() {
        let destination = Destination::new("1.1.1.1", 53);
        let request = build_request(&config(), &destination, COMMAND_UDP).unwrap();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut client: BoxStream = Box::new(client);
        client.write_all(&request.wire).await.unwrap();

        let (session, mut channels) = datagram_channel(8);
        let relay_destination = destination.clone();
        tokio::spawn(async move {
            relay_datagrams(
                client,
                relay_destination,
                request.session,
                &mut channels.uplink,
                channels.downlink,
                channels.cancel,
            )
            .await
        });

        let (command, request_key, request_iv, authentication) = read_request(&mut server).await;
        assert_eq!(command, COMMAND_UDP, "UDP flows must ask for command 2");

        session
            .send(Datagram::new(
                destination.clone(),
                Bytes::from_static(b"query-1"),
            ))
            .await
            .unwrap();
        session
            .send(Datagram::new(
                destination.clone(),
                Bytes::from_static(b"query-two"),
            ))
            .await
            .unwrap();

        let mut uplink_mask = Mask::new(&request_iv);
        for (counter, expected) in [(0_u16, &b"query-1"[..]), (1, &b"query-two"[..])] {
            let masked = server.read_u16().await.unwrap();
            let frame_len = usize::from(masked ^ uplink_mask.next());
            let mut frame = vec![0_u8; frame_len];
            server.read_exact(&mut frame).await.unwrap();
            assert_eq!(
                open(&request_key, &request_iv, counter, &frame),
                expected,
                "each datagram must be sealed as exactly one chunk"
            );
        }

        // Reply: response header, then one chunk per datagram.
        let mut response_key = [0_u8; 16];
        response_key.copy_from_slice(&sha256(&request_key)[..16]);
        let mut response_iv = [0_u8; 16];
        response_iv.copy_from_slice(&sha256(&request_iv)[..16]);

        let mut header = [authentication, 0, 0, 0];
        let content_key = kdf(&response_key, &[b"AEAD Resp Header Key"]);
        let content_nonce = kdf(&response_iv, &[b"AEAD Resp Header IV"]);
        let content_tag = crate::crypto::aes128_gcm_seal(
            &content_key[..16],
            &content_nonce[..12],
            b"",
            &mut header,
        )
        .unwrap();
        let mut length = (4_u16).to_be_bytes();
        let length_key = kdf(&response_key, &[b"AEAD Resp Header Len Key"]);
        let length_nonce = kdf(&response_iv, &[b"AEAD Resp Header Len IV"]);
        let length_tag = crate::crypto::aes128_gcm_seal(
            &length_key[..16],
            &length_nonce[..12],
            b"",
            &mut length,
        )
        .unwrap();
        server.write_all(&length).await.unwrap();
        server.write_all(&length_tag).await.unwrap();
        server.write_all(&header).await.unwrap();
        server.write_all(&content_tag).await.unwrap();

        let mut downlink_mask = Mask::new(&response_iv);
        for (counter, payload) in [(0_u16, &b"answer-1"[..]), (1, &b"answer-number-two"[..])] {
            let frame = seal(&response_key, &response_iv, counter, payload);
            let masked = frame.len() as u16 ^ downlink_mask.next();
            server.write_all(&masked.to_be_bytes()).await.unwrap();
            server.write_all(&frame).await.unwrap();
        }

        let first = session.recv().await.unwrap();
        let second = session.recv().await.unwrap();
        assert_eq!(
            &first.payload[..],
            b"answer-1",
            "two replies must not arrive concatenated"
        );
        assert_eq!(&second.payload[..], b"answer-number-two");
    }
}
