use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey, quic};
use aws_lc_rs::hkdf::{self, HKDF_SHA256, Salt};

pub const VERSION_1: u32 = 0x0000_0001;
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub const QUIC_TRANSPORT_PARAMETERS_EXTENSION: u16 = 0x0039;

pub mod transport_parameter {
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub const VERSION_INFORMATION: u64 = 0x11;
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x0020;
    pub const GREASE_QUIC_BIT: u64 = 0x2ab2;
    pub const MIN_ACK_DELAY_DRAFT07: u64 = 0xff04_de1b;

    pub fn is_reserved(id: u64) -> bool {
        id >= 27 && (id - 27).is_multiple_of(31)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding { len: usize },
    Ping,
    Ack,
    Crypto { offset: u64, len: usize },
    ConnectionClose,
    Other { ty: u64 },
}

#[derive(Debug, Clone)]
pub struct InitialPacket {
    pub first_byte: u8,
    pub version: u32,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_number: u64,
    pub packet_number_len: usize,
    pub frames: Vec<Frame>,
    pub crypto: Vec<(u64, Vec<u8>)>,
    pub packet_len: usize,
}

#[derive(Debug, Clone)]
pub struct InitialDatagram {
    pub len: usize,
    pub packets: Vec<InitialPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameter {
    pub id: u64,
    pub value: Vec<u8>,
}

impl TransportParameter {
    pub fn as_varint(&self) -> Option<u64> {
        let mut cursor = Cursor::new(&self.value);
        let value = cursor.varint().ok()?;
        cursor.done().then_some(value)
    }
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn done(&self) -> bool {
        self.remaining() == 0
    }

    fn byte(&mut self) -> io::Result<u8> {
        let value = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| other("QUIC packet ended mid-field"))?;
        self.at += 1;
        Ok(value)
    }

    fn slice(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| other("QUIC length overflow"))?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| other("QUIC packet ended mid-field"))?;
        self.at = end;
        Ok(value)
    }

    fn varint(&mut self) -> io::Result<u64> {
        let first = self.byte()?;
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..len {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(value)
    }
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(secret: &hkdf::Prk, label: &str, len: usize) -> io::Result<Vec<u8>> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(
        &u16::try_from(len)
            .map_err(|_| other("label too long"))?
            .to_be_bytes(),
    );
    info.push(u8::try_from(6 + label.len()).map_err(|_| other("label too long"))?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let mut out = vec![0u8; len];
    secret
        .expand(&[&info], Len(len))
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| other("HKDF expand failed"))?;
    Ok(out)
}

struct InitialKeys {
    key: LessSafeKey,
    iv: [u8; 12],
    header_protection: quic::HeaderProtectionKey,
}

impl InitialKeys {
    fn client(dcid: &[u8], version: u32) -> io::Result<Self> {
        if version != VERSION_1 {
            return Err(other(format!(
                "only QUIC v1 Initial keys are derived here, got version {version:#010x}"
            )));
        }
        let initial_secret = Salt::new(HKDF_SHA256, &INITIAL_SALT_V1).extract(dcid);
        let client_secret = expand_label(&initial_secret, "client in", 32)?;
        let client_secret = hkdf::Prk::new_less_safe(HKDF_SHA256, &client_secret);

        let key = expand_label(&client_secret, "quic key", 16)?;
        let iv = expand_label(&client_secret, "quic iv", 12)?;
        let hp = expand_label(&client_secret, "quic hp", 16)?;

        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(&AES_128_GCM, &key).map_err(|_| other("bad AES-128-GCM key"))?,
            ),
            iv: iv.try_into().map_err(|_| other("bad QUIC IV length"))?,
            header_protection: quic::HeaderProtectionKey::new(&quic::AES_128, &hp)
                .map_err(|_| other("bad QUIC header-protection key"))?,
        })
    }
}

pub fn parse_datagram(datagram: &[u8]) -> io::Result<InitialDatagram> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < datagram.len() {
        let rest = &datagram[offset..];
        if rest[0] == 0 || rest[0] & 0x80 == 0 {
            break;
        }
        if rest[0] & 0x30 != 0x00 {
            break;
        }
        let packet = parse_initial(rest)?;
        offset += packet.packet_len;
        packets.push(packet);
    }
    if packets.is_empty() {
        return Err(other("datagram carried no QUIC Initial packet"));
    }
    Ok(InitialDatagram {
        len: datagram.len(),
        packets,
    })
}

pub fn parse_initial(bytes: &[u8]) -> io::Result<InitialPacket> {
    let mut cursor = Cursor::new(bytes);
    let protected_first = cursor.byte()?;
    if protected_first & 0x80 == 0 {
        return Err(other("not a QUIC long-header packet"));
    }
    let version = u32::from_be_bytes(
        cursor
            .slice(4)?
            .try_into()
            .map_err(|_| other("short version"))?,
    );
    let dcid_len = usize::from(cursor.byte()?);
    let dcid = cursor.slice(dcid_len)?.to_vec();
    let scid_len = usize::from(cursor.byte()?);
    let scid = cursor.slice(scid_len)?.to_vec();
    let token_len =
        usize::try_from(cursor.varint()?).map_err(|_| other("token length overflow"))?;
    let token = cursor.slice(token_len)?.to_vec();
    let length = usize::try_from(cursor.varint()?).map_err(|_| other("length overflow"))?;
    let pn_offset = cursor.at;

    let sample = bytes
        .get(pn_offset + 4..pn_offset + 4 + 16)
        .ok_or_else(|| other("packet too short for a header-protection sample"))?;
    let keys = InitialKeys::client(&dcid, version)?;
    let mask = keys
        .header_protection
        .new_mask(sample)
        .map_err(|_| other("header-protection mask failed"))?;

    let first_byte = protected_first ^ (mask[0] & 0x0f);
    let packet_number_len = usize::from(first_byte & 0x03) + 1;
    let mut packet_number = 0u64;
    let mut header = bytes
        .get(..pn_offset + packet_number_len)
        .ok_or_else(|| other("packet too short for its packet number"))?
        .to_vec();
    header[0] = first_byte;
    for index in 0..packet_number_len {
        let byte = header[pn_offset + index] ^ mask[1 + index];
        header[pn_offset + index] = byte;
        packet_number = (packet_number << 8) | u64::from(byte);
    }

    let packet_len = pn_offset + length;
    let ciphertext = bytes
        .get(pn_offset + packet_number_len..packet_len)
        .ok_or_else(|| other("packet shorter than its own length field"))?;

    let mut nonce = keys.iv;
    for (index, byte) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    let mut payload = ciphertext.to_vec();
    let plaintext = keys
        .key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut payload,
        )
        .map_err(|_| other("Initial packet failed AEAD authentication"))?;

    let (frames, crypto) = parse_frames(plaintext)?;
    Ok(InitialPacket {
        first_byte,
        version,
        destination_connection_id: dcid,
        source_connection_id: scid,
        token,
        packet_number,
        packet_number_len,
        frames,
        crypto,
        packet_len,
    })
}

#[allow(clippy::type_complexity)]
fn parse_frames(payload: &[u8]) -> io::Result<(Vec<Frame>, Vec<(u64, Vec<u8>)>)> {
    let mut cursor = Cursor::new(payload);
    let mut frames: Vec<Frame> = Vec::new();
    let mut crypto = Vec::new();
    while !cursor.done() {
        let ty = cursor.varint()?;
        match ty {
            0x00 => match frames.last_mut() {
                Some(Frame::Padding { len }) => *len += 1,
                _ => frames.push(Frame::Padding { len: 1 }),
            },
            0x01 => frames.push(Frame::Ping),
            0x02 | 0x03 => {
                let _largest = cursor.varint()?;
                let _delay = cursor.varint()?;
                let ranges = cursor.varint()?;
                let _first = cursor.varint()?;
                for _ in 0..ranges {
                    let _gap = cursor.varint()?;
                    let _range = cursor.varint()?;
                }
                if ty == 0x03 {
                    for _ in 0..3 {
                        let _ecn = cursor.varint()?;
                    }
                }
                frames.push(Frame::Ack);
            }
            0x06 => {
                let offset = cursor.varint()?;
                let len = usize::try_from(cursor.varint()?)
                    .map_err(|_| other("CRYPTO length overflow"))?;
                let data = cursor.slice(len)?;
                frames.push(Frame::Crypto { offset, len });
                crypto.push((offset, data.to_vec()));
            }
            0x1c | 0x1d => {
                let _code = cursor.varint()?;
                if ty == 0x1c {
                    let _frame_type = cursor.varint()?;
                }
                let len = usize::try_from(cursor.varint()?)
                    .map_err(|_| other("close reason length overflow"))?;
                let _reason = cursor.slice(len)?;
                frames.push(Frame::ConnectionClose);
            }
            other_ty => {
                frames.push(Frame::Other { ty: other_ty });
                break;
            }
        }
    }
    Ok((frames, crypto))
}

pub fn client_hello(datagrams: &[InitialDatagram]) -> io::Result<Vec<u8>> {
    let mut chunks: Vec<(u64, &[u8])> = Vec::new();
    for datagram in datagrams {
        for packet in &datagram.packets {
            for (offset, data) in &packet.crypto {
                chunks.push((*offset, data));
            }
        }
    }
    chunks.sort_by_key(|(offset, _)| *offset);

    let mut stream: Vec<u8> = Vec::new();
    for (offset, data) in chunks {
        let offset = usize::try_from(offset).map_err(|_| other("CRYPTO offset overflow"))?;
        if offset > stream.len() {
            return Err(other(format!(
                "CRYPTO stream has a hole at {}..{offset}",
                stream.len()
            )));
        }
        let already = stream.len() - offset;
        if already < data.len() {
            stream.extend_from_slice(&data[already..]);
        }
    }

    if stream.first() != Some(&0x01) {
        return Err(other("CRYPTO stream does not begin with a ClientHello"));
    }
    let body_len = stream
        .get(1..4)
        .map(|len| usize::from(len[0]) << 16 | usize::from(len[1]) << 8 | usize::from(len[2]))
        .ok_or_else(|| other("CRYPTO stream shorter than a handshake header"))?;
    let total = 4 + body_len;
    if stream.len() < total {
        return Err(other(format!(
            "ClientHello is {} bytes short of its declared {total}",
            total - stream.len()
        )));
    }
    stream.truncate(total);
    Ok(stream)
}

pub fn transport_parameters(client_hello: &[u8]) -> io::Result<Vec<TransportParameter>> {
    let extension = find_extension(client_hello, QUIC_TRANSPORT_PARAMETERS_EXTENSION)
        .ok_or_else(|| other("ClientHello carries no quic_transport_parameters extension"))?;
    let mut cursor = Cursor::new(extension);
    let mut parameters = Vec::new();
    while !cursor.done() {
        let id = cursor.varint()?;
        let len =
            usize::try_from(cursor.varint()?).map_err(|_| other("parameter length overflow"))?;
        parameters.push(TransportParameter {
            id,
            value: cursor.slice(len)?.to_vec(),
        });
    }
    Ok(parameters)
}

pub struct InitialCapture {
    socket: UdpSocket,
}

#[derive(Debug, Clone)]
pub struct CapturedFlight {
    pub datagrams: Vec<InitialDatagram>,
    pub client_hello: Vec<u8>,
}

impl CapturedFlight {
    pub fn datagram_lens(&self) -> Vec<usize> {
        self.datagrams.iter().map(|d| d.len).collect()
    }

    pub fn first_packet(&self) -> &InitialPacket {
        &self.datagrams[0].packets[0]
    }

    pub fn transport_parameters(&self) -> io::Result<Vec<TransportParameter>> {
        transport_parameters(&self.client_hello)
    }
}

impl InitialCapture {
    pub fn bind() -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn collect_first_flight(&self, window: Duration) -> io::Result<CapturedFlight> {
        let deadline = Instant::now() + window;
        let mut datagrams = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(other(format!(
                    "no complete ClientHello within {window:?} ({} datagram(s) seen)",
                    datagrams.len()
                )));
            }
            self.socket.set_read_timeout(Some(left))?;
            let read = match self.socket.recv(&mut buffer) {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            datagrams.push(parse_datagram(&buffer[..read])?);
            if let Ok(client_hello) = client_hello(&datagrams) {
                return Ok(CapturedFlight {
                    datagrams,
                    client_hello,
                });
            }
        }
    }
}

pub fn find_extension(client_hello: &[u8], wanted: u16) -> Option<&[u8]> {
    let be16 = |at: usize| -> Option<usize> {
        Some(usize::from(u16::from_be_bytes([
            *client_hello.get(at)?,
            *client_hello.get(at + 1)?,
        ])))
    };
    let session_id_len = usize::from(*client_hello.get(38)?);
    let mut cursor = 39 + session_id_len;
    cursor += 2 + be16(cursor)?;
    cursor += 1 + usize::from(*client_hello.get(cursor)?);
    let extensions_len = be16(cursor)?;
    cursor += 2;
    let end = cursor + extensions_len;
    while cursor + 4 <= end {
        let ty = be16(cursor)?;
        let len = be16(cursor + 2)?;
        if u16::try_from(ty).ok()? == wanted {
            return client_hello.get(cursor + 4..cursor + 4 + len);
        }
        cursor += 4 + len;
    }
    None
}
