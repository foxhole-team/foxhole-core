use std::io;
use std::net::IpAddr;

use bytes::{BufMut, Bytes, BytesMut};
use foxcore_api::Destination;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const HEADER_LEN: usize = 7;
pub(crate) const CMD_WASTE: u8 = 0;
pub(crate) const CMD_SYN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_FIN: u8 = 3;
pub(crate) const CMD_SETTINGS: u8 = 4;
pub(crate) const CMD_ALERT: u8 = 5;
pub(crate) const CMD_UPDATE_PADDING: u8 = 6;
pub(crate) const CMD_SYNACK: u8 = 7;
pub(crate) const CMD_HEART_REQUEST: u8 = 8;
pub(crate) const CMD_HEART_RESPONSE: u8 = 9;
pub(crate) const CMD_SERVER_SETTINGS: u8 = 10;

const SOCKS_IPV4: u8 = 1;
const SOCKS_DOMAIN: u8 = 3;
const SOCKS_IPV6: u8 = 4;

#[derive(Debug)]
pub(crate) struct Frame {
    pub command: u8,
    pub stream_id: u32,
    pub data: Bytes,
}

pub(crate) fn encode_frame(
    command: u8,
    stream_id: u32,
    data: &[u8],
    output: &mut BytesMut,
) -> io::Result<()> {
    let length = u16::try_from(data.len())
        .map_err(|_| invalid("AnyTLS frame payload exceeds 65535 bytes"))?;
    output.reserve(HEADER_LEN + data.len());
    output.put_u8(command);
    output.put_u32(stream_id);
    output.put_u16(length);
    output.extend_from_slice(data);
    Ok(())
}

pub(crate) async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let command = reader.read_u8().await?;
    let stream_id = reader.read_u32().await?;
    let length = reader.read_u16().await? as usize;
    let mut data = BytesMut::zeroed(length);
    reader.read_exact(&mut data).await?;
    Ok(Frame {
        command,
        stream_id,
        data: data.freeze(),
    })
}

pub(crate) fn encode_socks_address(
    destination: &Destination,
    output: &mut BytesMut,
) -> io::Result<()> {
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            output.put_u8(SOCKS_IPV4);
            output.extend_from_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            output.put_u8(SOCKS_IPV6);
            output.extend_from_slice(&address.octets());
        }
        None => {
            let domain = destination.host.as_bytes();
            let length = u8::try_from(domain.len())
                .map_err(|_| invalid("AnyTLS destination domain exceeds 255 bytes"))?;
            if length == 0 {
                return Err(invalid("AnyTLS destination domain is empty"));
            }
            output.put_u8(SOCKS_DOMAIN);
            output.put_u8(length);
            output.extend_from_slice(domain);
        }
    }
    output.put_u16(destination.port);
    Ok(())
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_is_network_order() {
        let mut encoded = BytesMut::new();
        encode_frame(CMD_PSH, 0x0102_0304, b"abc", &mut encoded).unwrap();
        assert_eq!(&encoded[..7], &[2, 1, 2, 3, 4, 0, 3]);
        assert_eq!(&encoded[7..], b"abc");
    }

    #[test]
    fn socks_address_matches_rfc_1928() {
        let mut encoded = BytesMut::new();
        encode_socks_address(&Destination::new("example.com", 443), &mut encoded).unwrap();
        assert_eq!(encoded[0], SOCKS_DOMAIN);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..], &443_u16.to_be_bytes());
    }
}
