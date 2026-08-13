use std::io;
use std::net::IpAddr;

use bytes::{BufMut, BytesMut};
use foxcore_api::Destination;
use foxcore_transport::{BoxDatagramSession, BoxStream, Datagram, datagram_channel};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_IPV4: u8 = 0;
const UOT_IPV6: u8 = 1;
const UOT_DOMAIN: u8 = 2;

pub(crate) fn magic_destination() -> Destination {
    Destination::new(MAGIC_HOST, 0)
}

pub(crate) async fn open(
    mut stream: BoxStream,
    default_destination: Destination,
) -> io::Result<BoxDatagramSession> {
    // UoT v2 non-connect mode. The request still carries a destination for
    // compatibility, while every subsequent datagram carries its own address.
    let mut request = BytesMut::with_capacity(32);
    request.put_u8(0);
    encode_socks_address(&default_destination, &mut request)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let (session, mut channels) = datagram_channel(64);
    let cancel = channels.cancel.clone();
    tokio::spawn(async move {
        relay(
            stream,
            default_destination,
            &mut channels.uplink,
            channels.downlink,
            cancel,
        )
        .await;
    });
    Ok(session)
}

async fn relay(
    stream: BoxStream,
    default_destination: Destination,
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let upload_cancel = cancel.clone();
    let upload = async {
        loop {
            tokio::select! {
                _ = upload_cancel.cancelled() => break,
                outgoing = uplink.recv() => {
                    let Some(outgoing) = outgoing else { break };
                    if outgoing.payload.len() > u16::MAX as usize {
                        continue;
                    }
                    let destination = if outgoing.destination.host.is_empty() {
                        &default_destination
                    } else {
                        &outgoing.destination
                    };
                    let mut frame = BytesMut::with_capacity(32 + outgoing.payload.len());
                    if encode_uot_address(destination, &mut frame).is_err() {
                        continue;
                    }
                    frame.put_u16(outgoing.payload.len() as u16);
                    frame.extend_from_slice(&outgoing.payload);
                    tokio::select! {
                        _ = upload_cancel.cancelled() => break,
                        written = writer.write_all(&frame) => {
                            if written.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        let _ = writer.shutdown().await;
    };
    let download = async {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                received = read_datagram(&mut reader) => {
                    let Ok(datagram) = received else { break };
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        sent = downlink.send(datagram) => {
                            if sent.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    };
    tokio::pin!(upload);
    tokio::pin!(download);
    tokio::select! {
        _ = &mut upload => {}
        _ = &mut download => {}
    }
}

async fn read_datagram<R>(reader: &mut R) -> io::Result<Datagram>
where
    R: AsyncRead + Unpin,
{
    let destination = read_uot_address(reader).await?;
    let length = reader.read_u16().await? as usize;
    let mut payload = BytesMut::zeroed(length);
    reader.read_exact(&mut payload).await?;
    Ok(Datagram::new(destination, payload.freeze()))
}

fn encode_socks_address(destination: &Destination, output: &mut BytesMut) -> io::Result<()> {
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            output.put_u8(1);
            output.extend_from_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            output.put_u8(4);
            output.extend_from_slice(&address.octets());
        }
        None => {
            let domain = destination.host.as_bytes();
            let length = u8::try_from(domain.len())
                .map_err(|_| invalid("UoT destination domain exceeds 255 bytes"))?;
            if length == 0 {
                return Err(invalid("UoT destination domain is empty"));
            }
            output.put_u8(3);
            output.put_u8(length);
            output.extend_from_slice(domain);
        }
    }
    output.put_u16(destination.port);
    Ok(())
}

fn encode_uot_address(destination: &Destination, output: &mut BytesMut) -> io::Result<()> {
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            output.put_u8(UOT_IPV4);
            output.extend_from_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            output.put_u8(UOT_IPV6);
            output.extend_from_slice(&address.octets());
        }
        None => {
            let domain = destination.host.as_bytes();
            let length = u8::try_from(domain.len())
                .map_err(|_| invalid("UoT destination domain exceeds 255 bytes"))?;
            if length == 0 {
                return Err(invalid("UoT destination domain is empty"));
            }
            output.put_u8(UOT_DOMAIN);
            output.put_u8(length);
            output.extend_from_slice(domain);
        }
    }
    output.put_u16(destination.port);
    Ok(())
}

async fn read_uot_address<R>(reader: &mut R) -> io::Result<Destination>
where
    R: AsyncRead + Unpin,
{
    let host = match reader.read_u8().await? {
        UOT_IPV4 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        UOT_IPV6 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        UOT_DOMAIN => {
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid("UoT datagram has an empty domain"));
            }
            let mut domain = vec![0_u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| invalid("UoT domain is not UTF-8"))?
        }
        _ => return Err(invalid("UoT datagram has an unknown address type")),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_connect_datagram_roundtrips() {
        let mut frame = BytesMut::new();
        encode_uot_address(&Destination::new("example.com", 53), &mut frame).unwrap();
        frame.put_u16(3);
        frame.extend_from_slice(b"dns");
        let mut reader = &frame[..];
        let datagram = read_datagram(&mut reader).await.unwrap();
        assert_eq!(datagram.destination, Destination::new("example.com", 53));
        assert_eq!(datagram.payload, bytes::Bytes::from_static(b"dns"));
    }
}
