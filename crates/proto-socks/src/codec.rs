//! RFC 1928 / RFC 1929 wire codec.
//!
//! Everything here is length-checked before a single byte is allocated: the
//! only variable-length field a SOCKS5 peer controls is the domain name, and it
//! is capped at 255 bytes by the protocol itself.

use std::net::IpAddr;

use bytes::{BufMut, BytesMut};
use foxcore_api::Destination;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{SocksError, SocksReply};

pub(crate) const VERSION: u8 = 0x05;
pub(crate) const AUTH_VERSION: u8 = 0x01;
pub(crate) const METHOD_NO_AUTH: u8 = 0x00;
pub(crate) const METHOD_USERNAME_PASSWORD: u8 = 0x02;
pub(crate) const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
pub(crate) const CMD_CONNECT: u8 = 0x01;
pub(crate) const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub(crate) const ATYP_IPV4: u8 = 0x01;
pub(crate) const ATYP_DOMAIN: u8 = 0x03;
pub(crate) const ATYP_IPV6: u8 = 0x04;

/// Largest SOCKS5 UDP request that can ride in one IPv4 datagram payload.
pub(crate) const MAX_UDP_DATAGRAM: usize = 65_507;

/// Offer exactly one method.
///
/// When credentials are configured we deliberately do *not* also offer
/// `NO_AUTHENTICATION_REQUIRED`: a server picking 0x00 would drop the
/// configured authentication without anyone noticing, which is precisely the
/// silent downgrade the core forbids.
pub(crate) fn encode_greeting(authenticated: bool) -> BytesMut {
    let method = if authenticated {
        METHOD_USERNAME_PASSWORD
    } else {
        METHOD_NO_AUTH
    };
    let mut out = BytesMut::with_capacity(3);
    out.put_slice(&[VERSION, 0x01, method]);
    out
}

pub(crate) fn encode_auth(username: &str, password: &str) -> Result<BytesMut, SocksError> {
    let username = username.as_bytes();
    let password = password.as_bytes();
    if username.is_empty() || username.len() > u8::MAX as usize {
        return Err(SocksError::Malformed(
            "SOCKS5 username must contain 1..=255 bytes",
        ));
    }
    if password.is_empty() || password.len() > u8::MAX as usize {
        return Err(SocksError::Malformed(
            "SOCKS5 password must contain 1..=255 bytes",
        ));
    }
    let mut out = BytesMut::with_capacity(3 + username.len() + password.len());
    out.put_u8(AUTH_VERSION);
    out.put_u8(username.len() as u8);
    out.put_slice(username);
    out.put_u8(password.len() as u8);
    out.put_slice(password);
    Ok(out)
}

pub(crate) fn encode_request(
    command: u8,
    destination: &Destination,
) -> Result<BytesMut, SocksError> {
    let mut out = BytesMut::with_capacity(22 + destination.host.len());
    out.put_slice(&[VERSION, command, 0x00]);
    encode_address(destination, &mut out)?;
    Ok(out)
}

pub(crate) fn encode_address(
    destination: &Destination,
    out: &mut BytesMut,
) -> Result<(), SocksError> {
    match destination.ip() {
        Some(IpAddr::V4(address)) => {
            out.put_u8(ATYP_IPV4);
            out.put_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            out.put_u8(ATYP_IPV6);
            out.put_slice(&address.octets());
        }
        // Hostnames stay hostnames: the proxy resolves them, so no query ever
        // reaches the local resolver (remote DNS).
        None => {
            let domain = destination.host.as_bytes();
            if domain.is_empty() || domain.len() > u8::MAX as usize {
                return Err(SocksError::Malformed(
                    "SOCKS5 domain name must contain 1..=255 bytes",
                ));
            }
            out.put_u8(ATYP_DOMAIN);
            out.put_u8(domain.len() as u8);
            out.put_slice(domain);
        }
    }
    out.put_u16(destination.port);
    Ok(())
}

pub(crate) async fn read_method_selection<R>(reader: &mut R, offered: u8) -> Result<(), SocksError>
where
    R: AsyncRead + Unpin,
{
    let mut selection = [0_u8; 2];
    reader.read_exact(&mut selection).await?;
    if selection[0] != VERSION {
        return Err(SocksError::UnexpectedVersion(selection[0]));
    }
    match selection[1] {
        METHOD_NONE_ACCEPTABLE => Err(SocksError::NoAcceptableAuthMethod),
        method if method == offered => Ok(()),
        method => Err(SocksError::UnexpectedAuthMethod(method)),
    }
}

pub(crate) async fn read_auth_status<R>(reader: &mut R) -> Result<(), SocksError>
where
    R: AsyncRead + Unpin,
{
    let mut status = [0_u8; 2];
    reader.read_exact(&mut status).await?;
    if status[0] != AUTH_VERSION {
        return Err(SocksError::UnexpectedAuthVersion(status[0]));
    }
    if status[1] != 0x00 {
        return Err(SocksError::AuthenticationFailed(status[1]));
    }
    Ok(())
}

/// Read one reply, returning the `BND.ADDR`/`BND.PORT` pair.
pub(crate) async fn read_reply<R>(reader: &mut R) -> Result<Destination, SocksError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 3];
    reader.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(SocksError::UnexpectedVersion(header[0]));
    }
    let reply = SocksReply::from_code(header[1]);
    if reply != SocksReply::Succeeded {
        return Err(SocksError::Refused(reply));
    }
    read_address(reader).await
}

pub(crate) async fn read_address<R>(reader: &mut R) -> Result<Destination, SocksError>
where
    R: AsyncRead + Unpin,
{
    let host = match reader.read_u8().await? {
        ATYP_IPV4 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            // The length byte caps the allocation at 255 bytes by construction.
            let length = reader.read_u8().await? as usize;
            if length == 0 {
                return Err(SocksError::Malformed("empty SOCKS5 domain name"));
            }
            let mut domain = vec![0_u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|_| SocksError::Malformed("non-UTF-8 SOCKS5 domain name"))?
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

pub(crate) fn encode_udp_datagram(
    destination: &Destination,
    payload: &[u8],
    out: &mut BytesMut,
) -> Result<(), SocksError> {
    out.put_slice(&[0x00, 0x00, 0x00]);
    encode_address(destination, out)?;
    if out.len() + payload.len() > MAX_UDP_DATAGRAM {
        return Err(SocksError::Malformed(
            "SOCKS5 UDP request exceeds one datagram",
        ));
    }
    out.put_slice(payload);
    Ok(())
}

/// Split a received SOCKS5 UDP reply into its destination header and payload.
///
/// The whole datagram is already in memory and bounded by the receive buffer,
/// so every field is validated against `frame.len()` before it is sliced.
pub(crate) fn decode_udp_datagram(frame: &[u8]) -> Result<(Destination, &[u8]), SocksError> {
    if frame.len() < 4 {
        return Err(SocksError::Malformed("truncated SOCKS5 UDP header"));
    }
    // RFC 1928 §7 fixes `RSV` at X'0000'. It was read past without being looked
    // at, so two bytes of every reply were whatever the sender chose — and a
    // datagram that is not a SOCKS5 UDP request was accepted as one, with its
    // third and fourth bytes read as FRAG and ATYP.
    if frame[0] != 0x00 || frame[1] != 0x00 {
        return Err(SocksError::Malformed(
            "SOCKS5 UDP header RSV field must be zero",
        ));
    }
    if frame[2] != 0x00 {
        // Reassembly is not implemented, so a fragment must never be treated as
        // a complete datagram.
        return Err(SocksError::Malformed(
            "SOCKS5 UDP fragmentation is not supported",
        ));
    }
    let (address_length, host) = match frame[3] {
        ATYP_IPV4 => {
            let octets: [u8; 4] = frame
                .get(4..8)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(SocksError::Malformed("truncated SOCKS5 UDP IPv4 address"))?;
            (4, IpAddr::from(octets).to_string())
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = frame
                .get(4..20)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(SocksError::Malformed("truncated SOCKS5 UDP IPv6 address"))?;
            (16, IpAddr::from(octets).to_string())
        }
        ATYP_DOMAIN => {
            let length = *frame
                .get(4)
                .ok_or(SocksError::Malformed("truncated SOCKS5 UDP domain length"))?
                as usize;
            if length == 0 {
                return Err(SocksError::Malformed("empty SOCKS5 UDP domain name"));
            }
            let domain = frame
                .get(5..5 + length)
                .ok_or(SocksError::Malformed("truncated SOCKS5 UDP domain name"))?;
            (
                1 + length,
                std::str::from_utf8(domain)
                    .map_err(|_| SocksError::Malformed("non-UTF-8 SOCKS5 UDP domain name"))?
                    .to_owned(),
            )
        }
        other => return Err(SocksError::UnsupportedAddressType(other)),
    };
    let port_offset = 4 + address_length;
    let port_bytes: [u8; 2] = frame
        .get(port_offset..port_offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(SocksError::Malformed("truncated SOCKS5 UDP port"))?;
    Ok((
        Destination::new(host, u16::from_be_bytes(port_bytes)),
        &frame[port_offset + 2..],
    ))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use foxcore_api::Destination;

    use super::super::error::{SocksError, SocksReply};
    use crate::codec::*;

    #[test]
    fn greeting_offers_exactly_the_configured_methods() {
        assert_eq!(encode_greeting(false).as_ref(), &[0x05, 0x01, 0x00]);
        // Credentials must never be offered alongside no-auth: a server that
        // picked 0x00 would silently drop the configured authentication.
        assert_eq!(encode_greeting(true).as_ref(), &[0x05, 0x01, 0x02]);
    }

    #[test]
    fn auth_request_matches_rfc1929() {
        let encoded = encode_auth("fox", "hole").unwrap();
        assert_eq!(encoded.as_ref(), b"\x01\x03fox\x04hole");
    }

    #[test]
    fn auth_credentials_are_bounded_to_one_byte_lengths() {
        assert!(encode_auth("", "hole").is_err());
        assert!(encode_auth("fox", "").is_err());
        assert!(encode_auth(&"a".repeat(256), "hole").is_err());
        assert!(encode_auth("fox", &"b".repeat(256)).is_err());
    }

    #[test]
    fn connect_request_encodes_all_three_address_types() {
        let ipv4 = encode_request(CMD_CONNECT, &Destination::new("1.2.3.4", 443)).unwrap();
        assert_eq!(
            ipv4.as_ref(),
            &[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb]
        );

        let ipv6 = encode_request(CMD_CONNECT, &Destination::new("2001:db8::1", 53)).unwrap();
        assert_eq!(
            ipv6.as_ref(),
            &[
                0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                0x00, 0x35
            ]
        );

        // A hostname must stay a hostname on the wire: resolving it locally
        // would leak the destination to the local resolver.
        let domain =
            encode_request(CMD_UDP_ASSOCIATE, &Destination::new("example.com", 8080)).unwrap();
        assert_eq!(domain.as_ref(), b"\x05\x03\x00\x03\x0bexample.com\x1f\x90");
    }

    #[test]
    fn domain_names_are_bounded_before_encoding() {
        let long = Destination::new("a".repeat(256), 80);
        assert!(matches!(
            encode_request(CMD_CONNECT, &long),
            Err(SocksError::Malformed(_))
        ));
        assert!(encode_request(CMD_CONNECT, &Destination::new("", 80)).is_err());
    }

    #[tokio::test]
    async fn method_selection_accepts_only_the_offered_method() {
        assert!(
            read_method_selection(&mut &[0x05, 0x00][..], 0x00)
                .await
                .is_ok()
        );
        assert!(matches!(
            read_method_selection(&mut &[0x04, 0x00][..], 0x00).await,
            Err(SocksError::UnexpectedVersion(4))
        ));
        assert!(matches!(
            read_method_selection(&mut &[0x05, 0xff][..], 0x02).await,
            Err(SocksError::NoAcceptableAuthMethod)
        ));
        assert!(matches!(
            read_method_selection(&mut &[0x05, 0x00][..], 0x02).await,
            Err(SocksError::UnexpectedAuthMethod(0x00))
        ));
        assert!(matches!(
            read_method_selection(&mut &[0x05][..], 0x00).await,
            Err(SocksError::Io(_))
        ));
    }

    #[tokio::test]
    async fn auth_status_is_typed() {
        assert!(read_auth_status(&mut &[0x01, 0x00][..]).await.is_ok());
        assert!(matches!(
            read_auth_status(&mut &[0x01, 0x01][..]).await,
            Err(SocksError::AuthenticationFailed(0x01))
        ));
        assert!(matches!(
            read_auth_status(&mut &[0x05, 0x00][..]).await,
            Err(SocksError::UnexpectedAuthVersion(5))
        ));
    }

    #[tokio::test]
    async fn reply_returns_the_bound_address_for_every_address_type() {
        let ipv4 = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x27, 0x0f];
        assert_eq!(
            read_reply(&mut &ipv4[..]).await.unwrap(),
            Destination::new("127.0.0.1", 9999)
        );

        let mut ipv6 = vec![0x05, 0x00, 0x00, 0x04];
        ipv6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        ipv6.extend_from_slice(&[0x01, 0xbb]);
        assert_eq!(
            read_reply(&mut &ipv6[..]).await.unwrap(),
            Destination::new("2001:db8::7", 443)
        );

        let domain = b"\x05\x00\x00\x03\x0brelay.local\x04\x38";
        assert_eq!(
            read_reply(&mut &domain[..]).await.unwrap(),
            Destination::new("relay.local", 1080)
        );
    }

    #[tokio::test]
    async fn reply_failures_are_typed_and_carry_the_wire_code() {
        let refused = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        match read_reply(&mut &refused[..]).await {
            Err(SocksError::Refused(reply)) => {
                assert_eq!(reply, SocksReply::ConnectionRefused);
                assert_eq!(reply.code(), 0x05);
            }
            other => panic!("expected a typed refusal, got {other:?}"),
        }

        let unassigned = [0x05, 0x7a, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        match read_reply(&mut &unassigned[..]).await {
            Err(SocksError::Refused(reply)) => assert_eq!(reply.code(), 0x7a),
            other => panic!("expected a typed refusal, got {other:?}"),
        }

        assert!(matches!(
            read_reply(&mut &[0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0][..]).await,
            Err(SocksError::UnexpectedVersion(4))
        ));
        assert!(matches!(
            read_reply(&mut &[0x05, 0x00, 0x00, 0x09][..]).await,
            Err(SocksError::UnsupportedAddressType(0x09))
        ));
        // Truncated: only four of the ten IPv4 reply bytes arrived.
        assert!(matches!(
            read_reply(&mut &[0x05, 0x00, 0x00, 0x01, 127][..]).await,
            Err(SocksError::Io(_))
        ));
        // A zero-length domain would make the bound address unusable.
        assert!(matches!(
            read_reply(&mut &[0x05, 0x00, 0x00, 0x03, 0x00, 0, 0][..]).await,
            Err(SocksError::Malformed(_))
        ));
    }

    #[test]
    fn udp_header_is_prepended_to_the_payload() {
        let mut frame = BytesMut::new();
        encode_udp_datagram(&Destination::new("example.com", 53), b"query", &mut frame).unwrap();
        assert_eq!(
            frame.as_ref(),
            b"\x00\x00\x00\x03\x0bexample.com\x00\x35query"
        );
    }

    #[test]
    fn udp_datagrams_are_decoded_and_fragments_refused() {
        let decoded =
            decode_udp_datagram(b"\x00\x00\x00\x01\x08\x08\x08\x08\x00\x35answer").unwrap();
        assert_eq!(decoded.0, Destination::new("8.8.8.8", 53));
        assert_eq!(decoded.1, b"answer");

        // FRAG != 0 is reassembly we deliberately do not implement.
        assert!(matches!(
            decode_udp_datagram(b"\x00\x00\x01\x01\x08\x08\x08\x08\x00\x35x"),
            Err(SocksError::Malformed(_))
        ));

        // RFC 1928 §7 fixes RSV at X'0000'. Read past unchecked, a datagram
        // that is not a SOCKS5 UDP request parses as one, with whatever sits at
        // offsets 2 and 3 taken for FRAG and ATYP.
        for header in [
            b"\x01\x00\x00\x01\x08\x08\x08\x08\x00\x35answer",
            b"\x00\x01\x00\x01\x08\x08\x08\x08\x00\x35answer",
        ] {
            assert!(
                matches!(decode_udp_datagram(header), Err(SocksError::Malformed(_))),
                "a non-zero RSV must be refused: {header:?}"
            );
        }
        assert!(decode_udp_datagram(b"\x00\x00\x00\x01\x08\x08").is_err());
        assert!(matches!(
            decode_udp_datagram(b"\x00\x00\x00\x09\x00\x00"),
            Err(SocksError::UnsupportedAddressType(0x09))
        ));
    }
}
