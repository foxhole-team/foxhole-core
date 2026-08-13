//! The wire codec, opened to the fuzz harness in `fuzz/`.
//!
//! `codec` is `pub(crate)` because nothing above this crate has any business
//! framing SOCKS5 by hand, and that stays true — this module is compiled only
//! under the `fuzzing` feature, which nothing in the workspace enables. Without
//! it a fuzz target could reach the decoders only by completing a real TCP dial
//! to a real proxy, which is not something a fuzzer can drive, so the parsers
//! that actually read the network would go untested.
//!
//! These are pass-through wrappers, not a second implementation: anything that
//! diverges here would fuzz the wrapper instead of the codec.

use tokio::io::AsyncRead;

use crate::codec;
use crate::error::SocksError;

/// Split a received SOCKS5 UDP reply into its destination header and payload.
pub fn decode_udp_datagram(frame: &[u8]) -> Result<(foxcore_api::Destination, &[u8]), SocksError> {
    codec::decode_udp_datagram(frame)
}

/// Read one `CONNECT`/`UDP ASSOCIATE` reply, including the bound address.
pub async fn read_reply<R>(reader: &mut R) -> Result<foxcore_api::Destination, SocksError>
where
    R: AsyncRead + Unpin,
{
    codec::read_reply(reader).await
}

/// Read a bare `ATYP`-prefixed address, the variable-length part of a reply.
pub async fn read_address<R>(reader: &mut R) -> Result<foxcore_api::Destination, SocksError>
where
    R: AsyncRead + Unpin,
{
    codec::read_address(reader).await
}

/// Read the server's method-selection message.
pub async fn read_method_selection<R>(reader: &mut R, offered: u8) -> Result<(), SocksError>
where
    R: AsyncRead + Unpin,
{
    codec::read_method_selection(reader, offered).await
}

/// Read the RFC 1929 authentication status.
pub async fn read_auth_status<R>(reader: &mut R) -> Result<(), SocksError>
where
    R: AsyncRead + Unpin,
{
    codec::read_auth_status(reader).await
}

/// The protocol's own cap on a `ATYP=DOMAINNAME` host, asserted by the harness.
pub const MAX_DOMAIN_LEN: usize = u8::MAX as usize;

/// Largest SOCKS5 UDP request that can ride in one IPv4 datagram payload.
pub const MAX_UDP_DATAGRAM: usize = codec::MAX_UDP_DATAGRAM;
