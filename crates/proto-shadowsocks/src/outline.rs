//! Outline connection prefix: a literal in place of the leading salt bytes.
//!
//! A Shadowsocks TCP connection opens with a random salt in the clear, and the
//! session subkey is `HKDF(key, salt)`. Outline replaces the **first** bytes of
//! that salt with a fixed literal, so the connection opens with something that
//! reads as `POST ` or as a TLS record header while the protocol is unchanged:
//! the server derives its subkey from whatever salt it receives.
//!
//! Source: `Jigsaw-Code/outline-sdk`, `transport/shadowsocks/salt.go`
//! (`prefixSaltGenerator::GetSalt` copies the prefix over the salt and fills the
//! remainder from the CSPRNG, erroring when the prefix does not fit) and
//! `x/configurl/shadowsocks.go` (the `prefix=` URL option). The SDK's own
//! warning is the reason the length is bounded twice here: prefix bytes are
//! entropy taken out of the salt, and a repeated salt is a repeated subkey.
//!
//! It follows that the prefix cannot be applied by rewriting bytes on the wire
//! — the client has to *choose* the salt it derives from. `shadowsocks-rust`
//! generates the salt inside `CryptoStream::from_stream`, with no way to supply
//! one, so this module drives the crate's public `EncryptedWriter` and
//! `DecryptedReader` directly. That is also why it is AEAD-only: an AEAD-2022
//! stream additionally carries a request-salt echo and a response header, and
//! Outline neither specifies nor ships a prefix for it.

use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};

use bytes::{BufMut, BytesMut};
use rand::RngCore;
use shadowsocks::context::SharedContext;
use shadowsocks::crypto::{CipherCategory, CipherKind};
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::crypto_io::{DecryptedReader, EncryptedWriter, StreamType};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Half the salt is the smallest random tail this core will send.
///
/// Outline documents 16 bytes as the maximum prefix, which is exactly half of
/// the 32-byte salt of the ciphers it issues. Expressing the rule as a fraction
/// keeps it meaningful for a 16-byte salt too, where "16 bytes" would mean a
/// constant salt — one subkey for every connection to that server.
fn max_prefix_len(method: CipherKind) -> usize {
    method.salt_len() / 2
}

/// Reject a prefix the cipher cannot carry. Returns the salt to open with.
pub fn prefixed_salt(method: CipherKind, prefix: &[u8]) -> io::Result<Vec<u8>> {
    if method.category() != CipherCategory::Aead {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the Outline prefix is defined for AEAD Shadowsocks only; \
             2022 and stream ciphers do not carry it",
        ));
    }
    let limit = max_prefix_len(method);
    if prefix.is_empty() || prefix.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "an Outline prefix for {method} must be 1..={limit} bytes, \
                 so that at least half of the salt stays random"
            ),
        ));
    }
    let mut salt = vec![0_u8; method.salt_len()];
    salt[..prefix.len()].copy_from_slice(prefix);
    rand::rng().fill_bytes(&mut salt[prefix.len()..]);
    Ok(salt)
}

enum WriteState {
    /// The target address has not been sent yet. It travels with the first
    /// payload write so the opening packet has no distinctive size.
    Connect(Address),
    Connecting(BytesMut),
    Connected,
}

/// A Shadowsocks AEAD client stream that opens with a chosen salt.
///
/// Equivalent to `ProxyClientStream` over `CryptoStream` for the AEAD ciphers,
/// minus everything AEAD-2022 adds, and with the salt supplied instead of drawn.
pub struct PrefixedProxyStream<S> {
    stream: S,
    reader: DecryptedReader,
    writer: EncryptedWriter,
    context: SharedContext,
    state: WriteState,
}

impl<S> PrefixedProxyStream<S> {
    pub fn new(
        context: SharedContext,
        stream: S,
        method: CipherKind,
        key: &[u8],
        salt: &[u8],
        address: Address,
    ) -> Self {
        Self {
            stream,
            reader: DecryptedReader::new(StreamType::Client, method, key),
            // The writer sends this salt ahead of the first chunk and derives
            // the session subkey from the same bytes, which is what makes the
            // prefix a disguise rather than a corruption.
            writer: EncryptedWriter::new(StreamType::Client, method, key, salt),
            context,
            state: WriteState::Connect(address),
        }
    }
}

impl<S> AsyncRead for PrefixedProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reader
            .poll_read_decrypted(context, &this.context, &mut this.stream, buffer)
            .map_err(Into::into)
    }
}

impl<S> AsyncWrite for PrefixedProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match this.state {
                WriteState::Connect(ref address) => {
                    let mut first =
                        BytesMut::with_capacity(address.serialized_len() + buffer.len());
                    address.write_to_buf(&mut first);
                    first.put_slice(buffer);
                    this.state = WriteState::Connecting(first);
                }
                WriteState::Connecting(ref first) => {
                    let written = ready!(this.writer.poll_write_encrypted(
                        context,
                        &mut this.stream,
                        first
                    ))?;
                    debug_assert_eq!(written, first.len());
                    this.state = WriteState::Connected;
                    // The caller's bytes all went into the first chunk, even
                    // when there were none: an empty write still has to put
                    // salt and address on the wire.
                    return Poll::Ready(Ok(buffer.len()));
                }
                WriteState::Connected => {
                    return this
                        .writer
                        .poll_write_encrypted(context, &mut this.stream, buffer)
                        .map_err(Into::into);
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
    use shadowsocks::context::Context;
    use shadowsocks::relay::tcprelay::crypto_io::CryptoStream;
    use shadowsocks::relay::tcprelay::crypto_io::{CryptoRead, CryptoWrite};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn server(method: CipherKind) -> ServerConfig {
        ServerConfig::new(
            ServerAddr::SocketAddr(SocketAddr::from(([127, 0, 0, 1], 8388))),
            "correct horse battery staple",
            method,
        )
        .unwrap()
    }

    #[test]
    fn the_prefix_replaces_the_head_of_the_salt_and_nothing_else() {
        let method = CipherKind::CHACHA20_POLY1305;
        let prefix = b"\x16\x03\x01\x00\xa8";
        let first = prefixed_salt(method, prefix).unwrap();
        let second = prefixed_salt(method, prefix).unwrap();
        assert_eq!(first.len(), method.salt_len());
        assert_eq!(&first[..prefix.len()], prefix);
        assert_eq!(&second[..prefix.len()], prefix);
        // The tail is where the entropy that survives lives.
        assert_ne!(first[prefix.len()..], second[prefix.len()..]);
    }

    #[test]
    fn a_prefix_that_would_eat_more_than_half_the_salt_is_refused() {
        let method = CipherKind::CHACHA20_POLY1305;
        assert!(prefixed_salt(method, &[0_u8; 16]).is_ok());
        let error = prefixed_salt(method, &[0_u8; 17]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        // A 16-byte salt halves to 8, so Outline's documented maximum would be
        // a constant salt here and is refused rather than quietly accepted.
        let error = prefixed_salt(CipherKind::AES_128_GCM, &[0_u8; 9]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(prefixed_salt(CipherKind::AES_128_GCM, &[0_u8; 8]).is_ok());
    }

    #[test]
    fn an_empty_prefix_is_refused_rather_than_treated_as_absent() {
        let error = prefixed_salt(CipherKind::CHACHA20_POLY1305, b"").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn non_aead_methods_are_refused() {
        for method in [
            CipherKind::from_str("2022-blake3-aes-128-gcm").unwrap(),
            CipherKind::from_str("2022-blake3-chacha20-poly1305").unwrap(),
            CipherKind::NONE,
        ] {
            let error = prefixed_salt(method, b"POST ").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{method}");
        }
    }

    /// The wire test, in two halves: the connection must *open* with the
    /// prefix, and an unmodified reference decryptor must still read it. If the
    /// prefix were applied anywhere other than the salt the client derives
    /// from, exactly one of the two would fail.
    #[tokio::test]
    async fn a_prefixed_stream_opens_with_the_prefix_and_still_decrypts() {
        for method in [
            CipherKind::CHACHA20_POLY1305,
            CipherKind::AES_128_GCM,
            CipherKind::AES_256_GCM,
        ] {
            let config = server(method);
            let context = Context::new_shared(ServerType::Local);
            let prefix = b"\x16\x03\x01\x00\xa8";
            let salt = prefixed_salt(method, prefix).unwrap();
            let address = Address::DomainNameAddress("example.com".to_owned(), 443);

            let (client_side, mut tap) = tokio::io::duplex(64 * 1024);
            let mut client = PrefixedProxyStream::new(
                context.clone(),
                client_side,
                method,
                config.key(),
                &salt,
                address.clone(),
            );
            client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
            client.flush().await.unwrap();
            drop(client);

            let mut wire = Vec::new();
            tap.read_to_end(&mut wire).await.unwrap();
            assert_eq!(&wire[..prefix.len()], prefix, "{method}");
            assert_eq!(&wire[..method.salt_len()], &salt[..], "{method}");

            let (mut feed, server_side) = tokio::io::duplex(64 * 1024);
            feed.write_all(&wire).await.unwrap();
            feed.shutdown().await.unwrap();
            let mut server = CryptoStream::from_stream(
                &context,
                server_side,
                StreamType::Server,
                method,
                config.key(),
            );
            let mut decrypted = vec![0_u8; 64];
            let mut read = ReadBuf::new(&mut decrypted);
            std::future::poll_fn(|cx| {
                Pin::new(&mut server).poll_read_decrypted(cx, &context, &mut read)
            })
            .await
            .unwrap();

            // Address first, then the payload, exactly as plain Shadowsocks.
            let mut expected = BytesMut::new();
            address.write_to_buf(&mut expected);
            expected.put_slice(b"GET / HTTP/1.1\r\n");
            assert_eq!(read.filled(), &expected[..], "{method}");
        }
    }

    #[tokio::test]
    async fn the_server_direction_still_decrypts() {
        let method = CipherKind::CHACHA20_POLY1305;
        let config = server(method);
        let context = Context::new_shared(ServerType::Local);
        let salt = prefixed_salt(method, b"POST ").unwrap();
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);

        let mut client = PrefixedProxyStream::new(
            context.clone(),
            client_side,
            method,
            config.key(),
            &salt,
            Address::DomainNameAddress("example.com".to_owned(), 443),
        );
        client.write_all(b"ping").await.unwrap();

        let mut server = CryptoStream::from_stream(
            &context,
            server_side,
            StreamType::Server,
            method,
            config.key(),
        );
        let mut sink = vec![0_u8; 64];
        let mut read = ReadBuf::new(&mut sink);
        std::future::poll_fn(|cx| {
            Pin::new(&mut server).poll_read_decrypted(cx, &context, &mut read)
        })
        .await
        .unwrap();

        std::future::poll_fn(|cx| Pin::new(&mut server).poll_write_encrypted(cx, b"pong"))
            .await
            .unwrap();
        std::future::poll_fn(|cx| Pin::new(&mut server).poll_flush(cx))
            .await
            .unwrap();

        let mut answer = [0_u8; 4];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"pong");
    }
}
