#![forbid(unsafe_code)]

pub mod backoff;
mod datagram;
mod grpc;
mod h2io;
mod http2;
mod httpupgrade;
#[cfg(feature = "fingerprinting")]
pub mod ja;
pub mod quic;
#[cfg(feature = "fingerprinting")]
pub mod quic_initial;
mod serverfirst;
pub mod splice;
mod tls;
mod websocket;

use foxcore_api::{StreamTransportConfig, TlsConfig};
use tokio::io::{AsyncRead, AsyncWrite};

pub use datagram::{
    BoxDatagramSession, Datagram, DatagramChannelIo, DatagramSession, datagram_channel,
    with_authenticated_peer,
};
pub use serverfirst::ServerFirstStream;
pub use splice::{InnerCodec, PassthroughCodec, RecordLayer, relay, spawn_relay};
pub use tls::{rustls_client_config, wrap_tls, wrap_tls_spliced};
pub use websocket::wrap_stream_transport;

pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

pub type BoxStream = Box<dyn AsyncStream>;

/// Ensure crates that rely on rustls' process default can build safely.
///
/// Both rustls providers are compiled in, so rustls cannot infer a process
/// default. FoxCore's own TLS builders always pass an explicit provider, but
/// embedded clients such as Arti legitimately use the process default.
///
/// Installing is race-safe and respects a provider an embedding process already
/// selected. Once any provider is installed the ambiguity is gone; otherwise
/// FoxCore installs `aws_lc_rs` — the same provider [`tls::rustls_client_config`]
/// builds with. The two used to disagree, which meant an embedded client got a
/// different key-exchange group set than the core's own dials, for no reason
/// anyone had decided on.
pub fn ensure_process_crypto_provider() -> std::io::Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "rustls process CryptoProvider could not be installed",
        ))
    }
}

/// Compose the TLS layer (with ALPN forced to `h2` for gRPC/HTTP2 transports)
/// and the stream transport into one client byte stream. REALITY owns its
/// ClientHello and reuses only [`wrap_stream_transport`].
pub async fn establish_stream<S>(
    tcp: S,
    tls: &TlsConfig,
    transport: &StreamTransportConfig,
    server: &str,
    port: u16,
) -> std::io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let stream: BoxStream = if tls.enabled {
        let alpn: Option<&[&str]> = if transport_needs_h2(transport) {
            Some(&["h2"])
        } else {
            None
        };
        tls::wrap_tls_with_alpn(tcp, tls, server, alpn).await?
    } else {
        Box::new(tcp)
    };
    wrap_stream_transport(stream, transport, server, port, tls.enabled).await
}

fn transport_needs_h2(transport: &StreamTransportConfig) -> bool {
    matches!(
        transport,
        StreamTransportConfig::Grpc { .. } | StreamTransportConfig::Http2 { .. }
    )
}

#[cfg(test)]
mod provider_tests {
    #[test]
    fn a_process_with_both_rustls_providers_gets_one_explicit_default() {
        super::ensure_process_crypto_provider().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
