//! NaiveProxy client: HTTP/2 CONNECT over TLS with the Naive padding protocol.
//!
//! Padding is the whole reason this crate exists rather than reusing the plain
//! HTTP CONNECT outbound: without it the profile is an ordinary HTTP/2 forward
//! proxy with none of the length-distribution resistance the user asked for.
//! [`NaiveConfig::padding`] therefore defaults to *required*, and a server that
//! does not negotiate it is refused instead of silently accepted.
//!
//! Padding specification and reference implementation are cited in
//! [`mod@padding`].
//!
//! # Not implemented here
//! * The reference client also pads H2 `RST_STREAM` frames and pseudo-randomises
//!   the response HEADERS length. Both live inside Chromium's own SPDY session
//!   layer; the `h2` crate exposes no hook for either, so this client matches
//!   the payload padding and the request-side header padding only.
//! * TLS is `rustls` via `foxcore-transport`, so the ClientHello is a rustls
//!   fingerprint, not a Chromium one.

#![forbid(unsafe_code)]

mod error;
mod h2stream;
mod padding;
mod session;
mod stream;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::BytesMut;
use foxcore_api::Destination;
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{BoxDatagramSession, BoxStream, wrap_tls};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncWrite};

pub use error::NaiveError;
use h2stream::H2Stream;
use padding::{MAX_PADDING_SIZE, fill_nonindex_header_value};
use session::{Established, H2Pool, establish};
use stream::{PaddedStream, PaddingSizes};

/// `kPaddingHeader`.
const PADDING_HEADER: &str = "padding";
/// `kPaddingTypeRequestHeader` — supported types, most preferred first.
const PADDING_TYPE_REQUEST_HEADER: &str = "padding-type-request";
/// `kPaddingTypeReplyHeader` — the single type the server settled on.
const PADDING_TYPE_REPLY_HEADER: &str = "padding-type-reply";
/// What this client supports, in the reference client's own order.
const PADDING_TYPE_REQUEST: &str = "1, 0";
/// The reference client draws the request padding length from [16, 32].
const PADDING_HEADER_LENGTH: std::ops::RangeInclusive<usize> = 16..=32;

pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 15_000;

/// Negotiated padding scheme (`net::PaddingType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingType {
    /// Wire format "0".
    None,
    /// Wire format "1": the framing described in [`mod@padding`].
    Variant1,
}

/// The typed profile lives in `foxcore-api`; see the note in `proto-socks`.
pub use foxcore_api::NaiveConfig;

/// How many times a CONNECT may be re-tried on a fresh connection.
///
/// A pooled stream can lose a race with GOAWAY: the connection was live when
/// the slot was reserved and gone by the time the headers went out. That is one
/// retry's worth of bad luck, not a loop — a server that refuses every stream
/// must surface as an error rather than as an unbounded reconnect.
const MAX_CONNECT_ATTEMPTS: usize = 3;

#[derive(Debug, Clone)]
pub struct NaiveOutbound {
    config: Arc<NaiveConfig>,
    dialer: ProtectedDialer,
    /// Shared by every clone of this outbound, which is what makes the
    /// multiplexing real: the engine hands out clones per flow.
    sessions: Arc<H2Pool>,
}

impl NaiveOutbound {
    pub async fn new(mut config: NaiveConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        if !config.tls.enabled {
            return Err(NaiveError::TlsRequired.into());
        }
        if !config.tls.alpn.is_empty() && config.tls.alpn != ["h2"] {
            // Accepting a different ALPN would negotiate HTTP/1.1 and produce a
            // tunnel that is not NaiveProxy at all.
            return Err(NaiveError::AlpnMismatch.into());
        }
        config.tls.alpn = vec!["h2".to_owned()];

        if config.username.is_some() != config.password.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NaiveProxy requires both username and password, or neither",
            ));
        }
        if config
            .password
            .as_ref()
            .is_some_and(foxcore_api::SecretString::is_empty)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NaiveProxy password must not be empty",
            ));
        }
        if config.handshake_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NaiveProxy handshake_timeout_ms must be greater than zero",
            ));
        }

        dialer
            .resolve_server_addresses(&config.server, config.port, config.server_ip)
            .await?;
        Ok(Self {
            config: Arc::new(config),
            dialer,
            sessions: Arc::new(H2Pool::default()),
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let timeout = Duration::from_millis(self.config.handshake_timeout_ms);
        // The budget covers everything the flow waits on — reusing a connection,
        // opening one, and the CONNECT itself — because from the caller's side
        // they are one operation and only the total is observable.
        tokio::time::timeout(timeout, self.open_multiplexed(destination))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "NaiveProxy CONNECT handshake timed out",
                )
            })?
            .map_err(io::Error::from)
    }

    /// Open one CONNECT stream, on a shared connection where possible.
    async fn open_multiplexed(&self, destination: &Destination) -> Result<BoxStream, NaiveError> {
        multiplexed_connect(
            &self.sessions,
            || self.dial(),
            destination,
            self.credentials(),
            self.config.padding,
        )
        .await
    }

    /// Open a fresh HTTP/2 connection to the proxy and start driving it.
    async fn dial(&self) -> Result<Established, NaiveError> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let tls = wrap_tls(tcp, &self.config.tls, &self.config.server).await?;
        let (sender, connection) = h2::client::handshake(tls).await?;
        Ok(establish(sender, connection))
    }

    /// NaiveProxy tunnels TCP through CONNECT and has no datagram carrier, so
    /// a UDP flow is refused instead of being folded onto the stream.
    pub async fn connect_datagram(
        &self,
        _destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NaiveProxy is an HTTP/2 CONNECT tunnel and cannot carry UDP",
        ))
    }

    fn credentials(&self) -> Option<(&str, &str)> {
        match (&self.config.username, &self.config.password) {
            (Some(username), Some(password)) => Some((username.as_str(), password.expose())),
            _ => None,
        }
    }
}

/// Open a CONNECT stream on a pooled connection, reconnecting once the pool
/// hands out one that turns out to be going away.
///
/// Separate from [`NaiveOutbound`] and generic over the dial so the retry can be
/// driven over a pipe: the interesting case is a GOAWAY that arrives between the
/// stream slot being reserved and the headers going out, and reproducing that
/// through TLS and a socket would prove nothing extra.
async fn multiplexed_connect<F, Fut>(
    pool: &H2Pool,
    connect: F,
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    require_padding: bool,
) -> Result<BoxStream, NaiveError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Established, NaiveError>>,
{
    let mut last = None;
    for _ in 0..MAX_CONNECT_ATTEMPTS {
        let lease = pool.acquire(&connect).await?;
        let opened = open_stream(
            lease.sender(),
            destination,
            credentials,
            require_padding,
            None,
        )
        .await;
        match opened {
            Ok(tunnel) => return Ok(lease.attach(tunnel)),
            // An HTTP/2-level failure is about the connection, not this request:
            // a GOAWAY that arrived between the slot being reserved and the
            // headers going out reads exactly like this. The connection leaves
            // the pool and the flow tries a fresh one. A 407, or a server that
            // will not negotiate padding, is the server's answer and is returned
            // as it stands.
            Err(error) if error.is_connection_lost() => {
                lease.retire();
                last = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or(NaiveError::Invalid(
        "no NaiveProxy connection could carry the CONNECT",
    )))
}

/// Open one CONNECT tunnel over its own new HTTP/2 connection.
///
/// Production goes through [`NaiveOutbound::open_multiplexed`], which shares a
/// connection between flows; this is the one-connection-one-stream composition,
/// kept because it is the smallest thing a test can drive over a pipe.
///
/// `padding_sizes` overrides the RNG; production always passes `None`.
#[cfg(test)]
async fn open_tunnel<S>(
    stream: S,
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    require_padding: bool,
    padding_sizes: Option<PaddingSizes>,
) -> Result<BoxStream, NaiveError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (client, connection) = h2::client::handshake(stream).await?;
    let established = establish(client, connection);
    open_stream(
        established.sender(),
        destination,
        credentials,
        require_padding,
        padding_sizes,
    )
    .await
}

/// Open one CONNECT stream on an HTTP/2 connection that is already up.
async fn open_stream(
    sender: h2::client::SendRequest<bytes::Bytes>,
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    require_padding: bool,
    padding_sizes: Option<PaddingSizes>,
) -> Result<BoxStream, NaiveError> {
    let mut rng = StdRng::from_os_rng();
    let request = build_request(destination, credentials, &mut rng)?;

    // `ready` is the peer's stream limit expressed as backpressure. The pool
    // already accounts for it, so this normally returns at once; it is still
    // awaited because the accounting is an estimate of the peer's state and the
    // peer's own answer is not.
    let mut client = sender.ready().await?;
    let (response, send) = client.send_request(request, false)?;
    let response = response.await?;

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(NaiveError::Status(status));
    }
    let negotiated = negotiate_padding(response.headers())?;
    if require_padding && negotiated != PaddingType::Variant1 {
        return Err(NaiveError::PaddingRefused);
    }

    let tunnel = H2Stream::new(send, response.into_body());
    if negotiated == PaddingType::Variant1 {
        let sizes = padding_sizes
            .unwrap_or_else(move || Box::new(move || rng.random_range(0..=MAX_PADDING_SIZE)));
        Ok(Box::new(PaddedStream::new(tunnel, sizes)))
    } else {
        Ok(Box::new(tunnel))
    }
}

fn build_request<R>(
    destination: &Destination,
    credentials: Option<(&str, &str)>,
    rng: &mut R,
) -> Result<http::Request<()>, NaiveError>
where
    R: Rng,
{
    let authority = destination.authority();
    let uri: http::Uri = authority
        .parse()
        .map_err(|_| NaiveError::Invalid("the destination is not a valid HTTP/2 authority"))?;
    // Anything but bare authority-form would make h2 emit `:scheme`/`:path`,
    // which is illegal on CONNECT — and an empty host would send the proxy a
    // target it cannot dial.
    let well_formed = uri.scheme().is_none()
        && uri.path_and_query().is_none()
        && uri
            .authority()
            .is_some_and(|authority| !authority.host().is_empty());
    if !well_formed {
        return Err(NaiveError::Invalid(
            "a CONNECT target must be bare authority-form with a host",
        ));
    }

    let padding = http::HeaderValue::from_bytes(&padding_header_value(rng))
        .map_err(|_| NaiveError::Invalid("the padding header value is not a legal header"))?;
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header(PADDING_TYPE_REQUEST_HEADER, PADDING_TYPE_REQUEST)
        .header(PADDING_HEADER, padding);

    if let Some((username, password)) = credentials {
        if username.contains(':') {
            return Err(NaiveError::Invalid(
                "an HTTP basic userid must not contain a colon",
            ));
        }
        let mut plain = BytesMut::with_capacity(username.len() + 1 + password.len());
        plain.extend_from_slice(username.as_bytes());
        plain.extend_from_slice(b":");
        plain.extend_from_slice(password.as_bytes());
        let mut encoded = BytesMut::zeroed(plain.len().div_ceil(3) * 4);
        let written = STANDARD
            .encode_slice(&plain[..], &mut encoded)
            .map_err(|_| NaiveError::Invalid("the proxy credentials could not be encoded"))?;
        plain.fill(0);
        let mut value = BytesMut::with_capacity(6 + written);
        value.extend_from_slice(b"Basic ");
        value.extend_from_slice(&encoded[..written]);
        encoded.fill(0);
        let header = http::HeaderValue::from_bytes(&value)
            .map_err(|_| NaiveError::Invalid("the proxy credentials are not a legal header"))?;
        value.fill(0);
        builder = builder.header(http::header::PROXY_AUTHORIZATION, header);
    }

    builder
        .body(())
        .map_err(|_| NaiveError::Invalid("the CONNECT request could not be built"))
}

/// A `padding` header value: 16..=32 bytes that HPACK will not compress.
///
/// Returned as raw bytes rather than a `String` so the value never has to
/// survive a fallible UTF-8 conversion on the connect path.
fn padding_header_value<R>(rng: &mut R) -> Vec<u8>
where
    R: Rng,
{
    let length = rng.random_range(PADDING_HEADER_LENGTH);
    let mut value = vec![0_u8; length];
    fill_nonindex_header_value(rng.random::<u64>(), &mut value);
    value
}

/// Decide which padding scheme the server agreed to.
///
/// `padding-type-reply` is authoritative. Servers older than the type
/// negotiation only echo `padding`, and its bare presence means Variant1.
fn negotiate_padding(headers: &http::HeaderMap) -> Result<PaddingType, NaiveError> {
    match headers.get(PADDING_TYPE_REPLY_HEADER) {
        // A header the server sent but we cannot even read as ASCII is an
        // unknown type, not an invitation to guess.
        Some(value) => match value.to_str().map(str::trim) {
            Ok("0") => Ok(PaddingType::None),
            Ok("1") => Ok(PaddingType::Variant1),
            Ok(other) => Err(NaiveError::UnknownPaddingType(other.to_owned())),
            Err(_) => Err(NaiveError::UnknownPaddingType(
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )),
        },
        None if headers.contains_key(PADDING_HEADER) => Ok(PaddingType::Variant1),
        None => Ok(PaddingType::None),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use foxcore_api::{SecretString, TlsConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::padding::{FIRST_PADDINGS, PaddingFramer};

    trait ExpectError {
        fn expect_error(self) -> NaiveError;
    }

    impl<T> ExpectError for Result<T, NaiveError> {
        fn expect_error(self) -> NaiveError {
            match self {
                Ok(_) => panic!("expected the call to fail"),
                Err(error) => error,
            }
        }
    }

    fn seeded() -> rand::rngs::SmallRng {
        rand::rngs::SmallRng::seed_from_u64(0x5eed_1234_u64)
    }

    #[test]
    fn a_connect_request_is_authority_form_and_carries_both_padding_headers() {
        let mut rng = seeded();
        let request = build_request(&Destination::new("example.com", 443), None, &mut rng).unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().authority().unwrap(), "example.com:443");
        assert!(request.uri().scheme().is_none());
        assert!(request.uri().path_and_query().is_none());
        assert_eq!(
            request.headers()[PADDING_TYPE_REQUEST_HEADER],
            PADDING_TYPE_REQUEST
        );
        let padding = request.headers()[PADDING_HEADER].as_bytes();
        assert!(PADDING_HEADER_LENGTH.contains(&padding.len()));
        assert!(
            padding
                .iter()
                .all(|byte| b"!\"#$&'()*+,;<>?@X".contains(byte))
        );
    }

    #[test]
    fn ipv6_and_ipv4_destinations_are_valid_connect_authorities() {
        let mut rng = seeded();
        let ipv6 = build_request(&Destination::new("2001:db8::1", 443), None, &mut rng).unwrap();
        assert_eq!(ipv6.uri().authority().unwrap(), "[2001:db8::1]:443");
        let ipv4 = build_request(&Destination::new("1.2.3.4", 8443), None, &mut rng).unwrap();
        assert_eq!(ipv4.uri().authority().unwrap(), "1.2.3.4:8443");
    }

    #[test]
    fn credentials_become_a_basic_proxy_authorization_header() {
        let mut rng = seeded();
        let request = build_request(
            &Destination::new("example.com", 443),
            Some(("fox", "hole")),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            request.headers()[http::header::PROXY_AUTHORIZATION],
            "Basic Zm94OmhvbGU="
        );
    }

    #[test]
    fn a_destination_that_is_not_an_authority_is_refused() {
        let mut rng = seeded();
        assert!(matches!(
            build_request(&Destination::new("http://evil", 443), None, &mut rng),
            Err(NaiveError::Invalid(_))
        ));
        assert!(matches!(
            build_request(&Destination::new("", 443), None, &mut rng),
            Err(NaiveError::Invalid(_))
        ));
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn padding_type_reply_is_authoritative() {
        assert_eq!(
            negotiate_padding(&headers(&[("padding-type-reply", "1")])).unwrap(),
            PaddingType::Variant1
        );
        // Even with a `padding` header present, an explicit "0" means none.
        assert_eq!(
            negotiate_padding(&headers(&[
                ("padding-type-reply", "0"),
                ("padding", "~~~~")
            ]))
            .unwrap(),
            PaddingType::None
        );
        assert!(matches!(
            negotiate_padding(&headers(&[("padding-type-reply", "7")])),
            Err(NaiveError::UnknownPaddingType(_))
        ));
    }

    #[test]
    fn a_bare_padding_header_means_variant1_for_older_servers() {
        assert_eq!(
            negotiate_padding(&headers(&[("padding", "~~~~~~~~")])).unwrap(),
            PaddingType::Variant1
        );
        assert_eq!(
            negotiate_padding(&headers(&[("server", "caddy")])).unwrap(),
            PaddingType::None
        );
    }

    /// In-process HTTP/2 forward proxy.
    ///
    /// `reply_headers` decides what the server claims about padding, so the
    /// same harness covers a real Naive server and a plain H2 proxy.
    fn spawn_proxy(
        server_io: tokio::io::DuplexStream,
        reply_headers: &'static [(&'static str, &'static str)],
        pad_body: bool,
    ) -> tokio::task::JoinHandle<Option<http::HeaderMap>> {
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.ok()?;
            let (request, mut respond) = connection.accept().await?.ok()?;
            assert_eq!(request.method(), http::Method::CONNECT);
            let request_headers = request.headers().clone();

            let mut builder = http::Response::builder().status(200);
            for (name, value) in reply_headers {
                builder = builder.header(*name, *value);
            }
            let response = builder.body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();

            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let mut reader = PaddingFramer::new(Some(FIRST_PADDINGS));
                let mut writer = PaddingFramer::new(Some(FIRST_PADDINGS));
                while let Some(Ok(data)) = body.data().await {
                    let length = data.len();
                    let mut payload = BytesMut::new();
                    if pad_body {
                        reader.read(&data, &mut payload);
                    } else {
                        payload.extend_from_slice(&data);
                    }
                    let _ = body.flow_control().release_capacity(length);
                    if payload.is_empty() {
                        continue;
                    }
                    payload.iter_mut().for_each(u8::make_ascii_uppercase);

                    let wire = if pad_body && writer.written_frames() < FIRST_PADDINGS {
                        let mut wire = BytesMut::new();
                        writer.write(&payload, 31, &mut wire);
                        wire
                    } else {
                        payload
                    };
                    if send.send_data(Bytes::from(wire), false).is_err() {
                        break;
                    }
                }
                let _ = send.send_data(Bytes::new(), true);
            });
            while connection.accept().await.is_some() {}
            let _ = handler.await;
            Some(request_headers)
        })
    }

    #[tokio::test]
    async fn a_naive_server_round_trips_padded_payload() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let proxy = spawn_proxy(
            server_io,
            &[("padding", "~~~~~~~~~~~~~~~~"), ("padding-type-reply", "1")],
            true,
        );

        let mut tunnel = open_tunnel(
            client_io,
            &Destination::new("example.com", 443),
            None,
            true,
            Some(Box::new(|| 11)),
        )
        .await
        .expect("the tunnel must open");

        tunnel.write_all(b"hello").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = [0_u8; 5];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"HELLO");

        drop(tunnel);
        let request_headers = proxy.await.unwrap().expect("the proxy saw the request");
        assert!(request_headers.contains_key(PADDING_HEADER));
        assert_eq!(
            request_headers[PADDING_TYPE_REQUEST_HEADER],
            PADDING_TYPE_REQUEST
        );
    }

    #[tokio::test]
    async fn a_plain_http2_proxy_is_refused_when_padding_is_required() {
        // The silent-downgrade trap: this server tunnels bytes perfectly well,
        // it just is not NaiveProxy.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let proxy = spawn_proxy(server_io, &[("server", "caddy")], false);

        let error = open_tunnel(
            client_io,
            &Destination::new("example.com", 443),
            None,
            true,
            None,
        )
        .await
        .expect_error();
        assert!(matches!(error, NaiveError::PaddingRefused));
        assert_eq!(
            io::Error::from(error).kind(),
            io::ErrorKind::ConnectionRefused
        );
        proxy.abort();
    }

    #[tokio::test]
    async fn an_explicit_padding_type_zero_is_also_refused() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let proxy = spawn_proxy(
            server_io,
            &[("padding", "~~~~~~~~~~~~~~~~"), ("padding-type-reply", "0")],
            false,
        );
        let error = open_tunnel(
            client_io,
            &Destination::new("example.com", 443),
            None,
            true,
            None,
        )
        .await
        .expect_error();
        assert!(matches!(error, NaiveError::PaddingRefused));
        proxy.abort();
    }

    #[tokio::test]
    async fn an_unpadded_profile_may_use_a_plain_http2_proxy() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let proxy = spawn_proxy(server_io, &[("server", "caddy")], false);

        let mut tunnel = open_tunnel(
            client_io,
            &Destination::new("example.com", 443),
            None,
            false,
            None,
        )
        .await
        .expect("padding was explicitly not required");
        tunnel.write_all(b"plain").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = [0_u8; 5];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"PLAIN");
        drop(tunnel);
        proxy.abort();
    }

    #[tokio::test]
    async fn a_non_2xx_response_never_returns_a_tunnel() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let proxy = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(407).body(()).unwrap();
            let _ = respond.send_response(response, true);
            while connection.accept().await.is_some() {}
        });
        let error = open_tunnel(
            client_io,
            &Destination::new("example.com", 443),
            None,
            true,
            None,
        )
        .await
        .expect_error();
        assert_eq!(error.status(), Some(407));
        proxy.abort();
    }

    /// An HTTP/2 proxy that serves every CONNECT stream on the connection,
    /// echoing each stream's payload back in upper case.
    ///
    /// `max_streams` is the server's own `SETTINGS_MAX_CONCURRENT_STREAMS`, and
    /// `goaway_after_first` makes it stop accepting new streams once one is
    /// running — the case a pooled client has to survive.
    fn spawn_multiplexing_proxy(
        server_io: tokio::io::DuplexStream,
        max_streams: u32,
        goaway_after_first: bool,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .max_concurrent_streams(max_streams)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let mut streams = Vec::new();
            while let Some(accepted) = connection.accept().await {
                let Ok((request, mut respond)) = accepted else {
                    break;
                };
                assert_eq!(request.method(), http::Method::CONNECT);
                streams.push(tokio::spawn(async move {
                    let mut body = request.into_body();
                    let response = http::Response::builder()
                        .status(200)
                        .header(PADDING_TYPE_REPLY_HEADER, "0")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    while let Some(Ok(data)) = body.data().await {
                        let length = data.len();
                        let mut payload = BytesMut::from(&data[..]);
                        let _ = body.flow_control().release_capacity(length);
                        payload.iter_mut().for_each(u8::make_ascii_uppercase);
                        if send.send_data(Bytes::from(payload), false).is_err() {
                            break;
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                }));
                if goaway_after_first {
                    // "No new streams." The ones already running keep going,
                    // which is exactly what the client must not confuse with a
                    // connection that has died.
                    connection.graceful_shutdown();
                }
            }
            for stream in streams {
                let _ = stream.await;
            }
        })
    }

    /// One connection attempt, boxed so the closure that makes it has a name a
    /// human can read.
    type Dialling = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Established, NaiveError>> + Send>,
    >;

    /// Build the `connect` closure the pool calls, counting how many
    /// connections it actually opens.
    fn counting_dialer(
        max_streams: u32,
        goaway_after_first: bool,
    ) -> (impl Fn() -> Dialling, Arc<std::sync::atomic::AtomicUsize>) {
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = opened.clone();
        let dial = move || {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (client_io, server_io) = tokio::io::duplex(256 * 1024);
                spawn_multiplexing_proxy(server_io, max_streams, goaway_after_first);
                let (sender, connection) = h2::client::handshake(client_io).await?;
                Ok(establish(sender, connection))
            }) as Dialling
        };
        (dial, opened)
    }

    async fn echo(tunnel: &mut BoxStream, payload: &[u8]) -> Vec<u8> {
        tunnel.write_all(payload).await.unwrap();
        tunnel.flush().await.unwrap();
        let mut echoed = vec![0_u8; payload.len()];
        tunnel.read_exact(&mut echoed).await.unwrap();
        echoed
    }

    /// Every dial used to build its own TCP connection, TLS session and HTTP/2
    /// preface for a single CONNECT stream — on a phone, that is the whole stack
    /// re-run dozens of times for one page load, and dozens of identical
    /// ClientHellos for anyone counting them. HTTP/2 exists to carry many
    /// streams on one connection, and the reference client uses it that way.
    #[tokio::test]
    async fn flows_share_one_connection_instead_of_dialling_each() {
        let pool = H2Pool::default();
        let (dial, opened) = counting_dialer(100, false);

        let mut first = multiplexed_connect(
            &pool,
            &dial,
            &Destination::new("one.example", 443),
            None,
            false,
        )
        .await
        .expect("the first flow opens the connection");
        let mut second = multiplexed_connect(
            &pool,
            &dial,
            &Destination::new("two.example", 443),
            None,
            false,
        )
        .await
        .expect("the second flow rides the same connection");

        assert_eq!(echo(&mut first, b"alpha").await, b"ALPHA");
        assert_eq!(echo(&mut second, b"beta").await, b"BETA");
        assert_eq!(
            opened.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "two flows must not cost two connections"
        );
        assert_eq!(pool.connection_count(), 1);
    }

    /// The peer's `SETTINGS_MAX_CONCURRENT_STREAMS` is a statement about what it
    /// will accept, not advice: past it every extra stream is a `REFUSED_STREAM`
    /// and a dead flow. A saturated connection has to be passed over.
    #[tokio::test]
    async fn a_connection_at_the_peers_stream_limit_is_not_overloaded() {
        let pool = H2Pool::default();
        let (dial, opened) = counting_dialer(1, false);

        let mut first = multiplexed_connect(
            &pool,
            &dial,
            &Destination::new("one.example", 443),
            None,
            false,
        )
        .await
        .unwrap();
        // A completed round trip is the proof the server's SETTINGS have been
        // received and applied, which is what the limit is read from.
        assert_eq!(echo(&mut first, b"alpha").await, b"ALPHA");

        // Bounded: a client that piles the second stream onto a connection
        // allowed one does not fail, it waits — for the first stream to finish,
        // which is never. That is a hung flow, and a hung test would only look
        // like a slow one.
        let mut second = tokio::time::timeout(
            Duration::from_secs(5),
            multiplexed_connect(
                &pool,
                &dial,
                &Destination::new("two.example", 443),
                None,
                false,
            ),
        )
        .await
        .expect("a saturated connection must not park the next flow behind it")
        .expect("a second flow must still get a tunnel");
        assert_eq!(echo(&mut second, b"beta").await, b"BETA");
        assert_eq!(
            opened.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "a connection allowed one stream must not be given a second"
        );

        // And the slot comes back when the stream does.
        drop(first);
        drop(second);
    }

    /// GOAWAY means "no new streams here", not "everything on this connection is
    /// dead". The flow that races it has to land on a fresh connection instead
    /// of failing, and the flow already running has to be left alone.
    #[tokio::test]
    async fn a_goaway_drains_the_connection_and_the_next_flow_reconnects() {
        let pool = H2Pool::default();
        let (dial, opened) = counting_dialer(100, true);

        let mut first = multiplexed_connect(
            &pool,
            &dial,
            &Destination::new("one.example", 443),
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(echo(&mut first, b"alpha").await, b"ALPHA");

        let mut second = multiplexed_connect(
            &pool,
            &dial,
            &Destination::new("two.example", 443),
            None,
            false,
        )
        .await
        .expect("a flow that lands on a draining connection must be re-tried");
        assert_eq!(echo(&mut second, b"beta").await, b"BETA");
        assert!(
            opened.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the draining connection must be replaced, not reused"
        );

        // The stream that was already running is untouched by the GOAWAY.
        assert_eq!(echo(&mut first, b"still here").await, b"STILL HERE");
    }

    /// A dozen flows arriving at a cold pool must open one connection between
    /// them and none of them may wedge.
    ///
    /// A dozen and not more: until the peer's `SETTINGS` arrive the pool treats
    /// a connection as good for a conservative number of streams, so a
    /// larger burst legitimately opens a second one and would be measuring that
    /// instead of the property under test.
    ///
    /// This is the shape that a lock held across an `await` turns into a
    /// deadlock: the list of connections is taken and released synchronously,
    /// and only connection *setup* is serialised — with a second look at the
    /// pool after that wait, which is what makes the other nineteen reuse the
    /// first one's work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_of_flows_on_a_cold_pool_opens_one_connection_and_none_deadlock() {
        let pool = Arc::new(H2Pool::default());
        let (dial, opened) = counting_dialer(100, false);
        let dial = Arc::new(dial);

        let mut flows = Vec::new();
        for index in 0..12 {
            let pool = pool.clone();
            let dial = dial.clone();
            flows.push(tokio::spawn(async move {
                let mut tunnel = multiplexed_connect(
                    &pool,
                    dial.as_ref(),
                    &Destination::new(format!("host{index}.example"), 443),
                    None,
                    false,
                )
                .await
                .expect("every flow in the burst must get a tunnel");
                assert_eq!(echo(&mut tunnel, b"ping").await, b"PING");
            }));
        }
        for flow in flows {
            tokio::time::timeout(Duration::from_secs(10), flow)
                .await
                .expect("no flow may wedge waiting for a connection")
                .unwrap();
        }
        assert_eq!(
            opened.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a burst on a cold pool must not open a connection per flow"
        );
    }

    #[tokio::test]
    async fn tls_is_mandatory_and_alpn_is_pinned_to_h2() {
        let plaintext = NaiveConfig {
            server: "127.0.0.1".into(),
            port: 443,
            tls: TlsConfig::default(),
            ..NaiveConfig::default()
        };
        let error = NaiveOutbound::new(plaintext, ProtectedDialer::host())
            .await
            .expect_err("plaintext NaiveProxy must be refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let wrong_alpn = NaiveConfig {
            server: "127.0.0.1".into(),
            port: 443,
            tls: TlsConfig {
                enabled: true,
                alpn: vec!["http/1.1".to_owned()],
                ..TlsConfig::default()
            },
            ..NaiveConfig::default()
        };
        assert!(
            NaiveOutbound::new(wrong_alpn, ProtectedDialer::host())
                .await
                .is_err()
        );

        let unset_alpn = NaiveConfig {
            server: "127.0.0.1".into(),
            port: 443,
            tls: TlsConfig {
                enabled: true,
                ..TlsConfig::default()
            },
            ..NaiveConfig::default()
        };
        let outbound = NaiveOutbound::new(unset_alpn, ProtectedDialer::host())
            .await
            .unwrap();
        assert_eq!(outbound.config.tls.alpn, ["h2"]);
    }

    #[tokio::test]
    async fn udp_fails_closed() {
        let outbound = NaiveOutbound::new(
            NaiveConfig {
                server: "127.0.0.1".into(),
                port: 443,
                ..NaiveConfig::default()
            },
            ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let error = match outbound
            .connect_datagram(&Destination::new("dns.example", 53))
            .await
        {
            Ok(_) => panic!("NaiveProxy must not offer a datagram session"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn the_password_never_appears_in_debug_output() {
        let config = NaiveConfig {
            server: "edge.example".into(),
            port: 443,
            username: Some("fox".into()),
            password: Some(SecretString::new("super-secret")),
            ..NaiveConfig::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn padding_is_required_by_default() {
        assert!(NaiveConfig::default().padding);
    }
}
