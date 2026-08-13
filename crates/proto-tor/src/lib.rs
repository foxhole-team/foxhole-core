#![forbid(unsafe_code)]

#[cfg(feature = "arti")]
mod enabled {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::{
        BridgeConfigBuilder, CfgPath, TorClientConfig, TorClientConfigBuilder,
    };
    use arti_client::status::{BlockageKind, BootstrapStatus};
    use arti_client::{HasKind as _, TorClient};
    use foxcore_api::{Destination, TorConfig};
    use foxcore_dialer::ProtectedDialer;
    use foxcore_transport::{BoxDatagramSession, BoxStream};
    use futures::future::BoxFuture;
    use futures::io::{AsyncRead, AsyncWrite};
    use futures::stream::{self, Empty};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
    use tor_rtcompat::{
        CompoundRuntime, NetStreamListener, NetStreamProvider, PreferredRuntime,
        RuntimeSubstExt as _, StreamOps, TcpConnectOptions, TcpListenOptions,
    };

    type ArtiRuntime = CompoundRuntime<
        PreferredRuntime,
        PreferredRuntime,
        PreferredRuntime,
        ProtectedTcpProvider,
        PreferredRuntime,
        PreferredRuntime,
        PreferredRuntime,
    >;

    /// Stream source used for Arti guard connections.
    ///
    /// The default constructor uses Android-protected sockets. Tor-over-VPN supplies a closure that
    /// opens the same address through a validated FoxCore stream outbound instead.
    #[derive(Clone)]
    pub struct TorTcpDialer {
        connect: Arc<dyn Fn(SocketAddr) -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>,
    }

    impl TorTcpDialer {
        pub fn protected(dialer: ProtectedDialer) -> Self {
            Self::new(move |address| {
                let dialer = dialer.clone();
                async move { Ok(Box::new(dialer.connect_tcp(address).await?) as BoxStream) }
            })
        }

        pub fn new<F, Fut>(connect: F) -> Self
        where
            F: Fn(SocketAddr) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = io::Result<BoxStream>> + Send + 'static,
        {
            Self {
                connect: Arc::new(move |address| Box::pin(connect(address))),
            }
        }

        async fn connect(&self, address: SocketAddr) -> io::Result<BoxStream> {
            (self.connect)(address).await
        }
    }

    #[derive(Clone)]
    pub struct TorOutbound {
        client: Arc<TorClient<ArtiRuntime>>,
        isolate_streams: bool,
    }

    impl TorOutbound {
        pub async fn new(config: TorConfig, dialer: TorTcpDialer) -> io::Result<Self> {
            let arti_config = build_arti_config(&config)?;
            let runtime = PreferredRuntime::current().map_err(|error| {
                other(format!("create Arti runtime: {}", crate::describe(&error)))
            })?;
            let runtime = runtime.with_tcp_provider(ProtectedTcpProvider { dialer });
            let client = TorClient::with_runtime(runtime)
                .config(arti_config)
                .create_unbootstrapped_async()
                .await
                .map_err(|error| {
                    arti_failure(
                        &error,
                        format!("create Arti client: {}", crate::describe(&error)),
                    )
                })?;
            match tokio::time::timeout(
                Duration::from_secs(config.bootstrap_timeout_s),
                client.bootstrap(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(arti_failure(
                        &error,
                        format!("Arti bootstrap failed: {}", crate::describe(&error)),
                    ));
                }
                Err(_) => return Err(bootstrap_timeout(&client.bootstrap_status())),
            }
            Ok(Self {
                client,
                isolate_streams: config.isolate_streams,
            })
        }

        pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
            let client = if self.isolate_streams {
                self.client.isolated_client()
            } else {
                self.client.clone()
            };
            let stream = client
                .connect((destination.host.as_str(), destination.port))
                .await
                .map_err(|error| {
                    arti_failure(
                        &error,
                        format!("Tor connect failed: {}", crate::describe(&error)),
                    )
                })?;
            Ok(Box::new(stream))
        }

        pub async fn connect_datagram(
            &self,
            _destination: &Destination,
        ) -> io::Result<BoxDatagramSession> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Tor/Arti outbound is TCP-only",
            ))
        }

        pub fn network_changed(&self) {
            // The protected dialer reads the latest Android Network handle for every
            // new guard connection. Existing channels naturally fail and Arti rebuilds
            // them; no circuit is intentionally reused across the old network.
        }

        /// Publish a hidden service on this outbound's Tor connection.
        ///
        /// A passthrough rather than an accessor for the client, and the
        /// difference is the whole point. Handing out the `TorClient` would hand
        /// out the ability to dial anywhere through Tor, which walks straight
        /// past the `tor_enabled` gate, the route policy and the overlay gates —
        /// authority this core does not give away anywhere else. What comes back
        /// here can only ever receive.
        ///
        /// The caller gets an address to publish and a queue of accepted byte
        /// streams; no Arti type crosses this boundary, so nothing above it has
        /// to grow a Tor dependency to serve files.
        #[cfg(feature = "onion-service")]
        pub fn launch_onion_service(&self, nickname: &str, port: u16) -> io::Result<OnionService> {
            use tor_hsservice::config::OnionServiceConfigBuilder;

            let nickname = nickname.parse().map_err(|error| {
                other(format!(
                    "onion service nickname: {}",
                    crate::describe(&error)
                ))
            })?;
            let config = OnionServiceConfigBuilder::default()
                .nickname(nickname)
                .build()
                .map_err(|error| {
                    other(format!("onion service config: {}", crate::describe(&error)))
                })?;

            // `None` means the config disabled the service. We always build it
            // enabled, so this is a disagreement with Arti rather than a state
            // the caller asked for — an error, not a quiet no-op.
            let (service, requests) = self
                .client
                .launch_onion_service(config)
                .map_err(|error| {
                    other(format!("launch onion service: {}", crate::describe(&error)))
                })?
                .ok_or_else(|| other("Arti declined to launch the onion service"))?;

            // The address exists only once the identity key does. Without it
            // there is nothing to publish, and returning a service nobody can
            // reach would look like a working server.
            let address = service
                .onion_address()
                .ok_or_else(|| other("onion service has no address yet"))?;
            let address = OnionAddress(address);

            let (sender, incoming) = tokio::sync::mpsc::channel(16);
            tokio::spawn(accept_rend_requests(requests, port, sender));

            Ok(OnionService {
                address,
                incoming,
                _service: service,
            })
        }
    }

    /// A timeout without a stage is not actionable on a physical device. Arti's public status is
    /// deliberately coarse, so it can be surfaced without bridge addresses, relay identities or
    /// transport arguments. Keep this mapping typed instead of forwarding its human string: that
    /// way a future dependency message cannot accidentally become part of FoxCore diagnostics.
    fn bootstrap_timeout(status: &BootstrapStatus) -> io::Error {
        let progress = (status.as_frac() * 100.0).round() as u32;
        let reason =
            status
                .blocked()
                .map_or("progress_stalled", |blockage| match blockage.kind() {
                    BlockageKind::Disabled => "disabled",
                    BlockageKind::Offline => "offline",
                    BlockageKind::Filtering => "filtered",
                    BlockageKind::CantReachTor => "tor_unreachable",
                    BlockageKind::ClockSkewed => "clock_skew",
                    BlockageKind::CantBootstrap => "directory_unavailable",
                    _ => "unknown",
                });
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("Arti bootstrap timed out at {progress}% ({reason})"),
        )
    }

    /// A published hidden service and the connections arriving on it.
    ///
    /// Dropping it unpublishes the service and ends the accept loop.
    #[cfg(feature = "onion-service")]
    pub struct OnionService {
        address: OnionAddress,
        incoming: tokio::sync::mpsc::Receiver<BoxStream>,
        _service: Arc<tor_hsservice::RunningOnionService>,
    }

    #[cfg(feature = "onion-service")]
    impl OnionService {
        pub fn address(&self) -> &OnionAddress {
            &self.address
        }

        /// Next accepted connection, or `None` once the service is finished.
        pub async fn accept(&mut self) -> Option<BoxStream> {
            self.incoming.recv().await
        }
    }

    /// A `.onion` address, redacted unless deliberately exposed.
    ///
    /// Arti redacts `HsId` in `Display` and `Debug` by default and this keeps
    /// that property: an address that reaches a log identifies the service to
    /// anyone who reads it, and the whole point of publishing over Tor is that
    /// only the people given the address can find it.
    #[cfg(feature = "onion-service")]
    #[derive(Clone)]
    pub struct OnionAddress(tor_hsservice::HsId);

    #[cfg(feature = "onion-service")]
    impl OnionAddress {
        /// The full `xxxx.onion` name. Every caller of this is handing the
        /// address to someone.
        pub fn expose(&self) -> String {
            use safelog::DisplayRedacted as _;
            self.0.display_unredacted().to_string()
        }
    }

    #[cfg(feature = "onion-service")]
    impl std::fmt::Debug for OnionAddress {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            use safelog::DisplayRedacted as _;
            write!(f, "OnionAddress({})", self.0.display_redacted())
        }
    }

    #[cfg(feature = "onion-service")]
    impl std::fmt::Display for OnionAddress {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            use safelog::DisplayRedacted as _;
            write!(f, "{}", self.0.display_redacted())
        }
    }

    /// Accept `BEGIN` streams for one port and hand the byte streams up.
    ///
    /// Only `BEGIN`, and only the configured port: Arti's own note is that an
    /// implementation which answers anything else is distinguishable from every
    /// other onion service, which is the one property a hidden service cannot
    /// afford to lose.
    #[cfg(feature = "onion-service")]
    async fn accept_rend_requests<S>(
        requests: S,
        port: u16,
        sender: tokio::sync::mpsc::Sender<BoxStream>,
    ) where
        S: futures::Stream<Item = tor_hsservice::RendRequest> + Unpin,
    {
        use futures::StreamExt as _;
        use tor_cell::relaycell::msg::{Connected, End};
        use tor_proto::stream::IncomingStreamRequest;

        let mut streams = Box::pin(tor_hsservice::handle_rend_requests(requests));
        while let Some(request) = streams.next().await {
            let wanted = matches!(
                request.request(),
                IncomingStreamRequest::Begin(begin) if begin.port() == port
            );
            if !wanted {
                // END_REASON_MISC is what a client sends for an ordinary refusal;
                // anything more specific would say why, which is a signal.
                let _ = request.reject(End::new_misc()).await;
                continue;
            }
            let Ok(stream) = request.accept(Connected::new_empty()).await else {
                continue;
            };
            if sender.send(Box::new(stream) as BoxStream).await.is_err() {
                // The service was dropped; nothing is listening any more.
                return;
            }
        }
    }

    fn build_arti_config(config: &TorConfig) -> io::Result<TorClientConfig> {
        let mut builder =
            TorClientConfigBuilder::from_directories(&config.state_dir, &config.cache_dir);
        #[cfg(feature = "onion-service")]
        builder
            .storage()
            .keystore()
            .primary()
            .kind(tor_config::ExplicitOrAuto::Explicit(
                tor_keymgr::config::ArtiKeystoreKind::Ephemeral,
            ));
        builder
            .stream_timeouts()
            .connect_timeout(Duration::from_secs(config.stream_connect_timeout_s));
        builder
            .circuit_timing()
            .max_dirtiness(Duration::from_secs(config.circuit.max_dirtiness_s))
            .request_timeout(Duration::from_secs(config.circuit.request_timeout_s))
            .request_max_retries(config.circuit.request_max_retries);

        for (index, line) in config.bridges.iter().enumerate() {
            let bridge: BridgeConfigBuilder = line.expose().parse().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid Tor bridge line at index {index}: {}",
                        crate::describe(&error)
                    ),
                )
            })?;
            builder.bridges().bridges().push(bridge);
        }
        for (index, transport) in config.transports.iter().enumerate() {
            let protocols = transport
                .protocols
                .iter()
                .map(|protocol| {
                    protocol.parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid Tor transport protocol at index {index}"),
                        )
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            let mut configured = TransportConfigBuilder::default();
            configured
                .protocols(protocols)
                .path(CfgPath::new(transport.path.clone()))
                .arguments(
                    transport
                        .arguments
                        .iter()
                        .map(|argument| argument.expose().to_owned())
                        .collect(),
                )
                .run_on_startup(transport.run_on_startup);
            builder.bridges().transports().push(configured);
        }

        builder.build().map_err(|error| {
            if config.bridges.is_empty() && config.transports.is_empty() {
                other(format!("build Arti config: {}", crate::describe(&error)))
            } else {
                other("build Arti config with bridges failed")
            }
        })
    }

    #[derive(Clone)]
    struct ProtectedTcpProvider {
        dialer: TorTcpDialer,
    }

    #[async_trait::async_trait]
    impl NetStreamProvider for ProtectedTcpProvider {
        type Stream = ProtectedTorStream;
        type Listener = UnsupportedListener;
        type ConnectOptions = TcpConnectOptions;
        type ListenOptions = TcpListenOptions;

        async fn connect(
            &self,
            address: &SocketAddr,
            _options: &Self::ConnectOptions,
        ) -> io::Result<Self::Stream> {
            // Managed transports publish a private SOCKS listener to Arti. Sending that loopback
            // connection through Android's protected/network-bound dialer binds 127.0.0.1 to the
            // physical Network and makes the local listener unreachable. External guard
            // connections must still use the injected dialer; only kernel loopback is local.
            let stream: BoxStream = if address.ip().is_loopback() {
                Box::new(tokio::net::TcpStream::connect(*address).await?)
            } else {
                self.dialer.connect(*address).await?
            };
            Ok(ProtectedTorStream(Mutex::new(stream.compat())))
        }

        async fn listen(
            &self,
            _address: &SocketAddr,
            _options: &Self::ListenOptions,
        ) -> io::Result<Self::Listener> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "FoxCore Arti runtime does not accept inbound TCP",
            ))
        }
    }

    struct ProtectedTorStream(Mutex<Compat<BoxStream>>);

    impl ProtectedTorStream {
        fn stream(&mut self) -> &mut Compat<BoxStream> {
            self.0
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl AsyncRead for ProtectedTorStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(self.stream()).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for ProtectedTorStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(self.stream()).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(self.stream()).poll_flush(context)
        }

        fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(self.stream()).poll_close(context)
        }
    }

    impl StreamOps for ProtectedTorStream {}

    struct UnsupportedListener;

    impl NetStreamListener for UnsupportedListener {
        type Stream = ProtectedTorStream;
        type Incoming = Empty<io::Result<(ProtectedTorStream, SocketAddr)>>;

        fn incoming(self) -> Self::Incoming {
            stream::empty()
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "FoxCore Arti runtime has no TCP listener",
            ))
        }
    }

    fn other(message: impl Into<String>) -> io::Error {
        io::Error::other(message.into())
    }

    /// Turn an Arti failure into an `io::Error` whose *kind* still says what went
    /// wrong.
    ///
    /// Everything above this crate classifies availability from
    /// `io::Error::kind` — `UnavailableReason::of` is kind-driven precisely so a
    /// reworded message cannot change a verdict. Wrapping every Arti error with
    /// `io::Error::other` threw that away at the one boundary that had the answer:
    /// on the device an Arti bootstrap that failed on `files/tor/state` being
    /// world-writable was published as `reason=internal`, though `Permissions`
    /// exists for exactly it. The class is not cosmetic — `Internal` is
    /// retryable and `Permissions` is not, so the misclassification had the core
    /// re-attempting a bootstrap that could not succeed until the user changed a
    /// file mode.
    ///
    /// The message is unchanged and still names Arti's own text, so nothing is
    /// lost by classifying.
    fn arti_failure(error: &arti_client::Error, message: String) -> io::Error {
        io::Error::new(arti_error_kind(error.kind()), message)
    }

    /// The kind half of [`arti_failure`], split out so the mapping is testable
    /// without an `arti_client::Error`, which has no public constructor.
    ///
    /// Deliberately narrow. Only a kind whose `UnavailableReason` is *not*
    /// `Internal` is worth translating, and only where Arti's own meaning and the
    /// `io::ErrorKind` agree exactly; anything else keeps `Other`, which is
    /// `Internal`, which is what this returned for everything before. Widening it
    /// is a matter of adding an arm — the seam is the point.
    fn arti_error_kind(kind: arti_client::ErrorKind) -> io::ErrorKind {
        match kind {
            // "…is u=rwx,g=rwx,o=rwx; must be o-w". A file mode is not a network
            // fault and no number of retries will change it.
            arti_client::ErrorKind::FsPermissions => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::Other,
        }
    }

    #[cfg(test)]
    mod tests {
        use foxcore_api::{SecretString, TorCircuitConfig, TorTransportConfig};

        use super::*;

        /// The device found this as `reason=internal` on an Arti bootstrap that
        /// failed because `files/tor/state` was world-writable — the reproduced
        /// permissions trap. `UnavailableReason::Permissions`
        /// exists for exactly that error, and its comment says why: it is the
        /// class that must not be reported as a network problem, because three
        /// device runs were spent reading it as one.
        ///
        /// The class decides behaviour and not only text. `Internal` is
        /// retryable, so the core kept re-attempting a bootstrap that could not
        /// succeed until someone ran `chmod`; `Permissions` is not, so the lane
        /// stays down and says why.
        #[test]
        fn a_filesystem_permission_failure_is_permissions_and_not_a_retryable_internal() {
            use foxcore_api::UnavailableReason;

            let error = io::Error::new(
                arti_error_kind(arti_client::ErrorKind::FsPermissions),
                "Arti bootstrap failed: tor: problem with filesystem permissions",
            );

            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                UnavailableReason::of(&error),
                UnavailableReason::Permissions,
                "a file mode reported as an internal error sends the app looking \
                 at the network"
            );
            assert!(
                !UnavailableReason::of(&error).is_retryable(),
                "and retrying a bootstrap that needs chmod is work that cannot \
                 succeed"
            );
        }

        /// The other half: classifying must not quietly reclassify everything
        /// else. Anything this mapping does not name keeps the class it had.
        #[test]
        fn an_unclassified_arti_failure_keeps_the_class_it_always_had() {
            use foxcore_api::UnavailableReason;

            let error = io::Error::new(
                arti_error_kind(arti_client::ErrorKind::TorAccessFailed),
                "Arti bootstrap failed: tor: all attempts to obtain a circuit failed",
            );

            assert_eq!(
                UnavailableReason::of(&error),
                UnavailableReason::Internal,
                "widening this mapping is an arm at a time, with a reason each"
            );
        }

        fn config(bridges: Vec<SecretString>) -> TorConfig {
            TorConfig {
                state_dir: "/tmp/foxcore-tor-test-state".into(),
                cache_dir: "/tmp/foxcore-tor-test-cache".into(),
                upstream: None,
                bootstrap_timeout_s: 30,
                stream_connect_timeout_s: 12,
                isolate_streams: true,
                circuit: TorCircuitConfig {
                    max_dirtiness_s: 300,
                    request_timeout_s: 45,
                    request_max_retries: 8,
                },
                bridges,
                transports: Vec::new(),
            }
        }

        #[cfg(feature = "onion-service")]
        #[test]
        fn onion_service_primary_keystore_is_ephemeral() {
            let configured = build_arti_config(&config(Vec::new())).unwrap();
            assert_eq!(
                configured.keystore().primary_kind(),
                Some(tor_keymgr::config::ArtiKeystoreKind::Ephemeral),
            );
        }

        #[test]
        fn builds_custom_timing_and_direct_bridge_config() {
            let bridge =
                SecretString::new("192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956");
            build_arti_config(&config(vec![bridge])).unwrap();
        }

        #[test]
        fn builds_a_managed_obfs4_transport_without_exposing_its_arguments() {
            let line = "obfs4 192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956 cert=secret";
            let mut configured = config(vec![SecretString::new(line)]);
            configured.transports.push(TorTransportConfig {
                protocols: vec!["obfs4".into()],
                path: "/data/app/com.foxhole.guard/lib/arm64/liblyrebird.so".into(),
                arguments: vec![SecretString::new("-enableLogging=false")],
                run_on_startup: true,
            });

            build_arti_config(&configured).unwrap();
            let debug = format!("{configured:?}");
            assert!(!debug.contains("cert=secret"));
            assert!(!debug.contains("-enableLogging=false"));
        }

        #[test]
        fn rejects_pluggable_transport_without_exposing_bridge_line() {
            let line = "obfs4 192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956 cert=secret";
            let error = build_arti_config(&config(vec![SecretString::new(line)]))
                .unwrap_err()
                .to_string();
            assert!(!error.contains(line));
            assert!(!error.contains("cert=secret"));
        }

        #[test]
        fn accepts_the_bundled_snowflake_bridge_shape() {
            let line = concat!(
                "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 ",
                "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 ",
                "url=https://1098762253.rsc.cdn77.org/ ",
                "fronts=app.datapacket.com,www.datapacket.com ",
                "ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478 ",
                "utls-imitate=hellorandomizedalpn",
            );
            let bridge: BridgeConfigBuilder = line.parse().unwrap();
            bridge.build().unwrap();
        }

        #[tokio::test]
        async fn managed_transport_loopback_never_reaches_the_external_dialer() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let external_calls = Arc::new(AtomicUsize::new(0));
            let calls = external_calls.clone();
            let provider = ProtectedTcpProvider {
                dialer: TorTcpDialer::new(move |_| {
                    calls.fetch_add(1, Ordering::Relaxed);
                    async {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "external dialer must not carry managed-transport loopback",
                        ))
                    }
                }),
            };

            provider
                .connect(&address, &TcpConnectOptions::default())
                .await
                .unwrap();

            assert_eq!(external_calls.load(Ordering::Relaxed), 0);
            let external: SocketAddr = "192.0.2.10:443".parse().unwrap();
            let error = match provider
                .connect(&external, &TcpConnectOptions::default())
                .await
            {
                Ok(_) => panic!("an external address bypassed the injected dialer"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(external_calls.load(Ordering::Relaxed), 1);
        }
    }
}

#[cfg(not(feature = "arti"))]
mod disabled {
    use std::io;

    use foxcore_api::{Destination, TorConfig};
    use foxcore_dialer::ProtectedDialer;
    use foxcore_transport::{BoxDatagramSession, BoxStream};

    #[derive(Clone)]
    pub struct TorOutbound;

    impl TorOutbound {
        pub async fn new(_config: TorConfig, _dialer: ProtectedDialer) -> io::Result<Self> {
            Err(unavailable())
        }

        pub async fn connect_stream(&self, _destination: &Destination) -> io::Result<BoxStream> {
            Err(unavailable())
        }

        pub async fn connect_datagram(
            &self,
            _destination: &Destination,
        ) -> io::Result<BoxDatagramSession> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Tor/Arti outbound is TCP-only",
            ))
        }

        pub fn network_changed(&self) {}
    }

    fn unavailable() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Tor support is not compiled; enable proto-tor/arti",
        )
    }
}

/// Render an error together with everything underneath it.
///
/// `Display` on an Arti error prints only the top frame, and the top frame is
/// routinely the useless half. A bootstrap that fails on a state directory says
/// "problem with filesystem permissions" and keeps *which directory* and *what
/// mode* one `source()` down — and Arti checks the whole ancestor chain, so the
/// offending directory is often not even the one in the config. Flattening the
/// error here means no layer above can recover it, however carefully it renders
/// what it was given.
///
/// Consecutive frames are deduplicated because a `thiserror` parent that
/// interpolates its child would otherwise print the same sentence twice, and
/// the walk is bounded so a deep or self-referential chain cannot turn a startup
/// failure into an unbounded string.
/// Compiled without `arti` only so its tests keep running in the ordinary
/// workspace gate — nothing calls it when Tor is not built in.
#[cfg(any(feature = "arti", test))]
fn describe(error: &(dyn std::error::Error + 'static)) -> String {
    /// Enough to reach the cause in the chains Arti actually produces.
    const MAX_FRAMES: usize = 8;
    const MAX_LEN: usize = 1024;

    let mut rendered = error.to_string();
    let mut source = error.source();
    for _ in 0..MAX_FRAMES {
        let Some(cause) = source else { break };
        let text = cause.to_string();
        // A parent that already quotes its child adds nothing by repeating it.
        if !text.is_empty() && !rendered.ends_with(&text) {
            rendered.push_str(": ");
            rendered.push_str(&text);
        }
        if rendered.len() >= MAX_LEN {
            rendered.truncate(MAX_LEN);
            rendered.push('…');
            break;
        }
        source = cause.source();
    }
    rendered
}

#[cfg(not(feature = "arti"))]
pub use disabled::TorOutbound;
#[cfg(feature = "onion-service")]
pub use enabled::{OnionAddress, OnionService};
#[cfg(feature = "arti")]
pub use enabled::{TorOutbound, TorTcpDialer};

#[cfg(test)]
mod describe_tests {
    use super::describe;

    #[derive(Debug)]
    struct Layer {
        message: String,
        source: Option<Box<Layer>>,
    }

    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_deref()
                .map(|source| source as &(dyn std::error::Error + 'static))
        }
    }

    fn chain(messages: &[&str]) -> Layer {
        let mut layers: Option<Box<Layer>> = None;
        for message in messages.iter().rev() {
            layers = Some(Box::new(Layer {
                message: (*message).to_owned(),
                source: layers,
            }));
        }
        *layers.expect("a chain needs at least one frame")
    }

    #[test]
    fn the_cause_arti_hides_one_level_down_reaches_the_message() {
        // The real shape, and the three device runs it cost: the top frame names
        // a category and the directory and mode are underneath it.
        let error = chain(&[
            "problem with filesystem permissions",
            "Permissions on \"/data/user/0/com.foxhole.guard/files\" are too permissive",
            "mode is 0o40777",
        ]);
        assert_eq!(
            describe(&error),
            "problem with filesystem permissions: \
             Permissions on \"/data/user/0/com.foxhole.guard/files\" are too permissive: \
             mode is 0o40777"
        );
    }

    #[test]
    fn a_single_frame_reads_exactly_as_it_did_before() {
        assert_eq!(
            describe(&chain(&["Arti bootstrap timed out"])),
            "Arti bootstrap timed out"
        );
    }

    #[test]
    fn a_parent_that_already_quotes_its_child_does_not_say_it_twice() {
        // thiserror's `{0}` interpolation makes this the common case, and
        // repeating the sentence buries the frame that actually adds something.
        let error = chain(&["outer: inner detail", "inner detail", "the real cause"]);
        assert_eq!(describe(&error), "outer: inner detail: the real cause");
    }

    #[test]
    fn a_runaway_chain_cannot_grow_without_bound() {
        let frames: Vec<String> = (0..64).map(|index| format!("frame {index}")).collect();
        let borrowed: Vec<&str> = frames.iter().map(String::as_str).collect();
        let rendered = describe(&chain(&borrowed));
        assert!(rendered.len() <= 1025, "got {} bytes", rendered.len());
        assert!(rendered.starts_with("frame 0: frame 1: "));
    }
}

#[cfg(all(test, not(feature = "arti")))]
mod tests {
    use super::*;
    use foxcore_api::Destination;

    #[tokio::test]
    async fn tor_datagrams_are_explicitly_unsupported() {
        let outbound = TorOutbound;
        let error = match outbound
            .connect_datagram(&Destination::new("example.com", 53))
            .await
        {
            Ok(_) => panic!("Tor unexpectedly accepted a UDP session"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}
