use super::*;
use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use foxcore_api::{
    BlockReason, CoreEvent, Destination, DnsCategory, DnsConfig, DnsMode, DnsRoute, DnsUpstream,
    EventSink, FlowContext, IpTransport, TlsConfig,
};
use foxcore_dns::{DnsCache, http_query, nxdomain_response, restore_transaction_id};
use foxcore_outbound::{Outbound, OutboundKind, OutboundRegistry};
use foxcore_route::domain::{BlocklistSource, DomainBlocklist};
use foxcore_route::ruleset::RuleSetArtifact;
use foxcore_transport::{BoxDatagramSession, BoxStream, Datagram, wrap_tls};

use crate::metrics::FlowMetrics;
use crate::{is_i2p, is_onion};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request};
use url::Url;

#[derive(Clone)]
pub(crate) struct DnsProxy {
    generation: u64,
    config: Arc<DnsConfig>,
    cache: Arc<DnsCache>,
    outbounds: Arc<OutboundRegistry>,
    direct: Arc<Outbound>,
    tor_enabled: bool,
    i2p_enabled: bool,
    blocklist: Arc<DomainBlocklist>,
    blocklist_bypass_packages: Arc<HashSet<String>>,
    pub(super) upstream_state: Arc<Vec<UpstreamPool>>,
    metrics: Arc<FlowMetrics>,
    events: EventSink,
    network_epoch: Arc<AtomicU64>,
    network_barrier: Arc<Mutex<()>>,
}

impl DnsProxy {
    #[cfg(test)]
    pub(crate) fn new(
        generation: u64,
        config: DnsConfig,
        cache: Arc<DnsCache>,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
    ) -> Option<Self> {
        Self::new_with_gates(
            generation,
            config,
            cache,
            outbounds,
            direct,
            true,
            true,
            Arc::new(FlowMetrics::default()),
            EventSink::none(),
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_gates(
        generation: u64,
        config: DnsConfig,
        cache: Arc<DnsCache>,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
        tor_enabled: bool,
        i2p_enabled: bool,
        metrics: Arc<FlowMetrics>,
        events: EventSink,
    ) -> Option<Self> {
        Self::new_with_gates_and_rule_sets(
            generation,
            config,
            cache,
            outbounds,
            direct,
            tor_enabled,
            i2p_enabled,
            metrics,
            events,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_gates_and_rule_sets(
        generation: u64,
        mut config: DnsConfig,
        cache: Arc<DnsCache>,
        outbounds: Arc<OutboundRegistry>,
        direct: Arc<Outbound>,
        tor_enabled: bool,
        i2p_enabled: bool,
        metrics: Arc<FlowMetrics>,
        events: EventSink,
        rule_sets: Vec<RuleSetArtifact>,
    ) -> Option<Self> {
        if config.upstreams.is_empty()
            && let Some(address) = config.upstream.take()
        {
            config.upstreams.push(DnsUpstream::Udp { address });
        }
        // One predicate, owned by the config type. Duplicating it here is what
        // let a blocklist-only config validate and then quietly resolve every
        // name it was supposed to block.
        let enabled = config.intercepts();
        let upstream_state = config.upstreams.iter().map(UpstreamPool::new).collect();
        let mut sources = vec![BlocklistSource {
            category: None,
            exact: &config.blocklist.exact,
            suffixes: &config.blocklist.suffixes,
        }];
        sources.extend(
            config
                .blocklist
                .categories
                .iter()
                .map(|group| BlocklistSource {
                    category: Some(group.category),
                    exact: &group.exact,
                    suffixes: &group.suffixes,
                }),
        );
        let blocklist = Arc::new(
            DomainBlocklist::compile_sources(&sources)
                .with_allowlist(
                    &config.blocklist.allow_exact,
                    &config.blocklist.allow_suffixes,
                )
                .with_rule_sets(rule_sets),
        );
        let blocklist_bypass_packages =
            Arc::new(config.blocklist.bypass_packages.iter().cloned().collect());
        drop(sources);
        enabled.then(|| Self {
            generation,
            config: Arc::new(config),
            cache,
            outbounds,
            direct,
            tor_enabled,
            i2p_enabled,
            blocklist,
            blocklist_bypass_packages,
            upstream_state: Arc::new(upstream_state),
            metrics,
            events,
            network_epoch: Arc::new(AtomicU64::new(0)),
            network_barrier: Arc::new(Mutex::new(())),
        })
    }

    /// `exchange` without a caller, for tests that are about resolution rather
    /// than about who asked.
    #[cfg(test)]
    pub(crate) async fn exchange_for_test(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        self.exchange(query, None).await
    }

    /// Resolve a question with the complete Android attribution result.
    ///
    /// Android shared UIDs can name several packages. Filtering is bypassed
    /// only if every attributed package is explicitly allowed; selecting the
    /// first package would let one allowed neighbour disable filtering for all.
    pub(crate) async fn exchange_for_identity(
        &self,
        query: &[u8],
        primary_package: Option<&str>,
        packages: &[String],
    ) -> io::Result<Vec<u8>> {
        self.exchange_attributed(query, primary_package, packages)
            .await
    }

    /// Records a refused name once, in both channels the app reads: the counter
    /// it polls and the event stream the journal persists.
    fn refuse(
        &self,
        reason: BlockReason,
        domain: &str,
        package: Option<&str>,
        category: Option<DnsCategory>,
    ) {
        self.metrics.dns_blocked();
        self.events.emit_with(|| CoreEvent::DnsBlocked {
            reason,
            domain: domain.to_owned(),
            package: package.map(ToOwned::to_owned),
            category,
        });
    }

    /// A UDP upstream the selected outbound cannot carry.
    ///
    /// The same refusal `FlowEngine::open_datagram` reports, reached by the one
    /// path the first fix did not cover: a profile whose outbound is TCP-only —
    /// Naive, HTTP CONNECT, I2P — configured with a UDP resolver. Every lookup
    /// failed with a bare `io::Error` and nothing counted it, so DNS simply did
    /// not work and the telemetry said nothing about why.
    ///
    /// Counted per query, because the counter's job is to say how much failed.
    /// Reported once per policy generation, because the condition does not
    /// change until the configuration does.
    fn refuse_udp_upstream(&self, index: usize, domain: &str, package: Option<&str>) {
        self.metrics.udp_unsupported();
        self.metrics.dns_blocked();
        if self.upstream_state[index].report_udp_refusal_once() {
            self.events.emit_with(|| CoreEvent::DnsBlocked {
                reason: BlockReason::UdpUnsupported,
                domain: domain.to_owned(),
                package: package.map(ToOwned::to_owned),
                category: None,
            });
        }
    }

    #[cfg(test)]
    pub(crate) async fn exchange(
        &self,
        query: &[u8],
        package: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        self.exchange_attributed(query, package, &[]).await
    }

    async fn exchange_attributed(
        &self,
        query: &[u8],
        primary_package: Option<&str>,
        packages: &[String],
    ) -> io::Result<Vec<u8>> {
        if query.len() < 12 || query.len() > u16::MAX as usize {
            return Err(invalid("DNS query length must be in 12..=65535"));
        }
        // Counted before any verdict, so `dns_allowed` is a real difference and
        // not an assumption about which refusals were instrumented.
        self.metrics.dns_query();
        let question = DnsCache::question(query);
        let name = question.as_ref().map(|question| question.domain.as_str());
        let onion = name.is_some_and(is_onion);
        let i2p = name.is_some_and(is_i2p);
        let overlay_refusal = if onion && !self.tor_enabled {
            Some(".onion DNS is disabled by the active traffic policy")
        } else if i2p && !self.i2p_enabled {
            Some(".i2p DNS is disabled by the active traffic policy")
        } else if onion && self.outbounds.tor().is_none() {
            Some(".onion DNS requires a registered Tor outbound")
        } else if i2p && self.outbounds.i2p().is_none() {
            Some(".i2p DNS requires a registered I2P outbound")
        } else {
            None
        };
        if let Some(message) = overlay_refusal {
            self.refuse(
                BlockReason::DnsOverlayGate,
                name.unwrap_or_default(),
                primary_package,
                None,
            );
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
        }
        // The blocklist is consulted after the overlay gates but before the cache and
        // before fake-IP: a blocked name must never be answered from a pre-block cache
        // entry, must never burn a fake IP, and must never reach an upstream.
        let mut attributed_packages = packages
            .iter()
            .map(String::as_str)
            .chain(primary_package.filter(|_| packages.is_empty()));
        let bypasses_filtering = attributed_packages
            .next()
            .is_some_and(|package| self.blocklist_bypass_packages.contains(package))
            && attributed_packages.all(|package| self.blocklist_bypass_packages.contains(package));
        if !bypasses_filtering
            && let Some(domain) = name
            && let Some(verdict) = self.blocklist.lookup(domain)
        {
            self.refuse(
                BlockReason::DnsBlocklist,
                domain,
                primary_package,
                verdict.category(),
            );
            return nxdomain_response(query)
                .ok_or_else(|| invalid("cannot answer a malformed DNS query with NXDOMAIN"));
        }
        let network_epoch = self.current_network_epoch()?;
        if let Some(response) = self.cached_response(query, false, network_epoch)? {
            return Ok(response);
        }
        if self.config.mode == DnsMode::FakeIp
            && let Some(response) = self.cache.fake_response(
                query,
                self.config.fake_ipv4_pool,
                self.config.fake_ipv6_pool,
                self.config.fake_ttl_s,
            )
        {
            return Ok(response);
        }
        if onion || i2p {
            // Reached when fake-IP is off: the overlay is available, but there
            // is no address to hand back without asking a clearnet resolver,
            // which is the one thing a private namespace must never do.
            self.refuse(
                BlockReason::DnsOverlayGate,
                name.unwrap_or_default(),
                primary_package,
                None,
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private overlay DNS is never forwarded to an upstream resolver",
            ));
        }

        let mut last_error = None;
        for (index, upstream) in self.config.upstreams.iter().enumerate() {
            let exchange = self.exchange_upstream(index, upstream, query, name, primary_package);
            match tokio::time::timeout(Duration::from_millis(self.config.timeout_ms), exchange)
                .await
            {
                Ok(Ok(response)) if response.len() <= self.config.max_response_bytes => {
                    match self.cache_response(query, &response, network_epoch) {
                        Ok(true) => return Ok(response),
                        Ok(false) => {
                            self.reset_upstream(index);
                            last_error =
                                Some(invalid("DNS upstream returned a mismatched response"));
                        }
                        Err(error) => {
                            self.reset_upstream(index);
                            return Err(error);
                        }
                    }
                }
                Ok(Ok(_)) => {
                    self.reset_upstream(index);
                    last_error = Some(invalid("DNS upstream response exceeds configured limit"));
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    self.reset_upstream(index);
                    last_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DNS upstream timed out",
                    ));
                }
            }
        }
        if self.config.stale_on_error
            && let Some(response) = self.cached_response(query, true, network_epoch)?
        {
            return Ok(response);
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "DNS interceptor has no usable upstream",
            )
        }))
    }

    async fn exchange_upstream(
        &self,
        index: usize,
        upstream: &DnsUpstream,
        query: &[u8],
        name: Option<&str>,
        package: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        match upstream {
            DnsUpstream::Udp { address } => {
                let destination = parse_endpoint(address, DNS_PORT)?;
                self.exchange_udp(index, destination, query, name, package)
                    .await
            }
            DnsUpstream::Tcp { address } => {
                let destination = parse_endpoint(address, DNS_PORT)?;
                self.exchange_stream(index, destination, None, query).await
            }
            DnsUpstream::Dot {
                host,
                port,
                server_ip,
                insecure,
                pinned_spki_sha256,
            } => {
                let destination = Destination::new(
                    server_ip.map_or_else(|| host.clone(), |ip| ip.to_string()),
                    *port,
                );
                let tls = TlsConfig {
                    enabled: true,
                    server_name: Some(host.clone()),
                    insecure: *insecure,
                    pinned_spki_sha256: pinned_spki_sha256.clone(),
                    alpn: Vec::new(),
                    ..TlsConfig::default()
                };
                self.exchange_stream(index, destination, Some((tls, host)), query)
                    .await
            }
            DnsUpstream::Doh {
                url,
                server_ip,
                insecure,
                pinned_spki_sha256,
            } => {
                self.exchange_doh(
                    index,
                    url.expose(),
                    *server_ip,
                    *insecure,
                    pinned_spki_sha256.clone(),
                    query,
                )
                .await
            }
        }
    }

    async fn exchange_udp(
        &self,
        index: usize,
        destination: Destination,
        query: &[u8],
        name: Option<&str>,
        package: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        let Some(mut state) = self.upstream_state[index].try_lock() else {
            let session = self
                .open_udp_upstream(index, &destination, name, package)
                .await?;
            return exchange_datagram(&session, destination, query).await;
        };
        if !matches!(*state, UpstreamState::Udp(_)) {
            let session = self
                .open_udp_upstream(index, &destination, name, package)
                .await?;
            *state = UpstreamState::Udp(session);
        }
        let result = match &*state {
            UpstreamState::Udp(session) => exchange_datagram(session, destination, query).await,
            // Initialized immediately above, but the release profile aborts on
            // panic and this runs per DNS query: a wrong invariant would cost
            // the whole process instead of one lookup.
            _ => Err(other("DNS UDP upstream state was replaced concurrently")),
        };
        if result.is_err() {
            *state = UpstreamState::Empty;
        }
        result
    }

    /// Open the datagram session a UDP upstream needs, telling the two failure
    /// modes apart exactly as the flow engine does.
    ///
    /// The error is still returned rather than swallowed: a later DoT or DoH
    /// upstream in the same list is a legitimate answer, and it is protected
    /// too. What must not happen — and did — is the refusal passing through
    /// uncounted and unreported.
    async fn open_udp_upstream(
        &self,
        index: usize,
        destination: &Destination,
        name: Option<&str>,
        package: Option<&str>,
    ) -> io::Result<foxcore_transport::BoxDatagramSession> {
        let context = FlowContext::new(self.generation, IpTransport::Udp, destination.clone());
        match self.selected_outbound()?.connect_datagram(&context).await {
            Ok(session) => Ok(session),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                self.refuse_udp_upstream(index, name.unwrap_or_default(), package);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn exchange_stream(
        &self,
        index: usize,
        destination: Destination,
        tls: Option<(TlsConfig, &str)>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let Some(mut state) = self.upstream_state[index].try_lock() else {
            let mut stream = self.connect_stream(destination).await?;
            if let Some((tls, server_name)) = tls {
                stream = wrap_tls(stream, &tls, server_name).await?;
            }
            return exchange_length_prefixed(&mut stream, query, self.config.max_response_bytes)
                .await;
        };
        if !matches!(*state, UpstreamState::Stream(_)) {
            let mut stream = self.connect_stream(destination).await?;
            if let Some((tls, server_name)) = tls {
                stream = wrap_tls(stream, &tls, server_name).await?;
            }
            *state = UpstreamState::Stream(stream);
        }
        let result = match &mut *state {
            UpstreamState::Stream(stream) => {
                exchange_length_prefixed(stream, query, self.config.max_response_bytes).await
            }
            _ => Err(other("DNS stream upstream state was replaced concurrently")),
        };
        if result.is_err() {
            *state = UpstreamState::Empty;
        }
        result
    }

    async fn connect_stream(&self, destination: Destination) -> io::Result<BoxStream> {
        let context = FlowContext::new(self.generation, IpTransport::Tcp, destination.clone());
        self.selected_outbound()?
            .connect_stream(&context, destination)
            .await
    }

    async fn exchange_doh(
        &self,
        index: usize,
        endpoint: &str,
        server_ip: Option<std::net::IpAddr>,
        insecure: bool,
        pinned_spki_sha256: Option<String>,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let Some(mut state) = self.upstream_state[index].try_lock() else {
            let sender = self
                .connect_doh(endpoint, server_ip, insecure, pinned_spki_sha256)
                .await?;
            return self.doh_request(&sender, endpoint, query).await;
        };
        let sender = match &*state {
            UpstreamState::Doh(sender) => sender.clone(),
            _ => {
                let sender = self
                    .connect_doh(endpoint, server_ip, insecure, pinned_spki_sha256)
                    .await?;
                *state = UpstreamState::Doh(sender.clone());
                sender
            }
        };
        drop(state);
        let result = self.doh_request(&sender, endpoint, query).await;
        if result.is_err() {
            self.reset_upstream(index);
        }
        result
    }

    async fn connect_doh(
        &self,
        endpoint: &str,
        server_ip: Option<std::net::IpAddr>,
        insecure: bool,
        pinned_spki_sha256: Option<String>,
    ) -> io::Result<h2::client::SendRequest<Bytes>> {
        let url = Url::parse(endpoint).map_err(|_| invalid("invalid DoH URL"))?;
        let host = url
            .host_str()
            .ok_or_else(|| invalid("DoH URL has no host"))?
            .to_owned();
        let port = url.port_or_known_default().unwrap_or(DOH_PORT);
        let destination = Destination::new(
            server_ip.map_or_else(|| host.clone(), |ip| ip.to_string()),
            port,
        );
        let stream = self.connect_stream(destination).await?;
        let tls = TlsConfig {
            enabled: true,
            server_name: Some(host.clone()),
            insecure,
            pinned_spki_sha256,
            alpn: vec!["h2".into()],
            ..TlsConfig::default()
        };
        let stream = wrap_tls(stream, &tls, &host).await?;
        let (sender, connection) = h2::client::handshake(stream)
            .await
            .map_err(|error| other(format!("DoH HTTP/2 handshake: {error}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(sender)
    }

    pub(super) async fn doh_request(
        &self,
        sender: &h2::client::SendRequest<Bytes>,
        endpoint: &str,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let (transaction_id, query) =
            http_query(query).ok_or_else(|| invalid("invalid DNS query"))?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(endpoint)
            .header(ACCEPT, DNS_MESSAGE_TYPE)
            .header(CONTENT_TYPE, DNS_MESSAGE_TYPE)
            .header(CONTENT_LENGTH, query.len())
            .body(())
            .map_err(|_| invalid("invalid DoH request URI"))?;
        let mut ready = sender
            .clone()
            .ready()
            .await
            .map_err(|error| other(format!("DoH HTTP/2 sender: {error}")))?;
        let (response, mut body) = ready
            .send_request(request, false)
            .map_err(|error| other(format!("send DoH request headers: {error}")))?;
        body.send_data(Bytes::from(query), true)
            .map_err(|error| other(format!("send DoH request body: {error}")))?;

        let response = response
            .await
            .map_err(|error| other(format!("receive DoH response headers: {error}")))?;
        if !response.status().is_success() {
            return Err(other(format!(
                "DoH server returned HTTP status {}",
                response.status()
            )));
        }
        if !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_dns_message_type)
        {
            return Err(invalid("DoH response content type is not DNS wire format"));
        }
        let mut response_body = response.into_body();
        let mut output = BytesMut::new();
        while let Some(chunk) = response_body.data().await {
            let chunk =
                chunk.map_err(|error| other(format!("receive DoH response body: {error}")))?;
            if output.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                return Err(invalid("DoH response exceeds configured limit"));
            }
            response_body
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|error| other(format!("release DoH HTTP/2 capacity: {error}")))?;
            output.extend_from_slice(&chunk);
        }
        // Both ends of the size range are refused rather than parsed. The upper
        // one is checked per chunk above, so a server streaming without end is
        // cut off instead of accumulated; the lower one is checked here, because
        // a body that stops short of the header is a truncated or empty answer
        // and the only thing to do with it is fail the lookup.
        if output.len() < MIN_DNS_MESSAGE_BYTES {
            return Err(invalid("DoH response is shorter than a DNS header"));
        }
        let mut output = output.to_vec();
        if !restore_transaction_id(&mut output, transaction_id) {
            return Err(invalid("DoH response is not a DNS response"));
        }
        Ok(output)
    }

    fn selected_outbound(&self) -> io::Result<&Arc<Outbound>> {
        let outbound = match self.config.route {
            DnsRoute::Direct => Ok(&self.direct),
            // `default` is a clearnet placeholder on an L3 profile, and handing
            // it out here sent every intercepted lookup — the names, and with
            // them the browsing history the tunnel exists to hide — out on a
            // protected socket beside the tunnel rather than through it. The
            // flow engine has refused the same placeholder for flows since it
            // was introduced; the interceptor never learned to. Fail closed:
            // `DnsRoute::Primary` is the default route, so the alternative to an
            // error is the leak.
            DnsRoute::Primary if self.outbounds.primary_is_packet_tunnel() => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS route 'primary' has no outbound on an L3 packet-tunnel profile: the \
                     registry's default is a clearnet placeholder and answering through it \
                     would send every intercepted lookup outside the tunnel",
            )),
            DnsRoute::Primary => Ok(self.outbounds.default()),
            DnsRoute::Tor if !self.tor_enabled => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS Tor route is disabled by the active traffic policy",
            )),
            DnsRoute::Tor => self.outbounds.tor().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "DNS route requests Tor but no Tor outbound is registered",
                )
            }),
        }?;
        match outbound.kind() {
            OutboundKind::Tor if !self.tor_enabled => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS outbound is Tor and Tor is disabled by the active traffic policy",
            )),
            OutboundKind::I2p if !self.i2p_enabled => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS outbound is I2P and I2P is disabled by the active traffic policy",
            )),
            _ => Ok(outbound),
        }
    }

    fn reset_upstream(&self, index: usize) {
        self.upstream_state[index].reset_idle();
    }

    fn current_network_epoch(&self) -> io::Result<u64> {
        let _barrier = lock(&self.network_barrier);
        let epoch = self.network_epoch.load(Ordering::Acquire);
        if epoch & 1 == 0 {
            Ok(epoch)
        } else {
            Err(network_changed_error())
        }
    }

    fn cached_response(
        &self,
        query: &[u8],
        stale: bool,
        epoch: u64,
    ) -> io::Result<Option<Vec<u8>>> {
        let _barrier = lock(&self.network_barrier);
        if self.network_epoch.load(Ordering::Acquire) != epoch {
            return Err(network_changed_error());
        }
        Ok(self.cache.cached_response(query, stale))
    }

    fn cache_response(&self, query: &[u8], response: &[u8], epoch: u64) -> io::Result<bool> {
        let _barrier = lock(&self.network_barrier);
        if self.network_epoch.load(Ordering::Acquire) != epoch {
            return Err(network_changed_error());
        }
        Ok(self
            .cache
            .cache_response(query, response, self.config.negative_cache))
    }

    /// Drop the cached answers and the idle upstream connections.
    ///
    /// Both halves are about the same event and neither covers the other. The
    /// answers are wrong because the previous network's resolver gave them; the
    /// connections are dead because they are sockets on an interface that no
    /// longer routes, and a DoH session in particular would otherwise be
    /// discovered dead only by the first query after the switch, which then
    /// pays a full timeout.
    ///
    /// In-flight lanes keep ownership until they return, but their old-network
    /// answers are discarded by the epoch check and cannot refill the cache.
    pub(crate) fn network_changed(&self) {
        let _barrier = lock(&self.network_barrier);
        self.network_epoch.fetch_add(1, Ordering::AcqRel);
        self.cache.flush_responses();
        for pool in self.upstream_state.iter() {
            pool.reset_idle();
        }
        self.network_epoch.fetch_add(1, Ordering::Release);
    }
}

fn network_changed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "DNS network changed during upstream exchange",
    )
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Send one query and take the first datagram that is actually its answer.
///
/// A direct session is connected to its one resolved peer, so the kernel drops
/// a forgery from another host before it reaches this loop. Encapsulated proxy
/// sessions also report the logical source. Two things must still match before
/// a datagram counts: that reported source and the transaction ID. Neither
/// check is redundant: the source binds the response to the configured
/// upstream, while the ID binds it to this query on a reused session.
///
/// A mismatch is skipped rather than returned as an error, which is what an
/// ordinary resolver does: the genuine answer is usually right behind the
/// forgery, and turning a race into a failed lookup would hand the attacker a
/// denial of service instead. The caller's timeout bounds the loop.
pub(super) async fn exchange_datagram(
    session: &BoxDatagramSession,
    destination: Destination,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let transaction_id = query.first_chunk::<2>().copied();
    let authenticated_peer = session.authenticated_peer();
    session
        .send(Datagram::new(
            destination.clone(),
            Bytes::copy_from_slice(query),
        ))
        .await?;
    loop {
        let datagram = session.recv().await?;
        if is_upstream_source(
            &destination,
            &datagram.destination,
            authenticated_peer.as_ref(),
        ) && datagram.payload.first_chunk::<2>().copied() == transaction_id
        {
            return Ok(datagram.payload.to_vec());
        }
    }
}
