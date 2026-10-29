#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

type SocketCallback = Arc<dyn Fn(RawFd) -> bool + Send + Sync>;
type BindCallback = Arc<dyn Fn(RawFd, u64) -> bool + Send + Sync>;
type ResolveCallback = Arc<dyn Fn(&str, u16, u64) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
pub type ScopedResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;
pub type ScopedResolver = Arc<dyn Fn(&str, u16, u64) -> Option<ScopedResolveFuture> + Send + Sync>;

#[derive(Clone, Default)]
pub struct SocketCallbacks {
    protect: Option<SocketCallback>,
    bind: Option<BindCallback>,
    resolve: Option<ResolveCallback>,
    resolver_requires_network: bool,
}

impl fmt::Debug for SocketCallbacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketCallbacks")
            .field("protect", &self.protect.is_some())
            .field("bind", &self.bind.is_some())
            .field("resolve", &self.resolve.is_some())
            .finish()
    }
}

impl SocketCallbacks {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn new(
        protect: impl Fn(RawFd) -> bool + Send + Sync + 'static,
        bind: impl Fn(RawFd, u64) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            protect: Some(Arc::new(protect)),
            bind: Some(Arc::new(bind)),
            resolve: None,
            resolver_requires_network: false,
        }
    }

    pub fn protect_only(protect: impl Fn(RawFd) -> bool + Send + Sync + 'static) -> Self {
        Self {
            protect: Some(Arc::new(protect)),
            bind: None,
            resolve: None,
            resolver_requires_network: false,
        }
    }

    pub fn with_resolver(
        mut self,
        resolve: impl Fn(&str, u16, u64) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.resolve = Some(Arc::new(resolve));
        self.resolver_requires_network = true;
        self
    }

    /// Install a host resolver that owns its socket protection without an Android Network handle.
    pub fn with_host_resolver(
        mut self,
        resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.resolve = Some(Arc::new(move |host, port, _| resolve(host, port)));
        self.resolver_requires_network = false;
        self
    }
}

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CANDIDATE_STAGGER: Duration = Duration::from_millis(250);
const MAX_CONCURRENT_CANDIDATES: usize = 2;

#[derive(Clone)]
pub struct ProtectedDialer {
    callbacks: SocketCallbacks,
    network_handle: Arc<AtomicU64>,
    network_revision: Arc<AtomicU64>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    scoped_resolver: Option<ScopedResolver>,
}

impl fmt::Debug for ProtectedDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedDialer")
            .field("callbacks", &self.callbacks)
            .field("network_handle", &self.network_handle())
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish()
    }
}

impl ProtectedDialer {
    pub fn new(callbacks: SocketCallbacks, connect_timeout: Duration) -> Self {
        Self {
            callbacks,
            network_handle: Arc::new(AtomicU64::new(0)),
            network_revision: Arc::new(AtomicU64::new(0)),
            connect_timeout,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            scoped_resolver: None,
        }
    }

    /// Set the profile's handshake budget.
    #[must_use]
    pub fn with_handshake_timeout(mut self, handshake_timeout: Duration) -> Self {
        self.handshake_timeout = handshake_timeout;
        self
    }

    /// How long a protocol may spend on its handshake once connected.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    #[must_use]
    pub fn with_scoped_resolver(mut self, resolver: ScopedResolver) -> Self {
        self.scoped_resolver = Some(resolver);
        self
    }

    pub fn host() -> Self {
        Self::new(SocketCallbacks::none(), Duration::from_secs(10))
    }

    pub fn set_network_handle(&self, network_handle: u64) {
        self.network_handle.store(network_handle, Ordering::Release);
        self.network_revision.fetch_add(1, Ordering::AcqRel);
    }

    pub fn network_handle(&self) -> u64 {
        self.network_handle.load(Ordering::Acquire)
    }

    pub fn network_revision(&self) -> u64 {
        self.network_revision.load(Ordering::Acquire)
    }

    pub async fn resolve(&self, server: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(address) = server.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, port)]);
        }
        let network_handle = self.network_handle();
        if network_handle == 0 && self.callbacks.resolver_requires_network {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Android Network handle is required for protected DNS resolution",
            ));
        }
        if let Some(resolver) = &self.scoped_resolver
            && let Some(resolution) = resolver(server, port, network_handle)
        {
            return resolution.await;
        }
        let addresses = if let Some(resolve) = &self.callbacks.resolve {
            let resolve = resolve.clone();
            let server = server.to_owned();
            // Cancelling spawn_blocking cannot stop a resolver already running;
            // reject expired queued work before it consumes the shared pool.
            let deadline = Instant::now() + self.connect_timeout;
            tokio::time::timeout(
                self.connect_timeout,
                tokio::task::spawn_blocking(move || {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DNS resolution was abandoned before the resolver ran",
                        ));
                    }
                    resolve(&server, port, network_handle)
                }),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timed out"))?
            .map_err(|error| io::Error::other(format!("DNS resolver task failed: {error}")))??
        } else {
            tokio::time::timeout(
                self.connect_timeout,
                tokio::net::lookup_host((server, port)),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS resolution timed out"))??
            .collect()
        };
        if addresses.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no address for {server}:{port}"),
            ))
        } else {
            Ok(addresses)
        }
    }

    pub async fn resolve_one(&self, server: &str, port: u16) -> io::Result<SocketAddr> {
        self.resolve(server, port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "empty DNS result"))
    }

    pub async fn resolve_server(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
    ) -> io::Result<SocketAddr> {
        self.resolve_server_addresses(server, port, server_ip)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "empty DNS result"))
    }

    pub async fn resolve_server_addresses(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
    ) -> io::Result<Vec<SocketAddr>> {
        match server_ip {
            Some(address) => Ok(vec![SocketAddr::new(address, port)]),
            None => self.resolve(server, port).await,
        }
    }

    /// Race authenticated candidates within one DNS and handshake budget.
    /// Returned values must release their connection on drop, including race losers.
    pub async fn connect_server_candidates<T, F, Fut>(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
        connect: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: Fn(SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<T>> + Send + 'static,
    {
        self.connect_server_candidates_with_budget(
            server,
            port,
            server_ip,
            self.handshake_timeout,
            connect,
        )
        .await
    }

    async fn connect_server_candidates_with_budget<T, F, Fut>(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
        total_budget: Duration,
        connect: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: Fn(SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<T>> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + total_budget;
        let stagger = CANDIDATE_STAGGER.min(total_budget / 2);
        let addresses = tokio::time::timeout_at(
            deadline,
            self.resolve_server_addresses(server, port, server_ip),
        )
        .await
        .map_err(|_| candidate_timeout())??;
        let mut addresses = interleaved_candidates(addresses);
        let connect = Arc::new(connect);
        let mut attempts = tokio::task::JoinSet::new();
        let mut next_launch = tokio::time::Instant::now();
        let mut last_error = None;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                attempts.shutdown().await;
                return Err(candidate_timeout());
            }
            if !addresses.is_empty()
                && attempts.len() < MAX_CONCURRENT_CANDIDATES
                && (attempts.is_empty() || now >= next_launch)
            {
                let address = addresses.pop_front().expect("candidate queue is nonempty");
                // Reserve time for later batches when both active addresses are silent.
                let batches =
                    (addresses.len() + attempts.len() + 1).div_ceil(MAX_CONCURRENT_CANDIDATES);
                let budget = deadline.saturating_duration_since(now)
                    / u32::try_from(batches).unwrap_or(u32::MAX);
                let attempt_deadline = now + budget;
                let connect = connect.clone();
                attempts.spawn(async move {
                    tokio::time::timeout_at(attempt_deadline, connect(address))
                        .await
                        .map_err(|_| candidate_timeout())?
                });
                next_launch = now + stagger;
            }
            if attempts.is_empty() {
                return Err(last_error.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "server has no address")
                }));
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    attempts.shutdown().await;
                    return Err(candidate_timeout());
                }
                _ = tokio::time::sleep_until(next_launch),
                    if !addresses.is_empty() && attempts.len() < MAX_CONCURRENT_CANDIDATES => {}
                joined = attempts.join_next() => {
                    match joined.expect("attempt set is nonempty") {
                        Ok(Ok(connection)) => {
                            attempts.shutdown().await;
                            return Ok(connection);
                        }
                        Ok(Err(error)) => last_error = Some(error),
                        Err(error) => {
                            last_error = Some(io::Error::other(format!(
                                "server connection task failed: {error}"
                            )));
                        }
                    }
                }
            }
        }
    }

    pub async fn connect_tcp(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let socket = if address.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        self.prepare(socket.as_raw_fd())?;
        let stream = tokio::time::timeout(self.connect_timeout, socket.connect(address))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect to {address} timed out"),
                )
            })??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub async fn connect_tcp_server(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
    ) -> io::Result<TcpStream> {
        let dialer = self.clone();
        self.connect_server_candidates_with_budget(
            server,
            port,
            server_ip,
            self.connect_timeout,
            move |address| {
                let dialer = dialer.clone();
                async move { dialer.connect_tcp(address).await }
            },
        )
        .await
    }

    pub fn bind_udp_std(&self, ipv6: bool) -> io::Result<std::net::UdpSocket> {
        let bind = if ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        self.prepare(socket.as_raw_fd())?;
        Ok(socket)
    }

    pub async fn connect_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let socket = self.bind_udp_std(address.is_ipv6())?;
        let socket = UdpSocket::from_std(socket)?;
        socket.connect(address).await?;
        Ok(socket)
    }

    pub async fn connect_udp_server(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
    ) -> io::Result<UdpSocket> {
        self.connect_udp_server_with_address(server, port, server_ip)
            .await
            .map(|(socket, _)| socket)
    }

    pub async fn connect_udp_server_with_address(
        &self,
        server: &str,
        port: u16,
        server_ip: Option<IpAddr>,
    ) -> io::Result<(UdpSocket, SocketAddr)> {
        let addresses = self
            .resolve_server_addresses(server, port, server_ip)
            .await?;
        let mut last_error = None;
        for address in addresses {
            match self.connect_udp(address).await {
                Ok(socket) => return Ok((socket, address)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "server has no address")))
    }

    fn prepare(&self, fd: RawFd) -> io::Result<()> {
        if let Some(protect) = &self.callbacks.protect
            && !protect(fd)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host refused to protect outbound socket",
            ));
        }
        if let Some(bind) = &self.callbacks.bind {
            let network_handle = self.network_handle();
            if network_handle == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Android Network handle is required before an outbound socket may be opened",
                ));
            }
            if !bind(fd, network_handle) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "host refused to bind outbound socket to Android Network",
                ));
            }
        }
        Ok(())
    }
}

fn candidate_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "server connection budget expired")
}

fn interleaved_candidates(addresses: Vec<SocketAddr>) -> std::collections::VecDeque<SocketAddr> {
    use std::collections::{HashSet, VecDeque};
    let first_is_ipv6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
    let mut seen = HashSet::new();
    let (mut first, mut second): (VecDeque<_>, VecDeque<_>) = addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .partition(|address| address.is_ipv6() == first_is_ipv6);
    let mut ordered = VecDeque::with_capacity(first.len() + second.len());
    while !first.is_empty() || !second.is_empty() {
        if let Some(address) = first.pop_front() {
            ordered.push_back(address);
        }
        if let Some(address) = second.pop_front() {
            ordered.push_back(address);
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    #[tokio::test]
    async fn candidate_races_reach_later_addresses_and_release_losers() {
        use std::sync::atomic::AtomicUsize;

        struct Lease(Arc<AtomicUsize>);
        impl Drop for Lease {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }

        let callbacks = SocketCallbacks::none().with_resolver(|_, _, _| {
            Ok(vec![
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
                "127.0.0.1:3".parse().unwrap(),
            ])
        });
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1))
            .with_handshake_timeout(Duration::from_secs(1));
        dialer.set_network_handle(1);
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let winner = dialer
            .connect_server_candidates("synthetic.example", 443, None, {
                let live = live.clone();
                let peak = peak.clone();
                move |address| {
                    let live = live.clone();
                    let peak = peak.clone();
                    async move {
                        let active = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(active, Ordering::SeqCst);
                        let lease = Lease(live);
                        if address.port() != 3 {
                            std::future::pending::<()>().await;
                        }
                        Ok(lease)
                    }
                }
            })
            .await
            .expect("silent first addresses must not consume every candidate's budget");
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert_eq!(
            live.load(Ordering::SeqCst),
            1,
            "race losers must already be dropped"
        );
        drop(winner);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scoped_dns_requires_an_android_network_before_callback_or_socket() {
        use std::sync::atomic::AtomicUsize;

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let protections = Arc::new(AtomicUsize::new(0));
        let protected_calls = protections.clone();
        let callbacks = SocketCallbacks::protect_only(move |_| {
            protected_calls.fetch_add(1, Ordering::SeqCst);
            true
        })
        .with_resolver(|_, _, _| panic!("scoped DNS must never use the system resolver"));
        let base = ProtectedDialer::new(callbacks, Duration::from_secs(1));
        let scoped_calls = Arc::new(AtomicUsize::new(0));
        let called = scoped_calls.clone();
        let underlying = base.clone();
        let scoped: ScopedResolver = Arc::new(move |host, port, network| {
            assert_eq!(host, "bootstrap.example");
            assert_eq!(network, 1);
            called.fetch_add(1, Ordering::SeqCst);
            let underlying = underlying.clone();
            Some(Box::pin(async move {
                let socket = underlying.connect_udp(address).await?;
                socket.send(b"owned-bootstrap-fixture").await?;
                Ok(vec![SocketAddr::from(([192, 0, 2, 7], port))])
            }))
        });
        let dialer = base.with_scoped_resolver(scoped);
        assert_eq!(
            dialer
                .resolve("bootstrap.example", 443)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(scoped_calls.load(Ordering::SeqCst), 0);
        assert_eq!(protections.load(Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.recv(&mut [0; 64]))
                .await
                .is_err()
        );
        assert_eq!(
            dialer.resolve("192.0.2.7", 443).await.unwrap(),
            vec![SocketAddr::from(([192, 0, 2, 7], 443))]
        );
        dialer.set_network_handle(1);
        assert_eq!(
            dialer.resolve("bootstrap.example", 443).await.unwrap(),
            vec![SocketAddr::from(([192, 0, 2, 7], 443))]
        );
        let mut packet = [0; 64];
        let length = tokio::time::timeout(Duration::from_millis(100), peer.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..length], b"owned-bootstrap-fixture");
        assert_eq!(scoped_calls.load(Ordering::SeqCst), 1);
        assert_eq!(protections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn candidate_races_share_one_deadline_with_dns() {
        let callbacks = SocketCallbacks::none().with_resolver(|_, _, _| {
            std::thread::sleep(Duration::from_millis(180));
            Ok(vec!["127.0.0.1:443".parse().unwrap()])
        });
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1))
            .with_handshake_timeout(Duration::from_millis(300));
        dialer.set_network_handle(1);
        let result = dialer
            .connect_server_candidates("synthetic.example", 443, None, |address| async move {
                tokio::time::sleep(Duration::from_millis(180)).await;
                Ok(address)
            })
            .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    use super::*;

    #[tokio::test]
    async fn callbacks_run_before_connect_and_include_network() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let protect_events = events.clone();
        let bind_events = events.clone();
        let callbacks = SocketCallbacks::new(
            move |_| {
                protect_events.lock().unwrap().push("protect".to_string());
                true
            },
            move |_, network| {
                bind_events.lock().unwrap().push(format!("bind:{network}"));
                true
            },
        );
        let dialer = ProtectedDialer::new(callbacks, Duration::from_millis(50));
        dialer.set_network_handle(42);
        let _ = dialer.connect_tcp("127.0.0.1:9".parse().unwrap()).await;
        assert_eq!(*events.lock().unwrap(), ["protect", "bind:42"]);
    }

    #[tokio::test]
    async fn literal_address_is_refused_while_no_network_is_selected() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let protect_events = events.clone();
        let bind_events = events.clone();
        let callbacks = SocketCallbacks::new(
            move |_| {
                protect_events.lock().unwrap().push("protect".to_string());
                true
            },
            move |_, network| {
                bind_events.lock().unwrap().push(format!("bind:{network}"));
                true
            },
        );
        let dialer = ProtectedDialer::new(callbacks, Duration::from_millis(50));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let error = dialer.connect_tcp(reachable).await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert!(
            !events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.starts_with("bind"))
        );

        assert!(dialer.bind_udp_std(false).is_err());
        dialer.set_network_handle(42);
        dialer.connect_tcp(reachable).await.unwrap();
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event == "bind:42")
        );
    }

    #[tokio::test]
    async fn a_host_without_a_bind_callback_still_dials_unbound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let dialer = ProtectedDialer::new(
            SocketCallbacks::protect_only(|_| true),
            Duration::from_millis(500),
        );

        dialer.connect_tcp(reachable).await.unwrap();
    }

    #[tokio::test]
    async fn platform_resolver_is_bound_and_fails_closed_without_network() {
        let callbacks = SocketCallbacks::none().with_resolver(|server, port, network| {
            assert_eq!(server, "edge.example");
            assert_eq!(port, 8443);
            assert_eq!(network, 77);
            Ok(vec!["203.0.113.7:8443".parse().unwrap()])
        });
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1));

        let error = dialer.resolve("edge.example", 8443).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);

        dialer.set_network_handle(77);
        assert_eq!(
            dialer.resolve_one("edge.example", 8443).await.unwrap(),
            "203.0.113.7:8443".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn host_resolver_owns_bootstrap_without_an_android_network() {
        let callbacks = SocketCallbacks::none().with_host_resolver(|host, port| {
            assert_eq!(host, "router.example");
            Ok(vec![SocketAddr::new("203.0.113.7".parse().unwrap(), port)])
        });
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1));
        assert_eq!(
            dialer.resolve_one("router.example", 443).await.unwrap(),
            "203.0.113.7:443".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn literal_server_never_invokes_dns_resolver() {
        let callbacks = SocketCallbacks::none()
            .with_resolver(|_, _, _| panic!("literal address must bypass DNS resolver"));
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1));
        assert_eq!(
            dialer.resolve_one("2001:db8::7", 443).await.unwrap(),
            "[2001:db8::7]:443".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn server_resolution_preserves_all_platform_candidates() {
        let callbacks = SocketCallbacks::none().with_resolver(|_, port, _| {
            Ok(vec![
                SocketAddr::new("2001:db8::7".parse().unwrap(), port),
                SocketAddr::new("203.0.113.7".parse().unwrap(), port),
            ])
        });
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1));
        dialer.set_network_handle(9);
        assert_eq!(
            dialer
                .resolve_server_addresses("edge.example", 443, None)
                .await
                .unwrap(),
            [
                "[2001:db8::7]:443".parse().unwrap(),
                "203.0.113.7:443".parse().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn tcp_server_falls_back_after_the_first_address_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let callbacks = SocketCallbacks::none()
            .with_resolver(move |_, _, _| Ok(vec!["[::1]:1".parse().unwrap(), reachable]));
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(2));
        dialer.set_network_handle(9);

        let connected = dialer
            .connect_tcp_server("edge.example", reachable.port(), None)
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        assert_eq!(connected.peer_addr().unwrap(), reachable);
        drop(accepted);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_server_reaches_a_second_address_while_the_first_syn_is_dropped() {
        let silent = TcpSocket::new_v4().unwrap();
        silent.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let silent = silent.listen(0).unwrap();
        let silent_address = silent.local_addr().unwrap();
        // A full Linux accept queue drops later SYNs without needing a firewall.
        let _filler = TcpStream::connect(silent_address).await.unwrap();
        let reachable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable_address = reachable.local_addr().unwrap();
        let callbacks = SocketCallbacks::none()
            .with_resolver(move |_, _, _| Ok(vec![silent_address, reachable_address]));
        let dialer = ProtectedDialer::new(callbacks, Duration::from_secs(1));
        dialer.set_network_handle(1);

        let stream = tokio::time::timeout(
            Duration::from_millis(600),
            dialer.connect_tcp_server("synthetic.example", reachable_address.port(), None),
        )
        .await
        .expect("one dropped SYN must not hide the reachable address")
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), reachable_address);
        reachable.accept().await.unwrap();
    }
}
