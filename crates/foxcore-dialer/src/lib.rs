#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

type SocketCallback = Arc<dyn Fn(RawFd) -> bool + Send + Sync>;
type BindCallback = Arc<dyn Fn(RawFd, u64) -> bool + Send + Sync>;
type ResolveCallback = Arc<dyn Fn(&str, u16, u64) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

#[derive(Clone, Default)]
pub struct SocketCallbacks {
    protect: Option<SocketCallback>,
    bind: Option<BindCallback>,
    resolve: Option<ResolveCallback>,
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
        }
    }

    pub fn protect_only(protect: impl Fn(RawFd) -> bool + Send + Sync + 'static) -> Self {
        Self {
            protect: Some(Arc::new(protect)),
            bind: None,
            resolve: None,
        }
    }

    pub fn with_resolver(
        mut self,
        resolve: impl Fn(&str, u16, u64) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.resolve = Some(Arc::new(resolve));
        self
    }
}

#[derive(Clone)]
pub struct ProtectedDialer {
    callbacks: SocketCallbacks,
    network_handle: Arc<AtomicU64>,
    connect_timeout: Duration,
}

impl fmt::Debug for ProtectedDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedDialer")
            .field("callbacks", &self.callbacks)
            .field("network_handle", &self.network_handle())
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl ProtectedDialer {
    pub fn new(callbacks: SocketCallbacks, connect_timeout: Duration) -> Self {
        Self {
            callbacks,
            network_handle: Arc::new(AtomicU64::new(0)),
            connect_timeout,
        }
    }

    pub fn host() -> Self {
        Self::new(SocketCallbacks::none(), Duration::from_secs(10))
    }

    pub fn set_network_handle(&self, network_handle: u64) {
        self.network_handle.store(network_handle, Ordering::Release);
    }

    pub fn network_handle(&self) -> u64 {
        self.network_handle.load(Ordering::Acquire)
    }

    pub async fn resolve(&self, server: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(address) = server.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, port)]);
        }
        let addresses = if let Some(resolve) = &self.callbacks.resolve {
            let network_handle = self.network_handle();
            if network_handle == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Android Network handle is required for protected DNS resolution",
                ));
            }
            let resolve = resolve.clone();
            let server = server.to_owned();
            // The deadline goes *inside* the closure, not only around it.
            //
            // This is D13's shape in a new place: `tokio::time::timeout`
            // cancels the future, and dropping a `spawn_blocking` join handle
            // neither cancels a running task nor removes a queued one — tokio
            // still runs it. The blocking pool is two threads, and platform DNS
            // retries run well past this timeout, so two abandoned lookups took
            // the whole pool and everything behind them (flow attribution, the
            // next resolution) queued and timed out in turn.
            //
            // A task that has not started yet can still be dropped for free,
            // which is the case worth catching; one already inside
            // `android_getaddrinfofornetwork` cannot be, and no API makes it so.
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
            // The platform path above is bounded, so this one is too. It is not
            // reachable from Android (a resolver is always installed there), but
            // an unbounded `lookup_host` on the host build is the same stall
            // with a different stack.
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
        let addresses = self
            .resolve_server_addresses(server, port, server_ip)
            .await?;
        let mut last_error = None;
        for address in addresses {
            match self.connect_tcp(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "server has no address")))
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
        let network_handle = self.network_handle();
        if network_handle != 0
            && let Some(bind) = &self.callbacks.bind
            && !bind(fd, network_handle)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "host refused to bind outbound socket to Android Network",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

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
}
