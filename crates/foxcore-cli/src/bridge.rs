use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use zeroize::{Zeroize, Zeroizing};

const MAX_SESSIONS: usize = 64;
const MAX_UDP_TARGETS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    listen: SocketAddr,
    username: String,
    password: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

impl Credentials {
    fn read(path: &Path) -> Result<Self, &'static str> {
        let file = crate::config::private_file(path)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "BRIDGE_AUTH_UNREADABLE")?;
        if bytes.len() > 4096 {
            return Err("BRIDGE_AUTH_INVALID");
        }
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| "BRIDGE_AUTH_INVALID")?;
        if value.listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
            || value.listen.port() == 0
            || value.username == value.password
            || ![&value.username, &value.password]
                .iter()
                .all(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("BRIDGE_AUTH_INVALID");
        }
        Ok(value)
    }
}

struct Owner {
    path: PathBuf,
    status: crate::status::Status,
}

impl Owner {
    fn require(&self) -> Result<(), &'static str> {
        let current = crate::status::read_recent(&self.path)?;
        if (
            current.pid,
            current.process_start,
            current.generation,
            current.ifindex,
            current.tun_fd,
        ) != (
            self.status.pid,
            self.status.process_start,
            self.status.generation,
            self.status.ifindex,
            self.status.tun_fd,
        ) {
            return Err("TUN_OWNER_MISMATCH");
        }
        crate::status::require_owner(&current, &self.status.interface)
    }
}

fn same_secret(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && ip.octets()[0] > 0
                && ip.octets()[0] < 224
                && !(ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                && !(ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19))
                && !(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none()
                && (ip.segments()[0] & 0xe000) == 0x2000
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
        }
    }
}

fn protect(fd: i32, owner: &Owner) -> io::Result<()> {
    owner.require().map_err(|_| io::ErrorKind::NotConnected)?;
    crate::linux::mark_socket(fd, crate::args::TUNNEL_MARK)?;
    crate::linux::bind_device(fd, &owner.status.interface)
}

async fn tcp(owner: &Owner, target: SocketAddr) -> io::Result<TcpStream> {
    if target.port() == 0 || !allowed(target.ip()) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let socket = if target.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    protect(socket.as_raw_fd(), owner)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.connect(target))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Address {
    Ip(IpAddr),
    Host(String),
}

#[derive(Default)]
struct ResolutionCache(HashMap<(Address, u16), (SocketAddr, tokio::time::Instant)>);

impl ResolutionCache {
    fn get(
        &mut self,
        target: &Address,
        port: u16,
        now: tokio::time::Instant,
    ) -> Option<SocketAddr> {
        self.0.retain(|_, (_, stamp)| {
            now.saturating_duration_since(*stamp) < Duration::from_secs(30)
        });
        self.0
            .get(&(target.clone(), port))
            .map(|(address, _)| *address)
    }

    fn insert(
        &mut self,
        target: Address,
        port: u16,
        address: SocketAddr,
        now: tokio::time::Instant,
    ) {
        if self.0.len() < MAX_UDP_TARGETS {
            self.0.insert((target, port), (address, now));
        }
    }
}

fn address(bytes: &[u8]) -> io::Result<(Address, u16, usize)> {
    let (value, end) = match bytes.first().copied() {
        Some(1) if bytes.len() >= 7 => (
            Address::Ip(IpAddr::V4(Ipv4Addr::new(
                bytes[1], bytes[2], bytes[3], bytes[4],
            ))),
            5,
        ),
        Some(4) if bytes.len() >= 19 => {
            let octets: [u8; 16] = bytes[1..17]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?;
            (Address::Ip(IpAddr::V6(octets.into())), 17)
        }
        Some(3) if bytes.len() >= 2 => {
            let end = 2 + usize::from(bytes[1]);
            if bytes.len() < end + 2 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let host = std::str::from_utf8(&bytes[2..end])
                .map_err(|_| io::ErrorKind::InvalidData)?
                .to_owned();
            crate::bootstrap::query(&host, 1)?;
            (Address::Host(host), end)
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let port = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
    Ok((value, port, end + 2))
}

async fn read_address(socket: &mut TcpStream) -> io::Result<(Address, u16)> {
    let kind = socket.read_u8().await?;
    let mut bytes = vec![kind];
    let count = match kind {
        1 => 6,
        4 => 18,
        3 => {
            let length = socket.read_u8().await?;
            bytes.push(length);
            usize::from(length) + 2
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let start = bytes.len();
    bytes.resize(start + count, 0);
    socket.read_exact(&mut bytes[start..]).await?;
    let (address, port, _) = address(&bytes)?;
    Ok((address, port))
}

async fn resolve(owner: &Owner, address: Address, port: u16) -> io::Result<SocketAddr> {
    if port == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let ip = match address {
        Address::Ip(ip) => ip,
        Address::Host(host) => {
            let query = crate::bootstrap::query(&host, 1)?;
            let mut socket = tcp(
                owner,
                "1.1.1.1:53"
                    .parse()
                    .map_err(|_| io::ErrorKind::InvalidInput)?,
            )
            .await?;
            socket
                .write_all(&(query.len() as u16).to_be_bytes())
                .await?;
            socket.write_all(&query).await?;
            let size = socket.read_u16().await? as usize;
            if !(12..=8192).contains(&size) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut response = vec![0; size];
            socket.read_exact(&mut response).await?;
            foxcore_dns::validated_response_addresses(&query, &response)
                .ok_or(io::ErrorKind::InvalidData)?
                .into_iter()
                .find(|ip| allowed(*ip))
                .ok_or(io::ErrorKind::NotFound)?
        }
    };
    if !allowed(ip) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(SocketAddr::new(ip, port))
}

async fn handshake(
    socket: &mut TcpStream,
    credentials: &Credentials,
) -> io::Result<(u8, Address, u16)> {
    if socket.read_u8().await? != 5 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let count = socket.read_u8().await? as usize;
    if count == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut methods = vec![0; count];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        socket.write_all(&[5, 255]).await?;
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    socket.write_all(&[5, 2]).await?;
    if socket.read_u8().await? != 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut username = Zeroizing::new(vec![0; socket.read_u8().await? as usize]);
    socket.read_exact(&mut username).await?;
    let mut password = Zeroizing::new(vec![0; socket.read_u8().await? as usize]);
    socket.read_exact(&mut password).await?;
    if !(same_secret(credentials.username.as_bytes(), &username)
        & same_secret(credentials.password.as_bytes(), &password))
    {
        socket.write_all(&[1, 1]).await?;
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    socket.write_all(&[1, 0]).await?;
    let mut request = [0; 3];
    socket.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 || !matches!(request[1], 1 | 3) {
        socket.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(io::ErrorKind::InvalidData.into());
    }
    let (address, port) = read_address(socket).await?;
    Ok((request[1], address, port))
}

fn encoded_address(target: SocketAddr) -> Vec<u8> {
    let mut result = Vec::with_capacity(19);
    match target.ip() {
        IpAddr::V4(ip) => {
            result.push(1);
            result.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            result.push(4);
            result.extend_from_slice(&ip.octets());
        }
    }
    result.extend_from_slice(&target.port().to_be_bytes());
    result
}

async fn reply(socket: &mut TcpStream, target: SocketAddr) -> io::Result<()> {
    let mut result = vec![5, 0, 0];
    result.extend_from_slice(&encoded_address(target));
    socket.write_all(&result).await
}

fn udp_request(bytes: &[u8]) -> io::Result<(Address, u16, &[u8])> {
    if bytes.len() < 4 || bytes[..3] != [0, 0, 0] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let (target, port, count) = address(&bytes[3..])?;
    if port == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((target, port, &bytes[3 + count..]))
}

async fn udp(
    mut control: TcpStream,
    owner: &Owner,
    expected: Address,
    port: u16,
) -> io::Result<()> {
    let peer = control.peer_addr()?;
    match expected {
        Address::Ip(ip) if ip.is_unspecified() || ip == peer.ip() => {}
        _ => return Err(io::ErrorKind::PermissionDenied.into()),
    }
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    reply(&mut control, relay.local_addr()?).await?;
    let outbound = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    protect(outbound.as_raw_fd(), owner)?;
    let mut outbound6: Option<UdpSocket> = None;
    let mut client = (port != 0).then(|| SocketAddr::new(peer.ip(), port));
    let mut targets = HashSet::new();
    let mut resolutions = ResolutionCache::default();
    let mut request = vec![0; 65535];
    let mut response = vec![0; 65535];
    let mut response6 = vec![0; 65535];
    let mut control_byte = [0; 1];
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = control.read(&mut control_byte) => return Ok(()),
            _ = &mut idle => return Ok(()),
            packet = relay.recv_from(&mut request) => {
                let (count, source) = packet?;
                if source.ip() != peer.ip() || client.is_some_and(|known| source != known) { continue; }
                owner.require().map_err(|_| io::ErrorKind::NotConnected)?;
                let Ok((address, port, payload)) = udp_request(&request[..count]) else { continue; };
                let target = match resolutions.get(&address, port, tokio::time::Instant::now()) {
                    Some(target) => target,
                    None => {
                        let target = tokio::time::timeout(HANDSHAKE_TIMEOUT, resolve(owner, address.clone(), port)).await
                            .map_err(|_| io::ErrorKind::TimedOut)??;
                        resolutions.insert(address, port, target, tokio::time::Instant::now());
                        target
                    }
                };
                if targets.len() >= MAX_UDP_TARGETS && !targets.contains(&target) { continue; }
                client.get_or_insert(source);
                targets.insert(target);
                owner.require().map_err(|_| io::ErrorKind::NotConnected)?;
                if target.is_ipv6() {
                    if outbound6.is_none() {
                        let Ok(socket) = UdpSocket::bind("[::]:0").await else { continue; };
                        protect(socket.as_raw_fd(), owner)?;
                        outbound6 = Some(socket);
                    }
                    outbound6.as_ref().ok_or(io::ErrorKind::NotConnected)?.send_to(payload, target).await?;
                }
                else { outbound.send_to(payload, target).await?; }
                idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
            },
            packet = outbound.recv_from(&mut response) => {
                let (count, source) = packet?;
                if count > 65507 - 22 || !targets.contains(&source) { continue; }
                owner.require().map_err(|_| io::ErrorKind::NotConnected)?;
                if let Some(client) = client {
                    let mut packet = vec![0, 0, 0];
                    packet.extend_from_slice(&encoded_address(source));
                    packet.extend_from_slice(&response[..count]);
                    relay.send_to(&packet, client).await?;
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                }
            },
            packet = async {
                match outbound6.as_ref() {
                    Some(socket) => socket.recv_from(&mut response6).await,
                    None => std::future::pending().await,
                }
            } => {
                let (count, source) = packet?;
                if count > 65507 - 22 || !targets.contains(&source) { continue; }
                owner.require().map_err(|_| io::ErrorKind::NotConnected)?;
                if let Some(client) = client {
                    let mut packet = vec![0, 0, 0];
                    packet.extend_from_slice(&encoded_address(source));
                    packet.extend_from_slice(&response6[..count]);
                    relay.send_to(&packet, client).await?;
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                }
            },
        }
    }
}

async fn session(
    mut socket: TcpStream,
    credentials: Arc<Credentials>,
    owner: Arc<Owner>,
) -> io::Result<()> {
    let (command, address, port) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut socket, &credentials))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
    owner.require().map_err(|_| io::ErrorKind::NotConnected)?;
    if command == 3 {
        return udp(socket, &owner, address, port).await;
    }
    let target = tokio::time::timeout(HANDSHAKE_TIMEOUT, resolve(&owner, address, port))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let mut remote = tcp(&owner, target).await?;
    reply(&mut socket, remote.local_addr()?).await?;
    tokio::time::timeout(
        Duration::from_secs(3600),
        tokio::io::copy_bidirectional(&mut socket, &mut remote),
    )
    .await
    .map_err(|_| io::ErrorKind::TimedOut)??;
    Ok(())
}

pub(crate) async fn serve(state: &Path, auth: &Path, interface: &str) -> Result<(), &'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    let status = crate::status::read_recent(state)?;
    crate::status::require_owner(&status, interface)?;
    let credentials = Arc::new(Credentials::read(auth)?);
    let owner = Arc::new(Owner {
        path: state.to_owned(),
        status,
    });
    let listener = TcpListener::bind(credentials.listen)
        .await
        .map_err(|_| "BRIDGE_LISTEN_FAILED")?;
    let mut tasks = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "SIGNAL_UNAVAILABLE")?;
    let result = loop {
        tokio::select! {
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = tick.tick() => { if let Err(code) = owner.require() { break Err(code); } },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept(), if tasks.len() < MAX_SESSIONS => {
                let (socket, peer) = accepted.map_err(|_| "BRIDGE_ACCEPT_FAILED")?;
                if !peer.ip().is_loopback() { continue; }
                let credentials = credentials.clone();
                let owner = owner.clone();
                tasks.spawn(session(socket, credentials, owner));
            },
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn credentials_require_private_loopback_and_independent_full_length_secrets() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("auth.json");
        let mut value = serde_json::json!({"listen":"127.0.0.1:17891","username":"a".repeat(64),"password":"b".repeat(64)});
        let put = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        put(&value);
        assert!(Credentials::read(&path).is_ok());
        for listen in [
            "0.0.0.0:17891",
            "192.168.1.1:17891",
            "127.0.0.1:0",
            "[::1]:17891",
        ] {
            value["listen"] = listen.into();
            put(&value);
            assert!(Credentials::read(&path).is_err());
        }
        value["listen"] = "127.0.0.1:17891".into();
        value["password"] = "1234".into();
        put(&value);
        assert!(Credentials::read(&path).is_err());
    }

    #[test]
    fn udp_refuses_fragmentation_truncated_addresses_and_zero_ports() {
        assert!(udp_request(&[0, 0, 1, 1, 1, 1, 1, 1, 0, 53, 1]).is_err());
        assert!(udp_request(&[0, 0, 0, 1, 1, 1]).is_err());
        assert!(udp_request(&[0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1]).is_err());
        assert_eq!(
            udp_request(&[0, 0, 0, 1, 1, 1, 1, 1, 0, 53, 9]).unwrap(),
            (Address::Ip("1.1.1.1".parse().unwrap()), 53, &[9][..])
        );
        assert!(address(&[3, 1, b'\n', 0, 53]).is_err());
        assert_eq!(
            udp_request(&[0, 0, 0, 1, 1, 1, 1, 1, 0, 53]).unwrap().2,
            &[] as &[u8]
        );
    }

    #[test]
    fn udp_resolution_cache_is_bounded_and_cannot_return_an_expired_address() {
        let mut cache = ResolutionCache::default();
        let now = tokio::time::Instant::now();
        let first = Address::Host("first.example".into());
        let target = "1.1.1.1:443".parse().unwrap();
        cache.insert(first.clone(), 443, target, now);
        assert_eq!(
            cache.get(&first, 443, now + Duration::from_secs(29)),
            Some(target)
        );
        assert_eq!(cache.get(&first, 443, now + Duration::from_secs(30)), None);
        for index in 0..MAX_UDP_TARGETS + 10 {
            cache.insert(
                Address::Host(format!("node{index}.example")),
                443,
                target,
                now,
            );
        }
        assert_eq!(cache.0.len(), MAX_UDP_TARGETS);
        assert_eq!(cache.get(&first, 443, now), None);
    }

    #[test]
    fn router_and_local_targets_cannot_be_reached_through_the_bridge() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.1.1",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
            "2001:db8::1",
        ] {
            assert!(!allowed(ip.parse().unwrap()));
        }
        for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
            assert!(allowed(ip.parse().unwrap()));
        }
        assert!(same_secret(b"synthetic", b"synthetic"));
        assert!(!same_secret(b"synthetic", b"synthetiC"));
    }

    #[tokio::test]
    async fn anonymous_socks_clients_are_rejected_before_a_target_is_read() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let credentials = Credentials {
            listen: listener.local_addr().unwrap(),
            username: "a".repeat(64),
            password: "b".repeat(64),
        };
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            assert!(handshake(&mut socket, &credentials).await.is_err());
        });
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 255]);
        task.await.unwrap();
    }
}
