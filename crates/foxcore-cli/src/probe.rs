use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "connectivitycheck.gstatic.com";

async fn tunnel_tcp(
    interface: &str,
    address: SocketAddr,
) -> Result<tokio::net::TcpStream, &'static str> {
    let socket = if address.is_ipv6() {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    }
    .map_err(|_| "PROBE_SOCKET_FAILED")?;
    crate::linux::mark_socket(socket.as_raw_fd(), crate::args::PROOF_MARK)
        .map_err(|_| "PROBE_MARK_FAILED")?;
    crate::linux::bind_device(socket.as_raw_fd(), interface).map_err(|_| "PROBE_BIND_FAILED")?;
    tokio::time::timeout(Duration::from_secs(8), socket.connect(address))
        .await
        .map_err(|_| "PROBE_CONNECT_TIMEOUT")?
        .map_err(|_| "PROBE_CONNECT_FAILED")
}

async fn resolve(interface: &str) -> Result<Vec<IpAddr>, &'static str> {
    let mut transaction = [0; 2];
    getrandom::fill(&mut transaction).map_err(|_| "ENTROPY_UNAVAILABLE")?;
    let mut query = vec![transaction[0], transaction[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in HOST.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    // TCP DNS works for both packet tunnels and proxy protocols without a UDP relay.
    let mut socket =
        tunnel_tcp(interface, SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53))).await?;
    socket
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .map_err(|_| "PROBE_DNS_FAILED")?;
    socket
        .write_all(&query)
        .await
        .map_err(|_| "PROBE_DNS_FAILED")?;
    let size = socket.read_u16().await.map_err(|_| "PROBE_DNS_FAILED")? as usize;
    if !(12..=8192).contains(&size) {
        return Err("PROBE_DNS_INVALID");
    }
    let mut response = vec![0; size];
    socket
        .read_exact(&mut response)
        .await
        .map_err(|_| "PROBE_DNS_FAILED")?;
    let addresses =
        foxcore_dns::validated_response_addresses(&query, &response).ok_or("PROBE_DNS_INVALID")?;
    let addresses: Vec<_> = addresses
        .into_iter()
        .filter(public_address)
        .take(8)
        .collect();
    if addresses.is_empty() {
        Err("PROBE_DNS_EMPTY")
    } else {
        Ok(addresses)
    }
}

fn public_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_multicast()
                && ip.octets()[0] != 0
                && !(ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
                && ip.octets()[0] < 224
                && !(ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19))
                && !(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
                && !(ip.octets()[0] == 192 && ip.octets()[1] == 88 && ip.octets()[2] == 99)
        }
        // The proof asks for A records; mapped or synthesized IPv6 answers cannot redirect it.
        IpAddr::V6(_) => false,
    }
}

async fn https(interface: &str, address: IpAddr) -> Result<(), &'static str> {
    let socket = tunnel_tcp(interface, SocketAddr::new(address, 443)).await?;
    let tls = foxcore_api::TlsConfig {
        enabled: true,
        alpn: vec!["http/1.1".into()],
        ..Default::default()
    };
    let mut socket = foxcore_transport::wrap_tls(socket, &tls, HOST)
        .await
        .map_err(|_| "PROBE_TLS_FAILED")?;
    socket.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n").await.map_err(|_| "PROBE_HTTP_FAILED")?;
    let mut response = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let count = socket
            .read(&mut buffer)
            .await
            .map_err(|_| "PROBE_HTTP_FAILED")?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > 8192 {
            return Err("PROBE_HTTP_INVALID");
        }
        if response.windows(4).any(|v| v == b"\r\n\r\n") {
            break;
        }
    }
    if !response.windows(4).any(|v| v == b"\r\n\r\n") {
        return Err("PROBE_HTTP_INVALID");
    }
    let first = response
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or("PROBE_HTTP_INVALID")?;
    if first.starts_with(b"HTTP/1.1 204 ") || first.starts_with(b"HTTP/1.0 204 ") {
        Ok(())
    } else {
        Err("PROBE_HTTP_STATUS")
    }
}

pub(crate) async fn probe(state_path: &Path, interface: &str) -> Result<(), &'static str> {
    let owner = crate::status::read_recent(state_path)?;
    crate::status::require_owner(&owner, interface)?;
    let operation = async {
        let addresses = resolve(interface).await?;
        let mut last_error = "PROBE_CONNECT_FAILED";
        for address in addresses {
            match https(interface, address).await {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    };
    tokio::time::timeout(Duration::from_secs(40), operation)
        .await
        .map_err(|_| "PROBE_TIMEOUT")??;
    crate::status::require_owner(&owner, interface)?;
    let current = crate::status::read_recent(state_path)?;
    crate::status::require_owner(&current, interface)?;
    if (
        current.pid,
        current.process_start,
        current.generation,
        current.ifindex,
    ) != (
        owner.pid,
        owner.process_start,
        owner.generation,
        owner.ifindex,
    ) || current.phase != crate::status::Phase::Running
    {
        return Err("TUN_OWNER_MISMATCH");
    }
    println!(
        "{}",
        serde_json::json!({"validated":true,"generation":owner.generation,"generation_key":format!("{:016x}",owner.generation)})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_dns_cannot_target_private_local_or_documentation_addresses() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.2",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "2001::1",
            "2002:7f00:1::1",
            "3fff::1",
            "192.0.0.1",
            "192.88.99.1",
        ] {
            assert!(!public_address(&address.parse().unwrap()));
        }
        assert!(public_address(&"1.1.1.1".parse().unwrap()));
    }
}
