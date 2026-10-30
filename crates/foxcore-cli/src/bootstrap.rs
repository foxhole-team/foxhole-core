use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) fn query(host: &str, kind: u16) -> io::Result<Vec<u8>> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut transaction = [0; 2];
    getrandom::fill(&mut transaction).map_err(|_| io::ErrorKind::Other)?;
    let mut query = vec![transaction[0], transaction[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'-')
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&[0, 1]);
    Ok(query)
}

async fn exchange(host: &str, kind: u16, server: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let query = query(host, kind)?;
    let socket = if server.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    crate::linux::mark_socket(socket.as_raw_fd(), crate::args::UPSTREAM_MARK)?;
    let mut socket = socket.connect(server).await?;
    socket
        .write_all(&(query.len() as u16).to_be_bytes())
        .await?;
    socket.write_all(&query).await?;
    let size = socket.read_u16().await? as usize;
    if !(12..=8192).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut answer = vec![0; size];
    socket.read_exact(&mut answer).await?;
    let addresses = foxcore_dns::validated_response_addresses(&query, &answer)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(addresses
        .into_iter()
        .filter(|v| match (kind, v) {
            (1, IpAddr::V4(ip)) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
            (28, IpAddr::V6(ip)) => {
                !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
            }
            _ => false,
        })
        .take(8)
        .collect())
}

pub(crate) fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| io::ErrorKind::NotConnected)?;
    // ProtectedDialer invokes this only on its bounded blocking pool, never on an async worker.
    handle.block_on(async {
        let servers = ["1.1.1.1:53", "[2606:4700:4700::1111]:53"].map(|server| {
            server
                .parse::<SocketAddr>()
                .expect("literal bootstrap resolver")
        });
        let addresses = crate::bootstrap_budget::collect_addresses(|server, kind| {
            exchange(host, kind, servers[server])
        })
        .await?;
        Ok(addresses
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_bootstrap_names_are_refused_before_network_io() {
        for name in [
            "",
            "edge..example",
            "-option;exec",
            "edge\nexample",
            "ä.example",
        ] {
            assert!(query(name, 1).is_err());
        }
        let request = query("edge.example.", 1).unwrap();
        assert_eq!(
            &request[2..],
            b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04edge\x07example\x00\x00\x01\x00\x01"
        );
    }
}
