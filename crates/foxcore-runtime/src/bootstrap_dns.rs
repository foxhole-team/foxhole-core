use bytes::Bytes;
use foxcore_api::{BootstrapDnsConfig, DnsUpstream, TlsConfig, canonical_bootstrap_domain};
use foxcore_dialer::{ProtectedDialer, ScopedResolver};
use foxcore_dns::{
    http_query, response_domain_chain, restore_transaction_id, validated_response_addresses,
};
use foxcore_transport::dns_quic::{DnsQuicConnection, DnsQuicProtocol, connect_dns_quic_socket};
use foxcore_transport::{BoxStream, wrap_tls};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const MAX_RESPONSE: usize = 16 * 1024;

struct CachedQuic {
    network: u64,
    revision: u64,
    client: Arc<DnsQuicConnection>,
}
type QuicPool = Mutex<Option<CachedQuic>>;

pub(crate) fn install(dialer: ProtectedDialer, config: &BootstrapDnsConfig) -> ProtectedDialer {
    let config = Arc::new(config.clone());
    let protected = dialer.clone();
    let capacity = Arc::new(tokio::sync::Semaphore::new(4));
    let quic: Arc<Vec<QuicPool>> =
        Arc::new(config.upstreams.iter().map(|_| Mutex::new(None)).collect());
    let resolver: ScopedResolver = Arc::new(move |host, port, network| {
        if !config.matches(host) {
            return None;
        }
        let host = canonical_bootstrap_domain(host).expect("matched domain is valid");
        let config = config.clone();
        let protected = protected.clone();
        let capacity = capacity.clone();
        let quic = quic.clone();
        Some(Box::pin(async move {
            let _permit = capacity.try_acquire_owned().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "bootstrap DNS concurrency limit reached",
                )
            })?;
            resolve(&protected, &config, &quic, &host, port, network).await
        }))
    });
    dialer.with_scoped_resolver(resolver)
}

async fn resolve(
    dialer: &ProtectedDialer,
    config: &BootstrapDnsConfig,
    quic: &[QuicPool],
    host: &str,
    port: u16,
    network: u64,
) -> io::Result<Vec<SocketAddr>> {
    let revision = dialer.network_revision();
    ensure_network(dialer, network, revision)?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(config.timeout_ms);
    let mut last_error = invalid("bootstrap DNS did not return an address");
    for (index, upstream) in config.upstreams.iter().enumerate() {
        let mut addresses = Vec::new();
        for (family, kind) in [1u16, 28].into_iter().enumerate() {
            let query = query(host, kind)?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                last_error = io::Error::new(io::ErrorKind::TimedOut, "bootstrap DNS timed out");
                break;
            }
            let exchanges = (config.upstreams.len() - index) * 2 - family;
            let budget = remaining / u32::try_from(exchanges).unwrap_or(u32::MAX);
            let result = tokio::time::timeout(
                budget,
                exchange(dialer, upstream, &query, &quic[index], network, revision),
            )
            .await;
            ensure_network(dialer, network, revision)?;
            match result {
                Ok(Ok(response)) => match validated_response_addresses(&query, &response) {
                    Some(found) => {
                        for ip in found {
                            let canonical = ip.to_canonical();
                            if canonical.is_unspecified()
                                || canonical.is_multicast()
                                || matches!(canonical, std::net::IpAddr::V4(address) if address.is_broadcast())
                            {
                                return Err(invalid("bootstrap DNS returned an unusable address"));
                            }
                            let address = SocketAddr::new(ip, port);
                            if addresses.len() < config.max_candidates
                                && !addresses.contains(&address)
                            {
                                addresses.push(address);
                            }
                        }
                    }
                    None => last_error = invalid("bootstrap DNS response did not match the query"),
                },
                Ok(Err(error)) => last_error = error,
                Err(_) => {
                    last_error = io::Error::new(io::ErrorKind::TimedOut, "bootstrap DNS timed out")
                }
            }
        }
        if !addresses.is_empty() {
            return Ok(addresses);
        }
    }
    Err(last_error)
}

fn ensure_network(dialer: &ProtectedDialer, network: u64, revision: u64) -> io::Result<()> {
    if dialer.network_handle() != network || dialer.network_revision() != revision {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "bootstrap DNS network changed",
        ));
    }
    Ok(())
}

fn query(host: &str, kind: u16) -> io::Result<Vec<u8>> {
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).map_err(|_| io::Error::other("bootstrap DNS query ID unavailable"))?;
    let mut packet = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        packet.push(u8::try_from(label.len()).map_err(|_| invalid("invalid bootstrap DNS name"))?);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

async fn exchange(
    dialer: &ProtectedDialer,
    upstream: &DnsUpstream,
    query: &[u8],
    quic: &QuicPool,
    network: u64,
    revision: u64,
) -> io::Result<Vec<u8>> {
    match upstream {
        DnsUpstream::Udp { address } => {
            let address = address
                .parse::<SocketAddr>()
                .map_err(|_| invalid("invalid bootstrap DNS IP"))?;
            let socket = dialer.connect_udp(address).await?;
            socket.send(query).await?;
            let mut response = vec![0; MAX_RESPONSE + 1];
            let length = socket.recv(&mut response).await?;
            if !(12..=MAX_RESPONSE).contains(&length) {
                return Err(invalid("bootstrap DNS response size is invalid"));
            }
            response.truncate(length);
            if response[2] & 2 != 0 {
                if response[3] & 15 != 0 || response_domain_chain(query, &response).is_none() {
                    return Err(invalid("bootstrap DNS truncation did not match the query"));
                }
                return length_prefixed(Box::new(dialer.connect_tcp(address).await?), query).await;
            }
            Ok(response)
        }
        DnsUpstream::Tcp { address } => {
            let address = address
                .parse::<SocketAddr>()
                .map_err(|_| invalid("invalid bootstrap DNS IP"))?;
            length_prefixed(Box::new(dialer.connect_tcp(address).await?), query).await
        }
        DnsUpstream::Doq {
            host,
            port,
            server_ip,
            insecure,
            pinned_spki_sha256,
        } => {
            if *insecure {
                return Err(invalid("insecure bootstrap DNS is refused"));
            }
            let peer = SocketAddr::new(
                server_ip.ok_or_else(|| invalid("bootstrap DNS requires server_ip"))?,
                *port,
            );
            let tls = TlsConfig {
                enabled: true,
                server_name: Some(host.clone()),
                pinned_spki_sha256: pinned_spki_sha256.clone(),
                ..Default::default()
            };
            quic_exchange(
                dialer,
                quic,
                network,
                revision,
                peer,
                &tls,
                host,
                DnsQuicProtocol::Doq,
                None,
                query,
            )
            .await
        }
        DnsUpstream::Doh3 {
            url,
            server_ip,
            insecure,
            pinned_spki_sha256,
        } => {
            if *insecure {
                return Err(invalid("insecure bootstrap DNS is refused"));
            }
            let parsed =
                url::Url::parse(url.expose()).map_err(|_| invalid("invalid bootstrap DoH3 URL"))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| invalid("bootstrap DoH3 has no host"))?
                .trim_matches(['[', ']']);
            let peer = SocketAddr::new(
                server_ip.ok_or_else(|| invalid("bootstrap DNS requires server_ip"))?,
                parsed.port_or_known_default().unwrap_or(443),
            );
            let tls = TlsConfig {
                enabled: true,
                server_name: Some(host.to_owned()),
                pinned_spki_sha256: pinned_spki_sha256.clone(),
                ..Default::default()
            };
            quic_exchange(
                dialer,
                quic,
                network,
                revision,
                peer,
                &tls,
                host,
                DnsQuicProtocol::Doh3,
                Some(parsed.as_str()),
                query,
            )
            .await
        }
        DnsUpstream::Dot {
            host,
            port,
            server_ip,
            insecure,
            pinned_spki_sha256,
        } => {
            if *insecure {
                return Err(invalid("insecure bootstrap DNS is refused"));
            }
            let address = SocketAddr::new(
                server_ip.ok_or_else(|| invalid("bootstrap DNS requires server_ip"))?,
                *port,
            );
            let tls = TlsConfig {
                enabled: true,
                server_name: Some(host.clone()),
                pinned_spki_sha256: pinned_spki_sha256.clone(),
                alpn: vec!["dot".into()],
                ..Default::default()
            };
            let stream = wrap_tls(dialer.connect_tcp(address).await?, &tls, host).await?;
            length_prefixed(stream, query).await
        }
        DnsUpstream::Doh {
            url,
            server_ip,
            insecure,
            pinned_spki_sha256,
        } => {
            if *insecure {
                return Err(invalid("insecure bootstrap DNS is refused"));
            }
            let parsed =
                url::Url::parse(url.expose()).map_err(|_| invalid("invalid bootstrap DoH URL"))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| invalid("bootstrap DoH requires a host"))?
                .trim_matches(['[', ']']);
            let address = SocketAddr::new(
                server_ip.ok_or_else(|| invalid("bootstrap DNS requires server_ip"))?,
                parsed.port_or_known_default().unwrap_or(443),
            );
            let tls = TlsConfig {
                enabled: true,
                server_name: Some(host.to_owned()),
                pinned_spki_sha256: pinned_spki_sha256.clone(),
                alpn: vec!["h2".into()],
                ..Default::default()
            };
            let stream = wrap_tls(dialer.connect_tcp(address).await?, &tls, host).await?;
            doh(stream, url.expose(), query).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn quic_exchange(
    dialer: &ProtectedDialer,
    pool: &QuicPool,
    network: u64,
    revision: u64,
    peer: SocketAddr,
    tls: &TlsConfig,
    host: &str,
    protocol: DnsQuicProtocol,
    endpoint: Option<&str>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    ensure_network(dialer, network, revision)?;
    let mut state = pool.lock().await;
    let existing = state.as_ref().filter(|entry| {
        entry.network == network && entry.revision == revision && !entry.client.is_closed()
    });
    let client = if let Some(entry) = existing {
        entry.client.clone()
    } else {
        *state = None;
        let socket = dialer.bind_udp_std(peer.is_ipv6())?;
        ensure_network(dialer, network, revision)?;
        let client = Arc::new(connect_dns_quic_socket(socket, peer, tls, host, protocol).await?);
        ensure_network(dialer, network, revision)?;
        *state = Some(CachedQuic {
            network,
            revision,
            client: client.clone(),
        });
        client
    };
    drop(state);
    let result = match endpoint {
        Some(endpoint) => client.exchange_doh3(endpoint, query, MAX_RESPONSE).await,
        None => client.exchange_doq(query, MAX_RESPONSE).await,
    };
    if client.is_closed()
        && let Ok(mut state) = pool.try_lock()
        && state
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(&entry.client, &client))
    {
        *state = None;
    }
    result
}

async fn length_prefixed(mut stream: BoxStream, query: &[u8]) -> io::Result<Vec<u8>> {
    stream
        .write_u16(u16::try_from(query.len()).map_err(|_| invalid("bootstrap query is too large"))?)
        .await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let length = usize::from(stream.read_u16().await?);
    if !(12..=MAX_RESPONSE).contains(&length) {
        return Err(invalid("bootstrap DNS response size is invalid"));
    }
    let mut response = vec![0; length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

struct AbortConnection(tokio::task::JoinHandle<()>);
impl Drop for AbortConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn doh(stream: BoxStream, endpoint: &str, query: &[u8]) -> io::Result<Vec<u8>> {
    let (id, wire_query) =
        http_query(query).ok_or_else(|| invalid("invalid bootstrap DNS query"))?;
    let (sender, connection) = h2::client::Builder::new()
        .max_header_list_size(16 * 1024)
        .handshake(stream)
        .await
        .map_err(|_| invalid("bootstrap DoH handshake failed"))?;
    let _connection = AbortConnection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(endpoint)
        .header(ACCEPT, "application/dns-message")
        .header(CONTENT_TYPE, "application/dns-message")
        .header(CONTENT_LENGTH, wire_query.len())
        .body(())
        .map_err(|_| invalid("invalid bootstrap DoH request"))?;
    let mut sender = sender
        .ready()
        .await
        .map_err(|_| invalid("bootstrap DoH sender failed"))?;
    let (response, mut body) = sender
        .send_request(request, false)
        .map_err(|_| invalid("bootstrap DoH request failed"))?;
    body.send_data(Bytes::from(wire_query), true)
        .map_err(|_| invalid("bootstrap DoH body failed"))?;
    let response = response
        .await
        .map_err(|_| invalid("bootstrap DoH response failed"))?;
    if response.status() != http::StatusCode::OK
        || !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("application/dns-message")
            })
    {
        return Err(invalid("bootstrap DoH response is not DNS wire format"));
    }
    let mut body = response.into_body();
    let mut response = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| invalid("bootstrap DoH response body failed"))?;
        if response.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            return Err(invalid("bootstrap DoH response is too large"));
        }
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| invalid("bootstrap DoH flow control failed"))?;
        response.extend_from_slice(&chunk);
    }
    if response.first_chunk::<2>() != Some(&[0, 0]) || !restore_transaction_id(&mut response, id) {
        return Err(invalid("bootstrap DoH transaction ID is invalid"));
    }
    Ok(response)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
