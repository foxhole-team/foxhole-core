use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use foxcore_api::{Destination, DnsUpstream};
use foxcore_transport::{BoxDatagramSession, BoxStream};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub(crate) const DNS_MESSAGE_TYPE: &str = "application/dns-message";
/// A DNS message is a 12-byte header and at least one question, so nothing
/// shorter than the header can be an answer to anything.
pub(crate) const MIN_DNS_MESSAGE_BYTES: usize = 12;

/// Whether a `Content-Type` header names the DNS wire format (RFC 8484 §4.1).
///
/// Two rules, both from RFC 9110 §8.3: the type is case-insensitive, and it may
/// carry parameters. So `Application/DNS-Message` is the same media type and
/// `application/dns-message; charset=utf-8` is too.
///
/// The previous test was `starts_with`, which is wrong in both directions. It
/// refused the spelling a server is entitled to use, and it accepted
/// `application/dns-message-not-really` — any body whose type merely begins with
/// the right characters was parsed as a DNS answer, which is the half of the
/// mistake that matters: an HTML error page from an intercepting proxy is not a
/// resolver's answer and must not be read as one.
pub(crate) fn is_dns_message_type(value: &str) -> bool {
    let media = value.split(';').next().unwrap_or_default();
    media.trim().eq_ignore_ascii_case(DNS_MESSAGE_TYPE)
}
pub(crate) const DNS_PORT: u16 = 53;
pub(crate) const DOH_PORT: u16 = 443;
pub(crate) const DNS_UPSTREAM_POOL_LANES: usize = 4;

pub(crate) enum UpstreamState {
    Empty,
    Udp(BoxDatagramSession),
    Stream(BoxStream),
    Doh(h2::client::SendRequest<Bytes>),
}

pub(crate) struct UpstreamPool {
    pub(super) lanes: Vec<Mutex<UpstreamState>>,
    /// Whether this upstream's "the outbound has no UDP" refusal has already
    /// been put in the audit stream for this policy generation.
    udp_refusal_reported: std::sync::atomic::AtomicBool,
}

impl UpstreamPool {
    pub(crate) fn new(upstream: &DnsUpstream) -> Self {
        // HTTP/2 already multiplexes requests after connection setup. UDP,
        // TCP and DoT need independent lanes so a lost response cannot hold
        // the only session mutex and stall every lookup behind it.
        let lane_count = if matches!(upstream, DnsUpstream::Doh { .. }) {
            1
        } else {
            DNS_UPSTREAM_POOL_LANES
        };
        Self {
            lanes: (0..lane_count)
                .map(|_| Mutex::new(UpstreamState::Empty))
                .collect(),
            udp_refusal_reported: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// True the first time only. The condition is static — this profile's
    /// outbound cannot carry datagrams — so one record per lookup would bury
    /// the journal under a fact that does not change.
    pub(crate) fn report_udp_refusal_once(&self) -> bool {
        !self
            .udp_refusal_reported
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn try_lock(&self) -> Option<tokio::sync::MutexGuard<'_, UpstreamState>> {
        self.lanes.iter().find_map(|lane| lane.try_lock().ok())
    }

    pub(crate) fn reset_idle(&self) {
        for lane in &self.lanes {
            if let Ok(mut state) = lane.try_lock() {
                *state = UpstreamState::Empty;
            }
        }
    }
}
/// Whether a received datagram came from the upstream the query went to.
///
/// Compared as addresses rather than as strings, so an IPv6 upstream written any
/// of the ways it can be written still matches the source the outbound reports.
///
/// An upstream configured by name is the one case this helper cannot decide:
/// the datagram carries the address the name resolved to, and re-resolving here
/// would be a second lookup with an answer of its own. Direct UDP sessions are
/// therefore connected to the one resolved address before a query is sent, so
/// the kernel applies the missing IP check before this function runs. Encrypted
/// proxy sessions authenticate their transport and may report either the name
/// or its resolved address; their source metadata remains port-checked here.
pub(crate) fn is_upstream_source(
    upstream: &Destination,
    source: &Destination,
    authenticated_peer: Option<&Destination>,
) -> bool {
    let expected = authenticated_peer.unwrap_or(upstream);
    if source.port != expected.port {
        return false;
    }
    match expected.ip() {
        Some(expected) => source.ip() == Some(expected),
        // Encapsulated transports authenticate the outer session, but may
        // report either the logical hostname or a proxy-resolved address in
        // each datagram. They retain the historical port check. Direct UDP
        // never reaches this arm: its connected socket supplies a numeric
        // `authenticated_peer` above.
        None => true,
    }
}

pub(crate) async fn exchange_length_prefixed(
    stream: &mut BoxStream,
    query: &[u8],
    max_response_bytes: usize,
) -> io::Result<Vec<u8>> {
    let length =
        u16::try_from(query.len()).map_err(|_| invalid("DNS query exceeds 65535 bytes"))?;
    stream.write_u16(length).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let response_length = usize::from(stream.read_u16().await?);
    if response_length < 12 || response_length > max_response_bytes {
        return Err(invalid("invalid DNS TCP response length"));
    }
    let mut response = vec![0_u8; response_length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

pub(crate) fn parse_endpoint(value: &str, default_port: u16) -> io::Result<Destination> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(Destination::new(address.ip().to_string(), address.port()));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
    {
        let port = port
            .parse()
            .map_err(|_| invalid("DNS upstream port is not valid"))?;
        return Ok(Destination::new(host, port));
    }
    if value.trim().is_empty() {
        Err(invalid("DNS upstream address is empty"))
    } else {
        Ok(Destination::new(value, default_port))
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
