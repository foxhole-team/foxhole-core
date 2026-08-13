#![forbid(unsafe_code)]
// `run()` awaits every protocol in the product one after another, so its async
// state machine carries the layout of all of them at once. rustc's default
// query depth is 128 and this body needs 130 — it tipped over when two enum
// variants were added upstream, and only in `--test` mode, which is why
// `cargo build` was still fine while `cargo test --workspace` would not compile.
// Raising the limit is what the compiler itself suggests; the alternative is
// boxing each probe future, which would change what the harness measures.
#![recursion_limit = "256"]

//! Live outbound probe: does this profile actually carry traffic?
//!
//! The probe takes one *profile source* on stdin and a list of closed protocol
//! selectors on argv. Nothing about the profile — endpoint, UUID, password, SNI,
//! path, obfuscation secret — is ever printed or written to disk. Everything
//! this binary emits is a fixed stage label plus byte counters, so its output is
//! safe to paste into a report.
//!
//! Two source shapes, distinguished by the first non-space byte:
//!
//! * a subscription/link body (`vless://…`, one per line) — the shape a real
//!   subscription has;
//! * a JSON object mapping selector to [`OutboundConfig`] — the shape used for
//!   locally hosted servers (`tuic`, `shadowtls`, `anytls`, `socks`, `http`),
//!   which no subscription hands out and, for TUIC and ShadowTLS, no share-link
//!   scheme can express at all.
//!
//! Both arrive on stdin rather than argv precisely because they are credentials.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read};
use std::net::Ipv4Addr;
use std::time::Duration;

use foxcore_api::{Destination, FlowContext, IpTransport, OutboundConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_link::{ProfileScheme, import_first_profile_by_scheme};
use foxcore_outbound::Outbound;
use foxcore_transport::Datagram;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_INPUT_BYTES: u64 = 1024 * 1024 + 1;
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Enough of a response to prove bytes came back without buffering a page.
const MAX_RESPONSE_BYTES: usize = 32 * 1024;
const UDP_TIMEOUT: Duration = Duration::from_secs(6);
/// Fixed so a reply can be matched to its query. Not a secret and not random:
/// this socket carries exactly one exchange.
const DNS_QUERY_ID: u16 = 0x4658;
/// Fixed so the SYN-ACK can be matched to this probe and not to whatever else
/// the peer is carrying.
const TCP_PROBE_PORT: u16 = 40_001;
const TCP_PROBE_SEQ: u32 = 0x4658_0001;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A multi-thread runtime: the WireGuard relay runs as its own task and must
    // keep ticking while the probe task waits on a reply. On a current-thread
    // runtime both still make progress, but a blocking-looking stall in one
    // would be indistinguishable from a dead peer.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let selectors: Vec<String> = env::args().skip(1).collect();
    if selectors.is_empty() {
        return Err("missing protocol selector".into());
    }

    let mut body = String::new();
    io::stdin()
        .take(MAX_INPUT_BYTES)
        .read_to_string(&mut body)?;
    if body.len() >= MAX_INPUT_BYTES as usize {
        return Err("profile source exceeds 1 MiB".into());
    }
    let source = ProfileSource::parse(&body)?;
    // UDP is opt-in: several protocols in the queue are TCP-only by design, and
    // a probe that always tried it would report a designed refusal as a failure.
    let probe_udp = env::var_os("FOXCORE_PROBE_UDP").is_some();

    // Every selector is attempted even after one fails. A twelve-protocol run
    // that stops at the first failure hides eleven results, and re-running costs
    // another set of live handshakes.
    let mut failures = 0_usize;
    for selector in &selectors {
        match probe_selector(&source, selector, probe_udp).await {
            Ok(report) => println!("outbound_smoke_ok protocol={selector} {report}"),
            Err(stage) => {
                failures += 1;
                println!("outbound_smoke_fail protocol={selector} stage=\"{stage}\"");
            }
        }
    }
    if failures != 0 {
        return Err(format!("{failures} of {} outbound probes failed", selectors.len()).into());
    }
    Ok(())
}

/// Where profiles come from for this run.
enum ProfileSource {
    Links(String),
    Configs(BTreeMap<String, OutboundConfig>),
}

impl ProfileSource {
    fn parse(body: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if body.trim_start().starts_with('{') {
            let configs: BTreeMap<String, OutboundConfig> = serde_json::from_str(body)
                .map_err(|_| "profile source is not a selector-to-outbound JSON object")?;
            if configs.is_empty() {
                return Err("profile source contains no outbounds".into());
            }
            Ok(Self::Configs(configs))
        } else {
            Ok(Self::Links(body.to_owned()))
        }
    }

    fn resolve(&self, selector: &str) -> Result<OutboundConfig, &'static str> {
        match self {
            Self::Configs(configs) => configs
                .get(selector)
                .cloned()
                .ok_or("json source has no outbound for this selector"),
            Self::Links(body) => import_first_profile_by_scheme(body, scheme_for(selector)?)
                .map(|profile| profile.outbound)
                .map_err(|_| "selected profile could not be imported"),
        }
    }
}

/// Closed selector table. Adding a protocol here is the only way to make the
/// probe reach it, which keeps the argv surface a fixed vocabulary rather than
/// free text.
fn scheme_for(selector: &str) -> Result<ProfileScheme, &'static str> {
    match selector {
        "vless" => Ok(ProfileScheme::Vless),
        "vmess" => Ok(ProfileScheme::Vmess),
        "hysteria2" => Ok(ProfileScheme::Hysteria2),
        "trojan" => Ok(ProfileScheme::Trojan),
        "shadowsocks" => Ok(ProfileScheme::Shadowsocks),
        "naive" => Ok(ProfileScheme::Naive),
        "wireguard" => Ok(ProfileScheme::Wireguard),
        "socks" => Ok(ProfileScheme::Socks),
        "http" => Ok(ProfileScheme::Http),
        "anytls" => Ok(ProfileScheme::AnyTls),
        // Both are reachable through the JSON source. `foxcore-link` has no
        // importer for either scheme, so asking for them from a link body fails
        // at import rather than here — the selector is real, the link is not.
        "tuic" => Ok(ProfileScheme::Tuic),
        "shadowtls" => Ok(ProfileScheme::ShadowTls),
        _ => Err("protocol selector is not supported by the probe"),
    }
}

async fn probe_selector(
    source: &ProfileSource,
    selector: &str,
    probe_udp: bool,
) -> Result<String, &'static str> {
    match source.resolve(selector)? {
        // WireGuard is L3: it has no stream semantics to probe, so it gets the
        // packet path instead of a downgraded TCP impersonation.
        OutboundConfig::Wireguard(config) => probe_packet_tunnel(config).await,
        proxy => probe_proxy(proxy, probe_udp).await,
    }
}

/// Stream probe: build the outbound, fetch a well-known page through it, and
/// require an HTTP status line plus non-zero bytes in both directions.
async fn probe_proxy(config: OutboundConfig, probe_udp: bool) -> Result<String, &'static str> {
    tokio::time::timeout(PROBE_TIMEOUT, async move {
        let outbound = Outbound::from_config(config, ProtectedDialer::host())
            .await
            .map_err(|_| "outbound initialization failed")?;
        let destination = Destination::new("example.com", 80);
        let context = FlowContext::new(1, IpTransport::Tcp, destination.clone());
        let mut stream = outbound
            .connect_stream(&context, destination)
            .await
            .map_err(|_| "outbound connection failed")?;

        const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        stream
            .write_all(REQUEST)
            .await
            .map_err(|_| "outbound write failed")?;
        stream.flush().await.map_err(|_| "outbound flush failed")?;

        // Read to EOF rather than a fixed 16 bytes: a status line proves the
        // handshake, a body proves the tunnel keeps carrying data afterwards.
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|_| "outbound read failed")?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
            if response.len() >= MAX_RESPONSE_BYTES {
                break;
            }
        }
        if !response.starts_with(b"HTTP/1.") {
            return Err("outbound returned an unexpected response");
        }

        let udp = if probe_udp {
            probe_datagram(&outbound).await
        } else {
            "skipped"
        };
        Ok(format!(
            "target=public_http bytes_up={} bytes_down={} udp={udp}",
            REQUEST.len(),
            response.len()
        ))
    })
    .await
    .map_err(|_| "outbound probe timed out")?
}

/// UDP relay probe. Reported, never fatal: a TCP-only protocol refusing a
/// datagram is correct behaviour, and conflating it with a broken relay is how
/// a design decision turns into a bug report.
async fn probe_datagram(outbound: &Outbound) -> &'static str {
    let destination = Destination::new("1.1.1.1", 53);
    let context = FlowContext::new(1, IpTransport::Udp, destination.clone());
    let Ok(session) = outbound.connect_datagram(&context).await else {
        return "unsupported";
    };
    if session
        .send(Datagram::new(destination, dns_query("example.com")))
        .await
        .is_err()
    {
        return "send_failed";
    }
    match tokio::time::timeout(UDP_TIMEOUT, session.recv()).await {
        Ok(Ok(datagram)) if is_dns_answer(&datagram.payload) => "ok",
        Ok(Ok(_)) => "unexpected_response",
        Ok(Err(_)) => "recv_failed",
        Err(_) => "timed_out",
    }
}

/// L3 probe for WireGuard/AmneziaWG.
///
/// There is no stream to open, so the proof is a real IP packet: a DNS query is
/// written into the relay as if it came off a tun, and the decrypted answer has
/// to come back out. That exercises the handshake, the transport keys, the
/// address translator and the obfuscation layer in one pass — which is exactly
/// what a config-only check cannot do.
#[cfg(feature = "wireguard")]
async fn probe_packet_tunnel(config: foxcore_api::WireguardConfig) -> Result<String, &'static str> {
    use std::net::IpAddr;
    use std::sync::Arc;

    use foxcore_outbound::PacketTunnelOutbound;
    use foxcore_tun::{FlowMetrics, PacketTunnelRelay};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    /// The address the probe pretends the tun carries. The translator rewrites
    /// it to whatever the peer assigned, so it only has to be stable.
    const TUN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const RESOLVER_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    /// A handshake plus a retransmit or two. WireGuard's own REKEY_TIMEOUT is
    /// 5 s, so anything shorter would report a slow peer as a dead one.
    const ATTEMPTS: usize = 8;
    const ATTEMPT_INTERVAL: Duration = Duration::from_secs(2);

    let outbound = PacketTunnelOutbound::wireguard(config, ProtectedDialer::host())
        .map_err(|_| "packet tunnel initialization failed")?;
    let metrics = Arc::new(FlowMetrics::default());
    let relay = PacketTunnelRelay::connect(&outbound, &[IpAddr::V4(TUN_V4)], metrics.clone())
        .await
        .map_err(|_| "packet tunnel socket failed")?;

    let (to_relay, from_probe) = mpsc::channel(16);
    let (to_probe, mut from_relay) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let driver = tokio::spawn(relay.run(from_probe, to_probe, cancel.clone()));

    let query = udp_ipv4_packet(TUN_V4, 40_000, RESOLVER_V4, 53, &dns_query("example.com"));
    let udp = exchange(
        &to_relay,
        &mut from_relay,
        &query,
        ATTEMPTS,
        ATTEMPT_INTERVAL,
        |reply| udp_payload_from(reply, RESOLVER_V4).is_some_and(is_dns_answer),
    )
    .await;

    // A peer that forwards UDP and not TCP answers this probe and fails every
    // connection a user opens. That is not hypothetical: it is what a live
    // profile did, while the DNS answer arrived and nothing here disagreed.
    // One transport is not evidence for the other, so both are asked.
    let syn = tcp_ipv4_syn(TUN_V4, TCP_PROBE_PORT, RESOLVER_V4, 443, TCP_PROBE_SEQ);
    let tcp = exchange(
        &to_relay,
        &mut from_relay,
        &syn,
        ATTEMPTS,
        ATTEMPT_INTERVAL,
        |reply| is_tcp_synack(reply, RESOLVER_V4, 443, TCP_PROBE_PORT, TCP_PROBE_SEQ),
    )
    .await;

    cancel.cancel();
    drop(to_relay);
    let _ = driver.await;

    let snapshot = metrics.snapshot();
    match (udp, tcp) {
        (false, false) => Err("packet tunnel returned no answer"),
        // Named apart from a dead tunnel on purpose. A peer forwarding one
        // transport is reachable, keyed and routing — the fault is in what it
        // does with the other, and saying "no answer" would send the next
        // person back to the handshake.
        (true, false) => Err("packet tunnel carried UDP but no TCP handshake"),
        (false, true) => Err("packet tunnel carried TCP but no UDP answer"),
        (true, true) => {
            if snapshot.bytes_up == 0 || snapshot.bytes_down == 0 {
                return Err("packet tunnel carried no bytes in one direction");
            }
            Ok(format!(
                "target=packet_tunnel bytes_up={} bytes_down={} udp=ok tcp=ok",
                snapshot.bytes_up, snapshot.bytes_down
            ))
        }
    }
}

/// Send one packet into the tunnel until something coming back matches.
///
/// Replies that are not the awaited one — an ICMP error, the other probe's
/// answer, a stray retransmit — are skipped rather than counted, so the two
/// transports can share a relay without either deciding the other's verdict.
#[cfg(feature = "wireguard")]
async fn exchange(
    to_relay: &tokio::sync::mpsc::Sender<bytes::BytesMut>,
    from_relay: &mut tokio::sync::mpsc::Receiver<bytes::BytesMut>,
    packet: &[u8],
    attempts: usize,
    interval: Duration,
    matches: impl Fn(&[u8]) -> bool,
) -> bool {
    for _ in 0..attempts {
        if to_relay.send(bytes::BytesMut::from(packet)).await.is_err() {
            return false;
        }
        let deadline = tokio::time::Instant::now() + interval;
        while let Ok(Some(reply)) = tokio::time::timeout_at(deadline, from_relay.recv()).await {
            if matches(&reply) {
                return true;
            }
        }
    }
    false
}

#[cfg(not(feature = "wireguard"))]
async fn probe_packet_tunnel(
    _config: foxcore_api::WireguardConfig,
) -> Result<String, &'static str> {
    Err("this build has no wireguard feature")
}

/// A minimal A-record query. Written out rather than pulled from `foxcore-dns`
/// so the probe tests the data path with a wire message it fully controls.
fn dns_query(name: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + name.len());
    message.extend_from_slice(&DNS_QUERY_ID.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    message.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    message.extend_from_slice(&[0x00; 6]); // AN/NS/AR counts
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    message.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    message
}

/// A response to *our* query carrying at least one answer. The transaction id is
/// checked so a stray datagram cannot pass for a working relay.
fn is_dns_answer(message: &[u8]) -> bool {
    message.len() >= 12
        && message[..2] == DNS_QUERY_ID.to_be_bytes()
        && message[2] & 0x80 != 0
        && u16::from_be_bytes([message[6], message[7]]) > 0
}

/// The UDP payload of an IPv4 datagram that came from `source`, if that is what
/// this packet is.
fn udp_payload_from(packet: &[u8], source: Ipv4Addr) -> Option<&[u8]> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != 17 {
        return None;
    }
    if packet[12..16] != source.octets() {
        return None;
    }
    packet.get(header_len + 8..)
}

/// A UDP/IPv4 datagram with both checksums computed. The relay's translator
/// repairs them incrementally after the address rewrite, so they have to be
/// correct going in — a packet with a bad checksum is dropped at the peer and
/// looks exactly like a tunnel that never came up.
fn udp_ipv4_packet(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = internet_checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let pseudo = [
        source.octets().as_slice(),
        destination.octets().as_slice(),
        &[0, 17],
        &(udp_len as u16).to_be_bytes(),
    ]
    .concat();
    let udp_checksum = internet_checksum(&[&pseudo, &packet[20..]]);
    // Zero is the "no checksum" marker in UDP, so the equivalent encoding is used.
    let udp_checksum = if udp_checksum == 0 {
        0xffff
    } else {
        udp_checksum
    };
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    packet
}

/// A bare TCP SYN over IPv4, both checksums computed.
///
/// The point is the peer's answer, not a connection: nothing here completes the
/// handshake, so the RST that follows our silence is the remote stack cleaning
/// up a half-open socket and is expected.
fn tcp_ipv4_syn(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    const TCP_LEN: usize = 20;
    let total_len = 20 + TCP_LEN;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 6; // TCP
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = internet_checksum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[32] = 0x50; // 20-byte header, no options
    packet[33] = 0x02; // SYN
    packet[34..36].copy_from_slice(&64_240_u16.to_be_bytes()); // window
    let pseudo = [
        source.octets().as_slice(),
        destination.octets().as_slice(),
        &[0, 6],
        &(TCP_LEN as u16).to_be_bytes(),
    ]
    .concat();
    // Unlike UDP, a zero TCP checksum is not a "not computed" marker: it is
    // simply wrong, and the peer drops the segment without a word.
    let tcp_checksum = internet_checksum(&[&pseudo, &packet[20..]]);
    packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
    packet
}

/// Whether this packet is the SYN-ACK answering our SYN.
///
/// The acknowledgement number is checked, not just the flags: a SYN-ACK from an
/// unrelated flow shares everything else, and accepting one would report a
/// tunnel as working on somebody else's connection.
fn is_tcp_synack(
    packet: &[u8],
    source: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> bool {
    let Some(&first) = packet.first() else {
        return false;
    };
    if first >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 20 || packet[9] != 6 {
        return false;
    }
    if packet[12..16] != source.octets() {
        return false;
    }
    let tcp = &packet[header_len..];
    if u16::from_be_bytes([tcp[0], tcp[1]]) != source_port
        || u16::from_be_bytes([tcp[2], tcp[3]]) != destination_port
    {
        return false;
    }
    const SYN_ACK: u8 = 0x12;
    if tcp[13] & SYN_ACK != SYN_ACK {
        return false;
    }
    u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]) == sequence.wrapping_add(1)
}

/// RFC 1071 one's-complement sum over a sequence of byte runs.
fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    let mut odd_carry: Option<u8> = None;
    for part in parts {
        let mut bytes = *part;
        if let Some(high) = odd_carry.take()
            && let Some((low, rest)) = bytes.split_first()
        {
            sum += u32::from(u16::from_be_bytes([high, *low]));
            bytes = rest;
        }
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let [last] = chunks.remainder() {
            odd_carry = Some(*last);
        }
    }
    if let Some(high) = odd_carry {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
