//! A SOCKS5 front end onto one production outbound, for head-to-head measurement.
//!
//! The comparison this exists for is FoxCore against sing-box on the same
//! phone. sing-box cannot open a TUN on a stock, non-rooted Android device, so
//! the only shape both cores can take is the one they share: a local SOCKS5
//! listener in front of one outbound. That is what this binary is — not a
//! product surface, and never shipped.
//!
//! Everything below the listener is the real path: `foxcore-link` parses the
//! share link, `Outbound::from_config` builds the same object the runtime
//! builds, and `connect_stream` performs the same handshake. The listener is
//! the only thing that differs from production, and it is deliberately
//! available in two shapes:
//!
//!   * `--server lan` runs the audited component SOCKS5 server
//!     (`foxcore-component::lan`) through `start_loopback_proxy`. It carries
//!     mandatory username/password authentication and a hard ceiling of 64
//!     concurrent sessions.
//!   * `--server raw` runs a minimal RFC 1928 CONNECT server with no admission
//!     control at all.
//!
//! The ceiling is why both exist. It is a property of the LAN proxy, not of the
//! data path, and sing-box's `mixed` inbound has no equivalent — so measuring
//! concurrency against `lan` would report a product decision as a throughput
//! result. Headline numbers come from `raw`, and `lan` is run at concurrency
//! below the ceiling to show the two agree.
//!
//! The profile arrives on **stdin**, like every other testkit binary here: a
//! share link on a command line ends up in `ps`, in shell history and in the
//! activity manager's log.
//!
//! ```text
//! foxcore-socks --selector vless --socks-port 1080 --server raw < link.txt
//! ```

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use foxcore_api::{Destination, FlowContext, IpTransport, OutboundConfig};
use foxcore_component::{
    ComponentError, ComponentId, ComponentManager, LanConnect, LanCredentials, LanIo,
    LanProxyConfig, LanProxyPreset, LanRoute, LanUpstream, RuntimeKind, RuntimeLease,
    RuntimeLeaseProvider,
};
use foxcore_dialer::ProtectedDialer;
use foxcore_link::{ProfileScheme, import_first_profile_by_scheme};
use foxcore_outbound::Outbound;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Same ceiling the subscription probe uses. A profile source larger than this
/// is a mistake, not a subscription.
const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn main() -> Result<(), Box<dyn Error>> {
    // Multi-thread on purpose. The measurement drives up to 64 concurrent
    // flows through this process, and a current-thread runtime would make the
    // result a statement about one core rather than about the data path.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

struct Options {
    selector: String,
    socks_port: u16,
    server: ServerKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ServerKind {
    Lan,
    Raw,
}

impl Options {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut selector = None;
        let mut socks_port = None;
        let mut server = ServerKind::Raw;

        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--selector" => {
                    selector = Some(arguments.next().ok_or("--selector needs a value")?);
                }
                "--socks-port" => {
                    socks_port = Some(
                        arguments
                            .next()
                            .ok_or("--socks-port needs a value")?
                            .parse::<u16>()
                            .map_err(|_| "--socks-port must be a port number")?,
                    );
                }
                "--server" => match arguments.next().as_deref() {
                    Some("lan") => server = ServerKind::Lan,
                    Some("raw") => server = ServerKind::Raw,
                    _ => return Err("--server must be lan or raw".into()),
                },
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }

        let socks_port = socks_port.ok_or("--socks-port is required")?;
        if socks_port == 0 {
            return Err(
                "--socks-port must be non-zero: the harness has to know where to dial".into(),
            );
        }
        Ok(Self {
            selector: selector.ok_or("--selector is required")?,
            socks_port,
            server,
        })
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let options = Options::parse()?;

    let mut body = String::new();
    io::stdin()
        .take(MAX_INPUT_BYTES)
        .read_to_string(&mut body)?;
    if body.len() >= MAX_INPUT_BYTES as usize {
        return Err("profile source exceeds 1 MiB".into());
    }

    let config = resolve(&body, &options.selector)?;
    let outbound = Arc::new(
        Outbound::from_config(config, ProtectedDialer::host())
            .await
            .map_err(|error| format!("outbound initialization failed: {error}"))?,
    );

    match options.server {
        ServerKind::Raw => serve_raw(options.socks_port, outbound).await,
        ServerKind::Lan => serve_lan(options.socks_port, outbound).await,
    }
}

/// Resolve one selector to one outbound config.
///
/// `direct` is not a protocol — it is the control arm. Measuring both cores
/// with no protocol at all is what separates the cost of the proxy machinery
/// from the cost of the cryptography, and without it a difference in the
/// protocol arms cannot be attributed to either.
fn resolve(body: &str, selector: &str) -> Result<OutboundConfig, Box<dyn Error>> {
    if selector == "direct" {
        return Ok(OutboundConfig::Direct(Default::default()));
    }
    if body.trim_start().starts_with('{') {
        let configs: BTreeMap<String, OutboundConfig> = serde_json::from_str(body)
            .map_err(|_| "profile source is not a selector-to-outbound JSON object")?;
        return configs
            .get(selector)
            .cloned()
            .ok_or_else(|| "json source has no outbound for this selector".into());
    }
    let scheme = scheme_for(selector)?;
    import_first_profile_by_scheme(body, scheme)
        .map(|profile| profile.outbound)
        .map_err(|_| "selected profile could not be imported".into())
}

/// Closed selector table, same reasoning as the outbound probe: a fixed
/// vocabulary on the command line rather than free text.
fn scheme_for(selector: &str) -> Result<ProfileScheme, Box<dyn Error>> {
    match selector {
        "vless" => Ok(ProfileScheme::Vless),
        "vmess" => Ok(ProfileScheme::Vmess),
        "hysteria2" => Ok(ProfileScheme::Hysteria2),
        "trojan" => Ok(ProfileScheme::Trojan),
        "shadowsocks" => Ok(ProfileScheme::Shadowsocks),
        "naive" => Ok(ProfileScheme::Naive),
        "socks" => Ok(ProfileScheme::Socks),
        "http" => Ok(ProfileScheme::Http),
        "anytls" => Ok(ProfileScheme::AnyTls),
        other => Err(format!("protocol selector is not supported: {other}").into()),
    }
}

/// One outbound behind the component LAN proxy's upstream trait.
struct OneOutbound {
    outbound: Arc<Outbound>,
    flows: AtomicU64,
}

impl LanUpstream for OneOutbound {
    fn connect(&self, _route: LanRoute, host: String, port: u16) -> LanConnect {
        // The preset decides Vpn or Tor upstream in production. Here there is
        // exactly one outbound and no route table, so the route is recorded by
        // the caller and ignored — a second behaviour would be a second thing
        // to explain in the results.
        let outbound = self.outbound.clone();
        let flow = self.flows.fetch_add(1, Ordering::Relaxed) + 1;
        Box::pin(async move {
            let destination = Destination::new(host, port);
            let context = FlowContext::new(flow, IpTransport::Tcp, destination.clone());
            let stream = outbound.connect_stream(&context, destination).await?;
            Ok(Box::new(stream) as Box<dyn LanIo>)
        })
    }
}

struct AlwaysAvailable;

impl RuntimeLease for AlwaysAvailable {
    fn is_available(&self) -> bool {
        true
    }
}

/// This binary *is* the runtime, so the lease it hands out is unconditional.
/// In production the same trait is what refuses to serve a LAN session when
/// the tunnel is down; here there is nothing above to refuse.
struct StandaloneProvider;

impl RuntimeLeaseProvider for StandaloneProvider {
    fn acquire(&self, _runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError> {
        Ok(Arc::new(AlwaysAvailable))
    }
}

async fn serve_lan(socks_port: u16, outbound: Arc<Outbound>) -> Result<(), Box<dyn Error>> {
    // The component server has no anonymous mode, so the credential is
    // mandatory here too. It comes from the environment rather than argv for
    // the same reason the profile does.
    let user = env::var("FOXCORE_SOCKS_USER").unwrap_or_else(|_| "bench".to_owned());
    let password = env::var("FOXCORE_SOCKS_PASSWORD")
        .map_err(|_| "server=lan needs FOXCORE_SOCKS_PASSWORD in the environment")?;

    let manager = ComponentManager::new(Arc::new(StandaloneProvider));
    let handle = manager
        .start_loopback_proxy(
            tokio::runtime::Handle::current(),
            LanProxyConfig {
                id: ComponentId::new("lan:bench")?,
                preset: LanProxyPreset::Vpn,
                socks_port,
                // HTTP CONNECT is a second listener with its own accounting.
                // The comparison is SOCKS5 on both sides, so it stays off.
                http_port: 0,
                // Refused for an empty or non-ASCII credential rather than
                // silently downgraded — the component has no anonymous mode and
                // an arm that quietly became one would not be the same server.
                credentials: LanCredentials::new(&user, password.into_bytes())
                    .ok_or("FOXCORE_SOCKS_USER/PASSWORD must be 1..=255 bytes, user ASCII")?,
            },
            1,
            Arc::new(OneOutbound {
                outbound,
                flows: AtomicU64::new(0),
            }),
        )
        .map_err(|error| format!("lan proxy failed to start: {error:?}"))?;

    // Readiness is printed, not assumed: the harness waits for this line
    // instead of sleeping, so a slow start cannot be mistaken for a slow first
    // request.
    println!("foxcore_socks_ready server=lan socks_port={socks_port}");
    wait_forever().await;
    drop(handle);
    Ok(())
}

async fn serve_raw(socks_port: u16, outbound: Arc<Outbound>) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;
    println!("foxcore_socks_ready server=raw socks_port={socks_port}");

    let flows = Arc::new(AtomicU64::new(0));
    loop {
        let (client, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // A descriptor shortage under load is a measurement artifact, not a
            // reason to stop serving; dropping the accept and continuing keeps
            // the arm alive so the run still produces a number.
            Err(error) if error.kind() == io::ErrorKind::Other => continue,
            Err(error) => return Err(error.into()),
        };
        let outbound = outbound.clone();
        let flows = flows.clone();
        tokio::spawn(async move {
            let _ = serve_one_raw(client, outbound, flows).await;
        });
    }
}

/// RFC 1928 CONNECT, no authentication, no admission control.
///
/// Deliberately the smallest thing that can carry the measurement: sing-box's
/// `mixed` inbound with an empty `users` list is the same shape, so whatever
/// this costs, the other arm pays too.
async fn serve_one_raw(
    mut client: TcpStream,
    outbound: Arc<Outbound>,
    flows: Arc<AtomicU64>,
) -> io::Result<()> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(io::Error::other("not SOCKS5"));
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // Refuse rather than negotiate: an arm that silently fell back to
        // authentication would be measuring a different handshake.
        client.write_all(&[0x05, 0xFF]).await?;
        return Err(io::Error::other("client offered no acceptable method"));
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    if request[0] != 0x05 || request[1] != 0x01 {
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(io::Error::other("only CONNECT is served"));
    }

    let host = match request[3] {
        0x01 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length).await?;
            let mut name = vec![0_u8; length[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| io::Error::other("domain is not UTF-8"))?
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(io::Error::other("unsupported address type"));
        }
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    let flow = flows.fetch_add(1, Ordering::Relaxed) + 1;
    let destination = Destination::new(host, port);
    let context = FlowContext::new(flow, IpTransport::Tcp, destination.clone());
    let mut upstream = match outbound.connect_stream(&context, destination).await {
        Ok(stream) => stream,
        Err(error) => {
            // Printed, not swallowed. A SOCKS refusal on the wire is a single
            // byte, so without this the harness could only report "the arm
            // failed" and every diagnosis would be a guess about which layer.
            eprintln!(
                "foxcore_socks_connect_failed kind={:?} error={error}",
                error.kind()
            );
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(error);
        }
    };

    // The bound address in the reply is not used by any client that matters
    // here, and inventing one would be a second thing that could be wrong.
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // The same pooled 64 KiB relay the product uses, from the same crate — see
    // `foxcore-relay` for why both the size and the pool are there. This copy
    // used to live here, which made the harness the only place that had the
    // fix; measuring a pooling harness against an allocating product and
    // calling the difference a data-path result would have been exactly the
    // mistake the pool was found by avoiding.
    foxcore_relay::copy_bidirectional_pooled(&COPY_POOL, &mut client, &mut upstream)
        .await
        .map(|_| ())
}

/// 64 KiB, matching sing-box's `sing` library so the two arms are compared at
/// the same size.
const COPY_BUFFER: usize = 64 * 1024;

/// Deeper than any product pool: the harness is driven at concurrency 32 on
/// purpose, and a bench that started allocating halfway through a run would be
/// measuring its own cache miss rather than the core.
static COPY_POOL: foxcore_relay::BufferPool = foxcore_relay::BufferPool::new(COPY_BUFFER, 128);

async fn wait_forever() {
    // The harness stops this process with a signal once its samples are in.
    std::future::pending::<()>().await
}
