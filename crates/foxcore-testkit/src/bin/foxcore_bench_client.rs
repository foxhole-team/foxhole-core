//! The load and latency generator for the head-to-head comparison.
//!
//! It speaks SOCKS5 and plain HTTP/1.1 and **uses no FoxCore code at all** —
//! not the dialer, not the transport, not a single crate from this workspace.
//! That is the point: the same binary drives the FoxCore arm and the sing-box
//! arm, so nothing it does can favour either. If it imported the workspace's
//! own I/O stack, every number it produced would be open to the objection that
//! the generator and one of the subjects share a buffer strategy.
//!
//! What it records per request is what the comparison is actually about:
//!
//!   * `connect_us` — from opening the TCP socket to the proxy until the proxy
//!     answers that the upstream is connected. For a protocol arm this is the
//!     whole client-side handshake: TCP to the server, TLS/REALITY, and the
//!     protocol's own framing. This is "connection speed".
//!   * `ttfb_us` — request written to first response byte.
//!   * `total_us` — to EOF.
//!   * `bytes` — payload read.
//!
//! Percentiles are computed over the raw per-request series, not over
//! per-interval means, because a mean of means hides exactly the tail that
//! distinguishes two proxies under concurrency.
//!
//! ```text
//! foxcore-bench-client --proxy 127.0.0.1:1080 --target speed.example:80 \
//!     --path /10MB --concurrency 8 --requests 200 --out arm.jsonl
//! ```

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Reused for the life of a worker, so the generator contributes a constant to
/// its own footprint rather than a slope.
const READ_BUFFER: usize = 64 * 1024;

/// Origin server for the control arm.
///
/// The phone has no `httpd` and no `nc`, and pointing the control arm at the
/// internet would put the network back into the one measurement whose whole
/// purpose is to have none. So the generator can also *be* the origin: a fixed,
/// preallocated payload served with `Connection: close`, identical for both
/// arms because it is the same process image serving both.
///
/// `eager` makes it answer before reading anything. That is not a load-shaping
/// option — it is a diagnostic. A proxy protocol whose client blocks on a
/// server response header before it will forward the first request byte
/// deadlocks against a server that only emits that header once the destination
/// has spoken. Serving eagerly breaks the cycle from the far end, which turns
/// "the arm hangs" into a decided question about which side is waiting.
async fn serve(listen: &str, bytes: usize, eager: bool) -> Result<(), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("bench_origin_ready listen={listen} bytes={bytes} eager={eager}");

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
    );
    // Built once and shared. Allocating per connection would make the origin's
    // own allocator part of what the arms are being compared on.
    let payload: Arc<Vec<u8>> = Arc::new({
        let mut body = header.into_bytes();
        body.resize(body.len() + bytes, b'x');
        body
    });

    loop {
        let (mut stream, _) = listener.accept().await?;
        let payload = payload.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();
            let mut discard = [0_u8; 4096];
            if !eager {
                // Read the request line and headers, then stop; the generator
                // only ever sends `Connection: close` requests with no body.
                let _ = stream.read(&mut discard).await;
            }
            let _ = stream.write_all(&payload).await;
            let _ = stream.shutdown().await;
        });
    }
}

struct Options {
    proxy: Option<String>,
    target_host: String,
    target_port: u16,
    path: String,
    concurrency: usize,
    requests: Option<usize>,
    duration: Option<Duration>,
    timeout: Duration,
    credentials: Option<(String, String)>,
    out: Option<String>,
    label: String,
}

impl Options {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut proxy = None;
        let mut target = None;
        let mut path = "/".to_owned();
        let mut concurrency = 1_usize;
        let mut requests = None;
        let mut duration = None;
        let mut timeout = Duration::from_secs(30);
        let mut user = None;
        let mut password = None;
        let mut out = None;
        let mut label = "arm".to_owned();

        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            let mut value = || -> Result<String, Box<dyn Error>> {
                arguments
                    .next()
                    .ok_or_else(|| format!("{argument} needs a value").into())
            };
            match argument.as_str() {
                "--proxy" => proxy = Some(value()?),
                "--target" => target = Some(value()?),
                "--path" => path = value()?,
                "--concurrency" => concurrency = value()?.parse()?,
                "--requests" => requests = Some(value()?.parse()?),
                "--duration-s" => duration = Some(Duration::from_secs(value()?.parse()?)),
                "--timeout-s" => timeout = Duration::from_secs(value()?.parse()?),
                "--user" => user = Some(value()?),
                "--password" => password = Some(value()?),
                "--out" => out = Some(value()?),
                "--label" => label = value()?,
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }

        let target: String = target.ok_or("--target is required as host:port")?;
        let (target_host, target_port) = target
            .rsplit_once(':')
            .ok_or("--target must be host:port")?;
        if concurrency == 0 {
            return Err("--concurrency must be at least 1".into());
        }
        if requests.is_none() && duration.is_none() {
            return Err("one of --requests or --duration-s is required".into());
        }

        let credentials = match (user, password) {
            (Some(user), Some(password)) => Some((user, password)),
            (None, None) => None,
            _ => return Err("--user and --password go together".into()),
        };

        Ok(Self {
            // Absent means "go straight at the target". That is how the same
            // instrument measures a TUN plane, where the tunnel is transparent
            // and there is no proxy to dial — using a different downloader there
            // would make the two planes incomparable by construction.
            proxy,
            target_host: target_host.to_owned(),
            target_port: target_port.parse()?,
            path,
            concurrency,
            requests,
            duration,
            timeout,
            credentials,
            out,
            label,
        })
    }
}

#[derive(Clone, Copy)]
struct Sample {
    connect_us: u64,
    ttfb_us: u64,
    total_us: u64,
    bytes: u64,
}

#[derive(Default)]
struct Counters {
    ok: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    bytes: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Serving mode is checked before the client options are parsed, because the
    // two share no required arguments.
    let arguments: Vec<String> = env::args().skip(1).collect();
    if let Some(index) = arguments.iter().position(|argument| argument == "--serve") {
        let listen = arguments
            .get(index + 1)
            .ok_or("--serve needs host:port")?
            .clone();
        let bytes = arguments
            .iter()
            .position(|argument| argument == "--serve-bytes")
            .and_then(|index| arguments.get(index + 1))
            .map(|value| value.parse::<usize>())
            .transpose()?
            .unwrap_or(1024 * 1024);
        let eager = arguments.iter().any(|argument| argument == "--serve-eager");
        return serve(&listen, bytes, eager).await;
    }

    let options = Arc::new(Options::parse()?);
    let counters = Arc::new(Counters::default());
    let samples = Arc::new(Mutex::new(Vec::<Sample>::new()));
    let issued = Arc::new(AtomicU64::new(0));

    let started = Instant::now();
    let mut workers = Vec::with_capacity(options.concurrency);
    for _ in 0..options.concurrency {
        let options = options.clone();
        let counters = counters.clone();
        let samples = samples.clone();
        let issued = issued.clone();
        workers.push(tokio::spawn(async move {
            let mut buffer = vec![0_u8; READ_BUFFER];
            loop {
                // Both stop conditions are checked by the worker itself rather
                // than by a supervisor, so a slow in-flight request is always
                // allowed to finish instead of being counted as a failure of
                // the arm under test.
                // The counter is only bumped when a request limit exists, so the
                // duration mode does not silently consume budget it never had.
                if let Some(limit) = options.requests
                    && issued.fetch_add(1, Ordering::Relaxed) >= limit as u64
                {
                    break;
                }
                if let Some(limit) = options.duration
                    && started.elapsed() >= limit
                {
                    break;
                }

                match tokio::time::timeout(options.timeout, one_request(&options, &mut buffer))
                    .await
                {
                    Ok(Ok(sample)) => {
                        counters.ok.fetch_add(1, Ordering::Relaxed);
                        counters.bytes.fetch_add(sample.bytes, Ordering::Relaxed);
                        samples.lock().expect("sample lock").push(sample);
                    }
                    Ok(Err(_)) => {
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        counters.timed_out.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for worker in workers {
        let _ = worker.await;
    }
    let elapsed = started.elapsed();

    let mut samples = samples.lock().expect("sample lock").clone();
    report(&options, &counters, &mut samples, elapsed)?;
    Ok(())
}

async fn one_request(options: &Options, buffer: &mut [u8]) -> Result<Sample, Box<dyn Error>> {
    let started = Instant::now();

    let mut stream = match &options.proxy {
        Some(proxy) => {
            let mut stream = TcpStream::connect(proxy).await?;
            // Nagle would fold the SOCKS greeting and the request together and
            // shave a round trip off one arm depending on how its listener
            // reads. Off on both.
            stream.set_nodelay(true)?;
            socks5_connect(
                &mut stream,
                &options.target_host,
                options.target_port,
                options.credentials.as_ref(),
            )
            .await?;
            stream
        }
        None => {
            let stream =
                TcpStream::connect((options.target_host.as_str(), options.target_port)).await?;
            stream.set_nodelay(true)?;
            stream
        }
    };
    let connect_us = started.elapsed().as_micros() as u64;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
        options.path, options.target_host
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut bytes = 0_u64;
    let mut ttfb_us = None;
    loop {
        let read = stream.read(buffer).await?;
        if read == 0 {
            break;
        }
        if ttfb_us.is_none() {
            ttfb_us = Some(started.elapsed().as_micros() as u64);
        }
        bytes += read as u64;
    }

    Ok(Sample {
        connect_us,
        ttfb_us: ttfb_us.unwrap_or(connect_us),
        total_us: started.elapsed().as_micros() as u64,
        bytes,
    })
}

/// RFC 1928 CONNECT, optionally with RFC 1929 username/password.
///
/// Offering both methods and letting the server choose is what makes one
/// binary able to drive an authenticated arm and an anonymous one without a
/// second code path that could differ.
async fn socks5_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    credentials: Option<&(String, String)>,
) -> Result<(), Box<dyn Error>> {
    if credentials.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut selection = [0_u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != 0x05 {
        return Err("proxy is not SOCKS5".into());
    }
    match selection[1] {
        0x00 => {}
        0x02 => {
            let (user, password) = credentials.ok_or("proxy demanded authentication")?;
            let mut negotiation = vec![0x01, user.len() as u8];
            negotiation.extend_from_slice(user.as_bytes());
            negotiation.push(password.len() as u8);
            negotiation.extend_from_slice(password.as_bytes());
            stream.write_all(&negotiation).await?;
            let mut status = [0_u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err("proxy rejected the credentials".into());
            }
        }
        _ => return Err("proxy offered no acceptable method".into()),
    }

    // Always send the destination as a name. Resolving it here would move DNS
    // out of the subject under test and into the generator, and DNS handling is
    // one of the things the two cores do differently.
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(format!("proxy refused CONNECT with code {}", reply[1]).into());
    }
    // Consume the bound address so the response body does not start mid-header.
    match reply[3] {
        0x01 => {
            let mut discard = [0_u8; 6];
            stream.read_exact(&mut discard).await?;
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut discard = vec![0_u8; length[0] as usize + 2];
            stream.read_exact(&mut discard).await?;
        }
        0x04 => {
            let mut discard = [0_u8; 18];
            stream.read_exact(&mut discard).await?;
        }
        _ => return Err("proxy replied with an unknown address type".into()),
    }
    Ok(())
}

fn percentile(sorted: &[u64], fraction: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index]
}

fn report(
    options: &Options,
    counters: &Counters,
    samples: &mut [Sample],
    elapsed: Duration,
) -> Result<(), Box<dyn Error>> {
    if let Some(path) = &options.out {
        let mut writer = BufWriter::new(File::create(path)?);
        for sample in samples.iter() {
            writeln!(
                writer,
                r#"{{"connect_us":{},"ttfb_us":{},"total_us":{},"bytes":{}}}"#,
                sample.connect_us, sample.ttfb_us, sample.total_us, sample.bytes
            )?;
        }
        writer.flush()?;
    }

    let mut connect: Vec<u64> = samples.iter().map(|s| s.connect_us).collect();
    let mut ttfb: Vec<u64> = samples.iter().map(|s| s.ttfb_us).collect();
    let mut total: Vec<u64> = samples.iter().map(|s| s.total_us).collect();
    connect.sort_unstable();
    ttfb.sort_unstable();
    total.sort_unstable();

    let bytes = counters.bytes.load(Ordering::Relaxed);
    let seconds = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    let mib_per_second = (bytes as f64 / (1024.0 * 1024.0)) / seconds;

    // One line, machine-readable, with the arm label in it — the harness
    // interleaves arms and sorts afterwards, so every line has to identify
    // itself rather than rely on the order it was printed in.
    println!(
        concat!(
            r#"{{"label":"{}","concurrency":{},"elapsed_s":{:.3},"#,
            r#""ok":{},"failed":{},"timed_out":{},"bytes":{},"mib_per_s":{:.4},"#,
            r#""connect_us":{{"p50":{},"p95":{},"p99":{},"max":{}}},"#,
            r#""ttfb_us":{{"p50":{},"p95":{},"p99":{},"max":{}}},"#,
            r#""total_us":{{"p50":{},"p95":{},"p99":{},"max":{}}}}}"#
        ),
        options.label,
        options.concurrency,
        seconds,
        counters.ok.load(Ordering::Relaxed),
        counters.failed.load(Ordering::Relaxed),
        counters.timed_out.load(Ordering::Relaxed),
        bytes,
        mib_per_second,
        percentile(&connect, 0.50),
        percentile(&connect, 0.95),
        percentile(&connect, 0.99),
        connect.last().copied().unwrap_or(0),
        percentile(&ttfb, 0.50),
        percentile(&ttfb, 0.95),
        percentile(&ttfb, 0.99),
        ttfb.last().copied().unwrap_or(0),
        percentile(&total, 0.50),
        percentile(&total, 0.95),
        percentile(&total, 0.99),
        total.last().copied().unwrap_or(0),
    );
    Ok(())
}
