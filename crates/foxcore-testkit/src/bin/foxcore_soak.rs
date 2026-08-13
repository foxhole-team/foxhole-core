#![forbid(unsafe_code)]

//! Long-run and impaired-network harness for the production runtime.
//!
//! Everything the core had been measured on until now was a test that finished
//! in seconds. This binary is the opposite: it starts the *production* entry
//! point — [`CoreRuntime::start`], the same call the JNI layer makes — on a real
//! Linux TUN, drives load through it for hours, and writes one JSON line per
//! sample so the result is a **trend** rather than an average. A constant load
//! whose RSS climbs is a leak even when the absolute number looks harmless, and
//! that shape is invisible in a thirty-second run.
//!
//! It is also the netem harness. Nothing here knows whether the uplink is clean
//! or has 20% loss on it; the impairment is applied outside, to the container's
//! interface, and what changes is the numbers in the samples. That is the point:
//! the question under loss is not "does it work" but "how does it degrade", and
//! only a harness that records the same counters on both sides can answer it.
//!
//! Usage:
//!
//! ```text
//! foxcore-soak --config C.json --tun fox0 --target 1.2.3.4:80 --host example.org \
//!              --duration-s 21600 --interval-s 60 --concurrency 8 --out samples.jsonl
//! ```
//!
//! The load generator is deliberately dumb: HTTP/1.1 `GET` with
//! `Connection: close`, read to EOF, count bytes. It has no TLS, no keep-alive
//! and no parser, so nothing it does can be confused for the core's behaviour,
//! and its own footprint is a fixed buffer per worker that does not grow.
//!
//! Nothing about the profile is printed. Samples carry counters, sizes and
//! timings only.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use foxcore_api::EngineConfig;
use foxcore_dialer::SocketCallbacks;
use foxcore_runtime::CoreRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Per-worker read buffer. Fixed, and reused for the life of the worker, so the
/// generator contributes a constant to RSS instead of a slope of its own.
const READ_BUFFER: usize = 64 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::parse(std::env::args().skip(1))?;
    if options.role == Role::Load {
        return run_load_only(options);
    }
    if options.role == Role::Sink {
        return run_sink(options);
    }

    let json = std::fs::read_to_string(&options.config)?;
    let config = EngineConfig::parse(&json)?;
    let tun_fd = foxcore_tun::open_named_fd(&options.tun)?;

    let mut out = BufWriter::new(File::create(&options.out)?);

    // Cold start, measured around the call the app actually makes. This is the
    // product cold-start number, so it is taken here and not from a log line
    // written some time after the fact.
    let started = Instant::now();
    let runtime = CoreRuntime::start(1, config, tun_fd, SocketCallbacks::none())?;
    let start_ms = started.elapsed().as_secs_f64() * 1000.0;
    let runtime = Arc::new(runtime);
    eprintln!("soak start_ms={start_ms:.1}");

    let load = Arc::new(LoadCounters::default());
    let stop = Arc::new(AtomicBool::new(false));

    // In `--role core` the generator lives in another process under another
    // uid, because the destination is routed into the TUN and the core's own
    // socket must not be: same-process load would have to share the routing
    // table with the core it is driving.
    let generator = (options.role == Role::Both)
        .then(|| {
            let load = load.clone();
            let stop = stop.clone();
            let options = options.clone();
            std::thread::Builder::new()
                .name("soak-load".into())
                .spawn(move || run_load(options, load, stop))
        })
        .transpose()?;

    let mut record = Record::new();
    record.put("event", "start");
    record.put("start_ms", format!("{start_ms:.1}"));
    write_line(&mut out, &record)?;

    let deadline = Instant::now() + Duration::from_secs(options.duration_s);
    let mut next_network_change = options
        .network_change_every_s
        .map(|every| Instant::now() + Duration::from_secs(every));
    let mut sample_index = 0_u64;
    let run_started = Instant::now();

    while Instant::now() < deadline {
        std::thread::sleep(
            Duration::from_secs(options.interval_s.min(5))
                .min(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1)),
        );
        if let Some(when) = next_network_change
            && Instant::now() >= when
        {
            // The cheapest source of the "accumulated platform work" that only
            // shows up after hours: every one of these reaches the resolver and
            // the packet tunnel, and each rebind leaves something behind or it
            // does not.
            runtime.network_changed();
            next_network_change =
                Some(Instant::now() + Duration::from_secs(options.network_change_every_s.unwrap()));
        }
        if run_started.elapsed().as_secs() / options.interval_s > sample_index {
            sample_index += 1;
            let mut record = sample(&runtime, &load, run_started);
            record.put("event", "sample");
            record.put("i", sample_index.to_string());
            write_line(&mut out, &record)?;
        }
    }

    stop.store(true, Ordering::Release);
    let mut record = sample(&runtime, &load, run_started);
    record.put("event", "before_stop");
    write_line(&mut out, &record)?;

    // The measurement the six hours exist for. `stop()` has a ceiling by
    // construction; what is unknown is whether a runtime that has been working
    // for hours reaches it.
    let stopping = Instant::now();
    let result = runtime.stop();
    let stop_ms = stopping.elapsed().as_secs_f64() * 1000.0;
    eprintln!("soak stop_ms={stop_ms:.1} result={result:?}");

    if let Some(generator) = generator {
        let _ = generator.join();
    }

    let mut record = sample(&runtime, &load, run_started);
    record.put("event", "stopped");
    record.put("stop_ms", format!("{stop_ms:.1}"));
    record.put("stop_result", format!("{result:?}"));
    write_line(&mut out, &record)?;
    out.flush()?;
    Ok(())
}

/// A sink that reads and discards, concurrently.
///
/// The first upload arms measured nothing, and the reason was the sink rather
/// than the core: `while true; do nc -l -p 9999; done` accepts **one**
/// connection at a time, so seven of eight uploaders were refused and the eighth
/// raced the loop's restart. `bytes_up = 0` looked like a core that would not
/// push. A sink that accepts every connection is the difference between
/// measuring the backlog ceiling and measuring busybox.
fn run_sink(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(options.target).await?;
        eprintln!("sink listening on {}", options.target);
        let deadline = Instant::now() + Duration::from_secs(options.duration_s);
        while Instant::now() < deadline {
            let accept = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
            let Ok(Ok((mut stream, _))) = accept else {
                continue;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; READ_BUFFER];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                }
            });
        }
        Ok::<_, std::io::Error>(())
    })?;
    Ok(())
}

/// The generator half, as its own process.
///
/// It knows nothing about the core: it opens sockets to an address whose route
/// happens to be a TUN. That is the whole point of splitting it out — its uid
/// is what the routing rule selects on, so it cannot accidentally share the
/// core's path to the same destination.
fn run_load_only(options: Options) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = BufWriter::new(File::create(&options.out)?);
    let load = Arc::new(LoadCounters::default());
    let stop = Arc::new(AtomicBool::new(false));
    let generator = {
        let load = load.clone();
        let stop = stop.clone();
        let options = options.clone();
        std::thread::Builder::new()
            .name("soak-load".into())
            .spawn(move || run_load(options, load, stop))?
    };
    let started = Instant::now();
    let deadline = started + Duration::from_secs(options.duration_s);
    let mut sample_index = 0_u64;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        if started.elapsed().as_secs() / options.interval_s > sample_index {
            sample_index += 1;
            let mut record = Record::new();
            record.put("event", "sample");
            record.put("i", sample_index.to_string());
            record.put("t_s", started.elapsed().as_secs().to_string());
            record.put("wall", unix_seconds().to_string());
            record.put("load", load.drain_json());
            write_line(&mut out, &record)?;
        }
    }
    stop.store(true, Ordering::Release);
    let _ = generator.join();
    let mut record = Record::new();
    record.put("event", "final");
    record.put("t_s", started.elapsed().as_secs().to_string());
    record.put("wall", unix_seconds().to_string());
    record.put("load", load.drain_json());
    write_line(&mut out, &record)?;
    out.flush()?;
    Ok(())
}

/// One sample: what the core says, what the OS says, what the load says.
fn sample(runtime: &CoreRuntime, load: &LoadCounters, since: Instant) -> Record {
    let mut record = Record::new();
    record.put("t_s", since.elapsed().as_secs().to_string());
    record.put("wall", unix_seconds().to_string());
    record.put("core", runtime.snapshot_json());
    let process = ProcessStats::read();
    record.put("rss_kb", process.rss_kb.to_string());
    record.put("vsz_kb", process.vsz_kb.to_string());
    record.put("threads", process.threads.to_string());
    record.put("fds", process.fds.to_string());
    record.put("cpu_s", format!("{:.2}", process.cpu_s));
    record.put("load", load.drain_json());
    record
}

// ---------------------------------------------------------------------------
// Load generator
// ---------------------------------------------------------------------------

fn run_load(options: Options, load: Arc<LoadCounters>, stop: Arc<AtomicBool>) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("soak load runtime failed: {error}");
            return;
        }
    };
    runtime.block_on(async move {
        let mut workers = Vec::with_capacity(options.concurrency);
        for _ in 0..options.concurrency {
            let load = load.clone();
            let stop = stop.clone();
            let options = options.clone();
            workers.push(tokio::spawn(async move {
                let mut buffer = vec![0_u8; READ_BUFFER];
                while !stop.load(Ordering::Acquire) {
                    let began = Instant::now();
                    match tokio::time::timeout(
                        Duration::from_secs(options.request_timeout_s),
                        one_request(&options, &mut buffer),
                    )
                    .await
                    {
                        Ok(Ok(bytes)) => load.ok(began.elapsed(), bytes),
                        Ok(Err(_)) => load.failed(),
                        Err(_) => load.timed_out(),
                    }
                    if options.pace_ms != 0 {
                        tokio::time::sleep(Duration::from_millis(options.pace_ms)).await;
                    }
                }
            }));
        }
        for worker in workers {
            let _ = worker.await;
        }
    });
}

/// One request, ended by `Content-Length` rather than by EOF.
///
/// Reading to EOF was the first shape and it was wrong: busybox `httpd` ignores
/// `Connection: close` and holds the socket open, so every request "timed out"
/// after transferring its whole payload — a harness defect that reads exactly
/// like a core that never finishes a flow. The length is what the response
/// itself says, so the client closes the moment the body is complete and the
/// flow's lifetime is the transfer's lifetime.
async fn one_request(options: &Options, buffer: &mut [u8]) -> std::io::Result<u64> {
    if options.upload_bytes != 0 {
        return one_upload(options, buffer).await;
    }
    let mut stream = TcpStream::connect(options.target).await?;
    stream.set_nodelay(true)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: foxcore-soak\r\nConnection: close\r\n\r\n",
        options.path, options.host
    );
    stream.write_all(request.as_bytes()).await?;

    let mut header = Vec::with_capacity(512);
    let mut body_seen = 0_u64;
    let mut content_length: Option<u64> = None;
    loop {
        let read = stream.read(buffer).await?;
        if read == 0 {
            // EOF before the headers finished is a failure; after a complete
            // body it is a legitimate end for a server that does close.
            break;
        }
        if content_length.is_none() {
            header.extend_from_slice(&buffer[..read]);
            if let Some(end) = find_header_end(&header) {
                content_length = Some(parse_content_length(&header[..end]).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response carries no Content-Length",
                    )
                })?);
                body_seen = (header.len() - end) as u64;
                header.clear();
                header.shrink_to_fit();
            }
        } else {
            body_seen += read as u64;
        }
        if let Some(length) = content_length
            && body_seen >= length
        {
            return Ok(body_seen);
        }
        if let Some(cap) = options.max_response_bytes
            && body_seen >= cap
        {
            return Ok(body_seen);
        }
    }
    match content_length {
        Some(length) if body_seen >= length => Ok(body_seen),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "response ended before its body did",
        )),
    }
}

/// A flow that only pushes, against a sink that discards.
///
/// This is the shape that reaches the backlog ceiling, and nothing else does.
/// `BacklogGuard` only fills when the *outbound* stops taking bytes while the
/// device keeps offering them — a download cannot produce it, because the
/// direction that stalls is the one with backpressure. Pair this with an
/// impairment applied after the connection is established and the ceiling is
/// the only thing standing between one stalled flow and an unbounded heap.
async fn one_upload(options: &Options, buffer: &mut [u8]) -> std::io::Result<u64> {
    let mut stream = TcpStream::connect(options.target).await?;
    stream.set_nodelay(true)?;
    let mut sent = 0_u64;
    while sent < options.upload_bytes {
        let take = buffer
            .len()
            .min((options.upload_bytes - sent) as usize)
            .max(1);
        stream.write_all(&buffer[..take]).await?;
        sent += take as u64;
    }
    stream.flush().await?;
    Ok(sent)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

fn parse_content_length(header: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(header).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("Content-Length:"))
        .or_else(|| {
            text.lines()
                .find_map(|line| line.strip_prefix("content-length:"))
        })
        .and_then(|value| value.trim().parse().ok())
}

#[derive(Default)]
struct LoadCounters {
    ok: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    bytes: AtomicU64,
    /// Latencies of the requests completed since the last sample, in
    /// microseconds. Drained every sample so the percentiles describe the interval
    /// and not the whole run — a run-wide percentile hides exactly the
    /// degradation this harness is looking for.
    latencies: Mutex<Vec<u64>>,
}

impl LoadCounters {
    fn ok(&self, elapsed: Duration, bytes: u64) {
        self.ok.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        if let Ok(mut latencies) = self.latencies.lock() {
            latencies.push(elapsed.as_micros() as u64);
        }
    }

    fn failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn timed_out(&self) {
        self.timed_out.fetch_add(1, Ordering::Relaxed);
    }

    fn drain_json(&self) -> String {
        let mut latencies = match self.latencies.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => Vec::new(),
        };
        latencies.sort_unstable();
        let pick = |q: f64| -> u64 {
            if latencies.is_empty() {
                return 0;
            }
            let index = ((latencies.len() - 1) as f64 * q).round() as usize;
            latencies[index]
        };
        format!(
            "{{\"ok\":{},\"failed\":{},\"timed_out\":{},\"bytes\":{},\"n\":{},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"max_us\":{}}}",
            self.ok.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.timed_out.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            latencies.len(),
            pick(0.50),
            pick(0.95),
            pick(0.99),
            latencies.last().copied().unwrap_or(0),
        )
    }
}

// ---------------------------------------------------------------------------
// Process statistics
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ProcessStats {
    rss_kb: u64,
    vsz_kb: u64,
    threads: u64,
    fds: u64,
    cpu_s: f64,
}

impl ProcessStats {
    /// Read from `/proc`, which is where the numbers that matter live. On a
    /// host without it the fields stay zero rather than being guessed: a
    /// fabricated RSS trend is worse than none.
    fn read() -> Self {
        let mut stats = Self::default();
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                let mut parts = line.split_whitespace();
                let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                    continue;
                };
                let parsed = value.parse().unwrap_or(0);
                match key {
                    "VmRSS:" => stats.rss_kb = parsed,
                    "VmSize:" => stats.vsz_kb = parsed,
                    "Threads:" => stats.threads = parsed,
                    _ => {}
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            stats.fds = entries.count() as u64;
        }
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat")
            && let Some(tail) = stat.rsplit_once(')').map(|(_, tail)| tail)
        {
            let fields: Vec<&str> = tail.split_whitespace().collect();
            // utime and stime are fields 14 and 15 of `stat`; after splitting on
            // the comm's closing paren the first field here is `state`, so they
            // land at offsets 11 and 12.
            if fields.len() > 12 {
                let ticks = fields[11].parse::<f64>().unwrap_or(0.0)
                    + fields[12].parse::<f64>().unwrap_or(0.0);
                stats.cpu_s = ticks / 100.0;
            }
        }
        stats
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// A sample line. Values that are already JSON go in verbatim; everything else
/// is a string or a number, and the difference is decided by what it looks
/// like, so the output stays readable by `jq` without a schema.
struct Record(Vec<(String, String)>);

impl Record {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn put(&mut self, key: &str, value: impl Into<String>) {
        self.0.push((key.to_owned(), value.into()));
    }
}

fn write_line(out: &mut BufWriter<File>, record: &Record) -> std::io::Result<()> {
    let mut line = String::from("{");
    for (index, (key, value)) in record.0.iter().enumerate() {
        if index != 0 {
            line.push(',');
        }
        line.push('"');
        line.push_str(key);
        line.push_str("\":");
        let structural = value.starts_with('{') || value.starts_with('[');
        let numeric = !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.' || byte == b'-');
        if structural || numeric {
            line.push_str(value);
        } else {
            line.push('"');
            line.push_str(&value.replace('"', "'"));
            line.push('"');
        }
    }
    line.push('}');
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Which half of the harness this process is.
///
/// `Both` is the single-process shape, useful when the destination is not
/// routed through the tunnel the core owns. `Core` and `Load` are the split the
/// netem lab needs, where the routing decision is made on uid.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Core,
    Load,
    /// Accept and discard on `--target`. The other end of the upload arms.
    Sink,
    Both,
}

#[derive(Clone)]
struct Options {
    role: Role,
    config: String,
    tun: String,
    target: SocketAddr,
    host: String,
    path: String,
    concurrency: usize,
    duration_s: u64,
    interval_s: u64,
    pace_ms: u64,
    request_timeout_s: u64,
    /// Non-zero switches the generator from GET to a raw push of this many
    /// bytes. The target then has to be a sink that reads and discards.
    upload_bytes: u64,
    max_response_bytes: Option<u64>,
    network_change_every_s: Option<u64>,
    out: String,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        let mut arguments = arguments.peekable();
        while let Some(flag) = arguments.next() {
            let Some(name) = flag.strip_prefix("--") else {
                return Err(format!("unexpected argument {flag}"));
            };
            let value = arguments
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?;
            values.insert(name.to_owned(), value);
        }
        let take = |key: &str| -> Result<String, String> {
            values
                .get(key)
                .cloned()
                .ok_or_else(|| format!("--{key} is required"))
        };
        let number = |key: &str, default: u64| -> Result<u64, String> {
            match values.get(key) {
                Some(value) => value
                    .parse()
                    .map_err(|_| format!("--{key} is not a number")),
                None => Ok(default),
            }
        };
        let role = match values.get("role").map(String::as_str) {
            None | Some("both") => Role::Both,
            Some("core") => Role::Core,
            Some("load") => Role::Load,
            Some("sink") => Role::Sink,
            Some(other) => {
                return Err(format!("--role {other} is not core, load, sink or both"));
            }
        };
        // The core half never opens a socket to the target, so it does not need
        // one; the load half never reads a config or a device.
        let target: SocketAddr = match values.get("target") {
            Some(value) => value
                .parse()
                .map_err(|_| "--target must be an IP:port the harness will not have to resolve")?,
            None if role == Role::Core => "127.0.0.1:9".parse().expect("literal"),
            None => return Err("--target is required".into()),
        };
        let required_for_core = |key: &str| -> Result<String, String> {
            match role {
                Role::Load | Role::Sink => Ok(String::new()),
                _ => take(key),
            }
        };
        Ok(Self {
            role,
            config: required_for_core("config")?,
            tun: required_for_core("tun")?,
            target,
            host: values
                .get("host")
                .cloned()
                .unwrap_or_else(|| target.ip().to_string()),
            path: values
                .get("path")
                .cloned()
                .unwrap_or_else(|| "/".to_owned()),
            concurrency: number("concurrency", 8)? as usize,
            duration_s: number("duration-s", 300)?,
            interval_s: number("interval-s", 30)?.max(1),
            pace_ms: number("pace-ms", 0)?,
            request_timeout_s: number("request-timeout-s", 30)?,
            upload_bytes: number("upload-bytes", 0)?,
            max_response_bytes: values
                .get("max-response-bytes")
                .and_then(|value| value.parse().ok()),
            network_change_every_s: values
                .get("network-change-every-s")
                .and_then(|value| value.parse().ok()),
            // The sink writes no samples: it is the other end of a measurement,
            // not a party to it.
            out: match role {
                Role::Sink => values.get("out").cloned().unwrap_or_default(),
                _ => take("out")?,
            },
        })
    }
}
