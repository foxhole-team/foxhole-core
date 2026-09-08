//! The loopback-only server that hands out a [`crate::DownloadPermit`].
//!
//! This is the thing that lives *under* an onion service and nowhere else. Two
//! properties make that structural rather than a matter of configuration:
//!
//! * **There is no address parameter.** [`LoopbackServer::start`] binds
//!   `127.0.0.1` on an ephemeral port and takes nothing that could point it
//!   somewhere else. A caller cannot ask for `0.0.0.0`, for the Wi-Fi address,
//!   or for a fixed port, because none of those are expressible. `stage2` §2
//!   forbids a web server on the phone's Wi-Fi IP; the way to keep that promise
//!   is to make the mistake unrepresentable, not to check a flag.
//! * **The permit is still the only key.** This server does not decide who may
//!   download anything. It parses a request, hands the capability and password
//!   to [`crate::ShareManager::authorize_download`], and streams whatever permit
//!   comes back. Expiry, the download limit, the password and revocation are all
//!   enforced by the vault, on the live read — a share revoked mid-transfer
//!   fails at the next block and the body simply stops.
//!
//! Neither the capability nor the password appears in the URL. They arrive in an
//! `Authorization: Basic` header, which is the one browser-native way to send
//! two secrets without either landing in a path, a log line, a `Referer`, or
//! somebody's screenshot.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{DownloadPermit, FileId, ShareError, ShareId, ShareManager};

/// Concurrent downloads. A phone serving files over an onion service is not a
/// CDN, and an unbounded count is a way for one client to spend every
/// descriptor the process has.
const MAX_DOWNLOADS: usize = 8;
/// How long the accept loop waits after an error before trying again, so a
/// permanent one cannot hold a worker thread at full speed.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(20);
/// Largest request head accepted before the peer is dropped.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Total time allowed to finish an HTTP request head. An onion peer that sends
/// one byte at a time must not pin a download slot and wake the phone forever.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum idle time for any response write. This bounds both header stalls
/// and a receiver that stops consuming an encrypted file mid-transfer.
const IDLE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Plaintext chunks in flight between the decrypting task and the socket.
/// Bounded so a slow reader applies backpressure instead of buffering a file.
const CHUNK_QUEUE: usize = 4;
/// How many downloads may hold a blocking thread at once.
///
/// Decryption runs on the shared blocking pool and holds its thread for the
/// whole transfer, at whatever pace the receiver drains the socket. The other
/// two tenants of that pool are on the data path — the platform DNS resolver
/// and flow attribution — and they hold a thread for microseconds. Without a
/// cap, `MAX_DOWNLOADS` transfers could take every thread and leave a dial by
/// hostname queued behind a stranger's download until it timed out.
///
/// Four, against a pool default of six: two threads stay reserved for the data
/// path whatever the share server is doing. A download over the cap waits for a
/// slot rather than being refused — it already holds one of `MAX_DOWNLOADS`,
/// and refusing here would be a failure invented by an implementation detail.
const MAX_CONCURRENT_DECRYPTS: usize = 4;

/// A running loopback server. Dropping it stops accepting and cancels transfers.
pub struct LoopbackServer {
    address: SocketAddr,
    cancel: CancellationToken,
    alive: Arc<AtomicBool>,
}

impl LoopbackServer {
    /// Bind loopback and start serving.
    ///
    /// There is deliberately no address argument. The only way this server is
    /// reachable from outside the device is an onion service pointed at the
    /// port it reports, and that is the entire design.
    pub fn start(
        manager: Arc<ShareManager>,
        handle: &tokio::runtime::Handle,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let alive = Arc::new(AtomicBool::new(true));

        let accept_cancel = cancel.clone();
        let accept_alive = alive.clone();
        let inner_handle = handle.clone();
        handle.spawn(async move {
            let _alive = AliveGuard(accept_alive);
            let Ok(listener) = TcpListener::from_std(listener) else {
                return;
            };
            let slots = Arc::new(Semaphore::new(MAX_DOWNLOADS));
            loop {
                let accepted = tokio::select! {
                    _ = accept_cancel.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, peer)) = accepted else {
                    // Backed off rather than retried immediately: a permanent
                    // accept error returns at syscall speed and `continue` has
                    // no await point, so this loop would occupy one of the
                    // runtime's two worker threads outright. See the same fix
                    // and the device symptom in `foxcore-component::lan`.
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                };
                // Belt and braces beside the bind: if anything ever routes a
                // non-loopback peer here, it is refused rather than served.
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let manager = manager.clone();
                let clock = clock.clone();
                let cancel = accept_cancel.clone();
                let handle = inner_handle.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = serve(stream, manager, clock, handle) => {}
                    }
                });
            }
        });

        Ok(Self {
            address,
            cancel,
            alive,
        })
    }

    /// The loopback address an onion service should be pointed at.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Whether this server has been told to stop.
    ///
    /// Set synchronously by [`Self::stop`], before the accept loop notices. A
    /// caller that must shut things down in a particular order can therefore
    /// check the order actually happened, rather than inferring it from whether
    /// the socket has finished closing — which it will not have, yet.
    pub fn is_stopped(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Whether the accept task still exists and has not been cancelled.
    pub fn is_running(&self) -> bool {
        !self.cancel.is_cancelled() && self.alive.load(Ordering::Acquire)
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.stop();
    }
}

struct AliveGuard(Arc<AtomicBool>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// What a request asked for. Ids only; the secrets travel in a header.
struct Request {
    share: ShareId,
    file: FileId,
    capability: Vec<u8>,
    password: Option<Vec<u8>>,
}

async fn serve(
    mut stream: TcpStream,
    manager: Arc<ShareManager>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    handle: tokio::runtime::Handle,
) {
    let Some(head) = read_head(&mut stream).await else {
        let _ = respond(&mut stream, 400, "Bad Request", &[]).await;
        return;
    };
    let Some(request) = parse_request(&head) else {
        // Missing or malformed credentials get the challenge, not a hint about
        // whether the share exists.
        let _ = respond(
            &mut stream,
            401,
            "Unauthorized",
            &[("WWW-Authenticate", "Basic realm=\"foxhole-share\"")],
        )
        .await;
        return;
    };

    // Off the worker thread, because this call is not the cheap lookup its name
    // suggests: it verifies an Argon2id password (about 19 MiB and tens of
    // milliseconds on a phone) and then writes the session manifest with two
    // fsyncs. Those worker threads carry the data plane, and there are four of
    // them; a handful of download attempts arriving together used to make the
    // tunnel stutter while the CPU sat in a hash. It also cannot be cancelled
    // once started, so it would extend `nativeStop` by however long the flash
    // took to sync.
    let authorize = {
        let manager = manager.clone();
        let now_ms = clock();
        handle.spawn_blocking(move || {
            manager.authorize_download(
                request.share,
                request.file,
                &request.capability,
                request.password.as_deref(),
                now_ms,
            )
        })
    };
    let Ok(permit) = authorize.await else {
        // The blocking task itself failed — a panic inside the vault, or the
        // pool shutting down under a stop. Answered like any other refusal so
        // this cannot be told apart from a wrong capability.
        let _ = respond(&mut stream, 401, "Unauthorized", &[]).await;
        return;
    };
    let permit = match permit {
        Ok(permit) => permit,
        Err(error) => {
            // One status for every refusal that could distinguish a real share
            // from an invented one. A 404 for "no such share" and a 403 for
            // "wrong password" would turn this into an oracle for guessing
            // capabilities.
            let (code, text) = match error {
                ShareError::Expired | ShareError::DownloadLimit | ShareError::Revoked => {
                    (410, "Gone")
                }
                _ => (401, "Unauthorized"),
            };
            let _ = respond(&mut stream, code, text, &[]).await;
            return;
        }
    };

    stream_permit(stream, permit, handle).await;
}

/// Send the file, decrypting on a blocking task and writing from this one.
///
/// `write_plaintext` is synchronous and authenticates every block, so it cannot
/// run on the async path. The channel between the two is bounded: a slow reader
/// stops the decryption rather than letting it buffer a whole file, and a peer
/// that disappears drops the receiver, which fails the next write and ends the
/// blocking task instead of leaving it running.
/// Process-wide, because the blocking pool it rations is process-wide: two
/// engines sharing one runtime would otherwise each grant the full cap.
fn decrypt_slots() -> &'static Arc<Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_DECRYPTS)))
}

async fn stream_permit(stream: TcpStream, permit: DownloadPermit, handle: tokio::runtime::Handle) {
    let revoked = permit.revoked.clone();
    let deadline = tokio::time::Instant::from_std(permit.deadline);
    tokio::select! {
        biased;
        _ = revoked.cancelled() => {},
        _ = tokio::time::sleep_until(deadline) => {},
        _ = stream_permit_inner(stream, permit, handle) => {},
    }
}

async fn stream_permit_inner(
    mut stream: TcpStream,
    permit: DownloadPermit,
    handle: tokio::runtime::Handle,
) {
    let length = permit.expected_bytes();
    let headers = [
        ("Content-Type", "application/octet-stream"),
        // The receiver saves it. Nothing here invites a browser to open it, and
        // nothing unpacks an archive: `stage2` §2 forbids both, and the server
        // is where that starts.
        ("Content-Disposition", "attachment"),
        ("X-Content-Type-Options", "nosniff"),
        ("Cache-Control", "no-store"),
    ];
    if respond_with_length(&mut stream, 200, "OK", &headers, length)
        .await
        .is_err()
    {
        return;
    }

    let Ok(decrypt_slot) = decrypt_slots().clone().acquire_owned().await else {
        return;
    };
    let (sender, mut chunks) = mpsc::channel::<zeroize::Zeroizing<Vec<u8>>>(CHUNK_QUEUE);
    let decrypt = handle.spawn_blocking(move || {
        // Held for the length of the transfer and released with the closure,
        // including on an early return or a panic inside the decrypt.
        let _decrypt_slot = decrypt_slot;
        let mut writer = ChannelWriter { sender };
        permit.write_plaintext(&mut writer)
    });

    while let Some(chunk) = chunks.recv().await {
        if write_all_with_timeout(&mut stream, &chunk, IDLE_WRITE_TIMEOUT)
            .await
            .is_err()
        {
            break;
        }
    }
    // Dropping the receiver is what stops the decrypting task if we broke out
    // above; awaiting it keeps the transfer's outcome from being ignored.
    drop(chunks);
    let _ = decrypt.await;
    let _ = tokio::time::timeout(IDLE_WRITE_TIMEOUT, stream.flush()).await;
    // A revoked or damaged share stops the body early. The Content-Length was
    // already sent, so the receiver sees a short read — which is exactly the
    // signal it should see, rather than a file that looks complete.
}

struct ChannelWriter {
    sender: mpsc::Sender<zeroize::Zeroizing<Vec<u8>>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.sender
            .blocking_send(zeroize::Zeroizing::new(buffer.to_vec()))
            .map(|()| buffer.len())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "download peer is gone"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    read_head_with_timeout(stream, REQUEST_HEAD_TIMEOUT).await
}

async fn read_head_with_timeout(stream: &mut TcpStream, limit: Duration) -> Option<String> {
    tokio::time::timeout(limit, read_head_until_complete(stream))
        .await
        .ok()
        .flatten()
}

async fn read_head_until_complete(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if head.len() >= MAX_HEAD_BYTES {
            return None;
        }
        let remaining = MAX_HEAD_BYTES - head.len();
        let read_length = remaining.min(buffer.len());
        let count = stream.read(&mut buffer[..read_length]).await.ok()?;
        if count == 0 {
            return None;
        }
        head.extend_from_slice(&buffer[..count]);
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            head.truncate(end);
            return String::from_utf8(head).ok();
        }
    }
}

/// `GET /<share-hex>/<file-hex>` plus `Authorization: Basic
/// base64(capability-hex ":" password)`.
///
/// The capability is the Basic *username* and the share password is the Basic
/// *password*. That mapping is not cosmetic: it is what keeps both out of the
/// URL while still working in a plain browser, where the 401 challenge produces
/// exactly two fields.
fn parse_request(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split(' ');
    // Only GET. No upload, no listing, no method that could change anything.
    if start.next()? != "GET" {
        return None;
    }
    let path = start.next()?;
    // Fixed-length hex ids, so there is no path to traverse and nothing to
    // percent-decode.
    let mut segments = path.strip_prefix('/')?.split('/');
    let share = ShareId::from_hex(segments.next()?)?;
    let file = FileId::from_hex(segments.next()?)?;
    if segments.next().is_some() {
        return None;
    }

    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("authorization") {
            authorization = decode_basic(value.trim());
        }
    }
    let (capability, password) = authorization?;
    Some(Request {
        share,
        file,
        capability,
        password,
    })
}

fn decode_basic(value: &str) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    use base64::Engine as _;

    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let capability = decode_hex(std::str::from_utf8(&decoded[..separator]).ok()?)?;
    let password = &decoded[separator + 1..];
    Some((
        capability,
        (!password.is_empty()).then(|| password.to_vec()),
    ))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.is_empty() || !value.is_ascii() {
        return None;
    }
    (0..value.len() / 2)
        .map(|index| u8::from_str_radix(value.get(index * 2..index * 2 + 2)?, 16).ok())
        .collect()
}

async fn respond(
    stream: &mut TcpStream,
    code: u16,
    text: &str,
    headers: &[(&str, &str)],
) -> io::Result<()> {
    respond_with_length(stream, code, text, headers, 0).await
}

async fn respond_with_length(
    stream: &mut TcpStream,
    code: u16,
    text: &str,
    headers: &[(&str, &str)],
    length: u64,
) -> io::Result<()> {
    let mut response = format!("HTTP/1.1 {code} {text}\r\nContent-Length: {length}\r\n");
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");
    write_all_with_timeout(stream, response.as_bytes(), IDLE_WRITE_TIMEOUT).await
}

async fn write_all_with_timeout<W>(writer: &mut W, bytes: &[u8], limit: Duration) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(limit, writer.write_all(bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "share peer stopped reading"))?
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_request_carries_ids_in_the_path_and_secrets_in_the_header() {
        use base64::Engine as _;

        let share = [0x11_u8; 16];
        let file = [0x22_u8; 16];
        let credentials = base64::engine::general_purpose::STANDARD.encode("aabb:hunter2");
        let head = format!(
            "GET /{}/{} HTTP/1.1\r\nHost: x.onion\r\nAuthorization: Basic {credentials}",
            crate::encode_hex(&share),
            crate::encode_hex(&file)
        );

        let request = parse_request(&head).expect("a well-formed request");
        assert_eq!(request.capability, vec![0xaa, 0xbb]);
        assert_eq!(request.password.as_deref(), Some(&b"hunter2"[..]));
        assert!(
            !head.contains("hunter2") || head.contains("Authorization"),
            "the password must only ever appear inside the header"
        );
    }

    #[test]
    fn a_request_without_credentials_is_not_a_request() {
        let head = format!(
            "GET /{}/{} HTTP/1.1\r\nHost: x.onion",
            crate::encode_hex(&[0x11_u8; 16]),
            crate::encode_hex(&[0x22_u8; 16])
        );
        assert!(
            parse_request(&head).is_none(),
            "anonymous download is not a mode this server has"
        );
    }

    #[test]
    fn nothing_but_a_plain_two_segment_get_is_accepted() {
        use base64::Engine as _;

        let credentials = base64::engine::general_purpose::STANDARD.encode("aa:");
        let share = crate::encode_hex(&[0x11_u8; 16]);
        let file = crate::encode_hex(&[0x22_u8; 16]);
        let with = |line: String| format!("{line}\r\nAuthorization: Basic {credentials}");

        assert!(parse_request(&with(format!("GET /{share}/{file} HTTP/1.1"))).is_some());
        // No method that could change anything.
        assert!(parse_request(&with(format!("POST /{share}/{file} HTTP/1.1"))).is_none());
        assert!(parse_request(&with(format!("DELETE /{share}/{file} HTTP/1.1"))).is_none());
        // No traversal, no listing, no extra segments.
        assert!(parse_request(&with(format!("GET /{share}/{file}/.. HTTP/1.1"))).is_none());
        assert!(parse_request(&with(format!("GET /{share} HTTP/1.1"))).is_none());
        assert!(parse_request(&with("GET /../../etc/passwd HTTP/1.1".to_owned())).is_none());
        // An id that is not exactly the right length of hex is not an id.
        assert!(parse_request(&with(format!("GET /{share}/beef HTTP/1.1"))).is_none());
    }

    #[test]
    fn an_empty_basic_password_means_no_password_not_an_empty_one() {
        use base64::Engine as _;

        let credentials = base64::engine::general_purpose::STANDARD.encode("aabb:");
        let head = format!(
            "GET /{}/{} HTTP/1.1\r\nAuthorization: Basic {credentials}",
            crate::encode_hex(&[0x11_u8; 16]),
            crate::encode_hex(&[0x22_u8; 16])
        );
        let request = parse_request(&head).unwrap();
        assert!(
            request.password.is_none(),
            "a share with no password must not be sent an empty one to compare"
        );
    }

    // ---- end to end over the real loopback socket ----

    use crate::{ShareConfig, ShareManager};

    const NOW: u64 = 1_000_000;
    const PASSWORD: &[u8] = b"correct horse";

    #[tokio::test]
    async fn expiry_cancels_a_backpressured_download_without_control_operations() {
        let vault = vault(8 * 1024 * 1024, None, 1);
        let download = decode_hex(&vault.download).unwrap();
        let mut permit = vault
            .manager
            .authorize_download(vault.share, vault.file, &download, None, NOW)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        permit.deadline = std::time::Instant::now() + Duration::from_millis(100);
        let serving = tokio::spawn(stream_permit(
            stream,
            permit,
            tokio::runtime::Handle::current(),
        ));
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap();
        let mut body = Vec::new();
        peer.read_to_end(&mut body).await.unwrap();
        assert!(body.len() < vault.content.len());
    }

    struct Vault {
        _root: tempfile::TempDir,
        manager: Arc<ShareManager>,
        share: ShareId,
        file: FileId,
        download: String,
        owner: Vec<u8>,
        content: Vec<u8>,
    }

    fn vault(bytes: usize, password: Option<&[u8]>, max_downloads: u32) -> Vault {
        let root = tempfile::tempdir().unwrap();
        let manager = Arc::new(ShareManager::open(root.path(), [5_u8; 32]).unwrap());
        let created = manager
            .create(
                NOW,
                ShareConfig {
                    expires_at_ms: NOW + 60_000,
                    max_downloads,
                },
                password,
            )
            .unwrap();
        let content: Vec<u8> = (0..bytes).map(|index| (index % 251) as u8).collect();
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                NOW,
                "report.bin",
                "application/octet-stream",
                content.len() as u64,
                &mut content.as_slice(),
            )
            .unwrap();
        Vault {
            _root: root,
            manager,
            share: created.id,
            file: file.id,
            download: crate::encode_hex(created.download.as_bytes()),
            owner: created.owner.as_bytes().to_vec(),
            content,
        }
    }

    fn credentials(capability: &str, password: Option<&[u8]>) -> String {
        use base64::Engine as _;

        let mut raw = capability.as_bytes().to_vec();
        raw.push(b':');
        if let Some(password) = password {
            raw.extend_from_slice(password);
        }
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    /// Opens a raw connection so the test controls when the body is read —
    /// which is what makes the revoke case observable.
    async fn request(
        address: SocketAddr,
        vault: &Vault,
        capability: &str,
        password: Option<&[u8]>,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let head = format!(
            "GET /{}/{} HTTP/1.1\r\nHost: x.onion\r\nAuthorization: Basic {}\r\n\r\n",
            vault.share.to_hex(),
            vault.file.to_hex(),
            credentials(capability, password)
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream
    }

    async fn read_all(mut stream: TcpStream) -> (String, Vec<u8>) {
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a response head");
        (
            String::from_utf8_lossy(&raw[..split]).to_string(),
            raw[split + 4..].to_vec(),
        )
    }

    fn server(vault: &Vault) -> LoopbackServer {
        LoopbackServer::start(
            vault.manager.clone(),
            &tokio::runtime::Handle::current(),
            Arc::new(|| NOW),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_listener_is_loopback_and_nothing_else() {
        let vault = vault(64, None, 3);
        let server = server(&vault);
        assert!(
            server.address().ip().is_loopback(),
            "a share server on a routable address is the thing stage2 forbids outright"
        );
        assert_ne!(server.address().port(), 0);
        assert!(server.is_running());
    }

    #[tokio::test]
    async fn a_partial_request_head_times_out_instead_of_holding_a_slot() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server_side, _) = listener.accept().await.unwrap();
        client.write_all(b"G").await.unwrap();

        assert!(
            read_head_with_timeout(&mut server_side, Duration::from_millis(25))
                .await
                .is_none(),
        );
    }

    #[tokio::test]
    async fn a_stalled_writer_is_bounded_by_the_idle_timeout() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let error = write_all_with_timeout(&mut writer, &[7_u8; 64], Duration::from_millis(25))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_correct_capability_and_password_get_the_file_back_byte_for_byte() {
        let vault = vault(200_000, Some(PASSWORD), 3);
        let server = server(&vault);

        let stream = request(server.address(), &vault, &vault.download, Some(PASSWORD)).await;
        let (head, body) = read_all(stream).await;

        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(
            head.contains("Content-Disposition: attachment"),
            "the receiver saves it; nothing here invites a browser to open it: {head}"
        );
        assert!(head.contains("X-Content-Type-Options: nosniff"), "{head}");
        assert_eq!(body, vault.content);
    }

    #[tokio::test]
    async fn a_wrong_password_and_a_missing_one_are_the_same_answer() {
        let vault = vault(1_024, Some(PASSWORD), 3);
        let server = server(&vault);

        let (wrong, _) =
            read_all(request(server.address(), &vault, &vault.download, Some(b"guess")).await)
                .await;
        assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");

        let (none, _) =
            read_all(request(server.address(), &vault, &vault.download, None).await).await;
        assert!(none.starts_with("HTTP/1.1 401"), "{none}");

        // A capability that was never minted must look exactly like a wrong
        // password, or this is an oracle for guessing them.
        let (forged, _) =
            read_all(request(server.address(), &vault, &"aa".repeat(32), Some(PASSWORD)).await)
                .await;
        assert!(forged.starts_with("HTTP/1.1 401"), "{forged}");
    }

    #[tokio::test]
    async fn the_download_limit_is_enforced_by_the_vault_not_by_the_server() {
        let vault = vault(512, None, 2);
        let server = server(&vault);

        for _ in 0..2 {
            let (head, body) =
                read_all(request(server.address(), &vault, &vault.download, None).await).await;
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            assert_eq!(body.len(), vault.content.len());
        }

        let (exhausted, _) =
            read_all(request(server.address(), &vault, &vault.download, None).await).await;
        assert!(exhausted.starts_with("HTTP/1.1 410"), "{exhausted}");
    }

    /// The requirement that makes revoke mean something: it has to reach a
    /// transfer that is already running, not just refuse the next one. The
    /// vault checks on every block, so the body stops mid-file — and because a
    /// Content-Length was already sent, the receiver can tell.
    #[tokio::test]
    async fn revoking_mid_transfer_cuts_the_body_short_rather_than_completing_it() {
        // Large enough to span many 64 KiB blocks, so the transfer is still
        // running while the test revokes it.
        let vault = vault(4 * 1024 * 1024, None, 5);
        let server = server(&vault);

        let mut stream = request(server.address(), &vault, &vault.download, None).await;

        // Read just the head, then stall: the bounded chunk queue means the
        // decrypting task is parked partway through the file.
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).to_string();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(
            head.contains(&format!("Content-Length: {}", vault.content.len())),
            "the length must be declared so a short body is detectable: {head}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;

        vault.manager.revoke(vault.share, &vault.owner).unwrap();

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert!(
            body.len() < vault.content.len(),
            "a revoked share must stop mid-transfer, got all {} bytes",
            body.len()
        );
    }

    /// And the share is gone afterwards, so nothing new is served either.
    #[tokio::test]
    async fn a_revoked_share_serves_nothing_afterwards() {
        let vault = vault(4_096, None, 5);
        let server = server(&vault);
        vault.manager.revoke(vault.share, &vault.owner).unwrap();

        let (head, body) =
            read_all(request(server.address(), &vault, &vault.download, None).await).await;
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn stopping_the_server_closes_the_port() {
        let vault = vault(64, None, 3);
        let address = {
            let server = server(&vault);
            let address = server.address();
            server.stop();
            address
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if std::net::TcpListener::bind(address).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("a stopped share server must not keep its port");
    }
}
