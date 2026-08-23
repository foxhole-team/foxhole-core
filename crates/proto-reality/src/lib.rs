#![forbid(unsafe_code)]

//! Client-only REALITY transport.
//!
//! The public boundary accepts decoded fixed-size authentication material and
//! returns a bounded task-backed Tokio stream. A real certificate or an HMAC
//! mismatch is always rejected; FoxCore never enters Xray's crawler fallback.

mod buf_reader;
mod reality;

mod slide_buffer;
#[cfg(feature = "testkit")]
pub mod testkit;

use std::io::{self, BufRead as _, Write as _};
use std::time::Duration;

use foxcore_transport::{InnerCodec, PassthroughCodec, RecordLayer, spawn_relay};
#[cfg(feature = "fuzzing")]
pub use reality::fuzz_records as fuzz_internals;
pub use reality::{
    CipherSuite, RealityHello, RealityHelloProfile, clear_fingerprint_tables, decode_public_key,
    decode_short_id, install_fingerprint_tables, using_downloaded_fingerprint_tables,
};
use reality::{RealityClientConfig, RealityClientConnection};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

const TLS_IO_BUFFER_SIZE: usize = 16 * 1024;
const STREAM_BUFFER_CAPACITY: usize = 64 * 1024;
const MAX_HANDSHAKE_ITERATIONS: usize = 64;

/// Complete a REALITY handshake over an already protected TCP socket and
/// return a bounded plaintext stream.
pub async fn wrap_reality<S>(
    stream: S,
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
    hello: RealityHello,
    handshake_timeout: Duration,
) -> io::Result<DuplexStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    wrap_reality_spliced(
        stream,
        public_key,
        short_id,
        server_name,
        hello,
        handshake_timeout,
        PassthroughCodec,
    )
    .await
}

/// Like [`wrap_reality`], but an inner codec rides above the record layer and
/// may take the socket over mid-stream (XTLS-style flows).
///
/// The handover is only exact because the relay frames records itself; see
/// [`foxcore_transport::splice`].
pub async fn wrap_reality_spliced<S, C>(
    mut stream: S,
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
    hello: RealityHello,
    handshake_timeout: Duration,
    codec: C,
) -> io::Result<DuplexStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    C: InnerCodec,
{
    validate_server_name(&server_name)?;
    if handshake_timeout.is_zero() || handshake_timeout > Duration::from_secs(60) {
        return Err(invalid("REALITY handshake timeout must be in 1ms..=60s"));
    }

    let mut connection = RealityClientConnection::new(RealityClientConfig {
        public_key,
        short_id,
        server_name,
        hello,
    })?;

    tokio::time::timeout(
        handshake_timeout,
        perform_handshake(&mut connection, &mut stream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "REALITY handshake timed out"))??;

    Ok(spawn_relay(
        stream,
        RealityRecordLayer(connection),
        codec,
        STREAM_BUFFER_CAPACITY,
    ))
}

/// [`RecordLayer`] over a completed REALITY handshake.
struct RealityRecordLayer(RealityClientConnection);

impl RecordLayer for RealityRecordLayer {
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        self.0.read_tls(rd)
    }

    fn process_new_packets(&mut self) -> io::Result<()> {
        self.0.process_new_packets()
    }

    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        let mut reader = self.0.reader();
        loop {
            match reader.fill_buf() {
                Ok([]) => return Ok(true),
                Ok(available) => {
                    let count = available.len();
                    out.extend_from_slice(available);
                    reader.consume(count);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            }
        }
    }

    fn write_plaintext(&mut self, data: &[u8]) -> io::Result<()> {
        self.0.writer().write_all(data)
    }

    fn write_tls(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        while self.0.wants_write() {
            let before = out.len();
            self.0.write_tls(out)?;
            if out.len() == before {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "REALITY record writer made no progress",
                ));
            }
        }
        Ok(())
    }

    fn send_close_notify(&mut self) {
        self.0.send_close_notify();
    }
}

async fn perform_handshake<S>(
    connection: &mut RealityClientConnection,
    stream: &mut S,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut incoming = vec![0_u8; TLS_IO_BUFFER_SIZE];

    for _ in 0..MAX_HANDSHAKE_ITERATIONS {
        let wrote = drain_ciphertext(connection, stream).await?;
        if wrote {
            stream.flush().await?;
        }

        if !connection.is_handshaking() {
            let wrote = drain_ciphertext(connection, stream).await?;
            if wrote {
                stream.flush().await?;
            }
            return Ok(());
        }
        if !connection.wants_read() && !connection.wants_write() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY handshake state stalled",
            ));
        }

        if connection.wants_read() {
            let count = stream.read(&mut incoming).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during REALITY handshake",
                ));
            }
            feed_ciphertext(connection, &incoming[..count])?;
            connection.process_new_packets()?;
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "REALITY handshake iteration limit exceeded",
    ))
}

fn feed_ciphertext(connection: &mut RealityClientConnection, data: &[u8]) -> io::Result<()> {
    let mut cursor = io::Cursor::new(data);
    while cursor.position() < data.len() as u64 {
        let count = connection.read_tls(&mut cursor)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY ciphertext feeder made no progress",
            ));
        }
    }
    Ok(())
}

async fn drain_ciphertext<S>(
    connection: &mut RealityClientConnection,
    stream: &mut S,
) -> io::Result<bool>
where
    S: AsyncWrite + Unpin,
{
    let mut output = Vec::with_capacity(TLS_IO_BUFFER_SIZE);
    while connection.wants_write() {
        let before = output.len();
        connection.write_tls(&mut output)?;
        if output.len() == before {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "REALITY record writer made no progress",
            ));
        }
    }
    if output.is_empty() {
        return Ok(false);
    }
    stream.write_all(&output).await?;
    Ok(true)
}

fn validate_server_name(value: &str) -> io::Result<()> {
    let value = value.trim_end_matches('.');
    if value.is_empty()
        || value.len() > 253
        || value.parse::<std::net::IpAddr>().is_ok()
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid("REALITY server name must be an ASCII DNS name"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use aws_lc_rs::agreement;
    use tokio::io::ReadBuf;

    struct WriteGate {
        open: AtomicBool,
        blocked: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl WriteGate {
        fn new() -> Self {
            Self {
                open: AtomicBool::new(false),
                blocked: AtomicBool::new(false),
                waker: Mutex::new(None),
            }
        }

        fn open(&self) {
            self.open.store(true, Ordering::Release);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }
    }

    struct GatedNetwork(Arc<WriteGate>);

    impl AsyncRead for GatedNetwork {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for GatedNetwork {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.0.open.load(Ordering::Acquire) {
                return Poll::Ready(Ok(buf.len()));
            }
            let mut waker = self.0.waker.lock().unwrap();
            *waker = Some(cx.waker().clone());
            if self.0.open.load(Ordering::Acquire) {
                waker.take();
                return Poll::Ready(Ok(buf.len()));
            }
            self.0.blocked.store(true, Ordering::Release);
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn completed_test_connection() -> RealityClientConnection {
        let private = [0x42_u8; 32];
        let key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private).unwrap();
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(key.compute_public_key().unwrap().as_ref());
        RealityClientConnection::new(RealityClientConfig {
            public_key,
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            server_name: "example.com".to_owned(),
            hello: RealityHelloProfile::Chrome133.into(),
        })
        .unwrap()
        .complete_for_test()
        .unwrap()
    }

    #[test]
    fn validates_dns_server_names() {
        assert!(validate_server_name("www.example.com").is_ok());
        assert!(validate_server_name("127.0.0.1").is_err());
        assert!(validate_server_name("bad name").is_err());
        assert!(validate_server_name("-bad.example").is_err());
    }

    #[tokio::test]
    async fn blocked_network_applies_backpressure_and_wakes_the_application_writer() {
        let gate = Arc::new(WriteGate::new());
        let network = GatedNetwork(Arc::clone(&gate));
        let mut application = spawn_relay(
            network,
            RealityRecordLayer(completed_test_connection()),
            PassthroughCodec,
            STREAM_BUFFER_CAPACITY,
        );
        let payload = vec![0x5a; STREAM_BUFFER_CAPACITY + 2 * TLS_IO_BUFFER_SIZE];
        let mut writer = tokio::spawn(async move {
            application.write_all(&payload).await?;
            Ok::<_, io::Error>(application)
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.blocked.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay never reached the blocked network writer");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut writer)
                .await
                .is_err(),
            "application write completed while network output was blocked"
        );

        gate.open();
        let application = tokio::time::timeout(Duration::from_secs(1), &mut writer)
            .await
            .expect("application writer was not woken")
            .expect("application writer task panicked")
            .expect("application writer failed");
        drop(application);
    }
}
