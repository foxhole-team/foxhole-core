//! JA3 and JA4 for the generic (rustls) ClientHello, computed here and
//! **validated against a live detector**.
//!
//! The parrot work had never been checked against anything that actually
//! fingerprints TLS. This file closes that: `the_local_computation_matches_a_live_detector`
//! opens a real connection to `tls.browserleaks.com`, records the exact bytes
//! this core put on the wire, computes JA3/JA4 from those bytes, and asserts
//! the result equals what the detector independently computed for the same
//! connection.
//!
//! That is the point of the exercise. Once the computation is confirmed
//! correct against a third party, it can be pointed at any hello — including
//! the REALITY parrots, which cannot themselves reach a public detector because
//! they only complete a handshake against a REALITY server.
//!
//! The network test is `#[ignore]`d: `cargo test --workspace` must not depend
//! on a third-party service being up. Run it deliberately:
//!
//! ```text
//! cargo test -p foxcore-transport --test ja_fingerprint -- --ignored --nocapture
//! ```
//!
//! No credentials and no user data are involved: the request is a plain GET for
//! a public JSON endpoint that reports the fingerprint of the caller's own
//! ClientHello.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use foxcore_api::TlsConfig;
use foxcore_transport::{ja, rustls_client_config};

/// A `TcpStream` that keeps a copy of everything written to it.
struct Recording {
    inner: TcpStream,
    written: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Read for Recording {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl std::io::Write for Recording {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(data)?;
        self.written
            .lock()
            .unwrap()
            .extend_from_slice(&data[..written]);
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

const DETECTOR_HOST: &str = "tls.browserleaks.com";

/// Confirm the JA3/JA4 implementation above against a third party.
///
/// This is the measurement that had never been done. It proves two things at
/// once: that this core's generic ClientHello produces the fingerprint recorded
/// below, and that the computation used to fingerprint the REALITY parrots
/// (which cannot reach a public detector) is correct.
#[test]
#[ignore = "reaches tls.browserleaks.com; run deliberately"]
fn the_local_computation_matches_a_live_detector() {
    let mut tls = TlsConfig {
        enabled: true,
        server_name: Some(DETECTOR_HOST.to_owned()),
        ..TlsConfig::default()
    };
    tls.alpn = vec!["http/1.1".to_owned()];
    let config = rustls_client_config(&tls).expect("client config");

    let name = rustls::pki_types::ServerName::try_from(DETECTOR_HOST).unwrap();
    let mut connection = rustls::ClientConnection::new(config, name).expect("connection");
    let written = Arc::new(Mutex::new(Vec::new()));
    let mut socket = Recording {
        inner: TcpStream::connect((DETECTOR_HOST, 443)).expect("connect"),
        written: Arc::clone(&written),
    };

    let mut tls_stream = rustls::Stream::new(&mut connection, &mut socket);
    tls_stream
        .write_all(
            format!("GET /json HTTP/1.1\r\nHost: {DETECTOR_HOST}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("request");
    let mut response = Vec::new();
    let _ = tls_stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response).into_owned();

    // Our own hello, exactly as it left the socket.
    let recorded = written.lock().unwrap().clone();
    assert_eq!(recorded[0], 0x16, "first record is the handshake");
    let hello = ja::parse(&recorded[5..]);

    let ours_ja3 = ja::ja3_hash(&hello);
    let (ours_ja4, ours_ja4_raw) = ja::ja4(&hello);

    let field = |name: &str| -> String {
        response
            .split(&format!("\"{name}\": \""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_owned()
    };
    let theirs_ja3 = field("ja3_hash");
    let theirs_ja4 = field("ja4");
    let theirs_ja4_raw = field("ja4_r");

    println!("--- FoxCore generic (rustls) ClientHello ---");
    println!("  JA3  ours   {ours_ja3}");
    println!("  JA3  server {theirs_ja3}");
    println!("  JA4  ours   {ours_ja4}");
    println!("  JA4  server {theirs_ja4}");
    println!("  JA4_r ours   {ours_ja4_raw}");
    println!("  JA4_r server {theirs_ja4_raw}");

    assert!(
        !theirs_ja3.is_empty(),
        "detector returned no ja3: {response}"
    );
    assert_eq!(ours_ja3, theirs_ja3, "JA3 disagrees with the detector");
    assert_eq!(ours_ja4, theirs_ja4, "JA4 disagrees with the detector");
}

/// The JA4 of the configuration this core actually ships.
///
/// The live test above pins ALPN to `http/1.1`, because the detector's JSON has
/// to be read back over HTTP/1.1 and the endpoint negotiates h2 whenever it is
/// offered. The shipped default offers `h2, http/1.1`, so its JA4_a ends `h2`
/// rather than `h1`.
///
/// This computes both locally, with the implementation the live test confirms
/// against a third party character for character, and asserts the only
/// difference is the two-character ALPN field. That is what lets the
/// detector-measured number stand in for the shipped one.
///
/// Local, offline, and safe to run in CI.
#[test]
fn the_shipped_default_differs_from_the_measured_hello_only_in_alpn() {
    // What the live test measured, and what the detector independently agreed
    // it was.
    const MEASURED: &str = "t13d1011h1_61a7ad8aa9b6_f9531d972513";

    let mut http1 = TlsConfig {
        enabled: true,
        server_name: Some("measure.example".to_owned()),
        ..TlsConfig::default()
    };
    http1.alpn = vec!["http/1.1".to_owned()];
    let (http1_ja4, _) = ja::ja4(&ja::parse(&capture_local(&http1)[5..]));
    assert_eq!(
        http1_ja4, MEASURED,
        "the local computation no longer reproduces the detector-confirmed value; \
         re-run the live test before trusting anything else here"
    );

    // The shipped default: no ALPN in the profile, so `h2, http/1.1` applies.
    let default = TlsConfig {
        enabled: true,
        server_name: Some("measure.example".to_owned()),
        ..TlsConfig::default()
    };
    assert!(default.alpn.is_empty());
    let (default_ja4, _) = ja::ja4(&ja::parse(&capture_local(&default)[5..]));

    let (a1, rest1) = http1_ja4.split_once('_').expect("JA4_a");
    let (a2, rest2) = default_ja4.split_once('_').expect("JA4_a");
    assert_eq!(rest1, rest2, "both hashed halves must be identical");
    assert_eq!(&a1[..a1.len() - 2], &a2[..a2.len() - 2], "prefix identical");
    assert_eq!(&a1[a1.len() - 2..], "h1");
    assert_eq!(&a2[a2.len() - 2..], "h2");
    println!("shipped-default JA4: {default_ja4}");
}

/// One ClientHello record, captured off a loopback socket.
fn capture_local(tls: &TlsConfig) -> Vec<u8> {
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let config = rustls_client_config(tls).expect("client config");
    let client = std::thread::spawn(move || {
        let name = rustls::pki_types::ServerName::try_from("measure.example").unwrap();
        let mut connection = rustls::ClientConnection::new(config, name).expect("connection");
        let mut socket = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let _ = connection.write_tls(&mut socket);
    });
    let (mut server, _) = listener.accept().expect("accept");
    let mut buffer = vec![0_u8; 8192];
    let read = server.read(&mut buffer).expect("read");
    buffer.truncate(read);
    drop(server);
    let _ = client.join();
    buffer
}
