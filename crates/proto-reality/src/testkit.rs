//! A REALITY server, for tests only.
//!
//! The client half of REALITY has always been testable: it is one state machine
//! and it refuses everything it cannot verify. What could not be tested in-tree
//! was the other half of the sentence — *after* a handshake completes, does a
//! carrier above REALITY actually get a clean byte stream? The transports that
//! matter here (gRPC especially) sit on top of the completed stream, and every
//! test that stopped at "the client spoke REALITY first" proved ordering and
//! nothing about the bytes.
//!
//! So this is a minimal REALITY server: enough TLS 1.3 to complete a handshake
//! the real client accepts without relaxing a single one of its checks, and
//! nothing else. It is **not** a REALITY implementation. It does not crawl to a
//! real site, does not fall back, does not serve more than one connection, and
//! makes no attempt to be constant-time. Its whole purpose is to be the far end
//! of a socket so an integration test can assert on what crosses it.
//!
//! Behind the off-by-default `testkit` feature so none of it, and none of
//! `rcgen`, reaches a shipped build.
//!
//! Everything a caller supplies is synthetic by construction: the server's
//! private key is whatever the test passes in.

use std::io;

use aws_lc_rs::{agreement, digest, signature::Ed25519KeyPair};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reality::testkit_internals as internals;

/// The server side of one REALITY connection.
pub struct RealityTestServer {
    private_key: [u8; 32],
    server_name: String,
}

/// What a completed handshake leaves behind, so a test can talk over it.
pub struct RealityTestSession {
    keys: internals::ServerAppKeys,
    initial_record_header: [u8; 5],
}

impl RealityTestSession {
    /// The 5-byte header of the client's very first record, as it arrived.
    ///
    /// Captured by the harness rather than peeked at by the caller: a test that
    /// reads a few bytes off the socket first has to hand them back, and a
    /// hand-rolled push-back reader is its own source of flakiness.
    pub fn initial_record_header(&self) -> [u8; 5] {
        self.initial_record_header
    }
}

impl RealityTestServer {
    /// `private_key` is the REALITY private key whose public half the client
    /// was configured with. `server_name` goes in the certificate.
    pub fn new(private_key: [u8; 32], server_name: impl Into<String>) -> Self {
        Self {
            private_key,
            server_name: server_name.into(),
        }
    }

    /// The X25519 public key a client config must carry for this server.
    pub fn public_key(&self) -> io::Result<[u8; 32]> {
        let key = agreement::PrivateKey::from_private_key(&agreement::X25519, &self.private_key)
            .map_err(|_| io::Error::other("bad X25519 private key"))?;
        let public = key
            .compute_public_key()
            .map_err(|_| io::Error::other("cannot derive public key"))?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(public.as_ref());
        Ok(out)
    }

    /// Run the handshake to completion on `stream`.
    ///
    /// Returns once the client's Finished has been read, at which point the
    /// stream carries application data in both directions.
    pub async fn handshake<S>(&self, stream: &mut S) -> io::Result<RealityTestSession>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // ---- ClientHello -------------------------------------------------
        let (client_hello, initial_record_header) =
            read_record_with_header(stream, internals::CONTENT_TYPE_HANDSHAKE).await?;

        let parsed = internals::parse_client_hello(&client_hello, &self.private_key)?;

        // ---- ServerHello -------------------------------------------------
        let (server_hello, shared_secret) = internals::build_server_hello(&parsed)?;
        let mut record =
            internals::record_header(internals::CONTENT_TYPE_HANDSHAKE, server_hello.len());
        record.extend_from_slice(&server_hello);
        stream.write_all(&record).await?;

        // ---- key schedule ------------------------------------------------
        let mut transcript = digest::Context::new(parsed.cipher_suite.digest_algorithm());
        transcript.update(&client_hello);
        transcript.update(&server_hello);

        let flight = internals::build_encrypted_flight(
            &parsed,
            &shared_secret,
            transcript,
            &self.server_name,
            &client_hello,
            &server_hello,
        )?;
        stream.write_all(&flight.bytes).await?;

        // ---- client Finished ---------------------------------------------
        // Read and discard: the client's Finished is verified by nobody here.
        // A real server checks it; this harness exists to exercise the client,
        // and rejecting the client's Finished would only ever fail a test for
        // a reason the client is not responsible for.
        let _ = read_record(stream, internals::CONTENT_TYPE_APPLICATION_DATA).await?;

        Ok(RealityTestSession {
            keys: flight.keys,
            initial_record_header,
        })
    }
}

impl RealityTestSession {
    /// Read one application-data record and return its plaintext.
    pub async fn read<S>(&mut self, stream: &mut S) -> io::Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let (mut body, record_len) = read_record_raw(stream).await?;
        self.keys.decrypt(&mut body, record_len)
    }

    /// Write `plaintext` as one application-data record.
    pub async fn write<S>(&mut self, stream: &mut S, plaintext: &[u8]) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let record = self.keys.encrypt(plaintext)?;
        stream.write_all(&record).await
    }
}

async fn read_record<S>(stream: &mut S, expected: u8) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    Ok(read_record_with_header(stream, expected).await?.0)
}

/// The record body and the header it arrived under.
async fn read_record_with_header<S>(stream: &mut S, expected: u8) -> io::Result<(Vec<u8>, [u8; 5])>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected record type 0x{expected:02x}, got 0x{:02x}",
                header[0]
            ),
        ));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).await?;
    Ok((body, header))
}

/// The record payload plus the header's length field, which the AEAD needs as
/// part of its AAD.
async fn read_record_raw<S>(stream: &mut S) -> io::Result<(Vec<u8>, u16)>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    let length = u16::from_be_bytes([header[3], header[4]]);
    let mut body = vec![0_u8; length as usize];
    stream.read_exact(&mut body).await?;
    Ok((body, length))
}

/// Re-exported so a test can assert on the record-layer version the client
/// sent without reaching into the crate's private modules.
pub use crate::reality::testkit_internals::observed_initial_record_version;

/// The Ed25519 key type a caller may need to name.
pub type ServerSigningKey = Ed25519KeyPair;
