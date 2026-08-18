use std::io;

use aws_lc_rs::{agreement, digest, signature::Ed25519KeyPair};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reality::testkit_internals as internals;

pub struct RealityTestServer {
    private_key: [u8; 32],
    server_name: String,
}

pub struct RealityTestSession {
    keys: internals::ServerAppKeys,
    initial_record_header: [u8; 5],
}

impl RealityTestSession {
    pub fn initial_record_header(&self) -> [u8; 5] {
        self.initial_record_header
    }
}

impl RealityTestServer {
    pub fn new(private_key: [u8; 32], server_name: impl Into<String>) -> Self {
        Self {
            private_key,
            server_name: server_name.into(),
        }
    }

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

    pub async fn handshake<S>(&self, stream: &mut S) -> io::Result<RealityTestSession>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (client_hello, initial_record_header) =
            read_record_with_header(stream, internals::CONTENT_TYPE_HANDSHAKE).await?;

        let parsed = internals::parse_client_hello(&client_hello, &self.private_key)?;

        let (server_hello, shared_secret) = internals::build_server_hello(&parsed)?;
        let mut record =
            internals::record_header(internals::CONTENT_TYPE_HANDSHAKE, server_hello.len());
        record.extend_from_slice(&server_hello);
        stream.write_all(&record).await?;

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

        let _ = read_record(stream, internals::CONTENT_TYPE_APPLICATION_DATA).await?;

        Ok(RealityTestSession {
            keys: flight.keys,
            initial_record_header,
        })
    }
}

impl RealityTestSession {
    pub async fn read<S>(&mut self, stream: &mut S) -> io::Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let (mut body, record_len) = read_record_raw(stream).await?;
        self.keys.decrypt(&mut body, record_len)
    }

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

pub use crate::reality::testkit_internals::observed_initial_record_version;

pub type ServerSigningKey = Ed25519KeyPair;
