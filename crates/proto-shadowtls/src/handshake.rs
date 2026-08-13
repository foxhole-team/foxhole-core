use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use foxcore_api::{SecretString, ShadowTlsConfig, TlsVersion};
use foxcore_transport::rustls_client_config;
use rand::RngCore;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::transport::{SwitchState, switched_stream};
use crate::wire::{
    HmacChain, MAX_TLS_RECORD, TLS_APPLICATION_DATA, TLS_HANDSHAKE, invalid, sign_client_hello,
    xor_proof,
};

pub(crate) const MAX_HANDSHAKE_BUFFER: usize = 64 * 1024;
const MAX_PENDING_WRITE: usize = MAX_TLS_RECORD * 2;
const MUDDLED_RESPONSE_LIMIT: usize = 16 * 1024;

pub(crate) async fn connect(
    stream: TcpStream,
    config: &ShadowTlsConfig,
) -> io::Result<foxcore_transport::BoxStream> {
    let mut tls = config.tls.clone();
    tls.min_version = Some(TlsVersion::Tls13);
    tls.max_version = Some(TlsVersion::Tls13);
    let client = rustls_client_config(&tls)?;
    let server_name = tls
        .server_name
        .as_deref()
        .unwrap_or(&config.server)
        .to_owned();
    let rustls_name = ServerName::try_from(server_name.clone())
        .map_err(|error| invalid(format!("invalid ShadowTLS server name: {error}")))?;
    let io = HandshakeIo::new(stream, config.password.clone());
    let handshake = TlsConnector::from(client).connect(rustls_name, io);
    let mut tls_stream = tokio::time::timeout(
        Duration::from_millis(config.handshake_timeout_ms),
        handshake,
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ShadowTLS handshake timed out"))??;

    if !tls_stream.get_ref().0.authenticated() {
        muddled_request(&mut tls_stream, &server_name).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ShadowTLS server proof was not authenticated",
        ));
    }

    let (io, _) = tls_stream.into_inner();
    let (stream, state) = io.into_switch_state()?;
    Ok(switched_stream(stream, state))
}

async fn muddled_request<S>(stream: &mut S, server_name: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut random = [0_u8; 12];
    rand::rng().fill_bytes(&mut random);
    let path = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let request = format!(
        "GET /{path} HTTP/1.1\r\nHost: {server_name}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_ok() && stream.flush().await.is_ok() {
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let mut response = [0_u8; 2048];
            let mut total = 0usize;
            while total < MUDDLED_RESPONSE_LIMIT {
                let limit = response.len().min(MUDDLED_RESPONSE_LIMIT - total);
                match stream.read(&mut response[..limit]).await {
                    Ok(0) | Err(_) => break,
                    Ok(length) => total += length,
                }
            }
        })
        .await;
    }
    let _ = stream.shutdown().await;
}

pub(crate) struct HandshakeIo<S> {
    inner: S,
    password: Arc<SecretString>,
    read_wire: BytesMut,
    read_ready: BytesMut,
    write_input: BytesMut,
    write_pending: BytesMut,
    client_hello_signed: bool,
    handshake_messages: BytesMut,
    server_random: Option<[u8; 32]>,
    proof: Option<HmacChain>,
    authenticated: bool,
    hijacked: bool,
}

impl<S> HandshakeIo<S> {
    pub(crate) fn new(inner: S, password: SecretString) -> Self {
        Self {
            inner,
            password: Arc::new(password),
            read_wire: BytesMut::new(),
            read_ready: BytesMut::new(),
            write_input: BytesMut::new(),
            write_pending: BytesMut::new(),
            client_hello_signed: false,
            handshake_messages: BytesMut::new(),
            server_random: None,
            proof: None,
            authenticated: false,
            hijacked: false,
        }
    }

    pub(crate) fn authenticated(&self) -> bool {
        self.authenticated && !self.hijacked
    }

    fn process_client_hello(&mut self) -> io::Result<()> {
        if self.client_hello_signed || self.write_input.len() < 5 {
            return Ok(());
        }
        let length = u16::from_be_bytes([self.write_input[3], self.write_input[4]]) as usize;
        if length > MAX_TLS_RECORD {
            return Err(invalid("ShadowTLS ClientHello TLS record is too large"));
        }
        let record_length = 5 + length;
        if self.write_input.len() < record_length {
            return Ok(());
        }
        let mut first = self.write_input.split_to(record_length);
        sign_client_hello(&mut first, self.password.expose().as_bytes())?;
        self.write_pending.extend_from_slice(&first);
        self.write_pending.extend_from_slice(&self.write_input);
        self.write_input.clear();
        self.client_hello_signed = true;
        Ok(())
    }

    fn process_read_records(&mut self) -> io::Result<()> {
        loop {
            if self.read_wire.len() < 5 {
                return Ok(());
            }
            let length = u16::from_be_bytes([self.read_wire[3], self.read_wire[4]]) as usize;
            if length > MAX_TLS_RECORD {
                return Err(invalid("ShadowTLS handshake TLS record is too large"));
            }
            let record_length = 5 + length;
            if self.read_wire.len() < record_length {
                return Ok(());
            }
            let record = self.read_wire.split_to(record_length);
            if record[0] == TLS_HANDSHAKE && self.server_random.is_none() {
                self.collect_server_hello(&record[5..])?;
            }
            if record[0] == TLS_APPLICATION_DATA && self.server_random.is_some() && !self.hijacked {
                self.process_proof_record(&record)?;
            } else {
                self.read_ready.extend_from_slice(&record);
            }
        }
    }

    fn collect_server_hello(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.handshake_messages.len().saturating_add(payload.len()) > MAX_HANDSHAKE_BUFFER {
            return Err(invalid("ShadowTLS TLS handshake transcript is too large"));
        }
        self.handshake_messages.extend_from_slice(payload);
        loop {
            if self.handshake_messages.len() < 4 {
                return Ok(());
            }
            let length = ((self.handshake_messages[1] as usize) << 16)
                | ((self.handshake_messages[2] as usize) << 8)
                | self.handshake_messages[3] as usize;
            let message_length = 4usize
                .checked_add(length)
                .ok_or_else(|| invalid("ShadowTLS handshake message length overflow"))?;
            if message_length > MAX_HANDSHAKE_BUFFER {
                return Err(invalid("ShadowTLS handshake message is too large"));
            }
            if self.handshake_messages.len() < message_length {
                return Ok(());
            }
            let message = self.handshake_messages.split_to(message_length);
            if message[0] == 2 {
                if length < 34 {
                    return Err(invalid("ShadowTLS ServerHello is too short"));
                }
                let mut random = [0_u8; 32];
                random.copy_from_slice(&message[6..38]);
                self.proof = Some(HmacChain::new(self.password.expose().as_bytes(), &random)?);
                self.server_random = Some(random);
                self.handshake_messages.clear();
                return Ok(());
            }
        }
    }

    fn process_proof_record(&mut self, record: &[u8]) -> io::Result<()> {
        let payload = &record[5..];
        if payload.len() < 4 {
            return self.reject_or_mark_hijacked(record);
        }
        let (tag, processed) = payload.split_at(4);
        let valid = self
            .proof
            .as_mut()
            .is_some_and(|proof| proof.verify_and_advance(tag, processed));
        if !valid {
            return self.reject_or_mark_hijacked(record);
        }

        let server_random = self
            .server_random
            .as_ref()
            .ok_or_else(|| invalid("ShadowTLS proof exists without ServerRandom"))?;
        let mut restored = processed.to_vec();
        xor_proof(
            &mut restored,
            self.password.expose().as_bytes(),
            server_random,
        );
        let mut header = [0_u8; 5];
        header.copy_from_slice(&record[..5]);
        let restored_length = u16::try_from(restored.len())
            .map_err(|_| invalid("ShadowTLS restored TLS record is too large"))?;
        header[3..5].copy_from_slice(&restored_length.to_be_bytes());
        self.read_ready.extend_from_slice(&header);
        self.read_ready.extend_from_slice(&restored);
        self.authenticated = true;
        Ok(())
    }

    fn reject_or_mark_hijacked(&mut self, record: &[u8]) -> io::Result<()> {
        if self.authenticated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS server proof chain failed after authentication",
            ));
        }
        self.hijacked = true;
        self.read_ready.extend_from_slice(record);
        Ok(())
    }
}

/// The same state machine `poll_read` drives, minus the socket.
///
/// `poll_read` is a thin loop around `process_read_records`: it reads whatever
/// the socket gave it into `read_wire` and lets the record walk decide what to
/// do with it. Splitting that loop here is what lets a fuzz target hand the
/// machine one TCP segment at a time and look at the state between segments —
/// which is the whole point, because every interesting variable in this struct
/// (`read_wire`, `handshake_messages`, `proof`, `authenticated`, `hijacked`)
/// only means anything *across* reads. Going through a real socket instead
/// would mean the fuzzer had to drive an async runtime and could never choose
/// where a record is cut.
///
/// These are views, not a second implementation: the only thing that touches
/// state here is `feed`, and all it does is the two lines `poll_read` does.
#[cfg(feature = "fuzzing")]
impl<S> HandshakeIo<S> {
    /// One socket read: append the bytes and let the record walk run.
    pub(crate) fn feed(&mut self, segment: &[u8]) -> io::Result<()> {
        self.read_wire.extend_from_slice(segment);
        self.process_read_records()
    }

    /// The bytes `poll_read` would have handed to rustls, drained.
    pub(crate) fn take_ready(&mut self) -> BytesMut {
        std::mem::take(&mut self.read_ready)
    }

    /// Bytes of an incomplete record still held. A hostile server that declares
    /// a length and stops sending must not be able to grow this without bound.
    pub(crate) fn buffered_wire(&self) -> usize {
        self.read_wire.len()
    }

    /// Bytes of an incomplete handshake message still held, bounded by
    /// `MAX_HANDSHAKE_BUFFER` for the same reason.
    pub(crate) fn buffered_transcript(&self) -> usize {
        self.handshake_messages.len()
    }

    pub(crate) fn server_random(&self) -> Option<[u8; 32]> {
        self.server_random
    }

    /// Set once the machine decides the peer is a plain TLS server rather than
    /// a ShadowTLS one, and never cleared.
    pub(crate) fn hijacked(&self) -> bool {
        self.hijacked
    }
}

impl HandshakeIo<TcpStream> {
    fn into_switch_state(mut self) -> io::Result<(TcpStream, SwitchState)> {
        if !self.authenticated() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ShadowTLS switch attempted before server authentication",
            ));
        }
        if !self.write_input.is_empty() || !self.write_pending.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "ShadowTLS handshake left unsent client bytes",
            ));
        }
        let random = self
            .server_random
            .ok_or_else(|| invalid("ShadowTLS ServerRandom is missing"))?;
        let proof = self
            .proof
            .take()
            .ok_or_else(|| invalid("ShadowTLS proof state is missing"))?;
        // Bytes already transformed for rustls but not consumed are post-
        // handshake tickets/handshake residue. They must not leak into the
        // inner data protocol. Raw partial bytes remain for the stage-2 parser.
        self.read_ready.clear();
        Ok((
            self.inner,
            SwitchState {
                password: self.password,
                server_random: random,
                proof,
                prefix: self.read_wire,
            },
        ))
    }
}

impl<S> AsyncRead for HandshakeIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_ready.is_empty() {
                let length = output.remaining().min(self.read_ready.len());
                output.put_slice(&self.read_ready[..length]);
                self.read_ready.advance(length);
                return Poll::Ready(Ok(()));
            }

            let mut temporary = [0_u8; 8192];
            let mut buffer = ReadBuf::new(&mut temporary);
            match Pin::new(&mut self.inner).poll_read(context, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    if self.read_wire.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ShadowTLS handshake ended inside a TLS record",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.read_wire.extend_from_slice(buffer.filled());
                    if let Err(error) = self.process_read_records() {
                        return Poll::Ready(Err(error));
                    }
                }
            }
        }
    }
}

impl<S> AsyncWrite for HandshakeIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        while !self.write_pending.is_empty() {
            let pending = self.write_pending.clone();
            match Pin::new(&mut self.inner).poll_write(context, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ShadowTLS socket stopped accepting handshake bytes",
                    )));
                }
                Poll::Ready(Ok(length)) => self.write_pending.advance(length),
            }
        }

        if self.client_hello_signed {
            return Pin::new(&mut self.inner).poll_write(context, input);
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let capacity = MAX_PENDING_WRITE.saturating_sub(self.write_input.len());
        if capacity == 0 {
            return Poll::Ready(Err(invalid(
                "ShadowTLS ClientHello buffering limit exceeded",
            )));
        }
        let accepted = capacity.min(input.len());
        self.write_input.extend_from_slice(&input[..accepted]);
        if let Err(error) = self.process_client_hello() {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.client_hello_signed {
            if self.write_input.is_empty() {
                return Pin::new(&mut self.inner).poll_flush(context);
            }
            if let Err(error) = self.process_client_hello() {
                return Poll::Ready(Err(error));
            }
            if !self.client_hello_signed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ShadowTLS ClientHello was flushed before a complete TLS record",
                )));
            }
        }
        while !self.write_pending.is_empty() {
            let pending = self.write_pending.clone();
            match Pin::new(&mut self.inner).poll_write(context, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ShadowTLS socket stopped accepting handshake bytes",
                    )));
                }
                Poll::Ready(Ok(length)) => self.write_pending.advance(length),
            }
        }
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{TLS_LEGACY_VERSION, record_header};

    fn server_hello_record(random: [u8; 32]) -> Vec<u8> {
        let mut payload = vec![2, 0, 0, 34, 3, 3];
        payload.extend_from_slice(&random);
        let mut record = record_header(TLS_HANDSHAKE, payload.len())
            .unwrap()
            .to_vec();
        record.extend_from_slice(&payload);
        record
    }

    #[test]
    fn fragmented_server_hello_is_reassembled() {
        let (stream, _) = tokio::io::duplex(64);
        let mut io = HandshakeIo::new(stream, SecretString::new("password"));
        let record = server_hello_record([7_u8; 32]);
        io.collect_server_hello(&record[5..17]).unwrap();
        assert!(io.server_random.is_none());
        io.collect_server_hello(&record[17..]).unwrap();
        assert_eq!(io.server_random, Some([7_u8; 32]));
    }

    #[test]
    fn valid_server_proof_is_restored_and_bad_chain_fails_closed() {
        let (stream, _) = tokio::io::duplex(64);
        let password = b"password";
        let random = [5_u8; 32];
        let mut io = HandshakeIo::new(
            stream,
            SecretString::new(std::str::from_utf8(password).unwrap()),
        );
        io.server_random = Some(random);
        io.proof = Some(HmacChain::new(password, &random).unwrap());

        let plaintext_ciphertext = b"outer tls ciphertext".to_vec();
        let mut processed = plaintext_ciphertext.clone();
        xor_proof(&mut processed, password, &random);
        let mut sender = HmacChain::new(password, &random).unwrap();
        let tag = sender.tag_and_advance(&processed);
        let mut record = vec![
            TLS_APPLICATION_DATA,
            TLS_LEGACY_VERSION[0],
            TLS_LEGACY_VERSION[1],
            0,
            (processed.len() + 4) as u8,
        ];
        record.extend_from_slice(&tag);
        record.extend_from_slice(&processed);
        io.process_proof_record(&record).unwrap();
        assert!(io.authenticated());
        assert_eq!(&io.read_ready[5..], plaintext_ciphertext);

        let mut replay = record;
        replay[5] ^= 1;
        assert!(io.process_proof_record(&replay).is_err());
    }
}
