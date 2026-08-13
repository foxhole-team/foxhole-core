//! The two stateful readers of a ShadowTLS server's stream, opened to the fuzz
//! harness in `fuzz/`.
//!
//! Compiled only under the `fuzzing` feature, which nothing in the workspace
//! enables. Both readers are `pub(crate)` because the only legitimate caller is
//! the client above them, and reaching either from outside would otherwise mean
//! completing a real TLS 1.3 handshake against a real ShadowTLS server first —
//! something no fuzzer will ever do by mutation, so the code that reads the
//! server's bytes would never be reached at all.
//!
//! What makes this worth a target of its own: neither reader is a function of
//! the bytes in front of it. Stage 1 carries a partial-record buffer, a
//! handshake transcript reassembled across records, a `ServerRandom` learned
//! from one record and used to key every later one, an HMAC chain in which each
//! tag depends on all tags before it, and two mode flags that change how the
//! *next* record is handled. Stage 2 carries a partial-record buffer of its
//! own, seeded with whatever stage 1 left unconsumed. A target that handed each
//! record to a fresh object would exercise none of that.
//!
//! `ProofSender` is the only thing here that is not a pass-through. It is the
//! server half of the proof protocol, which this crate — a client — does not
//! implement anywhere, so it cannot drift out of sync with an implementation:
//! if it stopped agreeing with the client, every round trip in the harness
//! would fail at once. Without it no input could ever drive stage 1 past
//! "unauthenticated", and the states that only exist *after* authentication —
//! where a chain failure has to be a hard error rather than a downgrade — would
//! be unreachable.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use foxcore_api::SecretString;

use crate::handshake::{HandshakeIo, MAX_HANDSHAKE_BUFFER as HANDSHAKE_BUFFER_CAP};
use crate::transport::RecordReader;
use crate::wire::{
    HmacChain, MAX_TLS_RECORD as TLS_RECORD_CAP, TLS_APPLICATION_DATA as APPLICATION_DATA,
    TLS_HANDSHAKE as HANDSHAKE, TLS_LEGACY_VERSION as LEGACY_VERSION, record_header, xor_proof,
};

/// `ContentType | ProtocolVersion | Length`.
pub const RECORD_HEADER: usize = 5;
/// Largest payload a record header may declare before either stage refuses it.
pub const MAX_TLS_RECORD: usize = TLS_RECORD_CAP;
/// Cap on the handshake transcript stage 1 will reassemble across records.
pub const MAX_HANDSHAKE_BUFFER: usize = HANDSHAKE_BUFFER_CAP;
/// The two record types the proof protocol gives meaning to.
pub const TLS_HANDSHAKE: u8 = HANDSHAKE;
pub const TLS_APPLICATION_DATA: u8 = APPLICATION_DATA;
/// Every record on this wire claims TLS 1.2, TLS 1.3's own disguise.
pub const TLS_LEGACY_VERSION: [u8; 2] = LEGACY_VERSION;
/// Largest plaintext `ProofSender` can put in one record: the 4-byte chained
/// tag shares the payload with it.
pub const MAX_PROOF_PLAINTEXT: usize = MAX_TLS_RECORD - 4;

/// Drive a future that reads from an in-memory slice to completion.
///
/// `&[u8]` is an `AsyncRead` that is never pending, so a single poll always
/// finishes `RecordReader::read`. Doing it by hand rather than starting a Tokio
/// runtime keeps a fuzz iteration at the cost of the parse itself. `Pending` is
/// reported rather than looped on, so a future that unexpectedly parks cannot
/// hang the fuzzer.
fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

/// Stage 1: the handshake machine, fed one TCP segment at a time.
///
/// One of these stands for one connection. Feeding it twice is feeding one
/// server two segments, which is the only way the reassembly, the transcript
/// and the chain are ever reached.
pub struct HandshakeMachine {
    io: HandshakeIo<tokio::io::Empty>,
}

impl HandshakeMachine {
    /// `tokio::io::empty()` stands in for the socket. The machine never reads
    /// it: `feed` supplies the bytes `poll_read` would have read, so the inner
    /// stream is only there to satisfy the type.
    pub fn new(password: &str) -> Self {
        Self {
            io: HandshakeIo::new(tokio::io::empty(), SecretString::new(password)),
        }
    }

    /// One socket read. An error here is the connection ending; the caller must
    /// stop feeding, exactly as `poll_read` returning an error would.
    pub fn feed(&mut self, segment: &[u8]) -> io::Result<()> {
        self.io.feed(segment)
    }

    /// True once a record has passed the chained HMAC and the peer has proved
    /// it knows the password. False again — without an error — would mean a
    /// server could take the authentication back.
    pub fn authenticated(&self) -> bool {
        self.io.authenticated()
    }

    /// True once the peer has been written off as a plain TLS server that the
    /// client must not treat as a proxy.
    pub fn hijacked(&self) -> bool {
        self.io.hijacked()
    }

    pub fn server_random(&self) -> Option<[u8; 32]> {
        self.io.server_random()
    }

    /// Bytes still held because a record is incomplete.
    pub fn buffered_wire(&self) -> usize {
        self.io.buffered_wire()
    }

    /// Bytes still held because a handshake message is incomplete.
    pub fn buffered_transcript(&self) -> usize {
        self.io.buffered_transcript()
    }

    /// Drain what the machine would have handed to rustls.
    pub fn take_ready(&mut self) -> Vec<u8> {
        self.io.take_ready().to_vec()
    }
}

/// Stage 2: the post-switch record reader, fed one TCP segment at a time.
///
/// Constructed with the prefix stage 1 left in its wire buffer, which is how
/// the real switch happens — the first stage-2 record routinely begins in a
/// segment stage 1 already consumed.
pub struct SwitchedRecordReader {
    reader: RecordReader,
}

impl SwitchedRecordReader {
    pub fn new(prefix: &[u8]) -> Self {
        Self {
            reader: RecordReader::new(BytesMut::from(prefix)),
        }
    }

    /// Every complete record this segment finished, in order.
    ///
    /// Running out of segment is not an error here: the reader keeps the
    /// partial record and the next segment continues it, which is what the
    /// socket read loop does. Anything else — a bad version, an oversized
    /// length — is the connection ending and is returned.
    pub fn feed(&mut self, segment: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let mut rest = segment;
        let mut records = Vec::new();
        loop {
            match poll_once(self.reader.read(&mut rest)) {
                Some(Ok(record)) => records.push(record.to_vec()),
                Some(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(records);
                }
                Some(Err(error)) => return Err(error),
                // Unreachable with an in-memory reader, and not worth a panic
                // in code a fuzzer runs a hundred million times.
                None => return Ok(records),
            }
        }
    }
}

/// A minimal ServerHello record: the one message stage 1 has to find in the
/// transcript, because its 32-byte random keys every proof that follows.
pub fn server_hello_record(random: [u8; 32]) -> Vec<u8> {
    let mut payload = vec![2, 0, 0, 34, LEGACY_VERSION[0], LEGACY_VERSION[1]];
    payload.extend_from_slice(&random);
    let mut record = record_header(HANDSHAKE, payload.len())
        .expect("a 38-byte payload fits a record header")
        .to_vec();
    record.extend_from_slice(&payload);
    record
}

/// The server half of the proof protocol: masks a payload with the password and
/// the ServerRandom, then tags it with the chain the client verifies.
pub struct ProofSender {
    chain: HmacChain,
    password: Vec<u8>,
    random: [u8; 32],
}

impl ProofSender {
    pub fn new(password: &str, random: [u8; 32]) -> io::Result<Self> {
        Ok(Self {
            chain: HmacChain::new(password.as_bytes(), &random)?,
            password: password.as_bytes().to_vec(),
            random,
        })
    }

    /// One application-data record carrying `plaintext`.
    ///
    /// The chain advances, so records must be delivered in the order they were
    /// produced; that ordering is the property the client's chain enforces.
    pub fn record(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut processed = plaintext.to_vec();
        xor_proof(&mut processed, &self.password, &self.random);
        let tag = self.chain.tag_and_advance(&processed);
        let mut payload = Vec::with_capacity(4 + processed.len());
        payload.extend_from_slice(&tag);
        payload.extend_from_slice(&processed);
        let mut record = record_header(APPLICATION_DATA, payload.len())?.to_vec();
        record.extend_from_slice(&payload);
        Ok(record)
    }
}
