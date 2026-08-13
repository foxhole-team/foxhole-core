//! A TLS record-layer relay that can hand the socket over to a raw copy
//! mid-stream.
//!
//! XTLS-style flows stop being TLS partway through: once the *inner* connection
//! is itself TLS, the peer stops wrapping it in the outer record layer and
//! writes the inner records straight onto the socket. A relay that keeps
//! decrypting at that point sees the inner records as corrupt outer ones and
//! tears the connection down.
//!
//! Two properties make the handover exact, and both are the reason this relay
//! exists instead of a plain `TlsStream`:
//!
//! 1. **One record at a time.** Bytes are framed here, not inside the record
//!    layer, so the layer is never handed a byte that belongs after the
//!    handover. Whatever the peer sent after its last encrypted record is still
//!    sitting in *our* buffer, and is forwarded verbatim.
//! 2. **Plaintext is drained before the switch.** Anything already decrypted but
//!    not yet delivered goes to the application ahead of the raw tail, so the
//!    byte stream the application sees stays in order.
//!
//! `rustls` cannot do this on its own: it owns the receive buffer and exposes no
//! way to reclaim the bytes it has read but not consumed.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

/// Largest TLS 1.3 record on the wire: header plus `2^14 + 256` of ciphertext.
const MAX_RECORD_LEN: usize = 5 + (1 << 14) + 256;
const TLS_RECORD_HEADER_LEN: usize = 5;
/// Default plaintext chunk handed to [`InnerCodec::uplink`].
const DEFAULT_APP_CHUNK: usize = 16 * 1024;

/// The slice of a TLS 1.3 client state machine this relay drives.
///
/// Both `rustls::ClientConnection` and FoxCore's REALITY connection expose this
/// shape; the trait exists so the relay does not have to know which one it has.
pub trait RecordLayer: Send + 'static {
    /// Feed ciphertext. Mirrors `rustls`: one `read` call, may take less than offered.
    fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize>;
    fn process_new_packets(&mut self) -> io::Result<()>;
    /// Append every currently available plaintext byte. `Ok(true)` means the
    /// peer sent a verified close-notify.
    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> io::Result<bool>;
    fn write_plaintext(&mut self, data: &[u8]) -> io::Result<()>;
    /// Append every pending outgoing record.
    fn write_tls(&mut self, out: &mut Vec<u8>) -> io::Result<()>;
    fn send_close_notify(&mut self);
}

/// A framing layer that lives *inside* the record layer and may declare that
/// the rest of the connection is no longer wrapped.
pub trait InnerCodec: Send + 'static {
    /// Largest plaintext chunk to hand to [`Self::uplink`] in one call. Framing
    /// that depends on chunk size (Vision's padding does) pins this.
    fn max_app_chunk(&self) -> usize {
        DEFAULT_APP_CHUNK
    }

    /// How long to wait for the application's first byte before emitting
    /// [`Self::on_first_write_timeout`]. `None` disables the prelude.
    fn first_write_delay(&self) -> Option<Duration> {
        None
    }

    /// Emitted when the application produced nothing within
    /// [`Self::first_write_delay`].
    fn on_first_write_timeout(&mut self, _out: &mut Vec<u8>) -> io::Result<()> {
        Ok(())
    }

    /// Frame application bytes for the wire. `Ok(true)` means every *later*
    /// write bypasses the record layer; the bytes produced by this call do not.
    fn uplink(&mut self, app: &[u8], out: &mut Vec<u8>) -> io::Result<bool>;

    /// Unframe decrypted bytes for the application. `Ok(true)` means everything
    /// after this input arrives raw.
    fn downlink(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<bool>;
}

/// Codec for connections with nothing inside the record layer.
pub struct PassthroughCodec;

impl InnerCodec for PassthroughCodec {
    fn uplink(&mut self, app: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        out.extend_from_slice(app);
        Ok(false)
    }

    fn downlink(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
        out.extend_from_slice(plain);
        Ok(false)
    }
}

/// Run [`relay`] on a task and return the application end of the pipe.
pub fn spawn_relay<S, L, C>(network: S, layer: L, codec: C, buffer_capacity: usize) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    L: RecordLayer,
    C: InnerCodec,
{
    let (application, relay_end) = tokio::io::duplex(buffer_capacity);
    tokio::spawn(async move {
        let _ = relay(relay_end, network, layer, codec).await;
    });
    application
}

/// Pump one connection until either end closes.
pub async fn relay<S, L, C>(
    mut application: DuplexStream,
    mut network: S,
    mut layer: L,
    mut codec: C,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: RecordLayer,
    C: InnerCodec,
{
    let mut app_buffer = vec![0_u8; codec.max_app_chunk()];
    let mut network_buffer = vec![0_u8; MAX_RECORD_LEN];
    // Ciphertext the peer sent that has not been split into records yet. After
    // the downlink switches this is the head of the raw stream.
    let mut inbound = Vec::with_capacity(MAX_RECORD_LEN);
    let mut scratch = Vec::with_capacity(MAX_RECORD_LEN);
    let mut framed = Vec::with_capacity(MAX_RECORD_LEN);

    let mut uplink_direct = false;
    let mut downlink_direct = false;
    let mut first_write_delay = codec.first_write_delay();

    // Anything the record layer decrypted during the handshake is already
    // waiting; deliver it before touching the socket.
    if drain_downlink(
        &mut layer,
        &mut codec,
        &mut application,
        &mut scratch,
        &mut framed,
        &mut downlink_direct,
    )
    .await?
    {
        application.shutdown().await?;
        return Ok(());
    }

    loop {
        tokio::select! {
            outgoing = read_app(&mut application, &mut app_buffer, &mut first_write_delay) => {
                match outgoing? {
                    AppRead::Eof => {
                        if !uplink_direct {
                            layer.send_close_notify();
                            framed.clear();
                            layer.write_tls(&mut framed)?;
                            if !framed.is_empty() {
                                let _ = network.write_all(&framed).await;
                            }
                        }
                        let _ = network.shutdown().await;
                        return Ok(());
                    }
                    AppRead::Idle => {
                        framed.clear();
                        codec.on_first_write_timeout(&mut framed)?;
                        if !framed.is_empty() {
                            layer.write_plaintext(&framed)?;
                            flush_records(&mut layer, &mut network, &mut scratch).await?;
                        }
                    }
                    AppRead::Data(count) => {
                        if uplink_direct {
                            network.write_all(&app_buffer[..count]).await?;
                            continue;
                        }
                        framed.clear();
                        let switch = codec.uplink(&app_buffer[..count], &mut framed)?;
                        if !framed.is_empty() {
                            layer.write_plaintext(&framed)?;
                            flush_records(&mut layer, &mut network, &mut scratch).await?;
                        }
                        uplink_direct |= switch;
                    }
                }
            }
            incoming = network.read(&mut network_buffer) => {
                let count = incoming?;
                if count == 0 {
                    application.shutdown().await?;
                    return Ok(());
                }
                if downlink_direct {
                    application.write_all(&network_buffer[..count]).await?;
                    continue;
                }
                inbound.extend_from_slice(&network_buffer[..count]);
                let closed = feed_records(
                    &mut layer,
                    &mut codec,
                    &mut application,
                    &mut inbound,
                    &mut scratch,
                    &mut framed,
                    &mut downlink_direct,
                )
                .await?;
                if downlink_direct && !inbound.is_empty() {
                    // Whatever followed the peer's last encrypted record is
                    // already raw. It never reached the record layer, so it is
                    // still intact here.
                    application.write_all(&inbound).await?;
                    inbound.clear();
                }
                if closed {
                    application.shutdown().await?;
                    return Ok(());
                }
            }
        }
    }
}

enum AppRead {
    Data(usize),
    Idle,
    Eof,
}

/// Read the application side, honouring the codec's one-shot prelude deadline.
async fn read_app(
    application: &mut DuplexStream,
    buffer: &mut [u8],
    first_write_delay: &mut Option<Duration>,
) -> io::Result<AppRead> {
    match first_write_delay.take() {
        Some(delay) => match tokio::time::timeout(delay, application.read(buffer)).await {
            Ok(result) => classify(result?),
            Err(_) => Ok(AppRead::Idle),
        },
        None => classify(application.read(buffer).await?),
    }
}

fn classify(count: usize) -> io::Result<AppRead> {
    if count == 0 {
        Ok(AppRead::Eof)
    } else {
        Ok(AppRead::Data(count))
    }
}

async fn flush_records<S, L>(
    layer: &mut L,
    network: &mut S,
    scratch: &mut Vec<u8>,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    L: RecordLayer,
{
    scratch.clear();
    layer.write_tls(scratch)?;
    if scratch.is_empty() {
        return Ok(());
    }
    network.write_all(scratch).await?;
    network.flush().await
}

/// Split `inbound` into whole records, decrypt them one at a time, and stop the
/// moment the codec says the rest of the stream is raw.
async fn feed_records<L, C>(
    layer: &mut L,
    codec: &mut C,
    application: &mut DuplexStream,
    inbound: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    framed: &mut Vec<u8>,
    downlink_direct: &mut bool,
) -> io::Result<bool>
where
    L: RecordLayer,
    C: InnerCodec,
{
    let mut offset = 0;
    let mut closed = false;
    while let Some(length) = record_length(&inbound[offset..])? {
        let record = &inbound[offset..offset + length];
        let mut cursor = io::Cursor::new(record);
        while cursor.position() < length as u64 {
            let taken = layer.read_tls(&mut cursor)?;
            if taken == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record layer stopped consuming a complete record",
                ));
            }
        }
        offset += length;
        layer.process_new_packets()?;
        closed =
            drain_downlink(layer, codec, application, scratch, framed, downlink_direct).await?;
        if *downlink_direct || closed {
            break;
        }
    }
    inbound.drain(..offset);
    Ok(closed)
}

/// Move every currently decrypted byte through the codec to the application.
async fn drain_downlink<L, C>(
    layer: &mut L,
    codec: &mut C,
    application: &mut DuplexStream,
    scratch: &mut Vec<u8>,
    framed: &mut Vec<u8>,
    downlink_direct: &mut bool,
) -> io::Result<bool>
where
    L: RecordLayer,
    C: InnerCodec,
{
    scratch.clear();
    let closed = layer.read_plaintext(scratch)?;
    if scratch.is_empty() {
        return Ok(closed);
    }
    framed.clear();
    let switch = codec.downlink(scratch, framed)?;
    if !framed.is_empty() {
        application.write_all(framed).await?;
    }
    *downlink_direct |= switch;
    Ok(closed)
}

/// Length of the record at the head of `buffer`, or `None` while it is partial.
fn record_length(buffer: &[u8]) -> io::Result<Option<usize>> {
    if buffer.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }
    let payload = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    let length = TLS_RECORD_HEADER_LEN + payload;
    if length > MAX_RECORD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS record longer than the protocol allows",
        ));
    }
    if buffer.len() < length {
        return Ok(None);
    }
    Ok(Some(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partial_record_is_not_framed_yet() {
        assert_eq!(record_length(&[0x17, 0x03, 0x03]).unwrap(), None);
        assert_eq!(
            record_length(&[0x17, 0x03, 0x03, 0x00, 0x04]).unwrap(),
            None
        );
        assert_eq!(
            record_length(&[0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]).unwrap(),
            Some(9)
        );
    }

    #[test]
    fn a_record_longer_than_the_protocol_allows_is_refused() {
        // 0xFFFF payload is 65535 bytes: far past 2^14 + 256, so a peer sending
        // it is either broken or trying to make us buffer without bound.
        let error = record_length(&[0x17, 0x03, 0x03, 0xff, 0xff]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// Stand-in record layer: "encryption" is XOR, and every plaintext write
    /// becomes exactly one application-data record. Enough to pin the framing
    /// and handover contract without dragging a real handshake into a unit test.
    #[derive(Default)]
    struct MockLayer {
        inbound: Vec<u8>,
        plaintext: Vec<u8>,
        outbound: Vec<u8>,
    }

    const MASK: u8 = 0xaa;

    fn record(plain: &[u8]) -> Vec<u8> {
        let mut out = vec![0x17, 0x03, 0x03];
        out.extend_from_slice(&(plain.len() as u16).to_be_bytes());
        out.extend(plain.iter().map(|byte| byte ^ MASK));
        out
    }

    impl RecordLayer for MockLayer {
        fn read_tls(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
            let mut buffer = [0_u8; 4096];
            let count = rd.read(&mut buffer)?;
            self.inbound.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn process_new_packets(&mut self) -> io::Result<()> {
            let mut offset = 0;
            while let Some(length) = record_length(&self.inbound[offset..])? {
                let body = &self.inbound[offset + TLS_RECORD_HEADER_LEN..offset + length];
                self.plaintext.extend(body.iter().map(|byte| byte ^ MASK));
                offset += length;
            }
            self.inbound.drain(..offset);
            Ok(())
        }

        fn read_plaintext(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
            out.append(&mut self.plaintext);
            Ok(false)
        }

        fn write_plaintext(&mut self, data: &[u8]) -> io::Result<()> {
            self.outbound.extend_from_slice(&record(data));
            Ok(())
        }

        fn write_tls(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
            out.append(&mut self.outbound);
            Ok(())
        }

        fn send_close_notify(&mut self) {}
    }

    /// Hands the socket over as soon as it sees the sentinel.
    struct SwitchOnSentinel;

    impl InnerCodec for SwitchOnSentinel {
        fn uplink(&mut self, app: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
            out.extend_from_slice(app);
            Ok(app.ends_with(b"GO"))
        }

        fn downlink(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<bool> {
            out.extend_from_slice(plain);
            Ok(plain.ends_with(b"GO"))
        }
    }

    #[tokio::test]
    async fn raw_bytes_behind_the_last_record_survive_the_downlink_handover() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut application =
            spawn_relay(client, MockLayer::default(), SwitchOnSentinel, 64 * 1024);

        // One encrypted record that ends the framed region, immediately followed
        // by bytes the peer no longer wraps. Both arrive in the same read.
        let mut wire = record(b"hi GO");
        wire.extend_from_slice(b"raw-tail-bytes");
        server.write_all(&wire).await.unwrap();

        let mut seen = vec![0_u8; b"hi GOraw-tail-bytes".len()];
        application.read_exact(&mut seen).await.unwrap();
        assert_eq!(
            seen, b"hi GOraw-tail-bytes",
            "bytes past the last record must reach the application intact"
        );

        // And the connection stays raw afterwards.
        server.write_all(b"more-raw").await.unwrap();
        let mut more = vec![0_u8; 8];
        application.read_exact(&mut more).await.unwrap();
        assert_eq!(&more, b"more-raw");
    }

    #[tokio::test]
    async fn a_record_split_across_two_reads_is_only_decrypted_once_whole() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut application =
            spawn_relay(client, MockLayer::default(), SwitchOnSentinel, 64 * 1024);

        let wire = record(b"halves");
        server.write_all(&wire[..4]).await.unwrap();
        server.write_all(&wire[4..]).await.unwrap();

        let mut seen = vec![0_u8; 6];
        application.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"halves");
    }

    #[tokio::test]
    async fn the_uplink_stops_wrapping_after_the_handover() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut application =
            spawn_relay(client, MockLayer::default(), SwitchOnSentinel, 64 * 1024);

        application.write_all(b"up GO").await.unwrap();
        let framed = record(b"up GO");
        let mut seen = vec![0_u8; framed.len()];
        server.read_exact(&mut seen).await.unwrap();
        assert_eq!(
            seen, framed,
            "the frame that announces the handover is still wrapped"
        );

        application.write_all(b"plain").await.unwrap();
        let mut raw = vec![0_u8; 5];
        server.read_exact(&mut raw).await.unwrap();
        assert_eq!(
            &raw, b"plain",
            "every later write bypasses the record layer"
        );
    }

    #[test]
    fn a_maximum_sized_record_is_accepted() {
        let payload = (1 << 14) + 256;
        let mut header = vec![0x17, 0x03, 0x03];
        header.extend_from_slice(&(payload as u16).to_be_bytes());
        header.resize(TLS_RECORD_HEADER_LEN + payload, 0);
        assert_eq!(record_length(&header).unwrap(), Some(header.len()));
    }
}
