#![forbid(unsafe_code)]

pub mod codec;
pub mod encryption;
pub mod packetaddr;
pub mod vision;
pub mod xudp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use encryption::{ClientInstance, LiveCrypto};
use foxcore_api::{
    Destination, PacketEncoding, RealityFingerprint, StreamTransportConfig, TlsConfig, VlessConfig,
};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{
    BoxDatagramSession, BoxStream, Datagram, datagram_channel, establish_stream,
    wrap_stream_transport, wrap_tls_spliced,
};
use proto_reality::{
    RealityHello, RealityHelloProfile, decode_public_key, decode_short_id, wrap_reality,
    wrap_reality_spliced,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use vision::{VisionCodec, VisionSession, XRV};

#[derive(Clone)]
pub struct VlessOutbound {
    config: Arc<VlessConfig>,
    reality: Option<Arc<PreparedReality>>,
    dialer: ProtectedDialer,
    /// Per-outbound key for the XUDP Global ID; see [`VlessOutbound::xudp_global_id`].
    global_id_key: [u8; 32],
    /// `flow=xtls-rprx-vision`. Vision replaces the whole stream setup, so it is
    /// resolved once here instead of being re-parsed per connection.
    vision: bool,
    encryption: Option<Arc<ClientInstance>>,
}

struct PreparedReality {
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
    /// Resolved once at construction; `Randomized` intentionally has no static
    /// table and draws a fresh hello per connection.
    hello: RealityHello,
    handshake_timeout: Duration,
}

impl VlessOutbound {
    pub async fn new(config: VlessConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        dialer
            .resolve_server_addresses(&config.server, config.port, config.server_ip)
            .await?;
        parse_uuid(config.uuid.expose()).map_err(invalid)?;
        let reality = config
            .reality
            .as_ref()
            .map(|reality| {
                if config.tls != TlsConfig::default() {
                    return Err(invalid(
                        "VLESS Reality and ordinary TLS are mutually exclusive",
                    ));
                }
                Ok(Arc::new(PreparedReality {
                    public_key: decode_public_key(reality.public_key.expose())?,
                    short_id: decode_short_id(reality.short_id.expose())?,
                    server_name: reality.server_name.clone(),
                    hello: match reality.fingerprint {
                        RealityFingerprint::Chrome151 => RealityHelloProfile::Chrome151.into(),
                        RealityFingerprint::Chrome133 => RealityHelloProfile::Chrome133.into(),
                        RealityFingerprint::Chrome131 => RealityHelloProfile::Chrome131.into(),
                        RealityFingerprint::Edge85 => RealityHelloProfile::Edge85.into(),
                        RealityFingerprint::Safari263 => RealityHelloProfile::Safari263.into(),
                        RealityFingerprint::Ios14 => RealityHelloProfile::Ios14.into(),
                        RealityFingerprint::Qq111 => RealityHelloProfile::Qq111.into(),
                        RealityFingerprint::Firefox153 => RealityHelloProfile::Firefox153.into(),
                        RealityFingerprint::Firefox148 => RealityHelloProfile::Firefox148.into(),
                        RealityFingerprint::Randomized => RealityHello::Randomized,
                    },
                    handshake_timeout: Duration::from_millis(reality.handshake_timeout_ms),
                }))
            })
            .transpose()?;
        let vision = match config.flow.as_deref() {
            None => false,
            Some(XRV) => true,
            // Anything else is a flow whose wire behaviour we do not implement.
            // Sending the addon without honouring it desynchronises the server.
            Some(other) => {
                return Err(invalid(format!("unsupported VLESS flow '{other}'")));
            }
        };
        if vision {
            if !matches!(config.transport, StreamTransportConfig::Raw) {
                return Err(invalid("VLESS Vision requires raw TCP transport"));
            }
            if reality.is_none() && !config.tls.enabled {
                return Err(invalid("VLESS Vision requires REALITY or TLS"));
            }
            if config.packet_encoding != PacketEncoding::Xudp {
                return Err(invalid(
                    "VLESS Vision carries UDP as XUDP; set packet_encoding=xudp",
                ));
            }
        }
        let encryption = config
            .encryption
            .as_ref()
            .map(|spec| {
                if vision {
                    return Err(invalid(
                        "VLESS Vision over VLESS encryption is not implemented",
                    ));
                }
                let params = encryption::parse_encryption(spec.expose()).map_err(|error| {
                    io::Error::new(io::ErrorKind::Unsupported, error.to_string())
                })?;
                Ok(Arc::new(ClientInstance::new(params)))
            })
            .transpose()?;

        let mut global_id_key = [0_u8; 32];
        getrandom::fill(&mut global_id_key)
            .map_err(|_| io::Error::other("operating system RNG failed"))?;
        Ok(Self {
            config: Arc::new(config),
            reality,
            dialer,
            global_id_key,
            vision,
            encryption,
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        self.connect(codec::Command::Tcp, destination).await
    }

    /// `source` is the client 2-tuple behind this flow. XUDP needs it to derive a
    /// stable Global ID; without it every session looks like a new client and the
    /// server cannot reuse one UDP port across destinations.
    pub async fn connect_datagram(
        &self,
        destination: &Destination,
        source: Option<SocketAddr>,
    ) -> io::Result<BoxDatagramSession> {
        if self.vision && destination.port == 443 {
            // The reference client refuses UDP/443 on a Vision profile: QUIC's
            // own handshake inside the tunnel defeats the inner-TLS detection
            // the handover depends on. Refusing is the fail-closed answer —
            // dropping the flow to a weaker carrier would not be.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VLESS Vision does not carry UDP/443",
            ));
        }
        let command = match self.config.packet_encoding {
            PacketEncoding::None | PacketEncoding::Packetaddr => codec::Command::Udp,
            PacketEncoding::Xudp => codec::Command::Mux,
        };
        let global_id = match self.config.packet_encoding {
            PacketEncoding::None | PacketEncoding::Packetaddr => [0_u8; xudp::GLOBAL_ID_LEN],
            PacketEncoding::Xudp => self.xudp_global_id(source)?,
        };
        // packetaddr is announced by the request destination, not by a flag: the
        // magic name is what tells the server to expect an address in front of
        // every datagram. The real destination rides each frame instead.
        let header_destination = match self.config.packet_encoding {
            PacketEncoding::Packetaddr => {
                if destination.ip().is_none() {
                    // The format registers no address type for a name, so there
                    // is nothing to fall back to and nothing to guess.
                    return Err(packetaddr::PacketAddrError::DomainDestination.into());
                }
                Destination::new(packetaddr::MAGIC_ADDRESS, packetaddr::MAGIC_PORT)
            }
            _ => destination.clone(),
        };
        let stream = self.connect(command, &header_destination).await?;
        let (session, mut channels) = datagram_channel(64);
        let destination = destination.clone();
        let cancel = channels.cancel.clone();
        let packet_encoding = self.config.packet_encoding;
        tokio::spawn(async move {
            match packet_encoding {
                PacketEncoding::None => {
                    relay_datagrams(
                        stream,
                        destination,
                        &mut channels.uplink,
                        channels.downlink,
                        cancel,
                    )
                    .await
                }
                PacketEncoding::Xudp => {
                    relay_xudp(
                        stream,
                        destination,
                        global_id,
                        &mut channels.uplink,
                        channels.downlink,
                        cancel,
                    )
                    .await
                }
                PacketEncoding::Packetaddr => {
                    relay_packetaddr(stream, &mut channels.uplink, channels.downlink, cancel).await
                }
            }
        });
        Ok(session)
    }

    /// Global ID for this session; see [`xudp::derive_global_id`].
    fn xudp_global_id(&self, source: Option<SocketAddr>) -> io::Result<[u8; xudp::GLOBAL_ID_LEN]> {
        let Some(source) = source else {
            // No identity to bind to: fall back to a per-session random id rather
            // than letting unrelated flows collide on one server-side socket.
            let mut global_id = [0_u8; xudp::GLOBAL_ID_LEN];
            getrandom::fill(&mut global_id)
                .map_err(|_| io::Error::other("operating system RNG failed"))?;
            return Ok(global_id);
        };
        Ok(xudp::derive_global_id(&self.global_id_key, source))
    }

    fn request_header(
        &self,
        command: codec::Command,
        destination: &Destination,
    ) -> io::Result<Vec<u8>> {
        let uuid = parse_uuid(self.config.uuid.expose()).map_err(invalid)?;
        let mut request = Vec::with_capacity(96);
        codec::encode_request(
            &uuid,
            command,
            destination,
            self.config.flow.as_deref(),
            &mut request,
        )
        .map_err(|error| invalid(error.to_string()))?;
        Ok(request)
    }

    /// Vision owns the whole stream: the VLESS header rides inside the codec so
    /// it is flushed together with the first padded frame, and the response
    /// header is consumed by the codec because nothing may read the stream
    /// before the padding state machine does.
    async fn connect_vision(
        &self,
        command: codec::Command,
        destination: &Destination,
    ) -> io::Result<BoxStream> {
        let uuid = parse_uuid(self.config.uuid.expose()).map_err(invalid)?;
        let request = self.request_header(command, destination)?;
        let codec = VisionCodec::new(VisionSession::new(uuid), request);
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        if let Some(reality) = &self.reality {
            return Ok(Box::new(
                wrap_reality_spliced(
                    tcp,
                    reality.public_key,
                    reality.short_id,
                    reality.server_name.clone(),
                    reality.hello,
                    reality.handshake_timeout,
                    codec,
                )
                .await?,
            ));
        }
        wrap_tls_spliced(tcp, &self.config.tls, &self.config.server, codec).await
    }

    async fn connect(
        &self,
        command: codec::Command,
        destination: &Destination,
    ) -> io::Result<BoxStream> {
        if self.vision {
            return self.connect_vision(command, destination).await;
        }
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let mut stream: BoxStream = if let Some(reality) = &self.reality {
            let secured = wrap_reality(
                tcp,
                reality.public_key,
                reality.short_id,
                reality.server_name.clone(),
                reality.hello,
                reality.handshake_timeout,
            )
            .await?;
            wrap_stream_transport(
                secured,
                &self.config.transport,
                &self.config.server,
                self.config.port,
                true,
            )
            .await?
        } else {
            establish_stream(
                tcp,
                &self.config.tls,
                &self.config.transport,
                &self.config.server,
                self.config.port,
            )
            .await?
        };
        if let Some(encryption) = &self.encryption {
            stream = Box::new(encryption.handshake(stream, &mut LiveCrypto).await?);
        }
        let request = self.request_header(command, destination)?;
        stream.write_all(&request).await?;
        stream.flush().await?;

        // The response header is consumed on the first read, not here.
        //
        // Waiting for it before handing the stream back deadlocks against a
        // server that emits the header only once the destination has spoken —
        // and that is exactly what sing-box's VLESS inbound does. The cycle is:
        // this client waits for the header, the server waits for the
        // destination, and the destination waits for a request the caller
        // cannot send because it does not have the stream yet. Against Xray the
        // deadlock is invisible, because Xray writes the header as soon as it
        // has dialled, which is why this survived live testing.
        //
        // Proven on a Pixel 7 Pro against a sing-box VLESS server: with an
        // origin that answers only when asked, the flow times out with zero
        // bytes; with an origin that speaks first, the identical flow carries
        // its payload. The Vision path never had this problem — it splices the
        // request into a codec instead of blocking — and `response_header_len`
        // was written for this and had no caller outside its own tests.
        Ok(Box::new(LazyResponseHeader::new(stream)))
    }
}

/// Strips the VLESS response header from the front of the stream on first read.
///
/// Everything after the header is payload, so once the header is gone this is a
/// pass-through. Buffering is bounded by what the peer sends in the same read
/// as the header, which is at most one transport frame.
struct LazyResponseHeader {
    inner: BoxStream,
    buffered: Vec<u8>,
    stripped: bool,
}

impl LazyResponseHeader {
    fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            buffered: Vec::new(),
            stripped: false,
        }
    }
}

impl tokio::io::AsyncRead for LazyResponseHeader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;

        let this = self.get_mut();
        loop {
            if this.stripped {
                if !this.buffered.is_empty() {
                    let take = this.buffered.len().min(buf.remaining());
                    buf.put_slice(&this.buffered[..take]);
                    this.buffered.drain(..take);
                    return Poll::Ready(Ok(()));
                }
                return std::pin::Pin::new(&mut this.inner).poll_read(context, buf);
            }

            let mut chunk = [0_u8; 512];
            let mut probe = tokio::io::ReadBuf::new(&mut chunk);
            match std::pin::Pin::new(&mut this.inner).poll_read(context, &mut probe) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = probe.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS response header truncated",
                        )));
                    }
                    this.buffered.extend_from_slice(filled);
                    // Version is checked as soon as the first byte exists, so a
                    // wrong-version peer is refused on arrival rather than after
                    // an addon length has been trusted.
                    if this.buffered[0] != codec::VERSION {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported VLESS response version {}", this.buffered[0]),
                        )));
                    }
                    if let Ok(header) = codec::response_header_len(&this.buffered) {
                        this.buffered.drain(..header);
                        this.stripped = true;
                    }
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for LazyResponseHeader {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn relay_datagrams(
    stream: BoxStream,
    destination: Destination,
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Each direction is one long-lived future, pinned outside the select.
    //
    // The obvious shape — `reader.read_u16()` as a select arm — is wrong, and
    // wrong in a way that hides. `ReadU16` carries the bytes it has already
    // taken inside the future; a length prefix split across two TCP segments
    // leaves one byte in it. If the uplink arm becomes ready in that same poll,
    // select drops the future and that byte is gone. Every later prefix is then
    // read one byte off, so lengths become garbage, `vec![0; length]` allocates
    // whatever the shifted bytes say, and the session either dies or delivers
    // rubbish to the app. Nothing logs it, because nothing failed.
    let send = async {
        // One frame buffer for the session rather than one per datagram.
        let mut frame = Vec::with_capacity(2048);
        while let Some(outgoing) = uplink.recv().await {
            frame.clear();
            if codec::encode_udp(&outgoing.payload, &mut frame).is_err()
                || writer.write_all(&frame).await.is_err()
            {
                break;
            }
        }
    };
    let receive = async {
        while let Ok(length) = reader.read_u16().await {
            if length == 0 {
                continue;
            }
            let mut payload = vec![0_u8; length as usize];
            if reader.read_exact(&mut payload).await.is_err() {
                break;
            }
            if downlink
                .send(Datagram::new(destination.clone(), Bytes::from(payload)))
                .await
                .is_err()
            {
                break;
            }
        }
    };
    tokio::pin!(send, receive);
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = &mut send => {}
        _ = &mut receive => {}
    }
}

/// Relay datagrams with the destination in front of each one
/// (`packet_encoding=packetaddr`).
///
/// The VLESS length prefix is the frame boundary; everything inside it is the
/// address block plus payload. Unlike the plain path there is no session
/// destination to remember — each frame states its own, in both directions.
async fn relay_packetaddr(
    stream: BoxStream,
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Pinned per-direction futures rather than select arms — see the note in
    // `relay_datagrams` for what a dropped `ReadU16` costs.
    let send = async {
        let mut frame = Vec::with_capacity(2048);
        while let Some(outgoing) = uplink.recv().await {
            frame.clear();
            if packetaddr::encode(&outgoing.destination, &outgoing.payload, &mut frame).is_err() {
                // A destination this carrier cannot express drops the packet,
                // not the session: another peer on the same stream may be
                // perfectly expressible.
                continue;
            }
            let Ok(length) = u16::try_from(frame.len()) else {
                break;
            };
            if writer.write_all(&length.to_be_bytes()).await.is_err()
                || writer.write_all(&frame).await.is_err()
            {
                break;
            }
        }
    };
    let receive = async {
        while let Ok(length) = reader.read_u16().await {
            if length == 0 {
                // A zero-length frame cannot hold an address block; the
                // reference treats it as a hard error rather than a keepalive.
                break;
            }
            let mut payload = vec![0_u8; length as usize];
            if reader.read_exact(&mut payload).await.is_err() {
                break;
            }
            let Ok((source, body)) = packetaddr::decode(&payload) else {
                break;
            };
            let destination = Destination::new(source.ip().to_string(), source.port());
            if downlink
                .send(Datagram::new(destination, Bytes::copy_from_slice(body)))
                .await
                .is_err()
            {
                break;
            }
        }
    };
    tokio::pin!(send, receive);
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = &mut send => {}
        _ = &mut receive => {}
    }
}

/// One Mux.Cool sub-connection per datagram session is all we need: the
/// destination travels per frame, so a single id serves every peer.
const XUDP_SESSION_ID: u16 = 1;
/// Largest frame the wire format can produce (`len | metadata | len | payload`).
const MAX_XUDP_FRAME_LEN: usize = 2 + 512 + 2 + u16::MAX as usize;
const XUDP_READ_CHUNK: usize = 16 * 1024;

/// Relay datagrams as Mux.Cool sub-connection frames (`packetEncoding=xudp`).
///
/// The first frame opens the session (`New` + Global ID); every later frame is a
/// `Keep` that repeats its own destination, which is what lets one stream serve
/// several peers with full-cone semantics.
async fn relay_xudp(
    stream: BoxStream,
    destination: Destination,
    global_id: [u8; xudp::GLOBAL_ID_LEN],
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut opened = false;
    let mut pending = Vec::new();
    let mut chunk = vec![0_u8; XUDP_READ_CHUNK];
    // Frames may omit the address; the last one seen stays authoritative.
    let mut peer = destination;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            outgoing = uplink.recv() => {
                let Some(outgoing) = outgoing else { break };
                let (status, global_id) = if opened {
                    (xudp::STATUS_KEEP, None)
                } else {
                    (xudp::STATUS_NEW, Some(&global_id))
                };
                let mut frame = Vec::with_capacity(outgoing.payload.len() + 32);
                if xudp::encode_packet(
                    XUDP_SESSION_ID,
                    status,
                    &outgoing.destination,
                    global_id,
                    &outgoing.payload,
                    &mut frame,
                )
                .is_err()
                    || writer.write_all(&frame).await.is_err()
                {
                    break;
                }
                peer = outgoing.destination;
                opened = true;
            }
            read = reader.read(&mut chunk) => {
                let Ok(length) = read else { break };
                if length == 0 {
                    break;
                }
                pending.extend_from_slice(&chunk[..length]);
                if pending.len() > MAX_XUDP_FRAME_LEN {
                    // A frame that cannot exist on the wire means the stream is
                    // desynchronised; keeping the bytes would grow unbounded.
                    break;
                }
                if !drain_xudp(&mut pending, &mut peer, &downlink).await {
                    break;
                }
            }
        }
    }

    if opened {
        // Best effort: let the server release the sub-connection right away.
        let mut frame = Vec::with_capacity(32);
        if xudp::encode_packet(
            XUDP_SESSION_ID,
            xudp::STATUS_END,
            &peer,
            None,
            &[],
            &mut frame,
        )
        .is_ok()
        {
            let _ = writer.write_all(&frame).await;
        }
    }
}

/// Emit every complete frame in `pending`, returning `false` when the session
/// must end (peer `End`, malformed frame, or a closed downlink).
async fn drain_xudp(
    pending: &mut Vec<u8>,
    peer: &mut Destination,
    downlink: &tokio::sync::mpsc::Sender<Datagram>,
) -> bool {
    let mut offset = 0;
    loop {
        let frame = match xudp::parse_packet(&pending[offset..]) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => return false,
        };
        if let Some(destination) = frame.destination {
            *peer = destination;
        }
        if frame.status == xudp::STATUS_END {
            return false;
        }
        if frame.payload_len > 0 {
            let start = offset + frame.payload_start;
            let payload = Bytes::copy_from_slice(&pending[start..start + frame.payload_len]);
            if downlink
                .send(Datagram::new(peer.clone(), payload))
                .await
                .is_err()
            {
                return false;
            }
        }
        offset += frame.consumed;
    }
    pending.drain(..offset);
    true
}

pub fn parse_uuid(value: &str) -> Result<[u8; 16], String> {
    let hex: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if hex.len() != 32 {
        return Err(format!("bad UUID length ({} hex characters)", hex.len()));
    }
    let mut uuid = [0_u8; 16];
    for (index, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("bad UUID hex: {error}"))?;
    }
    Ok(uuid)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uuid_with_or_without_hyphens() {
        let canonical = parse_uuid("d0cf0001-0000-4000-8000-000000000000").unwrap();
        let compact = parse_uuid("d0cf0001000040008000000000000000").unwrap();
        assert_eq!(canonical, compact);
    }

    #[test]
    fn rejects_bad_uuid() {
        assert!(parse_uuid("not-a-uuid").is_err());
    }

    /// A stream that hands out exactly one scripted chunk per read.
    ///
    /// The point is the *splitting*: a peer is free to deliver the response
    /// header one byte at a time, and an adapter that assumed a whole header
    /// per read would pass a single-chunk test and still hang on the wire.
    struct ScriptedReads {
        chunks: std::collections::VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedReads {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into(),
                written: Vec::new(),
            }
        }
    }

    impl tokio::io::AsyncRead for ScriptedReads {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if let Some(chunk) = self.chunks.pop_front() {
                buf.put_slice(&chunk);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for ScriptedReads {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn read_all(mut stream: LazyResponseHeader) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut chunk = [0_u8; 64];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..read]);
            if out.len() >= 16 {
                break;
            }
        }
        Ok(out)
    }

    #[tokio::test]
    async fn response_header_is_stripped_when_it_arrives_with_the_payload() {
        let stream = ScriptedReads::new(vec![vec![codec::VERSION, 0, b'h', b'i']]);
        let payload = read_all(LazyResponseHeader::new(Box::new(stream)))
            .await
            .unwrap();
        assert_eq!(payload, b"hi");
    }

    #[tokio::test]
    async fn response_header_is_stripped_when_split_across_reads() {
        // Version, addon length and addon each in their own read, then payload.
        let stream = ScriptedReads::new(vec![
            vec![codec::VERSION],
            vec![3],
            vec![9, 9, 9],
            vec![b'o', b'k'],
        ]);
        let payload = read_all(LazyResponseHeader::new(Box::new(stream)))
            .await
            .unwrap();
        assert_eq!(payload, b"ok");
    }

    #[tokio::test]
    async fn a_wrong_response_version_is_refused_on_arrival() {
        let stream = ScriptedReads::new(vec![vec![7, 0, b'x']]);
        let error = read_all(LazyResponseHeader::new(Box::new(stream)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn eof_before_the_header_is_an_error_not_an_empty_stream() {
        // A truncated header must not read as a clean end of stream: that would
        // turn a refusing server into a zero-length success.
        let stream = ScriptedReads::new(vec![vec![codec::VERSION]]);
        let error = read_all(LazyResponseHeader::new(Box::new(stream)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
