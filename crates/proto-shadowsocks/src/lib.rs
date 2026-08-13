#![forbid(unsafe_code)]

mod outline;
mod simple_obfs;

use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use foxcore_api::{Destination, ShadowsocksConfig, StreamTransportConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_transport::{
    BoxDatagramSession, BoxStream, Datagram, ServerFirstStream, datagram_channel, establish_stream,
};

use crate::outline::{PrefixedProxyStream, prefixed_salt};
use crate::simple_obfs::SimpleObfsStream;
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use tokio::io::ReadBuf;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ShadowsocksOutbound {
    server: Arc<ServerConfig>,
    context: SharedContext,
    dialer: ProtectedDialer,
    udp: bool,
    method: CipherKind,
    /// The carrier under the codec. Non-`Raw` is a SIP003 `v2ray-plugin`
    /// tunnel expressed natively instead of as a subprocess; `obfs` is the
    /// other SIP003 plugin this core speaks, `simple-obfs`.
    config: Arc<ShadowsocksConfig>,
}

impl ShadowsocksOutbound {
    pub async fn new(config: ShadowsocksConfig, dialer: ProtectedDialer) -> io::Result<Self> {
        let server_address = dialer
            .resolve_server(&config.server, config.port, config.server_ip)
            .await?;
        let method = CipherKind::from_str(&config.method)
            .map_err(|error| invalid(format!("unsupported Shadowsocks method: {error}")))?;
        let server = ServerConfig::new(
            ServerAddr::SocketAddr(server_address),
            config.password.expose(),
            method,
        )
        .map_err(|error| invalid(format!("invalid Shadowsocks configuration: {error}")))?;
        if let Some(prefix) = &config.outline_prefix {
            // Checked once here so an impossible pairing of prefix and cipher
            // is a refused profile rather than a connection that fails later.
            prefixed_salt(method, prefix)?;
        }
        Ok(Self {
            server: Arc::new(server),
            context: Context::new_shared(ServerType::Local),
            dialer,
            udp: config.udp,
            method,
            config: Arc::new(config),
        })
    }

    pub async fn connect_stream(&self, destination: &Destination) -> io::Result<BoxStream> {
        let tcp = self
            .dialer
            .connect_tcp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        // The codec does not care what it rides on, so the carrier is composed
        // first and the Shadowsocks stream is layered over whatever came back.
        let carrier: BoxStream = match &self.config.obfs {
            Some(obfs) => Box::new(SimpleObfsStream::new(tcp, obfs, self.config.port)),
            None => {
                establish_stream(
                    tcp,
                    &self.config.tls,
                    &self.config.transport,
                    &self.config.server,
                    self.config.port,
                )
                .await?
            }
        };
        let Some(prefix) = &self.config.outline_prefix else {
            let stream = ProxyClientStream::from_stream(
                self.context.clone(),
                carrier,
                &self.server,
                to_address(destination),
            );
            // Salt and target address leave on the first write, so a server-first
            // destination — SSH, SMTP, IMAP, FTP, MySQL — would otherwise wait for
            // a banner the Shadowsocks server cannot ask for. `ServerFirstStream`
            // turns the caller's first *read* into the zero-length write that
            // upstream documents as "send the handshake and no payload".
            return Ok(Box::new(ServerFirstStream::new(stream)));
        };
        // A prefixed connection has to *derive* from the salt it sends, so the
        // salt is drawn here and handed to the writer rather than rewritten on
        // the wire afterwards.
        let salt = prefixed_salt(self.method, prefix)?;
        Ok(Box::new(ServerFirstStream::new(PrefixedProxyStream::new(
            self.context.clone(),
            carrier,
            self.method,
            self.server.key(),
            &salt,
            to_address(destination),
        ))))
    }

    pub async fn connect_datagram(
        &self,
        destination: &Destination,
    ) -> io::Result<BoxDatagramSession> {
        if !self.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is disabled for this Shadowsocks profile",
            ));
        }
        if !matches!(self.config.transport, StreamTransportConfig::Raw)
            || self.config.obfs.is_some()
        {
            // Refused rather than sent around the carrier: a datagram aimed at
            // the plugin's port in the clear is a different protocol than the
            // profile describes, and the port will not answer it anyway.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Shadowsocks over a stream transport carries TCP only",
            ));
        }
        let socket = self
            .dialer
            .connect_udp_server(&self.config.server, self.config.port, self.config.server_ip)
            .await?;
        let proxy = ProxySocket::from_socket(
            UdpSocketType::Client,
            self.context.clone(),
            &self.server,
            ProtectedUdpSocket(socket),
        );
        let (session, mut channels) = datagram_channel(64);
        let default_destination = destination.clone();
        let cancel = channels.cancel.clone();
        tokio::spawn(async move {
            relay_datagrams(
                proxy,
                default_destination,
                &mut channels.uplink,
                channels.downlink,
                cancel,
            )
            .await;
        });
        Ok(session)
    }
}

fn to_address(destination: &Destination) -> Address {
    match destination.ip() {
        Some(ip) => Address::SocketAddress(SocketAddr::new(ip, destination.port)),
        None => Address::DomainNameAddress(destination.host.clone(), destination.port),
    }
}

fn from_address(address: Address) -> Destination {
    match address {
        Address::SocketAddress(address) => {
            Destination::new(address.ip().to_string(), address.port())
        }
        Address::DomainNameAddress(domain, port) => Destination::new(domain, port),
    }
}

async fn relay_datagrams(
    proxy: ProxySocket<ProtectedUdpSocket>,
    default_destination: Destination,
    uplink: &mut tokio::sync::mpsc::Receiver<Datagram>,
    downlink: tokio::sync::mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let mut receive_buffer = vec![0_u8; 65_536];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            outgoing = uplink.recv() => {
                let Some(outgoing) = outgoing else { break };
                let destination = if outgoing.destination.host.is_empty() {
                    &default_destination
                } else {
                    &outgoing.destination
                };
                if proxy
                    .send(&to_address(destination), &outgoing.payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            received = proxy.recv(&mut receive_buffer) => {
                let Ok((length, address, _wire_length)) = received else { break };
                let datagram = Datagram::new(
                    from_address(address),
                    Bytes::copy_from_slice(&receive_buffer[..length]),
                );
                if downlink.send(datagram).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[derive(Debug)]
struct ProtectedUdpSocket(tokio::net::UdpSocket);

impl DatagramSocket for ProtectedUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl DatagramReceive for ProtectedUdpSocket {
    fn poll_recv(
        &self,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0.poll_recv(context, buffer)
    }

    fn poll_recv_from(
        &self,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.0.poll_recv_from(context, buffer)
    }

    fn poll_recv_ready(&self, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.poll_recv_ready(context)
    }
}

impl DatagramSend for ProtectedUdpSocket {
    fn poll_send(&self, context: &mut TaskContext<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(context, buffer)
    }

    fn poll_send_to(
        &self,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send_to(context, buffer, target)
    }

    fn poll_send_ready(&self, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.0.poll_send_ready(context)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_address_roundtrips() {
        let destinations = [
            Destination::new("example.com", 443),
            Destination::new("1.2.3.4", 53),
            Destination::new("2001:db8::1", 853),
        ];
        for destination in destinations {
            assert_eq!(from_address(to_address(&destination)), destination);
        }
    }

    #[test]
    fn known_aead_methods_parse() {
        assert!(CipherKind::from_str("aes-128-gcm").is_ok());
        assert!(CipherKind::from_str("2022-blake3-aes-128-gcm").is_ok());
    }

    fn profile(port: u16) -> ShadowsocksConfig {
        ShadowsocksConfig {
            server: "127.0.0.1".into(),
            port,
            server_ip: None,
            method: "chacha20-ietf-poly1305".into(),
            password: foxcore_api::SecretString::new("hunter2"),
            udp: false,
            transport: StreamTransportConfig::Raw,
            tls: Default::default(),
            outline_prefix: None,
            obfs: None,
        }
    }

    /// Open one connection through the real outbound and hand back what
    /// actually arrived at the far end. The module tests prove each carrier in
    /// isolation; this proves the config field reaches the socket.
    async fn first_bytes_on_the_wire(config: ShadowsocksConfig, count: usize) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            let mut head = vec![0_u8; count];
            server.read_exact(&mut head).await.unwrap();
            head
        });

        let outbound = ShadowsocksOutbound::new(
            ShadowsocksConfig { port, ..config },
            foxcore_dialer::ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        stream.write_all(b"payload").await.unwrap();
        stream.flush().await.unwrap();
        accept.await.unwrap()
    }

    #[tokio::test]
    async fn an_outline_profile_opens_the_connection_with_its_prefix() {
        let head = first_bytes_on_the_wire(
            ShadowsocksConfig {
                outline_prefix: Some(b"POST ".to_vec()),
                ..profile(0)
            },
            5,
        )
        .await;
        assert_eq!(head, b"POST ");
    }

    #[tokio::test]
    async fn a_simple_obfs_profile_opens_the_connection_with_its_disguise() {
        let head = first_bytes_on_the_wire(
            ShadowsocksConfig {
                obfs: Some(foxcore_api::SimpleObfsConfig::Tls {
                    host: "www.bing.com".into(),
                }),
                ..profile(0)
            },
            3,
        )
        .await;
        assert_eq!(head, &[0x16, 0x03, 0x01]);

        let head = first_bytes_on_the_wire(
            ShadowsocksConfig {
                obfs: Some(foxcore_api::SimpleObfsConfig::Http {
                    host: "www.bing.com".into(),
                    uri: "/".into(),
                    method: "GET".into(),
                }),
                ..profile(0)
            },
            16,
        )
        .await;
        assert_eq!(&head, b"GET / HTTP/1.1\r\n");
    }

    /// Open a connection through the real outbound, read before writing
    /// anything, and hand back the plaintext a Shadowsocks server would see.
    ///
    /// Nothing is ever written by the caller, so whatever the server decrypts
    /// is the request header and nothing else.
    async fn opening_payload_when_the_caller_reads_first(config: ShadowsocksConfig) -> Vec<u8> {
        use shadowsocks::relay::tcprelay::crypto_io::{CryptoRead, CryptoStream, StreamType};
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let method = CipherKind::from_str(&config.method).unwrap();
        let password = config.password.expose().to_owned();
        let accept = tokio::spawn(async move {
            let (server, _) = listener.accept().await.unwrap();
            let context = Context::new_shared(ServerType::Server);
            let server_config = ServerConfig::new(
                ServerAddr::SocketAddr(SocketAddr::from(([127, 0, 0, 1], 1))),
                password,
                method,
            )
            .unwrap();
            let mut crypto = CryptoStream::from_stream(
                &context,
                server,
                StreamType::Server,
                method,
                server_config.key(),
            );
            let mut buffer = vec![0_u8; 512];
            let mut read = ReadBuf::new(&mut buffer);
            std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut crypto).poll_read_decrypted(cx, &context, &mut read)
            })
            .await
            .unwrap();
            read.filled().to_vec()
        });

        let outbound = ShadowsocksOutbound::new(
            ShadowsocksConfig { port, ..config },
            foxcore_dialer::ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let mut stream = outbound
            .connect_stream(&Destination::new("example.com", 443))
            .await
            .unwrap();
        // The caller reads and never writes, which is every protocol whose
        // server sends the banner.
        let reader = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        let payload = tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("a server-first destination must not deadlock")
            .unwrap();
        reader.abort();
        payload
    }

    /// The deadlock this closes: salt and target address only ever left on an
    /// application *write*, so SSH, SMTP, IMAP, FTP and MySQL through a
    /// Shadowsocks profile hung with zero bytes on the wire — the client waiting
    /// for a banner and the server waiting to be told where to connect.
    #[tokio::test]
    async fn a_caller_that_reads_first_still_sends_salt_and_target_address() {
        let mut expected = bytes::BytesMut::new();
        Address::DomainNameAddress("example.com".to_owned(), 443).write_to_buf(&mut expected);

        assert_eq!(
            opening_payload_when_the_caller_reads_first(profile(0)).await,
            &expected[..]
        );

        // The Outline variant runs its own stream type, so it needs its own
        // proof rather than inheriting this one.
        assert_eq!(
            opening_payload_when_the_caller_reads_first(ShadowsocksConfig {
                outline_prefix: Some(b"POST ".to_vec()),
                ..profile(0)
            })
            .await,
            &expected[..]
        );
    }

    /// Without a prefix nothing about the existing path changes, including the
    /// salt being drawn by the crate rather than by us.
    #[tokio::test]
    async fn a_plain_profile_still_opens_with_a_random_salt() {
        let first = first_bytes_on_the_wire(profile(0), 32).await;
        let second = first_bytes_on_the_wire(profile(0), 32).await;
        assert_ne!(first, second);
    }
}
