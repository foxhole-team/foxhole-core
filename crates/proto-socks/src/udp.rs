//! RFC 1928 §7 `UDP ASSOCIATE`.
//!
//! The TCP control connection is *not* incidental: it defines the lifetime of
//! the association, so the relay task holds it open and tears the session down
//! the moment the proxy closes it.

use std::io;
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use foxcore_api::Destination;
use foxcore_transport::{BoxDatagramSession, Datagram, datagram_channel};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::SocksOutbound;
use crate::codec::{CMD_UDP_ASSOCIATE, MAX_UDP_DATAGRAM, decode_udp_datagram, encode_udp_datagram};

/// The client's future source address is unknown before the socket is bound, so
/// RFC 1928 tells us to send an all-zero `DST.ADDR`/`DST.PORT`.
const UNSPECIFIED_SOURCE: &str = "0.0.0.0";

/// Chunk size for draining the control connection. Sized so a chatty proxy costs one syscall per
/// chunk instead of one per byte; nothing is ever parsed out of it.
const CONTROL_DRAIN_BUFFER: usize = 512;

/// How much undefined chatter the control connection may produce before the association is dropped.
/// Generous enough that a keep-alive or a stray banner is absorbed, small enough that an endless
/// stream cannot keep this task fed forever.
const MAX_UNSOLICITED_CONTROL_BYTES: usize = 64 * 1024;

pub(crate) async fn associate(
    outbound: &SocksOutbound,
    destination: &Destination,
) -> io::Result<BoxDatagramSession> {
    let mut control = outbound
        .dialer
        .connect_tcp_server(
            &outbound.config.server,
            outbound.config.port,
            outbound.config.server_ip,
        )
        .await?;
    let server_address = control.peer_addr()?;
    let bound = outbound
        .run_handshake(
            &mut control,
            CMD_UDP_ASSOCIATE,
            &Destination::new(UNSPECIFIED_SOURCE, 0),
        )
        .await?;
    let relay = relay_address(outbound, &bound, server_address).await?;
    // `connect` pins the socket to the relay, so a third party spraying the
    // ephemeral port cannot inject datagrams into the session.
    let socket = outbound.dialer.connect_udp(relay).await?;

    let (session, mut channels) = datagram_channel(64);
    let default_destination = destination.clone();
    tokio::spawn(async move {
        relay_datagrams(
            control,
            socket,
            default_destination,
            &mut channels.uplink,
            channels.downlink,
            channels.cancel,
        )
        .await;
    });
    Ok(session)
}

/// Resolve the relay endpoint the server advertised.
///
/// A wildcard `BND.ADDR` means "same host as this control connection" — every
/// real deployment relies on that, and following it literally would send
/// datagrams to 0.0.0.0.
async fn relay_address(
    outbound: &SocksOutbound,
    bound: &Destination,
    server_address: SocketAddr,
) -> io::Result<SocketAddr> {
    if bound.port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP ASSOCIATE returned port 0",
        ));
    }
    match bound.ip() {
        Some(address) if address.is_unspecified() => {
            Ok(SocketAddr::new(server_address.ip(), bound.port))
        }
        Some(address) => Ok(SocketAddr::new(address, bound.port)),
        None => outbound.dialer.resolve_one(&bound.host, bound.port).await,
    }
}

async fn relay_datagrams(
    mut control: TcpStream,
    socket: UdpSocket,
    default_destination: Destination,
    uplink: &mut mpsc::Receiver<Datagram>,
    downlink: mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    let mut inbound = vec![0_u8; MAX_UDP_DATAGRAM];
    let mut control_probe = [0_u8; CONTROL_DRAIN_BUFFER];
    // Budget for bytes the protocol never defined. See the select arm below.
    let mut control_slack = MAX_UNSOLICITED_CONTROL_BYTES;
    let mut outbound_frame = BytesMut::with_capacity(MAX_UDP_DATAGRAM);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            // RFC 1928 §7 ties the association's lifetime to this TCP connection:
            // it ends when the connection ends, and not before. The request and
            // its reply are both behind us, so there is nothing left to receive
            // here — but "nothing to receive" is not "anything received is fatal".
            //
            // A one-byte probe that looped on every byte is what made this a hot
            // loop: the arm was ready again the instant it returned, so a proxy
            // that kept writing held a core at 100%, one `read` per byte, while
            // the association looked healthy. Killing the association on the
            // first stray byte would fix the spin by breaking every
            // non-conforming-but-harmless proxy that keeps its control
            // connection warm.
            //
            // So: read in chunks and discard. EOF or error ends the association,
            // because that is what the RFC actually says ends it. An endless
            // stream is still refused, but on a finite budget rather than on the
            // first byte — a peer that will not stop talking is not one whose
            // datagrams we can keep vouching for.
            read = control.read(&mut control_probe) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(length) => {
                        control_slack = control_slack.saturating_sub(length);
                        if control_slack == 0 {
                            break;
                        }
                    }
                }
            }
            outgoing = uplink.recv() => {
                let Some(outgoing) = outgoing else { break };
                let destination = if outgoing.destination.host.is_empty() {
                    &default_destination
                } else {
                    &outgoing.destination
                };
                outbound_frame.clear();
                if encode_udp_datagram(destination, &outgoing.payload, &mut outbound_frame).is_err() {
                    continue;
                }
                if socket.send(&outbound_frame).await.is_err() {
                    break;
                }
            }
            received = socket.recv(&mut inbound) => {
                let Ok(length) = received else { break };
                // A malformed or fragmented reply is dropped rather than
                // fatal: one bad datagram must not take down the session.
                let Ok((source, payload)) = decode_udp_datagram(&inbound[..length]) else {
                    continue;
                };
                let datagram = Datagram::new(source, Bytes::copy_from_slice(payload));
                if downlink.send(datagram).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use foxcore_dialer::ProtectedDialer;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use super::*;
    use crate::SocksConfig;

    /// In-process UDP relay: echoes the payload back from the address the
    /// client asked for.
    async fn spawn_udp_relay() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let (destination, payload) = decode_udp_datagram(&buffer[..length]).unwrap();
            assert_eq!(destination, Destination::new("dns.example", 53));
            assert_eq!(payload, b"question");

            let mut reply = BytesMut::new();
            encode_udp_datagram(&Destination::new("203.0.113.9", 53), b"answer", &mut reply)
                .unwrap();
            socket.send_to(&reply, peer).await.unwrap();
        });
        (address, handle)
    }

    #[tokio::test]
    async fn udp_associate_round_trips_a_datagram_with_a_remote_hostname() {
        let (relay, relay_task) = spawn_udp_relay().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let control = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0_u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&relay.port().to_be_bytes());
            stream.write_all(&reply).await.unwrap();
            // Hold the association open until the test drops the session.
            let mut sink = [0_u8; 1];
            let _ = stream.read(&mut sink).await;
        });

        let outbound = SocksOutbound::new(
            SocksConfig {
                server: proxy.ip().to_string(),
                port: proxy.port(),
                ..SocksConfig::default()
            },
            ProtectedDialer::host(),
        )
        .await
        .unwrap();

        let session = outbound
            .connect_datagram(&Destination::new("dns.example", 53))
            .await
            .unwrap();
        session
            .send(Datagram::new(
                Destination::new("dns.example", 53),
                Bytes::from_static(b"question"),
            ))
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("the UDP reply must arrive")
            .unwrap();
        assert_eq!(received.destination, Destination::new("203.0.113.9", 53));
        assert_eq!(received.payload, b"answer"[..]);

        drop(session);
        relay_task.await.unwrap();
        control.await.unwrap();
    }

    /// Stand up an association against an in-process proxy that either keeps
    /// its control connection silent or keeps writing on it, then let the relay
    /// run on a clock that only advances while every task is parked.
    ///
    /// That clock is the whole measurement. `tokio` auto-advances paused time
    /// when the runtime has nothing runnable, so an hour of it passes in
    /// microseconds if the relay is idle and never passes at all if the relay
    /// is spinning. The wall-clock watchdog on the outside is what turns "never"
    /// into a failed assertion instead of a hung test run.
    fn relay_reaches_idle(chatty_control: bool) -> bool {
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let relay_port = relay.local_addr().unwrap().port();
                tokio::spawn(async move {
                    let mut sink = vec![0_u8; 2048];
                    while relay.recv_from(&mut sink).await.is_ok() {}
                });

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let proxy = listener.local_addr().unwrap();
                tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut greeting = [0_u8; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    stream.write_all(&[0x05, 0x00]).await.unwrap();
                    let mut request = [0_u8; 10];
                    stream.read_exact(&mut request).await.unwrap();
                    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
                    reply.extend_from_slice(&relay_port.to_be_bytes());
                    stream.write_all(&reply).await.unwrap();
                    if chatty_control {
                        while stream.write_all(&[0x00; 64]).await.is_ok() {}
                    } else {
                        std::future::pending::<()>().await;
                    }
                });

                let outbound = SocksOutbound::new(
                    SocksConfig {
                        server: proxy.ip().to_string(),
                        port: proxy.port(),
                        ..SocksConfig::default()
                    },
                    ProtectedDialer::host(),
                )
                .await
                .unwrap();
                let session = outbound
                    .connect_datagram(&Destination::new("dns.example", 53))
                    .await
                    .unwrap();
                // Real time for the setup; the sockets have to actually connect.
                tokio::time::sleep(Duration::from_millis(100)).await;
                tokio::time::pause();
                tokio::time::sleep(Duration::from_secs(3600)).await;
                drop(session);
            });
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !worker.is_finished() {
            if std::time::Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        worker.join().unwrap();
        true
    }

    /// The relay must be asleep between datagrams.
    ///
    /// It was, until the proxy said anything. The control arm read one byte,
    /// dropped it and looped, so it was runnable again immediately: a proxy
    /// writing on the control connection held a core at 100% indefinitely while
    /// the association stayed up and every counter looked normal. RFC 1928 §7
    /// defines nothing to receive there, so the honest answer to a byte is to
    /// end the association.
    #[test]
    fn a_talkative_control_connection_does_not_spin_the_relay() {
        assert!(
            relay_reaches_idle(false),
            "an idle association must let the runtime park"
        );
        assert!(
            relay_reaches_idle(true),
            "a proxy writing on the control connection must not pin a core"
        );
    }

    /// RFC 1928 §7 ends the association with the TCP connection — not with the first byte the
    /// proxy has no business sending. A keep-alive is non-conforming and harmless; dropping UDP
    /// over it would be a self-inflicted outage on every proxy that does it.
    #[tokio::test]
    async fn a_keep_alive_on_the_control_connection_does_not_kill_the_association() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0_u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
            reply.extend_from_slice(&relay_port.to_be_bytes());
            stream.write_all(&reply).await.unwrap();
            // One stray keep-alive, then silence — the shape a real proxy produces.
            stream.write_all(&[0x00; 8]).await.unwrap();
            std::future::pending::<()>().await;
        });

        let outbound = SocksOutbound::new(
            SocksConfig {
                server: proxy.ip().to_string(),
                port: proxy.port(),
                ..SocksConfig::default()
            },
            ProtectedDialer::host(),
        )
        .await
        .unwrap();
        let session = outbound
            .connect_datagram(&Destination::new("dns.example", 53))
            .await
            .unwrap();
        session
            .send(Datagram::new(
                Destination::new("dns.example", 53),
                b"probe".to_vec(),
            ))
            .await
            .unwrap();

        let mut received = vec![0_u8; 2048];
        let read = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut received))
            .await
            .expect("the association must survive an unsolicited control byte")
            .unwrap();
        assert!(
            received[..read.0].ends_with(b"probe"),
            "the datagram must still reach the relay after the keep-alive"
        );
    }

    #[tokio::test]
    async fn a_wildcard_bound_address_falls_back_to_the_proxy_host() {
        let outbound = SocksOutbound {
            config: std::sync::Arc::new(SocksConfig::default()),
            dialer: ProtectedDialer::host(),
        };
        let server = "203.0.113.5:1080".parse().unwrap();
        let relay = relay_address(&outbound, &Destination::new("0.0.0.0", 5555), server)
            .await
            .unwrap();
        assert_eq!(relay, "203.0.113.5:5555".parse::<SocketAddr>().unwrap());

        let explicit = relay_address(&outbound, &Destination::new("198.51.100.4", 7777), server)
            .await
            .unwrap();
        assert_eq!(explicit, "198.51.100.4:7777".parse::<SocketAddr>().unwrap());

        assert!(
            relay_address(&outbound, &Destination::new("0.0.0.0", 0), server)
                .await
                .is_err()
        );
    }
}
