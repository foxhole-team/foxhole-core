use foxcore_dns::{doq_query, restore_doq_response};
use quinn::{Connection, ReadExactError, ReadToEndError, RecvStream, SendStream, VarInt};
use std::io;

const REQUEST_CANCELLED: VarInt = VarInt::from_u32(3);
const PROTOCOL_ERROR: VarInt = VarInt::from_u32(2);

struct Transaction {
    send: SendStream,
    recv: RecvStream,
    completed: bool,
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.recv.stop(REQUEST_CANCELLED);
            let _ = self.send.reset(REQUEST_CANCELLED);
        }
    }
}

pub(super) async fn exchange(
    connection: &Connection,
    query: &[u8],
    max_response_bytes: usize,
) -> io::Result<Vec<u8>> {
    let maximum = max_response_bytes.min(usize::from(u16::MAX));
    if maximum < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DoQ response limit",
        ));
    }
    let (transaction_id, wire) = doq_query(query)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid DoQ query"))?;
    let length = u16::try_from(wire.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "DoQ query exceeds 65535 bytes")
    })?;
    let (send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
    let mut transaction = Transaction {
        send,
        recv,
        completed: false,
    };
    transaction
        .send
        .write_all(&length.to_be_bytes())
        .await
        .map_err(io::Error::other)?;
    transaction
        .send
        .write_all(&wire)
        .await
        .map_err(io::Error::other)?;
    transaction.send.finish().map_err(io::Error::other)?;

    let mut prefix = [0; 2];
    match transaction.recv.read_exact(&mut prefix).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(_)) => return Err(protocol_error(connection)),
        Err(ReadExactError::ReadError(error)) => return Err(io::Error::other(error)),
    }
    let length = usize::from(u16::from_be_bytes(prefix));
    if length < 12 {
        return Err(protocol_error(connection));
    }
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "DoQ response exceeds configured limit",
        ));
    }
    // Local policy cancels a stream above; framing errors below close the peer.
    // Waiting for FIN prevents delivering a prefix of an unfinished reply.
    let mut response = match transaction.recv.read_to_end(length).await {
        Ok(response) => response,
        Err(ReadToEndError::TooLong) => return Err(protocol_error(connection)),
        Err(error) => return Err(io::Error::other(error)),
    };
    if response.len() != length {
        return Err(protocol_error(connection));
    }
    if !restore_doq_response(&mut response, transaction_id) {
        return Err(protocol_error(connection));
    }
    transaction.completed = true;
    Ok(response)
}

fn protocol_error(connection: &Connection) -> io::Error {
    connection.close(PROTOCOL_ERROR, b"invalid DoQ response");
    io::Error::new(io::ErrorKind::InvalidData, "invalid DoQ response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    fn query(id: u16) -> Vec<u8> {
        let mut packet = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        packet[..2].copy_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(b"\x04wire\x04test\0\0\x01\0\x01");
        packet
    }

    fn option(packet: &mut Vec<u8>, code: u16, data: &[u8]) {
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        packet.extend_from_slice(&(u16::try_from(data.len()).unwrap() + 4).to_be_bytes());
        packet.extend_from_slice(&code.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(data);
    }

    async fn peers(
        window: Option<u32>,
    ) -> (quinn::Endpoint, quinn::Endpoint, Connection, Connection) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(generated.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![generated.cert.der().clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"doq".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        if let Some(window) = window {
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(window.into());
            transport.receive_window(window.into());
            server_config.transport_config(Arc::new(transport));
        }
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"doq".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connecting = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (connected, accepted) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(connecting, async { server.accept().await.unwrap().await })
        })
        .await
        .unwrap();
        (client, server, connected.unwrap(), accepted.unwrap())
    }

    async fn request(recv: &mut RecvStream) -> Vec<u8> {
        let frame = recv.read_to_end(65_537).await.unwrap();
        assert!(frame.len() >= 14);
        assert_eq!(
            usize::from(u16::from_be_bytes([frame[0], frame[1]])),
            frame.len() - 2
        );
        assert_eq!(&frame[2..4], &[0, 0]);
        frame
    }

    async fn reply(send: &mut SendStream, mut frame: Vec<u8>) {
        frame[4] |= 0x80;
        send.write_all(&frame).await.unwrap();
        send.finish().unwrap();
    }

    #[tokio::test]
    async fn independent_streams_restore_each_callers_id_after_one_frame_and_fin() {
        let (_client, _server, connection, peer) = peers(None).await;
        let server_peer = peer.clone();
        let server = tokio::spawn(async move {
            let mut ids = Vec::new();
            for _ in 0..2 {
                let (mut send, mut recv) = server_peer.accept_bi().await.unwrap();
                ids.push(recv.id());
                let frame = request(&mut recv).await;
                reply(&mut send, frame).await;
            }
            assert_ne!(ids[0], ids[1]);
        });
        let first = query(0x1234);
        let second = query(0x5678);
        let (a, b) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                exchange(&connection, &first, 512),
                exchange(&connection, &second, 512)
            )
        })
        .await
        .unwrap();
        assert_eq!(&a.unwrap()[..2], &first[..2]);
        assert_eq!(&b.unwrap()[..2], &second[..2]);
        server.await.unwrap();
        assert!(connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn invalid_peer_frames_close_the_connection_with_protocol_error() {
        for case in ["id", "truncated", "extra", "oversized", "keepalive"] {
            let (_client, _server, connection, peer) = peers(None).await;
            let server_peer = peer.clone();
            let server = tokio::spawn(async move {
                let (mut send, mut recv) = server_peer.accept_bi().await.unwrap();
                let mut frame = request(&mut recv).await;
                frame[4] |= 0x80;
                match case {
                    "id" => frame[3] = 1,
                    "truncated" => {
                        frame.pop();
                    }
                    "extra" => frame.extend_from_slice(&frame.clone()),
                    "oversized" => {
                        frame = vec![0; 515];
                        frame[..2].copy_from_slice(&12u16.to_be_bytes());
                    }
                    "keepalive" => {
                        let mut packet = frame.split_off(2);
                        option(&mut packet, 11, &[]);
                        frame = u16::try_from(packet.len()).unwrap().to_be_bytes().to_vec();
                        frame.extend_from_slice(&packet);
                    }
                    _ => unreachable!(),
                }
                send.write_all(&frame).await.unwrap();
                send.finish().unwrap();
            });
            let error = tokio::time::timeout(
                Duration::from_secs(3),
                exchange(&connection, &query(7), 512),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{case}");
            server.await.unwrap();
            let closed = tokio::time::timeout(Duration::from_secs(3), peer.closed())
                .await
                .unwrap();
            assert!(
                matches!(closed, quinn::ConnectionError::ApplicationClosed(ref error) if error.error_code == VarInt::from_u32(2)),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn an_ordinary_server_stream_reset_propagates_without_closing_the_pool() {
        let (_client, _server, connection, peer) = peers(None).await;
        let server_peer = peer.clone();
        let server = tokio::spawn(async move {
            let (mut send, mut recv) = server_peer.accept_bi().await.unwrap();
            request(&mut recv).await;
            send.reset(VarInt::from_u32(1)).unwrap();
            let (mut send, mut recv) = server_peer.accept_bi().await.unwrap();
            let frame = request(&mut recv).await;
            reply(&mut send, frame).await;
        });
        assert!(
            tokio::time::timeout(
                Duration::from_secs(3),
                exchange(&connection, &query(1), 512)
            )
            .await
            .unwrap()
            .is_err()
        );
        assert!(connection.close_reason().is_none());
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(&connection, &query(2), 512),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..2], &[0, 2]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_legal_response_over_the_local_cap_cancels_only_its_stream() {
        let (_client, _server, connection, peer) = peers(None).await;
        let server_peer = peer.clone();
        let server = tokio::spawn(async move {
            let (mut send, mut recv) = server_peer.accept_bi().await.unwrap();
            let frame = request(&mut recv).await;
            let mut packet = frame[2..].to_vec();
            packet[2] |= 0x80;
            option(&mut packet, 12, &[0; 17_000]);
            assert!((16_385..=65_535).contains(&packet.len()));
            let mut validated = packet.clone();
            assert!(restore_doq_response(&mut validated, 0x7fff));
            let mut reply_frame = u16::try_from(packet.len()).unwrap().to_be_bytes().to_vec();
            reply_frame.extend_from_slice(&packet);
            // A conforming reply is larger than this caller wants. Withhold FIN
            // until its STOP_SENDING proves cancellation without a connection close.
            send.write_all(&reply_frame).await.unwrap();
            assert_eq!(send.stopped().await.unwrap(), Some(VarInt::from_u32(3)));
            let (mut send, mut recv) = server_peer.accept_bi().await.unwrap();
            let frame = request(&mut recv).await;
            reply(&mut send, frame).await;
        });
        let error = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(&connection, &query(0x7fff), 16_384),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(error.to_string(), "DoQ response exceeds configured limit");
        assert!(connection.close_reason().is_none());
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(&connection, &query(0x4242), 512),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..2], &[0x42, 0x42]);
        server.await.unwrap();
        assert!(connection.close_reason().is_none());
    }

    #[tokio::test]
    async fn cancellation_stops_and_resets_only_the_inflight_transaction_with_code_three() {
        let (_client, _server, connection, peer) = peers(Some(1024)).await;
        let server_peer = peer.clone();
        let mut packet = query(3);
        option(&mut packet, 12, &[0; 60_000]);
        let (ready, observed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (send, mut recv) = server_peer.accept_bi().await.unwrap();
            assert!(recv.read_chunk(1, true).await.unwrap().is_some());
            ready.send(()).unwrap();
            let (stopped, reset) = tokio::join!(send.stopped(), recv.read_to_end(65_537));
            assert_eq!(stopped.unwrap(), Some(VarInt::from_u32(3)));
            assert!(
                matches!(reset, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code == VarInt::from_u32(3))
            );
        });
        let client = connection.clone();
        let pending = tokio::spawn(async move { exchange(&client, &packet, 512).await });
        tokio::time::timeout(Duration::from_secs(3), observed)
            .await
            .unwrap()
            .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert!(connection.close_reason().is_none());
    }
}
