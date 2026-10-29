use std::{io, sync::Mutex};

use bytes::{Buf, Bytes};
use foxcore_dns::{http_query, restore_transaction_id};
use h3::error::Code;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};

const DNS_MESSAGE_TYPE: &str = "application/dns-message";
const MAX_HEADER_BYTES: u64 = 16 * 1024;

type Sender = h3::client::SendRequest<super::h3io::OpenStreams, Bytes>;
type Stream = h3::client::RequestStream<super::h3io::BidiStream, Bytes>;

pub(super) struct Http3Client {
    sender: Mutex<Sender>,
    driver: tokio::task::JoinHandle<()>,
}

impl Drop for Http3Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Http3Client {
    pub(super) fn is_closed(&self) -> bool {
        self.driver.is_finished()
    }

    pub(super) async fn new(connection: quinn::Connection) -> io::Result<Self> {
        let (mut connection, sender) = h3::client::builder()
            .max_field_section_size(MAX_HEADER_BYTES)
            .build(super::h3io::Connection::new(connection))
            .await
            .map_err(|_| invalid("DNS HTTP/3 handshake failed"))?;
        let driver = tokio::spawn(async move {
            let _ = connection.wait_idle().await;
        });
        Ok(Self {
            sender: Mutex::new(sender),
            driver,
        })
    }

    pub(super) async fn exchange(
        &self,
        endpoint: &str,
        query: &[u8],
        max_response_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        if !(12..=65535).contains(&query.len()) || !(12..=65535).contains(&max_response_bytes) {
            return Err(invalid("DNS HTTP/3 message limit is invalid"));
        }
        let (transaction_id, query) =
            http_query(query).ok_or_else(|| invalid("invalid DNS HTTP/3 query"))?;
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(endpoint)
            .header(ACCEPT, DNS_MESSAGE_TYPE)
            .header(CONTENT_TYPE, DNS_MESSAGE_TYPE)
            .header(CONTENT_LENGTH, query.len())
            .body(())
            .map_err(|_| invalid("invalid DNS HTTP/3 URI"))?;
        let mut sender = self
            .sender
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let stream = sender
            .send_request(request)
            .await
            .map_err(|_| invalid("DNS HTTP/3 request failed"))?;
        let mut request = RequestGuard {
            stream,
            completed: false,
        };
        request
            .stream
            .send_data(Bytes::from(query))
            .await
            .map_err(|_| invalid("DNS HTTP/3 query write failed"))?;
        request
            .stream
            .finish()
            .await
            .map_err(|_| invalid("DNS HTTP/3 query FIN failed"))?;
        let response = request
            .stream
            .recv_response()
            .await
            .map_err(|_| invalid("DNS HTTP/3 response headers failed"))?;
        if !response.status().is_success()
            || !response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(is_dns_message_type)
        {
            return Err(invalid("DNS HTTP/3 response is not DNS wire format"));
        }
        let expected_length = if let Some(length) = response.headers().get(CONTENT_LENGTH) {
            let length = length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| invalid("DNS HTTP/3 content length is invalid"))?;
            if !(12..=max_response_bytes).contains(&length) {
                return Err(invalid("DNS HTTP/3 response exceeds its message bounds"));
            }
            Some(length)
        } else {
            None
        };
        let mut output = Vec::new();
        while let Some(mut data) = request
            .stream
            .recv_data()
            .await
            .map_err(|_| invalid("DNS HTTP/3 body failed"))?
        {
            if output.len().saturating_add(data.remaining()) > max_response_bytes {
                return Err(invalid("DNS HTTP/3 response exceeds configured limit"));
            }
            while data.has_remaining() {
                let chunk = data.chunk();
                output.extend_from_slice(chunk);
                let length = chunk.len();
                data.advance(length);
            }
        }
        // Consume a possible trailing field section under the same 16 KiB
        // parser limit, and require the stream's normal end before accepting it.
        let _ = request
            .stream
            .recv_trailers()
            .await
            .map_err(|_| invalid("DNS HTTP/3 trailers failed"))?;
        if output.len() < 12
            || expected_length.is_some_and(|length| length != output.len())
            || output[..2] != [0, 0]
            || !restore_transaction_id(&mut output, transaction_id)
        {
            return Err(invalid(
                "DNS HTTP/3 response header or transaction ID is invalid",
            ));
        }
        request.completed = true;
        Ok(output)
    }
}

struct RequestGuard {
    stream: Stream,
    completed: bool,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            self.stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }
}

fn is_dns_message_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case(DNS_MESSAGE_TYPE)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_quic::{DnsQuicProtocol, connect_dns_quic_socket};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn query() -> Vec<u8> {
        let mut value = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        value.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        value
    }

    fn server_endpoint(window: Option<u32>) -> (quinn::Endpoint, String) {
        let generated = rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
        let (_, parsed) =
            x509_parser::parse_x509_certificate(generated.cert.der().as_ref()).unwrap();
        let pin = STANDARD.encode(Sha256::digest(parsed.tbs_certificate.subject_pki.raw));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![generated.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        if let Some(window) = window {
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(window.into());
            transport.receive_window((128u32 * 1024).into());
            config.transport_config(Arc::new(transport));
        }
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        (endpoint, pin)
    }

    async fn server(
        content_type: &'static str,
        response_bytes: Option<usize>,
        wrong_id: bool,
    ) -> (
        SocketAddr,
        String,
        quinn::Endpoint,
        tokio::task::JoinHandle<()>,
    ) {
        let (endpoint, pin) = server_endpoint(None);
        let address = endpoint.local_addr().unwrap();
        let shutdown = endpoint.clone();
        let task = tokio::spawn(async move {
            let Ok(connection) = endpoint.accept().await.unwrap().await else {
                return;
            };
            let data = connection
                .handshake_data()
                .unwrap()
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .unwrap();
            assert_eq!(data.protocol.as_deref(), Some(b"h3".as_slice()));
            assert_eq!(data.server_name.as_deref(), Some("dns.example"));
            let mut h3 = h3::server::builder()
                .max_field_section_size(16 * 1024)
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
            let Ok(Some(resolver)) = h3.accept().await else {
                return;
            };
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/custom-dns");
            assert_eq!(request.uri().authority().unwrap().host(), "dns.example");
            assert_eq!(
                request.headers()[http::header::CONTENT_TYPE],
                "application/dns-message"
            );
            let mut request_body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                while data.has_remaining() {
                    let chunk = data.chunk();
                    request_body.extend_from_slice(chunk);
                    let length = chunk.len();
                    data.advance(length);
                }
            }
            assert_eq!(&request_body[..2], &[0, 0]);
            let mut answer = request_body;
            answer[2] |= 0x80;
            if wrong_id {
                answer[..2].copy_from_slice(&[0, 1]);
            }
            if let Some(length) = response_bytes {
                answer.resize(length, 0);
            }
            stream
                .send_response(
                    http::Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_TYPE, content_type)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            let _ = stream.send_data(Bytes::from(answer)).await;
            let _ = stream.finish().await;
            let _ = connection.closed().await;
            endpoint.close(0u32.into(), b"test complete");
        });
        (address, pin, shutdown, task)
    }

    async fn request(
        content_type: &'static str,
        length: Option<usize>,
        wrong_id: bool,
        cap: usize,
    ) -> io::Result<Vec<u8>> {
        let (peer, pin, shutdown, server) = server(content_type, length, wrong_id).await;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let tls = foxcore_api::TlsConfig {
            enabled: true,
            pinned_spki_sha256: Some(pin),
            ..Default::default()
        };
        let client =
            connect_dns_quic_socket(socket, peer, &tls, "dns.example", DnsQuicProtocol::Doh3)
                .await
                .unwrap();
        let result = client
            .exchange_doh3(
                &format!("https://dns.example:{}/custom-dns", peer.port()),
                &query(),
                cap,
            )
            .await;
        drop(client);
        shutdown.close(0u32.into(), b"test complete");
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        result
    }

    #[tokio::test]
    async fn h3_dns_uses_the_original_origin_alpn_pin_and_post_body_then_restores_id() {
        let answer = request("Application/DNS-Message; charset=utf-8", None, false, 65535)
            .await
            .unwrap();
        assert_eq!(&answer[..2], &[0x12, 0x34]);
        assert_ne!(answer[2] & 0x80, 0);
    }

    #[tokio::test]
    async fn cancellation_with_pending_h3_response_headers_and_body_is_safe_and_stream_scoped() {
        use std::future::Future;
        use std::task::Poll;
        for body_phase in [false, true] {
            let (endpoint, pin) = server_endpoint(None);
            let address = endpoint.local_addr().unwrap();
            let shutdown = endpoint.clone();
            let (ready, observed) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let (cancelled, cancellation_observed) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let mut h3 = h3::server::builder()
                    .max_field_section_size(16 * 1024)
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
                let resolver = h3.accept().await.unwrap().unwrap();
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                while stream.recv_data().await.unwrap().is_some() {}
                if body_phase {
                    stream
                        .send_response(
                            http::Response::builder()
                                .status(200)
                                .header(CONTENT_TYPE, "application/dns-message")
                                .body(())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    stream.send_data(Bytes::from_static(b"abc")).await.unwrap();
                }
                ready.send(()).unwrap();
                released.await.unwrap();
                // Exceed the receive window without FIN so STOP_SENDING must
                // terminate this write; no timer-based scheduling assumption.
                let error = if body_phase {
                    stream
                        .send_data(Bytes::from(vec![0; 128 * 1024 + 1]))
                        .await
                        .unwrap_err()
                } else {
                    match stream
                        .send_response(
                            http::Response::builder()
                                .status(200)
                                .header(CONTENT_TYPE, "application/dns-message")
                                .body(())
                                .unwrap(),
                        )
                        .await
                    {
                        Err(error) => error,
                        Ok(()) => stream
                            .send_data(Bytes::from(vec![0; 128 * 1024 + 1]))
                            .await
                            .unwrap_err(),
                    }
                };
                assert!(
                    matches!(error, h3::error::StreamError::RemoteTerminate { code, .. } if code == Code::H3_REQUEST_CANCELLED)
                );
                assert!(connection.close_reason().is_none());
                cancelled.send(()).unwrap();
                let _ = connection.closed().await;
                endpoint.close(0u32.into(), b"test complete");
            });
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let tls = foxcore_api::TlsConfig {
                enabled: true,
                pinned_spki_sha256: Some(pin),
                ..Default::default()
            };
            let client = connect_dns_quic_socket(
                socket,
                address,
                &tls,
                "dns.example",
                DnsQuicProtocol::Doh3,
            )
            .await
            .unwrap();
            let mut sender = client
                .http3
                .as_ref()
                .unwrap()
                .sender
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(format!("https://dns.example:{}/custom-dns", address.port()))
                .header(CONTENT_TYPE, "application/dns-message")
                .body(())
                .unwrap();
            let stream = sender.send_request(request).await.unwrap();
            let mut guard = RequestGuard {
                stream,
                completed: false,
            };
            let mut packet = query();
            packet[..2].fill(0);
            guard.stream.send_data(Bytes::from(packet)).await.unwrap();
            guard.stream.finish().await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(3), observed)
                .await
                .unwrap()
                .unwrap();
            if body_phase {
                guard.stream.recv_response().await.unwrap();
                futures::future::poll_fn(|cx| {
                    loop {
                        match guard.stream.poll_recv_data(cx) {
                            Poll::Pending => return Poll::Ready(()),
                            Poll::Ready(Ok(Some(_))) => continue,
                            _ => panic!("body must remain unfinished before cancellation"),
                        }
                    }
                })
                .await;
            } else {
                let mut read = Box::pin(guard.stream.recv_response());
                futures::future::poll_fn(|cx| {
                    assert!(read.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(read);
            }
            // The actual pending read was polled above. Dropping this exact
            // production guard must STOP/RESET the owned stream, never panic.
            drop(guard);
            release.send(()).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(3), cancellation_observed)
                .await
                .unwrap()
                .unwrap();
            assert!(!client.is_closed());
            drop(sender);
            drop(client);
            shutdown.close(0u32.into(), b"test complete");
            tokio::time::timeout(std::time::Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn cancellation_during_h3_headers_stops_and_resets_only_that_request() {
        let (endpoint, pin) = server_endpoint(Some(128));
        let address = endpoint.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            (connection, endpoint)
        });
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tls = foxcore_api::TlsConfig {
            enabled: true,
            pinned_spki_sha256: Some(pin),
            ..Default::default()
        };
        let client = Arc::new(
            connect_dns_quic_socket(socket, address, &tls, "dns.example", DnsQuicProtocol::Doh3)
                .await
                .unwrap(),
        );
        let (peer, endpoint) = accepted.await.unwrap();
        let request_client = client.clone();
        let pending = tokio::spawn(async move {
            let endpoint = format!(
                "https://dns.example:{}/{}",
                address.port(),
                "x".repeat(3000)
            );
            request_client
                .exchange_doh3(&endpoint, &query(), 65535)
                .await
        });
        let (send, mut receive) =
            tokio::time::timeout(std::time::Duration::from_secs(3), peer.accept_bi())
                .await
                .unwrap()
                .unwrap();
        // Leave the 128-byte receive window closed: send_request is still
        // writing its HEADERS and has not returned a public RequestStream.
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        let (stopped, reset) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(send.stopped(), receive.read_to_end(4096))
        })
        .await
        .unwrap();
        assert_eq!(stopped.unwrap(), Some(quinn::VarInt::from_u32(0x10c)));
        assert!(
            matches!(reset, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code == quinn::VarInt::from_u32(0x10c))
        );
        assert!(!client.is_closed());
        drop(client);
        endpoint.close(0u32.into(), b"test complete");
    }

    #[tokio::test]
    async fn a_pooled_h3_client_cannot_send_to_a_different_origin() {
        let (peer, pin, shutdown, server) = server("application/dns-message", None, false).await;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tls = foxcore_api::TlsConfig {
            enabled: true,
            pinned_spki_sha256: Some(pin),
            ..Default::default()
        };
        let client =
            connect_dns_quic_socket(socket, peer, &tls, "dns.example", DnsQuicProtocol::Doh3)
                .await
                .unwrap();
        assert_eq!(
            client
                .exchange_doh3(
                    &format!("https://other.example:{}/custom-dns", peer.port()),
                    &query(),
                    65535
                )
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(client);
        shutdown.close(0u32.into(), b"test complete");
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn quic_dns_refuses_an_untrusted_key_a_wrong_pin_and_wrong_alpn() {
        for (pin, protocol) in [
            (None, DnsQuicProtocol::Doh3),
            (
                Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()),
                DnsQuicProtocol::Doh3,
            ),
        ] {
            let (peer, _actual_pin, shutdown, server) =
                server("application/dns-message", None, false).await;
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let tls = foxcore_api::TlsConfig {
                enabled: true,
                pinned_spki_sha256: pin,
                ..Default::default()
            };
            assert!(
                connect_dns_quic_socket(socket, peer, &tls, "dns.example", protocol)
                    .await
                    .is_err()
            );
            shutdown.close(0u32.into(), b"test complete");
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
        let (peer, pin, shutdown, server) = server("application/dns-message", None, false).await;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tls = foxcore_api::TlsConfig {
            enabled: true,
            pinned_spki_sha256: Some(pin),
            ..Default::default()
        };
        assert!(
            connect_dns_quic_socket(socket, peer, &tls, "dns.example", DnsQuicProtocol::Doq)
                .await
                .is_err()
        );
        shutdown.close(0u32.into(), b"test complete");
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn h3_dns_refuses_a_false_media_type_a_short_body_an_oversize_body_and_nonzero_wire_id() {
        for (media, length, wrong_id, cap) in [
            ("application/dns-message-suffix", None, false, 65535),
            ("application/dns-message", Some(11), false, 65535),
            ("application/dns-message", Some(129), false, 128),
            ("application/dns-message", None, true, 65535),
        ] {
            assert_eq!(
                request(media, length, wrong_id, cap)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
