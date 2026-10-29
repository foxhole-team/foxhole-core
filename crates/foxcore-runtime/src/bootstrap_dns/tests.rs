use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use foxcore_dialer::SocketCallbacks;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use x509_parser::prelude::{FromDer, X509Certificate};

fn policy(upstream: DnsUpstream) -> BootstrapDnsConfig {
    BootstrapDnsConfig {
        domains: vec!["group.example".into()],
        upstreams: vec![upstream],
        timeout_ms: 500,
        max_candidates: 8,
    }
}

fn answer(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    let kind = u16::from_be_bytes(query[query.len() - 4..query.len() - 2].try_into().unwrap());
    if kind == 1 {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 7]);
    }
    response
}

fn protected(count: Arc<AtomicUsize>, fallback: Arc<AtomicUsize>) -> ProtectedDialer {
    let calls = count.clone();
    let callbacks = SocketCallbacks::new(
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            true
        },
        |_, network| network == 1,
    )
    .with_host_resolver(move |_, port| {
        fallback.fetch_add(1, Ordering::SeqCst);
        Ok(vec![SocketAddr::from(([192, 0, 2, 99], port))])
    });
    let dialer = ProtectedDialer::new(callbacks, Duration::from_millis(500));
    dialer.set_network_handle(1);
    dialer
}

#[tokio::test]
async fn udp_scopes_only_exact_names_preserves_port_and_is_fresh_each_dial() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = DnsUpstream::Udp {
        address: socket.local_addr().unwrap().to_string(),
    };
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        let mut query = [0; 512];
        loop {
            let (length, peer) = socket.recv_from(&mut query).await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            socket
                .send_to(&answer(&query[..length]), peer)
                .await
                .unwrap();
        }
    });
    let protections = Arc::new(AtomicUsize::new(0));
    let fallback = Arc::new(AtomicUsize::new(0));
    let dialer = install(
        protected(protections.clone(), fallback.clone()),
        &policy(upstream),
    );
    for _ in 0..2 {
        assert_eq!(
            dialer.resolve("GROUP.example.", 8443).await.unwrap(),
            vec![SocketAddr::from(([192, 0, 2, 7], 8443))]
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 4);
    assert_eq!(protections.load(Ordering::SeqCst), 4);
    assert_eq!(fallback.load(Ordering::SeqCst), 0);
    assert_eq!(
        dialer.resolve("other.group.example", 443).await.unwrap(),
        vec![SocketAddr::from(([192, 0, 2, 99], 443))]
    );
    assert_eq!(fallback.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn ipv6_only_group_is_accepted_without_changing_the_peer_port() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = DnsUpstream::Udp {
        address: socket.local_addr().unwrap().to_string(),
    };
    let ip: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
    let server = tokio::spawn(async move {
        let mut query = [0; 512];
        for _ in 0..2 {
            let (length, peer) = socket.recv_from(&mut query).await.unwrap();
            let mut response = query[..length].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            if query[length - 3] == 28 {
                response[7] = 1;
                response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16]);
                response.extend_from_slice(&ip.octets());
            }
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let dialer = install(ProtectedDialer::host(), &policy(upstream));
    assert_eq!(
        dialer.resolve("group.example", 2443).await.unwrap(),
        vec![SocketAddr::new(ip.into(), 2443)]
    );
    server.await.unwrap();
}

#[tokio::test]
async fn mapped_ipv6_answers_cannot_become_unspecified_multicast_or_broadcast_candidates() {
    for value in [
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ] {
        let ip: std::net::Ipv6Addr = value.parse().unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = DnsUpstream::Udp {
            address: socket.local_addr().unwrap().to_string(),
        };
        let server = tokio::spawn(async move {
            let mut query = [0; 512];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut query).await.unwrap();
                let mut response = query[..length].to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                if query[length - 3] == 28 {
                    response[7] = 1;
                    response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16]);
                    response.extend_from_slice(&ip.octets());
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let fallback = Arc::new(AtomicUsize::new(0));
        let dialer = install(
            protected(Arc::new(AtomicUsize::new(0)), fallback.clone()),
            &policy(upstream),
        );
        assert_eq!(
            dialer
                .resolve("group.example", 443)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fallback.load(Ordering::SeqCst), 0);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn matching_udp_truncation_retries_tcp_at_the_same_ipv4_and_ipv6_resolver() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        let tcp = tokio::net::TcpListener::bind(bind).await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(address).await.unwrap();
        let udp_server = tokio::spawn(async move {
            let mut packet = [0; 512];
            for _ in 0..2 {
                let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
                let response = foxcore_dns::truncated_response(&packet[..length]).unwrap();
                udp.send_to(&response, peer).await.unwrap();
            }
        });
        let ip: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
        let tcp_server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let length = usize::from(stream.read_u16().await.unwrap());
                let mut query = vec![0; length];
                stream.read_exact(&mut query).await.unwrap();
                let mut response = answer(&query);
                if query[length - 3] == 28 {
                    response[7] = 1;
                    response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16]);
                    response.extend_from_slice(&ip.octets());
                }
                stream
                    .write_u16(u16::try_from(response.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = Arc::new(AtomicUsize::new(0));
        let dialer = install(
            protected(calls.clone(), fallback.clone()),
            &policy(DnsUpstream::Udp {
                address: address.to_string(),
            }),
        );
        assert_eq!(
            dialer.resolve("group.example", 2443).await.unwrap(),
            vec![
                SocketAddr::from(([192, 0, 2, 7], 2443)),
                SocketAddr::new(ip.into(), 2443)
            ]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(fallback.load(Ordering::SeqCst), 0);
        udp_server.await.unwrap();
        tcp_server.await.unwrap();
    }
}

#[tokio::test]
async fn forged_or_malformed_truncation_cannot_open_a_tcp_retry() {
    for mutation in 0..5 {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(address).await.unwrap();
        let server = tokio::spawn(async move {
            let mut packet = [0; 512];
            for _ in 0..2 {
                let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
                let mut response = foxcore_dns::truncated_response(&packet[..length]).unwrap();
                match mutation {
                    0 => response[0] ^= 1,
                    1 => response[13] ^= 1,
                    2 => response[length - 3] ^= 1,
                    3 => response[3] |= 5,
                    _ => response[7] = 1,
                }
                udp.send_to(&response, peer).await.unwrap();
            }
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = Arc::new(AtomicUsize::new(0));
        let dialer = install(
            protected(calls.clone(), fallback.clone()),
            &policy(DnsUpstream::Udp {
                address: address.to_string(),
            }),
        );
        assert!(dialer.resolve("group.example", 443).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(fallback.load(Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), tcp.accept())
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn rejected_dns_packets_never_fall_back_to_the_system_resolver() {
    for mutation in 0..4 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = DnsUpstream::Udp {
            address: socket.local_addr().unwrap().to_string(),
        };
        let server = tokio::spawn(async move {
            let mut query = [0; 512];
            loop {
                let (length, peer) = socket.recv_from(&mut query).await.unwrap();
                let mut response = answer(&query[..length]);
                match mutation {
                    0 => response[0] ^= 1,
                    1 => response[13] ^= 1,
                    2 => response[query[..length].len() - 3] ^= 1,
                    _ => response[3] |= 5,
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let fallback = Arc::new(AtomicUsize::new(0));
        let dialer = install(
            protected(Arc::new(AtomicUsize::new(0)), fallback.clone()),
            &policy(upstream),
        );
        assert!(dialer.resolve("group.example", 443).await.is_err());
        assert_eq!(fallback.load(Ordering::SeqCst), 0);
        server.abort();
    }
}

#[tokio::test]
async fn silent_dns_obeys_the_total_budget_without_public_fallback() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback = Arc::new(AtomicUsize::new(0));
    let dialer = install(
        protected(Arc::new(AtomicUsize::new(0)), fallback.clone()),
        &policy(DnsUpstream::Udp {
            address: socket.local_addr().unwrap().to_string(),
        }),
    );
    let started = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(650),
            dialer.resolve("group.example", 443)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(650));
    assert_eq!(fallback.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn host_denied_socket_protection_precedes_any_bootstrap_traffic() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = DnsUpstream::Udp {
        address: socket.local_addr().unwrap().to_string(),
    };
    let callbacks = SocketCallbacks::new(|_| false, |_, _| true);
    let base = ProtectedDialer::new(callbacks, Duration::from_millis(500));
    base.set_network_handle(1);
    let dialer = install(base, &policy(upstream));
    assert_eq!(
        dialer
            .resolve("group.example", 443)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), socket.recv(&mut [0; 512]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tcp_bootstrap_reads_real_length_prefixed_answers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(length)];
            stream.read_exact(&mut query).await.unwrap();
            let response = answer(&query);
            stream
                .write_u16(u16::try_from(response.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        }
    });
    let dialer = install(
        ProtectedDialer::host(),
        &policy(DnsUpstream::Tcp {
            address: address.to_string(),
        }),
    );
    assert_eq!(
        dialer.resolve("group.example", 2443).await.unwrap(),
        vec![SocketAddr::from(([192, 0, 2, 7], 2443))]
    );
    server.await.unwrap();
}

#[tokio::test]
async fn a_network_change_and_same_handle_reconnect_refuses_old_dns_answers() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = DnsUpstream::Udp {
        address: socket.local_addr().unwrap().to_string(),
    };
    let (seen, received) = tokio::sync::oneshot::channel();
    let (release, proceed) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut packet = [0; 512];
        let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
        seen.send(()).unwrap();
        proceed.await.unwrap();
        socket
            .send_to(&answer(&packet[..length]), peer)
            .await
            .unwrap();
    });
    let base = protected(Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let dialer = install(base.clone(), &policy(upstream));
    let lookup = tokio::spawn(async move { dialer.resolve("group.example", 443).await });
    received.await.unwrap();
    base.set_network_handle(1);
    release.send(()).unwrap();
    assert_eq!(
        lookup.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    server.await.unwrap();
}

fn tls_config(alpn: &[u8]) -> (Arc<rustls::ServerConfig>, String) {
    let generated = rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
    let (remaining, certificate) =
        X509Certificate::from_der(generated.cert.der().as_ref()).unwrap();
    assert!(remaining.is_empty());
    let pin = STANDARD.encode(Sha256::digest(certificate.tbs_certificate.subject_pki.raw));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![generated.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    (Arc::new(config), pin)
}

#[tokio::test]
async fn dot_negotiates_only_dot_and_connects_to_the_literal_ip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tls, pin) = tls_config(b"dot");
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(tls.clone())
                .accept(tcp)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"dot".as_slice()));
            assert_eq!(stream.get_ref().1.server_name(), Some("dns.example"));
            let length = stream.read_u16().await.unwrap();
            let mut query = vec![0; length as usize];
            stream.read_exact(&mut query).await.unwrap();
            let response = answer(&query);
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        }
    });
    let upstream = DnsUpstream::Dot {
        host: "dns.example".into(),
        port: address.port(),
        server_ip: Some(address.ip()),
        insecure: false,
        pinned_spki_sha256: Some(pin),
    };
    let mut config = policy(upstream);
    config.timeout_ms = 3000;
    let dialer = install(ProtectedDialer::host(), &config);
    assert_eq!(
        dialer.resolve("group.example", 443).await.unwrap(),
        vec![SocketAddr::from(([192, 0, 2, 7], 443))]
    );
    server.await.unwrap();
}

#[tokio::test]
async fn doh_negotiates_h2_zeroes_id_and_checks_wire_format() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tls, pin) = tls_config(b"h2");
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(tls.clone())
                .accept(tcp)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let (mut request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/dns-query");
            assert_eq!(request.headers()[CONTENT_TYPE], "application/dns-message");
            let mut query = Vec::new();
            while let Some(chunk) = request.body_mut().data().await {
                let chunk = chunk.unwrap();
                request
                    .body_mut()
                    .flow_control()
                    .release_capacity(chunk.len())
                    .unwrap();
                query.extend_from_slice(&chunk);
            }
            assert_eq!(&query[..2], &[0, 0]);
            let headers = http::Response::builder()
                .status(200)
                .header(CONTENT_TYPE, "application/dns-message")
                .body(())
                .unwrap();
            respond
                .send_response(headers, false)
                .unwrap()
                .send_data(Bytes::from(answer(&query)), true)
                .unwrap();
            let _ = connection.accept().await;
        }
    });
    let upstream = DnsUpstream::Doh {
        url: foxcore_api::SecretString::new(format!(
            "https://dns.example:{}/dns-query",
            address.port()
        )),
        server_ip: Some(address.ip()),
        insecure: false,
        pinned_spki_sha256: Some(pin),
    };
    let mut config = policy(upstream);
    config.timeout_ms = 3000;
    let dialer = install(ProtectedDialer::host(), &config);
    assert_eq!(
        dialer.resolve("group.example", 443).await.unwrap(),
        vec![SocketAddr::from(([192, 0, 2, 7], 443))]
    );
    server.await.unwrap();
}

#[tokio::test]
async fn an_untrusted_tls_key_is_never_accepted_as_bootstrap_dns() {
    for pin in [None, Some(STANDARD.encode([3u8; 32]))] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tls, _) = tls_config(b"dot");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                assert!(
                    tokio_rustls::TlsAcceptor::from(tls.clone())
                        .accept(tcp)
                        .await
                        .is_err()
                );
            }
        });
        let upstream = DnsUpstream::Dot {
            host: "dns.example".into(),
            port: address.port(),
            server_ip: Some(address.ip()),
            insecure: false,
            pinned_spki_sha256: pin,
        };
        let mut config = policy(upstream);
        config.timeout_ms = 3000;
        let dialer = install(ProtectedDialer::host(), &config);
        assert!(dialer.resolve("group.example", 443).await.is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tcp_frame_limits_refuse_oversized_and_truncated_dns() {
    for length in [11u16, 16385] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let n = stream.read_u16().await.unwrap();
                let mut query = vec![0; n as usize];
                stream.read_exact(&mut query).await.unwrap();
                stream.write_u16(length).await.unwrap();
            }
        });
        let dialer = install(
            ProtectedDialer::host(),
            &policy(DnsUpstream::Tcp {
                address: address.to_string(),
            }),
        );
        assert!(dialer.resolve("group.example", 443).await.is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn encrypted_quic_bootstrap_protection_failure_sends_no_datagrams() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    for upstream in [
        DnsUpstream::Doq {
            host: "dns.example".into(),
            port: address.port(),
            server_ip: Some(address.ip()),
            insecure: false,
            pinned_spki_sha256: None,
        },
        DnsUpstream::Doh3 {
            url: foxcore_api::SecretString::new(format!(
                "https://dns.example:{}/dns-query",
                address.port()
            )),
            server_ip: Some(address.ip()),
            insecure: false,
            pinned_spki_sha256: None,
        },
    ] {
        let fallback = Arc::new(AtomicUsize::new(0));
        let observed = fallback.clone();
        let callbacks =
            SocketCallbacks::new(|_| false, |_, _| true).with_host_resolver(move |_, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(vec![])
            });
        let base = ProtectedDialer::new(callbacks, Duration::from_millis(500));
        base.set_network_handle(1);
        let dialer = install(base, &policy(upstream));
        assert_eq!(
            dialer
                .resolve("group.example", 443)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fallback.load(Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), socket.recv(&mut [0; 2048]))
                .await
                .is_err()
        );
    }
}
