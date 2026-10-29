mod tunlab;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foxcore_api::{
    CoreEvent, DnsBlocklistConfig, DnsConfig, DnsMode, EventSink, FlowAttributor, FlowIdentity,
    IpTransport, RouteAction, RouteRule, RuntimeConfig, TrafficPolicyConfig,
};
use foxcore_dialer::{ProtectedDialer, SocketCallbacks};
use foxcore_outbound::{Outbound, OutboundRegistry};
use foxcore_route::RouteTable;
use foxcore_trafficmap::TrafficMap;
use foxcore_tun::{FlowEngine, FlowEngineContext, FlowMetrics, FlowPolicyStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tunlab::{FLAG_ACK, FLAG_PSH, Lab};

const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 53);
const FOREIGN_RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 54);
const NAME: &str = "example.test";
const WINDOW: Duration = Duration::from_secs(3);
const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted";

fn query(record_type: u16) -> Vec<u8> {
    let mut bytes = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in NAME.split('.') {
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&record_type.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes
}

fn dns() -> DnsConfig {
    DnsConfig {
        mode: DnsMode::FakeIp,
        advertise: Some(RESOLVER.to_string()),
        ..DnsConfig::default()
    }
}

fn domain_rule() -> RouteRule {
    RouteRule {
        uid: None,
        package: None,
        exact_domains: Vec::new(),
        domain_suffixes: vec!["test".into()],
        cidrs: Vec::new(),
        ports: Vec::new(),
        network: None,
        transport: None,
        action: RouteAction::Direct,
        expires_at_ms: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn engine(
    config: DnsConfig,
    rules: Vec<RouteRule>,
    traffic: TrafficPolicyConfig,
    attributor: FlowAttributor,
    resolver: Option<SocketAddr>,
    metrics: Arc<FlowMetrics>,
    recorded: Arc<Mutex<Vec<CoreEvent>>>,
) -> FlowEngine {
    engine_parts(
        config, rules, traffic, attributor, resolver, metrics, recorded,
    )
    .0
}

#[allow(clippy::too_many_arguments)]
fn engine_parts(
    config: DnsConfig,
    rules: Vec<RouteRule>,
    traffic: TrafficPolicyConfig,
    attributor: FlowAttributor,
    resolver: Option<SocketAddr>,
    metrics: Arc<FlowMetrics>,
    recorded: Arc<Mutex<Vec<CoreEvent>>>,
) -> (FlowEngine, Arc<FlowPolicyStore>) {
    let callbacks = match resolver {
        Some(address) => SocketCallbacks::none().with_resolver(move |host, port, _| {
            assert_eq!(
                host, NAME,
                "only a cache-restored domain may reach the dialer"
            );
            assert_eq!(port, address.port());
            Ok(vec![address])
        }),
        None => SocketCallbacks::none(),
    };
    let dialer = ProtectedDialer::new(callbacks, WINDOW);
    if resolver.is_some() {
        dialer.set_network_handle(7);
    }
    let direct = Arc::new(Outbound::direct(dialer));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let events = EventSink::new(move |event| recorded.lock().unwrap().push(event));
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile_with_traffic(rules, RouteAction::Direct, traffic, false, false),
            config,
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            events.clone(),
        )
        .unwrap(),
    );
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor,
        runtime: RuntimeConfig::default(),
        metrics,
        events,
        packet_tunnel: false,
        connections: Arc::new(TrafficMap::default()),
    });
    (engine, policy)
}

fn recording() -> Arc<Mutex<Vec<CoreEvent>>> {
    Arc::new(Mutex::new(Vec::new()))
}

fn accepted_address(answer: &[u8]) -> Ipv4Addr {
    assert_eq!(&answer[..2], &7_u16.to_be_bytes());
    assert_eq!(answer[3] & 0x0f, 0);
    assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 1);
    let address = answer.last_chunk::<4>().unwrap();
    assert_eq!(address[0], 198);
    assert!(matches!(address[1], 18 | 19));
    Ipv4Addr::from(*address)
}

async fn tcp_dns(lab: &mut Lab, request: &[u8]) -> Option<Vec<u8>> {
    lab.open_to(RESOLVER, 53).await;
    tcp_dns_on_open_stream(lab, request).await
}

async fn tcp_dns_on_open_stream(lab: &mut Lab, request: &[u8]) -> Option<Vec<u8>> {
    let mut frame = u16::try_from(request.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(request);
    lab.send(FLAG_PSH | FLAG_ACK, &frame).await;
    let reply = lab
        .receive_tcp_payload(WINDOW, |bytes| {
            bytes.len() >= 2
                && bytes.len() >= 2 + usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        })
        .await?;
    Some(reply[2..].to_vec())
}

async fn domain_dns_and_http(tcp: bool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 256];
        while !request.ends_with(b"\r\n\r\n") {
            let length = connection.read(&mut chunk).await.unwrap();
            assert_ne!(length, 0);
            request.extend_from_slice(&chunk[..length]);
            assert!(request.len() < 4096);
        }
        assert_eq!(
            request,
            b"GET /proof HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
        );
        connection.write_all(RESPONSE).await.unwrap();
        connection.shutdown().await.unwrap();
    });
    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        Some(remote),
        metrics.clone(),
        recording(),
    ));
    let request = query(1);
    let answer = if tcp {
        tcp_dns(&mut lab, &request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_153, &request, WINDOW).await
    }
    .expect("domain-only policy must answer intercepted DNS without a platform UID API");
    let fake = accepted_address(&answer);
    lab.open_to(fake, remote.port()).await;
    lab.send(
        FLAG_PSH | FLAG_ACK,
        b"GET /proof HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        lab.receive_tcp_payload(WINDOW, |bytes| bytes.len() >= RESPONSE.len())
            .await
            .unwrap(),
        RESPONSE
    );
    tokio::time::timeout(WINDOW, server).await.unwrap().unwrap();
    assert_eq!(metrics.snapshot().attribution_errors, 0);
    assert_eq!(metrics.snapshot().dial_errors, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_domain_rules_admit_udp_dns_then_a_fake_ip_http_flow_without_uid_api() {
    domain_dns_and_http(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_domain_rules_admit_tcp_dns_then_a_fake_ip_http_flow_without_uid_api() {
    domain_dns_and_http(true).await;
}

async fn package_bypass(tcp: bool, packages: &[&str]) -> (Vec<u8>, usize) {
    let (answer, lookups) =
        package_bypass_with_allowlist(tcp, packages, vec!["com.example.allowed".into()]).await;
    (
        answer.expect("valid DNS reaches its package-aware filter"),
        lookups,
    )
}

async fn package_bypass_with_allowlist(
    tcp: bool,
    packages: &[&str],
    allowed: Vec<String>,
) -> (Option<Vec<u8>>, usize) {
    let lookups = Arc::new(AtomicUsize::new(0));
    let count = lookups.clone();
    let packages: Vec<String> = packages.iter().map(|name| (*name).to_owned()).collect();
    let attributor = FlowAttributor::new(move |transport, _, destination| {
        assert_eq!(destination.port(), 53);
        assert_eq!(
            transport,
            if tcp {
                IpTransport::Tcp
            } else {
                IpTransport::Udp
            }
        );
        count.fetch_add(1, Ordering::SeqCst);
        Ok(Some(FlowIdentity {
            uid: 10_123,
            packages: packages.clone(),
            signing_digest: None,
        }))
    });
    let mut config = dns();
    config.blocklist = DnsBlocklistConfig {
        suffixes: vec!["test".into()],
        bypass_packages: allowed,
        ..DnsBlocklistConfig::default()
    };
    let mut lab = Lab::start_with(engine(
        config,
        Vec::new(),
        TrafficPolicyConfig::default(),
        attributor,
        None,
        Arc::new(FlowMetrics::default()),
        recording(),
    ));
    let request = query(1);
    let answer = if tcp {
        tcp_dns(&mut lab, &request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_155, &request, WINDOW).await
    };
    let lookups = lookups.load(Ordering::SeqCst);
    lab.stop().await;
    (answer, lookups)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_package_bypass_attributes_the_actual_dns_flow_without_app_route_rules() {
    let (answer, lookups) = package_bypass(false, &["com.example.allowed"]).await;
    accepted_address(&answer);
    assert!(lookups > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_package_bypass_attributes_the_actual_dns_flow_without_app_route_rules() {
    let (answer, lookups) = package_bypass(true, &["com.example.allowed"]).await;
    accepted_address(&answer);
    assert!(lookups > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_uid_with_one_unlisted_package_does_not_bypass_the_filter() {
    let (answer, lookups) =
        package_bypass(false, &["com.example.allowed", "com.example.other"]).await;
    assert_eq!(answer[3] & 0x0f, 3);
    assert!(lookups > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_shaped_packet_cannot_issue_a_fake_dns_promise() {
    let metrics = Arc::new(FlowMetrics::default());
    let lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    let mut invalid = query(1);
    invalid[2] |= 0x80;
    assert!(
        lab.dns_datagram(RESOLVER, 49_156, &invalid, Duration::from_millis(300))
            .await
            .is_none()
    );
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_resolver_is_not_a_domain_hint_identity_exception() {
    let lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        Arc::new(FlowMetrics::default()),
        recording(),
    ));
    assert!(
        lab.dns_datagram(
            FOREIGN_RESOLVER,
            49_157,
            &query(1),
            Duration::from_millis(300)
        )
        .await
        .is_none()
    );
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_fake_destination_remains_unattributed_and_closed() {
    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    lab.open_to(Ipv4Addr::new(198, 18, 0, 99), 443).await;
    assert!(lab.closed_within(WINDOW).await);
    assert_eq!(metrics.snapshot().attribution_errors, 1);
    assert_eq!(metrics.snapshot().dial_errors, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbound_real_ip_does_not_inherit_a_global_domain_route() {
    let metrics = Arc::new(FlowMetrics::default());
    let mut lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    lab.open_to(Ipv4Addr::LOCALHOST, 443).await;
    assert!(lab.closed_within(WINDOW).await);
    assert_eq!(metrics.snapshot().attribution_errors, 1);
    assert_eq!(metrics.snapshot().dial_errors, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unspecified_dns_source_cannot_use_the_bootstrap_exception() {
    let metrics = Arc::new(FlowMetrics::default());
    let lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    assert!(
        lab.dns_datagram_from_source(
            Ipv4Addr::UNSPECIFIED,
            RESOLVER,
            49_160,
            &query(1),
            Duration::from_millis(300)
        )
        .await
        .is_none()
    );
    assert_eq!(metrics.snapshot().dns_queries, 0);
    assert_eq!(metrics.snapshot().dial_errors, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_dns_source_port_cannot_use_the_bootstrap_exception() {
    let metrics = Arc::new(FlowMetrics::default());
    let lab = Lab::start_with(engine(
        dns(),
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    assert!(
        lab.dns_datagram(RESOLVER, 0, &query(1), Duration::from_millis(300))
            .await
            .is_none()
    );
    assert_eq!(metrics.snapshot().dns_queries, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uid_routes_still_require_attribution_before_intercepted_dns() {
    let metrics = Arc::new(FlowMetrics::default());
    let mut rule = domain_rule();
    rule.uid = Some(10_123);
    rule.domain_suffixes.clear();
    let lab = Lab::start_with(engine(
        dns(),
        vec![rule],
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    assert!(
        lab.dns_datagram(RESOLVER, 49_161, &query(1), Duration::from_millis(300))
            .await
            .is_none()
    );
    assert_eq!(metrics.snapshot().attribution_errors, 1);
    assert_eq!(metrics.snapshot().dns_queries, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quarantine_still_requires_package_identity_before_intercepted_dns() {
    let metrics = Arc::new(FlowMetrics::default());
    let traffic = TrafficPolicyConfig {
        quarantine_new_apps: true,
        ..Default::default()
    };
    let lab = Lab::start_with(engine(
        dns(),
        Vec::new(),
        traffic,
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    assert!(
        lab.dns_datagram(RESOLVER, 49_162, &query(1), Duration::from_millis(300))
            .await
            .is_none()
    );
    assert_eq!(metrics.snapshot().attribution_errors, 1);
    assert_eq!(metrics.snapshot().dns_queries, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_package_bypass_never_grants_access_without_any_identity() {
    let metrics = Arc::new(FlowMetrics::default());
    let mut config = dns();
    config.blocklist = DnsBlocklistConfig {
        suffixes: vec!["test".into()],
        bypass_packages: vec!["com.example.allowed".into()],
        ..Default::default()
    };
    let lab = Lab::start_with(engine(
        config,
        Vec::new(),
        TrafficPolicyConfig::default(),
        FlowAttributor::none(),
        None,
        metrics.clone(),
        recording(),
    ));
    let answer = lab
        .dns_datagram(RESOLVER, 49_163, &query(1), Duration::from_millis(300))
        .await;
    assert!(answer.is_none() || answer.as_ref().is_some_and(|bytes| bytes[3] & 0x0f != 0));
    assert_eq!(metrics.snapshot().dial_errors, 0);
    lab.stop().await;
}

async fn bypass_reload_on_existing_dns_flow(tcp: bool) {
    let lookups = Arc::new(AtomicUsize::new(0));
    let calls = lookups.clone();
    let attributor = FlowAttributor::new(move |_, _, destination| {
        assert_eq!(destination.port(), 53);
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(FlowIdentity {
            uid: 10_123,
            packages: vec!["com.example.allowed".into()],
            signing_digest: None,
        }))
    });
    let (engine, policy) = engine_parts(
        dns(),
        Vec::new(),
        TrafficPolicyConfig::default(),
        attributor,
        None,
        Arc::new(FlowMetrics::default()),
        recording(),
    );
    let mut lab = Lab::start_with(engine);
    let request = query(1);
    let before = if tcp {
        tcp_dns(&mut lab, &request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_170, &request, WINDOW).await
    }
    .unwrap();
    let promised = accepted_address(&before);
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    let mut changed = dns();
    changed.blocklist = DnsBlocklistConfig {
        suffixes: vec!["test".into()],
        bypass_packages: vec!["com.example.allowed".into()],
        ..Default::default()
    };
    assert_eq!(
        policy
            .reload(
                Some(1),
                RouteTable::compile(Vec::new(), RouteAction::Direct),
                changed
            )
            .unwrap(),
        2
    );
    for _ in 0..2 {
        let after = if tcp {
            tcp_dns_on_open_stream(&mut lab, &request).await
        } else {
            lab.dns_datagram(RESOLVER, 49_170, &request, WINDOW).await
        }
        .unwrap();
        assert_eq!(accepted_address(&after), promised);
    }
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        1,
        "bind missing identity once for the surviving DNS flow"
    );
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_package_bypass_reload_rebinds_identity_on_the_existing_dns_flow() {
    bypass_reload_on_existing_dns_flow(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_package_bypass_reload_rebinds_identity_on_the_existing_dns_flow() {
    bypass_reload_on_existing_dns_flow(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn package_bypass_rejects_an_over_capacity_shared_uid_without_truncation() {
    let allowed: Vec<String> = (0..32)
        .map(|index| format!("com.example.allowed{index:02}"))
        .collect();
    let mut packages = allowed.clone();
    packages.push("z.example.unlisted".into());
    let names: Vec<&str> = packages.iter().map(String::as_str).collect();
    let (answer, lookups) = package_bypass_with_allowlist(false, &names, allowed).await;
    assert!(answer.is_none() || answer.as_ref().is_some_and(|bytes| bytes[3] & 0x0f != 0));
    assert!(lookups > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn package_bypass_rejects_partially_invalid_package_metadata() {
    let (answer, lookups) = package_bypass_with_allowlist(
        false,
        &["com.example.allowed", "invalid\u{0000}package"],
        vec!["com.example.allowed".into()],
    )
    .await;
    assert!(answer.is_none() || answer.as_ref().is_some_and(|bytes| bytes[3] & 0x0f != 0));
    assert!(lookups > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_complete_32_package_shared_uid_can_bypass_only_when_all_are_listed() {
    let allowed: Vec<String> = (0..32)
        .map(|index| format!("com.example.allowed{index:02}"))
        .collect();
    let names: Vec<&str> = allowed.iter().map(String::as_str).collect();
    let (answer, lookups) = package_bypass_with_allowlist(false, &names, allowed.clone()).await;
    accepted_address(&answer.unwrap());
    assert!(lookups > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pure_uid_dns_rules_remain_usable_when_package_metadata_exceeds_the_bound() {
    let attributor = FlowAttributor::new(|_, _, _| {
        Ok(Some(FlowIdentity {
            uid: 10_123,
            packages: (0..33)
                .map(|index| format!("com.example.group{index:02}"))
                .collect(),
            signing_digest: None,
        }))
    });
    let mut rule = domain_rule();
    rule.uid = Some(10_123);
    rule.domain_suffixes.clear();
    let metrics = Arc::new(FlowMetrics::default());
    let lab = Lab::start_with(engine(
        dns(),
        vec![rule],
        TrafficPolicyConfig::default(),
        attributor,
        None,
        metrics.clone(),
        recording(),
    ));
    let answer = lab
        .dns_datagram(RESOLVER, 49_175, &query(1), WINDOW)
        .await
        .unwrap();
    accepted_address(&answer);
    assert_eq!(metrics.snapshot().attribution_errors, 0);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_ip_domain_routes_still_learn_scoped_dns_hints_with_a_platform_attributor() {
    let dns_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_address = dns_socket.local_addr().unwrap();
    let dns_server = tokio::spawn(async move {
        let mut bytes = [0_u8; 512];
        let (length, peer) = dns_socket.recv_from(&mut bytes).await.unwrap();
        let mut response = bytes[..length].to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response[8..12].fill(0);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
        dns_socket.send_to(&response, peer).await.unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let http_server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 256];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream.write_all(RESPONSE).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let lookups = Arc::new(AtomicUsize::new(0));
    let count = lookups.clone();
    let attributor = FlowAttributor::new(move |_, _, _| {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(Some(FlowIdentity {
            uid: 10_123,
            packages: vec!["com.example.owner".into()],
            signing_digest: None,
        }))
    });
    let config = DnsConfig {
        mode: DnsMode::RealIp,
        advertise: Some(RESOLVER.to_string()),
        route: foxcore_api::DnsRoute::Direct,
        upstreams: vec![foxcore_api::DnsUpstream::Udp {
            address: dns_address.to_string(),
        }],
        ..DnsConfig::default()
    };
    let mut lab = Lab::start_with(engine(
        config,
        vec![domain_rule()],
        TrafficPolicyConfig::default(),
        attributor,
        None,
        Arc::new(FlowMetrics::default()),
        recording(),
    ));
    let answer = lab
        .dns_datagram(RESOLVER, 49_180, &query(1), WINDOW)
        .await
        .unwrap();
    assert_eq!(answer[3] & 0x0f, 0);
    assert_eq!(answer.last_chunk::<4>().unwrap(), &[127, 0, 0, 1]);
    lab.open(address.port()).await;
    lab.send(
        FLAG_PSH | FLAG_ACK,
        b"GET /proof HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )
    .await;
    let received = lab
        .receive_tcp_payload(WINDOW, |bytes| bytes.len() >= RESPONSE.len())
        .await;
    assert_eq!(received.as_deref(), Some(RESPONSE));
    assert!(
        lookups.load(Ordering::SeqCst) >= 2,
        "both DNS and real-IP flow bind the same UID identity"
    );
    tokio::time::timeout(WINDOW, dns_server)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(WINDOW, http_server)
        .await
        .unwrap()
        .unwrap();
    lab.stop().await;
}

#[derive(Clone, Copy)]
enum OptionalDnsMetadata {
    MissingOwner,
    UidOnly,
    LookupError,
    InvalidPackage,
    OverflowPackages,
}

fn optional_bypass_dns() -> DnsConfig {
    let mut config = dns();
    config.blocklist = DnsBlocklistConfig {
        suffixes: vec!["blocked.test".into()],
        bypass_packages: vec!["com.example.allowed".into()],
        ..Default::default()
    };
    config
}

fn optional_question(name: &str, record_type: u16, edns: bool) -> Vec<u8> {
    let mut packet = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)];
    for label in name.split('.') {
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    if edns {
        packet.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    }
    packet
}

fn optional_attributor(kind: OptionalDnsMetadata, calls: Arc<AtomicUsize>) -> FlowAttributor {
    FlowAttributor::new(move |_, _, destination| {
        if destination.port() == 53 {
            calls.fetch_add(1, Ordering::SeqCst);
        }
        let packages = match kind {
            OptionalDnsMetadata::MissingOwner => return Ok(None),
            OptionalDnsMetadata::LookupError => {
                return Err(std::io::Error::other(
                    "test platform owner lookup unavailable",
                ));
            }
            OptionalDnsMetadata::UidOnly => Vec::new(),
            OptionalDnsMetadata::InvalidPackage => vec!["com.example.allowed".into(), "".into()],
            OptionalDnsMetadata::OverflowPackages => vec!["com.example.allowed".into(); 33],
        };
        Ok(Some(FlowIdentity {
            uid: 10_123,
            packages,
            signing_digest: None,
        }))
    })
}

async fn optional_dns_exchange(lab: &mut Lab, tcp: bool, packet: &[u8]) -> Option<Vec<u8>> {
    if tcp {
        tcp_dns(lab, packet).await
    } else {
        lab.dns_datagram(RESOLVER, 49_200, packet, WINDOW).await
    }
}

async fn optional_bypass_global_filter(tcp: bool, kind: OptionalDnsMetadata, real_ip: bool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let http = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 256];
        assert!(connection.read(&mut request).await.unwrap() > 0);
        connection.write_all(RESPONSE).await.unwrap();
        connection.shutdown().await.unwrap();
    });
    let metrics = Arc::new(FlowMetrics::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let attributor = optional_attributor(kind, calls.clone());
    assert!(attributor.is_available());
    let mut config = optional_bypass_dns();
    let mut rules = vec![domain_rule()];
    let mut dns_server = None;
    if real_ip {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        dns_server = Some(tokio::spawn(async move {
            let mut packet = [0_u8; 512];
            let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
            let mut answer = packet[..length].to_vec();
            answer[2..4].copy_from_slice(&[0x81, 0x80]);
            answer[6..8].copy_from_slice(&1_u16.to_be_bytes());
            answer[8..12].fill(0);
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
            socket.send_to(&answer, peer).await.unwrap();
        }));
        config.mode = DnsMode::RealIp;
        config.route = foxcore_api::DnsRoute::Direct;
        config.upstreams = vec![foxcore_api::DnsUpstream::Udp {
            address: address.to_string(),
        }];
        rules.clear();
    }
    let mut lab = Lab::start_with(engine(
        config.clone(),
        rules,
        TrafficPolicyConfig::default(),
        attributor,
        (!real_ip).then_some(remote),
        metrics.clone(),
        recording(),
    ));
    let answer = optional_dns_exchange(&mut lab, tcp, &optional_question(NAME, 1, !real_ip))
        .await
        .expect("missing optional bypass identity must still apply the global DNS filter");
    let address = if real_ip {
        assert_eq!(answer[3] & 0x0f, 0);
        Ipv4Addr::from(*answer.last_chunk::<4>().unwrap())
    } else {
        accepted_address(&answer)
    };
    let blocked_request = optional_question("blocked.test", 1, false);
    let blocked = if tcp {
        tcp_dns_on_open_stream(&mut lab, &blocked_request).await
    } else {
        optional_dns_exchange(&mut lab, tcp, &blocked_request).await
    }
    .expect("the global filter must answer a blocklisted name without granting bypass");
    assert_eq!(blocked[3] & 0x0f, 3);
    if !real_ip {
        let ipv6_request = optional_question(NAME, 28, true);
        let ipv6 = if tcp {
            tcp_dns_on_open_stream(&mut lab, &ipv6_request).await
        } else {
            optional_dns_exchange(&mut lab, tcp, &ipv6_request).await
        }
        .expect("normal AAAA plus EDNS0 stays usable without optional metadata");
        assert_eq!(ipv6[3] & 0x0f, 0);
        let address = std::net::Ipv6Addr::from(*ipv6.last_chunk::<16>().unwrap());
        assert!(config.synthesizes(std::net::IpAddr::V6(address)));
    }
    lab.open_to(address, remote.port()).await;
    lab.send(
        FLAG_PSH | FLAG_ACK,
        b"GET /proof HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        lab.receive_tcp_payload(WINDOW, |packet| packet.len() >= RESPONSE.len())
            .await
            .unwrap(),
        RESPONSE
    );
    tokio::time::timeout(WINDOW, http).await.unwrap().unwrap();
    if let Some(server) = dns_server {
        tokio::time::timeout(WINDOW, server).await.unwrap().unwrap();
    }
    assert!(calls.load(Ordering::SeqCst) > 0);
    assert_eq!(metrics.snapshot().attribution_errors, 0);
    assert_eq!(metrics.snapshot().dial_errors, 0);
    assert_eq!(metrics.snapshot().dns_blocked, 1);
    lab.stop().await;
}

macro_rules! optional_dns_filter_test {
    ($name:ident, $tcp:expr, $metadata:ident, $real_ip:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            optional_bypass_global_filter($tcp, OptionalDnsMetadata::$metadata, $real_ip).await;
        }
    };
}

optional_dns_filter_test!(
    udp_optional_bypass_missing_owner_filters_and_serves_http,
    false,
    MissingOwner,
    false
);
optional_dns_filter_test!(
    tcp_optional_bypass_missing_owner_filters_and_serves_http,
    true,
    MissingOwner,
    false
);
optional_dns_filter_test!(
    udp_optional_bypass_uid_only_filters_and_serves_http,
    false,
    UidOnly,
    false
);
optional_dns_filter_test!(
    tcp_optional_bypass_uid_only_filters_and_serves_http,
    true,
    UidOnly,
    false
);
optional_dns_filter_test!(
    udp_optional_bypass_lookup_error_filters_and_serves_http,
    false,
    LookupError,
    false
);
optional_dns_filter_test!(
    tcp_optional_bypass_lookup_error_filters_and_serves_http,
    true,
    LookupError,
    false
);
optional_dns_filter_test!(
    udp_optional_bypass_invalid_metadata_filters_without_prefix,
    false,
    InvalidPackage,
    false
);
optional_dns_filter_test!(
    udp_optional_bypass_overflow_metadata_filters_without_prefix,
    false,
    OverflowPackages,
    false
);
optional_dns_filter_test!(
    udp_real_ip_optional_bypass_missing_owner_filters_and_serves_http,
    false,
    MissingOwner,
    true
);
optional_dns_filter_test!(
    tcp_real_ip_optional_bypass_missing_owner_filters_and_serves_http,
    true,
    MissingOwner,
    true
);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn optional_bypass_never_weakens_mandatory_uid_app_or_quarantine_policy() {
    for (policy_kind, metadata) in [
        (0, OptionalDnsMetadata::MissingOwner),
        (1, OptionalDnsMetadata::MissingOwner),
        (2, OptionalDnsMetadata::MissingOwner),
        (1, OptionalDnsMetadata::UidOnly),
        (2, OptionalDnsMetadata::UidOnly),
    ] {
        let metrics = Arc::new(FlowMetrics::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut rules = Vec::new();
        let mut traffic = TrafficPolicyConfig::default();
        match policy_kind {
            0 => {
                let mut rule = domain_rule();
                rule.uid = Some(10_123);
                rule.domain_suffixes.clear();
                rules.push(rule);
            }
            1 => {
                traffic.applications = vec![foxcore_api::ApplicationRouteConfig {
                    package: "com.example.allowed".into(),
                    action: foxcore_api::ApplicationRouteAction::Direct,
                    expires_at_ms: None,
                }];
            }
            _ => traffic.quarantine_new_apps = true,
        }
        let lab = Lab::start_with(engine(
            optional_bypass_dns(),
            rules,
            traffic,
            optional_attributor(metadata, calls.clone()),
            None,
            metrics.clone(),
            recording(),
        ));
        assert!(
            lab.dns_datagram(RESOLVER, 49_210, &query(1), Duration::from_millis(300))
                .await
                .is_none()
        );
        assert!(calls.load(Ordering::SeqCst) > 0);
        assert_eq!(metrics.snapshot().attribution_errors, 1);
        assert_eq!(metrics.snapshot().dns_queries, 0);
        lab.stop().await;
    }
}

async fn optional_bypass_surviving_dns_reload(tcp: bool) {
    let metrics = Arc::new(FlowMetrics::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (engine, policy) = engine_parts(
        dns(),
        Vec::new(),
        TrafficPolicyConfig::default(),
        optional_attributor(OptionalDnsMetadata::MissingOwner, calls.clone()),
        None,
        metrics.clone(),
        recording(),
    );
    let mut lab = Lab::start_with(engine);
    let request = query(1);
    let before = optional_dns_exchange(&mut lab, tcp, &request)
        .await
        .unwrap();
    let promised = accepted_address(&before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        policy
            .reload(
                Some(1),
                RouteTable::compile(Vec::new(), RouteAction::Direct),
                optional_bypass_dns(),
            )
            .unwrap(),
        2
    );
    for _ in 0..2 {
        let after = if tcp {
            tcp_dns_on_open_stream(&mut lab, &request).await
        } else {
            lab.dns_datagram(RESOLVER, 49_200, &request, WINDOW).await
        }
        .expect("optional bypass reload must retain ordinary filtered DNS");
        assert_eq!(accepted_address(&after), promised);
    }
    let blocked_request = optional_question("blocked.test", 1, false);
    let blocked = if tcp {
        tcp_dns_on_open_stream(&mut lab, &blocked_request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_200, &blocked_request, WINDOW)
            .await
    }
    .unwrap();
    assert_eq!(blocked[3] & 0x0f, 3);
    assert!(calls.load(Ordering::SeqCst) > 0);
    assert_eq!(metrics.snapshot().attribution_errors, 0);
    assert_eq!(metrics.snapshot().dns_blocked, 1);
    lab.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_optional_bypass_reload_keeps_unknown_owner_on_global_filter() {
    optional_bypass_surviving_dns_reload(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_optional_bypass_reload_keeps_unknown_owner_on_global_filter() {
    optional_bypass_surviving_dns_reload(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn optional_bypass_does_not_require_packages_for_a_valid_pure_uid_rule() {
    let metrics = Arc::new(FlowMetrics::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rule = domain_rule();
    rule.uid = Some(10_123);
    rule.domain_suffixes.clear();
    let lab = Lab::start_with(engine(
        optional_bypass_dns(),
        vec![rule],
        TrafficPolicyConfig::default(),
        optional_attributor(OptionalDnsMetadata::UidOnly, calls.clone()),
        None,
        metrics.clone(),
        recording(),
    ));
    accepted_address(
        &lab.dns_datagram(RESOLVER, 49_212, &query(1), WINDOW)
            .await
            .expect("a trustworthy UID satisfies a pure UID rule without granting package bypass"),
    );
    let blocked = lab
        .dns_datagram(
            RESOLVER,
            49_212,
            &optional_question("blocked.test", 1, false),
            WINDOW,
        )
        .await
        .unwrap();
    assert_eq!(blocked[3] & 0x0f, 3);
    assert!(calls.load(Ordering::SeqCst) > 0);
    assert_eq!(metrics.snapshot().attribution_errors, 0);
    lab.stop().await;
}

#[derive(Clone, Copy)]
enum CachedDnsLookup {
    Missing,
    Error,
    PackagesAvailable,
    OtherOwnerBlocked,
}

fn cached_uid_rule() -> RouteRule {
    let mut rule = domain_rule();
    rule.uid = Some(10_123);
    rule.domain_suffixes.clear();
    rule
}

async fn cached_uid_dns_reload(tcp: bool, outcome: CachedDnsLookup, mandatory_packages: u8) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let http = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 256];
        assert!(connection.read(&mut request).await.unwrap() > 0);
        connection.write_all(RESPONSE).await.unwrap();
        connection.shutdown().await.unwrap();
    });
    let after_reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let changed = after_reload.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let lookups = calls.clone();
    let attributor = FlowAttributor::new(move |_, _, destination| {
        let mut packages = Vec::new();
        let mut uid = 10_123;
        let mut signing_digest = None;
        if destination.port() == 53 {
            lookups.fetch_add(1, Ordering::SeqCst);
            if changed.load(Ordering::SeqCst) {
                match outcome {
                    CachedDnsLookup::Missing => return Ok(None),
                    CachedDnsLookup::Error => {
                        return Err(std::io::Error::other("test DNS owner lookup error"));
                    }
                    CachedDnsLookup::PackagesAvailable => {
                        packages.push("com.example.allowed".into());
                    }
                    CachedDnsLookup::OtherOwnerBlocked => {
                        uid = 20_456;
                        packages.push("com.example.allowed".into());
                        signing_digest = Some([0x5a; 32]);
                    }
                }
            }
        }
        Ok(Some(FlowIdentity {
            uid,
            packages,
            signing_digest,
        }))
    });
    let metrics = Arc::new(FlowMetrics::default());
    let recorded = recording();
    let mut rules = vec![cached_uid_rule()];
    if matches!(outcome, CachedDnsLookup::OtherOwnerBlocked) {
        let mut blocked_owner = cached_uid_rule();
        blocked_owner.uid = Some(20_456);
        blocked_owner.action = RouteAction::Block;
        rules.push(blocked_owner);
    }
    let mut initial = optional_bypass_dns();
    initial.blocklist.bypass_packages.clear();
    let (engine, policy) = engine_parts(
        initial,
        rules.clone(),
        TrafficPolicyConfig::default(),
        attributor,
        Some(remote),
        metrics.clone(),
        recorded.clone(),
    );
    let mut lab = Lab::start_with(engine);
    let request = query(1);
    let before = if tcp {
        tcp_dns(&mut lab, &request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_240, &request, WINDOW).await
    }
    .expect("pure UID DNS must first bind a trustworthy UID-only owner");
    let promised = accepted_address(&before);
    let initial_lookups = calls.load(Ordering::SeqCst);
    assert_eq!(initial_lookups, 1);
    let mut traffic = TrafficPolicyConfig::default();
    if mandatory_packages == 1 {
        traffic.applications = vec![foxcore_api::ApplicationRouteConfig {
            package: "com.example.allowed".into(),
            action: foxcore_api::ApplicationRouteAction::Direct,
            expires_at_ms: None,
        }];
    } else if mandatory_packages == 2 {
        traffic.quarantine_new_apps = true;
    }
    assert_eq!(
        policy
            .reload(
                Some(1),
                RouteTable::compile_with_traffic(
                    rules,
                    RouteAction::Direct,
                    traffic,
                    false,
                    false,
                ),
                optional_bypass_dns(),
            )
            .unwrap(),
        2
    );
    after_reload.store(true, Ordering::SeqCst);
    let answer = if tcp {
        tcp_dns_on_open_stream(&mut lab, &request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_240, &request, WINDOW).await
    };
    assert!(calls.load(Ordering::SeqCst) > initial_lookups);
    if matches!(outcome, CachedDnsLookup::OtherOwnerBlocked) {
        assert!(answer.as_ref().is_some_and(|packet| packet[3] & 0x0f != 0));
        assert!(recorded.lock().unwrap().iter().any(|event| matches!(
            event,
            CoreEvent::Blocked {
                reason: foxcore_api::BlockReason::Policy,
                uid: Some(20_456),
                package: Some(package),
                ..
            } if package == "com.example.allowed"
        )));
        assert_eq!(metrics.snapshot().attribution_errors, 0);
        assert_eq!(metrics.snapshot().dns_queries, 1);
        lab.stop().await;
        http.abort();
        return;
    }
    if mandatory_packages != 0 {
        assert!(
            answer.is_none(),
            "a cached UID cannot satisfy new mandatory package policy"
        );
        assert_eq!(metrics.snapshot().dns_queries, 1);
        assert_eq!(metrics.snapshot().attribution_errors, 1);
        lab.stop().await;
        http.abort();
        return;
    }
    assert_eq!(
        accepted_address(
            &answer.expect("optional lookup failure must preserve the bound UID policy")
        ),
        promised
    );
    let blocked_request = optional_question("blocked.test", 1, false);
    let blocked = if tcp {
        tcp_dns_on_open_stream(&mut lab, &blocked_request).await
    } else {
        lab.dns_datagram(RESOLVER, 49_240, &blocked_request, WINDOW)
            .await
    }
    .unwrap();
    if matches!(outcome, CachedDnsLookup::PackagesAvailable) {
        accepted_address(&blocked);
        assert_eq!(metrics.snapshot().dns_blocked, 0);
        assert_eq!(calls.load(Ordering::SeqCst), initial_lookups + 1);
    } else {
        assert_eq!(blocked[3] & 0x0f, 3);
        assert_eq!(metrics.snapshot().dns_blocked, 1);
    }
    lab.open_to(promised, remote.port()).await;
    lab.send(
        FLAG_PSH | FLAG_ACK,
        b"GET /proof HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        lab.receive_tcp_payload(WINDOW, |packet| packet.len() >= RESPONSE.len())
            .await
            .unwrap(),
        RESPONSE
    );
    tokio::time::timeout(WINDOW, http).await.unwrap().unwrap();
    assert_eq!(metrics.snapshot().attribution_errors, 0);
    lab.stop().await;
}

macro_rules! cached_uid_dns_test {
    ($name:ident, $tcp:expr, $outcome:ident, $mandatory:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            cached_uid_dns_reload($tcp, CachedDnsLookup::$outcome, $mandatory).await;
        }
    };
}

cached_uid_dns_test!(
    tcp_cached_uid_survives_optional_missing_dns_lookup,
    true,
    Missing,
    0
);
cached_uid_dns_test!(
    udp_cached_uid_survives_optional_missing_dns_lookup,
    false,
    Missing,
    0
);
cached_uid_dns_test!(
    tcp_cached_uid_survives_optional_dns_lookup_error,
    true,
    Error,
    0
);
cached_uid_dns_test!(
    udp_cached_uid_survives_optional_dns_lookup_error,
    false,
    Error,
    0
);
cached_uid_dns_test!(
    tcp_cached_uid_attempts_available_optional_package_lookup,
    true,
    PackagesAvailable,
    0
);
cached_uid_dns_test!(
    udp_cached_uid_attempts_available_optional_package_lookup,
    false,
    PackagesAvailable,
    0
);
cached_uid_dns_test!(
    tcp_cached_uid_cannot_satisfy_new_app_package_policy,
    true,
    Missing,
    1
);
cached_uid_dns_test!(
    udp_cached_uid_cannot_satisfy_new_app_package_policy,
    false,
    Error,
    1
);
cached_uid_dns_test!(
    tcp_cached_uid_cannot_satisfy_new_quarantine_package_policy,
    true,
    Error,
    2
);
cached_uid_dns_test!(
    udp_cached_uid_cannot_satisfy_new_quarantine_package_policy,
    false,
    Missing,
    2
);

cached_uid_dns_test!(
    tcp_cached_uid_accepts_coherent_new_identity_for_route_audit,
    true,
    OtherOwnerBlocked,
    0
);
cached_uid_dns_test!(
    udp_cached_uid_accepts_coherent_new_identity_for_route_audit,
    false,
    OtherOwnerBlocked,
    0
);
