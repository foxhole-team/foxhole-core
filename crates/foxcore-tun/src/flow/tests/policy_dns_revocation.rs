use super::*;
use crate::netstack::{FlowStack, StackConfig, StackFlow};
use foxcore_api::{DnsMode, DnsRoute, DnsUpstream};
use foxcore_trafficmap::RevokeTarget;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
enum Revocation {
    Kill,
    Uid,
    Package,
}

async fn pending_dns_is_revoked(target: Revocation) {
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns = DnsConfig {
        mode: DnsMode::RealIp,
        route: DnsRoute::Direct,
        timeout_ms: 100,
        upstreams: vec![
            DnsUpstream::Udp {
                address: first.local_addr().unwrap().to_string(),
            },
            DnsUpstream::Udp {
                address: fallback.local_addr().unwrap().to_string(),
            },
        ],
        ..Default::default()
    };
    let direct = Arc::new(Outbound::direct(ProtectedDialer::host()));
    let outbounds = Arc::new(OutboundRegistry::single(direct.clone()));
    let metrics = Arc::new(FlowMetrics::default());
    let policy = Arc::new(
        FlowPolicyStore::new(
            1,
            RouteTable::compile(Vec::new(), RouteAction::Direct),
            dns.clone(),
            outbounds.clone(),
            direct.clone(),
            metrics.clone(),
            EventSink::none(),
        )
        .unwrap(),
    );
    let map = Arc::new(TrafficMap::default());
    let engine = FlowEngine::new(FlowEngineContext {
        outbounds,
        direct,
        policy: policy.clone(),
        attributor: FlowAttributor::none(),
        runtime: RuntimeConfig::default(),
        metrics: metrics.clone(),
        events: EventSink::none(),
        packet_tunnel: false,
        connections: map.clone(),
    });
    let unrelated = map.open(
        IpTransport::Udp,
        "unrelated.example".into(),
        53,
        FlowRoute::new(FlowLane::Direct, "dns"),
        vec!["com.example.unrelated".into()],
        Some(10002),
    );
    let query = dns_query(0x1234);
    let builder =
        etherparse::PacketBuilder::ipv4([10, 77, 0, 2], [192, 0, 2, 53], 64).udp(53000, 53);
    let mut packet = Vec::new();
    builder.write(&mut packet, &query).unwrap();
    let (device, mut app) = tokio::io::duplex(65536);
    let mut stack = FlowStack::new(StackConfig::default(), device);
    app.write_all(&packet).await.unwrap();
    let flow = tokio::time::timeout(Duration::from_secs(1), stack.accept())
        .await
        .unwrap()
        .unwrap();
    let StackFlow::Udp(mut flow) = flow else {
        panic!("expected synthetic UDP DNS flow")
    };
    let mut context = FlowContext::new(1, IpTransport::Udp, Destination::new("192.0.2.53", 53));
    context.uid = Some(10001);
    context.package = Some("com.example.target".into());
    context.packages = vec!["com.example.target".into()];
    let cancel = CancellationToken::new();
    let run = tokio::spawn(async move { serve_dns_udp(&mut flow, &engine, context, cancel).await });
    let mut request = [0u8; 512];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(1), first.recv_from(&mut request))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        &request[..length],
        query.as_slice(),
        "first upstream must receive the actual pending query"
    );
    match target {
        Revocation::Kill => {
            policy
                .reload(None, compiled(traffic(true), true, true), dns)
                .unwrap();
        }
        Revocation::Uid => assert_eq!(map.revoke(&RevokeTarget::Uid { uid: 10001 }), 1),
        Revocation::Package => assert_eq!(
            map.revoke(&RevokeTarget::Package {
                package: "com.example.target".into()
            }),
            1
        ),
    }
    tokio::time::timeout(Duration::from_secs(1), run)
        .await
        .expect("revoked query must stop while first upstream is silent")
        .unwrap();
    if !matches!(target, Revocation::Kill) {
        assert!(
            !unrelated.flow().revocation().is_cancelled(),
            "targeted revocation must not stop an unrelated identity"
        );
    }
    let mut response = query.clone();
    response[2] = 0x81;
    response[3] = 0x80;
    first.send_to(&response, peer).await.unwrap();
    let mut extra = [0u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(150), fallback.recv_from(&mut extra))
            .await
            .is_err(),
        "no second upstream send after revocation"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), app.read(&mut extra))
            .await
            .is_err(),
        "no late answer or SERVFAIL may reach TUN after revocation"
    );
    assert_eq!(metrics.snapshot().flows_revoked, 1);
    stack.shutdown().await;
}

#[cfg_attr(miri, ignore = "local UDP and TUN actor require an I/O driver")]
#[tokio::test]
async fn regression_dns_kill_switch_stops_fallback_and_late_tun_reply() {
    pending_dns_is_revoked(Revocation::Kill).await;
}
#[cfg_attr(miri, ignore = "local UDP and TUN actor require an I/O driver")]
#[tokio::test]
async fn regression_dns_uid_revocation_stops_fallback_and_late_tun_reply() {
    pending_dns_is_revoked(Revocation::Uid).await;
}
#[cfg_attr(miri, ignore = "local UDP and TUN actor require an I/O driver")]
#[tokio::test]
async fn regression_dns_package_revocation_stops_fallback_and_late_tun_reply() {
    pending_dns_is_revoked(Revocation::Package).await;
}
