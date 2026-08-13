//! Where LAN traffic goes once the ingress has authenticated it.
//!
//! The component crate defines the ingress and knows nothing about protocols;
//! this is the half that owns a tunnel, and it is the only place entitled to
//! hand one out. Every refusal here is final: a LAN session whose upstream is
//! unavailable is refused, never redirected. A LAN proxy that fell back to the
//! open network would carry another device's traffic in the clear while
//! presenting itself as the phone's tunnel — the one failure mode that makes
//! this feature worse than not having it.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use foxcore_api::{Destination, FlowContext, IpTransport};
use foxcore_component::{LanConnect, LanIo, LanRoute, LanUpstream};
use foxcore_outbound::OutboundRegistry;
use foxcore_trafficmap::{FlowHandle, FlowRoute, TrafficMap};
use foxcore_tun::{ContinuityGate, FlowLane, FlowPolicyStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The upstream the root runtime hands to a LAN proxy.
///
/// Holds the same policy store and continuity gate the data plane reads, so a
/// kill switch or a held lane stops LAN sessions at exactly the moment it stops
/// the phone's own flows. Checking a snapshot taken at start would leave the
/// LAN listener carrying traffic after the device itself went quiet.
pub(crate) struct RegistryUpstream {
    generation: u64,
    outbounds: Arc<OutboundRegistry>,
    policy: Arc<FlowPolicyStore>,
    continuity: Arc<ContinuityGate>,
    /// The same map the flow engine writes to. A LAN session reaches its
    /// outbound through the component ingress and never touches the flow
    /// engine, so without this it moved bytes that nothing counted.
    map: Arc<TrafficMap>,
    /// The protected dialer wrapped as an outbound, for the one route that is
    /// deliberately not a tunnel.
    ///
    /// Held rather than built per session because it is the same dialer the flow
    /// engine's `direct` split rules use, and because building it lazily would
    /// put a second construction site next to the one line in this file that
    /// hands out a non-tunnelled connection.
    direct: Arc<foxcore_outbound::Outbound>,
}

impl RegistryUpstream {
    pub(crate) fn new(
        generation: u64,
        outbounds: Arc<OutboundRegistry>,
        policy: Arc<FlowPolicyStore>,
        continuity: Arc<ContinuityGate>,
        map: Arc<TrafficMap>,
        direct: Arc<foxcore_outbound::Outbound>,
    ) -> Self {
        Self {
            generation,
            outbounds,
            policy,
            continuity,
            map,
            direct,
        }
    }

    /// Resolve one session's outbound, or refuse.
    ///
    /// Written as a single function returning `Option` so there is exactly one
    /// place a route can be produced, and no branch that could reach for a
    /// different one after this returns `None`.
    fn resolve(&self, route: LanRoute) -> Option<Arc<foxcore_outbound::Outbound>> {
        let policy = self.policy.gates();
        if policy.kill_switch() {
            return None;
        }
        match route {
            LanRoute::Vpn => {
                if self.continuity.is_held(FlowLane::Vpn) {
                    return None;
                }
                // On an L3 profile the registry's default is a clearnet
                // placeholder that dials outside the tunnel. Handing it out here
                // is the exact failure the module header forbids, and worse than
                // the plain version of it: the session is opened on
                // `FlowLane::Vpn`, so the traffic map — and the screen reading
                // it — shows another device's bytes as tunnelled while they are
                // on the open network. The control proxy runs on this preset and
                // the app really does switch it on, so this is the live path.
                if self.outbounds.primary_is_packet_tunnel() {
                    return None;
                }
                Some(self.outbounds.default().clone())
            }
            LanRoute::Tor => {
                // The overlay gate is hot: `tor_enabled=false` has to stop LAN
                // sessions the same instant it stops the device's own.
                if !policy.tor_enabled() || self.continuity.is_held(FlowLane::Tor) {
                    return None;
                }
                self.outbounds.tor().cloned()
            }
            // Reachable only from a named loopback inbound whose configuration
            // said `direct` in as many words. It is still gated: the kill switch
            // above stops it, and so does a hold on the direct lane, because
            // both of those mean "this device is not sending anything right now"
            // — and an inbound that kept going would be the one socket that
            // ignored the switch the user just flipped.
            LanRoute::Direct => {
                if self.continuity.is_held(FlowLane::Direct) {
                    return None;
                }
                Some(self.direct.clone())
            }
        }
    }
}

impl LanUpstream for RegistryUpstream {
    fn connect(&self, route: LanRoute, host: String, port: u16) -> LanConnect {
        let Some(outbound) = self.resolve(route) else {
            return Box::pin(std::future::ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LAN upstream is unavailable",
            ))));
        };
        let destination = Destination::new(host.clone(), port);
        let generation = self.generation;
        let lane = match route {
            LanRoute::Vpn => FlowLane::Vpn,
            LanRoute::Tor => FlowLane::Tor,
            LanRoute::Direct => FlowLane::Direct,
        };
        let map = self.map.clone();
        Box::pin(async move {
            let context = FlowContext::new(generation, IpTransport::Tcp, destination.clone());
            let stream = outbound.connect_stream(&context, destination).await?;
            // Opened only once the dial succeeded, so a refused session does not
            // leave a row that never carried anything.
            //
            // No packages and no uid, and that is the honest answer rather than a
            // gap: the traffic belongs to another machine on the Wi-Fi, so there
            // is no local app to name. Inventing one would file a neighbour's
            // bytes under something that looks like an installed app.
            let flow = map.open(
                IpTransport::Tcp,
                host,
                port,
                FlowRoute::new(lane, outbound.kind().name()),
                Vec::new(),
                None,
            );
            Ok(Box::new(CountedLanStream {
                inner: stream,
                flow,
            }) as Box<dyn LanIo>)
        })
    }
}

/// Counts a LAN session's bytes into the traffic map as they pass.
///
/// Counting at the relay would have meant teaching the component crate about
/// the map, and that crate deliberately owns no protocol or accounting code.
/// The runtime already hands out the tunnel, so it is also the place that can
/// say what the tunnel carried. Dropping the handle closes the row and folds
/// the totals in, so a session that ends abruptly is still accounted for.
///
/// Generic over the stream rather than naming the transport's boxed alias: this
/// crate does not otherwise depend on the transport crate, and a counting
/// wrapper has no reason to be the thing that introduces the edge.
struct CountedLanStream<S> {
    inner: S,
    flow: FlowHandle,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedLanStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let read = buf.filled().len().saturating_sub(before);
            if read > 0 {
                self.flow.add_down(read as u64);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedLanStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(written)) = result {
            self.flow.add_up(written as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::SocketAddr;

    use foxcore_api::{EventSink, OutboundId, RouteAction, TrafficPolicyConfig};
    use foxcore_dialer::ProtectedDialer;
    use foxcore_outbound::Outbound;
    use foxcore_route::RouteTable;
    use foxcore_trafficmap::TrafficMap;
    use foxcore_tun::FlowMetrics;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Echoes four bytes and closes, so the session has traffic in both
    /// directions and a definite end.
    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });
        address
    }

    fn upstream(map: &Arc<TrafficMap>) -> RegistryUpstream {
        build_upstream(map, false, TrafficPolicyConfig::default(), false)
    }

    /// The same registry with the kill switch armed in the compiled route
    /// table, which is what a reload that arms it produces.
    fn upstream_with_kill_switch(map: &Arc<TrafficMap>) -> RegistryUpstream {
        build_upstream(
            map,
            false,
            TrafficPolicyConfig {
                kill_switch: true,
                ..Default::default()
            },
            false,
        )
    }

    /// The overlay gate **on** and no Tor outbound in the registry.
    ///
    /// The distinction is load-bearing and it caught a test of mine passing for
    /// the wrong reason: with the gate off, `resolve` refuses on the gate and
    /// never reaches the line that looks the outbound up, so a substitution
    /// planted in that line went undetected. This harness is the profile where
    /// the user has Tor enabled and the profile simply has no Tor lane, which is
    /// the state the substitution would actually leak in.
    fn upstream_with_tor_enabled_but_no_tor_outbound(map: &Arc<TrafficMap>) -> RegistryUpstream {
        build_upstream(map, false, TrafficPolicyConfig::default(), true)
    }

    /// `packet_tunnel_primary` marks the registry's default as the clearnet
    /// stand-in an L3 profile leaves behind, which is what the runtime does when
    /// the primary outbound is a tunnel.
    fn upstream_with_primary(
        map: &Arc<TrafficMap>,
        packet_tunnel_primary: bool,
    ) -> RegistryUpstream {
        build_upstream(
            map,
            packet_tunnel_primary,
            TrafficPolicyConfig::default(),
            false,
        )
    }

    fn build_upstream(
        map: &Arc<TrafficMap>,
        packet_tunnel_primary: bool,
        traffic: TrafficPolicyConfig,
        tor_enabled: bool,
    ) -> RegistryUpstream {
        let dialer = ProtectedDialer::host();
        let direct = Arc::new(Outbound::direct(dialer.clone()));
        let registry = OutboundRegistry::new(direct.clone(), HashMap::new()).unwrap();
        let outbounds = Arc::new(if packet_tunnel_primary {
            registry.with_packet_tunnel_primary()
        } else {
            registry
        });
        let routes = RouteTable::compile_with_traffic(
            Vec::new(),
            RouteAction::Outbound(OutboundId("default".into())),
            traffic,
            tor_enabled,
            false,
        );
        let policy = Arc::new(
            FlowPolicyStore::new(
                1,
                routes,
                foxcore_api::DnsConfig::default(),
                outbounds.clone(),
                direct,
                Arc::new(FlowMetrics::default()),
                EventSink::none(),
            )
            .unwrap(),
        );
        let continuity = Arc::new(ContinuityGate::new(Default::default(), EventSink::none()));
        RegistryUpstream::new(
            1,
            outbounds,
            policy,
            continuity,
            map.clone(),
            Arc::new(Outbound::direct(dialer)),
        )
    }

    /// A LAN session must appear in the traffic map like any other flow.
    ///
    /// It reaches its outbound through the component ingress rather than the
    /// flow engine, and the map is opened by the flow engine — so this path had
    /// no row, no lane bytes and no live connection at all. That is the same
    /// shape as D1, D2, D7 and D10: the behaviour was right and the counter was
    /// silent, which on a screen is a Tor lane sitting idle while it carries a
    /// neighbour's traffic.
    #[tokio::test]
    async fn a_lan_session_is_counted_on_the_lane_that_carried_it() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream(&map);

        let mut stream = upstream
            .connect(LanRoute::Vpn, echo.ip().to_string(), echo.port())
            .await
            .expect("the direct outbound must serve a Vpn-preset session");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping", "the session has to actually carry bytes");
        drop(stream);

        let snapshot = map.snapshot();
        let vpn = snapshot
            .lanes
            .iter()
            .find(|lane| lane.lane == FlowLane::Vpn)
            .expect("the vpn lane is always present");
        assert_eq!(
            vpn.flows_opened, 1,
            "a LAN session must open exactly one row on the lane that carried it"
        );
        assert!(
            vpn.bytes_up >= 4 && vpn.bytes_down >= 4,
            "the bytes a LAN session carried must land on its lane, got up={} down={}",
            vpn.bytes_up,
            vpn.bytes_down
        );
    }

    /// On an L3 profile there is no tunnel to hand a LAN session, so it is
    /// refused.
    ///
    /// `LanRoute::Vpn` reached for the registry's default, and on a packet-tunnel
    /// profile that is the clearnet stand-in — a protected dialer that goes
    /// around the tunnel. The row is still opened on `FlowLane::Vpn`, so the
    /// traffic map and the screen reading it showed a neighbour's bytes as
    /// tunnelled while they were on the open network. That is the one failure
    /// the header of this module calls worse than not having the feature, and it
    /// is live: the control proxy runs on this preset and the app turns it on.
    #[tokio::test]
    async fn a_lan_session_on_a_packet_tunnel_profile_is_refused_rather_than_sent_clearnet() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream_with_primary(&map, true);

        let Err(error) = upstream
            .connect(LanRoute::Vpn, echo.ip().to_string(), echo.port())
            .await
        else {
            panic!("the default is a clearnet placeholder here and must not be handed out");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let snapshot = map.snapshot();
        for lane in &snapshot.lanes {
            assert_eq!(
                (lane.flows_opened, lane.bytes_up, lane.bytes_down),
                (0, 0, 0),
                "a refused session must not be filed as tunnelled traffic on the {:?} lane",
                lane.lane
            );
        }
    }

    /// The lane is the preset's, not a default.
    ///
    /// Reading the vpn lane alone cannot catch a session filed under the wrong
    /// preset, because every other app on a phone is already on that lane. Tor
    /// is the lane nothing else touches, which is why the device run used it.
    #[tokio::test]
    async fn a_lan_session_is_not_filed_under_a_lane_it_did_not_use() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream(&map);

        let mut stream = upstream
            .connect(LanRoute::Vpn, echo.ip().to_string(), echo.port())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        drop(stream);

        let snapshot = map.snapshot();
        for lane in &snapshot.lanes {
            if lane.lane == FlowLane::Vpn {
                continue;
            }
            assert_eq!(
                (lane.flows_opened, lane.bytes_up, lane.bytes_down),
                (0, 0, 0),
                "a Vpn-preset session must not appear on the {:?} lane",
                lane.lane
            );
        }
    }
    /// The `Direct` route exists for named loopback inbounds, and it is the one
    /// route in this file that is deliberately not a tunnel.
    ///
    /// It reaches the network — that is the point of it — and it is still gated
    /// by the same things the tunnelled routes are. The lane it is filed under
    /// is `Direct` and not `Vpn`, which is the difference between a screen that
    /// says "this app is outside the tunnel" and one that lies about it.
    #[tokio::test]
    async fn a_direct_named_inbound_leaves_directly_and_is_filed_on_the_direct_lane() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream(&map);

        let mut stream = upstream
            .connect(LanRoute::Direct, echo.ip().to_string(), echo.port())
            .await
            .expect("a direct inbound is the one route that is allowed to be untunnelled");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        drop(stream);

        let snapshot = map.snapshot();
        for lane in &snapshot.lanes {
            let expected = lane.lane == FlowLane::Direct;
            assert_eq!(
                lane.flows_opened > 0,
                expected,
                "a direct session must be filed on the direct lane and nowhere else, \
                 got {:?} with {} flows",
                lane.lane,
                lane.flows_opened
            );
        }
    }

    /// A `Tor` route with the overlay gate **on** and no Tor outbound in the
    /// profile is refused, never served by the registry's default.
    ///
    /// This is the leak the whole feature has to not have: a web app the user
    /// labelled Tor whose requests go out on the profile — or worse, directly —
    /// under a label that says they did not.
    ///
    /// The gate is deliberately on. With it off, `resolve` refuses one line
    /// earlier and never reaches the lookup, so this test passed against a build
    /// where the lookup had been replaced by `unwrap_or_else(|| default)` — it
    /// was checking the gate and reporting on the substitution. Two tests now,
    /// one per branch.
    #[tokio::test]
    async fn a_tor_route_without_a_tor_outbound_is_refused_rather_than_substituted() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream_with_tor_enabled_but_no_tor_outbound(&map);

        let Err(error) = upstream
            .connect(LanRoute::Tor, echo.ip().to_string(), echo.port())
            .await
        else {
            panic!("there is no tor lane here and there is no substitute for one");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let snapshot = map.snapshot();
        for lane in &snapshot.lanes {
            assert_eq!(
                (lane.flows_opened, lane.bytes_up, lane.bytes_down),
                (0, 0, 0),
                "a refused session must leave no trace on the {:?} lane",
                lane.lane
            );
        }
    }

    /// And the gate itself is hot: `tor_enabled=false` stops a Tor-labelled
    /// session at the moment it stops the device's own flows, without waiting
    /// for anything to be rebuilt.
    #[tokio::test]
    async fn a_tor_route_is_refused_the_moment_the_overlay_gate_is_off() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream(&map);

        let Err(error) = upstream
            .connect(LanRoute::Tor, echo.ip().to_string(), echo.port())
            .await
        else {
            panic!("the overlay gate is off and there is no substitute for Tor");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// The kill switch stops every route this file can hand out, including the
    /// one that was never a tunnel.
    ///
    /// `Direct` is the tempting exception — the user asked for it to be outside
    /// the tunnel, so why would the switch apply — and it is the wrong one: the
    /// kill switch means this device is not sending anything, and an inbound
    /// that kept going would be the one socket that ignored it.
    #[tokio::test]
    async fn the_kill_switch_stops_every_route_including_direct() {
        let echo = echo_server().await;
        let map = Arc::new(TrafficMap::default());
        let upstream = upstream_with_kill_switch(&map);

        for route in [LanRoute::Vpn, LanRoute::Tor, LanRoute::Direct] {
            let Err(error) = upstream
                .connect(route, echo.ip().to_string(), echo.port())
                .await
            else {
                panic!("{route:?} must be refused while the kill switch is armed");
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{route:?}");
        }
    }
}
