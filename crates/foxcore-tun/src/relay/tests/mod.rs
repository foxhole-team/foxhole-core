use super::*;
use bytes::BytesMut;
use std::sync::Arc;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use foxcore_api::{SecretString, WireguardConfig};
use foxcore_dialer::ProtectedDialer;
use foxcore_outbound::PacketTunnelOutbound;
use proto_wireguard::message::{Initiation, TYPE_INITIATION, message_type};
use proto_wireguard::noise::{TransportKeys, public_key, test_support::Responder};
use proto_wireguard::session::{TransportSession, ip_packet_len};
use tokio::net::UdpSocket;

const TUN_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const TUNNEL_V4: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const REMOTE_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const SERVER_STATIC: [u8; 32] = [9_u8; 32];
const SERVER_EPHEMERAL: [u8; 32] = [11_u8; 32];

fn base64(bytes: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn outbound(endpoint: SocketAddr) -> PacketTunnelOutbound {
    outbound_through(endpoint, ProtectedDialer::host())
}

fn outbound_through(endpoint: SocketAddr, dialer: ProtectedDialer) -> PacketTunnelOutbound {
    let config = WireguardConfig {
        server: endpoint.ip().to_string(),
        port: endpoint.port(),
        server_ip: Some(endpoint.ip()),
        private_key: SecretString::new(base64(&[7_u8; 32])),
        peer_public_key: SecretString::new(base64(&public_key(&SERVER_STATIC).unwrap())),
        preshared_key: None,
        address: vec![format!("{TUNNEL_V4}/32").parse().unwrap()],
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        mtu: 1420,
        persistent_keepalive_s: None,
        reserved: None,
        amnezia: None,
    };
    PacketTunnelOutbound::wireguard(config, dialer).unwrap()
}

/// What the platform does to every socket the core opens, recorded in the
/// order it happened.
///
/// The order is the point: `protect()` and the bind to the Android
/// `Network` have to run on a descriptor that has not yet carried a byte.
/// A rebind that reversed them would put the user's WireGuard datagrams
/// back into the tun the engine is serving.
#[derive(Default)]
struct PlatformCalls {
    calls: std::sync::Mutex<Vec<String>>,
    /// Refuse every `protect` after this many, so a rebind can be made to
    /// fail the way a real platform fails it.
    protect_budget: std::sync::atomic::AtomicI64,
}

impl PlatformCalls {
    fn unlimited() -> Arc<Self> {
        Arc::new(Self {
            calls: std::sync::Mutex::new(Vec::new()),
            protect_budget: std::sync::atomic::AtomicI64::new(i64::MAX),
        })
    }

    fn allowing(protects: i64) -> Arc<Self> {
        Arc::new(Self {
            calls: std::sync::Mutex::new(Vec::new()),
            protect_budget: std::sync::atomic::AtomicI64::new(protects),
        })
    }

    fn dialer(self: &Arc<Self>) -> ProtectedDialer {
        let protect = self.clone();
        let bind = self.clone();
        ProtectedDialer::new(
            foxcore_dialer::SocketCallbacks::new(
                move |_| {
                    let allowed = protect
                        .protect_budget
                        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
                        > 0;
                    protect.record(format!("protect:{allowed}"));
                    allowed
                },
                move |_, network| {
                    bind.record(format!("bind:{network}"));
                    true
                },
            ),
            Duration::from_secs(1),
        )
    }

    fn record(&self, call: String) {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(call);
    }

    fn taken(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// A minimal UDP/IPv4 packet. Checksums are not asserted here; `l3` owns
/// that and proves it separately.
fn ip_packet(source: Ipv4Addr, destination: Ipv4Addr) -> BytesMut {
    let mut packet = BytesMut::zeroed(28);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

async fn recv(socket: &UdpSocket, buffer: &mut [u8]) -> (usize, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), socket.recv_from(buffer))
        .await
        .expect("the relay should have sent something")
        .unwrap()
}

mod datapath;
mod lifecycle;
