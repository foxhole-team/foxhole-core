use std::net::UdpSocket;

use proto_wireguard::message::{Initiation, TYPE_INITIATION, message_type};
use proto_wireguard::noise::{TransportKeys, public_key, test_support::Responder};
use proto_wireguard::session::TransportSession;

const SERVER_STATIC: [u8; 32] = [9_u8; 32];

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn main() -> std::io::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(51820);
    let socket = UdpSocket::bind(("0.0.0.0", port))?;

    let public = public_key(&SERVER_STATIC).expect("static key");
    println!("listening on 0.0.0.0:{port}");
    println!("peer_public_key: {}", base64(&public));

    let responder = Responder::new(&SERVER_STATIC, [0; 32]).expect("responder");
    let mut session: Option<TransportSession> = None;
    let mut buffer = [0_u8; 2048];
    let mut nonce = 0_u32;
    let (mut handshakes, mut opened, mut dropped) = (0_u64, 0_u64, 0_u64);

    loop {
        let (len, from) = socket.recv_from(&mut buffer)?;
        if message_type(&buffer[..len]) == Some(TYPE_INITIATION) {
            let Ok(initiation) = Initiation::decode(&buffer[..len]) else {
                continue;
            };
            nonce = nonce.wrapping_add(1);
            let mut ephemeral = [0_u8; 32];
            ephemeral[0..4].copy_from_slice(&nonce.to_le_bytes());
            ephemeral[4] = 11;
            let sender_index = 0xABCD_0000_u32 | nonce;
            let Ok((response, send, receive)) =
                responder.respond(&initiation, &ephemeral, sender_index)
            else {
                continue;
            };
            socket.send_to(&response.encode(), from)?;
            session = Some(TransportSession::new(TransportKeys {
                send,
                receive,
                sender_index,
                receiver_index: initiation.sender_index,
            }));
            handshakes += 1;
            println!("handshake {handshakes} from {from} (opened={opened} dropped={dropped})");
            continue;
        }
        let Some(session) = session.as_mut() else {
            dropped += 1;
            continue;
        };
        if session.open(&mut buffer[..len]).is_err() {
            dropped += 1;
            continue;
        }
        opened += 1;
        let mut reply = Vec::new();
        if session.seal(&[], &mut reply).is_ok() {
            let _ = socket.send_to(&reply, from);
        }
    }
}
