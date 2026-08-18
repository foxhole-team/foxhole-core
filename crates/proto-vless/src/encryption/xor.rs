use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};

use super::aead::decode_header_raw;
use super::blake3;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let derived = blake3::derive_key(b"VLESS", key);
    Aes256Ctr::new((&derived).into(), iv.into())
}

pub fn mask_relay(nfs_public_key: &[u8], iv: &[u8; 16], relay: &mut [u8]) {
    new_ctr(nfs_public_key, iv).apply_keystream(relay);
}

pub struct RelayLink(Aes256Ctr);

impl RelayLink {
    pub fn new(nfs_key: &[u8], iv: &[u8; 16]) -> Self {
        Self(new_ctr(nfs_key, iv))
    }

    pub fn apply(&mut self, bytes: &mut [u8]) {
        self.0.apply_keystream(bytes);
    }
}

struct Direction {
    ctr: Option<Aes256Ctr>,
    skip: usize,
    header: Vec<u8>,
}

impl Direction {
    fn new(ctr: Option<Aes256Ctr>, skip: usize) -> Self {
        Self {
            ctr,
            skip,
            header: Vec::with_capacity(5),
        }
    }
}

pub struct XorState {
    out: Direction,
    inbound: Direction,
}

impl XorState {
    pub fn new(
        united_key: &[u8],
        out_iv: &[u8; 16],
        peer_iv: Option<&[u8; 16]>,
        out_skip: usize,
        in_skip: usize,
    ) -> Self {
        Self {
            out: Direction::new(Some(new_ctr(united_key, out_iv)), out_skip),
            inbound: Direction::new(peer_iv.map(|iv| new_ctr(united_key, iv)), in_skip),
        }
    }

    pub fn set_peer_iv(&mut self, united_key: &[u8], peer_iv: &[u8; 16]) {
        self.inbound.ctr = Some(new_ctr(united_key, peer_iv));
    }

    pub fn mask_outbound(&mut self, buffer: &mut [u8]) {
        Self::walk(&mut self.out, buffer, true);
    }

    pub fn unmask_inbound(&mut self, buffer: &mut [u8]) {
        Self::walk(&mut self.inbound, buffer, false);
    }

    fn walk(direction: &mut Direction, buffer: &mut [u8], outbound: bool) {
        let mut start = 0_usize;
        loop {
            if buffer.len() - start <= direction.skip {
                direction.skip -= buffer.len() - start;
                return;
            }
            start += direction.skip;
            direction.skip = 0;

            let Some(ctr) = direction.ctr.as_mut() else {
                return;
            };
            let need = 5 - direction.header.len();
            if buffer.len() - start < need {
                let tail = &mut buffer[start..];
                if outbound {
                    direction.header.extend_from_slice(tail);
                    ctr.apply_keystream(tail);
                } else {
                    ctr.apply_keystream(tail);
                    direction.header.extend_from_slice(tail);
                }
                return;
            }
            let slice = &mut buffer[start..start + need];
            if outbound {
                direction.header.extend_from_slice(slice);
                ctr.apply_keystream(slice);
            } else {
                ctr.apply_keystream(slice);
                direction.header.extend_from_slice(slice);
            }
            let mut header = [0_u8; 5];
            header.copy_from_slice(&direction.header);
            direction.header.clear();
            direction.skip = decode_header_raw(&header);
            start += need;
        }
    }
}
