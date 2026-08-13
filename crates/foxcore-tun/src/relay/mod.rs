//! L3 relay: tun packets in, WireGuard datagrams out. Owns the peer state
//! machine, one protected UDP socket and the address translator — no second
//! TCP stack. A packet is translated, sealed and written; the reverse on return.

mod engine;
mod state;

#[cfg(test)]
mod tests;

pub use state::*;
