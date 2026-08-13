#![no_main]

//! One UDP datagram from a WireGuard peer.
//!
//! The body lives in `foxcore-fuzz-harness` so it also compiles, and runs, on
//! the stable toolchain this repository is pinned to. See that crate's docs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    foxcore_fuzz_harness::wireguard_message(data);
});
