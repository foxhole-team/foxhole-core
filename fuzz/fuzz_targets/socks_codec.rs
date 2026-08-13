#![no_main]

//! What an adversarial SOCKS5 proxy wrote back on the socket.
//!
//! The body lives in `foxcore-fuzz-harness` so it also compiles, and runs, on
//! the stable toolchain this repository is pinned to. See that crate's docs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    foxcore_fuzz_harness::socks_codec(data);
});
