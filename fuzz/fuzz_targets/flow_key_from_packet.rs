#![no_main]

//! Every packet read off the TUN is keyed here before anything else touches it.
//!
//! The body lives in `foxcore-fuzz-harness` so it also compiles, and runs, on
//! the stable toolchain this repository is pinned to. See that crate's docs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    foxcore_fuzz_harness::flow_key_from_packet(data);
});
