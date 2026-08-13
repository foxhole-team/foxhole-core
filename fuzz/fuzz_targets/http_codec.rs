#![no_main]

//! The response head an adversarial HTTP proxy is streaming.
//!
//! The body lives in `foxcore-fuzz-harness` so it also compiles, and runs, on
//! the stable toolchain this repository is pinned to. See that crate's docs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    foxcore_fuzz_harness::http_codec(data);
});
