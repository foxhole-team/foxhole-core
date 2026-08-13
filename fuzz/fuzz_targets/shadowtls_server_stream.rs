#![no_main]

//! A ShadowTLS server's replies, arriving one socket read at a time.
//!
//! The one target with memory: the input is a *sequence* of segments fed to a
//! single decoder, so the reassembly buffers, the chained HMAC and the session
//! flags are carried from one segment to the next.
//!
//! The body lives in `foxcore-fuzz-harness` so it also compiles, and runs, on
//! the stable toolchain this repository is pinned to. See that crate's docs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    foxcore_fuzz_harness::shadowtls_server_stream(data);
});
