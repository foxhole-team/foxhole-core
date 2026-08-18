//! Client-only REALITY TLS 1.3 state machine.
//!
//! The implementation is derived from the MIT-licensed `cfal/shoes` project
//! at commit `386b11532424b8665ee3e46340c6236fb3c47595`. Server, TUN, routing and
//! configuration code are intentionally not included. See the workspace
//! `THIRD_PARTY_NOTICES.md` and this crate's `LICENSE-MIT`.

mod common;
#[cfg(test)]
mod fingerprint_vector;
mod hello_profile;
#[cfg(test)]
mod parrot_fingerprints;
mod randomized_hello;
mod reality_aead;
mod reality_auth;
#[cfg(any(test, feature = "testkit"))]
mod reality_certificate;
mod reality_cipher_suite;
mod reality_client_connection;
mod reality_client_verify;
mod reality_key_exchange;
mod reality_reader_writer;
mod reality_records;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;
mod runtime_tables;
#[cfg_attr(all(test, not(feature = "testkit")), allow(dead_code))]
#[cfg(any(test, feature = "testkit"))]
pub(crate) mod testkit_internals;

#[cfg(feature = "fuzzing")]
pub mod fuzz_records;

pub use hello_profile::RealityHelloProfile;
pub use reality_cipher_suite::CipherSuite;
pub use reality_client_connection::{RealityClientConfig, RealityClientConnection, RealityHello};
pub use reality_util::{decode_public_key, decode_short_id};
pub use runtime_tables::{
    clear_fingerprint_tables, install_fingerprint_tables, using_downloaded_fingerprint_tables,
};
