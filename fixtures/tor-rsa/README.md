# RSA reachability review

The 2026-09-16 update changes four fixture paths from `aws-lc-rs-1.17.3` to
`aws-lc-rs-1.18.1`. `examples/cipher.rs`, `src/cipher.rs` and
`src/cipher/tests/fips.rs` are byte-identical. Their `DecryptingKey` is a
symmetric-cipher type. `src/rsa.rs` only adds the public re-export
`KeyPairComponents` from AWS-LC's own key implementation; it does not use the
RustCrypto `rsa` crate affected by RUSTSEC-2023-0071.

The gate still requires `rsa` 0.9.10, the same three direct dependents, absent
relay/directory-authority paths, and the same API mentions across all 25 files.
No matching pattern or gate condition was relaxed.
