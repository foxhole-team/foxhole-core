# Changelog

## Unreleased

- Bound both UDP directions: each established flow retains at most 32 inbound
  datagrams and all flows share a 256-packet queue back to the TUN; overflow is
  dropped and counted instead of growing the process without a ceiling.
- Bound REALITY handshake plaintext and combined pending outgoing plaintext and
  ciphertext to 64 KiB, including backpressure regression coverage.
- Update `h2` to 0.4.18, closing the excessive-small-DATA-frame denial-of-service
  advisory and taking the subsequent HPACK and end-of-stream fixes.
- Keep rustls with aws-lc-rs as the Fox-owned TLS/QUIC backend. Direct BoringSSL
  is not added: a rustls primitive provider cannot change ClientHello shape, and
  a full libssl integration would add an unstable Android C++/FFI backend without
  replacing REALITY, Quinn, or non-Chromium fingerprint profiles.
