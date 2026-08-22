# Changelog

## Unreleased

- Replace the embedded `ipstack` fork with exact-pinned smoltcp 0.14.0 TCP,
  driven by a Fox-owned bounded Tokio actor. Transparent IPv4/IPv6 admission,
  SYN refusal, zero-window backpressure, FIN/RST, WireGuard packet-tunnel
  ownership and the existing Fox-owned UDP/DNS/ICMP policy remain covered by
  packet-level regressions. TCP buffer admission has a 64 MiB global budget,
  unpublished handshakes expire after 30 seconds, fatal TUN I/O reaches the
  engine unchanged, and shutdown joins both the actor and its writer.
- Add a coverage-guided fuzz target for the raw IP parser at the new netstack
  boundary, with valid IPv4, IPv6, options and extension-header seeds.
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
