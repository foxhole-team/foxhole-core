# Changelog

## Unreleased

- Document Guard release provenance checks and F-Droid Core selection from the
  app revision pin; correct the reproducible recipe's update-channel description.

- Set the workspace and native capabilities version to 0.0.4 while retaining
  ABI v1 and configuration schema v1.
- Give Tor-routed LAN and loopback CONNECT sessions 75 seconds to build a
  fresh circuit while retaining the 30-second VPN/direct budget and bounded,
  cancellation-aware session ownership.
- Preserve the unread tail of a UDP datagram when a public `DatagramFlow`
  caller supplies a short or zero-capacity `ReadBuf`; the first datagram and
  queued datagrams now share the same regression-covered partial-read path.
- Move the isolated smoltcp transparent-accept proof out of the production
  source tree and make it an explicitly named integration contract test.
- Remap checkout, Cargo-home and Rustup-home paths during Android release
  compilation. The ELF gate now rejects build-host paths, and the reproducible
  build check compares libraries built from different checkout and Cargo-home
  paths before accepting their bytes.
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
- Keep rustls with aws-lc-rs as the Fox-owned TLS/QUIC backend.
