# Changelog

## 0.0.5 — 2026-09-08

- Keep retained TCP/UDP sessions in one cancellation epoch across policy reloads;
  serialize network callbacks with policy and DNS-rule publication.
- Register LAN/loopback flows before dialing and cancel pending reads, writes,
  and handshakes on flow revocation, kill switch, or network change.
- Reject unsupported DNS questions before upstream I/O. Scope validated route
  hints to UID/packages and the current policy/network; preserve shared-IP
  ambiguity and refuse unbound IP flows when domain policy requires a name.
- Refresh both sides of fake-IP mappings, share their ownership across reloads,
  and refuse new allocations rather than evict addresses before their TTL.
- Own downloaded REALITY profiles with Arc, pin each connection to its selected
  table, and reject ECH payload lengths beyond the generator buffer.
- Return a typed Naive H2 closure error through the existing bounded retry.
- Enforce live share expiry and revocation under backpressure; zeroize queued
  plaintext on cancellation.
- Require explicit anonymous loopback consent and expose authentication mode.
- Expose route-rule explanations with shadowed Block rules while preserving
  schema-v1 specificity precedence for explicitly bound names.
- Pin release signatures to the owner signing subkey/primary key, require dev
  gate evidence no older than 24 hours, and add daily fresh-advisory checks.
- Test the minimal TUN feature set independently; retain ABI/config schema v1.

- Update transitive `chacha20` to 0.10.2 and `event-listener` to 5.4.2;
  regenerate both SBOMs and include transitive `bincode` in the maintenance inventory.
- Wait for peer-visible TCP resets before asserting that dropped sessions have
  released table capacity in the bounded-stack regression.

- Document Guard release provenance checks and F-Droid Core selection from the
  app revision pin inside its srclib; correct the reproducible recipe's
  update-channel and source-layout descriptions.

## 0.0.4

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
