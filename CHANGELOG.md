# Changelog

## 1.0.1 — 2026-10-30

- Fix kill switch activation with expired DNS data and cancel DNS queries when their policy or app access is revoked.
- Fix partial Clash/SIP008 imports, DNS reload errors and CLI bootstrap timeouts.

## 1.0.0 Stable

Published release. The historical entries below do not qualify 1.0.1 binaries.

- Document public-beta OpenWrt controls and the shared first-setup agreement in Guard and VPN, without changing the JNI/native contract.
- Document VPN router socket approval through physical Wi-Fi binding with the exact service, driver, ticket and generation owner.

- Support bounded DoQ and DNS-over-HTTP/3 through the selected outbound, with protected bootstrap and no direct fallback.
- Add XHTTP stream-one over HTTP/2; reject other XHTTP modes and unsupported options.
- Support an explicit Chrome 151 profile for generic TCP TLS through the pinned rustls fork, separately from compiled REALITY profiles and certificate verification.
- Document checked AmneziaWG header ranges, four-ABI Android delivery and the owner-signed LAB handoff publisher; retain per-artifact runtime acceptance.

- Update zstd to 0.14.3, zstd-safe to 8.2.0 and zstd-sys to 2.1.2 through the compatible compression-codecs update; retain the Tor protocol feature set.

- Document post-policy router proof publication, probe-boundary cache invalidation and source-content legal provenance while keeping native producer identities separate.

- Update ctutils to 0.4.4 and Tokio to 1.53.3; revoke TUN reactor registration and wake pending I/O before its external owner closes the descriptor.
- Update certificate verification to rustls-webpki 0.103.16 and webpki-roots 1.0.10; reject distrusted emSign certificate paths.
- Update Sentinel to Wasmtime 49.0.4 and its matching Cranelift dependencies; preserve Pulley execution and the existing feature set.

- Refresh both isolated fuzz lockfiles and deterministic source inventories for 1.0.
- Document authenticated router DNS, monotonic handoff admission and exact phone lease ownership without changing JNI.

- Preserve Hysteria2 certificate fingerprints separately from SPKI pins; enforce exact DER SHA-256 matching without insecure fallback or ambiguous pin types.

- Import bounded Clash/mihomo proxy YAML; preserve supported TLS/transport options and report unsupported nodes or client policy without loading it.

- Parse strict SIP008 and standard Outline JSON subscription nodes; normalize dynamic Outline keys to HTTPS without fetching or exposing access URLs.

- Import single router profiles through private files, with atomic output and the same compiled-protocol admission.

- Add a Linux router CLI with selectable VPN protocols, protected endpoint DNS, exclusive TUN ownership, private atomic status and generation-bound HTTPS connection proof.
- Add an authenticated loopback TCP/UDP bridge bound to the owned TUN; fence sessions by process, interface and generation, and report ownership with a lossless generation key.
- Expose query-validated DNS answer addresses and a host-owned resolver callback; preserve Android's selected-network resolver requirement.
- Store the large WireGuard peer configuration behind its packet-tunnel owner to reduce outbound-mode stack size.

- Honor authenticated Hysteria2 automatic/finite receive limits; apply loss-compensated Brutal pacing to actual UDP sends, with bounded datagram budgets and cancellable timer waits.

- Document VPN themes, queued restarts, owned-network socket readiness and bounded HTTPS admission without changing the JNI/native contract.

- Document standalone VPN widget commands, explicit Android consent and cached device/validated exit geography.

- Document semantic Android notices and the final APK-check settings block without changing the runtime contract.

- Require current ARM64, ARMv7, x86 and x86_64 JNI artifacts, capabilities origins and ELF checks through the explicit android4 release profile.
- Align data-delivery documentation with categorized DNS, all nine signed manifests and packaged application seeds.
- Document the theme-tinted vector VPN globe, anchored geographic callouts, bounded motion and route-midpoint centering.
- Document FoxHole VPN's signed REALITY table updater through the existing JNI contract, including compiled-baseline comparison, transactional cache publication and process-local future-handshake scope.
- Set the product release channel to Stable; retain individual protocol maturity and artifact-specific verification scope.
- Document the separate VPN-only Android consumer, encrypted profile storage, command ownership and VPN-bound connection proof.
- Distinguish foreground default-network geography from validated VPN-exit coordinates and document the manual globe presentation.

- Document authenticated user-initiated WebApp entry and lock-bound proxy acquisition.

- Document Android quarantine command receipts, unsupported per-app routing outcomes, notification access and complete Sentinel delivery inventory.

- Document per-package scanner constraint checks and retryable automatic-work interruption.

- Remove the debug-only ascii_tree scanner dependency; retain upstream parser fixtures and explicit BSD-3-Clause formatter provenance.
- Document User/Expert presentation, preference migration and visible critical notices without changing the runtime contract.

- Document the Android isolated scanner ownership, portable backup restore credential binding and categorized DNS seed/admission contracts.

- Add the optional isolated static-scanner native workspace with bounded YARA sessions, API26 read-only FD validation, locked Docker builds and dependency license notices.

- Stream canonical categorized DNS input verification, permit bounded full-tier compiler inputs and collect category facts during the existing FST validation pass.

- Add strict signed categorized DNS manifests, explicit category masks and a canonical tagged suffix compiler while preserving legacy bundles.
- Check answered DNS aliases before caching and route-hint learning; preserve package bypasses and empty-filter behavior.

- Return relay buffer-allocation failures before stream I/O; reject empty buffers and permit idle-cache growth to fail during buffer return.

- Document automatic Android worker selection and honest anomaly-notification submission without changing native schemas.

- Document owned feed-builder temporary directories, locked DNS compiler inputs and semantic numeric IOC validation.

- Document transient Sentinel IOC observation, privacy cursor reset and IPv6/late-owner
  handling with cancellation-safe quarantine workers at the Android boundary.

- Document the Android Sentinel process-owned journal IO lane and mandatory certificate
  inspection failure/cancellation contract without changing the JNI surface.

- Align detached fuzz-workspace MSRV declarations to 1.92 and refresh their locked
  Rustls/aws-lc security dependencies; retain separate stable harness verification.

- Update Quinn to 0.11.12, quinn-proto to 0.11.19 and quinn-udp to 0.5.16, including
  the upstream stream-limit and Retry handling security fixes.
- Update Arti and its Tor crates to 0.47.0 with safelog 0.10.0, always-on congestion
  control and MSRV 1.92; refresh the pinned RSA source audit and dependency inventory.

- Forward the pinned Rust toolchain and requested Cargo offline mode into Android Docker invocations, with regressions in local and CI gates.
- Document owned Android manual diagnostic counter reads and read-only existing-key journal snapshots.

- Clarify the TUN relay cache comment: its eight-buffer capacity floor can exceed the nominal 1 MiB idle budget; runtime behavior is unchanged.
- Document cancellation and fatal error propagation at the guarded Android native audit boundary.
- Document ownership-checked Android reload cancellation and generation-scoped validation failure audits.
- Wake Hysteria2 UDP receivers and release registrations when their QUIC owner closes or reconnects.
- Preserve global filtering and admitted UID DNS flows when optional package-bypass lookups fail; keep mandatory UID, app and quarantine guards.
- Document cancellable Sentinel refresh, coherent local feed publication and bounded Android DoH response reads.

- Restore validated Fake-IP DNS bootstrap on legacy Android; attribute DNS package bypasses without accepting partial shared-UID metadata.
- Support checked Amnezia HeaderProtectionKey profiles and decrypt protected transport in place with zeroizing key ownership.
- Support checked Amnezia content-padding ranges with authenticated padding and bounded peer-window allocation; advertise implemented padding capabilities.
- Preserve unexpired DNS address promises across Android engine replacement on the same TUN, with bounded ownership and cleanup.
- Document cooperative user Stop, native helper page alignment and verified build-cache identities.
- Isolate cold reproducibility targets from inherited caches and exclude local instructions from moved sources.
- Update rustls to 0.23.46 and its matching crypto dependencies, retaining the TLS security fixes.
- Share connection deadlines across resolved addresses; release losing TCP and QUIC candidates.
- Preserve fragmented Trojan UDP and coalesced VLESS XUDP frames under bidirectional traffic.
- Correct Amnezia custom-header authentication and support typed RandomTrailers padding.
- Retry unanswered WireGuard handshakes across resolved peer addresses without replacing live sessions.
- Build and verify ARM64, ARMv7, x86 and x86_64 native libraries with pinned Docker toolchains.
- Document bounded Expert core tuning and the Android settings, clock and startup contracts.

- Document bounded GitHub asset redirects and per-origin token handling in the Android clients.
- Document separate GitHub and F-Droid release APKs, their update policies and per-APK delivery verification.

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
