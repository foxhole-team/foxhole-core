# Interoperability

## Current 1.0.1 artifact status — 2026-10-30

Independent device/peer interoperability is **NOT_VERIFIED** for new 1.0.1 binaries.
All four Android JNI libraries have been built and passed the static ELF/page/export checks.
The ARM64 library also passed an ordinary-shell C ABI/capabilities probe on Pixel 7 Pro,
Android API 37 with 4 KiB pages. This is separate from JNI/app, 16 KiB runtime and peer acceptance.
Capabilities retain their beta/experimental maturity; source tests are separate evidence.

Each result must identify the actual binary, device/OS, API, ABI, runtime page size, peer implementation
and version, UTC date, direction/traffic result, and evidence. Use one row per actual combination;
replace PENDING only after the corresponding run. An ELF alignment check does not prove runtime on
a device with that page size. A harness, an app-owned IP indicator, or earlier binaries cannot qualify
independent interoperability for this release.

| Feature / variant | Binary SHA-256 | Device / OS | API | ABI | Runtime page size | Peer / version | UTC date | Result | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VLESS / TLS / REALITY / Vision / supported carriers | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| VMess AEAD | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| Trojan | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| Shadowsocks AEAD / AEAD-2022 / Outline | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| Hysteria2 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| WireGuard / AmneziaWG | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| Naive / HTTP CONNECT / SOCKS5 | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| TUIC / AnyTLS / ShadowTLS | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| Tor / bridges / onion service | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| I2P adapter | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |
| DNS transports / policy reload / LAN proxy | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING | NOT_VERIFIED | PENDING |

## New asset qualification ledger

| Asset | Target / ABI | Binary SHA-256 | Source / producer | Native build/gates | Device/API/page/peer result |
| --- | --- | --- | --- | --- | --- |
| libfoxhole_native.so | aarch64-linux-android / arm64-v8a | `e37c57e23d9d02b6c2eceee9623f5217973bdd8e9c39961bb887a0d4bafbd55c` | `7b15f5b614031181b5a2eab274acac6f15d961ff` | Build/static gates PASS | Pixel 7 Pro/API37/4KiB: C ABI probe PASS; JNI/peer NOT_VERIFIED |
| libfoxhole_native.so | armv7-linux-androideabi / armeabi-v7a | `c32d7561f6fcc90e97b1267366b0d39f32b1a8aea9aea0b37afe908d2d4b909a` | `7b15f5b614031181b5a2eab274acac6f15d961ff` | Build/static gates PASS | PENDING |
| libfoxhole_native.so | i686-linux-android / x86 | `8446dcfa44cf2aa2e314d397440d06db45fb04c7224a5714d428f8b6e9bbb583` | `7b15f5b614031181b5a2eab274acac6f15d961ff` | Build/static gates PASS | PENDING |
| libfoxhole_native.so | x86_64-linux-android / x86_64 | `2ab062d033f53c874690fe7404bd8d7064f1431b5e51b4fdb1c01bd8a3f0cb48` | `7b15f5b614031181b5a2eab274acac6f15d961ff` | Build/static gates PASS | PENDING |
| foxcore-dns-compile | x86_64-unknown-linux-gnu | `dd830749c246cb6d8f2c8a5d6368cfb7e18f1b562c5ec29ae391c2e9a1520414` | `7b15f5b614031181b5a2eab274acac6f15d961ff` | Build, tagged fixture and 5 compiler tests PASS | Host compiler; peer/device acceptance is N/A |

Native producer receipt SHA-256: `bfc4bbbb4aabf806a56c8bcb71dcab92b0287c45710345d78a44ed22ea9eaf40`.
Pixel C ABI probe receipt SHA-256: `1391aee857b854f7ee2a9863168d7bd1ad496b2dc1f325c6d431e95c038a7f5a`.
Capabilities SHA-256: `3d5b48f3a82c65171f558ff59ebba0dbc1647d014c8507e2aa15965623494e2c`.

## Source checks completed for the 1.0.1 patch

51 focused tests passed on an aarch64 Apple Darwin host with Rust 1.97.1: Clash 11,
SIP008/Outline 5, expired schema-3 emergency gate 1, DNS kill/UID/package revocation through local
UDP and an in-memory TUN 3, existing affected DNS cases 26, typed refusal/ABI values 2, and
virtual-clock CLI bootstrap budget 3. The normal three-package Miri recipe also passed 272 tests
with nightly-2026-08-12 on this host. The Linux workspace suite passed 1,719 tests with 10 ignored;
Clippy with warnings denied, all seven feature profiles, and the normal ABI/rollback record and
verification passed. The Android workspace/all-features cross-check passed for all four ABIs.
Fresh advisory, licence, source and both SBOM checks passed without new ignores.
Fuzz campaign results and retained component scopes are recorded separately in release provenance.
These source checks do not establish physical-device, ARM/16 KiB or independent-peer acceptance.

## Historical observations — earlier artifacts only

The previous document carried the following statements with a pending note dated 2026-08-17.
It did not provide per-row binary SHA, device/API, ABI/page, peer version, date or evidence identity.
They are retained here as historical statements, not promoted to verified 1.0.1 results. Original
LAB/device records, where available, keep their own source, binary, environment and date scopes.

| Feature | TCP | UDP | IPv6 | Status |
| --- | --- | --- | --- | --- |
| **VLESS** (raw/WS/HTTPUpgrade/gRPC/H2, TLS) | yes | yes | yes | `historical claim` |
| VLESS / REALITY | yes | n/a | yes | `historical claim` |
| VLESS / Vision | yes | via XUDP | yes | `historical claim` |
| VLESS / XUDP, packetaddr | n/a | yes | yes | `historical claim` |
| VLESS encryption (`mlkem768x25519plus`) | yes | n/a | yes | `historical harness claim` — 12 transcripts from the reference Go client/server |
| **VMess** (AEAD) | yes | yes | yes | `historical claim` |
| **Trojan** | yes | yes | yes | `historical claim` |
| **Shadowsocks** AEAD | yes | yes | yes | `historical claim` |
| Shadowsocks AEAD-2022 | yes | yes | yes | `historical claim` |
| Shadowsocks Outline prefix | yes | n/a | yes | `historical claim` |
| Shadowsocks `simple-obfs` | yes | n/a | yes | `historical claim` (`http` mode only; `tls` mode never run) |
| **Naive** (H2 CONNECT + padding) | yes | no | yes | `historical claim` |
| **Hysteria2** (Brutal, Salamander, port hopping) | yes | yes | yes | `historical claim` |
| **WireGuard** (L3, Noise_IKpsk2) | L3 | yes | yes | `historical claim` |
| **AmneziaWG** | L3 | yes | yes | `untested-datapath` — golden vectors for the 2.0 `I1`–`I5` templates; not one probe against a peer, ever |
| **TUIC v5** | yes | yes | yes | `untested-datapath` |
| **AnyTLS v2** | yes | yes | yes | `untested-datapath` |
| **ShadowTLS v3** | yes | yes | yes | `untested-datapath` |
| **SOCKS5** | yes | yes | yes | `historical claim` (host-side; UDP ASSOCIATE untested — no server offered it) |
| **HTTP CONNECT** | yes | no | yes | `historical claim` (host-side) |
| **Tor / Arti** | yes | no | yes | `historical claim` — live `.onion`, fail-closed gate open→closed→open on one tunnel |
| Tor pluggable transports | yes | no | yes | `untested-datapath` — config and loopback bridge built, no run recorded |
| Tor onion service (publishing) | yes | no | yes | `untested-datapath` — compiled for ABI v1, but Guard has no product call site and no publication run is recorded |
| **I2P** (external i2pd over loopback SOCKS5) | yes | no | n/a | `historical claim` — live i2pd, fail-closed gate, three-runtime independence |
| **Selector / urltest** | yes | yes | yes | `historical harness claim` |


| Feature | Status |
| --- | --- |
| TUN flow engine | `historical claim` — two 30-minute device soaks, netem lab |
| DNS: UDP, TCP, DoT, DoH | `historical claim` |
| DNS fake-IP | `historical claim` |
| `.onion` / `.i2p` fail-closed routing | `historical claim` |
| Signed DNS rule-set installation | `historical claim` |
| Signed TLS fingerprint tables | `historical harness claim` |
| Atomic routing-policy reload | `historical claim` |
| LAN proxy | `historical claim` |
| ECH, ECH GREASE | `historical harness claim` |
| ECH from HTTPS resource records | `not-implemented` |
| Share vault and onion publication | `untested-datapath` — shipped for ABI v1 compatibility, with no Guard product call site |


## Status rules

- `VERIFIED`: real authenticated/tunneled traffic against an independently operated peer on the
  exact recorded binary/device combination, with the required identifiers and evidence.
- `HARNESS_PASS`: an explicitly identified harness/transcript result, without independent-peer claims.
- `NOT_VERIFIED` / `PENDING`: the current artifact combination has no completed qualifying run.
- `NOT_IMPLEMENTED`: absent functionality, distinct from missing evidence.

No status is a security audit or a guarantee of unobservability. Unsupported modes remain unsupported;
a successful carrier or protocol variant does not qualify other variants.
