<h1 align="center">🦀 FoxHole Core</h1>

<div align="center">

**FoxHole Core** is the Rust networking core of the FoxHole ecosystem.
It processes TCP/UDP flows, applies routing and DNS policy, and connects the
selected outbound. FoxHole Guard and FoxHole VPN use its C/JNI interface on
Android; the OpenWrt client uses the Linux CLI. Available features depend on
the build and integration.

</div>

<p align="center">
    <img
      src="media/fhg.gif"
      alt="FoxHole Core"
      width="180"
      height="180"
    >
</p>

<p align="center">
  <a href="README.md">
    <img src="https://img.shields.io/badge/🇬🇧-English-ff7a00?style=flat-square">
  </a>
  <a href="./docs/README.ru.md">
    <img src="https://img.shields.io/badge/🇷🇺-Русский-ff7a00?style=flat-square">
  </a>
</p>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-core/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-core?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

![Rust](https://img.shields.io/badge/core-Rust-000000?logo=rust&logoColor=white&style=flat-square)
![Android](https://img.shields.io/badge/platform-Android-3DDC84?logo=android&logoColor=white&style=flat-square)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-007ec6?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.html)
![❤️ We support I2P](https://img.shields.io/badge/❤️_We_support-I2P-7B1FA2?style=flat-square)

| Build variant | Contents |
| --- | --- |
| Android JNI | Default `shipped` profile, including Tor, the I2P adapter and experimental onion-service publishing |
| Linux CLI | Hysteria2 by default; other VPN protocols are selected at build time. Tor and I2P are not included in the CLI |
| Specific client | Exposes only its available features; a Core capability does not imply a corresponding app UI feature |

<p align="center"><a href="#quickstart">Get started</a> · <a href="#features">Features</a> · <a href="#details">Details</a> · <a href="#whats-new">What's new</a> · <a href="ROADMAP.md">Roadmap</a> · <a href="docs/verification/1.0.2/README.md">Verification</a></p>

<a id="whats-new"></a>

## 🆕 What's new - 1.0.3

- Fixed DNS routing in application scenarios.

<a id="features"></a>

## ⚙️ Core capabilities

| Layer | Implementation |
| --- | --- |
| **TUN** | exact-pinned smoltcp TCP actor, Fox-owned UDP demux and ICMPv4 echo, bounded flow/packet memory |
| **Routing** | compiled indexes, O(1) package policy, Direct/VPN/Tor/Block, I2P gate |
| **DNS** | UDP/TCP, DoT, DoH over HTTP/2, DoQ, DoH over HTTP/3, cache, stale cache, fake-IP |
| **Android protected dialer** | Android callback `protect(fd)` → bind to the selected Android `Network` → connect/send |
| **TLS** | rustls/WebPKI, SNI, ALPN, SPKI SHA-256 pin, ECH and ECH GREASE |
| **Firewall** | Block priority, kill switch, quarantine, TTL rules |
| **Traffic map** | live flows, per-app/per-lane accounting, route/outbound state |
| **Core events** | bounded native event stream with an explicit `dropped` counter |
| **Web Apps / leases (ABI only)** | identity, lease and notification primitives retained in JNI for v0.0.1 compatibility; FoxHole Guard has no product caller |
| **File sharing (ABI only)** | XChaCha20-Poly1305 vault and onion-publication primitives retained in JNI; FoxHole Guard has no user flow |
| **Proxy server** | SOCKS5 / HTTP CONNECT, mandatory authentication, network binding, JNI entry points |
| **Android / Native ABI** | versioned C/JNI ABI, capabilities JSON, safe handles |

Flow tables are bounded by default to 1024 TCP and 512 UDP entries. A flow exceeding the limit is rejected and accounted for. TCP admission also shares a 64 MiB buffer budget, and a handshake that never establishes releases its reservation after 30 seconds. Each UDP flow retains at most 32 packets while its outbound is busy; UDP and raw responses use bounded 256-packet queues back to the TUN, and UDP overflow is dropped and counted.

---

## Subscription and profile import

| Input | Supported content |
| --- | --- |
| URI subscription | Plaintext links, one per line, or a Base64-encoded body |
| Clash / Mihomo YAML | Compatible nodes in `proxies`; unsupported nodes and client settings are reported |
| SIP008 JSON | Version 1 Shadowsocks server lists |
| Outline JSON | One Shadowsocks access-key object; `ss://` links also work |

Supported URI schemes are `vless`, `vmess`, `hysteria2` / `hy2`,
`trojan`, `ss`, `wg` / `wireguard`, `socks` / `socks5`,
`http` / `https`, `naive+https`, and `anytls`.
Connection availability depends on the protocol modules compiled into the build.
`socks4://` and `naive://` links are rejected.
The CLI also imports canonical Core JSON and WireGuard `[Interface]` configuration;
its `import` command requires exactly one profile. Arbitrary Xray or sing-box JSON
is not a supported subscription format.

Core parses subscription bodies without downloading them. Clients own download,
redirect and TLS policy, including fetching dynamic Outline `ssconf://` sources.
FoxHole Android apps additionally unwrap v2rayTun import links before calling Core.
Partial import returns rejected entries explicitly; strict import rejects an
unsupported entry. See the [subscription parser](crates/foxcore-link/src/lib.rs),
[structured formats](crates/foxcore-link/src/structured.rs), and
[CLI import](crates/foxcore-cli/src/import.rs).

## 🔌 Supported protocols

| Protocol | Support | Maturity |
| --- | --- | --- |
| **VLESS** | raw, WebSocket, HTTP Upgrade, gRPC/H2, XHTTP stream-one over H2, TLS, ECH; Reality under stream transports, Vision over raw TCP | `beta` |
| **VMess** | AEAD (`alterId=0`), TCP/UDP, raw, WebSocket, HTTP Upgrade, gRPC/H2, XHTTP stream-one over H2, TLS, ECH | `beta` |
| **Hysteria2** | QUIC/H3, Brutal, Salamander obfs, TCP/UDP, destination port hopping | `beta` |
| **WireGuard** | implementation of the Noise_IKpsk2 handshake, L3 tunnel, `reserved`, `wg://`, `.conf` | `beta` |
| **AmneziaWG** | AWG parameters and 2.0 init-packet templates | `experimental` |
| **Trojan** | TLS TCP/UDP, WebSocket, HTTP Upgrade, gRPC/H2, XHTTP stream-one over H2, ECH | `beta` |
| **Shadowsocks** | AEAD + AEAD-2022, TCP/UDP | `beta` |
| **Outline** | Shadowsocks variant, static prefix for AEAD over TCP | `beta` |
| **Naive** | native HTTP/2 CONNECT with protocol padding, TCP only | `beta` |
| **TUIC** | native v5, QUIC, TCP/UDP, fragmentation | `experimental` |
| **AnyTLS** | native v2, multiplexing, padding, TCP/UoT | `experimental` |
| **ShadowTLS** | strict v3 / TLS 1.3, Shadowsocks inner only | `experimental` |
| **SOCKS5** | CONNECT, UDP ASSOCIATE, authentication | `beta` |
| **HTTP** | CONNECT proxy | `beta` |
| **Tor** | Arti, TCP, `.onion`, bridges, pluggable transports | `beta` |
| Tor onion **service** (publishing) | Compiled experimental API; no ready-to-use Guard publishing flow or independent publication qualification claimed | `experimental` |
| **I2P** | TCP-only SOCKS5 adapter to external `i2pd` | `experimental` |
| **Selector** | named outbound group, connect failover, urltest | `beta` |

`Selector` is a utility group of up to 64 outbounds, supporting member selection, connection failover and `urltest`. Its use depends on the client configuration; Core also accepts an individual outbound without Selector.

### Transport composition constraints

The protocol list above is not a freely composable transport matrix:

- **Reality** is a security layer, not a carrier, and is mutually exclusive with normal TLS. A stream transport may sit above it: WebSocket, HTTP Upgrade, gRPC and H2 are all accepted, gRPC being the common shape in the wild. **Vision** is the exception - it requires raw TCP.
- **Vision**, in this implementation, requires TLS 1.3 on the outer layer and `packet_encoding = xudp`, and rejects UDP on port 443.
- **XHTTP** implements only stream-one over HTTP/2. Other modes and unsupported settings are refused.
- **Outline** `prefix=` applies to AEAD ciphers over TCP; it is not carried over to AEAD-2022 or UDP.
- **Hysteria2 port hopping** rotates the destination port from the configured set while retaining one protected local UDP socket. The reference client also rotates the source port, so this implementation is deliberately narrower.
- **ShadowTLS v3** carries Shadowsocks only; no share-link form is supported.

- **ECH** requires an explicit `ECHConfigList`; automatic retrieval from DNS HTTPS records is not implemented. ECH GREASE does not hide SNI. ECH is unavailable for Hysteria2, TUIC and ShadowTLS and cannot be combined with `tls.fingerprint`.

### TLS and limitations

**TLS fingerprints:** REALITY forms ClientHello using ten browser profiles: seven transcribed from uTLS, two from first-party captures and one source-derived Chromium156 configuration without supplied Trust Anchor IDs. Provenance and measurements are in `fingerprints/`. Matching ClientHello parameters does not imply matching the browser’s complete network behavior.

REALITY keeps its compiled Fox-owned ClientHello generator. Generic TCP TLS
separately supports explicit `chrome_156` and historical `chrome_151` profiles through the pinned rustls
fork; incompatible TLS settings are refused. These two mechanisms are described
in [TLS fingerprinting](docs/architecture/02-cryptography.md#25-tls-fingerprinting--two-disjoint-mechanisms).

### Shadowsocks / Outline

Supported:

- AEAD;
- AEAD-2022;
- Outline `prefix=` for AEAD over TCP;
- native SIP003 transport `v2ray-plugin` (WebSocket);
- native `simple-obfs` in `http` / `tls` modes.

Both plugins are implemented natively. No plugin subprocess is started, and any unsupported SIP003 plugin is rejected. Outline is treated as a Shadowsocks configuration variant.

### WireGuard / AmneziaWG

WireGuard is an L3 tunnel with an implementation of the Noise_IKpsk2 handshake. Key lifetime follows the protocol:

- the session key rotates well before expiry;
- after `REJECT_AFTER_TIME` (180 s), the key no longer encrypts traffic and the previous key stops decrypting, so late datagrams encrypted with a retired key are dropped;
- `reserved` bytes are preserved, allowing providers that depend on them to work.

Endpoint roaming is not implemented; there is no server role.

AmneziaWG adds junk/header parameters (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`), checked header ranges and 2.0 init-packet tag templates `I1`–`I5`. Optional `RandomTrailers`, content-padding ranges and `HeaderProtectionKey` have explicit validation and bounded allocation. Endpoint roaming, server mode and container-link imports remain unsupported; AmneziaWG remains experimental.

### Intentionally unsupported

- **ShadowsocksR (SSR)** - deprecated and unsupported.
- **ShadowTLS v1** - FoxHole Core implements strict ShadowTLS v3 only.

---

## 🛣️ Traffic routing

Supported route actions:

```text
Direct
VPN
Named Outbound
Tor
I2P
Block
```

Policy supplied by the application may use:

- package/application identity;
- domain and domain suffix;
- CIDR;
- DNS policy;
- TTL rules;
- the global kill switch.

Route/DNS/application policy is updated atomically without restarting TUN: each
new flow sees either the complete old policy or the complete new policy, never a
mixture. A rejected reload changes nothing. An ordinary reload does not
immediately recompute the route of an open active flow; existing-flow behavior
depends on the data plane and the published runtime capabilities.

Up to 16 named outbounds and up to 64 selector members are supported. Changing protocol configuration or adding/removing outbounds requires a new runtime generation.

### Fail-closed

FoxHole Core does not redirect protected traffic to `Direct` when the required route is unavailable:

```text
App → VPN
       ↓
   VPN failure
       ↓
     Block
```

Applications explicitly assigned to `Direct` continue to use a separate protected dialer.

---

## 🌐 DNS

DNS supports UDP/TCP, DoT, DoH over HTTP/2, DoQ and DoH over HTTP/3, caching, policy-controlled stale cache, fake-IP, and route-aware DNS. DoQ and DoH over HTTP/3 require a route with UDP support.

`.onion` and `.i2p` are handled fail-closed and never leak to clearnet DNS.

DNS bootstrap on Android uses the selected physical Android `Network`.

Packet tunnels, including WireGuard, cannot use fake-IP for ordinary clearnet L3 traffic. Incompatible configurations are rejected rather than silently degraded.

---

## 🧅 Tor access

Tor is implemented through **Arti** and included in the standard Android build.

Supported:

- TCP;
- `.onion`;
- bridges, both direct and through managed pluggable transports;
- user isolation;
- timeouts;
- network connections through the Android protected dialer;



Onion-service publishing is a separate experimental core capability.
It is compiled into the standard Android build; this does not imply
a ready-to-use publishing flow in the Guard interface. See [interop.md](docs/interop.md) for qualification status.
---

## 🕸️ I2P access

FoxHole Core does not embed or manage an I2P router:

```text
FoxHole Core
   ↓
127.0.0.1 SOCKS5
   ↓
 i2pd
   ↓
 I2P
```

Requirements:

- loopback endpoint;
- TCP only;
- `.i2p` through fake-IP;
- `I2P` route action;
- RFC 1929 authentication when credentials are configured.

---

## 🧱 Firewall

Firewall policy is part of the routing engine.

Supported:

- per-app blocking;
- Block priority;
- quarantine;
- kill switch;
- TTL rules;
- protocol-specific termination of live flows by the global kill switch, network change, or an explicit targeted revocation call;
- typed reload refusals.

---

<a id="quickstart"></a>

## 🧪 Build and checks

The toolchain is pinned in `rust-toolchain.toml`.

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Check the `foxcore-android` crate with all Cargo features on the current host platform:

```bash
cargo check --locked -p foxcore-android --all-features
```

Android libraries are built through `scripts/android-build.sh` with pinned NDK and cargo-ndk. By default it builds four ABIs and runs ELF checks. Offline builds require dependencies to be available locally. Device checks and protocol interoperability are documented separately in [interop.md](docs/interop.md).

---

<a id="details"></a>

## 🧭 Architecture and execution model

**Android traffic path**

```text
FoxHole Guard / Android
        ↓
VpnService + TUN + policy
        ↓
      C/JNI ABI
        ↓
    FoxHole Core
        ↓
TUN → flow engine → routing policy → outbound
                              ├─ VPN / Named Outbound
                              ├─ Tor / Arti
                              ├─ I2P → loopback SOCKS5 → i2pd
                              ├─ Direct → protected socket
                              └─ Block
```

### Mapping to the FoxHole Guard model

At the application level, the user operates with the chain **mode → scenario → routing rules**. These concepts belong to FoxHole Guard. Before applying them, the application compiles them into runtime configuration and route/DNS/application policy executed by FoxHole Core.

FoxHole Core does not choose the user mode on its own. Its responsibility is to deterministically apply the already compiled policy to each new flow and fail closed when the required protected route is unavailable.

### Core principles

- fixed `enum Outbound`;
- one Android protected dialer;
- native TCP/UDP flow engine;
- compiled routing policy;
- atomic policy reload;
- fail-closed routing;
- on Android, every outbound socket passes `protect(fd)` and binds to the selected physical `Network` before connect/send;
- no silent downgrade when a protected route fails.

Per-app/application policy is compiled inside `foxcore-route` and updated through the native API without recreating the TUN interface.

I2P is a separate runtime boundary: FoxHole Core connects to an already running `i2pd` instance through a local SOCKS5 adapter and does not manage the I2P process itself.

---

## 📡 Core events and audit

The core publishes a bounded event stream read by the application; the core does not push event callbacks into Java. The buffer holds 512 events; events that do not fit are reported through an explicit `dropped` counter for the affected window.

Event types:

```text
blocked
dns_blocked
config_applied
confirmation_required
confirmation_expired
outbound_unavailable
outbound_restored
```

The shipped ABI also exposes traffic-map open/close events with its own `dropped` counter.
Component/share event streams remain exported for v0.0.1 ABI compatibility, but the current Guard
does not subscribe to them.

The Core networking library does not maintain a persistent security journal or run FoxHole Sentinel; the Android app manages these functions. This repository also contains a separate [native YARA scanner](native/sentinel-yara/README.md) for the isolated Sentinel process, built separately from the networking core.

---

## 🧩 Extensions and system components

The component, lease and vault model below is implemented in the core. Its 19 Android JNI exports
remain in release libraries because v0.0.1 shipped them; the current Guard has no product call
sites. The Engine surface separately includes LAN proxy and loopback-inbound operations.

At the FoxHole Core level, every component has a bounded ASCII identifier. A Web
App also has a separately validated canonical HTTPS origin, which is its origin
identity for authorization and notifications. Userinfo, any path other than `/`,
query, and fragment are rejected during registration, so alternate spellings of
one origin cannot create distinct identities.

Operations are authorized through leases. A lease is not a permanent grant: it may outlive the runtime that issued it, so every operation re-checks availability.

| Lease purpose | Route it resolves to |
| --- | --- |
| Web navigation | Web App's own route |
| Web notification | Web App's own route |
| File sharing | always Tor; no clearnet fallback |
| Proxy server | no component lease route; its preset selects VPN/Tor upstreams |

The shipped core contains the vault implementation, onion-service support and the compatibility
JNI exports, so `share.compiled` reports code presence. FoxHole Guard has no product call site for
this surface.

---

### Proxy server for local network

The Proxy server for local network is owned by one runtime generation. It is not assigned a component
lease route: the selected preset independently maps its SOCKS5 and HTTP CONNECT
listeners to VPN or Tor upstreams.

- **SOCKS5** and **HTTP CONNECT**.
- **Authentication is mandatory and cannot be disabled.** A SOCKS5 client
  offering only “no authentication” is rejected; HTTP without
  `Proxy-Authorization` receives `407`. Credentials are valid only within one
  runtime generation.
- **Binding is restricted.** Only Wi-Fi and Ethernet are accepted. Cellular, wildcard, unspecified and multicast addresses are rejected. Exactly one address is bound.
- **The user confirms the network separately for every runtime generation.** The
  confirmation is held in memory only. A network change closes listeners and
  invalidates credentials instead of rebinding automatically.

Presets:

```text
vpn     SOCKS5 → VPN,  HTTP → VPN
tor     SOCKS5 → Tor,  HTTP → Tor
mixed   SOCKS5 → VPN,  HTTP → Tor
```

There is no `direct` preset.

Loopback inputs are named, carry their own credentials and are included in the runtime snapshot. Their structure is defined in `crates/foxcore-android/capabilities.schema.json` and described in [`docs/abi.md`](docs/abi.md).

The component is exposed to Android through `nativeConfirmLanNetwork`, `nativeStartLanProxy`, `nativeStopLanProxy` and `nativeLanProxyStatus`.

---

## 🤖 Android / Native ABI

FoxHole Core exposes a versioned C/JNI ABI.

The Android application queries runtime capabilities.

Guard uses the versioned `FoxholeNativeEngine` JNI interface. The legacy start without an Android `Network` remains in Core for compatibility but is not declared by the current app. See [abi.md](docs/abi.md) for the contract and export checks.
Signed DNS starts and
`nativeTrafficMap` are used in production. Link-import and continuity declarations are retained as
compatibility-only ABI, with no Kotlin product wrapper. Signed DNS downloads are persisted first,
then installed live into a stable engine; enabling filtering or changing trust uses an atomic
replacement start, and an inactive engine consumes the bundle at its next start.

Release ELF files also retain the 19 v0.0.1 component/share exports. They are compatibility ABI,
not released Guard functionality.

Capabilities include:

- compiled protocols;
- TCP/UDP support;
- transports;
- optional features;
- unsupported extensions.

Release 1.0.1 uses the `android4` delivery profile:

```text
arm64-v8a
armeabi-v7a
x86
x86_64
```

`config/foxcore-android-delivery.json` and the LAB release scope require current JNI
artifacts, capabilities origins and ELF checks for all four ABIs. Compilation and
packaging checks remain separate from runtime acceptance on each device class.

Native build gates:

- pinned Rust toolchain;
- pinned Android NDK;
- RELRO/NOW;
- non-executable stack;
- 16 KiB page alignment;
- `libandroid.so`;
- frozen ABI-v1 C/JNI exports and capabilities/config compatibility; the ELF export set is checked for every built ABI.

---

## 🔏 Release integrity

Native builds and full release checks run in the private LAB or on the authorized build host
with pinned Rust, NDK and lockfile inputs. The GitHub publisher verifies the owner-signed source
and immutable LAB handoff, checks the selected archive and required evidence, then publishes
those exact bytes without rebuilding. The handoff binds the delivery source and compiled
producer separately; documentation-only changes do not change a native producer identity.

Each `foxhole-core-v<version>.tar.gz` release archive contains the four gated JNI libraries,
the Linux x86_64 DNS compiler, their producer records, the rollback manifest,
the committed CycloneDX SBOMs and `Cargo.lock`. The release also contains
`SHA256SUMS` and keyless Sigstore provenance bound to this repository, workflow
and release commit:

```bash
sha256sum -c SHA256SUMS
gh attestation verify foxhole-core-v<version>.tar.gz \
  --repo foxhole-team/foxhole-core
```

---

## 🗂️ Workspace structure

```text
crates/
├── foxcore-api
├── foxcore-runtime
├── foxcore-android
├── foxcore-cli
├── foxcore-tun
├── foxcore-route
├── foxcore-dns
├── foxcore-dialer
├── foxcore-transport
├── foxcore-relay
├── foxcore-outbound
├── foxcore-trafficmap
├── foxcore-link
├── foxcore-component
├── foxcore-share
│
├── proto-vless
├── proto-reality
├── proto-vmess
├── proto-hysteria2
├── proto-tuic
├── proto-trojan
├── proto-shadowsocks
├── proto-anytls
├── proto-shadowtls
├── proto-tor
├── proto-i2p
├── proto-socks
├── proto-http
├── proto-naive
├── proto-wireguard
│
└── foxcore-testkit
```

`native/sentinel-yara` is a separate native Sentinel scanner workspace, outside the main Cargo workspace.

---

## 📚 Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture/README.md) | cross-repository architecture, trust boundaries and release data flow |
| [SECURITY.md](SECURITY.md) | vulnerability reporting and security scope |
| [threat-model.md](docs/threat-model.md) | threat model and security boundaries |
| [abi.md](docs/abi.md) | FFI contract: handles, threads, panic boundaries, error codes and limits |
| [interop.md](docs/interop.md) | artifact-bound interoperability status and pending evidence |
| [fingerprints/](fingerprints/) | provenance of REALITY ClientHello fingerprints |

FoxHole VPN is a separate consumer of the same Core ABI. Its connection-data updater checks
the signed FoxHole DB REALITY table feed against the pinned compiled baseline and applies
changed tables only after a user action. It downloads data for known profiles, not native code
or other Guard feeds. Native acceptance affects future handshakes in that application's process
without reconnecting the tunnel; see [VPN client architecture](docs/architecture/06-vpn-client.md).

[FoxHole OpenWrt Client](https://github.com/foxhole-team/foxhole-openwrt-client) uses Core in its router client modules and is available as a public beta. Current packages and platform limitations are listed in the [OpenWrt Client releases](https://github.com/foxhole-team/foxhole-openwrt-client/releases).

---

<a id="ecosystem"></a>

## 🔗 FoxHole ecosystem

| Project | Role |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android: VPN, Tor/I2P, traffic rules and local monitoring |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android: simple VPN client and paired OpenWrt management |
| [**FoxHole Core**](https://github.com/foxhole-team/foxhole-core) | Shared Rust networking core; features depend on the build |
| [FoxHole OpenWrt](https://github.com/foxhole-team/foxhole-openwrt-client) | Router VPN and local-network management |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Signed rules and reference datasets |

## 🤝 Contributing

Report bugs and propose changes through [Issues](https://github.com/foxhole-team/foxhole-core/issues).

## ❤️ Support

**XMR (Monero):**

```text
48yBVPTdcyJ1WoJtnKmVpEZziEsDy4HvbCW7eQDS9mfdiWPFXwZ8F5h9YZ2UTTBLxPcJgQgvth7iqLZM2yMCaQ432qaouqr
```

**BTC (Bitcoin):**

```text
bc1qatnyy7jcpqrp0d3dk9rta9vqfejgh4mysd6m2f
```

**ETH (Ethereum):**

```text
0xDEBA357Cc8f5E865ea7FFa98E138C8241A16A465
```

---

## ⚠️ Disclaimer

- Tor is a trademark of The Tor Project. FoxHole Core is not a product of The Tor Project and is not endorsed, sponsored by, or affiliated with The Tor Project.
- FoxHole Core is not an official product of I2P or PurpleI2P.

---

## 📄 License

FoxHole Core is distributed under:

**GNU General Public License v3.0 or later (`GPL-3.0-or-later`)**

Copyright (C) 2026 FOXHOLE TEAM.

Third-party dependency licenses are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and in the SBOM:

```text
sbom/*.cdx.json
```
