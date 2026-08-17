# 1. Protocols

Every outbound FoxCore implements, what carries it, what protects it, where it ends.

---

## 1.1 The stack

```mermaid
flowchart TD
    TUN["Android TUN fd"] --> FE["flow engine<br/>foxcore-tun"]
    FE --> RT["route decision<br/>foxcore-route"]
    RT -->|Block| BLK["dropped and counted"]
    RT -->|Direct| DIR["protected socket"]
    RT -->|VPN / Named| OB["Outbound enum<br/>foxcore-outbound"]
    RT -->|Tor| TOR["in-process Arti"]
    RT -->|I2P| I2P["loopback SOCKS5 -> external i2pd"]

    OB --> L1["protocol codec<br/>proto-*"]
    L1 --> L2["security layer<br/>TLS / REALITY / Noise / QUIC-TLS"]
    L2 --> L3["stream carrier<br/>raw ws http_upgrade grpc http2"]
    L3 --> DIALER["ProtectedDialer<br/>foxcore-dialer"]
    DIR --> DIALER
    TOR --> DIALER
    I2P --> DIALER
    DIALER --> NET["network"]
```

Layer order matters: the security layer sits **below** the stream carrier, so a WebSocket rides
inside TLS, not the other way round (`crates/foxcore-transport/src/lib.rs:72-101`).

---

## 1.2 Config identifiers

`OutboundConfig` is internally tagged on `type`, `rename_all = "snake_case"` —
`crates/foxcore-api/src/config/outbound.rs:9-33`. Fifteen variants:

```
direct  vless  vmess  hysteria2  tuic  trojan  shadowsocks
i2p  tor  wireguard  selector  socks  http  naive
anytls      (explicit rename, outbound.rs:29-30)
shadowtls   (explicit rename, outbound.rs:31-32)
```

Stream carriers — `StreamTransportConfig`, tagged on `type`
(`crates/foxcore-api/src/config/transport.rs:11-54`):

```
raw  websocket  http_upgrade  grpc  http2
```

Bounds: ≤16 named outbounds (`engine.rs:74-78`), ≤64 selector members (`selector.rs:9`),
engine config ≤1 MiB (`engine.rs:34-39`). Ids `default`, `primary`, `direct`, `block` are reserved;
`tor` and `i2p` are id-locked in both directions (`engine.rs:86-115`).

---

## 1.3 Protocol matrix

| Protocol | Carried on | Security layer | Stream carriers | UDP | Terminated at |
|---|---|---|---|---|---|
| **VLESS** | TCP | rustls TLS **or** REALITY (exclusive); optional inner ML-KEM768+X25519 "VLESS Encryption" | all 5 | yes — `none`/`xudp`/`packetaddr` | remote VLESS server |
| **VLESS + Vision** | TCP only | TLS 1.3 required | raw only | **refused on port 443** | remote VLESS server |
| **VMess** | TCP | optional rustls TLS; no REALITY | all 5 | yes | remote VMess server |
| **Trojan** | TCP | TLS **mandatory** | all 5 | yes | remote Trojan server |
| **Shadowsocks / Outline** | TCP + native UDP | AEAD or AEAD-2022; optional `simple-obfs` http/tls, Outline salt prefix | all 5 (as native `v2ray-plugin`) | conditional | remote SS server |
| **Hysteria2** | **QUIC/UDP** (quinn) | TLS inside QUIC; optional **Salamander** packet obfs; port hopping | none | conditional on server | remote HY2 server |
| **TUIC v5** | **QUIC/UDP** (quinn) | TLS inside QUIC, TLS-exporter auth | none | conditional | remote TUIC server |
| **AnyTLS v2** | TCP | TLS mandatory; own mux + bounded padding above TLS | none by design | yes — UoT v2 | remote AnyTLS server |
| **ShadowTLS v3** | TCP | TLS 1.3 only, server proof + chained HMAC; inner protocol **hardcoded to Shadowsocks** | none | conditional — UoT v2 | ShadowTLS server → its inner SS |
| **Naive** | TCP | TLS mandatory, ALPN `h2`, HTTP/2 CONNECT + padding | none | **no** | remote naive server |
| **HTTP** | TCP | optional TLS | none | **no** | remote HTTP proxy |
| **SOCKS5** | TCP (+UDP) | **none** — no `tls` field exists | none | yes — UDP ASSOCIATE | remote/LAN/loopback proxy |
| **WireGuard / AmneziaWG** | **UDP** | Noise IKpsk2; AmneziaWG adds junk/header obfs only | n/a — L3 packet tunnel | yes (carries all IP) | remote WG peer |
| **Tor** | TCP guards | Arti's own crypto; bridges + managed pluggable transports | n/a | **no** | Tor network, in-process |
| **I2P** | TCP to `127.0.0.1` | none (plain SOCKS5, optional RFC 1929) | n/a | **no** | **external i2pd process** |
| **Selector** | — | inherits from active member | inherits | inherits | up to 64 members |
| **Direct** | TCP/UDP | none | n/a | yes | destination, protected socket |

Only VLESS, VMess, Trojan and Shadowsocks carry a `transport` field. Every other config has no such
field at all — the carriers simply do not apply (`crates/foxcore-android/src/capabilities.rs:466-684`).

REALITY and WireGuard are not standalone outbounds: REALITY is a security layer used only by VLESS;
WireGuard is only reachable as `OutboundMode::PacketTunnel`.

---

## 1.4 Tor and I2P are structurally different

```mermaid
flowchart LR
    subgraph tor["Tor — in-process"]
        A["foxcore-outbound"] --> B["arti-client 0.44.0"]
        B --> C["ProtectedTcpProvider"]
        C --> D["ProtectedDialer -> guards"]
        B -.->|optional| E["managed PT helper<br/>lyrebird / conjure-client<br/>loopback SOCKS, raw"]
        B -.->|feature onion-service| F["onion service listener<br/>ephemeral in-memory keystore"]
    end
```

```mermaid
flowchart LR
    subgraph i2p["I2P — out of process"]
        G["foxcore-outbound"] --> H["SOCKS5 to 127.0.0.1:port"]
        H --> I["i2pd, separate process"]
        I --> J["I2P network"]
    end
```

| | Tor | I2P |
|---|---|---|
| `implementation` string | `in_process_arti` (`capabilities.rs:1094`) | `external_i2pd_socks5_loopback` (`:1117`) |
| Process ownership | core owns it | **not owned** — `unsupported: ["udp","process_ownership","clearnet"]` (`:1121-1126`) |
| Listener | onion service only, gated on feature; only `BEGIN` on the configured port | **none** — `connect_datagram` returns `Unsupported` |
| Constraint re-check | — | endpoint must be loopback, destination must end `.i2p`, re-checked at construction |
| Cargo feature | **not a default feature** (`foxcore-outbound/Cargo.toml:32`) | default |

On the client side, `i2pd` ships as `libi2pd.so` in `jniLibs` (Android only executes from
`nativeLibraryDir`) and is launched by `I2pdRuntimeInstaller` / `RuntimeChildProcessLauncher`.
The Tor pluggable-transport helpers come from a Tor Expert Bundle in
`app/src/main/assets/tor/<abi>/tor/pluggable_transports/`.

---

## 1.5 DNS transports

The resolver is **not** in `foxcore-dns` (that crate is wire parsing only). The outbound DNS client
is `crates/foxcore-tun/src/dns/{proxy.rs,upstream.rs}`.

```mermaid
flowchart TD
    Q["query from TUN"] --> G1["overlay gate<br/>.onion / .i2p"]
    G1 --> G2["blocklist -> NXDOMAIN<br/>never reaches an upstream"]
    G2 --> G3["cache / stale cache"]
    G3 --> G4["fake-IP"]
    G4 --> U["upstream"]
    U --> U1["udp"]
    U --> U2["tcp"]
    U --> U3["dot — TLS, insecure + SPKI pin supported"]
    U --> U4["doh — RFC 8484 over HTTP/2"]
```

| `type` | Transport | Pool lanes | Note |
|---|---|---|---|
| `udp` | plain UDP/53 | 4 | |
| `tcp` | plain TCP/53 | 4 | |
| `dot` | DNS-over-TLS | 4 | supports `insecure` and `pinned_spki_sha256` |
| `doh` | DNS-over-HTTPS, **HTTP/2** via the `h2` crate | 1 (H2 already multiplexes) | URL must be HTTPS, no userinfo/fragment, ≤4096 bytes |

**DoQ and DNS-over-HTTP/3 are not implemented.** Published capability agrees:
`DnsCapabilities { udp, tcp, dot, doh_http2, fake_ip, private_namespaces_fail_closed: ["onion","i2p"] }`
(`capabilities.rs:1172-1178`).

`dns.route` ∈ `direct` | `primary` | `tor`. A Tor DNS route with the overlay disabled is
`PermissionDenied`, and the resolved outbound is re-checked against the overlay gates *after*
selection (`dns/proxy.rs:671-711`).

---

## 1.6 Fail-closed

The core never redirects protected traffic to `Direct` when the required route is unavailable.
Stated intent: "no silent downgrade when a protected route fails" (`foxhole-core/README.md:120`).

```mermaid
stateDiagram-v2
    [*] --> Routing
    Routing --> Blocked: kill switch set (stage 0)
    Routing --> Blocked: overlay gated off
    Routing --> Blocked: lane build failed (DeferredOutbound)
    Routing --> Blocked: continuity hold pending confirmation
    Routing --> Blocked: shared-UID decision conflict
    Routing --> Blocked: quarantined or unknown app
    Routing --> Blocked: packet-tunnel primary asked for a stream
    Routing --> Dialing: route available
    Dialing --> Blocked: protect(fd) refused by host
    Dialing --> Blocked: no Android Network handle for DNS
    Dialing --> Connected: handshake ok
    Connected --> Blocked: kill switch, network change, targeted revocation
```

### Why, path by path

| Path | Mechanism | Cite |
|---|---|---|
| **Global kill switch** | stage 0 of routing, ahead of every allowance — including explicitly allowed apps, `.onion`/`.i2p` auto-routes and locally answered ICMP echo | `config/policy.rs:63-67`; `foxcore-route/src/lib.rs:185-190`; LAN ingress `foxcore-runtime/src/lan.rs:73-76` |
| **`.onion` / `.i2p`** | refused rather than forwarded when fake-IP is off — "private overlay DNS is never forwarded to an upstream resolver". Tor/I2P routing *requires* `dns.mode='fake_ip'` or the profile is rejected at load | `foxcore-tun/src/dns/proxy.rs:248-268`, `:308-322`; `config/engine.rs:262-281` |
| **Overlay switched off** | `gated()` turns a Tor/I2P action into `Block` immediately; `.onion`/`.i2p` hosts are force-routed to the overlay lane *before* the route table and return `None` ⇒ Block if the lane is gated or absent | `foxcore-route/src/lib.rs:301-315`; `foxcore-tun/src/flow/select.rs:438-449`, `:475-486` |
| **Failed outbound build** | becomes a `DeferredOutbound` under the same id; the engine still starts and flows get `BlockReason::LaneUnavailable` — "never answered by another lane" | `foxcore-runtime/src/registry.rs:95-118`; `flow/select.rs:421-437` |
| **L3 packet-tunnel primary** | a WireGuard primary has no stream semantics, so the registry's `default` is a flagged direct socket that every consumer refuses: flow engine, DNS interceptor, LAN proxy, and two config-load rules | `foxcore-outbound/src/lib.rs:207-219`; `flow/select.rs:494-499`; `dns/proxy.rs:671-690`; `lan.rs:80-92`; `engine.rs:207-217`, `:234-245` |
| **Network moved, no protected socket** | `socket = None` is the fail-closed state — packets dropped and counted, never queued; a bounded run of receive errors closes the tunnel until a rebind | `foxcore-tun/src/relay/engine.rs:159-162`, `:294-301`, `:335-345` |
| **Continuity hold** | turning off a continuity flag holds the lane blocked and raises `ConfirmationRequired`. There is deliberately no third outcome where packets keep moving; the removed `stop_engine_leaving_network_open` value is now *rejected* under `deny_unknown_fields` | `config/policy.rs:96-119`, `:139-146`, `:188-230` |
| **Shared UID / quarantine** | an Android shared UID resolving to a mixed decision fails closed to Block; quarantined and unknown apps never reach the network | `foxcore-route/src/lib.rs:289-297`, `:206-212` |
| **Protected socket refused** | `protect(fd)` returning false is a hard `PermissionDenied`, not a fallback | `foxcore-dialer/src/lib.rs:328-348` |
| **DNS without a network handle** | protected resolution requires a non-zero Android `Network` handle; otherwise `NotConnected` | `foxcore-dialer/src/lib.rs:144-151` |
| **Loopback inbound with a dead upstream** | answers `502`; never falls through to direct | `capabilities.rs:60-63`, `:1229`; `foxcore-component/src/lan.rs:952-956` |

### Protocol-level refusals (offered ≠ accepted)

| Refusal | Why |
|---|---|
| **ECH is all-or-nothing** — no `optional` mode | on rejection rustls has verified the cert against the ECH *public name*, so "continuing" means talking to the cover domain while the profile believes it reached its proxy (`config/tls.rs:55-84`) |
| ECH refused at config time for **hysteria2, tuic, shadowtls** | QUIC reports no ECH status so acceptance cannot be enforced; ShadowTLS v3 rewrites the session id ECH seals as AAD (`config/tls.rs:98-114`; `capabilities.rs:1170`) |
| **PQ downgrade guard** | `curve_preferences` *replaces* the provider list, so omitting `X25519MLKEM768` used to silently drop it. It is now prepended unless `allow_classical_only_key_exchange` is set (`config/tls.rs:32-47`) |
| **REALITY** refuses TLS 1.2 selection, HelloRetryRequest, certificate compression, session resumption; never performs Xray's crawler fallback | `capabilities.rs:775-806`; `proto-reality/src/lib.rs:3-7` |
| **VMess** rejects legacy `alter_id`; refuses a server instruction rather than obeying it | `proto-vmess/src/lib.rs:33-40`; `src/stream.rs:236-243` |
| **TUIC** `zero_rtt_handshake` is representable but rejected at validation | `config/outbound.rs:386-392` |
| **Naive** padding is required; a server that does not negotiate it is refused | `proto-naive/src/lib.rs:3-8` |
| **Selector** probe URL must be plain `http://`; only stream proxies may join, so failover cannot change privacy class | `config/selector.rs:90-96`, `:26-31` |
| **Tor upstream** (Tor-over-VPN) must be a stream proxy — direct, I2P, nested Tor, WireGuard and selector refused | `foxcore-outbound/src/lib.rs:970-980` |
| **`http_upgrade`** fails closed unless the server answers `101`; never downgrades to a plain stream | `foxcore-transport/src/httpupgrade.rs:23-26` |
| **WebSocket** text frames and oversized messages fail closed (64 KiB duplex, 2 MiB max message) | `foxcore-transport/src/websocket.rs:24-28` |

A permanent "this protocol has no UDP" refusal is counted as `udp_unsupported` + `block_flow`,
**not** as a dial error, so a working fail-closed core does not read as a network fault
(`flow/select.rs:258-283`).

---

## 1.7 Not implemented

| Absent | Evidence |
|---|---|
| **mkcp / kcp** as a transport | zero implementation; `"kcp" \| "mkcp" => ProfileTransport::Kcp` at `foxcore-link/src/lib.rs:942` is a diagnostic label only, and the importer refuses transports it cannot build (`:1490-1493`) |
| **xhttp / splithttp** | zero occurrences anywhere in the repo |
| **DoQ, DNS-over-HTTP/3** | zero occurrences in `foxcore-tun/src/dns/` or `config/dns.rs` |
| **SOCKS-over-TLS** | `SocksConfig` has no `tls` field (`config/outbound.rs:58-73`) |
| **ShadowsocksR, ShadowTLS v1/v2** | declared unsupported (`capabilities.rs:962-972`) |
| **Generic ShadowTLS inner protocol** | `ShadowTlsInnerConfig` has exactly one variant; the general `StreamDialer` detour seam does not exist yet (`config/outbound.rs:148-165`) |
| **SIP003 subprocess plugins** | only `v2ray-plugin` and `simple-obfs` are native; the family is refused, never substituted (`capabilities.rs:906-919`) |
| **WireGuard endpoint roaming, server role** | `unsupported: ["endpoint_roaming","server_role"]` |

Maturity ceiling in this build is `beta`; nothing claims `stable`, and
`live_interop_verified_this_build: false` (`capabilities.rs:1240-1252`). TUIC, AnyTLS, ShadowTLS and
AmneziaWG are `experimental`.
