# Interoperability

Protocol support and interoperability are separate claims.

The FoxHole Core README describes what the current build implements. This document records what has
actually been made to carry traffic, and against whom.

> **Pending, as of 2026-08-17:** the acceptance matrix is being re-run on the release artifact.
> Until that run is recorded, `verified` below means the datapath has carried real traffic against
> an independently-operated peer on a physical Android device, on a build earlier than the one now
> being prepared. This note is removed when the release run lands, not before.

---

## Status model

Three statuses, and the difference between them is *who was on the other end* — not how many tests
exist. A protocol with two hundred unit tests and no peer has never been shown to interoperate with
anything.

| Status | Meaning |
| --- | --- |
| `verified` | Carried real traffic against an **independently-operated** implementation, both directions, on a physical Android device. |
| `harness-verified` | Completed against an in-repo harness or against recorded transcripts from the reference implementation. No independent peer. |
| `untested-datapath` | Unit, codec or known-answer tests only. The datapath has never run against anything. |
| `not-implemented` | Not available in this build. |

`untested-datapath` is not a synonym for broken. It means nobody has evidence either way, which is
the only honest thing to write.

---

## Protocol matrix

| Feature | TCP | UDP | IPv6 | Status |
| --- | --- | --- | --- | --- |
| **VLESS** (raw/WS/HTTPUpgrade/gRPC/H2, TLS) | yes | yes | yes | `verified` |
| VLESS / REALITY | yes | n/a | yes | `verified` |
| VLESS / Vision | yes | via XUDP | yes | `verified` |
| VLESS / XUDP, packetaddr | n/a | yes | yes | `verified` |
| VLESS encryption (`mlkem768x25519plus`) | yes | n/a | yes | `harness-verified` — 12 transcripts from the reference Go client/server |
| **VMess** (AEAD) | yes | yes | yes | `verified` |
| **Trojan** | yes | yes | yes | `verified` |
| **Shadowsocks** AEAD | yes | yes | yes | `verified` |
| Shadowsocks AEAD-2022 | yes | yes | yes | `verified` |
| Shadowsocks Outline prefix | yes | n/a | yes | `verified` |
| Shadowsocks `simple-obfs` | yes | n/a | yes | `verified` (`http` mode only; `tls` mode never run) |
| **Naive** (H2 CONNECT + padding) | yes | no | yes | `verified` |
| **Hysteria2** (Brutal, Salamander, port hopping) | yes | yes | yes | `verified` |
| **WireGuard** (L3, Noise_IKpsk2) | L3 | yes | yes | `verified` |
| **AmneziaWG** | L3 | yes | yes | `untested-datapath` — golden vectors for the 2.0 `I1`–`I5` templates; not one probe against a peer, ever |
| **TUIC v5** | yes | yes | yes | `untested-datapath` |
| **AnyTLS v2** | yes | yes | yes | `untested-datapath` |
| **ShadowTLS v3** | yes | yes | yes | `untested-datapath` |
| **SOCKS5** | yes | yes | yes | `verified` (host-side; UDP ASSOCIATE untested — no server offered it) |
| **HTTP CONNECT** | yes | no | yes | `verified` (host-side) |
| **Tor / Arti** | yes | no | yes | `verified` — live `.onion`, fail-closed gate open→closed→open on one tunnel |
| Tor pluggable transports | yes | no | yes | `untested-datapath` — config and loopback bridge built, no run recorded |
| Tor onion service (publishing) | yes | no | yes | `untested-datapath` — compiled for ABI v1, but Guard has no product call site and no publication run is recorded |
| **I2P** (external i2pd over loopback SOCKS5) | yes | no | n/a | `verified` — live i2pd, fail-closed gate, three-runtime independence |
| **Selector / urltest** | yes | yes | yes | `harness-verified` |

---

## Non-protocol features

| Feature | Status |
| --- | --- |
| TUN flow engine | `verified` — two 30-minute device soaks, netem lab |
| DNS: UDP, TCP, DoT, DoH | `verified` |
| DNS fake-IP | `verified` |
| `.onion` / `.i2p` fail-closed routing | `verified` |
| Signed DNS rule-set installation | `verified` |
| Signed TLS fingerprint tables | `harness-verified` |
| Atomic routing-policy reload | `verified` |
| LAN proxy | `verified` |
| ECH, ECH GREASE | `harness-verified` |
| ECH from HTTPS resource records | `not-implemented` |
| Share vault and onion publication | `untested-datapath` — shipped for ABI v1 compatibility, with no Guard product call site |

---

## What `verified` deliberately does not claim

1. **Not a security audit.** No part of this codebase has had an external security review. The
   closest comparable product, Tor VPN Beta, is Cure53-audited and still tells its users not to rely
   on it for anything sensitive.
2. **Not unobservability.** REALITY sends a browser-faithful ClientHello; the generic TLS path does
   not, and QUIC carries its own distinguishers. Separately, a censor can fingerprint the *fact* of a
   TLS handshake nested inside a TLS tunnel — a protocol-agnostic attack that padding and
   multiplexing cannot close, and which applies to every proxy of this shape, not just this one. See
   the README's TLS section.
3. **Not every transport of a protocol.** Where a mode was never run — `simple-obfs` over `tls`,
   SOCKS5 UDP ASSOCIATE, Tor pluggable transports — the row says so instead of inheriting the
   protocol's status.

Internal unit, property, loopback and known-answer tests establish implementation correctness. They
are not interoperability evidence, and no number of them promotes a row out of `untested-datapath`.

---

## Interpretation

The capabilities document is the authoritative source for which features are compiled and at what
maturity. This document records only what has been observed on the wire, and against whom.
