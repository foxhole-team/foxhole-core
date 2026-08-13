# Interoperability

Protocol support and interoperability are separate claims.

The FoxHole Core README describes what the current build implements. This document defines when a protocol or feature may be described as independently interoperable.

> A feature is considered release-verified only when the build being shipped has carried real traffic against an independent implementation. Verification from an older build is not inherited.

---

## Status model

| Status | Meaning |
| --- | --- |
| `release-verified` | Verified against an independent implementation on the current release build. |
| `not-release-verified` | Implemented, but the current release build has no independent interoperability evidence. |
| `not-implemented` | Not available in the current build. |

The current build does not claim `release-verified` status for any protocol.

---

## Protocol matrix

| Feature | TCP | UDP | IPv6 | Current status |
| --- | --- | --- | --- | --- |
| **VLESS** | yes | yes | yes | `not-release-verified` |
| VLESS / Reality | yes | n/a | yes | `not-release-verified` |
| VLESS / Vision | yes | via XUDP | yes | `not-release-verified` |
| VLESS / XUDP, packetaddr | n/a | yes | yes | `not-release-verified` |
| **VMess** | yes | yes | yes | `not-release-verified` |
| **Hysteria2** | yes | yes | yes | `not-release-verified` |
| Hysteria2 / port hopping | yes | yes | yes | `not-release-verified` |
| **Trojan** | yes | yes | yes | `not-release-verified` |
| **Shadowsocks AEAD** | yes | yes | yes | `not-release-verified` |
| Shadowsocks AEAD-2022 | yes | yes | yes | `not-release-verified` |
| Shadowsocks / SIP003 | yes | n/a | yes | `not-release-verified` |
| Outline prefix | yes | n/a | yes | `not-release-verified` |
| **Naive** | yes | no | yes | `not-release-verified` |
| **WireGuard** | L3 | yes | yes | `not-release-verified` |
| **AmneziaWG** | L3 | yes | yes | `not-release-verified` |
| **TUIC v5** | yes | yes | yes | `not-release-verified` |
| **AnyTLS v2** | yes | yes | yes | `not-release-verified` |
| **ShadowTLS v3** | yes | yes | yes | `not-release-verified` |
| **SOCKS5** | yes | yes | yes | `not-release-verified` |
| **HTTP CONNECT** | yes | no | yes | `not-release-verified` |
| **Tor / Arti** | yes | no | yes | `not-release-verified` |
| Tor pluggable transports | yes | no | yes | `not-release-verified` |
| Tor onion service | yes | no | yes | `not-release-verified` |
| **I2P** | yes | no | n/a | `not-release-verified` |
| **Selector / urltest** | yes | yes | yes | `not-release-verified` |

---

## Non-protocol features

| Feature | Current status |
| --- | --- |
| ECH | `not-release-verified` |
| ECH GREASE | `not-release-verified` |
| ECH from HTTPS resource records | `not-implemented` |
| DNS: UDP, TCP, DoT, DoH | `not-release-verified` |
| DNS fake-IP | `not-release-verified` |
| `.onion` / `.i2p` fail-closed routing | `not-release-verified` |
| Signed DNS rule-set installation | `not-release-verified` |
| Atomic routing-policy reload | `not-release-verified` |
| LAN proxy | `not-release-verified` |
| Share vault and onion publication | `not-release-verified` |

---

## Verification requirements

A feature may be promoted to `release-verified` only when all applicable conditions are met:

1. the exact release build is used;
2. traffic is exchanged with an implementation maintained independently from FoxHole Core;
3. both traffic directions are exercised;
4. TCP and UDP are validated separately when both are claimed;
5. Android-shipped functionality is exercised on a physical Android device;
6. the result is recorded as release evidence together with the peer implementation and relevant configuration.

Internal unit, property, loopback and known-answer tests establish implementation correctness but are not treated as independent interoperability evidence.

---

## Interpretation

`not-release-verified` does not mean that a feature is absent. It means only that the public release does not make an independent interoperability claim for that feature.

The capabilities document is the authoritative source for compiled features and maturity. This document defines only the evidence threshold for interoperability claims.
