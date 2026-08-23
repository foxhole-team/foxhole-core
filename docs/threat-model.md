# Threat model

This document defines the security boundaries and explicit non-goals of FoxHole Core.

It covers the native Rust data plane only. FoxHole Guard owns the Android UI, application storage, permissions, `VpnService` lifecycle and security journal.

---

## Trust boundaries

```text
┌──────────────────────────────────────────────────────────┐
│ FoxHole Guard / Android application                      │
│ VpnService · TUN fd · UI · profile storage · journal     │
└───────────────────────────┬──────────────────────────────┘
                            │ JNI / C ABI
┌───────────────────────────┴──────────────────────────────┐
│ FoxHole Core                                             │
│ flow engine · routing · DNS · TLS · outbounds            │
└───────────────────────────┬──────────────────────────────┘
                            │ protected sockets
┌───────────────────────────┴──────────────────────────────┐
│ Untrusted network                                        │
└──────────────────────────────────────────────────────────┘
        │                                      │
        │ loopback                             │ LAN listener
   external i2pd                          other devices
```

### Android application ↔ core

The Android application is trusted by the core. The ABI validates malformed input and contains native failures, but it is not intended to defend against a malicious host application.

### Core ↔ network

Servers, peers, DNS resolvers and all received network data are untrusted.

### Core ↔ `i2pd`

I2P is reached through a loopback SOCKS5 endpoint. FoxHole Core does not start, supervise or attest the external `i2pd` process.

### LAN proxy

LAN clients are untrusted. The proxy is disabled by default, requires authentication and binds only after explicit network confirmation.

---

## Malicious VPN or proxy server

FoxHole Core protects the transport properties implemented by the selected protocol:

- authenticated TLS/REALITY/WireGuard-family handshakes where applicable;
- WebPKI certificate validation and optional SPKI SHA-256 pinning;
- no plaintext retry after a protected handshake failure;
- local route selection that cannot be changed by the remote peer;
- fail-closed behaviour when the required outbound is unavailable.

The remote endpoint still observes information inherent to its role, including the client's network address, requested destinations and traffic timing/volume. A proxy operator may also refuse service or log metadata.

Tor changes the trust model by separating entry and destination observation, but does not eliminate global traffic-correlation risk.

---

## Hostile local network

The core is designed to resist:

- passive inspection of encrypted proxy/VPN transports;
- TLS interception when certificate validation is enabled;
- DNS manipulation when DoT or DoH is used;
- captive-portal or transparent-proxy redirection that cannot satisfy the expected authentication;
- accidental LAN-proxy exposure outside a user-confirmed Wi-Fi or Ethernet network.

Residual exposure remains:

- bootstrap resolution may reveal the configured resolver endpoint;
- destination IPs, timing and traffic shape remain observable at the local link;
- an active network may block traffic entirely.

REALITY, ECH and pluggable transports are traffic-shaping and censorship-resistance mechanisms, not invisibility guarantees.

---

## Malicious configuration or subscription

Configuration and imported links are untrusted input.

The core applies:

- strict schema validation;
- bounded resource limits;
- rejection of unsupported protocol/transport combinations;
- redaction of secret values from debug output;
- fail-closed refusal instead of silent capability downgrade.

These controls do not establish trust in the server operator. A valid profile that points to a malicious provider remains a valid route to a malicious provider.

Subscription provenance and provider reputation are application/user trust decisions.

The TUN boundary also treats packets and handshake bytes as hostile input. TCP admission is charged
against a 64 MiB aggregate buffer budget and an unestablished flow is reaped after 30 seconds;
packet-device queues are capped at 256 entries. Each UDP flow retains at most 32 datagrams and the
shared UDP/raw response paths are bounded at 256 packets. REALITY refuses more than 64 KiB of
accumulated handshake plaintext and shares a separate 64 KiB allowance between pending ciphertext
and application plaintext (`crates/foxcore-tun/src/netstack/actor.rs:31-42,242-282`;
`crates/foxcore-tun/src/netstack/mod.rs:160-166`;
`crates/foxcore-tun/src/netstack/stream/smoltcp_tcp.rs:22-47`;
`crates/proto-reality/src/reality/reality_client_connection.rs:56-68,931-936`;
`crates/proto-reality/src/reality/reality_reader_writer.rs:65-70`).

---

## DNS security

FoxHole Core supports UDP/TCP DNS, DoT and DoH.

Security properties include:

- authenticated transport for DoT/DoH;
- bounded cache handling;
- route-aware resolution;
- fail-closed handling for `.onion` and `.i2p`;
- no clearnet DNS fallback for private overlay namespaces.

Plain UDP/TCP DNS remains susceptible to an on-path resolver attacker. A configured resolver, including a DoH provider, can observe the queries sent to it.

---

## Components and Web Apps

The core enforces component identity and route authorization through canonical origins and leases.

- Web App origins are canonicalized before registration;
- leases are scoped to their registered identity and purpose;
- notification authorization is origin-bound;
- a component cannot select a route outside its assigned policy;
- stale operations re-check runtime availability.

The core does not sandbox Web content. WebView isolation, rendering security and permission handling belong to the Android application and platform.

---

## Local applications on the device

Loopback services are not assumed to be private from other Android applications.

The core therefore relies on explicit credentials for local control/proxy access and uses generation-scoped credentials for LAN proxy sessions.

Vault content is encrypted with XChaCha20-Poly1305 using a key supplied by the application. File-sharing onion identities are ephemeral to the active publication/runtime.

A local application that compromises FoxHole Guard's process, memory or stored credentials is outside the native core's trust boundary.

---

## Rooted or physically compromised device

A rooted or physically compromised device is out of scope.

An attacker with sufficient local privilege can read process memory, session keys and plaintext, replace the native library, attach a debugger or alter the Android runtime. User-space cryptography cannot provide a meaningful confidentiality guarantee against that attacker while the protected data is in use.

Encrypted on-disk artifacts protect data at rest only while the corresponding key remains unavailable to the attacker.

---

## Fail-closed routing

The primary routing guarantee is:

> Traffic assigned to a protected route leaves through that route or it does not leave.

Properties:

- unavailable VPN/Tor/I2P routes do not fall back to `Direct`;
- `Direct` is an explicit policy action, not a degradation path;
- policy reload is atomic for new flows;
- invalid or incompatible configurations are refused rather than silently weakened;
- `.onion` and `.i2p` are not resolved through clearnet DNS.

### Existing flows

Policy reload does not generally re-route or terminate already established flows.

Existing flows are cancelled when the kill switch is armed or when the underlying network changes. A newly added `Block` or quarantine rule applies to subsequent connections while already-open flows remain active until they close.

Applications must use the capabilities document rather than assuming stronger live-flow semantics.

---

## Fingerprinting and censorship resistance

REALITY fingerprint profiles comprise seven tables transcribed from maintained uTLS data and two
first-party captures of shipping browsers (`chrome_151` and `firefox_153`). Their provenance and
measured JA4 are recorded per profile.

They are not claimed to be byte-identical to every browser release or to provide an independently
validated censorship-evasion guarantee.

Fingerprint mimicry reduces protocol distinguishability only within the limits of the selected profile, transport and surrounding traffic pattern.

---

## Out of scope

The native core does not claim to defend against:

- a rooted or fully compromised device;
- a global passive adversary performing timing/volume correlation;
- vulnerabilities in Android, Arti/Tor, `i2pd`, rustls or other upstream dependencies unless FoxHole Core uses them incorrectly;
- information leakage inherent to the specification of a selected proxy protocol;
- malicious behaviour by a provider the user intentionally configured;
- denial of service by an adversary already able to block the network path.

---

## Summary

| Threat | Coverage |
| --- | --- |
| Malicious VPN/proxy server | Partial: transport protected; peer-visible metadata remains |
| Hostile local network | Strong for authenticated transports; traffic shape and blocking remain |
| Malicious configuration | Strictly parsed and bounded; provider trust is not established |
| DNS attacker | Protected with DoT/DoH; plain DNS inherits normal on-path risk |
| Malicious Web App/component | Route and identity isolation in core; content sandboxing is external |
| Local unprivileged app | Credential-based protection for loopback services |
| Rooted device | Out of scope |
| Global timing/traffic correlation | Out of scope |
