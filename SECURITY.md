# Security policy

FoxHole Core is the native network data plane used by FoxHole Guard. Security reports concerning routing, protocol handling, DNS, TLS, JNI/C boundaries or native data-plane isolation are handled in this repository.

---

## Supported versions

Security fixes are provided for the current FoxHole Guard release and the FoxHole Core revision shipped with it.

Pre-1.0 releases do not have a long-term-support or backport branch unless explicitly stated in the release notes.

---

## Reporting a vulnerability

Use GitHub **Private Vulnerability Reporting** for this repository:

**Security → Report a vulnerability**

Do not publish security-sensitive details in an issue, pull request or discussion before coordinated disclosure.

A useful report should include, where available:

- affected component or protocol;
- FoxHole Core version/commit and FoxHole Guard release;
- attacker position or trust boundary;
- security impact;
- minimal reproduction, configuration, packet trace or crash trace;
- Android version and ABI for device-specific issues.

### Response targets

| Stage | Target |
| --- | --- |
| Initial acknowledgement | 72 hours |
| Initial assessment | 10 days |
| Fix or documented mitigation for accepted issues | within 90 days, coordinated |

These are response targets rather than a contractual SLA.

### Coordinated disclosure

The default disclosure window is up to 90 days or the release of a fix, whichever occurs first. Actively exploited vulnerabilities may require an accelerated release and disclosure schedule.

Reporter credit is optional and follows the reporter's preference.

---

## Scope

### In scope

Security issues reachable through data parsed by FoxHole Core or interfaces exposed by it, including:

- **protocol implementations** — authentication bypass, cryptographic misuse, nonce/key reuse, memory-safety defects or remotely reachable panics;
- **TLS / REALITY / ECH** — certificate or pin bypass, downgrade, unintended SNI or destination disclosure;
- **routing** — violations of the fail-closed guarantee or traffic leaving through the wrong outbound;
- **DNS** — cache poisoning, private namespace leakage, fake-IP confusion or route/DNS inconsistency;
- **JNI/C ABI** — lifetime, handle, panic-boundary or buffer-ownership violations;
- **components and file sharing** — identity/lease confusion, capability bypass or vault-key exposure;
- **LAN proxy** — authentication bypass, invalid interface binding or use without network confirmation;
- **signed rule-set delivery** — acceptance of an invalid signature, digest, key, sequence or compatibility state;
- **build and supply chain** — shipped dependency or artifact integrity issues with a reachable security impact.

### Out of scope

- FoxHole Guard UI, application storage and Android permissions that do not involve the native ABI;
- vulnerabilities that exist solely in upstream projects such as Arti/Tor, `i2pd`, rustls or Android;
- rooted or fully compromised devices;
- global traffic-analysis and timing-correlation attacks;
- information leakage required by the specification of a selected protocol;
- hardening suggestions without a reachable security impact;
- denial of service by an adversary already able to block the network path;
- automated scanner output without a demonstrated reachable vulnerability.

If FoxHole Core integrates an upstream dependency incorrectly, that integration defect remains in scope.

---

## Security guarantees and non-goals

The security model is defined in [`docs/threat-model.md`](docs/threat-model.md).

In particular, FoxHole Core does not claim to:

- hide VPN/proxy use from every network observer;
- protect secrets from root on a running device;
- defeat a global passive adversary;
- make an untrusted VPN/proxy provider trustworthy.

Reports should distinguish implementation failures from documented protocol or threat-model limitations.
