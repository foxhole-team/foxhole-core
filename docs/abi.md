# FFI / Android ABI contract

This document defines the public integration contract between FoxHole Guard and `libfoxhole_native.so`.

The Android application owns `VpnService`, the TUN file descriptor, UI state and application lifecycle. FoxHole Core owns the native data plane exposed through the C/JNI ABI.

## Versions

| Interface | Version |
| --- | ---: |
| ABI | `1` |
| Configuration schema | `1` |
| Capabilities schema | `1` |
| Core package (current source) | `1.0.4` (`../Cargo.toml`, workspace package) |
| Native library | `foxhole_native` |

Compatibility is negotiated by ABI version, configuration schema and the runtime capabilities document. Library version numbers are not used for feature detection.

**Historical change in Core 0.0.5:** named-loopback validation was tightened: complete credentials are required unless the host
sets `allow_anonymous: true`; missing/partial credentials or conflicting modes fail. Listener
status adds `authentication: "credentials" | "anonymous"`. ABI/config schema remain v1, while
legacy anonymous requests must be migrated explicitly (`crates/foxcore-api/src/config/rt.rs:136,162`;
`crates/foxcore-runtime/src/snapshot.rs:127`).

---

## C interface

The C surface exposes version and capabilities discovery:

| Symbol | Contract |
| --- | --- |
| `foxhole_core_abi_version` | Returns the ABI version. |
| `foxhole_core_config_schema_version` | Returns the configuration schema version. |
| `foxhole_core_capabilities_json_len` | Returns the required capabilities buffer size, including the trailing NUL. |
| `foxhole_core_capabilities_json_write` | Writes the capabilities document into caller-owned memory. |

Buffer ownership never crosses the ABI. The caller allocates and frees all buffers passed to the C interface.

The Engine JNI source surface has **36 definitions**: 34 in
`crates/foxcore-android/src/lib.rs` and two in `link.rs`, in the reviewed current
source. This is a source inventory, not an inventory of a published release ELF.
The current Guard facade declares **35** methods in
`core/runtime/src/main/java/com/foxhole/core/runtime/FoxholeNativeEngine.java`.
Only legacy `nativeStart`, which lacks an Android `Network`, is omitted.
Guard pins compiled producer `3fc3b70d8e9d700b3e07ec27638515c00651b013`;
its source-checkout record separately identifies the equivalent public checkout
`90ae3e0d60de3d35e88e24558c99e771d9ca0bcf`. Declaration parity is checked
against that consumer and producer, not inferred from an export count.

The 19 Component/Share definitions remain compatibility ABI. Do not remove them
while ABI version1 is supported. Source declarations, Kotlin reachability and
exported symbols in a particular ELF are separate inventories.

Current Guard has production wrappers for signed/trusted DNS starts, DNS
continuation and generation-fenced DNS installation. Link import declarations
remain a separate compatibility boundary; `nativeTrafficMap` is the canonical
traffic snapshot and `nativeConnections` remains its ABI alias. See
[the app/Core boundary](architecture/04-app-core-boundary.md).

## DNS continuity start and lease ownership

Java signatures (the implicit JNI environment/class parameters are omitted):

```java
long nativeRetainDnsContinuation(long predecessorHandle);
void nativeReleaseDnsContinuation(long token);
long nativeStartOnNetworkWithDnsContinuity(
    int tunFd, String configJson, long networkHandle, long token,
    String name, byte[] manifest, byte[] signature, byte[] artifact,
    boolean trusted, Object host);
```

Retain while the predecessor handle is still registered, **before stopping it**.
Retain returns a positive opaque token; error/panic returns0 and attempts to throw
`IllegalStateException`. There is one process-wide outstanding lease; tokens are
not reused. The retained policy/cache reference has its own stop fence and
outlives removal of the predecessor's engine handle.

Start requires a positive, live token and a cleanly joined predecessor. A timed-out
or force-killed predecessor is not ready. Force-kill revokes the owner's lease.
A stream/flow DNS continuation cannot be imported into an L3 packet tunnel;
new runtime/configuration and cache-identity restrictions still apply.

| Continuity-start result | Caller action |
| ---: | --- |
| `> 0` | Published successor engine handle. |
| `0` | Ordinary failure; an `IllegalStateException` is attempted. No successor handle is returned. |
| `-1` | Unpublished cleanup was quarantined; it is not a handle and does not authorize an overlapping replacement. |
| `-2` | Unpublished cleanup failed, or the guarded operation panicked. It is not a handle. |

The existing TUN-adoption rule applies, including failures after adoption. Stop
and cleanup ownership remain authoritative; returning from a failed start does
not prove that an adopted descriptor or worker has been released.

The caller owns the lease until it explicitly releases it. A successful start
borrows the continuation and does not consume the token. Keep the lease until
start returns, and release it on success, failure, cancellation and abandoned
handover. Releasing it during start can reject publication and invoke unpublished
cleanup. Release of a nonpositive/stale token is a no-op; a release panic attempts
to throw `IllegalStateException`. Never infer success merely from an absent
exception. Guard's `FoxCoreDnsContinuation.kt`, `FoxCoreNativeSeam.kt` and
`FoxCoreNativeSessionStarter.kt` contain the corresponding lifecycle wrappers.

Bootstrap arrays have exactly one of these shapes:

- none: all payload references null and `trusted=false`;
- trusted: name/artifact present, manifest/signature null, `trusted=true`;
- signed: name/manifest/signature/artifact present, `trusted=false`.

Mixed/incomplete shapes are refused. The token is unrelated to the separate
`nativeConfirmContinuity(handle, token)` network-continuity protocol.

---

## Panic and exception boundary

Rust unwinding is contained inside the native boundary. A panic must not unwind into Java or C.

Public failure semantics are deterministic:

- integer-returning guarded calls use their documented negative or zero failure value;
- string-returning calls may return `null` after a panic or JNI string-allocation failure;
- link-import calls also throw `IllegalStateException` and return `null` on parse or render errors;
- lifecycle and configuration operations that expose Java exceptions use `IllegalStateException`;
- malformed input and runtime refusals are returned through typed result codes or structured error documents.

The caller must treat documented result codes as ABI values.

---

## Handles

Engine handles are opaque positive integers. Mini-platform builds use the same rule for lease,
share and publication handles.

- `0` and negative values are invalid;
- handles are not reused during the process lifetime;
- stale or unknown handles return a documented failure state rather than causing undefined behaviour;
- secrets represented by a handle remain inside the native core and are not exported through JNI.

Sub-resources retain the engine identity recorded when they are created. Operations that accept both an engine handle and a sub-handle additionally verify ownership.

---

## TUN file-descriptor ownership

`nativeStart*` consumes the TUN file descriptor after the descriptor passes the initial validity checks.

The caller retains ownership only when:

1. `tunFd < 0`; or
2. the descriptor is not open in the current process.

After adoption, the descriptor belongs to FoxHole Core even if runtime construction later fails. The Android side must not close an adopted descriptor.

On normal shutdown the descriptor is released with the worker runtime. `nativeForceKill` removes the engine handle from the ABI surface but does not guarantee immediate descriptor release.

---

## Concurrency

JNI/C entry points are designed for concurrent invocation.

- shared state is synchronized internally;
- poisoned synchronization state is recovered rather than propagated;
- locks are not held across Java upcalls;
- blocking lifecycle operations are serialized where required.

Only one data-plane worker may be active per Android process. A second start is refused while the previous worker remains alive.

Re-entrant Java → native calls from a native-triggered Java upcall are not part of the public contract.

---

## Java upcalls

FoxHole Core does not push data-plane events into Java.

The core calls Android only for platform operations required by the data plane, including:

- `VpnService.protectSocket(int)`;
- connection-owner attribution and package lookup;
- Android network and platform information during runtime initialization.

A failed `protectSocket` operation refuses the socket. The core does not continue with an unprotected connection.

Per-app attribution requires Android API level 29 or newer.

---

## Event streams

Events are pull-based and bounded.

| Stream | Buffer | Maximum requested batch |
| --- | ---: | ---: |
| Core audit events | 512 | 4096 |
| Traffic events | 512 | 4096 |
| Component events (compatibility ABI) | 256 per component | 512 |
| Share events (compatibility ABI) | 256 per share | 512 |

Each drain reports `dropped` when the producer exceeded the bounded queue. The counter represents events lost since the previous read.

Traffic-map snapshots are independently bounded and report omitted rows explicitly.

---

## Shutdown

### `nativeStop`

`nativeStop` is bounded by a 3-second public timeout.

| Return | Meaning |
| ---: | --- |
| `0` | Runtime stopped by this call. |
| `1` | Runtime was already stopped. |
| `2` | Stop timed out; cancellation was requested but the worker remains alive. |
| `3` | Unknown or invalid handle. |
| `-1` | Panic boundary failure. |

A timed-out stop keeps the engine generation active until the worker exits. A new data-plane generation is therefore refused while that worker remains alive.

### `nativeForceKill`

`nativeForceKill` removes the engine handle from the public registry and abandons the worker without waiting for a normal join.

It is an emergency lifecycle operation, not a guarantee that all native resources have already been released.

---

## Result codes

### LAN proxy and compatibility components/shares

| Code | Meaning |
| ---: | --- |
| `0` | OK |
| `1` | Invalid argument |
| `2` | Engine unavailable |
| `3` | Not found |
| `4` | Already exists |
| `5` | Capacity exceeded |
| `6` | Authorization denied |
| `7` | Required runtime or route unavailable |
| `8` | Vault error |
| `9` | LAN network refused |
| `10` | LAN network not confirmed |
| `11` | LAN bind failed |
| `-1` | Panic boundary failure |

### Policy reload

A successful `nativeReloadPolicy` returns the installed revision (`> 0`).

| Return | Refusal |
| ---: | --- |
| `-1` | Invalid policy |
| `-2` | Unknown outbound |
| `-3` | Tor unavailable |
| `-4` | I2P unavailable |
| `-5` | Overlay requires fake-IP |
| `-6` | Application identity unavailable |
| `-7` | Revision conflict |
| `-8` | Packet tunnel rejects fake-IP |
| `-9` | Packet tunnel rejects `dns.route = "primary"` |

The refusal numbers are part of the ABI and must not be reordered.

Ordinary rejected reloads preserve the current policy. **Emergency exception:**
when a request enables kill switch and its DNS policy is refused, Core can retain
the admitted DNS policy, publish emergency Block at a new revision and revoke the
previous epoch, then return `Invalid (-1)` (`FlowPolicyStore::reload`).
After a negative return, read `nativeLastPolicyError(handle)` for the bounded
failure detail and `nativeStats(handle).policy_revision` for the effective revision.
Serialize these reads with reloads for the same generation; the two calls are not
an atomic state document. The detail includes the emergency revision when that
path ran. JNI stats do **not** expose a complete effective routing policy or a
machine-readable emergency-Block boolean. Do not draw the old saved toggle as
proven live state: retain conservative protection and reconcile with an explicit
valid policy operation. Runtime callers in Rust can inspect `policy.gates()`.

For L3 ordinary reload vs revocation, see [atomic policy integration](atomic-policy-updates.md).


### Continuity

| Code | Meaning |
| ---: | --- |
| `0` | Confirmed |
| `1` | Nothing pending |
| `2` | Stale token |
| `3` | Unknown handle |
| `-1` | Panic boundary failure |

### Enumerations

Route:

```text
1 = VPN
2 = Tor
3 = Direct
4 = Block
```

Purpose:

```text
1 = web navigation
2 = web notification
3 = file sharing
```

Operation:

```text
1 = navigation
2 = subresource
3 = notification delivery
4 = notification action
5 = share publish
6 = share download
```

Unknown enum values are rejected; they are never interpreted as a default route or operation.

---

## Input limits

All externally supplied data is bounded.

### Runtime and policy

| Limit | Value |
| --- | ---: |
| Engine configuration JSON | 1 MiB |
| Policy configuration JSON | 256 KiB |
| Named outbounds | 16 |
| Selector members | 64 |
| Route rules | 4096 |
| DNS blocklist entries | 65,536 |
| DNS rule sets | 16 |
| `runtime.connect_timeout_ms` | `100..=120000` ms |
| `runtime.handshake_timeout_ms` | `100..=300000` ms |
| `selector.member_timeout_ms` | `1..=120000` ms; default `5000` ms |

Protocol-specific strings, headers and ECH configuration are also bounded before runtime construction.

### Data-plane buffers

| Limit | Value |
| --- | ---: |
| Default TCP / UDP flow slots | 1024 / 512 |
| TCP actor buffer budget across admitted flows | 64 MiB |
| Unestablished TCP reservation | 30 seconds |
| Netstack ingress / egress packet queues | 256 / 256 |
| Retained datagrams per UDP flow | 32 |
| UDP reply / raw-response queues back to the TUN | 256 / 256 |
| REALITY accumulated handshake plaintext | 64 KiB |
| REALITY pending ciphertext plus application plaintext | 64 KiB |

Flow defaults come from `crates/foxcore-api/src/config/rt.rs:522-532` and are applied to the
netstack at `crates/foxcore-tun/src/flow/route.rs:292-314`. Queue and aggregate memory caps are at
`crates/foxcore-tun/src/netstack/mod.rs:160-166` and
`crates/foxcore-tun/src/netstack/actor.rs:31-42,242-282`; the TCP reservation default is at
`crates/foxcore-tun/src/netstack/stream/smoltcp_tcp.rs:22-47`. REALITY's two limits are enforced at
`crates/proto-reality/src/reality/reality_client_connection.rs:56-68,931-936` and
`crates/proto-reality/src/reality/reality_reader_writer.rs:65-70`.

The public `DatagramFlow` adapts a datagram payload to `AsyncRead` without discarding bytes: when
the caller's `ReadBuf` is short, later reads return the remaining tail before the next datagram. A
zero-capacity read consumes nothing. Each successful write still represents exactly one datagram;
a payload above the current IP/UDP MTU allowance is refused rather than split
(`crates/foxcore-tun/src/netstack/stream/udp.rs:169-244`; regression at `:334-383`).

### Signed DNS rule sets

| Input | Limit |
| --- | ---: |
| Manifest | 64 KiB |
| Signature | 256 bytes |
| Artifact | 64 MiB |

A failed rule-set installation does not replace the currently active verified rule set.

`nativeStartWithNetworkAndDnsRuleSet` is the atomic bootstrap form: the signed bundle is checked
before the resolver can answer and any refusal aborts the start. Guard persists a verified update
before calling `nativeInstallDnsRuleSet`. A running engine with the same pinned name and key adopts
the new bytes immediately and returns its new policy revision. Enabling the rule set or changing its
trust identity changes the immutable engine fingerprint and therefore uses an atomic replacement
start. If no stable engine owns the generation, the persisted bundle is selected by the next start.

### Mini-platform components and vault

| Limit | Value |
| --- | ---: |
| Components | 1024 |
| Leases | 4096 |
| Confirmed LAN networks | 64 |
| Component identifier | 96 bytes |
| Origin | 2048 bytes |
| Vault sessions | 256 |
| Files per session | 1024 |
| File size | 8 GiB |
| Share lifetime | 31 days |
| Maximum downloads | 100,000 |
| Vault key | exactly 32 bytes |

Drain batch sizes and selected diagnostic fields may be clamped to their documented maximums.

---

## LAN proxy request

LAN-proxy configuration is strict and does not apply implicit defaults.

- preset: `vpn`, `tor` or `mixed`;
- transport: `wifi`, `ethernet`, `cellular` or `unknown`;
- bind address: explicit IPv4 address;
- at least one proxy port must be non-zero;
- username and password are mandatory;
- disallowed interfaces and unconfirmed networks are refused.

---

## Version negotiation

The Android application must:

1. compare `nativeAbiVersion()` with the ABI it was built for;
2. compare the configuration schema version;
3. feature-detect all optional behaviour from the capabilities document.

An absent capability means that the native library predates that feature.

`compiled: true` means the implementation is present in the build. It does not imply release maturity or independent interoperability verification.
