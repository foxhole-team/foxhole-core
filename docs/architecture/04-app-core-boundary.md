# 4. App ↔ core boundary

How a stored profile becomes a running engine, what crosses the FFI, and in what form.

---

## 4.1 The seam

```mermaid
flowchart TD
    subgraph kt["Kotlin / Java — FoxHole Guard"]
        P["profile in SQLCipher"] --> A["RuntimeConfigAssembler"]
        A --> T["FoxCoreConfigTranslator"]
        T --> S["FoxCoreNativeSessionStarter"]
        S --> J["FoxholeNativeEngine.java<br/>System.loadLibrary(foxhole_native)"]
    end
    subgraph rs["Rust — libfoxhole_native.so"]
        J -->|JNI| AN["foxcore-android"]
        AN --> RU["foxcore-runtime<br/>CoreRuntime"]
        RU --> DP["data plane:<br/>tun / route / dns / outbound"]
    end
    DP -.->|upcall| J
```

| Fact | Value |
|---|---|
| Library | `libfoxhole_native.so` — `crate-type = ["cdylib"]`, lib name `foxhole_native` |
| Load site | `core/runtime/src/main/java/com/foxhole/core/runtime/FoxholeNativeEngine.java:51-53` — the only one |
| Shipped Engine seam | **33 Rust exports / 32 Java declarations** (`FoxholeNativeEngine.java:55-227`). Only legacy `nativeStart`, which has no Android `Network` handle, is intentionally absent from Java. |
| Kotlin wrapper | `interface FoxCoreNativeApi` + `object JniFoxCoreNativeApi` expose the product-reachable subset; link import and continuity stop at Java compatibility declarations |
| Cross-repository gate | The app compares every shipped Engine export with Java declarations and production Kotlin references (`scripts/verify-foxcore-jni-seam.sh`), then executes product-reachable calls against the packaged `.so` on Android (`FoxCoreNativeSeamAndroidTest.kt`). |
| Core release version | `0.0.4` comes from the workspace package (`Cargo.toml:36-41`). `CORE_VERSION` is `CARGO_PKG_VERSION` (`crates/foxcore-api/src/lib.rs:38-40`) and supplies both JNI `nativeVersion` (`crates/foxcore-android/src/lib.rs:105-115`) and capabilities JSON (`crates/foxcore-android/src/capabilities.rs:699-707`). |
| ABI version | `1`, frozen; class and package name are part of the ABI |
| Structured documents | JSON, with no protobuf. TUN/network handles and signed DNS/fingerprint payloads use their native scalar/byte-array forms. |
| Build-path contract | `scripts/android-build.sh:67-98` remaps the checkout, Cargo home and Rustup home before compiling. The ELF gate refuses build-host paths (`scripts/android-elf-gate.sh:138-166,222-225`), and the release reproducibility check compares bytes from different checkout and Cargo-home paths (`scripts/reproducible-build.sh:46-150`). |
| Release provenance | release requires a verified main commit plus a successful dev CI run with the identical Git tree (`.github/workflows/release.yml:35-117`), then rebuilds and re-verifies the JNI manifest, both ARM ABIs and SBOM inputs on main (`.github/workflows/release.yml:133-177`). `RELEASE.json` binds both commits, their shared tree and the gate run; SHA-256 and keyless attestation cover the archive (`:179-210`). |

---

## 4.2 Profile → engine config

```mermaid
flowchart TD
    P["stored profile"] --> R["ProfileRepository.getResolvedConfig<br/>+ parser.sanitizeResolvedConfig"]
    R --> AS["RuntimeConfigAssembler.assemble<br/>assembleTunnel / assembleProxy /<br/>assembleLocalGuard / assembleTorOnly"]
    AS --> IM["intermediate document<br/>sing-box shaped<br/>keys: log dns inbounds outbounds<br/>endpoints route experimental"]
    IM --> TR["FoxCoreConfigTranslator.translate"]
    TR --> OUT["FoxCoreSessionConfig"]
    OUT --> E["engineConfigJson"]
    OUT --> PO["policyConfigJson"]
    OUT --> TP["tunPlan"]
    OUT --> DB["dnsRuleSetBootstrap"]
```

Two documents, two shapes. The intermediate is sing-box-like and never crosses the FFI; the engine
config is FoxCore's own schema. `log` may only carry `{level, timestamp}` and is dropped;
`experimental` must be empty (`FoxCoreConfigTranslator.kt:260-289`).

Sub-translators, all in `core/runtime/src/main/kotlin/com/foxhole/core/runtime/`:

| File | Entry | Produces |
|---|---|---|
| `FoxCoreTunTranslator.kt:11` | `translateFoxCoreTun` | `FoxCoreTunPlan` — mtu, v4/v6 + prefix, routes, advertised DNS, app include/exclude |
| `FoxCoreTunTranslator.kt:54` | `translateFoxCoreControlProxy` | `runtime.control_proxy` |
| `FoxCoreOutboundTranslator.kt:23` | `translate` | `FoxCoreOutboundPlan` — primary, named, packet-tunnel flag, overlays |
| `FoxCoreProxyOutboundTranslator.kt:8` | `translateFoxCoreProxyOutbound` | per-protocol outbound object |
| `FoxCoreWireGuardTranslator.kt:26` | `translateFoxCoreWireGuard` | `type:"wireguard"` |
| `FoxCoreTorTranslator.kt:13,65` | `translateOverlay` / `translateOutbound` | named `tor` outbound |
| `FoxCoreTlsTransportTranslator.kt:18,211` | `translateFoxCoreTls` / `translateFoxCoreTransport` | `tls` / `transport` sub-objects |
| `FoxCorePolicyTranslator.kt:30` | `translate` | dns, routes, traffic, `dns.rule_sets[]` |

Rejections are a closed enum (`FoxCoreConfigRejection`); the exception never echoes document values.

Tor bridge policy is resolved before translation. `AUTO` selects one Snowflake group; explicit
transports cannot cross-fallback, while downloaded-to-bundled fallback is allowed only for that
same transport (`core/runtime/src/main/kotlin/com/foxhole/core/runtime/TorBridgeTorrcLines.kt:50-81`).
The runtime derives the required protocol tokens from the resulting bridge lines, narrows and
coalesces the PT process declarations, and fails preflight if any selected protocol has no helper
(`core/runtime/src/main/kotlin/com/foxhole/core/runtime/TorRuntimeInstaller.kt:169-198,274-305`).
The translator therefore receives only the selected `bridges` and `pluggable_transports`, validates
their shape, and emits those values without reopening transport selection
(`core/runtime/src/main/kotlin/com/foxhole/core/runtime/FoxCoreTorTranslator.kt:65-125,163-193`).

### The engine config the core accepts

`EngineConfig` — `crates/foxcore-api/src/config/engine.rs:9-30`, `deny_unknown_fields`, ≤1 MiB:

| Field | Type | Constraint |
|---|---|---|
| `schema_version` | `u32` | must equal `1` |
| `outbound` | `OutboundConfig` | the primary; addressable as `default` / legacy `primary` |
| `outbounds` | `Vec<NamedOutboundConfig>` | ≤16; `default`/`primary`/`direct`/`block` reserved |
| `tun` | `TunConfig` | `{mtu ≥ 1280, ipv4, ipv6?}` |
| `dns` | `DnsConfig` | |
| `runtime` | `RuntimeConfig` | `local_guard` ⇔ primary is `direct` |
| `routes` | `Vec<RouteRule>` | ≤4096 incl. `traffic.applications` |
| `traffic` | `TrafficPolicyConfig` | the reloadable half |

There is **no `inbounds`, no `log`, no `route`** key in `EngineConfig` — those belong to the
intermediate document only.

`PolicyConfig`, the reload document (`config/policy.rs:11-22`, ≤256 KiB):
`expected_revision?`, `dns`, `routes`, `traffic`.

---

## 4.3 What crosses, and in what form

| Item | Direction | Type | Ownership / bound |
|---|---|---|---|
| TUN fd | Java → Rust | **`jint`**, a raw int — not a `ParcelFileDescriptor` | Kotlin does `dup(...).detachFd()`; **Rust owns it on every path including failure** and Kotlin must not close it. Validated: `S_IFCHR`, `O_RDWR`, and on Android `TUNGETIFF ⇒ IFF_TUN` |
| Engine config | Java → Rust | `JString` UTF-8 JSON | ≤1 MiB, `deny_unknown_fields` |
| Policy config | Java → Rust | `JString` UTF-8 JSON | ≤256 KiB |
| Network handle | Java → Rust | `jlong` from `Network.getNetworkHandle()` | negative rejected; drives `android_setsocknetwork` / `android_getaddrinfofornetwork` |
| Host object | Java → Rust | `JObject` → `GlobalRef` | retained for the runtime's life |
| Engine handle | Rust → Java | `jlong` > 0, opaque, never reused | `0` means failure **and** a thrown exception |
| Stats | Rust → Java | `jstring` JSON `RuntimeSnapshot` | `{}` if the handle is dead |
| Traffic map | Rust → Java | `jstring` JSON | `{generation, connections[], packages[], lanes[], omitted_rows, dropped_events, dns{...}}` |
| Events | Rust → Java | `jstring` `{"events":[...],"dropped":N}` | **pull-based, bounded, drop-on-overflow.** No push callbacks into Java |
| DNS rule set | Java → Rust | `JByteArray` ×3 + name `JString` | manifest ≤64 KiB, signature ≤256 B, artifact ≤64 MiB; name ASCII ≤128 B |
| Fingerprint tables | Java → Rust | `JByteArray` | ≤4 MiB; **never throws**, returns a code |
| Errors | Rust → Java | two channels | `IllegalStateException` for lifecycle/config (message walks the whole `source()` chain); numeric codes for anything switchable |
| **Logs** | — | **none** | There is no Java log callback. Rust writes to logcat directly (tag `FoxCore`), capped at `warn` because debug/trace records interpolate `NetworkTuple` — the user's connection list |

### Upcalls (Rust → Java)

```mermaid
sequenceDiagram
    participant R as FoxCore
    participant H as FoxholeVpnService (host)
    R->>H: protectSocket(fd) : boolean
    H-->>R: false = socket refused, never sent unprotected
    R->>H: getSystemService(name), getPackageManager()
    R->>H: ConnectivityManager.getConnectionOwnerUid(...)
    Note over R,H: per-app attribution needs API 29 or later,<br/>package cache 5 min / 1024 entries
```

Host contract: `RuntimeServiceHost` —
`core/runtime/src/main/kotlin/com/foxhole/core/runtime/RuntimeNativeSupport.kt:12-34`; implementation
`app/src/main/kotlin/com/foxhole/guard/runtime/FoxholeVpnService.kt:67,485-504`.

Panic containment: every JNI entry is wrapped in `catch_unwind(AssertUnwindSafe(...))`; a contained
panic becomes `IllegalStateException("panic inside FoxCore JNI boundary")` or a `-1`-family code.

---

## 4.4 JNI surface

### C ABI (4 symbols)

| Symbol | Signature | Purpose |
|---|---|---|
| `foxhole_core_abi_version` | `() -> u32` | `1` |
| `foxhole_core_config_schema_version` | `() -> u32` | `1` |
| `foxhole_core_capabilities_json_len` | `() -> usize` | length including NUL |
| `foxhole_core_capabilities_json_write` | `(*mut u8, usize) -> usize` | NULL/short buffer left untouched, returns required size |

Header: `crates/foxcore-android/include/foxhole_core.h`.

### `FoxholeNativeEngine` — 33 Rust exports

```mermaid
flowchart LR
    subgraph life["Lifecycle"]
        L1["nativeStart"]
        L2["nativeStartWithNetwork"]
        L3["nativeStartWithNetworkAndDnsRuleSet"]
        L4["nativeStartWithNetworkAndTrustedDnsRuleSet"]
        L5["nativeStop / nativeForceKill"]
        L6["nativeConfirmContinuity"]
    end
    subgraph obs["Observation — all pull-based"]
        O1["nativeStats"]
        O2["nativeTrafficMap / nativeConnections"]
        O3["nativeDrainTrafficEvents"]
        O4["nativeDrainEvents"]
        O5["nativeLastPolicyError"]
        O6["nativeLastStopDiagnostics"]
    end
    subgraph ctl["Control"]
        C1["nativeReloadPolicy"]
        C2["nativeRevokeFlows"]
        C3["nativeNetworkChanged(WithHandle)"]
        C4["nativeInstallDnsRuleSet"]
        C5["nativeInstall/ClearTlsFingerprintTables"]
    end
    subgraph comp["Components"]
        P1["nativeConfirmLanNetwork"]
        P2["nativeStart/Stop/StatusLanProxy"]
        P3["nativeStart/Stop/ListLoopbackInbound"]
    end
    subgraph imp["Link import — compatibility-only declarations"]
        K1["nativeImportLink"]
        K2["nativeImportSubscription"]
    end
```

Key signatures:

| Function | Java signature | Returns |
|---|---|---|
| `nativeStartWithNetwork` | `(ILjava/lang/String;JLjava/lang/Object;)J` | handle > 0, or `0` + `IllegalStateException` |
| `nativeStartWithNetworkAndDnsRuleSet` | `(ILjava/lang/String;JLjava/lang/String;[B[B[BLjava/lang/Object;)J` | atomic signed bootstrap: handle > 0, or no engine + throw |
| `nativeStartWithNetworkAndTrustedDnsRuleSet` | `(ILjava/lang/String;JLjava/lang/String;[BLjava/lang/Object;)J` | APK-trusted artifact, no signature check |
| `nativeInstallDnsRuleSet` | `(JLjava/lang/String;[B[B[B)J` | revision, or `0` + throw |
| `nativeTrafficMap` | `(J)Ljava/lang/String;` | canonical bounded traffic-map document |
| `nativeConfirmContinuity` | `(JJ)I` | typed `0..3` result, or `-1` panic |
| `nativeInstallTlsFingerprintTables` | `([B)I` | profiles replaced, or `-1` unreadable / `-2` refused / `-3` panic |
| `nativeStop` / `nativeForceKill` | `(J)I` | `0` stopped, `1` already, `2` timed out, `3` unknown handle, `-1` panic |
| `nativeReloadPolicy` | `(JLjava/lang/String;)J` | > 0 revision, `0` not running, `-1..-9` refusal |
| `nativeRevokeFlows` | `(JLjava/lang/String;)I` | count ≥ 0, or `-1` panic / `-2` no engine / `-3` bad target. Target JSON tagged on `kind`: `all\|lane\|uid\|package\|outbound\|flow` |
| `nativeLastStopDiagnostics` | `()Ljava/lang/String;` | **no handle** — the caller has just been told its stop timed out. `{phase, engine_ms, shutdown_ms, generation}` |

Release libraries also retain 19 component/share exports: ten `FoxholeNativeShares_*` and nine
`FoxholeNativeComponents_*`. v0.0.1 shipped them, and the frozen ABI-v1 fixture requires them
(`fixtures/abi/v1/exports.txt:1-19`; `scripts/abi-gate.sh:1-17`). The app has a nine-method Shares
facade but no production call site, and no Components facade. These symbols are outside the 33/32
Engine seam and remain solely for ABI compatibility.

---

## 4.5 Connect sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant S as FoxholeVpnService
    participant R as FoxCoreRuntime
    participant O as FoxCoreTunOwner
    participant N as FoxCore (Rust)

    Note over S: onCreate already ran installTlsFingerprintTables(), before any dial
    U->>S: ACTION_CONNECT
    S->>S: resolve gate/settings/profile, validate Private DNS mode
    S->>S: beginRuntimeTransition("connect") — new generation
    S->>S: Tor ordering step 1: defer in-tunnel Tor out of the first config
    S->>S: make-before-break: retire the old worker,<br/>it releases the FoxCore lease but KEEPS its master TUN open
    S->>S: build session -> assembler -> translator
    S->>S: publish CONNECTING, register network callbacks, wake lock,<br/>start notification-health + child watchdogs
    S->>R: startFailClosed(session)
    R->>N: preflight — nativeAbiVersion + nativeCapabilities
    R->>S: currentUnderlyingNetwork()
    Note over R: null, or a handle of 0 or less, is a HARD failure
    R->>O: establish TUN
    O->>O: hasVpnPermission -> setSession/setMtu -> setUnderlyingNetworks -><br/>setMetered -> addAddress -> addRoute* -> app split -> addDnsServer* -> establish()
    R->>R: dup(tun.fileDescriptor).detachFd()
    alt no DNS bootstrap
        R->>N: nativeStartWithNetwork(dupFd, engineConfigJson, networkHandle, host)
    else APK-trusted bundled artifact
        R->>N: nativeStartWithNetworkAndTrustedDnsRuleSet(...)
    else persisted signed update
        R->>N: nativeStartWithNetworkAndDnsRuleSet(..., manifest, signature, artifact, ...)
    end
    Note over N: signed bytes are verified before the resolver can answer its first query
    N-->>R: handle, or no engine + exception
    R-->>S: started
    S->>N: nativeNetworkChangedWithHandle — post-handoff network reset
    S->>S: validation probes: runtime proxy, early UDP literal,<br/>pre-DNS, endpoint pre-IP, VPN-bound DNS, IP refresh, grace retry
    S->>S: publish CONNECTED, start traffic sampler
    S->>S: Tor ordering step 2: reload(profileId) so Tor engages<br/>only after the VPN proved itself
```

**The real order is: host registered by construction → establish TUN (Android) → dup fd → start
engine.** `protect()` is never called before the engine exists — it is a Rust→Java upcall made per
outbound socket.

Direct bridged Tor-only validation is one authenticated runtime-proxy request with an 80 s call cap
inside one monotonic 120 s validation deadline; 5 s is reserved for a classification-only control
probe after a strict failure (`RuntimeValidationProbePlan.kt:139-175`;
`RuntimeValidationRun.kt:331-360`; `RuntimeProxyEgressValidationSupport.kt:84-146,350-388`). The
core assigns that Tor CONNECT route 75 s to build its upstream while VPN and direct routes retain
30 s. The accepted session still owns a bounded permit, and listener cancellation races the whole
serve future, so stop does not wait for either connect ceiling
(`crates/foxcore-component/src/lan.rs:114-121,286-291,821-830,927-939,963-988`).

---

## 4.6 Disconnect sequence

```mermaid
stateDiagram-v2
    [*] --> Transition: beginRuntimeTransition("disconnect")
    Transition --> PhaseVPN: publish DISCONNECTING
    PhaseVPN --> PhaseVPN2: stop tickers, watchdogs, auto-reconnect<br/>invalidateValidationEpoch
    PhaseVPN2 --> NativeStop: stopRuntimeFailClosed
    NativeStop --> ForceKill: nativeStop timed out
    NativeStop --> TunProbe: stopped
    ForceKill --> TunProbe: nativeForceKill
    TunProbe --> PhaseTOR: probe /proc/self/fd/N startsWith /dev/tun, close master TUN
    PhaseTOR --> PhaseI2P: stop Tor helper
    PhaseI2P --> PhaseAndroid: stop i2pd child
    PhaseAndroid --> Settle: poll for VPN network teardown, 4 s
    Settle --> Settle2: still up -> forceKillRuntimeForStuckVpnTeardown
    Settle2 --> Terminate: still up -> terminateProcessIfTunnelStillUp
    Settle --> Idle: released
    Settle2 --> Idle: released
    Terminate --> [*]
    Idle --> [*]: publish IDLE or ERROR, stopService
```

The last resort kills the process so Android revokes every descriptor, including FoxCore's dup.
This is the self-kill path recorded in the teardown notes.

The Kotlin JNI fence lets `nativeStop` use the full graceful budget plus a 750 ms return-settlement
margin (`FoxCoreNativeEngineOperations.kt:92-100`; `RuntimeStopSupport.kt:20-23,560-568`). With the
production 3,000 ms policy, the native call therefore has 3,750 ms; its outer fail-closed supervisor
has 5,750 ms, covering that complete window, the 1,500 ms `nativeForceKill` fence and 500 ms of
scheduling overhead (`RuntimeStopSupport.kt:513-550`). Timeout arithmetic saturates at `Long.MAX_VALUE`
instead of wrapping to an immediate timeout.

### States

| Layer | Enum | Values |
|---|---|---|
| UI / bridge | `ConnectionState` | `IDLE, CONNECTING, CONNECTED, RECONNECTING, DISCONNECTING, ERROR` |
| Teardown phase | `RuntimeTeardownPhase` | `VPN, TOR, I2P, ANDROID_TUNNEL` |
| Native FSM | `RuntimeState` | `IDLE, PREPARING, STARTING, VALIDATING, RUNNING, RELOADING, STOPPING, KILLING, RESTARTING, ERROR` |
| Supervisor | `RuntimePhase` | `Idle, Preparing, StartingNative, WaitingVpnNetwork, ValidatingTunnel, Connected, Reconnecting, Reloading, Stopping, Killing, Error` |

### Watchdogs

| Watchdog | Behaviour |
|---|---|
| Notification connectivity health | 1 s probe; 3 consecutive failures ⇒ reconnect |
| Child process (i2pd) | event-first via `setUnexpectedExitListener`, slow poll fallback; a child that ran and is later killed ⇒ **full runtime rebuild**, fail-closed |
| Stop / teardown | the 3-stage escalation above |
| Session ticker | one timer, tasks: `traffic`, `app_traffic`, `dns_guard_window`, `notification_health`, `child_watchdog`, `lan_proxy`, `i2p_traffic` |
| Local guard heal | bounded self-heal; deliberately survives an error teardown |
| Native stop reaper (Rust) | 40 attempts × `STOP_TIMEOUT` |

`CoreRuntime::start` acquires a **process-wide worker lease** — only one data-plane worker per
process (`crates/foxcore-runtime/src/start.rs:119-120`).

---

## 4.7 Reachability and remaining gaps

The release surface and the product call graph are different questions:

| Surface | Boundary status | Product reachability |
|---|---|---|
| Engine lifecycle | 33 Rust exports, 32 Java declarations | Complete by design: only legacy `nativeStart` is omitted; every production start passes an Android `Network` handle. |
| Signed DNS bootstrap | Java declaration, `FoxCoreNativeApi` methods and JNI calls are present (`FoxCoreNativeSeam.kt:73-99,219-270`); start dispatch is at `FoxCoreNativeSessionStarter.kt:252-283` | A persisted signed update is verified as part of `nativeStartWithNetworkAndDnsRuleSet`, before the engine is published; the same boundary also supports generation-fenced live signed install. |
| Traffic map | `nativeTrafficMap` is declared and called by `JniFoxCoreNativeApi` (`FoxCoreNativeSeam.kt:284-288`) | `FoxCoreRuntime.runtimeTrafficMapJson` uses the canonical call (`FoxCoreRuntime.kt:714-717`); `nativeConnections` remains a compatibility alias. |
| Link import | The two Rust exports and Java declarations are retained as compatibility-only ABI and classified by `verify-foxcore-jni-seam.sh` | **No Kotlin product wrapper or importer/data-layer call site.** `ProfileImportParser` remains the app's parser. The native DTO is not a drop-in replacement for the app's normalized profile contract. |
| Continuity | The Rust export and Java declaration are retained as compatibility-only ABI | Audit events are parsed and journalled, but the translator keeps automatic continuity defaults and no service/UI action exposes a confirmation token. |
| Live DNS install | `nativeInstallDnsRuleSet` is called through a generation-fenced runtime method after the exact verified bytes are persisted | A stable engine with the same trust adopts the update live and commits the returned revision. Enable or trust rotation changes the immutable fingerprint and uses signed replacement start; no active engine defers to the next start. |
| Native Rust build paths | Release compilation remaps checkout, Cargo-home and Rustup-home variants; the ELF gate rejects detected host roots (`scripts/android-build.sh:67-98`; `scripts/android-elf-gate.sh:138-166,222-225`) | The release proof builds from a second checkout and Cargo home, requires byte-identical `.so` files, and checks both for path leaks (`scripts/reproducible-build.sh:46-150`). The Rust library requires no fixed builder directory. |
| Component/share JNI | 19 exports are frozen in ABI v1 and remain in release ELF files | Guard has no product call site. They do not count toward the separate 33/32 Engine seam. |

### Two link parsers, two answers

```mermaid
flowchart LR
    subgraph R["foxcore-link (Rust) — compatibility-only JNI"]
        R1["vless vmess hysteria2 hy2 trojan ss<br/>wg wireguard socks socks4 socks5<br/>http https naive naive+https anytls"]
    end
    subgraph K["core/importer (Kotlin) — production path"]
        K1["vless trojan naive naive+https ss outline<br/>vmess hy2 hysteria2 tuic anytls wireguard wg"]
    end
    R1 -.->|compatibility-only JNI, no repository call| D1["socks* , http(s)"]
    K1 -.->|Kotlin only| D2["tuic , outline"]
```

`foxcore-link/src/lib.rs:636-650` exposes the partial subscription import intended for applications.
The JNI exports remain frozen, but the repository calls the Kotlin parser and the two disagree on
four schemes. A product switch requires a shared DTO and policy/secret-handling corpus first.

---

## 4.8 Inconsistencies found

The app's direct bridged-Tor proof budget had outgrown the core component's route-agnostic 30 s
CONNECT ceiling, so the authenticated loopback proxy could return `502` before a fresh managed-
bridge circuit was usable. FoxCore 0.0.4 makes only that internal policy route-aware (Tor 75 s,
VPN/direct 30 s); ABI v1, configuration schema v1 and capabilities schema v1 are unchanged
(`Cargo.toml:36-41`; `crates/foxcore-component/src/lan.rs:114-121,286-291`;
`docs/abi.md:7-17`).
