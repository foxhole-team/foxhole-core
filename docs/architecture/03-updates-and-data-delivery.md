# 3. Updates and data delivery

Two independent channels: **signed data feeds** from FoxHole DB — four published, a fifth (TLS
fingerprint tables) built and verified but withheld until the core revision it mirrors is public —
and the **APK update channel**
from GitHub Releases. They share no trust anchor.

---

## 3.1 The whole picture

```mermaid
flowchart TD
    subgraph db["foxhole-team.github.io/foxhole-db"]
        M1["manifest.json + .sig"]
        M2["bridges-manifest.json + .sig"]
        M3["threat-intel-manifest.json + .sig"]
        M4["geoip-manifest.json + .sig"]
        M5["fingerprint-manifest.json + .sig"]
    end

    subgraph app["FoxHole Guard"]
        PK["pinned ECDSA P-256 key<br/>FoxholeDb.kt:47-64"]
        UC["five update clients<br/>WorkManager scheduled"]
        ST["on-disk stores<br/>atomic replace"]
    end

    subgraph core["FoxCore (libfoxhole_native.so)"]
        RS["DNS rule set<br/>re-verified natively"]
        FP["ClientHello tables"]
    end

    db --> UC
    PK --> UC
    UC --> ST
    ST -->|next engine start| RS
    ST -->|JNI| FP

    GH["api.github.com<br/>foxhole-guard/releases/latest"] --> AU["AppUpdateClient"]
    AU --> AV["AppUpdateApkVerifier<br/>installed-signer match"]
    AV --> INS["user-driven ACTION_VIEW install"]
```

| Channel | Trust anchor | Signature over |
|---|---|---|
| Data feeds | ECDSA P-256 key pinned in the **app** (`FoxholeDb.kt`); the core takes it from engine-config JSON and pins nothing itself | the manifest bytes |
| APK | the certificate the **currently installed app** is signed with | the APK itself (Android signing scheme) |

The APK update manifest is *not* signed by the FoxHole DB key, and there is no static
certificate-hash literal in the client — see [3.6](#36-apk-update-channel).

---

## 3.2 The pinned key

```mermaid
flowchart LR
    PEM["manifest.public.pem<br/>foxhole-db"] --> LIT["FoxholeDb.kt:47-53<br/>PEM literal"]
    LIT --> B64["FoxholeDb.kt:58-64<br/>derived DER + base64 for the core"]
    LIT --> SHA["FoxholeDb.kt:55-56<br/>DER SHA-256 literal"]
    LIT --> VF["requireFoxholeDbManifestSignature<br/>FoxholeDb.kt:148-160"]
```

| Item | Value / location |
|---|---|
| Algorithm | ECDSA P-256, `SHA256withECDSA`, DER signature |
| PEM literal | `app/src/main/kotlin/com/foxhole/guard/runtime/FoxholeDb.kt:47-53` |
| DER SHA-256 | `3acd123f1fd03f8aee97b2e71029ba1f6efdd9c17703419d7cda78a790198d69` — `FoxholeDb.kt:55-56` |
| Base64 DER handed to Rust | derived from the PEM at `FoxholeDb.kt:58-64`, consumed at `DnsFilterAssetInstaller.kt:255-258` |
| Failure mode | `check(...)` → `IllegalStateException`, treated as **non-retryable** |
| Derivation test | `app/src/test/kotlin/com/foxhole/guard/runtime/FoxholeDbSigningKeyContractTest.kt:13-33` |

All five manifest URLs derive from **one** configurable base (`FoxholeDb.kt:29-45`); artifacts resolve
relative to their manifest URL. Redirecting the base moves every feed together. **The pin does not
move with it** — a mirror is only usable if it is published by the same tooling.

Every request additionally passes `requirePublicHttpsUrl(resolveHost = true)`
(`core/network/.../PublicUrlPolicy.kt:67-84`): HTTPS only, and the resolved addresses must not be
private or loopback.

---

## 3.3 Verification chain — DNS rule set (the strictest)

```mermaid
sequenceDiagram
    autonumber
    participant W as DnsFilterUpdateWorker
    participant C as DnsFilterUpdateClient
    participant I as DnsFilterAssetInstaller
    participant S as FoxCoreNativeSessionStarter
    participant N as FoxCore (Rust)

    W->>C: refresh
    C->>C: URL is public HTTPS, host resolves public
    C->>C: GET manifest.json (cap 64 KiB)
    C->>C: GET manifest.json.sig (app cap 72 B)
    C->>C: ECDSA verify vs pinned key
    Note over C: failure = non-retryable
    C->>C: requireValid — schema 2, name, format,<br/>positive sequence, skew at most 600s, validity 1..31d,<br/>key_sha256 == SHA256(pinned DER), core_schema == 1
    C->>C: requireNotRolledBack vs installed sequence
    C->>C: GET artifact (cap 64 MiB)
    C->>C: size, FHDNS1 magic, sha256, counters,<br/>embedded source input_sha256, zeroed reserved
    C->>I: installVerifiedDnsRuleSet
    I->>I: atomic move, manifest written LAST as commit marker
    Note over I: every later read re-verifies signature + key_sha256 + artifact
    I-->>C: persisted bundle
    Note over I,N: an already-running engine is unchanged
    S->>I: prepareVerifiedOrNull on a later session start
    I-->>S: paths for manifest + signature + artifact
    S->>N: nativeStartWithNetworkAndDnsRuleSet(...)
    N->>N: verify_rule_set — signature FIRST, then manifest fields
    N-->>S: handle, or refuse the entire start
```

Client-side sites: `DnsFilterUpdateClient.kt:288-315` (signature), `:317-352` (manifest),
`:354-370` (rollback), `:372-392` (artifact); persistence
`DnsFilterAssetInstaller.kt:48-76`, re-verify on read `:107-139`; atomic start selection
`FoxCoreNativeSessionStarter.kt:63-89,235-266`.

### The native half

The core re-does the whole check on bytes the app already validated —
`foxhole-core/crates/foxcore-route/src/ruleset.rs`:

```mermaid
flowchart TD
    A["verify_rule_set :252"] --> B["validate_input_sizes :382<br/>manifest<=64K, sig<=256B, key<=4K, artifact<=64M"]
    B --> C["ECDSA_P256_SHA256_ASN1 verify :261-264<br/>aws-lc-rs, before any parsing"]
    C --> D["serde parse, deny_unknown_fields :206-244"]
    D --> E["validate_manifest :401"]
    E --> E1["schema==2, format, core_schema==1"]
    E --> E2["name == expected_name"]
    E --> E3["sequence >= minimum_sequence  else Rollback"]
    E --> E4["generated_at <= now + 10 min  else FutureManifest"]
    E --> E5["now < expires_at, 0 < validity <= 31 d"]
    E --> E6["SHA256(public_key) == key_sha256  else WrongKey"]
    E --> E7["artifact size + sha256, entries <= 5,000,000"]
    E --> F["parse_artifact :484<br/>magic FHDNS1\\0\\0, 80-byte header, FST maps"]
    F --> G["counters and source digest must match the manifest :275-279"]
```

`RuleSetError` variants are the refusal vocabulary: `WrongKey`, `InvalidSignature`,
`InvalidManifest`, `UnsupportedManifest`, `WrongIdentity`, `Rollback`, `FutureManifest`,
`ExpiredManifest`, `ArtifactMismatch`, `InvalidArtifact`, `Truncated`, `TooLarge`.

There is deliberately **no** unsigned network update entry point. APK-trusted bytes use
`nativeStartWithNetworkAndTrustedDnsRuleSet`; persisted network bytes use the signed atomic start
(`crates/foxcore-android/src/lib.rs:209-268`). The core also exposes
`nativeInstallDnsRuleSet` for a live signed replacement, but the current app has no production
caller. A downloaded DNS bundle therefore becomes active on the next engine start.

---

## 3.4 Per-feed comparison

| Feed | Manifest schema | Rollback anchor | Expiry | `min_app_version` | Extra artifact check |
|---|---|---|---|---|---|
| DNS | 2 | **monotonic `sequence`**, equal sequence must carry the same sha256 | `expires_at_unix`, ≤31 d | n/a (uses `core_schema`) | FST header, counters, embedded input digest |
| Threat intel | 1 | `generated_at` strictly newer | device rejects age >45 d | **yes** | JSON parse + `supportsSchema` |
| TLS fingerprints | 1 | `generated_at` strictly newer | device rejects age >45 d | **yes** | per-profile digest re-derived, count must match |
| GeoIP | 1 | persisted `generated_at` floor | device rejects age >45 d | **yes** | range re-parse, `MIN_RANGES_PER_FAMILY` |
| Tor bridges | 1 | persisted `generated_at` floor | device rejects age >45 d | **yes** | bridge-line shape, `MIN_BRIDGE_LINES` |

> **Closed.** GeoIP and the bridges mirror had no ordering check: a validly signed *older*
> manifest read as "changed" and installed, and neither enforced `min_app_version`. Both now refuse
> a rollback and check the version. The bridge floor is persisted rather than process-scoped —
> a memory-only floor reopened the window on every cold start.

Rollback floors are stored beside the feed: `sentinel/threat-intel-remote.generated-at`
(`FileThreatIntelStore.kt:47-53`), `fingerprints/fingerprints-remote.generated-at`
(`FileTlsFingerprintStore.kt:45`), the GeoIP stamp (`GeoIpUpdateClient.kt:239-256`) and the Tor
bridge stamp (`TorBridgeUpdateClient.kt:72-94`). The DNS floor is read from the on-disk manifest
(`DnsFilterAssetInstaller.kt:84-100`) and passed to the core as `minimum_sequence`.

DNS carries an explicit expiry and ≤31-day validity window. The other four are bounded on the phone
by `requireFreshFoxholeDbManifest` to at most 45 days old (`FoxholeDb.kt:83-121`), matching the
publisher-side `MAX_AGE_DAYS=45` gate.

---

## 3.5 When a document takes effect

```mermaid
flowchart TD
    subgraph dnsp["DNS rule set — persist first, then live or atomic-start activation"]
        D1["DnsFilterAssetInstaller<br/>atomic three-file bundle"] --> D2["prepareVerifiedOrNull<br/>re-verify on read"]
        D1 --> D6["LiveActivatingDnsRuleSetStore<br/>exact verified bytes"]
        D6 --> D7["FoxCoreRuntime.installDnsRuleSet<br/>generation-fenced"]
        D7 -->|"same trust, stable engine"| D8["nativeInstallDnsRuleSet<br/>commit policy revision"]
        D2 --> D3["FoxCoreDnsRuleSetBootstrap<br/>signedUpdate paths"]
        D3 --> D4["FoxCoreNativeSessionStarter<br/>read bounded bytes"]
        D4 --> D5["nativeStartWithNetworkAndDnsRuleSet<br/>verify before first DNS query"]
        D7 -->|"no stable engine"| D5
    end

    subgraph fpp["TLS fingerprint tables"]
        F1["FileTlsFingerprintStore<br/>temp + rename"] --> F2["TlsFingerprintProvider.documentInEffect"]
        F2 --> F3["TlsFingerprintTableInstaller.install"]
        F3 --> F4["nativeInstallTlsFingerprintTables"]
        F4 -->|"negative return"| F5["nativeClearTlsFingerprintTables<br/>fall back to compiled-in tables"]
    end

    subgraph other["The other three — never touch the data plane"]
        T1["threat-intel.json"] --> T2["FileThreatIntelStore, read lazily by Sentinel"]
        G1["dbip CSVs"] --> G2["GeoIpDatabaseStore + TorGeoIpCountryResolver.invalidateShared"]
        B1["bridges.json"] --> B2["TorBridgeStore, applies at next Tor start"]
    end
```

The DNS immutable fingerprint includes only bootstrap presence, rule-set name and pinned public
key. Therefore enabling filtering or rotating trust replaces the engine atomically, while sequence,
artifact hash and file paths can change through live install without restarting the tunnel.

The DNS download path stops after durable persistence. It does not call
`nativeInstallDnsRuleSet`, so it neither mutates nor restarts a running engine. The next session
loads all three signed files and starts atomically with the verified bundle; a native refusal
fails the start rather than publishing an engine without the requested rules.

What the core does with a fingerprint document (`proto-reality::install_fingerprint_tables`,
`crates/proto-reality/src/reality/runtime_tables.rs:39-70`): bounded size, JSON object, schema check,
no duplicate names, every entry must map to a profile this build already implements, and
`verify_declared_digest` (`:154-169`) re-derives each `fingerprint_sha256`. Any failure refuses the
**whole** document — never a partial install. A feed can change *which bytes a known parrot sends*
and nothing else.

> **Closed.** The installer's comment claimed it ran "after every successful feed update" while it
> had exactly one call site, `FoxholeVpnService.onCreate()` — so a table set downloaded into a live
> VPN process did nothing until the service was recreated. The hand-off now happens in
> `TlsFingerprintUpdateRepository.refreshNow()`, the single choke point all three refresh paths go
> through; app and service share one process, so the core picks it up in place.

---

## 3.6 APK update channel

```mermaid
sequenceDiagram
    autonumber
    participant U as User / AppUpdateWorker
    participant C as AppUpdateClient
    participant V as AppUpdateApkVerifier
    participant P as Android installer

    U->>C: check(currentVersionCode)
    C->>C: GET releases/latest (cap 512 KiB)
    C->>C: find asset update-manifest.json, GET it
    C->>C: versionCode > current, else UpToDate
    C->>C: apkSha256 is 64 hex, else Failed
    U->>C: download()
    C->>C: stream APK, cap 256 MiB, SHA-256 as it goes
    C->>C: announced size match, then digest match
    Note over C: any failure deletes the file
    C->>V: verify(apk, manifest)
    V->>V: packageName == ours
    V->>V: longVersionCode == manifest.versionCode
    V->>V: apkContentsSigners digests == installed app's
    Note over V: empty set is never "trusted"
    V-->>U: Downloaded state reachable only now
    U->>P: ACTION_VIEW, FileProvider uri, user confirms
```

| Fact | Value |
|---|---|
| Default endpoint | `https://api.github.com/repos/foxhole-team/foxhole-guard/releases/latest` — `AppUpdateClient.kt:237` |
| Overridable | yes, `updateSources.appReleasesUrl` + optional bearer token |
| Token scope | attached **only** to the exact configured host; never to the default feed, never across a redirect — `AppUpdateClient.kt:224-232` |
| Manifest | `update-manifest.json` asset: `versionCode, versionName, apkName, apkSha256, notes` — `:28-34` |
| Manifest signed? | **No.** No `.sig` is fetched anywhere in this client |
| Real anchor | signer-certificate set equality with the installed app — `AppUpdateApkVerifier.kt:29-53` |
| Which signers | `apkContentsSigners`, deliberately **not** `signingCertificateHistory`, so a rotated-away key is refused — `:63-76` |
| Static cert pin | none in the client. `foxhole_guard/config/release-cert-sha256.txt` (`e59de248…0df665`) is a **build-time** check, not a runtime one |
| Install | user-driven `ACTION_VIEW`, no `PackageInstaller` session, no silent install — `HomeViewModelAppUpdateSupport.kt:50-78` |
| Channel gate | `github` only; the F-Droid build stamps `updateFloorVersionCode` / `updateSupportedUntilEpochDay` instead — `app/build.gradle.kts:165-174` |

The manifest digest proves the bytes match what the source described; it does **not** prove the
source is ours, because the releases URL and token are user-editable settings. That is why the
verifier re-reads the archive through `PackageManager` before the installer is ever shown.

---

## 3.7 Smaller inconsistencies found

| Finding | Where |
|---|---|
| DNS and threat-intel re-implement signature verification inline (`DnsFilterUpdateClient.kt:288-315`, `ThreatIntelUpdateClient.kt:177-197`) instead of calling the shared `requireFoxholeDbManifestSignature`. GeoIP/bridges/fingerprints use the shared helper. | client |
| The Kotlin JSON parser uses `ignoreUnknownKeys = true` while the Rust core uses `deny_unknown_fields`. The DNS builder comment claims both consumers deny. | both |
| `nativeInstallDnsRuleSet` supports a live signed replacement, but the app update path only persists the bundle. DNS downloads activate on the next engine start. | app ↔ core |
