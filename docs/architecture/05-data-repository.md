# 5. Data repository — FoxHole DB

Repo: `foxhole-team/foxhole-db` (public).
Five independent feeds, one signing key, one publication set.

---

## 5.1 Build model

One scheduled GitHub Actions job builds all five feeds together and publishes them as one set.

```mermaid
flowchart TD
    subgraph up["Upstream sources"]
        A["AdGuardSDNSFilter<br/>Filters/filter.txt"]
        AC["AdGuard / EasyPrivacy / HaGezi<br/>immutable category source pins"]
        B["bridges.torproject.org<br/>moat/circumvention/builtin"]
        C["AssoEchap/stalkerware-indicators<br/>ioc.yaml"]
        D["sapics/ip-location-db<br/>dbip-country"]
        E["foxhole-core<br/>fingerprints/*.json"]
    end

    subgraph build["build-all-feeds.sh"]
        A --> A1["build-adguard-dns-filter.sh<br/>+ foxcore-dns-compile"]
        AC --> AC1["build-dns-categories.sh<br/>four tagged-input variants"]
        B --> B1["build-bridges.sh"]
        C --> C1["build-threat-intel.sh"]
        D --> D1["build-geoip.sh"]
        E --> E1["build-fingerprints.sh"]
    end

    A1 & AC1 & B1 & C1 & D1 & E1 --> S["sign nine manifests<br/>ECDSA P-256 / SHA-256"]
    S --> V["verify-feeds.sh<br/>mandatory gate"]
    V -->|pass| P["GitHub Pages + release assets"]
    V -->|fail| X["nothing published"]
```

`build-all-feeds.sh:8-22` builds every feed and always ends with `verify-feeds.sh`. CI runs the same
gate at `.github/workflows/feeds.yml:160`, after signing and before the Pages deploy.

---

## 5.2 Feeds

| Feed | Artifact | Format | Built by | Upstream | Client consumer |
|---|---|---|---|---|---|
| DNS rules | `adguard-dns-filter.fhds` | `foxhole-dns-fst-v1` | `build-adguard-dns-filter.sh:152-179` | AdGuardSDNSFilter (commit pinned) | `DnsFilterUpdateClient` → core |
| Categorized DNS | four `dns-categories/<variant>/dns-categories.fhds` artifacts | `foxhole-dns-fst-v1`, manifest schema3 | `build-dns-categories.sh:51-78` | pinned AdGuard, EasyPrivacy and HaGezi inputs | `DnsFilterUpdateClient.downloadCategorized` → staged store → core (`foxhole_guard/app/src/main/kotlin/com/foxhole/guard/runtime/DnsFilterUpdateClient.kt:260`) |
| Tor bridges | `bridges.json` | `tor-bridges-json` | `build-bridges.sh:44-71` | Tor Moat builtin bridges | `TorBridgeUpdateClient` → `TorBridgeStore` |
| Sentinel threat intel | `threat-intel.json` | `sentinel-threat-intel-json`, doc `schema: 3` | `build-threat-intel.sh:99-276` | stalkerware-indicators (commit pinned) | `ThreatIntelUpdateClient` → `FileThreatIntelStore` |
| GeoIP | `dbip-country-ipv4.csv`, `dbip-country-ipv6.csv` | `dbip-country-csv` | `build-geoip.sh:60-119` | DB-IP Lite via ip-location-db | `GeoIpUpdateClient` → `GeoIpDatabaseStore` |
| TLS fingerprints | `fingerprints.json` | `tls-fingerprint-tables-json` | `build-fingerprints.sh:146-168` | `foxhole-core/fingerprints/` (revision pinned) | `TlsFingerprintUpdateClient` → core |

The five root feeds emit manifests, signatures, artifact checksums and provenance files.
Each categorized DNS variant adds a manifest, signature, artifact and checksum; its source
descriptors are bound inside the canonical manifest. The exact 43-file set is the contract
`.github/published-files.txt`, diffed by `verify-feeds.sh:54-67`.

---

## 5.3 What each builder does

```mermaid
flowchart LR
    subgraph dns["DNS — the only compiled artifact"]
        d1["clone AdGuardSDNSFilter<br/>pin commit"] --> d2["Filters/filter.txt"]
        d2 --> d3["foxcore-dns-compile<br/>cargo -p foxcore-route"]
        d3 --> d4[".fhds<br/>80-byte header + 2 FST maps"]
        d4 --> d5["manifest: size, sha256,<br/>block/allow counters,<br/>source input_sha256"]
    end
```

```mermaid
flowchart LR
    subgraph rest["The other four — transcode and hash"]
        r1["fetch upstream"] --> r2["normalise<br/>jq --sort-keys / python / csv"]
        r2 --> r3["artifact bytes"]
        r3 --> r4["manifest: size + sha256<br/>+ generated_at + min_app_version"]
    end
```

Notable per-builder detail:

| Script | Detail |
|---|---|
| `build-adguard-dns-filter.sh:204-224`, `build-dns-categories.sh:34-44` | both DNS builders derive the public-key DER SHA-256 and refuse a signing-key mismatch before signing |
| `build-adguard-dns-filter.sh:225-250` | binds `key_sha256` into the manifest |
| `build-bridges.sh:44-71` | `curl --max-filesize 262144`, re-emitted with `jq --sort-keys --indent 2`. **Not byte-reproducible:** `--sort-keys` orders object keys, not array elements, so two builds of an unchanged upstream can emit the same bridge set in a different order and hash differently |
| `build-threat-intel.sh:99-276` | embedded Python/PyYAML converter, emits document `schema: 3` (`:243-250`) |
| `build-geoip.sh:121-150` | only manifest with an `artifacts` **array** and a top-level `version` copied from upstream `package.json` |
| `build-fingerprints.sh:80-122` | derives per-profile `fingerprint_sha256` via `jq -cSa` over the `fingerprint` object |

The DNS fallback compiler preserves the Core lockfile (`foxhole-db/build-adguard-dns-filter.sh:70`). Each builder treats `WORK_DIR` as a parent and owns a unique temporary child; EXIT cleanup removes only that child unless `KEEP_WORK_DIR=true` (`foxhole-db/build-threat-intel.sh:8-11`, `:27-32`). Numeric indicators are validated with Python `ipaddress`, scoped addresses are excluded, and IPv6 is canonicalized without DNS (`foxhole-db/build-threat-intel.sh:147-158`).

---

## 5.4 Signing

One ECDSA **P-256** key signs all nine manifests. Detached `.sig`, DER ASN.1, `SHA256withECDSA`.

```mermaid
flowchart LR
    M["manifest.json"] --> SG["openssl dgst -sha256 -sign<br/>FOXHOLE_DNS_SIGNING_KEY_PEM"]
    SG --> SIG["manifest.json.sig"]
    PK["manifest.public.pem<br/>prime256v1"] --> VF["openssl dgst -sha256 -verify"]
    SIG --> VF
    M --> VF
```

| Fact | Value |
|---|---|
| Algorithm | ECDSA P-256 / SHA-256 — **not** Ed25519 |
| Public key, committed | `foxhole-db/manifest.public.pem` |
| Key DER SHA-256 | `3acd123f1fd03f8aee97b2e71029ba1f6efdd9c17703419d7cda78a790198d69` |
| Bound into DNS manifest | `manifest.json` → `key_sha256` (same value) |
| Signing secret | repo secret `FOXHOLE_DNS_SIGNING_KEY_PEM`, `main` publication only |
| Publication signing | `.github/workflows/feeds.yml:142-160` verifies the supplied key, signs five root and four categorized manifests, then verifies the whole candidate |

All six builders accept a private-key file or the common `FOXHOLE_DNS_SIGNING_KEY_PEM` input.
Materialized temporary PEM keys are removed on EXIT even when `KEEP_WORK_DIR=true` retains
other build work. Caller-supplied key files remain owned by the caller
(`foxhole-db/build-adguard-dns-filter.sh:30-41`; `foxhole-db/build-dns-categories.sh:11-26`).

The `.sig` files are produced only into `public/`; they are never committed. `feeds.yml:35` asserts
`test ! -e manifest.json.sig` on the tree. The committed root snapshots therefore **cannot** be
signature-checked locally — by design.

---

## 5.5 `verify-feeds.sh` — the publication gate

`./verify-feeds.sh <dir>`; no secrets needed, uses the committed public key.

```mermaid
flowchart TD
    P0["dir, key, contract file present"] --> P1["no symlinks or special files<br/>verify-feeds.sh:50-53"]
    P1 --> P2["file set == published-files.txt<br/>exact diff -u :54-67"]
    P2 --> F["per feed"]

    F --> C1["manifest exists, valid JSON"]
    C1 --> C2["schema / format / name match"]
    C2 --> C3["artifact filename set matches"]
    C3 --> C4["DNS only: key_sha256 == SHA256 of pubkey DER"]
    C4 --> C5["signature verifies :127-135"]
    C5 --> C6["DNS only: expires_at_unix > now"]
    C6 --> C7["typed bounded epochs<br/>generated_at within 45 days and at most one day ahead"]
    C7 --> C8["per artifact: size then sha256"]
    C8 --> G["fingerprints: re-derive every profile digest :206-229"]
    G -->|any failure| STOP["exit 1 — must not be published"]
    G -->|all pass| CAT["verify four canonical categorized variants<br/>signature, freshness, provenance, hash and header"]
    CAT -->|pass| OK["publishable"]
    CAT -->|fail| STOP
```

Feed order: DNS → bridges → threat-intel → geoip → fingerprints, followed by all four
categorized variants (`verify-feeds.sh:185-203`, `:239-245`).

Structural checks intentionally run before signature verification so the local publisher gate can
aggregate candidate diagnostics (`verify-feeds.sh:108-135`). A publishable run still requires every
detached signature to verify; none of the parsed fields is accepted by a consumer on the strength
of this diagnostic ordering.
Untrusted epoch fields are validated as bounded integral JSON numbers before Bash arithmetic;
strings cannot be interpreted as shell expressions. Generation more than one day in the future
also fails the publisher gate (`foxhole-db/verify-feeds.sh:72-91`, `:140-160`).

---

## 5.6 What the client re-checks on receipt

Nothing the repository asserts is taken on trust. The receipt-side checks live in the client and,
for DNS and TLS fingerprints, again inside the Rust core.

```mermaid
flowchart LR
    R["foxhole-db public/"] -->|HTTPS| K["Kotlin update client"]
    K --> K1["pinned-key signature"]
    K1 --> K2["manifest field validation"]
    K2 --> K3["rollback floor"]
    K3 --> K4["size + sha256"]
    K4 --> K5["artifact structure re-parse"]
    K5 --> N["Rust core"]
    N --> N1["DNS: full re-verify, ruleset.rs:248-295"]
    N --> N2["fingerprints: re-derive every digest, runtime_tables.rs:154-169"]
```

---

### Categorized compiler input

`foxcore-dns-compile --tagged-input INPUT.json --output OUTPUT.fhds` is separate from the
legacy input/category/allowlist mode. It accepts canonical closed schema1 tagged input:
unique sorted lowercase suffixes and category memberships, source descriptors, tier identity
and curated global allow suffixes. The tagged-input file is bounded to 256 MiB; legacy list input and native artifacts stay bounded to 64 MiB. Canonical bytes are compared during serialization without materializing a second JSON tree. Header `source_sha256` binds the exact input bytes
(`crates/foxcore-route/src/ruleset.rs:390`,
`crates/foxcore-route/src/ruleset/categories.rs:134`).

Source-specific exceptions must be applied by the producer to that source before union.
They cannot become global exceptions that unblock another source's malicious membership.
Only explicitly curated compatibility or user exceptions belong in the global allow map.
The native compiler validates representation and provenance shape; it does not fetch or
classify upstream domains. Actual provider commits, licenses and category coverage remain
builder inputs requiring verification.

The legacy schema2 producer and four schema3 category producers are separate delivery paths.
The category builder resolves one source-built pinned compiler, verifies immutable original
input digests, applies source-specific exceptions before union and emits canonical signed
variants. Publication comparison includes their semantic identity and expiry, while the release
archive contains their nested paths (`foxhole-db/build-all-feeds.sh:9`;
`foxhole-db/build-dns-categories.sh:51`; `foxhole-db/dns-categories-manifest.py:67`;
`foxhole-db/should-publish-feeds.py:18`; `foxhole-db/.github/workflows/feeds.yml:155,179`).

Ads uses named AdGuard Base/Mobile adserver sections. Normal trackers combines unconditional
EasyPrivacy and AdGuard third-party tracking servers; Pro adds first-party/mobile sections.
Telemetry is limited to the named Huawei, Samsung, OPPO/Realme, Vivo and Xiaomi OEM inputs.
Malicious medium/full selects the corresponding HaGezi TIF input. Unsupported rule forms are
skipped rather than widened; no new global vendor whitelist is inserted. AdGuard and HaGezi
are GPL-3.0; EasyPrivacy is used under GPL-3.0-or-later with EasyList author attribution
(`foxhole-db/dns-category-sources/normal-medium.json:1`;
`foxhole-db/dns-category-sources/pro-full.json:1`; `foxhole-db/LICENSES.md:14`).

The legacy local builder now defaults to the official tracked generated gh-pages filter, with
explicit reference overrides retained. Existing CI already used that branch. Local unsigned
artifacts and temporary-key verification do not establish owner-signed publication, current
upstream freshness after a pin ages, or Android runtime acceptance
(`foxhole-db/build-adguard-dns-filter.sh:11`; `foxhole-db/.github/workflows/feeds.yml:95`).

## 5.7 Inconsistencies found

The former 27-file/five-manifest description omitted categorized DNS. The publication contract
contains 43 files and nine signed manifests (`foxhole-db/.github/published-files.txt:1-43`).
Guard packages four categorized seeds with APK-signing trust; these do not claim downloaded
manifest expiry or sequence (`foxhole_guard/app/src/main/kotlin/com/foxhole/guard/runtime/DnsFilterAssetInstaller.kt:54-82`).

The old publication comparison removed timestamps only from manifests, while the fingerprint
artifact digest still changed with its own build timestamp. The comparison now verifies current
manifest signatures and fingerprint bytes, compares semantic table/provenance content, and
requires renewal after 21 days or within seven days of DNS expiry
(`foxhole-db/should-publish-feeds.py:62`). CI caches the immutable feed compiler inputs without
changing which source revision builds the format (`foxhole-db/.github/workflows/feeds.yml:83`). `*-source-info.json` files are
publication audit artifacts by design; the client consumes the signed manifests and artifacts,
not these provenance companions.

The prior numeric-IP converter accepted malformed IPv6 through a character-only regular expression. The current converter validates the address grammar and normalizes equivalent spellings (`foxhole-db/build-threat-intel.sh:147-158`). Caller-owned working directories are no longer removed by cleanup (`foxhole-db/build-threat-intel.sh:8-11`, `:27-32`).
