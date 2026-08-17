# 5. Data repository — FoxHole DB

Repo: `foxhole-team/foxhole-db` (public).
Five independent feeds, one signing key, one publication set.

---

## 5.1 Build model

One scheduled GitHub Actions job builds the feeds together and publishes them as one set. Four are
published today; the fifth, TLS fingerprint tables, is built and gated but withheld until the core
revision it mirrors is public.

```mermaid
flowchart TD
    subgraph up["Upstream sources"]
        A["AdGuardSDNSFilter<br/>Filters/filter.txt"]
        B["bridges.torproject.org<br/>moat/circumvention/builtin"]
        C["AssoEchap/stalkerware-indicators<br/>ioc.yaml"]
        D["sapics/ip-location-db<br/>dbip-country"]
        E["foxhole-core<br/>fingerprints/*.json"]
    end

    subgraph build["build-all-feeds.sh"]
        A --> A1["build-adguard-dns-filter.sh<br/>+ foxcore-dns-compile"]
        B --> B1["build-bridges.sh"]
        C --> C1["build-threat-intel.sh"]
        D --> D1["build-geoip.sh"]
        E --> E1["build-fingerprints.sh"]
    end

    A1 & B1 & C1 & D1 & E1 --> S["sign each manifest<br/>ECDSA P-256 / SHA-256"]
    S --> V["verify-feeds.sh<br/>mandatory gate"]
    V -->|pass| P["GitHub Pages + release assets"]
    V -->|fail| X["nothing published"]
```

`build-all-feeds.sh:14-18` always ends with `verify-feeds.sh`. CI runs the same gate at
`.github/workflows/feeds.yml:159`, after signing and before the Pages deploy.

---

## 5.2 Feeds

| Feed | Artifact | Format | Built by | Upstream | Client consumer |
|---|---|---|---|---|---|
| DNS rules | `adguard-dns-filter.fhds` | `foxhole-dns-fst-v1` | `build-adguard-dns-filter.sh:149-176` | AdGuardSDNSFilter (commit pinned) | `DnsFilterUpdateClient` → core |
| Tor bridges | `bridges.json` | `tor-bridges-json` | `build-bridges.sh:41-68` | Tor Moat builtin bridges | `TorBridgeUpdateClient` → `TorBridgeStore` |
| Sentinel threat intel | `threat-intel.json` | `sentinel-threat-intel-json`, doc `schema: 3` | `build-threat-intel.sh:96-275` | stalkerware-indicators (commit pinned) | `ThreatIntelUpdateClient` → `FileThreatIntelStore` |
| GeoIP | `dbip-country-ipv4.csv`, `dbip-country-ipv6.csv` | `dbip-country-csv` | `build-geoip.sh:57-116` | DB-IP Lite via ip-location-db | `GeoIpUpdateClient` → `GeoIpDatabaseStore` |
| TLS fingerprints | `fingerprints.json` | `tls-fingerprint-tables-json` | `build-fingerprints.sh:143-165` | `foxhole-core/fingerprints/` (revision pinned) | `TlsFingerprintUpdateClient` → core |

Each feed also emits `<feed>-manifest.json`, `<feed>-manifest.json.sig`, `<artifact>.sha256` and
`<feed>-source-info.json`. 27 files total; the exact set is a contract file,
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
| `build-adguard-dns-filter.sh:199-215` | the **only** builder that pre-checks the signing key: derives the pubkey DER SHA-256 from the private key and refuses a mismatch before signing; re-verifies its own signature afterwards (`:322-325`) |
| `build-adguard-dns-filter.sh:244` | binds `key_sha256` into the manifest |
| `build-bridges.sh:41-68` | `curl --max-filesize 262144`, re-emitted with `jq --sort-keys --indent 2`. **Not byte-reproducible:** `--sort-keys` orders object keys, not array elements, so two builds of an unchanged upstream can emit the same bridge set in a different order and hash differently |
| `build-threat-intel.sh:96-275` | embedded Python/PyYAML converter, emits document `schema: 3` (`:256`) |
| `build-geoip.sh:131-148` | only manifest with an `artifacts` **array** and a top-level `version` copied from upstream `package.json` |
| `build-fingerprints.sh:118-132` | derives per-profile `fingerprint_sha256` via `jq -cSa` over the `fingerprint` object |

---

## 5.4 Signing

One ECDSA **P-256** key signs all five manifests. Detached `.sig`, DER ASN.1, `SHA256withECDSA`.

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
| Signing sites | `build-adguard-dns-filter.sh:318-344`, `build-bridges.sh:119-146`, `build-threat-intel.sh:391-423`, `build-geoip.sh:169-196`, `build-fingerprints.sh:214-241` |

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
    C4 --> C5["signature verifies :119-127"]
    C5 --> C6["DNS only: expires_at_unix > now"]
    C6 --> C7["generated_at within MAX_AGE_DAYS, default 45"]
    C7 --> C8["per artifact: size then sha256"]
    C8 --> G["fingerprints: re-derive every profile digest :196-221"]
    G -->|any failure| STOP["exit 1 — must not be published"]
    G -->|all pass| OK["publishable"]
```

Feed order: DNS → bridges → threat-intel → geoip → fingerprints (`verify-feeds.sh:173-191`).

> **Ordering note.** The comment at `verify-feeds.sh:118` says "Authenticate bytes before trusting
> manifest fields", but the schema/format/name/`key_sha256` checks at `:99-116` run *before* the
> signature check at `:119-127`. Failures accumulate and the script still exits non-zero, so the
> outcome is unaffected — but the code does not do what the comment claims.

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
    N --> N1["DNS: full re-verify, ruleset.rs:250"]
    N --> N2["fingerprints: re-derive every digest, runtime_tables.rs:213"]
```

Details of both stages are in [03 — Updates and data delivery](03-updates-and-data-delivery.md).

---

## 5.7 Known drift between README and code

| Claim | Reality |
|---|---|
| `README.md:206` — the app "pins this value exactly (`ThreatIntelDocument.SCHEMA`) and rejects any other" | the client accepts a **range**: `schema in 1..SCHEMA` with `SCHEMA = 4` — `core/model/.../ThreatIntelDocument.kt:59-68`. Feed still emits `3`. |
| `build-adguard-dns-filter.sh:20` — "Both consumers deny unknown manifest fields" | true for the Rust core (`foxcore-route/src/ruleset.rs:204-244`, `deny_unknown_fields`), **false** for the Kotlin client (`ignoreUnknownKeys = true`) |
| `README.md:314` — "an ephemeral key in verification" | `feeds.yml` generates no ephemeral key; PR/dev builds run with `FOXHOLE_DNS_REQUIRE_SIGNATURE=false` (`feeds.yml:83`) and are verified unsigned |
| `MIN_APP_VERSION` defaults | `1.0.0-beta1` for DNS/threat-intel vs `1.1.3` for bridges/geoip/fingerprints; CI overrides all to `0.0.1` (`feeds.yml:21`) |

`*-source-info.json` files have no client consumer; they are audit artifacts only.
