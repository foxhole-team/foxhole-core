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

`build-all-feeds.sh:8-18` builds every feed and always ends with `verify-feeds.sh`. CI runs the same
gate at `.github/workflows/feeds.yml:159`, after signing and before the Pages deploy.

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
| `build-adguard-dns-filter.sh:198-220` | the **only** builder that pre-checks the signing key: derives the pubkey DER SHA-256 from the private key and refuses a mismatch before signing; re-verifies its own signature afterwards (`:322-325`) |
| `build-adguard-dns-filter.sh:222-247` | binds `key_sha256` into the manifest |
| `build-bridges.sh:41-68` | `curl --max-filesize 262144`, re-emitted with `jq --sort-keys --indent 2`. **Not byte-reproducible:** `--sort-keys` orders object keys, not array elements, so two builds of an unchanged upstream can emit the same bridge set in a different order and hash differently |
| `build-threat-intel.sh:96-275` | embedded Python/PyYAML converter, emits document `schema: 3` (`:242-249`) |
| `build-geoip.sh:118-147` | only manifest with an `artifacts` **array** and a top-level `version` copied from upstream `package.json` |
| `build-fingerprints.sh:77-119` | derives per-profile `fingerprint_sha256` via `jq -cSa` over the `fingerprint` object |

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
| Signing sites | `build-adguard-dns-filter.sh:318-344`, `build-bridges.sh:118-145`, `build-threat-intel.sh:377-409`, `build-geoip.sh:167-194`, `build-fingerprints.sh:195-222` |

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

Structural checks intentionally run before signature verification so the local publisher gate can
aggregate candidate diagnostics (`verify-feeds.sh:99-127`). A publishable run still requires every
detached signature to verify; none of the parsed fields is accepted by a consumer on the strength
of this diagnostic ordering.

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

## 5.7 Inconsistencies found

No open publication-gate inconsistency was found in this pass. `*-source-info.json` files are
publication audit artifacts by design; the client consumes the signed manifests and artifacts,
not these provenance companions.
