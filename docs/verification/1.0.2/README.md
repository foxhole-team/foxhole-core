# Core 1.0.2 verification data

`verification-handoff.json` binds `android-binary-binding.json` and the unchanged `advisories.json` by SHA-256. Verify its detached owner signature with the public key and fingerprint policy pinned to Core commit `c06c3c43670163f293773f5dfcb0576dfdfceebe`:

```sh
gpg --verify verification-handoff.json.asc verification-handoff.json
```

The binary mapping lists the ten released Guard 1.0.2 and VPN 1.0.1 APK URLs and digests, eight distinct Core libraries and four Guard Sentinel libraries across four ABIs. Each entry identifies its packaged library and embedded SBOM/coverage bytes. Core producer `66286391…`, the signed source bank `13d7deff…`, public source `c06c3c43…`, and the 529-input manifest `013c64d8…` retain separate roles.

Sentinel uses retained native compilation under the current source context. Its producer digest and packaged digest differ because Android packaging strips symbols. The mapping records both digests and the exactly reproduced Android NDK 29 stripping step. VPN reference Sentinel attribution is outside its packaged-native scope.

The handoff records 25 TLS tests, five host descriptor-lifecycle tests and the own-crate deprecated-API compile check. It also lists the remaining emSign-chain, adversarial PQ/session-store, QUIC DoS and Android FD-runtime scopes. The RustSec report remains **FAILED** for three Sentinel Wasmtime findings; the observed feature graph and source reasoning do not replace that result. These files do not claim a complete release gate or independent reproducibility, and create no new Core release or consumer pin.
