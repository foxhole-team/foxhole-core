# Android router source contract v1

This bundle freezes four package-normalized router source files, the exact Java JNI facade, and shared synthetic catalog/TLS fixtures. It is metadata, not a Core native producer pin or release qualification.

The manifest filename contains the SHA-256 of its exact bytes. Each app vendors that same manifest and fixtures and pins its hash in `config/android-router-contract.json`. Its offline source CI invokes the versioned checker against its own checkout. The optional peer-root check reads a supplied checkout against this same content pin; neither app depends on a peer commit or mutable branch.

The canonical Core clean public commit is explicitly pending in app references. Root fills that origin only after the actual commit exists. This does not replace, change or infer any Core 1.0.1 binary, source-producer or release binding.

Only the exact app router package prefix is normalized; whitespace, line endings and all other bytes remain significant. The Java files must match byte for byte. A changed contract requires a newly addressed manifest and review of both app pins. The checker and fixture-test template have their own content hashes in the manifest.

Each app stores fixtures once in the standard `app/src/test/resources/android-router-contract-v1` classpath directory; Gradle inputs remain unchanged. Both copies of `RouterContractFixtureTest.kt` use the production catalog parser and TLS trust-manager admission logic. TLS certificates are explicit stubs with synthetic bytes; these cases do not qualify certificate DER parsing, a TLS handshake, device networking, or JNI runtime behavior.

## Optional JNI evidence

Source-only CI reports JNI `NOT_CHECKED`. A lab caller can require the Java exports as a subset of one selected Core ELF's actual dynamic exports:

```text
python3 scripts/check-android-router-contract.py --root . --require-jni \
  --elf /absolute/path/to/selected/libfoxhole_native.so \
  --elf-sha256 ACTUAL_SELECTED_NATIVE_PIN --abi arm64-v8a \
  --readelf /absolute/path/to/llvm-readelf
```

The checker verifies the ELF's exact caller-supplied native pin and ABI before invoking readelf. It never executes the library. Supply the actual existing producer/delivery pin, not this metadata manifest hash.

Alternatively, pass `--exports-manifest FILE --exports-sha256 ACTUAL_VERIFIED_MANIFEST_SHA256 --elf-sha256 ACTUAL_SELECTED_NATIVE_PIN --abi ABI`. This manifest must already be independently verified and hash pinned by its caller. Its shape is `{ "schema": 1, "abi": "...", "elfSha256": "...", "exports": ["..."] }`. No future export evidence or digest is asserted here.

JNI checks reject missing Java-required exports. The known `nativeStart` compatibility export is explicitly accepted; other additional exports are counted without being declared missing or invalid. Existing app producer, signature and JNI seam gates remain separate and unchanged.

Prepared checker and fixture cases require their own behavioral validation. Authoring/syntax checks alone do not mark these cases passed.
