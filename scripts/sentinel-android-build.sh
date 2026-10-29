#!/usr/bin/env bash
set -euo pipefail

CORE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_ROOT="${FOXCORE_SENTINEL_SOURCE_ROOT:-$CORE_ROOT/native/sentinel-yara}"
OUTPUT_ROOT="${FOXCORE_SENTINEL_OUTPUT_ROOT:-$CORE_ROOT/target/sentinel-yara-android}"
ABIS="${FOXCORE_SENTINEL_ABIS:-armeabi-v7a arm64-v8a x86 x86_64}"
[[ -f "$SOURCE_ROOT/Cargo.lock" && -f "$SOURCE_ROOT/Cargo.toml" ]]
: "${ANDROID_NDK_HOME:?Pinned Android NDK is required}"
mkdir -p "$OUTPUT_ROOT"
SOURCE_ROOT="$(cd "$SOURCE_ROOT" && pwd)"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
[[ "$OUTPUT_ROOT" != "$SOURCE_ROOT" && "$OUTPUT_ROOT" != "$CORE_ROOT" ]]
[[ "$OUTPUT_ROOT" != "$SOURCE_ROOT/"* ]]
for abi in $ABIS; do
    case "$abi" in armeabi-v7a|arm64-v8a|x86|x86_64) ;; *) exit 2 ;; esac
done
export YRX_REGENERATE_MODULES_RS=false
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384 --remap-path-prefix=$SOURCE_ROOT=sentinel-yara"
cd "$SOURCE_ROOT"
for abi in $ABIS; do
    cargo ndk -t "$abi" -P 26 -o "$OUTPUT_ROOT/jniLibs" build --locked --release
done
