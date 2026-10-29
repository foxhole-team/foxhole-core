#!/usr/bin/env bash
set -euo pipefail

CORE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_ROOT="${FOXCORE_SENTINEL_SOURCE_ROOT:-$CORE_ROOT/native/sentinel-yara}"
OUTPUT_ROOT="${FOXCORE_SENTINEL_OUTPUT_ROOT:-$CORE_ROOT/target/sentinel-yara-android}"
IMAGE="${FOXCORE_SENTINEL_DOCKER_IMAGE:-sha256:714fd4e08db9ffb2b890fcded36dcf48136f9f10df4de3146005c09113ade70a}"
REGISTRY_VOLUME="${FOXCORE_SENTINEL_REGISTRY_VOLUME:-foxhole-sentinel-yara-cargo}"
TARGET_VOLUME="${FOXCORE_SENTINEL_TARGET_VOLUME:-foxhole-sentinel-yara-android-target}"
ABIS="${FOXCORE_SENTINEL_ABIS:-armeabi-v7a arm64-v8a x86 x86_64}"
MODE="${1:-build}"
case "$MODE" in build|fetch) ;; *) exit 2 ;; esac
[[ -f "$SOURCE_ROOT/Cargo.lock" && -f "$SOURCE_ROOT/Cargo.toml" ]]
mkdir -p "$OUTPUT_ROOT"
SOURCE_ROOT="$(cd "$SOURCE_ROOT" && pwd)"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
[[ "$OUTPUT_ROOT" != "$SOURCE_ROOT" && "$OUTPUT_ROOT" != "$CORE_ROOT" ]]
[[ "$OUTPUT_ROOT" != "$SOURCE_ROOT/"* ]]
for abi in $ABIS; do
    case "$abi" in armeabi-v7a|arm64-v8a|x86|x86_64) ;; *) exit 2 ;; esac
done

if [[ "$MODE" == "fetch" ]]; then
    docker run --rm --init --cpus=1 --memory=2g --memory-swap=2g \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --mount "type=bind,source=$SOURCE_ROOT,target=/work,readonly" \
        --mount "type=volume,source=$REGISTRY_VOLUME,target=/cache" \
        --env CARGO_HOME=/cache --env CARGO_TARGET_DIR=/tmp/cargo-target \
        --workdir /work "$IMAGE" cargo fetch --locked
    exit
fi

docker run --rm --init --cpus=2 --memory=4g --memory-swap=4g \
    --network=none --cap-drop=ALL --security-opt=no-new-privileges \
    --mount "type=bind,source=$SOURCE_ROOT,target=/work,readonly" \
    --mount "type=bind,source=$OUTPUT_ROOT,target=/output" \
    --mount "type=volume,source=$REGISTRY_VOLUME,target=/cache,readonly" \
    --mount "type=volume,source=$TARGET_VOLUME,target=/build" \
    --env CARGO_HOME=/cargo-cache --env CARGO_TARGET_DIR=/build \
    --env CARGO_NET_OFFLINE=true --env CARGO_BUILD_JOBS=1 \
    --env YRX_REGENERATE_MODULES_RS=false --env "SENTINEL_BUILD_ABIS=$ABIS" \
    --env 'RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384 --remap-path-prefix=/work=sentinel-yara --remap-path-prefix=/cargo-cache=cargo' \
    --workdir /work "$IMAGE" bash -c '
        set -euo pipefail
        mkdir -p "$CARGO_HOME"
        ln -s /cache/registry "$CARGO_HOME/registry"
        for abi in $SENTINEL_BUILD_ABIS; do
            cargo ndk -t "$abi" -P 26 -o /output/jniLibs build --locked --release
            /opt/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf -a "/output/jniLibs/$abi/libfoxhole_sentinel_yara.so" > "/output/$abi-readelf.txt"
        done
        cargo metadata --locked --format-version 1 > /output/cargo-metadata.json
    '
