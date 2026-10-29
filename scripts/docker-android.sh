#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
IMAGE="${FOXCORE_ANDROID_DOCKER_IMAGE:-foxhole/android-rust-lab:1.97.1-ndk29}"
CACHE="${FOXCORE_ANDROID_DOCKER_CACHE:-foxhole-android-rust-1-97-1-ndk29}"
OUTPUT="${FOXCORE_JNI_OUTPUT:-$ROOT/target/android-jni}"

if [ "${1:-}" = image ]; then
    exec docker build --platform linux/amd64 --tag "$IMAGE" \
        --file "$ROOT/docker/Dockerfile.android" "$ROOT/docker"
fi
if [ "$#" -eq 0 ]; then
    echo "Usage: scripts/docker-android.sh image | build | <command> [arguments...]" >&2
    exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Build the pinned Android lab first: scripts/docker-android.sh image" >&2
    exit 1
fi
if [ "$1" = build ]; then
    shift
    [ "$#" -eq 0 ] || { echo "build does not accept command arguments" >&2; exit 2; }
    set -- bash -c 'cargo fetch --locked && scripts/android-build.sh'
fi
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
git_mount=()
if git_dir="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    git_mount=(--mount "type=bind,source=$git_dir,target=$git_dir,readonly")
fi

exec docker run --rm --init --platform linux/amd64 \
    --cpus="${FOXCORE_DOCKER_CPUS:-2}" \
    --memory="${FOXCORE_DOCKER_MEMORY:-6g}" \
    --security-opt=no-new-privileges \
    --mount "type=bind,source=$ROOT,target=/work,readonly" \
    --mount "type=bind,source=$OUTPUT,target=/output" \
    --mount "type=volume,source=$CACHE-cargo,target=/cargo-cache" \
    --mount "type=volume,source=$CACHE-target,target=/build" \
    ${git_mount[@]+"${git_mount[@]}"} \
    --env "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.97.1}" \
    --env "CARGO_NET_OFFLINE=${CARGO_NET_OFFLINE:-false}" \
    --env "CARGO_BUILD_JOBS=${FOXCORE_DOCKER_JOBS:-2}" \
    --env "FOXCORE_ANDROID_ABIS=${FOXCORE_ANDROID_ABIS:-arm64-v8a armeabi-v7a x86 x86_64}" \
    --env "FOXCORE_ANDROID_FEATURES=${FOXCORE_ANDROID_FEATURES-shipped}" \
    --env FOXCORE_JNI_OUTPUT=/output \
    "$IMAGE" "$@"
