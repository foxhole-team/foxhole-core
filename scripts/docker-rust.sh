#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
IMAGE="${FOXCORE_DOCKER_IMAGE:-foxhole/rust-lab:1.97.1}"
CACHE="${FOXCORE_DOCKER_CACHE:-foxhole-rust-1-97-1}"

if [ "${1:-}" = image ]; then
    exec docker build --tag "$IMAGE" --file "$ROOT/docker/Dockerfile" "$ROOT/docker"
fi
if [ "$#" -eq 0 ]; then
    echo "Usage: scripts/docker-rust.sh image | <command> [arguments...]" >&2
    exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Build the pinned lab first: scripts/docker-rust.sh image" >&2
    exit 1
fi
git_mount=()
if git_dir="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    git_mount=(--mount "type=bind,source=$git_dir,target=$git_dir,readonly")
fi

exec docker run --rm --init \
    --cpus="${FOXCORE_DOCKER_CPUS:-2}" \
    --memory="${FOXCORE_DOCKER_MEMORY:-6g}" \
    --security-opt=no-new-privileges \
    --mount "type=bind,source=$ROOT,target=/work,readonly" \
    --mount "type=volume,source=$CACHE-cargo,target=/cargo-cache" \
    --mount "type=volume,source=$CACHE-target,target=/build" \
    ${git_mount[@]+"${git_mount[@]}"} \
    --env "CARGO_BUILD_JOBS=${FOXCORE_DOCKER_JOBS:-2}" \
    "$IMAGE" "$@"
