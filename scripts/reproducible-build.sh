#!/usr/bin/env bash
# Compare a clean release build with one from a moved checkout and CARGO_HOME.
# Kept as a release gate because two cold Android builds are too costly for CI.
#
# Usage:
#   scripts/reproducible-build.sh                 # both runs, arm64-v8a
#   FOXCORE_ANDROID_ABIS="arm64-v8a armeabi-v7a" scripts/reproducible-build.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

ABIS="${FOXCORE_ANDROID_ABIS:-arm64-v8a}"
WORK_REQUESTED="${FOXCORE_REPRO_WORK:-${TMPDIR:-/tmp}/foxcore-repro.$$}"
case "$WORK_REQUESTED" in
    /*) ;;
    *) WORK_REQUESTED="$PWD/$WORK_REQUESTED" ;;
esac
PRIMARY_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

# Two cold targets need roughly 6 GiB per ABI.
available_gib() {
    df -g "$ROOT" 2>/dev/null | awk 'NR == 2 { print $4 }' ||
        df -BG "$ROOT" 2>/dev/null | awk 'NR == 2 { gsub(/G/, "", $4); print $4 }'
}
space="$(available_gib)"
needed=$((6 * $(printf '%s' "$ABIS" | wc -w | tr -d ' ')))
if [ -n "$space" ] && [ "$space" -lt "$needed" ]; then
    echo "Not enough disk: ${space} GiB free, this needs about ${needed} GiB for ${ABIS}." >&2
    echo "Free space or narrow FOXCORE_ANDROID_ABIS, rather than trusting a partial run." >&2
    exit 1
fi

mkdir -p "$WORK_REQUESTED"
WORK="$(cd "$WORK_REQUESTED" && pwd -P)"
echo "workspace for this run: $WORK"

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

path_leak_count() {
    local lib="$1"
    shift
    {
        strings -a "$lib" |
            grep -E '/(Users|home|root|builds)/|^/(private|tmp|var/folders)/' || true
        for host_root in "$@"; do
            [ -n "$host_root" ] || continue
            strings -a "$lib" | grep -F "$host_root" || true
        done
    } | sort -u | wc -l | tr -d ' '
}

run() {
    local name="$1" source="$2" cargo_home="$3"
    echo
    echo "== $name: building from $source =="
    mkdir -p "$WORK/$name"
    (
        cd "$source" || exit 1
        CARGO_HOME="$cargo_home" \
            FOXCORE_ANDROID_ABIS="$ABIS" FOXCORE_JNI_OUTPUT="$WORK/$name" \
            ./scripts/android-build.sh
    ) >"$WORK/$name.log" 2>&1 || {
        echo "$name failed; see $WORK/$name.log" >&2
        tail -20 "$WORK/$name.log" >&2
        exit 1
    }
    grep -E 'ELF gate|Finished' "$WORK/$name.log" | tail -3
}

for abi_target in aarch64-linux-android armv7-linux-androideabi; do
    rm -rf "$ROOT/target/$abi_target"
done
run clean "$ROOT" "$PRIMARY_CARGO_HOME" || exit 1

# Exclude `.git` and `target` so the moved build is source-only and cold.
MOVED_SOURCE="$WORK_REQUESTED/moved-src"
MOVED_CARGO_HOME="$WORK_REQUESTED/moved-cargo-home"
rm -rf "$MOVED_SOURCE"
mkdir -p "$MOVED_SOURCE"
rsync -a --exclude target --exclude .git "$ROOT/" "$MOVED_SOURCE/" || exit 1
rm -rf "$MOVED_CARGO_HOME"
mkdir -p "$MOVED_CARGO_HOME"
for cache in registry git; do
    if [ -e "$PRIMARY_CARGO_HOME/$cache" ]; then
        cp -al "$PRIMARY_CARGO_HOME/$cache" "$MOVED_CARGO_HOME/" || exit 1
    fi
done
for abi_target in aarch64-linux-android armv7-linux-androideabi; do
    rm -rf "$ROOT/target/$abi_target"
done
run moved "$MOVED_SOURCE" "$MOVED_CARGO_HOME" || exit 1

echo
echo "== comparison =="
status=0
for abi in $ABIS; do
    a="$WORK/clean/$abi/libfoxhole_native.so"
    b="$WORK/moved/$abi/libfoxhole_native.so"
    if [ ! -f "$a" ] || [ ! -f "$b" ]; then
        echo "$abi: one of the two builds produced no library" >&2
        status=1
        continue
    fi
    if cmp -s "$a" "$b"; then
        echo "$abi: identical  $(sha256 "$a")"
    else
        echo "$abi: DIFFERS" >&2
        echo "   clean $(sha256 "$a")" >&2
        echo "   moved $(sha256 "$b")" >&2
        cmp "$a" "$b" >&2 || true
        status=1
    fi
done

echo
echo "absolute paths compiled into the artifact:"
for abi in $ABIS; do
    clean_lib="$WORK/clean/$abi/libfoxhole_native.so"
    moved_lib="$WORK/moved/$abi/libfoxhole_native.so"
    [ -f "$clean_lib" ] && [ -f "$moved_lib" ] || continue
    clean_count="$(
        path_leak_count "$clean_lib" "$ROOT" "$PRIMARY_CARGO_HOME" \
            "${RUSTUP_HOME:-$HOME/.rustup}"
    )"
    moved_count="$(
        path_leak_count "$moved_lib" "$MOVED_SOURCE" "$WORK/moved-src" \
            "$MOVED_CARGO_HOME" "$WORK/moved-cargo-home" \
            "${RUSTUP_HOME:-$HOME/.rustup}"
    )"
    echo "   $abi: clean=$clean_count moved=$moved_count"
    if [ "$clean_count" != "0" ] || [ "$moved_count" != "0" ]; then
        status=1
    fi
done

echo
if [ "$status" = "0" ]; then
    echo "reproducible-build: IDENTICAL"
else
    echo "reproducible-build: NOT REPRODUCIBLE"
fi
echo "logs and artifacts kept in $WORK"
exit "$status"
