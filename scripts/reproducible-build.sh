#!/usr/bin/env bash
# Build the Android library twice and compare the bytes.
#
# The claim "reproducible build" is worth exactly as much as the last time
# someone ran this. It is not in CI: two release builds of this workspace cost
# about twenty minutes and several gigabytes of target directory, which is a
# per-release check rather than a per-commit one.
#
# Two runs, chosen because they fail differently:
#
#   clean  — same source path, target directory removed in between. Catches
#            anything that leaks the build *order* or a stale intermediate into
#            the artifact.
#   moved  — the source tree copied to a different absolute path, with its own
#            target directory. Catches an absolute path compiled into the
#            binary, which is the usual reason two developers get different
#            bytes from the same commit.
#
# What neither run can catch: both use the same CARGO_HOME, and registry paths
# are compiled into the artifact, so this proves reproducibility for one
# machine's layout rather than across independent builders.
#
# Usage:
#   scripts/reproducible-build.sh                 # both runs, arm64-v8a
#   FOXCORE_ANDROID_ABIS="arm64-v8a armeabi-v7a" scripts/reproducible-build.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

ABIS="${FOXCORE_ANDROID_ABIS:-arm64-v8a}"
WORK="${FOXCORE_REPRO_WORK:-${TMPDIR:-/tmp}/foxcore-repro.$$}"

# A release target directory for one ABI is roughly 4.5 GiB, and the moved run
# needs its own. Refusing early is better than dying half way through a
# twenty-minute build and leaving both.
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

mkdir -p "$WORK"
echo "workspace for this run: $WORK"

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

run() {
    local name="$1" source="$2"
    echo
    echo "== $name: building from $source =="
    mkdir -p "$WORK/$name"
    (
        cd "$source" || exit 1
        FOXCORE_ANDROID_ABIS="$ABIS" FOXCORE_JNI_OUTPUT="$WORK/$name" \
            ./scripts/android-build.sh
    ) >"$WORK/$name.log" 2>&1 || {
        echo "$name failed; see $WORK/$name.log" >&2
        tail -20 "$WORK/$name.log" >&2
        exit 1
    }
    grep -E 'ELF gate|Finished' "$WORK/$name.log" | tail -3
}

# Run one: the repository itself, from a removed target directory.
for abi_target in aarch64-linux-android armv7-linux-androideabi; do
    rm -rf "$ROOT/target/$abi_target"
done
run clean "$ROOT" || exit 1

# Run two: the same source at a different absolute path, own target directory.
# .git is excluded so the copy is source only; target is excluded so the second
# run really is cold.
rm -rf "$WORK/moved-src"
mkdir -p "$WORK/moved-src"
rsync -a --exclude target --exclude .git "$ROOT/" "$WORK/moved-src/" || exit 1
for abi_target in aarch64-linux-android armv7-linux-androideabi; do
    rm -rf "$ROOT/target/$abi_target"
done
run moved "$WORK/moved-src" || exit 1

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
        # Naming the first divergent offset turns "not reproducible" into
        # something someone can actually look at.
        cmp "$a" "$b" >&2 || true
        status=1
    fi
done

echo
echo "absolute paths compiled into the artifact:"
for abi in $ABIS; do
    lib="$WORK/clean/$abi/libfoxhole_native.so"
    [ -f "$lib" ] || continue
    count="$(strings -a "$lib" | grep -cE '^/(Users|home|root|private)/' || true)"
    echo "   $abi: $count"
done

echo
if [ "$status" = "0" ]; then
    echo "reproducible-build: IDENTICAL"
else
    echo "reproducible-build: NOT REPRODUCIBLE"
fi
echo "logs and artifacts kept in $WORK"
exit "$status"
