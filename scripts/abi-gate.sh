#!/usr/bin/env bash
# Frozen ABI-v1 exports, C buffer ownership, schemas and on-disk constants.
# Fixtures must not be regenerated as part of an ordinary verification run.
# Usage: scripts/abi-gate.sh [--elf DIR | --record]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

FIXTURES="$ROOT/fixtures/abi/v1"
RECORD=0
ELF_DIR=""

# Cargo resolves a relative CARGO_TARGET_DIR against the workspace and returns
# one canonical absolute path here.  Keeping that resolution in Cargo itself
# prevents the gate from building into a caller-supplied local disk and then
# silently looking for the cdylib in the repository's default target/ tree.
TARGET_DIR="$(
    cargo metadata --locked --format-version 1 --no-deps |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
)" || {
    echo "could not resolve Cargo target_directory" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --record) RECORD=1 ;;
        --elf)
            shift
            ELF_DIR="${1:-}"
            [ -n "$ELF_DIR" ] || {
                echo "--elf needs a directory" >&2
                exit 2
            }
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

status=0
step() { printf '\n== %s ==\n' "$1"; }
fail() {
    printf '!! %s\n' "$1" >&2
    status=1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

DL=""
[ "$(uname -s)" = "Linux" ] && DL="-ldl"
cc -O1 -Wall -Wextra -o "$WORK/capdump" "$ROOT/scripts/abi-capabilities-dump.c" $DL ||
    fail "compiling scripts/abi-capabilities-dump.c"

host_cdylib() {
    local candidate
    for candidate in \
        "$TARGET_DIR/debug/libfoxhole_native.dylib" \
        "$TARGET_DIR/debug/libfoxhole_native.so"; do
        [ -f "$candidate" ] && printf '%s\n' "$candidate" && return 0
    done
    return 1
}

# `nm` output differs between Mach-O and ELF, and Mach-O prefixes every C symbol
# with an underscore that is not part of the name the linker on Android uses.
dump_exports() {
    local object="$1"
    case "$(uname -s)" in
        Darwin) nm -gU "$object" | awk '$2 == "T" || $2 == "S" { print $3 }' | sed 's/^_//' ;;
        *) nm -D --defined-only "$object" | awk '$2 == "T" { print $3 }' ;;
    esac | grep -E '^(Java_|foxhole_core_)' | sort -u
}

# Reduced builds must report unavailable protocols while retaining every frozen JNI export.
if [ "$RECORD" != "1" ]; then
    step "a reduced build reports what it is"
    cargo build -p foxcore-android --no-default-features 2>&1 | tail -3 ||
        fail "cargo build -p foxcore-android --no-default-features"
    if MINIMAL="$(host_cdylib)"; then
        cp "$MINIMAL" "$WORK/minimal-lib"
        if "$WORK/capdump" "$WORK/minimal-lib" >"$WORK/minimal.json"; then
            python3 - "$WORK/minimal.json" "$FIXTURES/capabilities.json" <<'PY' || fail "a reduced build misreports its protocol set"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    reduced = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    reference = json.load(handle)

# Selector is unconditional and serves as the reduced-build control.
always = {"selector"}
problems = []
compiled = {p["id"] for p in reduced["protocols"] if p.get("compiled")}
for entry in reference["protocols"]:
    identifier = entry["id"]
    if identifier in always:
        if identifier not in compiled:
            problems.append(f"{identifier}: absent from a build that always contains it")
    elif identifier in compiled:
        problems.append(f"{identifier}: claims compiled=true in a build without the feature")

# Clients rank profiles by maturity, so absent protocol code must report unavailable.
for entry in reduced["protocols"]:
    identifier = entry["id"]
    state = entry.get("maturity")
    if state is None:
        problems.append(f"{identifier}: declares no maturity")
    elif entry.get("compiled") != (state != "unavailable"):
        problems.append(
            f"{identifier}: compiled={entry.get('compiled')} contradicts maturity={state!r}"
        )

for pinned in ("capabilities_schema_version", "abi_version", "config_schema_version"):
    if reduced[pinned] != reference[pinned]:
        problems.append(f"{pinned}: {reference[pinned]} -> {reduced[pinned]} in a reduced build")

for problem in problems:
    print(f"!! {problem}", file=sys.stderr)
if problems:
    sys.exit(1)
print(f"reduced build declares {len(compiled)} compiled entries: {', '.join(sorted(compiled))}")
PY
        else
            fail "the C ABI contract does not hold for a reduced build"
        fi
        if [ -f "$FIXTURES/exports.txt" ]; then
            dump_exports "$WORK/minimal-lib" >"$WORK/minimal-exports.txt"
            reduced_missing="$(comm -23 "$FIXTURES/exports.txt" "$WORK/minimal-exports.txt")"
            if [ -n "$reduced_missing" ]; then
                fail "turning a protocol off removed a JNI entry point:"
                printf '     %s\n' $reduced_missing >&2
                echo "   A reduced core has to *say* it lacks a protocol, not fail to link." >&2
            else
                echo "all frozen symbols survive a build with no protocol features"
            fi
        fi
    else
        fail "no host cdylib was produced for the reduced build"
    fi
fi

# Host and Android libraries share JNI exports; --elf also checks the supplied Android artifact.
# Use the same explicit shipped feature graph as android-build.sh.
step "host cdylib"
cargo build -p foxcore-android --no-default-features --features shipped 2>&1 | tail -3 ||
    fail "cargo build -p foxcore-android --features shipped"
LIB="$(host_cdylib)" || {
    echo "no host cdylib was produced under $TARGET_DIR/debug" >&2
    exit 1
}
echo "$LIB"

step "exports"
dump_exports "$LIB" >"$WORK/exports.txt"
count="$(wc -l <"$WORK/exports.txt" | tr -d ' ')"
echo "$count exported entry points in the host cdylib"

if [ "$RECORD" = "1" ]; then
    mkdir -p "$FIXTURES"
    cp "$WORK/exports.txt" "$FIXTURES/exports.txt"
    echo "recorded $FIXTURES/exports.txt"
else
    [ -f "$FIXTURES/exports.txt" ] || {
        echo "missing fixture $FIXTURES/exports.txt; run --record once" >&2
        exit 1
    }
    missing="$(comm -23 "$FIXTURES/exports.txt" "$WORK/exports.txt")"
    if [ -n "$missing" ]; then
        fail "ABI v1 exports were removed or renamed:"
        printf '     %s\n' $missing >&2
        echo "   An installed app calling these gets UnsatisfiedLinkError on a device." >&2
    fi
    added="$(comm -13 "$FIXTURES/exports.txt" "$WORK/exports.txt")"
    if [ -n "$added" ]; then
        echo "additive (allowed), not in the v1 fixture:"
        printf '   + %s\n' $added
        echo "   Rollback note: an app that starts calling these cannot be"
        echo "   rolled back onto a library that predates them."
    fi
    [ -n "$missing" ] || echo "all $(wc -l <"$FIXTURES/exports.txt" | tr -d ' ') frozen symbols present"
fi

# -------------------------------------------------------------- capabilities
step "C API and capabilities document"
if [ -x "$WORK/capdump" ]; then
    if "$WORK/capdump" "$LIB" >"$WORK/capabilities.json"; then
        python3 -m json.tool "$WORK/capabilities.json" >"$WORK/capabilities.pretty.json" ||
            fail "the capabilities document is not valid JSON"
    else
        fail "the frozen ABI-v1 C contract does not hold for this build"
    fi
fi

if [ "$RECORD" = "1" ]; then
    if [ -s "$WORK/capabilities.pretty.json" ]; then
        cp "$WORK/capabilities.pretty.json" "$FIXTURES/capabilities.json"
        echo "recorded $FIXTURES/capabilities.json"
    fi
elif [ -s "$WORK/capabilities.pretty.json" ]; then
    python3 "$ROOT/scripts/abi-compare-json.py" --self-test ||
        fail "the capabilities compatibility checker failed its self-test"
    python3 "$ROOT/scripts/abi-compare-json.py" \
        "$FIXTURES/capabilities.json" "$WORK/capabilities.pretty.json" ||
        fail "the capabilities document is no longer backward compatible"
fi

# ------------------------------------------------- rollback-critical constants
# Extracted from the source that produced this build, then compared to what was
# frozen. These are not call-ABI: they are the on-disk contract, and every one of
# them is a way a previous library refuses (or destroys) data written by this one.
step "on-disk format constants"
# awk rather than sed: the alternation this needs is a GNU sed extension, and
# macOS ships BSD sed, where the pattern silently matches nothing — which is a
# gate that passes because it checked zero things.
extract() {
    local file="$1" prefix="$2"
    shift 2
    local name
    for name in "$@"; do
        awk -v name="$name" -v prefix="$prefix" '
            $0 ~ ("^(pub )?(pub\\(crate\\) )?const " name ":") {
                position = index($0, "=")
                value = substr($0, position + 1)
                sub(/^ +/, "", value)
                sub(/; *$/, "", value)
                printf "%s.%s = %s\n", prefix, name, value
            }' "$file"
    done
}
{
    extract crates/foxcore-share/src/lib.rs share \
        MAGIC VERSION CHUNK_BYTES HEADER_BYTES \
        MANIFEST_MAGIC MANIFEST_VERSION MANIFEST_HEADER_BYTES
    extract crates/foxcore-api/src/lib.rs api \
        CORE_ABI_VERSION CAPABILITIES_SCHEMA_VERSION
    extract crates/foxcore-api/src/config/base.rs api SCHEMA_VERSION
} | sort >"$WORK/ondisk.txt"

lines="$(wc -l <"$WORK/ondisk.txt" | tr -d ' ')"
# The floor is the exact count, not a comfortable margin: this check exists
# because a renamed or moved declaration makes `extract` match nothing and the
# gate then passes having compared fewer things than it meant to.
if [ "$lines" -lt 10 ]; then
    fail "only $lines on-disk constants were extracted; a declaration moved or was reshaped"
    cat "$WORK/ondisk.txt"
fi
echo "$lines format constants"

if [ "$RECORD" = "1" ]; then
    cp "$WORK/ondisk.txt" "$FIXTURES/ondisk.txt"
    echo "recorded $FIXTURES/ondisk.txt"
else
    if ! diff -u "$FIXTURES/ondisk.txt" "$WORK/ondisk.txt"; then
        fail "an on-disk format constant changed"
        echo "   A previous library reads these files. Changing a magic, a version" >&2
        echo "   or a parser ceiling means it refuses them. Define and test the" >&2
        echo "   migration and rollback behavior before re-recording this fixture." >&2
    fi
fi

# -------------------------------------------------------------- config corpus
step "frozen v1 config corpus"
cargo test -p foxcore-api --test abi_v1_fixtures 2>&1 | tail -5 ||
    fail "an ABI v1 config fixture no longer parses"

# ------------------------------------------------------------- shipped .so set
if [ -n "$ELF_DIR" ] && [ "$RECORD" != "1" ]; then
    step "shipped Android libraries"
    found=0
    for lib in "$ELF_DIR"/*/libfoxhole_native.so; do
        [ -f "$lib" ] || continue
        found=$((found + 1))
        abi="$(basename "$(dirname "$lib")")"
        # The NDK's readelf, because the host nm cannot read a foreign ELF.
        readelf_bin=""
        for candidate in "${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/29.0.14206865}"/toolchains/llvm/prebuilt/*/bin/llvm-readelf; do
            [ -x "$candidate" ] && readelf_bin="$candidate" && break
        done
        if [ -z "$readelf_bin" ]; then
            fail "llvm-readelf was not found; cannot check $abi"
            continue
        fi
        "$readelf_bin" --dyn-syms --wide "$lib" |
            awk '$4 == "FUNC" && $7 != "UND" { print $8 }' |
            grep -E '^(Java_|foxhole_core_)' | sort -u >"$WORK/elf-$abi.txt"
        elf_missing="$(comm -23 "$FIXTURES/exports.txt" "$WORK/elf-$abi.txt")"
        if [ -n "$elf_missing" ]; then
            fail "$abi: ABI v1 exports missing from the shipped library:"
            printf '     %s\n' $elf_missing >&2
        else
            echo "$abi: all $(wc -l <"$FIXTURES/exports.txt" | tr -d ' ') frozen symbols present"
        fi
    done
    [ "$found" -gt 0 ] || fail "no libfoxhole_native.so under $ELF_DIR"
fi

printf '\n'
if [ "$status" = "0" ]; then
    if [ "$RECORD" = "1" ]; then
        echo "abi-gate: RECORDED — review the diff in fixtures/abi/v1 before committing"
    else
        echo "abi-gate: PASS"
    fi
else
    echo "abi-gate: FAIL"
fi
exit "$status"
