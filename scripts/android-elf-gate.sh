#!/usr/bin/env bash
# Refuse Android JNI artifacts that would only fail when loaded on a device.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB_ROOT="${1:-"$ROOT/target/android-jni"}"
JNI_SOURCE="$ROOT/crates/foxcore-android/src"
ANDROID_MANIFEST="$ROOT/crates/foxcore-android/Cargo.toml"
# The cargo feature that carries the component and share entry points, and the
# one source file they live in. Both names are checked against the crate below
# rather than trusted, because this gate's whole claim is that those exports are
# not in a release artifact.
GATED_FEATURE="mini-platform"
GATED_SOURCE="$JNI_SOURCE/ecosystem.rs"
# Kept in step with scripts/android-build.sh.
NDK_VERSION="29.0.14206865"

find_ndk() {
    if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
        printf '%s\n' "$ANDROID_NDK_HOME"
        return
    fi
    for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk"; do
        if [ -n "$sdk" ] && [ -d "$sdk/ndk/$NDK_VERSION" ]; then
            printf '%s\n' "$sdk/ndk/$NDK_VERSION"
            return
        fi
    done
    return 1
}

NDK="$(find_ndk)" || {
    echo "Android NDK $NDK_VERSION was not found; set ANDROID_NDK_HOME." >&2
    exit 1
}

READELF=""
for candidate in "$NDK"/toolchains/llvm/prebuilt/*/bin/llvm-readelf; do
    if [ -x "$candidate" ]; then
        READELF="$candidate"
        break
    fi
done
[ -n "$READELF" ] || {
    echo "llvm-readelf was not found under $NDK." >&2
    exit 1
}

# The floor. These are the entries whose absence would not look like a build
# failure — the library would load, the app would start, and one feature would
# be dead. Deriving the list purely from the source (below) cannot catch that:
# a deleted `#[unsafe(no_mangle)] fn` would quietly shrink the requirement to
# match, and the gate would pass on the very change it exists to catch.
#
# The `FoxholeNativeJournal` entries used to be part of this floor. They are
# gone with the Rust journal port: the journal is the app's, in
# Kotlin, and a floor that names symbols no build can export is a gate that
# fails on every build rather than on a regression.
REQUIRED_EXPORTS="
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeVersion
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeAbiVersion
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeCapabilities
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStart
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartWithNetwork
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStop
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStats
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeConnections
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeDrainEvents
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeReloadPolicy
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeNetworkChanged
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeNetworkChangedWithHandle
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartWithNetworkAndTrustedDnsRuleSet
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeInstallDnsRuleSet
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeForceKill
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLastPolicyError
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLastStopDiagnostics
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeConfirmLanNetwork
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStartLanProxy
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeStopLanProxy
Java_com_foxhole_core_runtime_FoxholeNativeEngine_nativeLanProxyStatus
"
# The four LAN entries are on the floor for the reason the floor exists: the LAN
# proxy is reachable *only* through them, so losing one is a feature that is
# silently dead on a device rather than a build that fails. The library still
# loads, the tunnel still runs, and the toggle does nothing.
#
# The four entries before them were added because the list had drifted the wrong way:
# it pinned `nativeImportLink` and `nativeImportSubscription`, which no caller in
# the app has, while leaving unpinned the symbols the production start and
# teardown paths actually resolve. A floor that guards what nobody calls and not
# what everybody does is a floor in name only. `nativeImportLink` and
# `nativeImportSubscription` are still built and still covered by the derived
# ceiling below; they are simply no longer treated as release-critical.

# And the ceiling: every JNI entry the crate actually defines. A hand-kept list
# drifts the moment someone adds a function — this gate shipped for a while
# without nativeInstallDnsRuleSet and nativeStartWithNetworkAndDnsRuleSet for
# exactly that reason. Deriving it means a new entry point is covered the day it
# is written rather than the day someone remembers this file.
list_exports() {
    sed -nE 's/.*pub extern "system" fn (Java_[A-Za-z0-9_]+).*/\1/p' "$@" | sort -u
}

ALL_SOURCE_EXPORTS="$(
    find "$JNI_SOURCE" -type f -name '*.rs' -exec \
        sed -nE 's/.*pub extern "system" fn (Java_[A-Za-z0-9_]+).*/\1/p' {} + |
        sort -u
)"
if [ -z "$ALL_SOURCE_EXPORTS" ]; then
    echo "no JNI entry points were found under $JNI_SOURCE" >&2
    exit 1
fi

# --------------------------------------------------------------- the gated set
# Nineteen exports — `FoxholeNativeComponents_*` and `FoxholeNativeShares_*` —
# are behind the `mini-platform` cargo feature, which no release build enables.
# They are groundwork for a later release and stay in the repository; what must
# not happen is that they reach a phone, because the Java classes they are named
# for do not exist in the app and an export nothing can call is attack surface
# that delivers nothing.
#
# Three checks, because any one of them alone is defeatable by a one-line edit:
#
#   1. The feature is not in the crate's `shipped` set. This is the check that
#      catches the re-enabling *before* an artifact exists, and it reads the
#      manifest rather than the build command.
#   2. The module declaration still carries the `cfg`. Deleting that attribute
#      would put the exports back in every build while leaving both the feature
#      and this script looking correct.
#   3. The symbols are absent from each library below. That is the one that
#      speaks about the artifact rather than about the source.
[ -f "$GATED_SOURCE" ] || {
    echo "$GATED_SOURCE does not exist; the gated export set cannot be derived." >&2
    exit 1
}
GATED_EXPORTS="$(list_exports "$GATED_SOURCE")"
if [ -z "$GATED_EXPORTS" ]; then
    echo "no JNI entry points were found in $GATED_SOURCE." >&2
    echo "   If the component and share surface moved, move GATED_SOURCE with it." >&2
    exit 1
fi

# `shipped = [...]` is a multi-line array, so the extraction is scoped to it
# rather than grepping the whole manifest — the feature has its own definition
# line further down, and matching that would make this check always pass.
if awk '
        /^shipped = \[/ { inside = 1; next }
        inside && /^\]/ { inside = 0 }
        inside { print }
    ' "$ANDROID_MANIFEST" | grep -Fq "\"$GATED_FEATURE\""; then
    echo "$GATED_FEATURE is in the crate's shipped feature set." >&2
    echo "   That puts these exports into every release artifact:" >&2
    printf '     %s\n' $GATED_EXPORTS >&2
    echo "   The Java classes they are named for do not exist in the app. Wire" >&2
    echo "   them first, then move them out of the gate deliberately." >&2
    exit 1
fi

if ! grep -Fq "#[cfg(feature = \"$GATED_FEATURE\")]" "$JNI_SOURCE/lib.rs"; then
    echo "lib.rs no longer gates a module behind $GATED_FEATURE." >&2
    echo "   Without that attribute the exports in $GATED_SOURCE are in every" >&2
    echo "   build regardless of the feature list." >&2
    exit 1
fi

# What a release artifact must contain: everything the crate defines, minus the
# gated file's exports.
SOURCE_EXPORTS="$(comm -23 \
    <(printf '%s\n' "$ALL_SOURCE_EXPORTS") \
    <(printf '%s\n' "$GATED_EXPORTS"))"

for symbol in $REQUIRED_EXPORTS; do
    if ! printf '%s\n' "$SOURCE_EXPORTS" | grep -Fqx "$symbol"; then
        echo "required JNI entry $symbol is not a shipped export of $JNI_SOURCE" >&2
        exit 1
    fi
done

EXPECTED_EXPORTS="$(printf '%s\n%s\n' "$REQUIRED_EXPORTS" "$SOURCE_EXPORTS" |
    sed '/^[[:space:]]*$/d' | sort -u)"

# A build that deliberately asked for the feature is a real workflow — the same
# escape hatch the non-ARM ABIs get below, and read from the same variable
# scripts/android-build.sh takes its feature list from. It is not a release: a
# gated symbol present without this is a failure.
GATED_ALLOWED=0
case ",${FOXCORE_ANDROID_FEATURES-},"  in
    *",$GATED_FEATURE,"*) GATED_ALLOWED=1 ;;
esac

status=0
checked=0
for lib in "$LIB_ROOT"/*/libfoxhole_native.so; do
    [ -f "$lib" ] || continue
    checked=$((checked + 1))
    lib_status=0
    abi="$(basename "$(dirname "$lib")")"
    dynamic="$("$READELF" -d "$lib")"
    headers="$("$READELF" -h "$lib")"
    programs="$("$READELF" -lW "$lib")"
    symbols="$("$READELF" -Ws "$lib")"

    case "$abi" in
        arm64-v8a) machine="AArch64" ;;
        armeabi-v7a) machine="ARM" ;;
        x86_64) machine="Advanced Micro Devices X86-64" ;;
        x86) machine="Intel 80386" ;;
        *)
            echo "$abi: unknown ABI directory" >&2
            status=1
            continue
            ;;
    esac

    # The shipped set is the two ARM ABIs. A non-ARM library is still *checkable*
    # — the emulator build is a real workflow — but it has to have been asked
    # for, by the same variable that asks the build script for it. Without this
    # an x86_64 artifact left over from an emulator session sits in the jniLibs
    # tree, passes every check below, and is packaged into a release: the gate
    # would have verified it correctly and shipped it anyway.
    case "$abi" in
        arm64-v8a | armeabi-v7a) ;;
        *)
            case " ${FOXCORE_ANDROID_ABIS:-} " in
                *" $abi "*)
                    echo "$abi: not a shipped ABI; checked because FOXCORE_ANDROID_ABIS asked for it"
                    ;;
                *)
                    echo "$abi: not a shipped ABI (only arm64-v8a and armeabi-v7a ship)." >&2
                    echo "   Build it deliberately with FOXCORE_ANDROID_ABIS=$abi, or delete it" >&2
                    echo "   from $LIB_ROOT before packaging." >&2
                    status=1
                    continue
                    ;;
            esac
            ;;
    esac

    if ! grep -Eq "Machine:[[:space:]]+$machine$" <<<"$headers"; then
        echo "$abi: ELF machine does not match its ABI directory" >&2
        lib_status=1
    fi
    if ! grep -Eq 'NEEDED.*\[libandroid\.so\]' <<<"$dynamic"; then
        echo "$abi: libandroid.so is missing from DT_NEEDED" >&2
        lib_status=1
    fi
    if ! grep -Eq 'BIND_NOW|FLAGS_1.*NOW' <<<"$dynamic"; then
        echo "$abi: immediate binding is not enabled" >&2
        lib_status=1
    fi
    if grep -Eq 'TEXTREL|RPATH|RUNPATH' <<<"$dynamic"; then
        echo "$abi: forbidden TEXTREL/RPATH/RUNPATH entry" >&2
        lib_status=1
    fi
    if ! grep -Eq '^  GNU_RELRO' <<<"$programs"; then
        echo "$abi: GNU_RELRO is missing" >&2
        lib_status=1
    fi
    if ! grep -Eq '^  GNU_STACK.* RW ' <<<"$programs" || grep -Eq '^  GNU_STACK.*RWE' <<<"$programs"; then
        echo "$abi: stack is executable or malformed" >&2
        lib_status=1
    fi

    # 16 KiB pages, on every ABI including 32-bit ARM, where it needs both
    # -Wl,-z,max-page-size and -Wl,-z,common-page-size. The segment count is
    # checked too: an alignment test with nothing to test passes, and "no LOAD
    # segments" is not a pass.
    loads="$(awk '$1 == "LOAD" { print $NF }' <<<"$programs")"
    load_count="$(awk 'NF { count += 1 } END { print count + 0 }' <<<"$loads")"
    if [ -z "$loads" ] || [ "${load_count:-0}" -lt 1 ]; then
        echo "$abi: no LOAD segments to check alignment on" >&2
        lib_status=1
    elif grep -Eqv '^0x4000$' <<<"$loads"; then
        echo "$abi: a LOAD segment is not aligned for 16 KiB Android pages" >&2
        lib_status=1
    fi

    for symbol in $EXPECTED_EXPORTS; do
        if ! grep -Eq "[[:space:]]$symbol$" <<<"$symbols"; then
            echo "$abi: missing JNI export $symbol" >&2
            lib_status=1
        fi
    done
    # The other direction, and the reason the two lists are derived separately: a
    # missing export is a feature that is dead on a device, and a *present* gated
    # export is a surface the app cannot reach but an attacker can.
    gated_present=""
    for symbol in $GATED_EXPORTS; do
        if grep -Eq "[[:space:]]$symbol$" <<<"$symbols"; then
            gated_present="$gated_present $symbol"
        fi
    done
    if [ -n "$gated_present" ]; then
        if [ "$GATED_ALLOWED" -eq 1 ]; then
            echo "$abi: $GATED_FEATURE exports present; checked because FOXCORE_ANDROID_FEATURES asked for it"
        else
            echo "$abi: $GATED_FEATURE exports are in the library:" >&2
            printf '     %s\n' $gated_present >&2
            echo "   No app class calls these, so they are only reachable by something" >&2
            echo "   that is not the app. Build without $GATED_FEATURE, or ask for it by" >&2
            echo "   name in FOXCORE_ANDROID_FEATURES if this is not a release." >&2
            lib_status=1
        fi
    fi
    for symbol in android_setsocknetwork android_getaddrinfofornetwork; do
        if ! grep -Eq "UND[[:space:]]+$symbol$" <<<"$symbols"; then
            echo "$abi: expected Android network symbol $symbol is missing" >&2
            lib_status=1
        fi
    done

    if [ "$lib_status" -eq 0 ]; then
        exported="$(printf '%s\n' "$EXPECTED_EXPORTS" | awk 'NF { count += 1 } END { print count + 0 }')"
        gated="$(printf '%s\n' "$GATED_EXPORTS" | awk 'NF { count += 1 } END { print count + 0 }')"
        echo "$abi: ELF gate PASS (jni_exports=$exported, gated_absent=$gated, load_align=16KiB)"
    else
        echo "$abi: ELF gate FAIL" >&2
        status=1
    fi
done

if [ "$checked" -eq 0 ]; then
    echo "No libfoxhole_native.so files found under $LIB_ROOT." >&2
    exit 1
fi
exit "$status"
