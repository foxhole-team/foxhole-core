#!/usr/bin/env bash
# Refuse Android JNI artifacts that would only fail when loaded on a device.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB_ROOT="${1:-"$ROOT/target/android-jni"}"
JNI_SOURCE="$ROOT/crates/foxcore-android/src"
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
SOURCE_EXPORTS="$(
    find "$JNI_SOURCE" -type f -name '*.rs' -exec \
        sed -nE 's/.*pub extern "system" fn (Java_[A-Za-z0-9_]+).*/\1/p' {} + |
        sort -u
)"
if [ -z "$SOURCE_EXPORTS" ]; then
    echo "no JNI entry points were found under $JNI_SOURCE" >&2
    exit 1
fi

for symbol in $REQUIRED_EXPORTS; do
    if ! printf '%s\n' "$SOURCE_EXPORTS" | grep -Fqx "$symbol"; then
        echo "required JNI entry $symbol no longer exists in $JNI_SOURCE" >&2
        exit 1
    fi
done

EXPECTED_EXPORTS="$(printf '%s\n%s\n' "$REQUIRED_EXPORTS" "$SOURCE_EXPORTS" |
    sed '/^[[:space:]]*$/d' | sort -u)"

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
    for symbol in android_setsocknetwork android_getaddrinfofornetwork; do
        if ! grep -Eq "UND[[:space:]]+$symbol$" <<<"$symbols"; then
            echo "$abi: expected Android network symbol $symbol is missing" >&2
            lib_status=1
        fi
    done

    if [ "$lib_status" -eq 0 ]; then
        exported="$(printf '%s\n' "$EXPECTED_EXPORTS" | awk 'NF { count += 1 } END { print count + 0 }')"
        echo "$abi: ELF gate PASS (jni_exports=$exported, load_align=16KiB)"
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
