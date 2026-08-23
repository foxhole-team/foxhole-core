#!/usr/bin/env bash
# Refuse Android JNI artifacts that would only fail when loaded on a device.
set -euo pipefail

ROOT_LOGICAL="$(cd "$(dirname "$0")/.." && pwd -L)"
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
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

absolute_input_path() {
    local path="$1"
    case "$path" in
        /*) printf '%s\n' "$path" ;;
        *) printf '%s\n' "$ROOT_LOGICAL/$path" ;;
    esac
}

logical_path() {
    local path="$1"
    if [ -d "$path" ]; then
        (cd "$path" && pwd -L)
    else
        printf '%s\n' "$path"
    fi
}

physical_path() {
    local path="$1"
    if [ -d "$path" ]; then
        (cd "$path" && pwd -P)
    else
        printf '%s\n' "$path"
    fi
}

LIB_ROOT_RAW="$(absolute_input_path "$LIB_ROOT")"
LIB_ROOT_LOGICAL="$(logical_path "$LIB_ROOT_RAW")"
LIB_ROOT_PHYSICAL="$(physical_path "$LIB_ROOT_RAW")"
CARGO_HOME_RAW="$(absolute_input_path "${CARGO_HOME:-$HOME/.cargo}")"
CARGO_HOME_LOGICAL="$(logical_path "$CARGO_HOME_RAW")"
CARGO_HOME_PHYSICAL="$(physical_path "$CARGO_HOME_RAW")"
RUSTUP_HOME_RAW="$(absolute_input_path "${RUSTUP_HOME:-$HOME/.rustup}")"
RUSTUP_HOME_LOGICAL="$(logical_path "$RUSTUP_HOME_RAW")"
RUSTUP_HOME_PHYSICAL="$(physical_path "$RUSTUP_HOME_RAW")"
NDK_LOGICAL="$(logical_path "$NDK")"
NDK_PHYSICAL="$(physical_path "$NDK")"

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

ALL_SOURCE_EXPORTS="$(
    find "$JNI_SOURCE" -type f -name '*.rs' -exec \
        sed -nE 's/.*pub extern "system" fn (Java_[A-Za-z0-9_]+).*/\1/p' {} + |
        sort -u
)"
if [ -z "$ALL_SOURCE_EXPORTS" ]; then
    echo "no JNI entry points were found under $JNI_SOURCE" >&2
    exit 1
fi
SOURCE_EXPORTS="$ALL_SOURCE_EXPORTS"

for symbol in $REQUIRED_EXPORTS; do
    if ! printf '%s\n' "$SOURCE_EXPORTS" | grep -Fqx "$symbol"; then
        echo "required JNI entry $symbol is not a shipped export of $JNI_SOURCE" >&2
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

    leaked_host_paths="$(
        {
            # These roots are distinctive enough to find even when a panic or
            # linker string prefixes the path. `/private/` and `/tmp/` stay
            # anchored because dependency paths such as `src/private/de.rs`
            # are valid virtual paths after remapping.
            strings -a "$lib" |
                grep -E '/(Users|home|root|builds)/|^/(private|tmp|var/folders)/' || true
            for host_root in \
                "$ROOT_LOGICAL" \
                "$ROOT" \
                "$LIB_ROOT_RAW" \
                "$LIB_ROOT_LOGICAL" \
                "$LIB_ROOT_PHYSICAL" \
                "$CARGO_HOME_RAW" \
                "$CARGO_HOME_LOGICAL" \
                "$CARGO_HOME_PHYSICAL" \
                "$RUSTUP_HOME_RAW" \
                "$RUSTUP_HOME_LOGICAL" \
                "$RUSTUP_HOME_PHYSICAL" \
                "$HOME/" \
                "$NDK" \
                "$NDK_LOGICAL" \
                "$NDK_PHYSICAL"; do
                [ -n "$host_root" ] || continue
                strings -a "$lib" | grep -F "$host_root" || true
            done
        } | sort -u | sed -n '1,5p'
    )"

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
    if [ -n "$leaked_host_paths" ]; then
        echo "$abi: build-host paths are embedded in the Rust library:" >&2
        printf '   %s\n' "$leaked_host_paths" >&2
        lib_status=1
    fi

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
        echo "$abi: ELF gate PASS (jni_exports=$exported, load_align=16KiB, host_paths=0)"
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
