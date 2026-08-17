#!/usr/bin/env bash
# Execute the Android-only branches of the JNI boundary on a real device, and
# print a table.
#
#   scripts/device-abi-invariants.sh [serial]
#
# docs/24-unsafe-audit.md §9 opens with the honest sentence this script exists to
# retire: everything under `#[cfg(target_os = "android")]` was checked by reading
# it and by `cargo check --target aarch64-linux-android`, and executed never. The
# invariants in question are about bionic, ART and the kernel — a `getSystemService`
# that leaves an exception pending, a descriptor that is not the character device
# `VpnService.establish()` promises, a panic barrier under ART's unwinder — and no
# host build can settle any of them.
#
# So: one command, no configuration, no server, no subscription. The harness uses
# a `direct` outbound, which is the one `OutboundConfig` variant behind no cargo
# feature, so the run means the same thing on a minimal build as on the shipped
# one. On a phone that already has the harness installed it takes under a minute.
#
#   SKIP_BUILD=1   reuse whatever is installed (no cargo, no gradle, no install)
#   ADB=...        path to adb
#
# What it does NOT do is decide anything itself. Every verdict is a line the
# on-device harness printed; a check that could not run says SKIP and a run that
# died halfway leaves the summary line missing, which this reports as missing
# evidence rather than as a pass.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
PKG="com.foxhole.coretest"
ACTIVITY="$PKG/.MainActivity"
APK="$ROOT/android-testapp/app/build/outputs/apk/debug/app-debug.apk"
# The harness's tag and the core's own. Both are needed: the table comes from the
# harness, and the cross-check for the descriptor shape comes from the core.
APP_TAG="FoxholeCoreTest"
CORE_TAG="FoxCore"
TIMEOUT="${TIMEOUT:-180}"

[ -x "$ADB" ] || {
    echo "adb not found at $ADB; set ADB=/path/to/adb" >&2
    exit 2
}

serial="${1:-}"
if [ -z "$serial" ]; then
    # One device, no ambiguity. Two devices and a guess would run against the
    # wrong phone and produce a table that looks exactly as trustworthy — and
    # this repository ships to two, an arm64 Pixel and a 32-bit Realme.
    #
    # Written for bash 3.2, which is what macOS has: `mapfile` is bash 4 and
    # would silently leave the array empty here.
    attached="$("$ADB" devices | awk '$2 == "device" { print $1 }')"
    count="$(printf '%s\n' "$attached" | grep -c '[^[:space:]]')"
    if [ "$count" != "1" ]; then
        echo "expected exactly one attached device, found $count:" >&2
        "$ADB" devices >&2
        echo "pass the serial: scripts/device-abi-invariants.sh <serial>" >&2
        exit 2
    fi
    serial="$(printf '%s\n' "$attached" | head -1)"
fi

device() { "$ADB" -s "$serial" "$@"; }

echo "== device =="
device shell getprop ro.product.model | tr -d '\r'
device shell getprop ro.build.version.sdk | tr -d '\r' | sed 's/^/api /'

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    echo
    echo "== build =="
    # The same script the release uses, so the .so under test is the shipped
    # feature set rather than whatever `cargo build` defaults to today.
    "$ROOT/scripts/android-build.sh" || exit 1
    # Gradle wants the SDK from `local.properties` or the environment, and
    # `local.properties` is gitignored — so on a clean checkout the build fails
    # with "SDK location not found" and nothing about this run. Everything else
    # here already assumes the standard location; so does this.
    if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ] &&
        [ ! -f "$ROOT/android-testapp/local.properties" ]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    fi
    (cd "$ROOT/android-testapp" && ./gradlew --quiet :app:assembleDebug) || exit 1
    [ -f "$APK" ] || {
        echo "no APK at $APK" >&2
        exit 1
    }
    echo
    echo "== install =="
    device install -r -g "$APK" || exit 1
    # Without this the first `am start` raises the consent dialog, and with
    # nobody to tap it the run dies as "VPN permission denied".
    device shell appops set "$PKG" ACTIVATE_VPN allow
fi

echo
echo "== run =="
device logcat -c
device shell am start -n "$ACTIVITY" --es cmd invariants >/dev/null || exit 1

waited=0
while [ "$waited" -lt "$TIMEOUT" ]; do
    if device logcat -d -s "$APP_TAG" | rg -q 'INVARIANT_RUN end'; then
        break
    fi
    sleep 3
    waited=$((waited + 3))
done

log="$(device logcat -d -s "$APP_TAG")"
core="$(device logcat -d -s "$CORE_TAG")"

echo
echo "== invariants =="
printf '%s\n' "$log" | rg 'INVARIANT' || true

echo
echo "== the core's own record of the descriptor =="
# `take_tun_fd` records a descriptor that is not a character device and starts
# anyway. Nothing is printed when the shape is the expected one, so absence here
# is the ordinary result — and it is only meaningful next to the harness's own
# `tun_fd_is_a_character_device` line, which asks the kernel independently.
if printf '%s\n' "$core" | rg -q 'tun-fd:'; then
    printf '%s\n' "$core" | rg 'tun-fd:'
else
    echo "no tun-fd anomaly recorded by the core"
fi

echo
if ! printf '%s\n' "$log" | rg -q 'INVARIANT_RUN end'; then
    echo "device-abi-invariants: INCOMPLETE — the run never reached its summary line." >&2
    echo "   Neither a pass nor a fail: the harness stopped, and what it stopped in" >&2
    echo "   the middle of is in the full logcat." >&2
    exit 1
fi
printf '%s\n' "$log" | rg 'INVARIANT_RUN end'
if printf '%s\n' "$log" | rg -q 'INVARIANT .* FAIL'; then
    echo "device-abi-invariants: FAIL" >&2
    exit 1
fi
if printf '%s\n' "$log" | rg -q 'INVARIANT .* SKIP'; then
    echo "device-abi-invariants: PASS with skips — a skipped invariant is not a checked one."
    exit 0
fi
echo "device-abi-invariants: PASS"
