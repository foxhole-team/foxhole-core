#!/usr/bin/env bash
set -uo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
PKG="com.foxhole.coretest"
ACTIVITY="$PKG/.MainActivity"
FILES="/data/user/0/$PKG/files"
TAG="FoxholeCoreTest"
HERE="$(cd "$(dirname "$0")" && pwd)"

serial="${1:?usage: device-silent-datapath-hunt.sh <serial> <config-name> [runs] [outdir]}"
config="${2:?needs a config name, e.g. vless}"
runs="${3:-30}"
outdir="${4:-$PWD/foxcore-silent-hunt-$(date +%Y%m%d-%H%M%S)}"
soak="${FOXCORE_HUNT_SOAK:-18}"

mkdir -p "$outdir"
device() { "$ADB" -s "$serial" "$@"; }

echo "hunting on $serial with $config, $runs runs, log in $outdir"

for run in $(seq 1 "$runs"); do
    device shell am force-stop "$PKG" >/dev/null 2>&1
    sleep 2
    device logcat -c >/dev/null 2>&1
    device shell am start -n "$ACTIVITY" --es cmd start --es cfg "$FILES/$config.json" \
        --ez with_network true --ei soak "$soak" >/dev/null 2>&1

    line=""
    waited=0
    limit=$((soak + 120))
    while [ "$waited" -lt "$limit" ]; do
        line="$(device logcat -d -s "$TAG" 2>/dev/null | grep 'STATS AFTER_SOAK' | tail -1)"
        [ -n "$line" ] && break
        if device logcat -d -s "$TAG" 2>/dev/null |
                grep -qE 'RESULT start_failed|CMD start failed'; then
            break
        fi
        sleep 3
        waited=$((waited + 3))
    done

    tun="$(device shell ip addr show tun0 2>/dev/null | head -1)"
    printf '%s\n' "$line" >> "$outdir/all-runs.txt"

    if [ -z "$line" ]; then
        started="$(device logcat -d -s "$TAG" 2>/dev/null |
            grep -cE 'RESULT start_failed|CMD start failed')"
        echo "run $run/$runs: no AFTER_SOAK line after ${waited}s (start_failed hits=$started)"
        continue
    fi

    field() { printf '%s\n' "$line" | tr ' ' '\n' | grep "^$1=" | cut -d= -f2; }
    connected="$(field connected)"
    dns="$(field dns)"
    up="$(field up)"
    down="$(field down)"
    active="$(field active)"
    rejected="$(field rejected)"
    blocked="$(field blocked)"
    split="$(field split_stack)"
    rev="$(field rev)"

    echo "run $run/$runs: connected=$connected dns=$dns up=$up down=$down active=$active rejected=$rejected blocked=$blocked split_stack=$split rev=$rev"

    if [ "$connected" = "true" ] && [ "${dns:-1}" = "0" ] \
       && [ "${up:-1}" = "0" ] && [ "${down:-1}" = "0" ]; then
        echo
        echo "CAUGHT on run $run: connected with nothing moving"
        echo "  tun0: $tun"
        {
            echo "caught_on_run=$run"
            echo "stats_line=$line"
            echo "tun0=$tun"
        } > "$outdir/CAUGHT.txt"
        "$HERE/device-state-collect.sh" "$serial" "$outdir/capture" \
            "silent datapath caught on hunt run $run"
        echo "engine left RUNNING on $serial for further probing - stop it by hand"
        exit 0
    fi
done

echo
echo "not reproduced in $runs runs; per-run counters in $outdir/all-runs.txt"
device shell am start -n "$ACTIVITY" --es cmd stop >/dev/null 2>&1
sleep 4
device shell am force-stop "$PKG" >/dev/null 2>&1
exit 1
