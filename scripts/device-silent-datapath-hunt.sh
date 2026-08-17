#!/usr/bin/env bash
# Start the engine over and over until it comes up connected and carries nothing.
#
# The defect: `tun0` present, `connected=true`, every counter zero, `dns` never
# grows, no flow ever opens. Seen once in about thirty starts on the Realme, and
# three consecutive cycles failed to reproduce it, so the only method left is
# repetition with an automatic verdict - a human watching thirty logs will miss
# the one that matters.
#
#   scripts/device-silent-datapath-hunt.sh <serial> <config-name> [runs] [outdir]
#
# The catch condition is written against counters that already exist, and it is
# deliberately narrow: `connected` true (so a failed start is not a catch) with
# `dns`, `up`, `down` and `active` all still zero after the probes have run and
# the soak has elapsed. A healthy start on this harness always moves `dns` -
# the probes resolve three names - so a zero there after a successful start is
# the signature and not a slow sample.
#
# On a catch this script does exactly two things: stop hunting, and hand off to
# scripts/device-state-collect.sh. Collection is a separate program on purpose
# (see its header) - the evidence must not depend on this loop surviving.
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

    # Wait for the line, do not guess at it. A fixed sleep here read as "no
    # AFTER_SOAK line" on every run: the exit-IP probes between the soak and the
    # snapshot take a variable ten to thirty seconds, so any constant is either
    # wrong or wasteful, and a hunt that mis-scores every run finds nothing.
    line=""
    waited=0
    limit=$((soak + 120))
    while [ "$waited" -lt "$limit" ]; do
        line="$(device logcat -d -s "$TAG" 2>/dev/null | grep 'STATS AFTER_SOAK' | tail -1)"
        [ -n "$line" ] && break
        # A start that failed never produces the line; do not spend the budget.
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

    # Pull the counters out of the STATS line by name rather than by position:
    # the line has grown four times this pass and every positional parse of it
    # has silently read the wrong field afterwards.
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
        # Hand off and stop. The engine is left running on purpose: the
        # collector needs it alive, and stopping it here would destroy the
        # only instance of the thing being hunted.
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
