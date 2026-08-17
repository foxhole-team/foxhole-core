#!/usr/bin/env bash
# Snapshot everything about a running engine, once, to the host.
#
# This is a separate executable step on purpose. The defect it exists for shows
# up about once in thirty starts, and the run that catches it does not get a
# second chance: if collection were a branch inside the hunt loop, an interrupted
# session would take the evidence with it. A standalone collector can be aimed at
# a caught engine by hand, from any shell, long after whatever started it died.
#
#   scripts/device-state-collect.sh <serial> [outdir] [note]
#
# Output goes to the HOST filesystem, never to the device and never inside a
# container: sampled data written into a container is data already lost once
# (docs/17 soaks). Each probe is best-effort and its failure is recorded rather
# than fatal - a collector that aborts halfway is worse than one that reports
# which half it got.
set -uo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
PKG="com.foxhole.coretest"
ACTIVITY="$PKG/.MainActivity"
TAG="FoxholeCoreTest"

serial="${1:?usage: device-state-collect.sh <serial> [outdir] [note]}"
outdir="${2:-$PWD/foxcore-capture-$(date +%Y%m%d-%H%M%S)}"
note="${3:-}"

mkdir -p "$outdir"
device() { "$ADB" -s "$serial" "$@"; }

# Every probe through here, so one missing binary cannot end the collection.
grab() {
    local name="$1"
    shift
    if "$@" > "$outdir/$name" 2> "$outdir/$name.err"; then
        local bytes
        bytes="$(wc -c < "$outdir/$name" | tr -d ' ')"
        # An empty file reported as ok is a probe that answered nothing dressed
        # up as evidence - `dumpsys netd` does exactly this on a device with no
        # such service, and at catch time that reads as "netd had nothing to
        # say" rather than "this was never collected".
        if [ "$bytes" = "0" ]; then
            printf '  EMPTY %s (%s)\n' "$name" \
                "$(head -1 "$outdir/$name.err" 2>/dev/null || echo 'no output')"
        else
            printf '  ok   %s (%s bytes)\n' "$name" "$bytes"
        fi
    else
        printf '  FAIL %s: %s\n' "$name" "$(head -1 "$outdir/$name.err" 2>/dev/null)"
    fi
    [ -s "$outdir/$name.err" ] || rm -f "$outdir/$name.err"
}

{
    echo "serial=$serial"
    echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "note=$note"
    echo "host=$(hostname)"
} > "$outdir/00-manifest.txt"

echo "collecting into $outdir"

# --- the engine's own answer, asked while it is still up ------------------
# Ordered first because it is the only source that dies with the process. The
# three hypotheses for a silent datapath are separated here and nowhere else:
# a tun loop that never reads leaves dns/split_stack/active all at zero, a
# classify that refuses everything moves rejected/blocked, and a policy applied
# empty shows in the revision with blocked climbing.
device shell am start -n "$ACTIVITY" --es cmd stats  >/dev/null 2>&1
sleep 2
device shell am start -n "$ACTIVITY" --es cmd lanes  >/dev/null 2>&1
sleep 2
device shell am start -n "$ACTIVITY" --es cmd drain --ei drain_max 512 >/dev/null 2>&1
sleep 3

grab 01-logcat-harness.txt device logcat -d -s "$TAG"
grab 02-logcat-full.txt    device logcat -d -v threadtime

# --- what the OS thinks the tunnel is ------------------------------------
grab 10-ip-addr.txt        device shell ip addr
grab 11-ip-route-all.txt   device shell "ip route show table all"
grab 12-ip-rule.txt        device shell ip rule
grab 13-tun0.txt           device shell ip addr show tun0
# The single sharpest reading for a silent datapath, and it needs no root:
# per-interface packet counters. tun0 RX climbing while the engine's own
# counters sit at zero means the packets reached the interface and the read
# loop never took them; tun0 RX at zero means nothing was routed into the tunnel
# at all, which is a policy or route answer rather than a datapath one.
# `ip -s link show tun0` is the obvious way to ask and is refused without root,
# so it is asked here instead.
grab 17-proc-net-dev.txt   device shell "cat /proc/net/dev"
grab 14-connectivity.txt   device shell dumpsys connectivity
grab 15-netstats.txt       device shell dumpsys netstats --uid
grab 16-netd.txt           device shell dumpsys netd

# --- the process ----------------------------------------------------------
pid="$(device shell pidof "$PKG" 2>/dev/null | tr -d '\r\n ')"
echo "pid=$pid" >> "$outdir/00-manifest.txt"
if [ -n "$pid" ]; then
    grab 20-proc-status.txt  device shell "cat /proc/$pid/status"
    grab 21-proc-net-dev.txt device shell "cat /proc/$pid/net/dev"
    grab 22-proc-net-tcp.txt device shell "cat /proc/$pid/net/tcp"
    grab 23-proc-net-tcp6.txt device shell "cat /proc/$pid/net/tcp6"
    grab 24-proc-net-udp.txt device shell "cat /proc/$pid/net/udp"
    grab 25-fd-count.txt     device shell "ls /proc/$pid/fd | wc -l"
    grab 26-task-list.txt    device shell "ls /proc/$pid/task"
    grab 27-sched.txt        device shell "cat /proc/$pid/sched"

    # Thread stacks. Without root neither /data/anr nor debuggerd is readable,
    # so SIGQUIT into the app's own uid and the ART dump that follows it in the
    # log is the only stack we can get - which is why the log is re-grabbed
    # after, not before.
    device shell "run-as $PKG kill -3 $pid" >/dev/null 2>&1
    sleep 4
    grab 28-logcat-after-sigquit.txt device logcat -d -v threadtime
    grab 29-anr-dir.txt device shell "ls -la /data/anr/ 2>&1"
fi

# --- thread stacks, the slow way, because the fast ways are root-only --------
# Measured on the Realme: SIGQUIT does produce a dump, but it lands in
# /data/anr/trace_NN owned by tombstoned:system - unreadable by `shell`, by
# `run-as`, and by `adb pull` alike - and nothing of it reaches logcat. A
# bugreport is the only route to those stacks without root. It is minutes and
# tens of megabytes, so it runs last, after every cheap probe is already safely
# on the host, and it can be skipped for a quick look.
if [ "${FOXCORE_COLLECT_BUGREPORT:-1}" = "1" ]; then
    echo "  .... bugreport (slow; FOXCORE_COLLECT_BUGREPORT=0 to skip)"
    if device bugreport "$outdir/40-bugreport.zip" >/dev/null 2>&1; then
        printf '  ok   40-bugreport.zip (%s bytes)\n' \
            "$(wc -c < "$outdir/40-bugreport.zip" | tr -d ' ')"
    else
        echo "  FAIL 40-bugreport.zip"
    fi
fi

# --- a second engine sample, so a frozen counter can be told from a slow one
sleep 5
device shell am start -n "$ACTIVITY" --es cmd stats >/dev/null 2>&1
sleep 3
grab 30-logcat-second-sample.txt device logcat -d -s "$TAG"

echo "done: $outdir"
