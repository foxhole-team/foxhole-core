#!/usr/bin/env bash
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

grab() {
    local name="$1"
    shift
    if "$@" > "$outdir/$name" 2> "$outdir/$name.err"; then
        local bytes
        bytes="$(wc -c < "$outdir/$name" | tr -d ' ')"
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

device shell am start -n "$ACTIVITY" --es cmd stats  >/dev/null 2>&1
sleep 2
device shell am start -n "$ACTIVITY" --es cmd lanes  >/dev/null 2>&1
sleep 2
device shell am start -n "$ACTIVITY" --es cmd drain --ei drain_max 512 >/dev/null 2>&1
sleep 3

grab 01-logcat-harness.txt device logcat -d -s "$TAG"
grab 02-logcat-full.txt    device logcat -d -v threadtime

grab 10-ip-addr.txt        device shell ip addr
grab 11-ip-route-all.txt   device shell "ip route show table all"
grab 12-ip-rule.txt        device shell ip rule
grab 13-tun0.txt           device shell ip addr show tun0
grab 17-proc-net-dev.txt   device shell "cat /proc/net/dev"
grab 14-connectivity.txt   device shell dumpsys connectivity
grab 15-netstats.txt       device shell dumpsys netstats --uid
grab 16-netd.txt           device shell dumpsys netd

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

    device shell "run-as $PKG kill -3 $pid" >/dev/null 2>&1
    sleep 4
    grab 28-logcat-after-sigquit.txt device logcat -d -v threadtime
    grab 29-anr-dir.txt device shell "ls -la /data/anr/ 2>&1"
fi

if [ "${FOXCORE_COLLECT_BUGREPORT:-1}" = "1" ]; then
    echo "  .... bugreport (slow; FOXCORE_COLLECT_BUGREPORT=0 to skip)"
    if device bugreport "$outdir/40-bugreport.zip" >/dev/null 2>&1; then
        printf '  ok   40-bugreport.zip (%s bytes)\n' \
            "$(wc -c < "$outdir/40-bugreport.zip" | tr -d ' ')"
    else
        echo "  FAIL 40-bugreport.zip"
    fi
fi

sleep 5
device shell am start -n "$ACTIVITY" --es cmd stats >/dev/null 2>&1
sleep 3
grab 30-logcat-second-sample.txt device logcat -d -s "$TAG"

echo "done: $outdir"
