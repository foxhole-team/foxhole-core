#!/bin/bash

set -uo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
SERIAL="${1:?usage: tunplane.sh <serial> <arm> <seconds>}"
ARM="${2:?usage: tunplane.sh <serial> foxcore|singbox <seconds>}"
DURATION="${3:-30}"
TARGET="${TUNPLANE_TARGET:-speed.cloudflare.com:80}"
PATH_ARG="${TUNPLANE_PATH:-/__down?bytes=20000000}"

device() { "$ADB" -s "$SERIAL" "$@"; }

case "$ARM" in
    foxcore) PKG="com.foxhole.coretest" ;;
    singbox) PKG="io.nekohasekai.sfa" ;;
    *) echo "arm must be foxcore or singbox" >&2; exit 2 ;;
esac

proc_pid() { device shell "pidof $PKG" | tr -d '\r\n'; }

cpu_ticks() {
    local pid="$1"
    device shell "cat /proc/$pid/stat 2>/dev/null" |
        sed 's/.*) //' | awk '{print $12 + $13}' | tr -d '\r\n'
}

rss_kb() {
    device shell "awk '/^VmRSS:/ {print \$2}' /proc/$1/status 2>/dev/null" | tr -d '\r\n'
}

tunnel_up() { device shell "ip -o addr show 2>/dev/null | grep -c tun" | tr -d '\r\n'; }

echo "=== $ARM: жду поднятого туннеля ==="
START_MS=$(python3 -c "import time;print(int(time.time()*1000))")
i=0
while [ $i -lt 60 ]; do
    [ "$(tunnel_up)" != "0" ] && break
    i=$((i + 1))
    sleep 1
done
UP_MS=$(python3 -c "import time;print(int(time.time()*1000))")
if [ "$(tunnel_up)" = "0" ] ; then
    echo "туннель так и не поднялся — запусти арм вручную и повтори"
    exit 1
fi
echo "туннель поднят за $((UP_MS - START_MS)) мс ожидания (с момента запуска скрипта)"

PID=$(proc_pid)
[ -z "$PID" ] && { echo "процесс $PKG не найден"; exit 1; }
echo "pid=$PID"

CPU_BEFORE=$(cpu_ticks "$PID")
RSS_BEFORE=$(rss_kb "$PID")

echo "=== нагрузка $DURATION с через туннель ==="
LOAD=$(device shell "cd /data/local/tmp/ab && ./foxcore-bench-client --target $TARGET --path '$PATH_ARG' --concurrency 4 --duration-s $DURATION --timeout-s 40 --label tun/$ARM" 2>&1 | tr -d '\r')

CPU_AFTER=$(cpu_ticks "$PID")
RSS_AFTER=$(rss_kb "$PID")

echo "$LOAD"
printf '{"arm":"%s","cpu_ticks":%s,"rss_kb_before":%s,"rss_kb_after":%s}\n' \
    "$ARM" "$((CPU_AFTER - CPU_BEFORE))" "${RSS_BEFORE:-0}" "${RSS_AFTER:-0}"
