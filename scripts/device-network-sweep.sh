#!/bin/bash

set -uo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
SERIAL="${1:?usage: ssidswap.sh <serial> <config>}"
CONFIG="${2:?usage: ssidswap.sh <serial> <config>}"
PKG="com.foxhole.coretest"

device() { "$ADB" -s "$SERIAL" "$@"; }
harvest() { device logcat -d -s FoxholeCoreTest; }
send() { device shell am start -n "$PKG/.MainActivity" "$@" >/dev/null; }
current_ssid() { device shell "dumpsys wifi 2>/dev/null | grep -m1 -oE 'mWifiInfo SSID: \"[^\"]*\"'" | sed 's/.*SSID: //'; }

tap_network() {
    local wanted="$1"
    device shell "am start -a android.settings.WIFI_SETTINGS" >/dev/null 2>&1
    sleep 4
    device shell "cmd wifi start-scan" >/dev/null 2>&1
    sleep 6
    local attempt=0
    while [ "$attempt" -lt 4 ]; do
        device shell "uiautomator dump /sdcard/ui.xml" >/dev/null 2>&1
        local bounds
        bounds=$(device shell "cat /sdcard/ui.xml" 2>/dev/null | tr '>' '\n' |
            grep -oE "content-desc=\"$wanted,[^\"]*\"[^/]*bounds=\"\[[0-9,]*\]\[[0-9,]*\]\"" |
            grep -oE 'bounds="\[[0-9,]*\]\[[0-9,]*\]"' | head -1)
        if [ -n "$bounds" ]; then
            local x1 y1 x2 y2
            x1=$(echo "$bounds" | grep -oE '\[[0-9]+,[0-9]+\]' | head -1 | tr -d '[]' | cut -d, -f1)
            y1=$(echo "$bounds" | grep -oE '\[[0-9]+,[0-9]+\]' | head -1 | tr -d '[]' | cut -d, -f2)
            x2=$(echo "$bounds" | grep -oE '\[[0-9]+,[0-9]+\]' | tail -1 | tr -d '[]' | cut -d, -f1)
            y2=$(echo "$bounds" | grep -oE '\[[0-9]+,[0-9]+\]' | tail -1 | tr -d '[]' | cut -d, -f2)
            device shell "input tap $(((x1 + x2) / 2)) $(((y1 + y2) / 2))" >/dev/null 2>&1
            return 0
        fi
        device shell "input swipe 720 1600 720 1000" >/dev/null 2>&1
        sleep 2
        attempt=$((attempt + 1))
    done
    return 1
}

probe_exit() {
    local before after
    before=$(harvest | grep -cE 'EXIT_SET')
    send --es cmd exit
    sleep 25
    after=$(harvest | grep -cE 'EXIT_SET')
    if [ "$after" -gt "$before" ]; then
        harvest | grep -E 'EXIT_SET' | tail -1 | grep -oE 'fingerprints=.*'
    else
        echo "проба не вернулась"
    fi
}

echo "=== туннель на $(current_ssid) ==="
device logcat -c
send --es cmd start --es cfg "/data/user/0/$PKG/files/$CONFIG.json" --ez with_network true
sleep 20
echo "выход: $(probe_exit)"

for target in albert_wesker umbrella_corp; do
    echo
    echo "=== переключаюсь на $target ==="
    if ! tap_network "$target"; then
        echo "не нашёл $target в списке — пропускаю"
        continue
    fi
    i=0
    while [ $i -lt 30 ]; do
        [ "$(current_ssid)" = "\"$target\"" ] && break
        i=$((i + 1))
        sleep 2
    done
    sleep 8
    echo "сеть теперь: $(current_ssid)"
    echo "проба ДО netchange: $(probe_exit)"
    send --es cmd netchange
    sleep 8
    echo "проба ПОСЛЕ netchange: $(probe_exit)"
    harvest | grep -oE 'STATS [A-Z_]+ .*' | tail -1 |
        grep -oE '(connected|reconnects|rebinds|rebind_fail|sock_err|flow_errors)=[a-z0-9]+' | tr '\n' ' '
    echo
done

echo
echo "=== останов ==="
send --es cmd stop
sleep 10
harvest | grep -E 'STOP' | tail -1
