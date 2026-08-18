#!/usr/bin/env bash
set -euo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
PKG="com.foxhole.coretest"
ACTIVITY="$PKG/.MainActivity"
FILES="/data/user/0/$PKG/files"
TAG="FoxholeCoreTest"

serial="${1:?usage: device-scenarios.sh <serial> <command> [args]}"
command="${2:?usage: device-scenarios.sh <serial> <command> [args]}"
shift 2

device() {
    "$ADB" -s "$serial" "$@"
}

start() {
    device shell am start -n "$ACTIVITY" "$@" >/dev/null
}

harvest() {
    device logcat -d -s "$TAG"
}

wait_for() {
    local pattern="$1"
    local timeout="$2"
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if harvest | rg -q "$pattern"; then
            return 0
        fi
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

case "$command" in
    install)
        apk="${1:?install needs an apk path}"
        device install -r -g "$apk"
        device shell appops set "$PKG" ACTIVATE_VPN allow
        device shell "run-as $PKG mkdir -p files"
        echo "installed on $serial"
        ;;

    push)
        directory="${1:?push needs a config directory}"
        device shell "run-as $PKG mkdir -p files"
        for config in "$directory"/*.json; do
            [ -f "$config" ] || continue
            name="$(basename "$config")"
            device shell "run-as $PKG sh -c 'cat > files/$name'" < "$config"
            echo "pushed $name"
        done
        ;;

    baseline)
        device logcat -c
        start --es cmd baseline
        wait_for 'BASELINE end' 60 || echo "baseline did not finish" >&2
        harvest | rg 'EXIT_SET|EXIT_PROBE|DNS host'
        ;;

    protocol)
        name="${1:?protocol needs a config name}"
        soak="${2:-20}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak "$soak"
        wait_for 'AFTER_SOAK|RESULT start_failed|STOP result=' $((soak + 120)) ||
            echo "$name: no terminal line" >&2
        sleep 3
        echo "--- $name ---"
        harvest | rg 'NET_HANDLE|START handle|STATS AFTER_START|STATS AFTER_SOAK|LANES AFTER_SOAK|EXIT_SET|DNS host|PROTECT_SUMMARY|RESULT|BOOTSTRAP_DNS'
        start --es cmd stop
        sleep 4
        device shell am force-stop "$PKG"
        ;;

    matrix)
        for name in "$@"; do
            "$0" "$serial" protocol "$name" "${FOXCORE_DEVICE_SOAK:-20}"
        done
        ;;

    lifecycle)
        cycles="${1:-10}"
        device logcat -c
        name="${FOXCORE_DEVICE_PROFILE:-vless}"
        start --es cmd lifecycle --es cfg "$FILES/$name.json" --ez with_network true \
            --ei cycles "$cycles"
        wait_for 'LIFECYCLE done|start_failed|stop_incomplete' $((cycles * 40 + 120)) ||
            echo "lifecycle did not finish" >&2
        harvest | rg 'LIFECYCLE|STOP result'
        ;;

    policy)
        name="${1:?policy needs a policy name}"
        start --es cmd policy --es policy "$FILES/$name.json"
        sleep 6
        harvest | rg 'POLICY|STATS AFTER_POLICY|LANES AFTER_POLICY' | tail -6
        ;;

    soak)
        name="${1:?soak needs a config name}"
        minutes="${2:-30}"
        interval="${3:-60}"
        device logcat -c
        start --es cmd soak --es cfg "$FILES/$name.json" --ez with_network true \
            --ei minutes "$minutes" --ei interval "$interval"
        echo "soak started on $serial: $name, ${minutes}m, sampling every ${interval}s"
        ;;

    netchange)
        start --es cmd netchange
        sleep 6
        harvest | rg 'NETCHANGE|STATS AFTER_NETCHANGE' | tail -4
        ;;

    churn)
        name="${1:?churn needs a config name}"
        flows="${2:-300}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd churn --es cfg "$FILES/$name.json" --ez with_network true \
            --ei cycles "$flows"
        wait_for 'CHURN stop_result|CHURN start_failed' 300 || echo "churn did not finish" >&2
        sleep 3
        harvest | rg 'CHURN|STATS AFTER_CHURN|LANES AFTER_CHURN'
        device shell am force-stop "$PKG"
        ;;

    continuity)
        name="${1:?continuity needs a config name}"
        policy="${2:-pol-hold-netswitch}"
        wait_s="${3:-45}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 240
        wait_for 'EXIT_SET phase=tunnel' 90 || echo "engine did not come up" >&2
        start --es cmd continuity --es policy "$FILES/$policy.json" --ei soak "$wait_s"
        wait_for 'CONTINUITY held_exit|CONTINUITY no hold' $((wait_s + 180)) ||
            echo "continuity did not finish" >&2
        harvest | rg 'CONTINUITY|POLICY result|EXIT_SET phase=continuity'
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    killdl)
        name="${1:?killdl needs a config name}"
        policy="${2:-pol-kill-on}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 240
        wait_for 'EXIT_SET phase=tunnel' 90 || echo "engine did not come up" >&2
        start --es cmd killdl --es policy "$FILES/$policy.json"
        wait_for 'KILLDL verdict' 180 || echo "killdl did not finish" >&2
        harvest | rg 'KILLDL|POLICY result|STATS AFTER_KILLDL|LANES AFTER_KILLDL'
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    i2p)
        name="${1:-overlays}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 240
        wait_for 'EXIT_SET phase=tunnel' 90 || echo "engine did not come up" >&2
        echo "--- .i2p with no loopback listener (must fail closed) ---"
        start --es cmd i2presolve
        sleep 12
        harvest | rg 'DNS host=stats.i2p|STATS AFTER_I2P_RESOLVE|LANES AFTER_I2P_RESOLVE' | tail -4
        echo "--- .i2p with the loopback stub listening ---"
        start --es cmd i2pstub --ei port 4447
        sleep 4
        start --es cmd i2presolve
        sleep 12
        harvest | rg 'I2P_STUB|DNS host=stats.i2p|STATS AFTER_I2P_RESOLVE|LANES AFTER_I2P_RESOLVE' | tail -8
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    tor)
        name="${1:-ov-tor}"
        onion="${2:?tor needs an .onion host}"
        off_policy="${3:-pol-tor-off}"
        on_policy="${4:-pol-tor-on}"
        device shell am force-stop "$PKG"
        sleep 2
        device shell "run-as $PKG sh -c 'mkdir -p files/tor/state files/tor/cache;
            chmod 700 files files/tor files/tor/state files/tor/cache'"
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 600
        wait_for 'EXIT_SET phase=tunnel|RESULT start_failed|CMD start failed' 960 ||
            echo "engine did not come up" >&2
        harvest | rg 'START handle|RESULT start_failed|CMD start failed' | tail -3
        echo "--- .onion with the gate open ---"
        start --es cmd i2pconnect --es host "$onion"
        sleep 25
        harvest | rg "I2P_CONNECT host=$onion|LANES AFTER_I2P_CONNECT" | tail -4
        echo "--- gate shut: the flow must be blocked, not sent to the clearnet ---"
        "$0" "$serial" policy "$off_policy" | tail -3
        start --es cmd i2pconnect --es host "$onion"
        sleep 25
        harvest | rg "I2P_CONNECT host=$onion|STATS AFTER_I2P_CONNECT|LANES AFTER_I2P_CONNECT" | tail -6
        echo "--- gate reopened on the same tunnel ---"
        "$0" "$serial" policy "$on_policy" | tail -3
        start --es cmd i2pconnect --es host "$onion"
        sleep 25
        harvest | rg "I2P_CONNECT host=$onion|LANES AFTER_I2P_CONNECT" | tail -4
        echo "--- generation must not have moved: no tunnel was rebuilt ---"
        harvest | rg 'STATS AFTER_I2P_CONNECT' | tail -3
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    upload)
        name="${1:-vless}"
        mib="${2:-32}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 900
        wait_for 'EXIT_SET phase=tunnel' 120 || echo "engine did not come up" >&2
        start --es cmd upload --ei mib "$mib"
        wait_for 'UPLOAD verdict' $((mib * 20 + 300)) || echo "upload did not finish" >&2
        harvest | rg 'UPLOAD|STATS AFTER_UPLOAD|LANES AFTER_UPLOAD'
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    pushchan)
        name="${1:-vless}"
        idle="${2:-360}"
        host="${3:-outlook.office365.com}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak $((idle + 300))
        wait_for 'EXIT_SET phase=tunnel' 120 || echo "engine did not come up" >&2
        start --es cmd push --es host "$host" --ei port 143 --ei idle "$idle"
        wait_for 'PUSH verdict' $((idle + 240)) || echo "push probe did not finish" >&2
        harvest | rg 'PUSH|STATS AFTER_PUSH'
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    naiveudp)
        device logcat -c
        start --es cmd start --es cfg "$FILES/naive.json" --ez with_network true --ei soak 120
        wait_for 'EXIT_SET phase=tunnel' 90 || echo "engine did not come up" >&2
        start --es cmd naiveudp
        wait_for 'AFTER_UDP_REFUSAL' 90 || echo "udp probe did not finish" >&2
        harvest | rg 'UDP_REFUSAL|STATS BEFORE_UDP_REFUSAL|STATS AFTER_UDP_REFUSAL|EVENTS'
        start --es cmd stop
        sleep 3
        device shell am force-stop "$PKG"
        ;;

    lanproxy)
        name="${1:-vless}"
        device shell am force-stop "$PKG"
        sleep 2
        device logcat -c
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 300
        wait_for 'EXIT_SET phase=tunnel' 90 || echo "engine did not come up" >&2
        start --es cmd lanproxy
        sleep 8
        harvest | rg 'LANPROXY'
        ;;

    logs)
        harvest
        ;;

    *)
        echo "unknown command: $command" >&2
        exit 2
        ;;
esac
