#!/usr/bin/env bash
# Drive the on-device harness and render a verdict per scenario.
#
#   scripts/device-scenarios.sh <serial> install <apk>
#   scripts/device-scenarios.sh <serial> push <config-dir>
#   scripts/device-scenarios.sh <serial> baseline
#   scripts/device-scenarios.sh <serial> protocol <name> [soak-seconds]
#   scripts/device-scenarios.sh <serial> matrix <name> [name...]
#   scripts/device-scenarios.sh <serial> lifecycle <cycles>
#   scripts/device-scenarios.sh <serial> policy <policy-name>
#   scripts/device-scenarios.sh <serial> soak <name> <minutes> [interval-s]
#   scripts/device-scenarios.sh <serial> tor <config> <host.onion> [off-pol] [on-pol]
#   scripts/device-scenarios.sh <serial> netchange
#
# Config files are named by protocol and live in the app's own files directory;
# only the *name* ever travels through `am start`, never the config body — a
# profile on a command line ends up in `ps`, in the shell history and in the
# activity manager's own log.
#
# Nothing here decides whether a run passed. The verdict comes from logcat lines
# the harness prints, so a scenario that silently did nothing reads as missing
# evidence rather than as a pass.
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

# Everything the harness logged since the marker, protocol output only.
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
        # Without this the first `am start` raises the consent dialog and, with
        # no one to tap it, the run dies as "VPN permission denied".
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
        # Force-stop first. A VpnService that has already run keeps its process
        # and its foreground notification alive, and the next `am start` was
        # observed to be swallowed rather than delivered — the run then produced
        # no log lines at all, which reads exactly like a protocol that failed.
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
        # The first config in the directory is as good as any: this scenario is
        # about fds, threads and RSS returning to where they started, not about
        # which protocol carried the bytes.
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

    # D13: the stop path under abandoned platform work. Start/stop cycles never
    # reproduced it — each new flow costs one attribution call whose timeout
    # cancels the future but not the blocking call under it, so the queue only
    # builds under flow churn.
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

    # Continuity: a lane held blocked across an interruption, released only by an
    # explicit confirmation. The negative half is the point — held must mean
    # blocked, not quietly direct.
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

    # The kill switch has to reach a transfer that is already running.
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

    # `.i2p` through the loopback contract. The stub is not i2pd and cannot reach
    # an eepsite; it proves the core's half — fake-IP gate, route, fail-closed.
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

    # A live `.onion` through the Tor lane, then the gate shut and reopened on
    # the same tunnel. `CONNECTED` on its own proves nothing here — the local
    # stack completes the handshake — so the verdict comes from the lane
    # counters, and the half that matters is the closed gate: the flow must be
    # blocked, not quietly sent to the clearnet.
    #
    # The chmod is not tidiness. Arti checks the permissions of the whole
    # directory chain, and an app files/ dir left group- or world-writable makes
    # bootstrap fail with a filesystem error nobody would connect to Tor.
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
        # Arti's first bootstrap runs minutes; with saved state it is seconds.
        start --es cmd start --es cfg "$FILES/$name.json" --ez with_network true \
            --ei soak 600
        # Generous on purpose: this returns the moment either pattern shows, and
        # a first Arti bootstrap on a slow link runs well past the few minutes a
        # cached one takes. A wait shorter than the config's own bootstrap budget
        # reports "did not come up" while the core is still legitimately working.
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

    # One large upload in one flow. Three of three of these died at 0.4-1.4 MiB
    # on a clean link, back when the backlog ceiling was a volume
    # verdict. The verdict here is written == offered, not the HTTP status.
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

    # A push channel: silent for longer than the old 300 s TCP timeout, then it
    # has to still be there. IMAP/143 is the sink because RFC 3501 forbids the
    # server hanging up first inside 30 minutes, so a death at six is ours.
    #
    # Exchange rather than Gmail: Gmail refuses 143 outright (TLS-only on 993),
    # which would have made this row a probe of the sink rather than of the core.
    #
    # `pushchan`, not `push`: `push` is already the config-upload command above,
    # and a second case with the same label is dead code the shell never reaches.
    # It cost this row one run — the scenario reported nothing at all, which read
    # as a harness that had not been built rather than as a name collision.
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
