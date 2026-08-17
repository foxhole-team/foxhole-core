#!/system/bin/sh
# The unplugged battery window, run entirely ON the device.
#
#   ab-unplugged-window.sh <dir> <seconds-per-arm> <node> [node...]
#
# WHY THIS RUNS ON THE PHONE AND NOT FROM THE HOST
#
# adb on this device is USB-only (`adb_wifi_enabled=0`, no `service.adb.tcp.port`).
# The moment the owner pulls the cable the host loses the transport, so a
# host-driven unplugged regime cannot start an arm, cannot sample it and cannot
# read a battery counter. Enabling network adb would be a change to the device's
# debugging posture, which is not ours to make. So the whole window is handed to
# the device before the unplug: this script waits for the cable to go, runs both
# arms itself, writes everything to disk, and the host collects after replug.
#
# WHY EACH ARM GETS ITS OWN SUB-WINDOW
#
# Battery draw cannot be attributed per-arm inside one window. Both arms run as
# uid 2000 (shell), so `dumpsys batterystats` reports one aggregate for the uid
# that also contains the sampler and the load generator. Asking it which of the
# two proxies spent the charge is asking a question the data cannot answer.
# Instead each arm gets its own equal-length sub-window with the other stopped,
# and the charge counter is read across each. Equal length is enforced below and
# recorded; if the two differ, the comparison is void and the reader must see it.
#
# WHY charge_counter AND NOT ONLY `Discharge:`
#
# `/sys/class/power_supply/battery/charge_counter` is the fuel gauge's own µAh
# accumulator - fine-grained and read directly. `dumpsys batterystats` Discharge
# is reported in coarse mAh and is derived. Both are recorded; the counter is the
# primary and batterystats is the corroboration.
set -u

DIR="${1:?usage: ab-unplugged-window.sh <dir> <seconds-per-arm> <node...>}"
WINDOW="${2:?seconds per arm}"
shift 2
NODES="$*"

FOX_PORT=11080
SB_PORT=11081
TARGET="${AB_TARGET:-speedtest.tele2.net:80}"
PATH_ARG="${AB_PATH:-/10MB.zip}"
CONC="${AB_CONCURRENCY:-4}"

cd "$DIR" || exit 2
OUT="$DIR/unplugged"
rm -rf "$OUT"; mkdir -p "$OUT"
LOG="$OUT/window.log"
say() { echo "[$(date +%H:%M:%S)] $*" >> "$LOG"; }

charge_uah() { cat /sys/class/power_supply/battery/charge_counter 2>/dev/null || echo -1; }
battery_pct() { dumpsys battery 2>/dev/null | awk '/^  level:/ {print $2}'; }
plugged() {
    dumpsys battery 2>/dev/null | awk '
        /USB powered: true/ {print "usb"; f=1}
        /AC powered: true/ {print "ac"; f=1}
        /Wireless powered: true/ {print "wireless"; f=1}
        END {if (!f) print "unplugged"}' | head -1
}
doze_deep() { dumpsys deviceidle get deep 2>/dev/null | tr -d '\r'; }
doze_light() { dumpsys deviceidle get light 2>/dev/null | tr -d '\r'; }
screen_state() { dumpsys power 2>/dev/null | grep -m1 'mWakefulness=' | sed 's/.*mWakefulness=//' | tr -d '\r'; }

kill_arms() {
    for p in $(pgrep -f 'f[o]xcore-socks --selector') $(pgrep -f 's[i]ng-box run -c') \
             $(pgrep -f 'f[o]xcore-bench-client') $(pgrep -f 'a[b]-proc-sampler'); do
        kill "$p" 2>/dev/null
    done
    sleep 3
    for p in $(pgrep -f 'f[o]xcore-socks --selector') $(pgrep -f 's[i]ng-box run -c'); do
        kill -9 "$p" 2>/dev/null
    done
    sleep 2
}

wait_listener() {
    _hex=$(printf '%04X' "$1")
    _i=0
    while [ "$_i" -lt 25 ]; do
        if cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '{print $2}' | grep -qi ":$_hex\$"; then
            return 0
        fi
        sleep 1; _i=$((_i + 1))
    done
    return 1
}

# One arm, one node, one equal-length sub-window.
run_arm() {
    _arm="$1"; _node="$2"; _sel="$3"
    _pre="$OUT/${_node}__${_arm}"
    kill_arms

    _c0=$(charge_uah); _p0=$(battery_pct); _t0=$(date +%s)
    _dz0="$(doze_deep)"; _dl0="$(doze_light)"; _sc0="$(screen_state)"; _pl0="$(plugged)"

    if [ "$_arm" = foxcore ]; then
        _port=$FOX_PORT
        [ -n "$_sel" ] || { echo "no foxcore selector" > "$_pre.skip"; return; }
        ( setsid ./foxcore-socks --selector "$_sel" --socks-port $_port --server raw \
            < "$_node.link" > "$_pre.arm.out" 2>&1 & )
    else
        _port=$SB_PORT
        [ -f "$_node.sb.json" ] || { echo "no sing-box translation" > "$_pre.skip"; return; }
        ( setsid ./sing-box run -c "$_node.sb.json" --disable-color > "$_pre.arm.out" 2>&1 & )
    fi

    if ! wait_listener "$_port"; then
        echo "listener never bound" > "$_pre.skip"
        say "$_node/$_arm: listener never bound"
        kill_arms
        return
    fi

    _pid=$(if [ "$_arm" = foxcore ]; then pgrep -f 'f[o]xcore-socks --selector'; else pgrep -f 's[i]ng-box run -c'; fi | head -1)
    [ -n "$_pid" ] || { echo "no pid" > "$_pre.skip"; kill_arms; return; }

    ( setsid sh ./ab-proc-sampler.sh "$_pid" 2 "$_pre.proc.jsonl" >/dev/null 2>&1 & )

    # The window is a wall-clock duration, identical for both arms. The
    # generator is given the same duration; a protocol that stalls burns its
    # window rather than being handed a longer one.
    ./foxcore-bench-client --proxy "127.0.0.1:$_port" --target "$TARGET" --path "$PATH_ARG" \
        --concurrency "$CONC" --duration-s "$WINDOW" --timeout-s 25 \
        --label "unplugged/$_arm/$_node" --out "$_pre.bench.jsonl" > "$_pre.bench.txt" 2>&1

    _c1=$(charge_uah); _p1=$(battery_pct); _t1=$(date +%s)
    _dz1="$(doze_deep)"; _dl1="$(doze_light)"; _sc1="$(screen_state)"; _pl1="$(plugged)"
    kill_arms

    printf '{"arm":"%s","node":"%s","window_s":%s,"elapsed_s":%s,' \
        "$_arm" "$_node" "$WINDOW" "$((_t1 - _t0))" >> "$_pre.batt.json"
    printf '"charge_uah_before":%s,"charge_uah_after":%s,"charge_uah_used":%s,' \
        "$_c0" "$_c1" "$((_c0 - _c1))" >> "$_pre.batt.json"
    printf '"battery_pct_before":%s,"battery_pct_after":%s,' "$_p0" "$_p1" >> "$_pre.batt.json"
    printf '"plugged_before":"%s","plugged_after":"%s","screen_before":"%s","screen_after":"%s",' \
        "$_pl0" "$_pl1" "$_sc0" "$_sc1" >> "$_pre.batt.json"
    printf '"doze_deep_before":"%s","doze_deep_after":"%s","doze_light_before":"%s","doze_light_after":"%s"}\n' \
        "$_dz0" "$_dz1" "$_dl0" "$_dl1" >> "$_pre.batt.json"
    say "$_node/$_arm: ${_t1}-${_t0}=$((_t1 - _t0))s used $((_c0 - _c1))uAh doze=$_dz1 screen=$_sc1 plugged=$_pl1"
}

say "waiting for the cable to be pulled"
i=0
while [ "$i" -lt 240 ]; do
    [ "$(plugged)" = "unplugged" ] && break
    sleep 5; i=$((i + 1))
done
if [ "$(plugged)" != "unplugged" ]; then
    say "cable never came out; aborting without measuring"
    echo aborted > "$OUT/DONE"
    exit 1
fi
say "unplug registered; settling 30s before the first arm"
sleep 30

dumpsys batterystats --reset >/dev/null 2>&1
say "batterystats reset; doze deep=$(doze_deep) light=$(doze_light) screen=$(screen_state)"
printf 'start_epoch=%s\nstart_charge_uah=%s\nstart_pct=%s\n' \
    "$(date +%s)" "$(charge_uah)" "$(battery_pct)" > "$OUT/window.meta"

for entry in $NODES; do
    node="${entry%%:*}"
    sel="${entry##*:}"
    [ "$sel" = "$node" ] && sel=""
    run_arm foxcore "$node" "$sel"
    run_arm singbox "$node" "$sel"
done

printf 'end_epoch=%s\nend_charge_uah=%s\nend_pct=%s\nend_doze_deep=%s\nend_doze_light=%s\nend_plugged=%s\n' \
    "$(date +%s)" "$(charge_uah)" "$(battery_pct)" "$(doze_deep)" "$(doze_light)" "$(plugged)" \
    >> "$OUT/window.meta"
dumpsys batterystats > "$OUT/batterystats.txt" 2>&1
dumpsys deviceidle > "$OUT/deviceidle.txt" 2>&1

say "window complete"
echo complete > "$OUT/DONE"

# The owner is told by the device itself, because the host may still be
# disconnected at this point and cannot post anything.
cmd notification post -S bigtext -t 'FoxCore A/B: window done' ab_unplug_done \
    'The unplugged measurement window has finished. You can reconnect the cable.' >/dev/null 2>&1
