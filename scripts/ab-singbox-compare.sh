#!/usr/bin/env bash
set -uo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
SERIAL="${1:?usage: ab-singbox-compare.sh <serial> <command> [args]}"
COMMAND="${2:?usage: ab-singbox-compare.sh <serial> <command> [args]}"
shift 2

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

WORK="${AB_WORK_DIR:-${TMPDIR:-/tmp}/foxcore-ab}"
DEVDIR="${AB_DEVICE_DIR:-/data/local/tmp/ab-run}"

AB_TARGET="${AB_TARGET:-speed.cloudflare.com:80}"
AB_PATH="${AB_PATH:-/__down?bytes=10000000}"
AB_CONCURRENCY="${AB_CONCURRENCY:-4}"
AB_DURATION_S="${AB_DURATION_S:-20}"
AB_TIMEOUT_S="${AB_TIMEOUT_S:-30}"
AB_SAMPLE_S="${AB_SAMPLE_S:-1}"
AB_FOX_PORT="${AB_FOX_PORT:-11080}"
AB_SB_PORT="${AB_SB_PORT:-11081}"
AB_PROMPT_TIMEOUT_S="${AB_PROMPT_TIMEOUT_S:-900}"

device() { "$ADB" -s "$SERIAL" "$@"; }
dsh() { device shell "$@" 2>/dev/null | tr -d '\r'; }

dspawn() {
    local command="$1" out="$2" in_file="${3:-/dev/null}"
    device shell "cd $DEVDIR && ( setsid $command <$in_file >>$out 2>&1 & ) ; echo spawned" >/dev/null 2>&1
}
log() { printf '[ab] %s\n' "$*" >&2; }
die() { printf '[ab] FATAL: %s\n' "$*" >&2; exit 1; }


state_json() {
    local battery power idle plugged level temp screen deep light
    battery="$(dsh dumpsys battery)"
    power="$(dsh dumpsys power | grep -m1 'mWakefulness=')"
    plugged="unplugged"
    case "$battery" in
        *"USB powered: true"*) plugged="usb" ;;
        *"AC powered: true"*) plugged="ac" ;;
        *"Wireless powered: true"*) plugged="wireless" ;;
    esac
    level="$(printf '%s\n' "$battery" | awk '/^  level:/ {print $2}')"
    temp="$(printf '%s\n' "$battery" | awk '/^  temperature:/ {print $2}')"
    case "$power" in
        *Awake*) screen="on" ;;
        *Dreaming*) screen="dreaming" ;;
        *Asleep*|*Dozing*) screen="off" ;;
        *) screen="unknown" ;;
    esac
    deep="$(dsh dumpsys deviceidle get deep)"
    light="$(dsh dumpsys deviceidle get light)"
    local charge
    charge="$(dsh 'cat /sys/class/power_supply/battery/charge_counter 2>/dev/null')"
    printf '{"plugged":"%s","battery_pct":%s,"battery_decikelvin":%s,"screen":"%s","doze_deep":"%s","doze_light":"%s","vpn_capture":"%s","charge_uah":%s,"t":%s}' \
        "$plugged" "${level:-null}" "${temp:-null}" "$screen" "${deep:-unknown}" "${light:-unknown}" \
        "$(shell_egress_interface)" "${charge:--1}" "$(date +%s)"
}

shell_egress_interface() {
    dsh "ip route get 1.1.1.1 2>/dev/null" | awk '/dev/ {for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}'
}

state_key() {
    printf '%s\n' "$1" | sed -E 's/.*"plugged":"([^"]*)".*"screen":"([^"]*)","doze_deep":"([^"]*)","doze_light":"([^"]*)".*/\1|\2|\3|\4/'
}

notify() {
    local tag="$1" title="$2" body="$3"
    dsh "cmd notification post -S bigtext -t '$title' '$tag' '$body'" >/dev/null
}

await_state() {
    local field="$1" want="$2" tag="$3" title="$4" body="$5"
    local waited=0 current
    notify "$tag" "$title" "$body"
    while [ "$waited" -lt "$AB_PROMPT_TIMEOUT_S" ]; do
        current="$(state_json)"
        case "$field" in
            plugged)
                case "$want" in
                    unplugged) printf '%s' "$current" | grep -q '"plugged":"unplugged"' && { log "state reached: unplugged"; return 0; } ;;
                    plugged)   printf '%s' "$current" | grep -q '"plugged":"unplugged"' || { log "state reached: plugged"; return 0; } ;;
                esac
                ;;
            screen)
                printf '%s' "$current" | grep -q "\"screen\":\"$want\"" && { log "state reached: screen $want"; return 0; }
                ;;
        esac
        sleep 5
        waited=$((waited + 5))
        [ $((waited % 60)) -eq 0 ] && notify "$tag" "$title" "$body"
    done
    log "timed out after ${AB_PROMPT_TIMEOUT_S}s waiting for $field=$want"
    return 1
}


resolve_subscription() {
    local sub_file="" url_env=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --sub-file) sub_file="${2:?--sub-file needs a path}"; shift 2 ;;
            --sub-url-env) url_env="${2:?--sub-url-env needs a variable name}"; shift 2 ;;
            *) shift ;;
        esac
    done
    mkdir -p "$WORK" && chmod 700 "$WORK"
    if [ -n "$sub_file" ]; then
        [ -r "$sub_file" ] || die "cannot read $sub_file"
        cp "$sub_file" "$WORK/body.raw" && chmod 600 "$WORK/body.raw"
        log "subscription taken from file"
        return 0
    fi
    if [ -n "$url_env" ]; then
        local url="${!url_env:-}"
        [ -n "$url" ] || die "$url_env is empty"
        case "$url" in https://*) ;; *) die "$url_env must be an https URL" ;; esac
        printf 'url = "%s"\n' "$url" | curl --config - --fail --silent --show-error \
            --location --proto '=https' --tlsv1.2 --max-filesize 1048576 \
            --max-time 60 --retry 2 --retry-all-errors \
            -o "$WORK/body.raw" || die "subscription fetch failed"
        chmod 600 "$WORK/body.raw"
        log "subscription fetched once and cached locally (provider rate-limits; re-runs reuse the cache)"
        return 0
    fi
    [ -s "$WORK/body.raw" ] || die "no subscription: pass --sub-file or --sub-url-env, or prime $WORK/body.raw"
    log "reusing cached subscription body"
}

plan() {
    resolve_subscription "$@"
    local pin=()
    [ "${AB_PIN_SERVER_IP:-1}" = "1" ] && pin+=("--pin-server-ip")
    python3 "$HERE/ab-link-to-singbox.py" \
        --sub-file "$WORK/body.raw" \
        --out-dir "$WORK/nodes" \
        --socks-port "$AB_SB_PORT" \
        --log-path "$DEVDIR/sb.log" \
        ${pin[@]+"${pin[@]}"}
}


stage() {
    plan "$@" >/dev/null || die "planning failed"
    dsh "mkdir -p $DEVDIR && chmod 700 $DEVDIR" >/dev/null

    local fox_socks="${AB_FOXCORE_SOCKS:-$ROOT/target/aarch64-linux-android/release/foxcore-socks}"
    local bench="${AB_BENCH_CLIENT:-$ROOT/target/aarch64-linux-android/release/foxcore-bench-client}"
    local singbox="${AB_SINGBOX:-}"

    for pair in "foxcore-socks:$fox_socks" "foxcore-bench-client:$bench"; do
        local name="${pair%%:*}" path="${pair#*:}"
        if [ -x "$path" ]; then
            device push "$path" "$DEVDIR/$name" >/dev/null && dsh "chmod 755 $DEVDIR/$name" >/dev/null
            log "staged $name from host build"
        elif dsh "test -x /data/local/tmp/ab/$name && echo yes" | grep -q yes; then
            dsh "cp /data/local/tmp/ab/$name $DEVDIR/$name && chmod 755 $DEVDIR/$name" >/dev/null
            log "staged $name from the device's existing /data/local/tmp/ab copy - VERSION NOT VERIFIED"
        else
            die "no $name: build for aarch64-linux-android or set AB_${name//-/_}"
        fi
    done

    if [ -n "$singbox" ] && [ -f "$singbox" ]; then
        device push "$singbox" "$DEVDIR/sing-box" >/dev/null && dsh "chmod 755 $DEVDIR/sing-box" >/dev/null
        log "staged sing-box from host"
    elif dsh "test -x /data/local/tmp/ab/sing-box && echo yes" | grep -q yes; then
        dsh "cp /data/local/tmp/ab/sing-box $DEVDIR/sing-box && chmod 755 $DEVDIR/sing-box" >/dev/null
        log "staged sing-box from the device's existing copy"
    else
        die "no sing-box binary: set AB_SINGBOX to a verified host-side download"
    fi

    device push "$HERE/ab-proc-sampler.sh" "$DEVDIR/proc-sampler.sh" >/dev/null
    dsh "chmod 755 $DEVDIR/proc-sampler.sh" >/dev/null

    local count=0
    for file in "$WORK"/nodes/*.link "$WORK"/nodes/*.sb.json; do
        [ -e "$file" ] || continue
        device push "$file" "$DEVDIR/$(basename "$file")" >/dev/null
        dsh "chmod 600 $DEVDIR/$(basename "$file")" >/dev/null
        count=$((count + 1))
    done
    log "staged $count node files"

    {
        printf 'sing_box_version: %s\n' "$(dsh "$DEVDIR/sing-box version | head -1")"
        printf 'sing_box_sha256: %s\n' "$(dsh "sha256sum $DEVDIR/sing-box" | awk '{print $1}')"
        printf 'foxcore_socks_sha256: %s\n' "$(dsh "sha256sum $DEVDIR/foxcore-socks" | awk '{print $1}')"
        printf 'bench_client_sha256: %s\n' "$(dsh "sha256sum $DEVDIR/foxcore-bench-client" | awk '{print $1}')"
        printf 'foxcore_version: %s\n' "$(awk -F'"' '/^version = /{print $2; exit}' "$ROOT/Cargo.toml")"
        printf 'device: %s %s (android %s, sdk %s)\n' \
            "$(dsh getprop ro.product.model)" "$(dsh getprop ro.product.cpu.abi)" \
            "$(dsh getprop ro.build.version.release)" "$(dsh getprop ro.build.version.sdk)"
    } > "$WORK/provenance.txt"
    cat "$WORK/provenance.txt" >&2
}


FOX_PATTERN='f[o]xcore-socks --selector'
SB_PATTERN='s[i]ng-box run -c'

arm_pattern() { [ "$1" = foxcore ] && printf '%s' "$FOX_PATTERN" || printf '%s' "$SB_PATTERN"; }

kill_arms() {
    dsh "for p in \$(pgrep -f '$FOX_PATTERN'; pgrep -f '$SB_PATTERN'; pgrep -f 'p[r]oc-sampler.sh'; pgrep -f 'f[o]xcore-bench-client'); do kill \$p 2>/dev/null; done" >/dev/null
    local waited=0
    while [ "$waited" -lt 15 ]; do
        if [ -z "$(dsh "pgrep -f '$FOX_PATTERN' ; pgrep -f '$SB_PATTERN'")" ]; then
            if ! dsh "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null" | awk '{print $2}' \
                | grep -qiE ":($(printf '%04X' "$AB_FOX_PORT")|$(printf '%04X' "$AB_SB_PORT"))\$"; then
                return 0
            fi
        fi
        sleep 1; waited=$((waited + 1))
    done
    dsh "for p in \$(pgrep -f '$FOX_PATTERN'; pgrep -f '$SB_PATTERN'); do kill -9 \$p 2>/dev/null; done" >/dev/null
    sleep 2
    if [ -n "$(dsh "pgrep -f '$FOX_PATTERN'; pgrep -f '$SB_PATTERN'")" ]; then
        log "WARNING: an arm survived teardown; the next measurement is not trustworthy"
        return 1
    fi
    return 0
}

await_listener() {
    local port_hex waited=0
    port_hex="$(printf '%04X' "$1")"
    while [ "$waited" -lt 25 ]; do
        if dsh "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null" | awk '{print $2}' | grep -qi ":$port_hex\$"; then
            return 0
        fi
        sleep 1; waited=$((waited + 1))
    done
    return 1
}

measure() {
    local arm="$1" node="$2" selector="$3" regime="$4"
    local port pid start_state end_state out_prefix
    out_prefix="$WORK/results/${regime}__${node}__${arm}"
    mkdir -p "$WORK/results"

    kill_arms
    start_state="$(state_json)"

    case "$arm" in
        foxcore)
            port="$AB_FOX_PORT"
            [ -n "$selector" ] || { record_skip "$out_prefix" "$arm" "$node" "$regime" "$start_state" "no foxcore selector for this scheme"; return; }
            dspawn "./foxcore-socks --selector $selector --socks-port $port --server raw" \
                "$node.$arm.out" "$node.link"
            ;;
        singbox)
            port="$AB_SB_PORT"
            dsh "test -f $DEVDIR/$node.sb.json && echo yes" | grep -q yes || { record_skip "$out_prefix" "$arm" "$node" "$regime" "$start_state" "no sing-box translation for this scheme"; return; }
            dspawn "./sing-box run -c $node.sb.json --disable-color" "$node.$arm.out"
            ;;
    esac

    if ! await_listener "$port"; then
        record_skip "$out_prefix" "$arm" "$node" "$regime" "$start_state" \
            "listener never bound: $(dsh "tail -3 $DEVDIR/$node.$arm.out" | tr '\n' ' ' | cut -c1-200)"
        kill_arms
        return
    fi

    pid="$(dsh "pgrep -f '$(arm_pattern "$arm")'" | head -1)"
    [ -n "$pid" ] || { record_skip "$out_prefix" "$arm" "$node" "$regime" "$start_state" "arm bound a listener but has no pid"; kill_arms; return; }

    dspawn "sh ./proc-sampler.sh $pid $AB_SAMPLE_S $node.$arm.proc.jsonl" "$node.$arm.sampler.out"

    _rep=1
    while [ "$_rep" -le "${AB_REPEATS:-1}" ]; do
        dsh "cd $DEVDIR && ./foxcore-bench-client --proxy 127.0.0.1:$port --target '$AB_TARGET' --path '$AB_PATH' --concurrency $AB_CONCURRENCY --duration-s $AB_DURATION_S --timeout-s $AB_TIMEOUT_S --label $regime/$arm/$node/r$_rep --out $node.$arm.bench.$_rep.jsonl" \
            > "$out_prefix.bench.$_rep.txt" 2>&1
        _rep=$((_rep + 1))
    done
    cat "$out_prefix.bench."*.txt > "$out_prefix.bench.txt" 2>/dev/null

    end_state="$(state_json)"
    kill_arms

    device pull "$DEVDIR/$node.$arm.proc.jsonl" "$out_prefix.proc.jsonl" >/dev/null 2>&1
    device pull "$DEVDIR/$node.$arm.bench.jsonl" "$out_prefix.bench.jsonl" >/dev/null 2>&1

    local valid="true" reason=""
    if [ "$(state_key "$start_state")" != "$(state_key "$end_state")" ]; then
        valid="false"; reason="device state changed during the measurement"
    fi
    printf '{"arm":"%s","node":"%s","regime":"%s","valid":%s,"invalid_reason":"%s","state_before":%s,"state_after":%s,"load":{"target":"%s","concurrency":%s,"duration_s":%s}}\n' \
        "$arm" "$node" "$regime" "$valid" "$reason" "$start_state" "$end_state" \
        "$AB_TARGET" "$AB_CONCURRENCY" "$AB_DURATION_S" > "$out_prefix.meta.json"
    log "$regime $node $arm: valid=$valid $reason"
}

record_skip() {
    local prefix="$1" arm="$2" node="$3" regime="$4" state="$5" reason="$6"
    mkdir -p "$(dirname "$prefix")"
    printf '{"arm":"%s","node":"%s","regime":"%s","valid":false,"invalid_reason":"%s","state_before":%s}\n' \
        "$arm" "$node" "$regime" "$reason" "$state" > "$prefix.meta.json"
    log "$regime $node $arm: SKIPPED - $reason"
}

run_regime() {
    local regime="${1:?run needs a regime label}"
    [ -s "$WORK/nodes/manifest.json" ] || die "run 'stage' first"

    local egress
    egress="$(shell_egress_interface)"
    case "$egress" in
        tun*|ppp*)
            log "shell traffic egresses via '$egress' - an always-on VPN is capturing this uid."
            log "Both arms would run inside that tunnel, and FoxCore would additionally be"
            log "carrying its own arm, so its CPU column would be understated. Ask the owner to"
            log "turn the always-on VPN off for the run (do not clear the setting yourself), or"
            log "set AB_ALLOW_VPN_CAPTURE=1 to record clearly-labelled non-comparable numbers."
            [ "${AB_ALLOW_VPN_CAPTURE:-0}" = "1" ] || die "refusing to measure through a captured uid"
            log "AB_ALLOW_VPN_CAPTURE=1: continuing, rows will be labelled vpn_capture=$egress"
            ;;
    esac

    log "=== regime $regime : $(state_json) ==="
    python3 - "$WORK/nodes/manifest.json" "${AB_ALL_NODES:-0}" "${AB_ONLY_NODES:-}" <<'PY' > "$WORK/selected.txt"
import json, sys
manifest = json.load(open(sys.argv[1]))
everything = sys.argv[2] == "1"
only = {n for n in sys.argv[3].split(",") if n}
seen = set()
for record in manifest:
    if only:
        if record["node_id"] not in only:
            continue
    elif not everything and record["shape"] in seen:
        continue
    seen.add(record["shape"])
    print(record["node_id"], record["foxcore_selector"] or "", record["singbox_translatable"])
PY
    while read -r node selector translatable <&3; do
        [ -n "$node" ] || continue
        case "$selector" in True|False) selector="" ;; esac
        case "${AB_ONLY_ARM:-both}" in
            foxcore) measure foxcore "$node" "$selector" "$regime" ;;
            singbox) measure singbox "$node" "$selector" "$regime" ;;
            *)
                measure foxcore "$node" "$selector" "$regime"
                measure singbox "$node" "$selector" "$regime"
                ;;
        esac
    done 3< "$WORK/selected.txt"
    log "regime $regime complete; results in $WORK/results"
}


regimes() {
    run_regime "plugged-screen-on"

    await_state plugged unplugged ab_unplug "FoxCore A/B: unplug now" \
        "Please DISCONNECT the USB cable. The harness is polling and will continue by itself once the unplug registers." \
        || die "no unplug registered"
    if ! device shell true >/dev/null 2>&1; then
        log "adb transport lost with the cable; the unplugged regime needs wireless adb (adb tcpip)."
        await_state plugged plugged ab_replug "FoxCore A/B: reconnect" \
            "adb was lost with the cable. Please RECONNECT the cable so the harness can finish." || true
        return 1
    fi
    run_regime "unplugged-screen-on"

    await_state screen off ab_screenoff "FoxCore A/B: screen off" \
        "Please turn the SCREEN OFF and leave the phone alone. The harness continues on its own." \
        || log "screen never went off; skipping the screen-off regime"
    if state_json | grep -q '"screen":"off"'; then
        run_regime "unplugged-screen-off"
    fi

    await_state plugged plugged ab_replug "FoxCore A/B: reconnect the cable" \
        "Measurements are done. Please RECONNECT the cable so logs can be collected." || true
    collect_logs
}

collect_logs() {
    mkdir -p "$WORK/logs"
    device logcat -d > "$WORK/logs/logcat.txt" 2>/dev/null
    dsh "dumpsys batterystats --charged" > "$WORK/logs/batterystats.txt" 2>/dev/null
    dsh "dumpsys power" > "$WORK/logs/power.txt" 2>/dev/null
    dsh "dumpsys deviceidle" > "$WORK/logs/deviceidle.txt" 2>/dev/null
    dsh "dumpsys thermalservice" > "$WORK/logs/thermal.txt" 2>/dev/null
    for file in "$WORK"/results/*.meta.json; do [ -e "$file" ] || continue; done
    log "logs collected into $WORK/logs"
    notify ab_done "FoxCore A/B: finished" "All regimes are done. You can use the phone normally."
}

table() {
    python3 "$HERE/ab-render-table.py" --results "$WORK/results" --provenance "$WORK/provenance.txt"
}

clean() {
    kill_arms
    dsh "rm -rf $DEVDIR" >/dev/null
    log "device scratch $DEVDIR removed (node links and configs with it)"
}

case "$COMMAND" in
    plan)    plan "$@" ;;
    stage)   stage "$@" ;;
    run)     run_regime "${1:-manual}" ;;
    regimes) regimes ;;
    logs)    collect_logs ;;
    table)   table ;;
    clean)   clean ;;
    state)   state_json; echo ;;
    *)       die "unknown command: $COMMAND" ;;
esac
