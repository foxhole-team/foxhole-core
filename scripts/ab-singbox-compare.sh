#!/usr/bin/env bash
# FoxCore against bare sing-box, per protocol, on one phone, automatically.
#
#   scripts/ab-singbox-compare.sh <serial> plan     [--sub-file P | --sub-url-env VAR]
#   scripts/ab-singbox-compare.sh <serial> stage    [--sub-file P | --sub-url-env VAR]
#   scripts/ab-singbox-compare.sh <serial> run      <regime-label>
#   scripts/ab-singbox-compare.sh <serial> regimes
#   scripts/ab-singbox-compare.sh <serial> table
#   scripts/ab-singbox-compare.sh <serial> clean
#
# ---------------------------------------------------------------------------
# WHY THE COMPARISON HAS THIS SHAPE
#
# Both arms are driven as a local SOCKS5 listener on the phone, not as a VPN.
# That is not a convenience: sing-box cannot open a TUN on a stock non-rooted
# Android device, and Android deliberately keeps the `shell` uid outside VPN
# capture so adb survives a tunnel - so a shell-side load generator never
# reaches a TUN in either arm. A SOCKS listener in front of one outbound is the
# only shape both cores can take identically, which makes it the only shape in
# which a number means anything. `scripts/device-tun-plane.sh` covers what the
# TUN plane can still say honestly (process footprint), and says why it cannot
# say more.
#
# Everything that could differ between the arms is pinned to the same value:
#
#   * the same node - one share link, parsed by foxcore-link for the FoxCore
#     arm and translated once by ab-link-to-singbox.py for the sing-box arm;
#   * the same load - one `foxcore-bench-client` binary, which imports no
#     workspace crate, driving both arms with identical target, concurrency,
#     duration and timeout;
#   * the same listener shape - SOCKS5 with no authentication on both sides
#     (`--server raw` for FoxCore, a `socks` inbound for sing-box), because
#     FoxCore's audited LAN proxy carries a 64-session ceiling that sing-box's
#     inbound has no equivalent of, and measuring against it would report a
#     product decision as a throughput result;
#   * the same accounting - /proc sampling from outside both processes, so
#     neither a Rust nor a Go runtime's own bookkeeping is in the number;
#   * the same regime - device state is read before and after every single
#     measurement, and a measurement whose state moved underneath it is
#     written out as INVALID rather than kept.
#
# WHAT THIS CANNOT MEASURE, AND WILL NOT PRETEND TO
#
#   * Doze and app-standby buckets do not apply to a `shell`-uid process, so
#     the screen-off and unplugged regimes here capture the CPU governor, the
#     radio and thermal state - not Doze. Rows are labelled with the state
#     that was actually read, never with a regime that was merely intended.
#   * Wakelocks are an app-framework concept. Neither arm holds one, so the
#     column reports involuntary/voluntary context switches from /proc, which
#     is the closest symmetric proxy, and says so.
#   * If a node starts in one arm and not the other, that is the result. The
#     row is kept with the failing cell marked, never dropped and never
#     re-pointed at a different node.
#
# CREDENTIALS
#
# The subscription is never a literal in this file. It arrives as a file path
# or as the *name* of an environment variable holding the URL. Generated node
# configs live in a scratch directory outside the repo, mode 0600, and are
# removed from the device by `clean`. Nothing this script prints contains a
# server address, uuid, password or key: nodes are named `vless-reality-grpc-3`.
set -uo pipefail

ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
SERIAL="${1:?usage: ab-singbox-compare.sh <serial> <command> [args]}"
COMMAND="${2:?usage: ab-singbox-compare.sh <serial> <command> [args]}"
shift 2

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# Scratch, never the repo. Overridable so a caller can keep a run.
WORK="${AB_WORK_DIR:-${TMPDIR:-/tmp}/foxcore-ab}"
DEVDIR="${AB_DEVICE_DIR:-/data/local/tmp/ab-run}"

# Load shape. One set of values for both arms, recorded into every row.
AB_TARGET="${AB_TARGET:-speed.cloudflare.com:80}"
AB_PATH="${AB_PATH:-/__down?bytes=10000000}"
AB_CONCURRENCY="${AB_CONCURRENCY:-4}"
AB_DURATION_S="${AB_DURATION_S:-20}"
AB_TIMEOUT_S="${AB_TIMEOUT_S:-30}"
AB_SAMPLE_S="${AB_SAMPLE_S:-1}"
AB_FOX_PORT="${AB_FOX_PORT:-11080}"
AB_SB_PORT="${AB_SB_PORT:-11081}"
# How long to wait for the owner to unplug / reconnect before giving up on a
# regime. The owner is using the phone; blind sleeps are not acceptable here.
AB_PROMPT_TIMEOUT_S="${AB_PROMPT_TIMEOUT_S:-900}"

device() { "$ADB" -s "$SERIAL" "$@"; }
dsh() { device shell "$@" 2>/dev/null | tr -d '\r'; }

# Start something on the device and come straight back.
#
# `adb shell "cmd &"` does NOT return: adb holds the connection open until every
# descendant has released the shell's stdout, and a backgrounded child keeps it.
# Observed directly here - the arm came up, and the harness then sat on the adb
# call forever while the measurement window it was supposed to be timing ran out.
# `setsid` in a subshell with all three descriptors redirected is what actually
# detaches it.
# dspawn <command> <stdout-file> [stdin-file]
dspawn() {
    local command="$1" out="$2" in_file="${3:-/dev/null}"
    device shell "cd $DEVDIR && ( setsid $command <$in_file >>$out 2>&1 & ) ; echo spawned" >/dev/null 2>&1
}
log() { printf '[ab] %s\n' "$*" >&2; }
die() { printf '[ab] FATAL: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Device state. Read, never assumed. Every measurement carries the state it
# was taken in, and a state that moved mid-measurement invalidates the row.
# --------------------------------------------------------------------------

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
    # `Dreaming` is the screensaver/daydream, and it is NOT an idle display: the
    # panel is lit and the CPU is doing screensaver work. It used to fall into
    # the `*)` arm and be recorded as "unknown", which the fairness gate then
    # happily compared against another "unknown" - two rows agreeing that
    # neither knew what state it was in. Named explicitly so a dreaming window
    # can never be published as a screen-off one. `stay_on_while_plugged_in`
    # plus no display timeout is what produces it while charging.
    case "$power" in
        *Awake*) screen="on" ;;
        *Dreaming*) screen="dreaming" ;;
        *Asleep*|*Dozing*) screen="off" ;;
        *) screen="unknown" ;;
    esac
    deep="$(dsh dumpsys deviceidle get deep)"
    light="$(dsh dumpsys deviceidle get light)"
    # The fuel gauge's own uAh accumulator, carried on every measurement so a
    # battery delta needs no separate bookkeeping. It quantises at 16000 uAh on
    # this device (one step = 16 mAh), which is why a 180s window was
    # unresolvable: three of four arms landed on exactly one step and the
    # comparison could not tell them apart. A window has to be long enough to
    # accumulate many steps before the difference between arms means anything.
    local charge
    charge="$(dsh 'cat /sys/class/power_supply/battery/charge_counter 2>/dev/null')"
    printf '{"plugged":"%s","battery_pct":%s,"battery_decikelvin":%s,"screen":"%s","doze_deep":"%s","doze_light":"%s","vpn_capture":"%s","charge_uah":%s,"t":%s}' \
        "$plugged" "${level:-null}" "${temp:-null}" "$screen" "${deep:-unknown}" "${light:-unknown}" \
        "$(shell_egress_interface)" "${charge:--1}" "$(date +%s)"
}

# Which interface the `shell` uid actually leaves by.
#
# This is not a detail. Android usually keeps uid 2000 outside VPN capture so
# adb survives a tunnel - but with an always-on VPN in lockdown mode the uid
# range that gets the tun table is 0-99999, which includes shell. On this
# device `ip route get 1.1.1.1` for uid 2000 resolved to `dev tun0`, meaning
# BOTH arms were dialling out through the owner's running VPN.
#
# That is fatal to the CPU column specifically: FoxCore then sits in the path
# twice - once as the arm under test, once as the VPN carrying it - and only
# the first process is sampled, so FoxCore's measured cost is understated by
# however much work happened in the VPN process. Throughput and latency are
# merely bounded rather than skewed, but nothing here is a clean core number.
shell_egress_interface() {
    dsh "ip route get 1.1.1.1 2>/dev/null" | awk '/dev/ {for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}'
}

state_key() {
    # The fields a row is only comparable within. Battery percentage and
    # temperature drift continuously and are recorded but not part of the key.
    printf '%s\n' "$1" | sed -E 's/.*"plugged":"([^"]*)".*"screen":"([^"]*)","doze_deep":"([^"]*)","doze_light":"([^"]*)".*/\1|\2|\3|\4/'
}

notify() {
    local tag="$1" title="$2" body="$3"
    dsh "cmd notification post -S bigtext -t '$title' '$tag' '$body'" >/dev/null
}

# Poll a real device predicate rather than sleeping. The owner may take a long
# time; the notification is re-posted periodically so it is not lost under
# other notifications.
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
        # Re-post every minute so a buried notification still gets seen.
        [ $((waited % 60)) -eq 0 ] && notify "$tag" "$title" "$body"
    done
    log "timed out after ${AB_PROMPT_TIMEOUT_S}s waiting for $field=$want"
    return 1
}

# --------------------------------------------------------------------------
# Subscription intake. Path or env-var name, never a literal, never argv.
# --------------------------------------------------------------------------

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
        # Down curl's stdin config, so the URL never appears in `ps`.
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
    # `--pin-server-ip` is on by default and can be turned off with
    # AB_PIN_SERVER_IP=0. See the note in ab-link-to-singbox.py: without it the
    # sing-box arm cannot resolve the node's own hostname on Android and fails
    # every request in milliseconds, which would read as a FoxCore win.
    local pin=()
    [ "${AB_PIN_SERVER_IP:-1}" = "1" ] && pin+=("--pin-server-ip")
    python3 "$HERE/ab-link-to-singbox.py" \
        --sub-file "$WORK/body.raw" \
        --out-dir "$WORK/nodes" \
        --socks-port "$AB_SB_PORT" \
        --log-path "$DEVDIR/sb.log" \
        ${pin[@]+"${pin[@]}"}
}

# --------------------------------------------------------------------------
# Staging. Binaries and node configs onto the device.
# --------------------------------------------------------------------------

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

    # Node material. 0600 on the device too; `clean` removes it.
    local count=0
    for file in "$WORK"/nodes/*.link "$WORK"/nodes/*.sb.json; do
        [ -e "$file" ] || continue
        device push "$file" "$DEVDIR/$(basename "$file")" >/dev/null
        dsh "chmod 600 $DEVDIR/$(basename "$file")" >/dev/null
        count=$((count + 1))
    done
    log "staged $count node files"

    # Record exactly what is being compared, by digest, so a table can never be
    # quoted against a binary nobody can identify later.
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

# --------------------------------------------------------------------------
# One arm, one node, one measurement.
# --------------------------------------------------------------------------

# The arms are started after a `cd` into the device directory, so their argv[0]
# is the bare `./foxcore-socks`, NOT the absolute path. Matching on `$DEVDIR/...`
# therefore matches nothing - which is not a harmless miss: it left a previous
# run's listener holding the port, the new arm died with EADDRINUSE, and the
# load generator happily measured the stale process instead. Both the pattern
# and its verification are on argv shapes that actually occur.
#
# The bracket in each pattern is load-bearing, not decoration. `pgrep -f` and
# `pkill -f` on toybox match against every process's full command line -
# including the `sh -c "pkill -f 'sing-box run -c'"` that adb just spawned to
# run the kill. So a naive `pkill -f 'sing-box run -c'` matches its own shell
# and kills it, and the process it was aimed at survives. Observed directly:
# sing-box stayed up for four minutes across several measurements while
# proc-samplers piled up behind it, which is the failure that silently
# measures a stale process from a previous node. `s[i]ng-box` is a regex that
# matches the literal text "sing-box" in the target, but the killer shell's own
# argv contains "s[i]ng-box", which that regex does not match.
FOX_PATTERN='f[o]xcore-socks --selector'
SB_PATTERN='s[i]ng-box run -c'

arm_pattern() { [ "$1" = foxcore ] && printf '%s' "$FOX_PATTERN" || printf '%s' "$SB_PATTERN"; }

kill_arms() {
    dsh "for p in \$(pgrep -f '$FOX_PATTERN'; pgrep -f '$SB_PATTERN'; pgrep -f 'p[r]oc-sampler.sh'; pgrep -f 'f[o]xcore-bench-client'); do kill \$p 2>/dev/null; done" >/dev/null
    local waited=0
    while [ "$waited" -lt 15 ]; do
        if [ -z "$(dsh "pgrep -f '$FOX_PATTERN' ; pgrep -f '$SB_PATTERN'")" ]; then
            # A dead process can still hold the port for a moment; the next arm
            # binds the same one, so wait for the socket, not just the pid.
            if ! dsh "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null" | awk '{print $2}' \
                | grep -qiE ":($(printf '%04X' "$AB_FOX_PORT")|$(printf '%04X' "$AB_SB_PORT"))\$"; then
                return 0
            fi
        fi
        sleep 1; waited=$((waited + 1))
    done
    dsh "for p in \$(pgrep -f '$FOX_PATTERN'; pgrep -f '$SB_PATTERN'); do kill -9 \$p 2>/dev/null; done" >/dev/null
    sleep 2
    # A teardown that did not tear down must not be silent: the next arm would
    # bind nothing, the generator would drive the corpse of the previous one,
    # and the row would look perfectly normal.
    if [ -n "$(dsh "pgrep -f '$FOX_PATTERN'; pgrep -f '$SB_PATTERN'")" ]; then
        log "WARNING: an arm survived teardown; the next measurement is not trustworthy"
        return 1
    fi
    return 0
}

# A listener that is bound is not the same as a core that is ready, but it is
# the only readiness signal both arms emit identically, so it is what both are
# held to - and the handshake cost that follows lands in `connect_us`, where it
# belongs, for both.
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

# arm=foxcore|singbox  node_id  selector  regime
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

    # Repeats, because one window is not a measurement. The same node/arm was
    # seen to swing 16.49 -> 10.78 MiB/s between two single 20s windows, which
    # is wide enough that any single-window throughput claim is noise. The arm
    # stays up across the repeats so what varies is the network, not process
    # startup; the /proc sampler spans the whole set, so CPU-per-GiB is computed
    # over total ticks and total bytes and is unaffected by the split.
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

    # Refuse rather than produce a number nobody can defend. An always-on VPN in
    # lockdown mode pulls the shell uid into the tunnel, and then every byte of
    # both arms is carried by a third proxy whose CPU is charged to neither.
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
    # One representative node per distinct shape by default: the owner's list
    # carries ten identical gRPC nodes, and measuring all of them costs an hour
    # to learn one fact. AB_ALL_NODES=1 measures every line.
    # AB_ONLY_NODES narrows the run to named nodes. The battery regime needs
    # windows of 20-30 minutes per arm to clear the fuel gauge's 16 mAh quantum,
    # and at that length a full protocol sweep would take hours of the owner's
    # phone. One node measured properly is worth more than six measured below
    # the resolution of the instrument.
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
    # The node list is read on fd 3, not stdin. `adb` drains its own stdin, so
    # a plain `while read ... done < list` loses every line after the first:
    # observed here as a regime that reported "complete" after one node of
    # eight, which is the worst possible failure - it looks like a finished run.
    while read -r node selector translatable <&3; do
        [ -n "$node" ] || continue
        # A node with no FoxCore selector prints an empty second field, which
        # word-splitting collapses so `translatable` lands in `selector`. Left
        # alone that produced "protocol selector is not supported: False",
        # which reads as a FoxCore parser failure rather than "this scheme has
        # no FoxCore arm".
        case "$selector" in True|False) selector="" ;; esac
        # AB_ONLY_ARM re-takes a single arm. Needed because a battery window
        # can be spoiled by the Doze state it happened to start in: the first
        # FoxCore window spanned INACTIVE->IDLE while sing-box's sat entirely in
        # IDLE, so FoxCore carried pre-Doze drain sing-box never saw. Re-taking
        # one arm into the same steady state is the fix; re-running both would
        # just move the mismatch to the other arm.
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

# --------------------------------------------------------------------------
# The regime sequence the owner described, driven by notifications and by
# polling real device state - never by a blind sleep.
# --------------------------------------------------------------------------

regimes() {
    run_regime "plugged-screen-on"

    await_state plugged unplugged ab_unplug "FoxCore A/B: unplug now" \
        "Please DISCONNECT the USB cable. The harness is polling and will continue by itself once the unplug registers." \
        || die "no unplug registered"
    # adb over USB is gone at this point unless the owner has wireless adb on.
    # Verify the transport survived before claiming a regime can run at all.
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
