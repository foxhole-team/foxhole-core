#!/usr/bin/env bash
# FoxCore on a network that is not ideal.
#
# Every end-to-end run this core had was over a clean link, which answers "does
# it work" and nothing else. The question that matters on a phone is how it
# *degrades*: whether a lossy uplink turns into growing memory, whether a stalled
# flow is ever torn down, whether the backlog ceiling fires where it should and
# stays quiet where it should not, and whether a black hole — packets that leave
# and never come back — is closed by a timeout or held forever.
#
# Two containers on a private bridge:
#
#   origin  busybox httpd with fixed-size payloads. Nothing about it varies.
#   client  the real data plane: a Linux TUN, CoreRuntime started on it through
#           the same entry point the JNI layer uses, and a load generator.
#
# The impairment is `tc netem` on **both** containers' egress, because this
# kernel (linuxkit) has no `ifb` module and therefore no ingress redirect: one
# sided netem would impair our packets and leave the replies pristine, which is
# not what a bad link looks like. Applying it to both egress paths gives a
# bidirectional impairment without ifb.
#
# The loop this design has to avoid: the load generator's destination is routed
# into the TUN, and a `direct` route means the core dials that same address. If
# both used the same routing table the core's own socket would be fed back into
# its own tunnel. The fix is the one Android itself uses — route by UID. The
# generator runs as uid 1000 and its traffic goes to the TUN; the core runs as
# root and its sockets take the ordinary route.
#
# Usage:
#   scripts/netem-lab.sh up
#   scripts/netem-lab.sh run <arm> <engine-config.json> <out-dir> [seconds]
#   scripts/netem-lab.sh down
#
# Arms: clean delay loss1 loss5 loss20 reorder duplicate mtu1280 blackhole
set -euo pipefail

# Overridable so a six-hour soak can have a bridge and an origin of its own.
# Two labs on one bridge would share the impairment: `tc` is applied to the
# origin's interface, and a netem arm would silently impair the soak too.
LAB="${FOXCORE_LAB:-foxlab}"
NET="$LAB"
SUBNET="${FOXCORE_LAB_SUBNET:-172.31.7.0/24}"
ORIGIN_IP="${FOXCORE_LAB_ORIGIN:-172.31.7.10}"
IMAGE=foxcore-lab:net
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# Built for aarch64 with `+crt-static`, so it carries its own libc and runs on
# any aarch64 Linux kernel — including this Alpine image, which has no glibc.
# The alternative was a full toolchain container, and on a 10 KB/s uplink that
# is a four-hour download rather than a build.
BIN="${FOXCORE_SOAK_BIN:-$HERE/target/aarch64-linux-android/release/foxcore-soak}"

# Payload sizes the origin serves. 1 MiB is the throughput unit; 64 KiB is small
# enough that a run under 20% loss still completes requests, which is what makes
# the loss arms comparable at all.
PAYLOAD_LARGE=1048576
PAYLOAD_SMALL=65536

netem_for() {
    case "$1" in
    clean) printf '' ;;
    delay) printf 'delay 100ms 20ms distribution normal' ;;
    loss1) printf 'loss 1%%' ;;
    loss5) printf 'loss 5%%' ;;
    loss20) printf 'loss 20%%' ;;
    # Reordering needs a delay to reorder *against*; netem cannot reorder a
    # queue it releases immediately.
    reorder) printf 'delay 20ms reorder 25%% 50%%' ;;
    duplicate) printf 'duplicate 5%%' ;;
    mtu1280) printf '' ;;
    # The one arm that is not about throughput: packets leave and nothing comes
    # back. A flow that survives this is a flow that leaks.
    blackhole | blackhole-mid | upload-blackhole) printf 'loss 100%%' ;;
    upload-clean) printf '' ;;
    *)
        echo "unknown arm: $1" >&2
        exit 2
        ;;
    esac
}

# When the impairment lands. Empty means "before the run", which is the honest
# way to measure a dial into a hole; a number means "after the flow is already
# established", which is a different failure and the only one that can reach the
# backlog ceiling.
impair_at_for() {
    case "$1" in
    blackhole-mid | upload-blackhole) printf '20' ;;
    *) printf '' ;;
    esac
}

# The upload arms push into a sink that discards, because a download can never
# fill the backlog: the direction that stalls there is the one the stack already
# applies backpressure to.
is_upload() {
    case "$1" in
    upload-*) return 0 ;;
    *) return 1 ;;
    esac
}

up() {
    docker network inspect "$NET" >/dev/null 2>&1 ||
        docker network create --subnet "$SUBNET" "$NET" >/dev/null
    if ! docker inspect $LAB-origin >/dev/null 2>&1; then
        docker run -d --name $LAB-origin --network "$NET" --ip "$ORIGIN_IP" \
            --cap-add=NET_ADMIN \
            -v "$BIN":/usr/local/bin/foxcore-soak:ro \
            "$IMAGE" sh -c "
              mkdir -p /srv
              dd if=/dev/zero of=/srv/large bs=1 count=0 seek=$PAYLOAD_LARGE 2>/dev/null
              dd if=/dev/zero of=/srv/small bs=1 count=0 seek=$PAYLOAD_SMALL 2>/dev/null
              foxcore-soak --role sink --target 0.0.0.0:9999 --duration-s 86400 &
              httpd -f -p 80 -h /srv" >/dev/null
    fi
    echo "lab up: origin=$ORIGIN_IP net=$NET"
}

down() {
    docker rm -f $LAB-origin >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    echo "lab down"
}

run_arm() {
    local arm="$1" config="$2" outdir="$3" seconds="${4:-120}"
    local qdisc
    qdisc="$(netem_for "$arm")"
    mkdir -p "$outdir"
    [ -x "$BIN" ] || {
        echo "harness binary missing: $BIN" >&2
        exit 3
    }

    local impair_at
    impair_at="$(impair_at_for "$arm")"

    # Both directions, because there is no ifb on this kernel.
    docker exec $LAB-origin sh -c "tc qdisc del dev eth0 root 2>/dev/null || true"
    if [ -n "$qdisc" ] && [ -z "$impair_at" ]; then
        docker exec $LAB-origin sh -c "tc qdisc replace dev eth0 root netem $qdisc"
    fi
    if [ -n "$impair_at" ]; then
        (
            sleep "$impair_at"
            docker exec $LAB-origin sh -c "tc qdisc replace dev eth0 root netem $qdisc" || true
            docker exec "${LAB}-client-${arm}" sh -c \
                "tc qdisc replace dev eth0 root netem $qdisc" || true
            echo "arm=$arm impairment applied at t=${impair_at}s"
        ) &
    fi

    local mtu=1400
    [ "$arm" = "mtu1280" ] && mtu=1280
    # The local origin is the deterministic case. A proxy profile has to reach a
    # server on the real internet, and then the only honest target is one out
    # there too — so both are expressible, and which one a row used is recorded
    # with the row.
    local load_args="--path ${FOXCORE_ARM_PATH:-/large} --target ${FOXCORE_ARM_TARGET:-$ORIGIN_IP:80}"
    if is_upload "$arm"; then
        load_args="--upload-bytes 33554432 --target $ORIGIN_IP:9999"
    fi
    # One pusher by default on the upload arms: the ceiling is a per-flow
    # property, and eight of them racing only makes it harder to say which flow
    # reached it.
    local default_concurrency=8
    is_upload "$arm" && default_concurrency=1
    local concurrency="${FOXCORE_ARM_CONCURRENCY:-$default_concurrency}"
    local load_seconds="${FOXCORE_ARM_LOAD_SECONDS:-$((seconds - 5))}"

    docker run --rm --name "${LAB}-client-${arm}" --network "$NET" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        -v "$BIN":/usr/local/bin/foxcore-soak:ro \
        -v "$config":/run/config.json:ro \
        -v "$outdir":/out \
        -e ARM="$arm" -e SECONDS_TO_RUN="$seconds" \
        -e QDISC="$([ -z "$impair_at" ] && printf '%s' "$qdisc")" \
        -e LOAD_ARGS="$load_args" -e CONCURRENCY="$concurrency" \
        -e LOAD_SECONDS="$load_seconds" \
        -e ORIGIN_IP="$ORIGIN_IP" -e TUN_MTU="$mtu" \
        "$IMAGE" sh -c '
set -e
if [ -n "$QDISC" ]; then tc qdisc replace dev eth0 root netem $QDISC; fi
if [ "$TUN_MTU" = "1280" ]; then ip link set eth0 mtu 1280; fi
ip tuntap add dev fox0 mode tun
# The same address the generated device config carries, so the packet the core
# reads has the source it expects to see.
ip addr add 10.0.0.2/24 dev fox0
ip link set fox0 mtu "$TUN_MTU" up
# Per-UID routing: only the generator goes through the tunnel, so the core
# dialling the same destination does not re-enter its own TUN.
ip route add default dev fox0 table 100
ip rule add uidrange 1000-1000 lookup 100
adduser -D -u 1000 loadgen 2>/dev/null || true
foxcore-soak --role core --config /run/config.json --tun fox0 \
    --duration-s "$SECONDS_TO_RUN" --interval-s 10 --out "/out/$ARM.core.jsonl" &
CORE=$!
sleep 3
su loadgen -s /bin/sh -c "foxcore-soak --role load $LOAD_ARGS --host origin \
    --concurrency $CONCURRENCY --duration-s $LOAD_SECONDS --interval-s 10 \
    --request-timeout-s 30 --out /out/$ARM.load.jsonl"
wait $CORE
'
    echo "arm=$arm done -> $outdir/$arm.core.jsonl"
}

# The long run, detached.
#
# Detached on purpose: six hours is longer than any shell that started it is
# likely to live, and a soak that dies with its terminal measures the terminal.
# The samples land on a host directory as they are written, so a run that is
# interrupted still leaves the trend up to the point it stopped.
soak() {
    local config="$1" outdir="$2" seconds="${3:-21600}" concurrency="${4:-4}"
    local pace="${5:-200}"
    mkdir -p "$outdir"
    docker rm -f "$LAB-soak" >/dev/null 2>&1 || true
    docker run -d --name "$LAB-soak" --network "$NET" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        -v "$BIN":/usr/local/bin/foxcore-soak:ro \
        -v "$config":/run/config.json:ro \
        -v "$outdir":/out \
        -e SECONDS_TO_RUN="$seconds" -e ORIGIN_IP="$ORIGIN_IP" \
        -e CONCURRENCY="$concurrency" -e PACE_MS="$pace" \
        -e NAME="${FOXCORE_SOAK_NAME:-soak}" \
        -e TARGET_HOST="${FOXCORE_SOAK_TARGET:-}" \
        -e TARGET_PATH="${FOXCORE_SOAK_PATH:-/large}" \
        "$IMAGE" sh -c '
set -e
ip tuntap add dev fox0 mode tun
ip addr add 10.0.0.2/24 dev fox0
ip link set fox0 mtu 1400 up
ip route add default dev fox0 table 100
ip rule add uidrange 1000-1000 lookup 100
adduser -D -u 1000 loadgen 2>/dev/null || true
TARGET="${TARGET_HOST:-$ORIGIN_IP:80}"
foxcore-soak --role core --config /run/config.json --tun fox0 \
    --duration-s "$SECONDS_TO_RUN" --interval-s 60 \
    --network-change-every-s 900 --out "/out/$NAME.core.jsonl" &
CORE=$!
sleep 3
LOAD_SECONDS=$((SECONDS_TO_RUN - 10))
su loadgen -s /bin/sh -c "foxcore-soak --role load \
    --target $TARGET --path $TARGET_PATH --host origin \
    --concurrency $CONCURRENCY --pace-ms $PACE_MS \
    --duration-s $LOAD_SECONDS --interval-s 60 \
    --request-timeout-s 60 --out /out/$NAME.load.jsonl" &
wait $CORE
' >/dev/null
    echo "soak started: container=$LAB-soak out=$outdir seconds=$seconds"
}

case "${1:-}" in
up) up ;;
down) down ;;
run)
    shift
    run_arm "$@"
    ;;
soak)
    shift
    soak "$@"
    ;;
*)
    echo "usage: netem-lab.sh up | run <arm> <config> <outdir> [seconds] |" >&2
    echo "       soak <config> <outdir> [seconds] [concurrency] [pace-ms] | down" >&2
    exit 2
    ;;
esac
