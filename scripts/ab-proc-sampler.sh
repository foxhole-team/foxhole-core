#!/system/bin/sh
set -u

pid="${1:?usage: ab-proc-sampler.sh <pid> <interval-s> <out.jsonl>}"
interval="${2:?usage: ab-proc-sampler.sh <pid> <interval-s> <out.jsonl>}"
out="${3:?usage: ab-proc-sampler.sh <pid> <interval-s> <out.jsonl>}"

TICKS_PER_SECOND=100

if [ ! -d "/proc/$pid" ]; then
    echo "no such pid: $pid" >&2
    exit 2
fi

: > "$out"

read_cpu_ticks() {
    _line=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
    _rest=${_line#*") "}
    echo "$_rest" | awk '{print $12, $13}'
}

started=$(date +%s)

while [ -d "/proc/$pid" ]; do
    now=$(date +%s)
    elapsed=$((now - started))

    ticks=$(read_cpu_ticks) || break
    utime=${ticks% *}
    stime=${ticks#* }

    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    vsz=$(awk '/^VmSize:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    vctx=$(awk '/^voluntary_ctxt_switches:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    nvctx=$(awk '/^nonvoluntary_ctxt_switches:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l | tr -d ' ')

    printf '{"t":%s,"elapsed_s":%s,"pid":%s,"utime_ticks":%s,"stime_ticks":%s,"ticks_per_s":%s,"rss_kb":%s,"hwm_kb":%s,"vsz_kb":%s,"threads":%s,"fds":%s,"vol_ctx":%s,"nonvol_ctx":%s}\n' \
        "$now" "$elapsed" "$pid" \
        "${utime:--1}" "${stime:--1}" "$TICKS_PER_SECOND" \
        "${rss:--1}" "${hwm:--1}" "${vsz:--1}" "${threads:--1}" "${fds:--1}" \
        "${vctx:--1}" "${nvctx:--1}" \
        >> "$out"

    sleep "$interval"
done

echo "sampler done: pid $pid gone after ${elapsed:-0}s" >&2
