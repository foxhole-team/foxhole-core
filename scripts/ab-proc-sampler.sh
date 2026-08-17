#!/system/bin/sh
# Sample one process the same way for both arms of the comparison.
#
#   ab-proc-sampler.sh <pid> <interval-seconds> <out.jsonl>
#
# Everything here comes from /proc, so the arm being measured contributes
# nothing to its own measurement: no agent inside the process, no protocol, no
# clock of its own. That matters because the two arms are a Rust binary and a Go
# binary; sing-box's own `/debug/memory` reports Go heap figures and a getrusage
# high-water mark, and FoxCore exposes nothing comparable, so any in-process
# accounting would compare two runtimes' bookkeeping rather than their cost.
#
# This is `/data/local/tmp/ab/proc-sampler.sh` plus the two context-switch
# counters. The comparison asks for "wakeups", which on Android normally means
# the framework's per-uid alarm and wakelock accounting - and that does not
# exist for either arm here, because both run as the `shell` uid outside the
# app framework. Voluntary and non-voluntary context switches are the closest
# symmetric proxy /proc offers, and are labelled as a proxy rather than sold as
# wakeups.
#
# utime/stime are in clock ticks. Android is 100 Hz on every device this runs
# on, and /proc exposes no getconf here, so the divisor is fixed and recorded in
# the output rather than guessed at read time.
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

# Field 14 and 15 of /proc/<pid>/stat are utime and stime, but the second field
# is the executable name in parentheses and may itself contain spaces. Cutting
# after the last ')' is the only parse that survives that.
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

    # A field that could not be read is emitted as -1 rather than skipped, so a
    # gap in the series is visible instead of being silently interpolated later.
    printf '{"t":%s,"elapsed_s":%s,"pid":%s,"utime_ticks":%s,"stime_ticks":%s,"ticks_per_s":%s,"rss_kb":%s,"hwm_kb":%s,"vsz_kb":%s,"threads":%s,"fds":%s,"vol_ctx":%s,"nonvol_ctx":%s}\n' \
        "$now" "$elapsed" "$pid" \
        "${utime:--1}" "${stime:--1}" "$TICKS_PER_SECOND" \
        "${rss:--1}" "${hwm:--1}" "${vsz:--1}" "${threads:--1}" "${fds:--1}" \
        "${vctx:--1}" "${nvctx:--1}" \
        >> "$out"

    sleep "$interval"
done

echo "sampler done: pid $pid gone after ${elapsed:-0}s" >&2
