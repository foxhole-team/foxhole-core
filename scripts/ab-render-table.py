#!/usr/bin/env python3
"""Render the FoxCore/sing-box comparison as a markdown table.

The rules this file enforces are the point of it. A comparison is only worth
publishing if the reader can tell which cells are measurements and which are
absences, so:

  * a cell whose two arms were measured in different device states is left
    EMPTY, with the reason printed underneath - a number taken under different
    conditions in the two arms is worse than no number;
  * an arm that failed to start is printed as `failed`, and the row is kept:
    "this protocol works in one core and not the other" is a result, not a
    missing row;
  * every row carries the regime it was taken in, so screen-on and screen-off
    numbers can never be silently averaged together;
  * CPU is reported as CPU-seconds per GiB carried, not as a percentage. A
    percentage rewards an arm that moved less data.

Nothing here reaches the network, and nothing it prints contains an endpoint.
"""

import argparse
import json
import os
import sys
from collections import defaultdict


def read_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def read_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as handle:
            return json.load(handle)
    except Exception:
        return None


def median(values):
    values = sorted(values)
    if not values:
        return None
    mid = len(values) // 2
    return values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2


def bench_summary(path):
    """Every repeat window, folded into one summary.

    Throughput becomes the MEDIAN across repeats with the min/max kept beside
    it, because a single window of this is demonstrably noisy. Byte and request
    counters are summed, since CPU-per-GiB is computed over the whole sampled
    span and has to be divided by the bytes that span actually carried.
    """
    if not os.path.exists(path):
        return None
    runs = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("{") and '"mib_per_s"' in line:
                try:
                    runs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not runs:
        return None
    rates = [r.get("mib_per_s", 0.0) for r in runs]
    merged = dict(runs[0])
    merged["mib_per_s"] = median(rates)
    merged["mib_per_s_min"] = min(rates)
    merged["mib_per_s_max"] = max(rates)
    merged["repeats"] = len(runs)
    merged["bytes"] = sum(r.get("bytes", 0) for r in runs)
    merged["ok"] = sum(r.get("ok", 0) for r in runs)
    merged["failed"] = sum(r.get("failed", 0) for r in runs)
    widest = max(runs, key=lambda r: r.get("ok", 0))
    merged["connect_us"] = widest.get("connect_us", {})
    merged["ttfb_us"] = widest.get("ttfb_us", {})
    return merged


def proc_delta(rows):
    """CPU ticks, context switches and peak memory over the sampled window."""
    rows = [r for r in rows if r.get("utime_ticks", -1) >= 0]
    if len(rows) < 2:
        return None
    first, last = rows[0], rows[-1]
    ticks_per_s = first.get("ticks_per_s", 100)
    cpu_s = ((last["utime_ticks"] + last["stime_ticks"])
             - (first["utime_ticks"] + first["stime_ticks"])) / ticks_per_s
    def delta(key):
        a, b = first.get(key, -1), last.get(key, -1)
        return (b - a) if (a >= 0 and b >= 0) else None
    return {
        "cpu_s": cpu_s,
        "rss_peak_kb": max((r.get("hwm_kb", -1) for r in rows), default=-1),
        "rss_max_kb": max((r.get("rss_kb", -1) for r in rows), default=-1),
        "threads_max": max((r.get("threads", -1) for r in rows), default=-1),
        "vol_ctx": delta("vol_ctx"),
        "nonvol_ctx": delta("nonvol_ctx"),
        "samples": len(rows),
    }


def load_cell(results_dir, regime, node, arm):
    prefix = os.path.join(results_dir, f"{regime}__{node}__{arm}")
    meta = read_json(prefix + ".meta.json")
    if meta is None:
        return None
    cell = {"meta": meta, "bench": bench_summary(prefix + ".bench.txt"),
            "proc": proc_delta(read_jsonl(prefix + ".proc.jsonl"))}
    return cell


def state_key(state):
    if not isinstance(state, dict):
        return None
    return (state.get("plugged"), state.get("screen"),
            state.get("doze_deep"), state.get("doze_light"))


def fmt(value, spec="{:.2f}", missing=""):
    return missing if value is None else spec.format(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--provenance", default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.results):
        print(f"no results directory: {args.results}", file=sys.stderr)
        return 1

    cells = defaultdict(dict)
    for name in sorted(os.listdir(args.results)):
        if not name.endswith(".meta.json"):
            continue
        stem = name[: -len(".meta.json")]
        try:
            regime, node, arm = stem.split("__")
        except ValueError:
            continue
        cell = load_cell(args.results, regime, node, arm)
        if cell:
            cells[(regime, node)][arm] = cell

    if args.provenance and os.path.exists(args.provenance):
        print("```")
        print(open(args.provenance).read().rstrip())
        print("```\n")

    if not cells:
        print("No measurements yet. Run `ab-singbox-compare.sh <serial> regimes` first.")
        print("\nEvery cell below would be filled by that run; nothing is estimated here.")
        return 0

    notes = []
    header = ("| regime | measured state | protocol node | arm | throughput MiB/s | CPU s/GiB "
              "| peak RSS MB | threads | ctx-sw /s (proxy for wakeups) | connect p50 ms "
              "| connect p95 ms | TTFB p50 ms | ok/failed |")
    print(header)
    print("|" + "---|" * 13)

    for (regime, node) in sorted(cells):
        arms = cells[(regime, node)]
        fox, sbx = arms.get("foxcore"), arms.get("singbox")

        comparable = True
        reason = ""
        for arm_name, cell in (("FoxCore", fox), ("sing-box", sbx)):
            if cell is None:
                comparable = False
                reason = f"{arm_name} arm was never run"
            elif not cell["meta"].get("valid", False):
                comparable = False
                reason = f"{arm_name}: {cell['meta'].get('invalid_reason') or 'invalid'}"
        if comparable:
            key_fox = state_key(fox["meta"].get("state_before"))
            key_sbx = state_key(sbx["meta"].get("state_before"))
            if key_fox != key_sbx:
                comparable = False
                reason = (f"device state differed between arms: FoxCore {key_fox} "
                          f"vs sing-box {key_sbx}")
            else:
                screen = (fox["meta"].get("state_before") or {}).get("screen")
                if screen in ("unknown", "dreaming"):
                    comparable = False
                    reason = (f"display was '{screen}', not a resolved on/off state - a dreaming "
                              f"or unreadable display is not an idle one")

        for arm_label, cell in (("FoxCore", fox), ("sing-box", sbx)):
            if cell is None:
                print(f"| {regime} | | {node} | {arm_label} | | | | | | | | | not run |")
                continue
            meta, bench, proc = cell["meta"], cell["bench"], cell["proc"]
            before = meta.get("state_before") or {}
            measured = "{}/{}/doze:{}".format(
                before.get("plugged", "?"), before.get("screen", "?"),
                before.get("doze_deep", "?"))
            if not meta.get("valid", False) and bench is None:
                print(f"| {regime} | {measured} | {node} | {arm_label} | | | | | | | | | "
                      f"failed: {meta.get('invalid_reason','')[:70]} |")
                continue
            if not comparable:
                print(f"| {regime} | {measured} | {node} | {arm_label} | | | | | | | | | withheld |")
                continue

            mib = bench.get("mib_per_s") if bench else None
            gib = (bench.get("bytes", 0) / (1024 ** 3)) if bench else 0
            cpu_per_gib = (proc["cpu_s"] / gib) if (proc and gib > 0) else None
            elapsed = bench.get("elapsed_s") if bench else None
            ctx = None
            if proc and elapsed and proc["vol_ctx"] is not None and proc["nonvol_ctx"] is not None:
                ctx = (proc["vol_ctx"] + proc["nonvol_ctx"]) / elapsed
            rss = (proc["rss_peak_kb"] / 1024) if (proc and proc["rss_peak_kb"] > 0) else None
            threads = proc["threads_max"] if proc else None
            connect = bench.get("connect_us", {}) if bench else {}
            ttfb = bench.get("ttfb_us", {}) if bench else {}
            spread = ""
            if bench and bench.get("repeats", 1) > 1 and mib:
                spread = " ({:.1f}-{:.1f}, n={})".format(
                    bench["mib_per_s_min"], bench["mib_per_s_max"], bench["repeats"])
            print(
                f"| {regime} | {measured} | {node} | {arm_label} "
                f"| {fmt(mib)}{spread} | {fmt(cpu_per_gib)} | {fmt(rss, '{:.1f}')} "
                f"| {threads if threads and threads > 0 else ''} | {fmt(ctx, '{:.0f}')} "
                f"| {fmt(connect.get('p50', 0) / 1000 if connect else None, '{:.1f}')} "
                f"| {fmt(connect.get('p95', 0) / 1000 if connect else None, '{:.1f}')} "
                f"| {fmt(ttfb.get('p50', 0) / 1000 if ttfb else None, '{:.1f}')} "
                f"| {bench.get('ok','')}/{bench.get('failed','')} |"
            )
        if not comparable and reason:
            notes.append(f"* `{regime}` / `{node}`: cells withheld - {reason}")

    if notes:
        print("\n**Withheld cells**\n")
        for note in notes:
            print(note)

    print("\n**How each number was obtained**\n")
    print("* throughput: `bytes / elapsed_s` from the shared `foxcore-bench-client`, "
          "which imports no workspace crate and drives both arms identically.")
    print("* CPU s/GiB: `(utime+stime)` deltas from `/proc/<pid>/stat` at 100 Hz over the "
          "load window, divided by bytes actually carried. Per-GiB, not per-cent, so an "
          "arm that moved less data gets no credit for it.")
    print("* peak RSS: max `VmHWM` from `/proc/<pid>/status` across the window.")
    print("* ctx-sw/s: `voluntary_ctxt_switches + nonvoluntary_ctxt_switches` deltas from "
          "`/proc/<pid>/status`, per second. This is a PROXY. Real Android wakeup and "
          "wakelock accounting is per-uid in `batterystats`, and both arms run as the "
          "`shell` uid outside the app framework, so neither holds a wakelock and "
          "`batterystats` cannot separate them.")
    print("* latency: percentiles over the raw per-request series inside the generator, "
          "not over per-interval means.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
