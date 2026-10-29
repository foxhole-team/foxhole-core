#!/usr/bin/env python3
"""Check every shipped Rust graph without hiding later results after a failure."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import signal
import subprocess


SCANNER_VERSION = "cargo-deny 0.20.2"
GRAPHS = (
    ("default", ()),
    ("all-features", ("--all-features", "--config", "deny-all-features.toml")),
    ("sentinel", ("--manifest-path", "native/sentinel-yara/Cargo.toml", "--config", "native/sentinel-yara/deny.toml")),
)
LOCKFILES = ("Cargo.lock", "native/sentinel-yara/Cargo.lock")


def run(command, root, log, timeout):
    with log.open("wb") as output:
        try:
            process = subprocess.Popen(command, cwd=root, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                return process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                output.write(b"\nScanner command timed out.\n")
                return 124
        except OSError as error:
            output.write(str(error).encode("utf-8", errors="replace") + b"\n")
            return 127


def lock_hashes(root):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            if (root / name).is_file() else None for name in LOCKFILES}


def diagnostics(log):
    result = []
    for line in log.read_text(errors="replace").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue  # CLI/metadata failures still fail by their actual exit status; retain raw bytes.
        if not isinstance(value, dict) or value.get("type") != "diagnostic":
            continue
        fields = value.get("fields")
        if not isinstance(fields, dict):
            result.append({"severity": "error", "code": "invalid-diagnostic", "message": "Malformed scanner diagnostic"})
            continue
        entry = {key: fields.get(key, "") for key in ("severity", "code", "message")}
        for note in fields.get("notes", []):
            if isinstance(note, str) and re.fullmatch(r"ID: (RUSTSEC|CVE|GHSA)-[A-Za-z0-9-]+", note):
                entry["id"] = note.removeprefix("ID: ")
                break
        advisory = fields.get("advisory")
        metadata = advisory.get("advisory") if isinstance(advisory, dict) else None
        if isinstance(metadata, dict) and isinstance(metadata.get("cvss"), str):
            entry["cvss"] = metadata["cvss"]
        result.append(entry)
    return result


def escape_annotation(value, property_value=False):
    value = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return value.replace(":", "%3A").replace(",", "%2C") if property_value else value


def markdown(value):
    return html.escape(" ".join(str(value).split())).replace("|", "\\|").replace("`", "&#96;")


def summary(report):
    lines = ["## Dependency advisories: " + ("FAILED" if report["failed"] else "PASS"), "",
             "Source commit: `" + (report["source_commit"] or "unavailable") + "`", "",
             "| Graph | Fresh database fetch | Advisory check |", "| --- | --- | --- |"]
    for graph in report["graphs"]:
        lines.append(f"| {graph['name']} | {graph['fetch_exit']} | {graph['check_exit'] if graph['check_exit'] is not None else 'not run'} |")
    for graph in report["graphs"]:
        for entry in graph["diagnostics"]:
            lines.append(f"\n- **{markdown(entry['severity'])}** ({graph['name']}, {markdown(entry['code'])}): "
                         f"{markdown(entry.get('id', ''))} {markdown(entry['message'])}")
            if entry.get("cvss"):
                lines.append("  Published CVSS vector: `" + markdown(entry["cvss"]) + "`")
    lines += ["", "Every disallowed advisory fails this job. Accepted advisories remain visible under the committed policy.",
              "Missing tools, failed database fetches, timeouts and changed lockfiles also fail; they are not a clean CVE result.",
              "Raw scanner logs, actual exit statuses and lockfile hashes are included in the artifact.",
              "This checks the resolved Rust graphs against RustSec; it does not prove exploitability or cover OS and unrelated native dependencies."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300, help="Seconds per fetch/check command")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("timeout must be between 1 and 600 seconds")
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    before = lock_hashes(root)
    source_exit = run(["git", "rev-parse", "HEAD"], root, output / "source-commit.log", 10)
    source = (output / "source-commit.log").read_text(errors="replace").strip()
    source = source if source_exit == 0 and re.fullmatch(r"[0-9a-f]{40}", source) else None
    version_exit = run(["cargo", "deny", "--version"], root, output / "scanner-version.log", 10)
    version = (output / "scanner-version.log").read_text(errors="replace").strip()
    failed = source is None or version_exit != 0 or version != SCANNER_VERSION or any(v is None for v in before.values())
    graphs = []
    if version_exit == 0 and version == SCANNER_VERSION:
        for name, options in GRAPHS:
            print(f"Checking fresh advisories: {name}", flush=True)
            fetch_exit = run(["cargo", "deny", *options, "fetch"], root, output / f"{name}-fetch.log", args.timeout)
            check_exit = None
            entries = []
            if fetch_exit == 0:
                log = output / f"{name}-check.jsonl"
                check_exit = run(["cargo", "deny", "--locked", "--format", "json", *options, "check", "advisories"],
                                 root, log, args.timeout)
                entries = diagnostics(log)
            graph_failed = fetch_exit != 0 or check_exit != 0 or any(e["severity"] in ("error", "bug") for e in entries)
            failed |= graph_failed
            graphs.append({"name": name, "fetch_exit": fetch_exit, "check_exit": check_exit, "diagnostics": entries})
            if graph_failed and not any(e["severity"] in ("error", "bug") for e in entries):
                print(f"::error title=Dependency check unavailable::{name}: fetch exit {fetch_exit}, check exit {check_exit}; inspect raw logs.")
            for entry in entries:
                if entry["severity"] in ("error", "bug", "warning"):
                    kind = "warning" if entry["severity"] == "warning" else "error"
                    title = escape_annotation(f"{name}: {entry.get('id', entry['code'])}", True)
                    print(f"::{kind} title={title}::{escape_annotation(entry['message'])}")
    after = lock_hashes(root)
    if before != after:
        failed = True
        print("::error title=Lockfile changed::Advisory scanning modified a locked dependency graph.")
    if version_exit != 0 or version != SCANNER_VERSION or source is None or any(v is None for v in before.values()):
        print("::error title=Dependency check unavailable::Missing source identity, lockfile or pinned scanner; inspect the artifact.")
    report = {"schema": 1, "checked_at": datetime.now(timezone.utc).isoformat(), "source_commit": source,
              "scanner": version, "failed": bool(failed), "lockfiles_before": before, "lockfiles_after": after, "graphs": graphs}
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    text = summary(report)
    (output / "report.md").write_text(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as destination:
            destination.write(text)
    print("Dependency advisory scan: " + ("FAILED" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
