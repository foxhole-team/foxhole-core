import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class AdvisoryScanTest(unittest.TestCase):
    def run_scan(self, mode="clean"):
        temporary = tempfile.TemporaryDirectory(prefix="foxcore advisories ")
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name) / "repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "native/sentinel-yara").mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / "advisories.py"
        if source.exists():
            shutil.copy2(source, repo / "scripts/advisories.py")
        for name in ("Cargo.lock", "native/sentinel-yara/Cargo.lock"):
            (repo / name).write_text("synthetic locked graph\n")
        tools = repo / "tools"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["SCAN_AUDIT"]).open("a") as output:
    output.write(json.dumps(args) + "\n")
if args == ["deny", "--version"]:
    print("cargo-deny 0.20.2")
    raise SystemExit(0)
sentinel = "native/sentinel-yara/Cargo.toml" in args
wide = "--all-features" in args
mode = os.environ["SCAN_MODE"]
if args[-1] == "fetch":
    if mode == "fetch-failure" and not sentinel:
        print("database unavailable", file=sys.stderr)
        raise SystemExit(5)
    raise SystemExit(0)
if args[-2:] != ["check", "advisories"] or "--locked" not in args or "json" not in args:
    raise SystemExit(91)
if mode == "tool-failure" and wide:
    print("metadata failed before diagnostics", file=sys.stderr)
    raise SystemExit(2)
if mode == "changed-lock" and sentinel:
    Path("Cargo.lock").write_text("changed by the scanner\n")
if mode in ("vulnerable", "unexpected-error") and not sentinel:
    print(json.dumps({"type":"diagnostic", "fields": {
        "severity":"error", "code":"vulnerability", "message":"Remote panic%\n::notice::injection",
        "notes":["ID: RUSTSEC-2099-0001"],
        "advisory":{"advisory":{"id":"RUSTSEC-2099-0001", "cvss":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}
    }}), file=sys.stderr)
    raise SystemExit(0 if mode == "unexpected-error" else 1)
print(json.dumps({"type":"log", "fields":{"level":"info", "message":"checks passed"}}))
''')
        cargo.chmod(0o755)
        git = tools / "git"
        git.write_text(f"#!{sys.executable}\nprint('" + "a" * 40 + "')\n")
        git.chmod(0o755)
        audit = repo / "audit.jsonl"
        env = os.environ.copy()
        env.update({"PATH": str(tools) + os.pathsep + env["PATH"],
                    "SCAN_MODE": mode, "SCAN_AUDIT": str(audit)})
        result = subprocess.run([sys.executable, str(repo / "scripts/advisories.py"),
                                 "--output", str(repo / "report")], cwd=repo,
                                env=env, text=True, capture_output=True, timeout=15)
        report_path = repo / "report/report.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else None
        calls = [json.loads(x) for x in audit.read_text().splitlines()] if audit.exists() else []
        return result, report, calls, repo

    def test_first_vulnerability_still_checks_all_three_graphs_and_keeps_raw_logs(self):
        result, report, calls, repo = self.run_scan("vulnerable")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(3, len([c for c in calls if c[-2:] == ["check", "advisories"]]))
        self.assertEqual([1, 1, 0], [g["check_exit"] for g in report["graphs"]])
        self.assertEqual("RUSTSEC-2099-0001", report["graphs"][0]["diagnostics"][0]["id"])
        self.assertIn("RUSTSEC-2099-0001", (repo / "report/default-check.jsonl").read_text())
        self.assertIn("%25%0A::notice::injection", result.stdout)
        self.assertNotIn("\n::notice::injection", result.stdout)

    def test_failed_fetch_never_uses_a_stale_database_and_scanner_graph_still_runs(self):
        result, report, calls, _ = self.run_scan("fetch-failure")
        self.assertEqual(1, result.returncode, result.stderr)
        checks = [c for c in calls if c[-2:] == ["check", "advisories"]]
        self.assertEqual(1, len(checks))
        self.assertIn("native/sentinel-yara/Cargo.toml", checks[0])
        self.assertEqual([5, 5, 0], [g["fetch_exit"] for g in report["graphs"]])
        self.assertIsNone(report["graphs"][0]["check_exit"])

    def test_a_tool_failure_without_advisory_diagnostics_remains_a_failure(self):
        result, report, _, repo = self.run_scan("tool-failure")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(2, report["graphs"][1]["check_exit"])
        self.assertIn("metadata failed", (repo / "report/all-features-check.jsonl").read_text())

    def test_success_records_actual_source_and_unchanged_lockfile_hashes(self):
        result, report, _, _ = self.run_scan()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertFalse(report["failed"])
        self.assertEqual("a" * 40, report["source_commit"])
        self.assertEqual(report["lockfiles_before"], report["lockfiles_after"])

    def test_isolated_scanner_uses_its_own_advisory_policy(self):
        result, _, calls, _ = self.run_scan()
        self.assertEqual(0, result.returncode, result.stderr)
        scanner = [c for c in calls if "native/sentinel-yara/Cargo.toml" in c]
        self.assertEqual(2, len(scanner))
        for command in scanner:
            self.assertIn("--config", command)
            self.assertEqual("native/sentinel-yara/deny.toml", command[command.index("--config") + 1])

    def test_a_scanner_that_rewrites_a_lockfile_is_not_a_pass(self):
        result, report, _, _ = self.run_scan("changed-lock")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertNotEqual(report["lockfiles_before"], report["lockfiles_after"])

    def test_error_diagnostics_cannot_be_hidden_by_a_zero_tool_exit(self):
        result, report, _, _ = self.run_scan("unexpected-error")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertTrue(report["failed"])


if __name__ == "__main__":
    unittest.main()
