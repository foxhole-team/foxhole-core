"""Exercise the retained lab release recipe against synthetic read-only APIs."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ReleaseGateTest(unittest.TestCase):
    def candidate_script(self):
        source = Path(__file__).resolve().parents[2] / ".github/lab-workflows/release.yml"
        lines = source.read_text().splitlines()
        start = next(i for i, line in enumerate(lines) if "id: candidate" in line)
        start = next(i for i in range(start, len(lines)) if lines[i] == "        run: |") + 1
        body = []
        for line in lines[start:]:
            if line and not line.startswith("          "):
                break
            body.append(line[10:] if line else "")
        return "\n".join(body)

    def run_candidate(self, **overrides):
        temporary = tempfile.TemporaryDirectory(prefix="foxcore release gate ")
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name)
        tools = repo / "tools"
        tools.mkdir()
        (repo / "fixtures/abi/v1").mkdir(parents=True)
        (repo / "Cargo.toml").write_text('[workspace.package]\nversion = "1.0.0"\n')
        (repo / "fixtures/abi/v1/capabilities.json").write_text('{"core_version":"1.0.0"}')
        run = {"id": 123, "head_sha": "a" * 40, "head_branch": "main", "status": "completed",
               "conclusion": "success", "event": "push",
               "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        run.update(overrides)
        fixture = repo / "runs.json"
        fixture.write_text(json.dumps({"workflow_runs": [run]}))
        gh = tools / "gh"
        gh.write_text(f"#!{sys.executable}\n" + r'''import os, sys
from pathlib import Path
a=sys.argv[1:]
if a[:1]==["api"] and a[-2:]==["--jq", ".visibility"]: print("public")
elif a[:3]==["api", "--method", "GET"] and "branch=main" in a:
    print(Path(os.environ["RELEASE_RUNS"]).read_text())
elif a[:2]==["release", "view"]: raise SystemExit(1)
else: raise SystemExit(92)
''')
        git = tools / "git"
        git.write_text(f"#!{sys.executable}\n" + r'''import sys
a=sys.argv[1:]
if a[:1]==["rev-parse"]: print("b"*40)
elif a[:1]==["ls-remote"]: raise SystemExit(2)
else: raise SystemExit(93)
''')
        python = tools / "python3"
        python.write_text(f"#!{sys.executable}\n" + r'''import os, sys
from pathlib import Path
assert sys.argv[1:] == ["scripts/verify-release-signature.py", "a"*40]
Path(os.environ["SIGNATURE_PROBE"]).write_text("checked")
''')
        for tool in (gh, git, python):
            tool.chmod(0o755)
        env = os.environ.copy()
        output = repo / "outputs.txt"
        signature = repo / "signature-probe.txt"
        env.update({"PATH": str(tools) + os.pathsep + env["PATH"], "RELEASE_RUNS": str(fixture),
                    "SIGNATURE_PROBE": str(signature), "GITHUB_SHA": "a" * 40,
                    "GITHUB_REPOSITORY": "synthetic/core", "GITHUB_OUTPUT": str(output)})
        result = subprocess.run(["bash", "-c", self.candidate_script()], cwd=repo, env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertTrue(signature.exists(), result.stderr)
        return result, output.read_text() if output.exists() else ""

    def test_exact_successful_fresh_main_commit_is_selected(self):
        result, outputs = self.run_candidate()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("run_id=123", outputs)
        self.assertIn("source_sha=" + "a" * 40, outputs)

    def test_a_successful_dev_run_cannot_qualify_main(self):
        result, _ = self.run_candidate(head_branch="dev")
        self.assertNotEqual(0, result.returncode)

    def test_another_commit_cannot_qualify_even_if_the_tree_is_equal(self):
        result, _ = self.run_candidate(head_sha="c" * 40)
        self.assertNotEqual(0, result.returncode)

    def test_failed_and_running_checks_do_not_qualify(self):
        for overrides in ({"conclusion": "failure"}, {"status": "in_progress"}, {"event": "pull_request"}):
            with self.subTest(overrides=overrides):
                result, _ = self.run_candidate(**overrides)
                self.assertNotEqual(0, result.returncode)

    def test_stale_or_future_results_do_not_qualify(self):
        for hours in (-25, 2):
            time = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            with self.subTest(hours=hours):
                result, _ = self.run_candidate(updated_at=time)
                self.assertNotEqual(0, result.returncode)


if __name__ == "__main__":
    unittest.main()
