import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class AndroidDockerEnvironmentTest(unittest.TestCase):
    def run_wrapper(self, command, overrides=None, docker_exit=0):
        temporary = tempfile.TemporaryDirectory(prefix="foxcore wrapper test ")
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name).resolve()
        repo = folder / "repo"
        (repo / "scripts").mkdir(parents=True)
        source = Path(os.environ.get(
            "FOXCORE_DOCKER_ANDROID_SCRIPT_UNDER_TEST",
            Path(__file__).resolve().parents[1] / "docker-android.sh",
        ))
        script = repo / "scripts/docker-android.sh"
        shutil.copy2(source, script)
        tools = folder / "tools"
        tools.mkdir()
        audit = folder / "docker-argv.jsonl"
        docker = tools / "docker"
        docker.write_text(f"#!{sys.executable}\n" + """import json, os, sys
args = sys.argv[1:]
with open(os.environ["FOXCORE_WRAPPER_TEST_AUDIT"], "a") as output:
    output.write(json.dumps(args) + "\\n")
if args[:2] == ["image", "inspect"]:
    raise SystemExit(0)
if args[:1] == ["run"]:
    raise SystemExit(int(os.environ["FOXCORE_WRAPPER_TEST_EXIT"]))
raise SystemExit(93)
""")
        docker.chmod(0o755)
        git = tools / "git"
        git.write_text(f"#!{sys.executable}\n" + """import os, sys
args = sys.argv[1:]
if len(args) == 5 and args[0] == "-C" and args[2:] == ["rev-parse", "--path-format=absolute", "--git-common-dir"]:
    print(os.environ["FOXCORE_WRAPPER_TEST_GIT_DIR"])
    raise SystemExit(0)
raise SystemExit(94)
""")
        git.chmod(0o755)
        env = os.environ.copy()
        for name in (
            "RUSTUP_TOOLCHAIN", "CARGO_NET_OFFLINE", "FOXCORE_ANDROID_DOCKER_IMAGE",
            "FOXCORE_ANDROID_DOCKER_CACHE", "FOXCORE_JNI_OUTPUT", "FOXCORE_DOCKER_CPUS",
            "FOXCORE_DOCKER_MEMORY", "FOXCORE_DOCKER_JOBS", "FOXCORE_ANDROID_ABIS",
            "FOXCORE_ANDROID_FEATURES",
        ):
            env.pop(name, None)
        env.update({
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "FOXCORE_WRAPPER_TEST_AUDIT": str(audit),
            "FOXCORE_WRAPPER_TEST_EXIT": str(docker_exit),
            "FOXCORE_WRAPPER_TEST_GIT_DIR": str(repo / ".git"),
        })
        env.update(overrides or {})
        result = subprocess.run(
            ["bash", str(script), *command], env=env,
            text=True, capture_output=True, timeout=10,
        )
        calls = [json.loads(line) for line in audit.read_text().splitlines()]
        runs = [call for call in calls if call[:1] == ["run"]]
        self.assertEqual(1, len(runs), calls)
        self.assertEqual(2, len(calls), calls)
        self.assertEqual(["image", "inspect"], calls[0][:2])
        return result, runs[0], repo

    def container_environment(self, args):
        values = [args[index + 1] for index, value in enumerate(args) if value == "--env"]
        self.assertEqual(len(values), len({value.split("=", 1)[0] for value in values}))
        return dict(value.split("=", 1) for value in values)

    def test_default_build_forwards_pinned_toolchain_and_online_default(self):
        result, args, repo = self.run_wrapper(["build"])
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        values = self.container_environment(args)
        self.assertEqual("1.97.1", values.get("RUSTUP_TOOLCHAIN"))
        self.assertEqual("false", values.get("CARGO_NET_OFFLINE"))
        self.assertEqual("2", values["CARGO_BUILD_JOBS"])
        self.assertEqual("arm64-v8a armeabi-v7a x86 x86_64", values["FOXCORE_ANDROID_ABIS"])
        self.assertEqual("shipped", values["FOXCORE_ANDROID_FEATURES"])
        self.assertEqual("/output", values["FOXCORE_JNI_OUTPUT"])
        self.assertIn("--cpus=2", args)
        self.assertIn("--memory=6g", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertEqual("linux/amd64", args[args.index("--platform") + 1])
        self.assertIn(f"type=bind,source={repo},target=/work,readonly", args)
        self.assertIn(f"type=bind,source={repo}/.git,target={repo}/.git,readonly", args)
        self.assertIn("type=volume,source=foxhole-android-rust-1-97-1-ndk29-cargo,target=/cargo-cache", args)
        self.assertIn("type=volume,source=foxhole-android-rust-1-97-1-ndk29-target,target=/build", args)
        self.assertEqual(
            ["foxhole/android-rust-lab:1.97.1-ndk29", "bash", "-c", "cargo fetch --locked && scripts/android-build.sh"],
            args[-4:],
        )

    def test_explicit_command_preserves_host_overrides_and_offline_request(self):
        command = ["bash", "-c", "cargo fetch --locked --offline && scripts/android-build.sh"]
        result, args, _ = self.run_wrapper(command, {
            "RUSTUP_TOOLCHAIN": "1.98.0", "CARGO_NET_OFFLINE": "true",
            "FOXCORE_DOCKER_CPUS": "1", "FOXCORE_DOCKER_MEMORY": "2g",
            "FOXCORE_DOCKER_JOBS": "3", "FOXCORE_ANDROID_ABIS": "x86",
            "FOXCORE_ANDROID_FEATURES": "", "FOXCORE_ANDROID_DOCKER_IMAGE": "owned-fixture:1",
        })
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        values = self.container_environment(args)
        self.assertEqual("1.98.0", values.get("RUSTUP_TOOLCHAIN"))
        self.assertEqual("true", values.get("CARGO_NET_OFFLINE"))
        self.assertEqual("3", values["CARGO_BUILD_JOBS"])
        self.assertEqual("x86", values["FOXCORE_ANDROID_ABIS"])
        self.assertEqual("", values["FOXCORE_ANDROID_FEATURES"])
        self.assertIn("--cpus=1", args)
        self.assertIn("--memory=2g", args)
        self.assertEqual(["owned-fixture:1", *command], args[-4:])

    def test_container_failure_exit_is_preserved(self):
        result, _, _ = self.run_wrapper(["build"], docker_exit=23)
        self.assertEqual(23, result.returncode)


if __name__ == "__main__":
    unittest.main()
