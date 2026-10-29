import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ReproIsolationTest(unittest.TestCase):
    def run_fixture(self, inherit_target):
        temporary = tempfile.TemporaryDirectory(prefix='foxcore-repro-test-')
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        repo = folder / 'repo'
        (repo / 'scripts').mkdir(parents=True)
        source = Path(os.environ.get('FOXCORE_REPRO_SCRIPT_UNDER_TEST',
                                     Path(__file__).parents[1] / 'reproducible-build.sh'))
        shutil.copy2(source, repo / 'scripts/reproducible-build.sh')
        shutil.copy2(Path(__file__).parents[1] / 'android-path-leaks.py', repo / 'scripts/android-path-leaks.py')
        (repo / 'nested').mkdir()
        (repo / 'AGENTS.md').write_text('local instructions\n')
        (repo / 'nested/AGENTS.md').write_text('nested local instructions\n')
        (repo / 'source.rs').write_text('source fixture\n')
        audit = folder / 'targets.txt'
        stub = repo / 'scripts/android-build.sh'
        stub.write_text('''#!/usr/bin/env bash
set -euo pipefail
target="${CARGO_TARGET_DIR:-$PWD/target}"
printf '%s\\n' "$target" >> "$FOXCORE_REPRO_TEST_AUDIT"
mkdir -p "$target"
value="cold artifact"
if [ -e "$target/used" ]; then value="reused artifact"; fi
touch "$target/used"
for abi in $FOXCORE_ANDROID_ABIS; do
    mkdir -p "$FOXCORE_JNI_OUTPUT/$abi"
    printf '%s\\n' "$value" > "$FOXCORE_JNI_OUTPUT/$abi/libfoxhole_native.so"
done
printf 'Finished stub build\\n'
''')
        stub.chmod(0o755)
        tool_dir = folder / 'bin'
        tool_dir.mkdir()
        rsync = tool_dir / 'rsync'
        rsync.write_text('''#!/usr/bin/env python3
import shutil, sys
arguments = sys.argv[1:]
excluded = [arguments[i + 1] for i, arg in enumerate(arguments) if arg == '--exclude']
shutil.copytree(arguments[-2], arguments[-1], dirs_exist_ok=True, symlinks=True,
                ignore=shutil.ignore_patterns(*excluded))
''')
        rsync.chmod(0o755)
        cargo_home = folder / 'cargo-home'
        (cargo_home / 'registry').mkdir(parents=True)
        ambient = folder / 'ambient-target'
        ambient.mkdir()
        (ambient / 'owner-cache').write_text('preserve\n')
        work = folder / 'work'
        env = dict(os.environ, FOXCORE_ANDROID_ABIS='x86 x86_64',
                   FOXCORE_REPRO_WORK=str(work), CARGO_HOME=str(cargo_home),
                   FOXCORE_REPRO_TEST_AUDIT=str(audit),
                   PATH=str(tool_dir) + os.pathsep + os.environ['PATH'])
        env.pop('CARGO_TARGET_DIR', None)
        if inherit_target:
            env['CARGO_TARGET_DIR'] = str(ambient)
        result = subprocess.run(['bash', str(repo / 'scripts/reproducible-build.sh')],
                                env=env, text=True, capture_output=True, timeout=20)
        return result, audit, work, ambient

    def test_inherited_cache_cannot_turn_two_cold_builds_into_a_reuse(self):
        result, audit, _, ambient = self.run_fixture(True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        targets = audit.read_text().splitlines()
        self.assertEqual(2, len(targets))
        self.assertNotEqual(targets[0], targets[1])
        self.assertNotIn(str(ambient), targets)
        self.assertEqual('preserve\n', (ambient / 'owner-cache').read_text())
        self.assertFalse((ambient / 'used').exists())

    def test_moved_source_omits_local_instructions_at_every_level(self):
        result, _, work, _ = self.run_fixture(False)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertFalse((work / 'moved-src/AGENTS.md').exists())
        self.assertFalse((work / 'moved-src/nested/AGENTS.md').exists())
        self.assertTrue((work / 'moved-src/source.rs').exists())


if __name__ == '__main__':
    unittest.main()
