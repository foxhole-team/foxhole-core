import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "android_path_leaks", Path(__file__).resolve().parents[1] / "android-path-leaks.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AndroidPathLeakTest(unittest.TestCase):
    def test_virtual_source_filenames_do_not_alias_container_directory_names(self):
        sources = [
            ".cargo/registry/src/quinn/src/work_limiter.rs",
            ".cargo/registry/src/tokio/src/runtime/metrics/worker.rs",
            ".cargo/registry/src/miniz_oxide/src/inflate/output_buffer.rs",
            "/rust/deps/miniz_oxide/src/inflate/output_buffer.rs",
            "crate/src/private/codec.rs",
        ]
        self.assertEqual([], MODULE.leaked_paths(sources, ["/work", "/output", "/tmp/build"]))

    def test_directory_boundaries_still_refuse_actual_build_paths(self):
        sources = [
            "panic at /work/crates/proto-wireguard/src/tunnel.rs",
            "/output/arm64-v8a/libfoxhole_native.so",
            "/tmp/build/generated/foo.rs",
        ]
        self.assertEqual(sorted(sources), MODULE.leaked_paths(sources, ["/work", "/output", "/tmp/build"]))

    def test_personal_roots_and_bare_directory_paths_remain_forbidden(self):
        sources = [
            "panic at /Users/owner/project/foo.rs",
            "panic at /home/owner/project/foo.rs",
            "/root/private/foo.rs",
            "/private/tmp/owner/foo.rs",
            "/work",
        ]
        self.assertEqual(sorted(sources), MODULE.leaked_paths(sources, ["/work/"]))
