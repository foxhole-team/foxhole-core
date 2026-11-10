import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sqlite_fork", ROOT / "scripts/sqlite-fork-origin.py")
FORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FORK)


class SQLiteForkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="foxcore-sqlite-backport-")
        cls.root = Path(cls.temporary.name).resolve()
        for name in ("Cargo.toml", "Cargo.lock", FORK.METADATA, "config/source-forks/libsqlite3-sys-0.37.0.NOTICE.md", "patches/libsqlite3-sys-0.37.0-CVE-2026-119375.patch", "deny.toml"):
            path = cls.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, path)
        shutil.copytree(ROOT / "vendor/libsqlite3-sys", cls.root / "vendor/libsqlite3-sys")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_exact_backport_derives_only_the_reviewed_exception(self):
        output = self.root / "verified.toml"
        proof = FORK.policy(self.root, self.root / "deny.toml", output)
        self.assertEqual("RUSTSEC-2026-0459", proof["advisory"])
        self.assertEqual(1, output.read_text().count('id = "RUSTSEC-2026-0459"'))
        self.assertIn('id = "RUSTSEC-2023-0071"', output.read_text())

    def test_changed_source_is_refused_without_creating_policy(self):
        path = self.root / "vendor/libsqlite3-sys/sqlite3/sqlite3.c"
        raw = path.read_bytes()
        try:
            path.write_bytes(raw + b"\n/* unreviewed */\n")
            output = self.root / "refused.toml"
            with self.assertRaises(ValueError):
                FORK.policy(self.root, self.root / "deny.toml", output)
            self.assertFalse(output.exists())
        finally:
            path.write_bytes(raw)

    def test_forged_original_inventory_is_refused(self):
        path = self.root / FORK.METADATA
        raw = path.read_bytes()
        try:
            metadata = json.loads(raw)
            metadata["upstreamFiles"][0]["sha256"] = "0" * 64
            path.write_text(json.dumps(metadata))
            with self.assertRaises(ValueError):
                FORK.validate(self.root)
        finally:
            path.write_bytes(raw)

    def test_registry_lock_identity_cannot_inherit_the_source_exception(self):
        path = self.root / "Cargo.lock"
        raw = path.read_bytes()
        try:
            text = raw.decode().replace('name = "libsqlite3-sys"\nversion = "0.37.0"', 'name = "libsqlite3-sys"\nversion = "0.37.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"')
            self.assertNotEqual(text.encode(), raw)
            path.write_text(text)
            with self.assertRaises(ValueError):
                FORK.validate(self.root)
        finally:
            path.write_bytes(raw)

    def test_actual_sqlite_and_sqlcipher_wal_functions_initialize_page_tails(self):
        prefix = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned int u32;
typedef int64_t i64;
typedef struct { struct { int szPage; } hdr; void *pWalFd; } Wal;
#define testcase(x) ((void)(x))
#define WAL_FRAME_HDRSIZE 24
static int bytes_read;
static int read_error;
static i64 walFrameOffset(u32 frame, int size) { return 32 + (i64)(frame-1)*(size+24); }
static int sqlite3OsRead(void *file, void *out, int size, i64 offset) {
  (void)file; (void)offset; bytes_read=size;
  if(read_error) return read_error;
  memset(out, 0x11, size); return 0;
}
'''
        suffix = r'''
int main(void) {
  int sizes[] = {512, 1024, 4096, 65536};
  for(unsigned int i=0; i<sizeof(sizes)/sizeof(sizes[0]); i++) {
    int page=sizes[i]; Wal wal={{page==65536 ? 1 : page}, 0};
    for(int scale=1; scale<=3; scale++) {
      int size=scale==1 ? page/2 : scale==2 ? page : page*2;
      u8 *out=malloc(size+16); memset(out, 0xa5, size+16);
      if(sqlite3WalReadFrame(&wal,1,size,out)!=0 || bytes_read!=(size<page ? size : page)) return 1;
      for(int n=0;n<size;n++) if(out[n]!=(n<page ? 0x11 : 0)) return 2;
      for(int n=size;n<size+16;n++) if(out[n]!=0xa5) return 3;
      read_error=17;
      if(sqlite3WalReadFrame(&wal,1,size,out)!=17) return 4;
      read_error=0; free(out);
    }
  }
  return 0;
}
'''
        for relative in sorted(FORK.CHANGED):
            text = (ROOT / "vendor/libsqlite3-sys" / relative).read_text()
            start = text.rindex("int sqlite3WalReadFrame(")
            end = text.index("\n}\n", start) + 3
            fixed = text[start:end]
            original = fixed.replace(FORK.AFTER, FORK.BEFORE).replace(FORK.NEW_RETURN, FORK.OLD_RETURN)
            self.assertNotEqual(original, fixed)
            for label, body, success in (("original", original, False), ("fixed", fixed, True)):
                with self.subTest(source=relative, variant=label):
                    source = self.root / "wal-test.c"
                    executable = self.root / "wal-test"
                    source.write_text(prefix + body + suffix)
                    compiled = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0", str(source), "-o", str(executable)], capture_output=True, timeout=30)
                    self.assertEqual(0, compiled.returncode, compiled.stderr.decode())
                    result = subprocess.run([str(executable)], capture_output=True, timeout=5)
                    self.assertEqual(success, result.returncode == 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
