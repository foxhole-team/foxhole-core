#!/usr/bin/env bash
# The artifact that makes a FoxCore release rollback auditable.
#
# Replacing the native library is not a deployment step that can be undone by
# shipping the previous APK: the previous library also has to still be able to
# read what the new one wrote — the encrypted share vault above all, which
# authenticates every blob against constants baked into the build. Without a
# recorded artifact there is nothing to roll back *to* and no way to know in
# advance whether rolling back is safe. That is a larger risk than any single
# defect in the core.
#
# So each release records one directory containing the shipped .so files, the
# lockfile that produced them, and a manifest of every version number the two
# sides of a rollback have to agree on. `compare` then answers one question with
# evidence: can a device that ran NEW go back to OLD without losing user data?
#
# This script records the machine-checkable inputs needed to decide whether an
# older core can safely read state written by the new one.
#
# Usage:
#   scripts/rollback-artifact.sh record  <out-dir> [--libs <jniLibs-dir>]
#   scripts/rollback-artifact.sh verify  <artifact-dir>
#   scripts/rollback-artifact.sh compare <old-artifact> <new-artifact>
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        sha256sum "$1" | awk '{print $1}'
    fi
}

usage() {
    sed -n '2,25p' "$0" >&2
    exit 2
}

# ------------------------------------------------------------------- record
record() {
    local out="${1:-}"
    shift || true
    [ -n "$out" ] || usage
    local libs=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --libs)
                shift
                libs="${1:-}"
                ;;
            *)
                echo "unknown argument: $1" >&2
                exit 2
                ;;
        esac
        shift
    done

    mkdir -p "$out/jniLibs"
    cd "$ROOT"

    if [ -z "$libs" ]; then
        echo "== building the Android libraries =="
        libs="$out/jniLibs"
        FOXCORE_JNI_OUTPUT="$libs" "$ROOT/scripts/android-build.sh" || {
            echo "the Android build failed; nothing was recorded" >&2
            exit 1
        }
    else
        echo "== taking the libraries from $libs =="
        for lib in "$libs"/*/libfoxhole_native.so; do
            [ -f "$lib" ] || continue
            abi="$(basename "$(dirname "$lib")")"
            mkdir -p "$out/jniLibs/$abi"
            cp "$lib" "$out/jniLibs/$abi/"
        done
    fi

    local found=0
    : >"$out/.libs.tsv"
    for lib in "$out/jniLibs"/*/libfoxhole_native.so; do
        [ -f "$lib" ] || continue
        found=$((found + 1))
        printf '%s\t%s\t%s\n' \
            "$(basename "$(dirname "$lib")")" \
            "$(sha256 "$lib")" \
            "$(wc -c <"$lib" | tr -d ' ')" >>"$out/.libs.tsv"
    done
    if [ "$found" = "0" ]; then
        echo "no libfoxhole_native.so was recorded; refusing to write a manifest" >&2
        exit 1
    fi

    cp "$ROOT/Cargo.lock" "$out/Cargo.lock"

    # The ABI surface and the capabilities document, from the same tree.
    echo "== recording the ABI surface =="
    local work
    work="$(mktemp -d)"
    "$ROOT/scripts/abi-gate.sh" >"$work/abi-gate.log" 2>&1
    local abi_status=$?
    cp "$work/abi-gate.log" "$out/abi-gate.log"
    if [ "$abi_status" != "0" ]; then
        echo "   abi-gate did not pass; its output is in $out/abi-gate.log" >&2
        echo "   Recording anyway: an artifact of a build that fails the ABI gate" >&2
        echo "   is still the thing you would have to roll back to." >&2
    fi

    FOXCORE_OUT="$out" FOXCORE_ROOT="$ROOT" python3 - <<'PYTHON'
import hashlib
import json
import os
import pathlib
import subprocess
import sys

out = pathlib.Path(os.environ["FOXCORE_OUT"])
root = pathlib.Path(os.environ["FOXCORE_ROOT"])
fixtures = root / "fixtures/abi/v1"


def run(*command):
    try:
        return subprocess.run(
            command, cwd=root, capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        return ""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lines(path):
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


libs = []
for row in (out / ".libs.tsv").read_text(encoding="utf-8").splitlines():
    abi, sha, size = row.split("\t")
    libs.append({"abi": abi, "sha256": sha, "bytes": int(size)})
libs.sort(key=lambda entry: entry["abi"])
(out / ".libs.tsv").unlink()

ondisk = {}
for line in lines(fixtures / "ondisk.txt"):
    if " = " in line:
        key, value = line.split(" = ", 1)
        ondisk[key] = value

capabilities = {}
capabilities_path = fixtures / "capabilities.json"
if capabilities_path.exists():
    capabilities = json.loads(capabilities_path.read_text(encoding="utf-8"))
    (out / "capabilities.json").write_text(
        json.dumps(capabilities, indent=2) + "\n", encoding="utf-8"
    )

manifest = {
    # 2 dropped `journal_event_tags` and the `journal.*` on-disk constants: the
    # security journal is the app's, in Kotlin, and the Rust port was removed.
    # `compare` still reads a version-1 manifest — the vanished keys surface as
    # "only the older artifact records it" warnings rather than a crash.
    "manifest_version": 2,
    "core_version": capabilities.get("core_version"),
    "git": {
        "commit": run("git", "rev-parse", "HEAD"),
        "dirty": bool(run("git", "status", "--porcelain")),
    },
    "build_inputs": {
        "rustc": run("rustc", "--version"),
        "cargo": run("cargo", "--version"),
        "cargo_ndk": run("cargo", "ndk", "--version"),
        "ndk_pin": next(
            (
                line.split('"')[1]
                for line in (root / "scripts/android-build.sh")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.startswith("NDK_VERSION=")
            ),
            None,
        ),
        "cargo_lock_sha256": digest(out / "Cargo.lock"),
    },
    "abi": {
        "core_abi_version": ondisk.get("api.CORE_ABI_VERSION"),
        "config_schema_version": ondisk.get("api.SCHEMA_VERSION"),
        "capabilities_schema_version": ondisk.get("api.CAPABILITIES_SCHEMA_VERSION"),
        "exports": lines(fixtures / "exports.txt"),
    },
    "ondisk": ondisk,
    "libs": libs,
}

if not manifest["abi"]["exports"]:
    print(
        "!! fixtures/abi/v1/exports.txt is empty or missing: run scripts/abi-gate.sh --record",
        file=sys.stderr,
    )
    sys.exit(1)

(out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(
    f"recorded {len(libs)} library/libraries, {len(manifest['abi']['exports'])} exports, "
    f"{len(ondisk)} on-disk constants"
)
PYTHON
    local status=$?
    rm -rf "$work"
    [ "$status" = "0" ] || exit "$status"
    echo "artifact: $out"
    echo "Keep this artifact with the signed APK of the same release."
}

# ------------------------------------------------------------------- verify
verify() {
    local dir="${1:-}"
    [ -n "$dir" ] || usage
    [ -f "$dir/MANIFEST.json" ] || {
        echo "$dir has no MANIFEST.json" >&2
        exit 1
    }
    : >"$dir/.rehash.tsv"
    for lib in "$dir/jniLibs"/*/libfoxhole_native.so; do
        [ -f "$lib" ] || continue
        printf '%s\t%s\n' "$(basename "$(dirname "$lib")")" "$(sha256 "$lib")" >>"$dir/.rehash.tsv"
    done
    printf 'Cargo.lock\t%s\n' "$(sha256 "$dir/Cargo.lock")" >>"$dir/.rehash.tsv"
    FOXCORE_DIR="$dir" python3 - <<'PYTHON'
import json
import os
import pathlib
import sys

directory = pathlib.Path(os.environ["FOXCORE_DIR"])
manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
actual = {}
for row in (directory / ".rehash.tsv").read_text(encoding="utf-8").splitlines():
    name, sha = row.split("\t")
    actual[name] = sha
(directory / ".rehash.tsv").unlink()

problems = []
for entry in manifest["libs"]:
    got = actual.get(entry["abi"])
    if got is None:
        problems.append(f"{entry['abi']}: the library is missing from the artifact")
    elif got != entry["sha256"]:
        problems.append(f"{entry['abi']}: sha256 {got} != recorded {entry['sha256']}")
recorded_lock = manifest["build_inputs"]["cargo_lock_sha256"]
if actual.get("Cargo.lock") != recorded_lock:
    problems.append(
        f"Cargo.lock: sha256 {actual.get('Cargo.lock')} != recorded {recorded_lock}"
    )

for problem in problems:
    print(f"!! {problem}", file=sys.stderr)
if problems:
    print("artifact: TAMPERED OR INCOMPLETE", file=sys.stderr)
    sys.exit(1)
print(f"artifact: intact ({len(manifest['libs'])} library/libraries, lockfile matches)")
PYTHON
}

# ------------------------------------------------------------------ compare
compare() {
    local old="${1:-}" new="${2:-}"
    [ -n "$old" ] && [ -n "$new" ] || usage
    FOXCORE_OLD="$old" FOXCORE_NEW="$new" python3 - <<'PYTHON'
"""Can a device running NEW go back to OLD without losing user data?

Every rule below is a failure mode located in the code, not a precaution. The
file:line references are what to re-read when one of them fires.
"""
import json
import os
import pathlib
import sys

old = json.loads((pathlib.Path(os.environ["FOXCORE_OLD"]) / "MANIFEST.json").read_text())
new = json.loads((pathlib.Path(os.environ["FOXCORE_NEW"]) / "MANIFEST.json").read_text())

blocking: list[tuple[str, str]] = []
warnings: list[str] = []


def block(what: str, why: str) -> None:
    blocking.append((what, why))


# 1. The call ABI. The app is not being downgraded with the library, so it keeps
#    calling whatever it called before.
if old["abi"]["core_abi_version"] != new["abi"]["core_abi_version"]:
    block(
        f"ABI version {new['abi']['core_abi_version']} -> {old['abi']['core_abi_version']}",
        "the installed app compares this number before it starts and will refuse",
    )
if old["abi"]["config_schema_version"] != new["abi"]["config_schema_version"]:
    block(
        "config schema version differs",
        "the app's saved engine config is rejected by EngineConfig::parse "
        "(foxcore-api/src/config.rs:439)",
    )

gained_exports = sorted(set(new["abi"]["exports"]) - set(old["abi"]["exports"]))
if gained_exports:
    block(
        f"{len(gained_exports)} entry point(s) exist only in the newer library: "
        + ", ".join(gained_exports[:6])
        + ("..." if len(gained_exports) > 6 else ""),
        "if the installed app calls any of them it gets UnsatisfiedLinkError on "
        "the device; safe only if the app version being kept predates their use",
    )
lost_exports = sorted(set(old["abi"]["exports"]) - set(new["abi"]["exports"]))
if lost_exports:
    warnings.append(
        f"{len(lost_exports)} entry point(s) exist only in the older library: "
        + ", ".join(lost_exports[:6])
    )

# 2. The on-disk formats. This is the part that loses data rather than
#    functionality. The security journal used to be checked here too; it is the
#    app's now, in Kotlin, and its rollback contract belongs with the app.
ondisk_keys = sorted(set(old["ondisk"]) | set(new["ondisk"]))
WHY = {
    "share.VERSION": "vault blobs fail authentication (foxcore-share/src/lib.rs:1226)",
    "share.MAGIC": "vault blobs fail authentication",
    "share.CHUNK_BYTES": "the chunk size is recorded in the blob header and compared "
    "exactly (foxcore-share/src/lib.rs:1226)",
    "share.MANIFEST_VERSION": "one unreadable manifest fails the whole vault open "
    "(foxcore-share/src/lib.rs:790)",
    "share.MANIFEST_MAGIC": "same as the manifest version",
}
for key in ondisk_keys:
    before, after = old["ondisk"].get(key), new["ondisk"].get(key)
    if before == after:
        continue
    if before is None:
        warnings.append(f"{key}: only the newer artifact records it ({after})")
        continue
    if after is None:
        # A version-1 manifest carries `journal.*` keys this build no longer
        # records. That is the expected shape of this warning, not a defect.
        warnings.append(f"{key}: only the older artifact records it ({before})")
        continue
    block(
        f"{key}: {after} -> {before}",
        WHY.get(key, "an on-disk format constant differs and requires a tested migration"),
    )

# 3. Reporting.
print(f"old: {os.environ['FOXCORE_OLD']}  ({old['git']['commit'][:12] or 'no commit'})")
print(f"new: {os.environ['FOXCORE_NEW']}  ({new['git']['commit'][:12] or 'no commit'})")
print()
for warning in warnings:
    print(f" ~ {warning}")
for what, why in blocking:
    print(f" ! {what}\n     {why}")
print()
if blocking:
    print(f"rollback new -> old: BLOCKED ({len(blocking)} reason(s))")
    print("Do not ship this rollback without a tested migration for every blocker.")
    sys.exit(1)
print("rollback new -> old: SAFE for user data")
print("Checked: call ABI, config schema, exported entry points, share vault format.")
print("NOT checked here: the app's own security journal, which is Kotlin-side.")
PYTHON
}

case "${1:-}" in
    record)
        shift
        record "$@"
        ;;
    verify)
        shift
        verify "$@"
        ;;
    compare)
        shift
        compare "$@"
        ;;
    *) usage ;;
esac
