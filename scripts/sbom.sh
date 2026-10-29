#!/usr/bin/env bash
# Deterministic CycloneDX graph from cargo metadata --locked.
# Target graphs exclude dev dependencies; --all retains all platforms and dependency kinds.
# Usage: scripts/sbom.sh [--target TARGET | --all] [--check]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

TARGET="aarch64-linux-android"
ALL=0
CHECK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            shift
            TARGET="${1:-}"
            ;;
        --all) ALL=1 ;;
        --check) CHECK=1 ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

mkdir -p "$ROOT/sbom"
if [ "$ALL" = "1" ]; then
    OUT="$ROOT/sbom/workspace-all-targets.cdx.json"
    METADATA_ARGS=()
else
    OUT="$ROOT/sbom/foxcore-$TARGET.cdx.json"
    METADATA_ARGS=(--filter-platform "$TARGET")
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --locked is the point of the exercise: if it fails, the lockfile does not
# describe a resolvable graph and nothing downstream of it is pinned.
cargo metadata --locked --format-version 1 "${METADATA_ARGS[@]+"${METADATA_ARGS[@]}"}" \
    >"$WORK/metadata.json" || {
    echo "cargo metadata --locked failed: the lockfile is stale or unresolvable" >&2
    exit 1
}

FOXCORE_METADATA="$WORK/metadata.json" \
    FOXCORE_TARGET="$([ "$ALL" = "1" ] && echo "all-targets" || echo "$TARGET")" \
    FOXCORE_ALL="$ALL" \
FOXCORE_SOURCE_ROOT="$ROOT" \
    python3 - >"$WORK/sbom.json" <<'PYTHON'
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

metadata = json.load(open(os.environ["FOXCORE_METADATA"], encoding="utf-8"))
target = os.environ["FOXCORE_TARGET"]
include_dev = os.environ["FOXCORE_ALL"] == "1"

packages = {package["id"]: package for package in metadata["packages"]}
workspace = set(metadata["workspace_members"])
resolve = metadata["resolve"]
nodes = {node["id"]: node for node in resolve["nodes"]}

source_root = Path(os.environ["FOXCORE_SOURCE_ROOT"])
fork_origin = None
fork_ids = set()
fork_module = None
fork_candidates = [p for p in packages.values() if p.get("source") is None and p["name"] == "rustls"]
if fork_candidates or (source_root / "config/source-forks/rustls-0.23.46.json").exists():
    if len(fork_candidates) != 1:
        raise ValueError("Frozen rustls fork must resolve to exactly one path package")
    fork_package = fork_candidates[0]
    if (fork_package["version"] != "0.23.46" or fork_package["id"] in workspace or
            Path(fork_package["manifest_path"]).resolve() != (source_root / "vendor/rustls/Cargo.toml").resolve()):
        raise ValueError("Only the exact non-workspace vendor/rustls0.23.46 source is admitted")
    revision = os.environ.get("FOXCORE_SOURCE_REVISION", "")
    if re.fullmatch("[0-9a-f]{40}", revision) is None:
        raise ValueError("Modified rustls SBOM requires the actual FOXCORE_SOURCE_REVISION")
    spec = importlib.util.spec_from_file_location("rustls_fork_origin", source_root / "scripts/rustls-fork-origin.py")
    fork_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fork_module)
    vendor_root = source_root / fork_module.VENDOR_PATH
    if any(p.is_symlink() for p in vendor_root.rglob("*")):
        raise ValueError("Vendor source cannot contain symlinks")
    names = {str(p.relative_to(source_root)) for p in vendor_root.rglob("*") if p.is_file()}
    names.update((fork_module.ORIGIN_PATH, fork_module.UPSTREAM_PATH, fork_module.PATCH_PATH, fork_module.NOTICE_PATH))
    def read_source(name):
        path = source_root / name
        if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("Fork source must be regular and cannot traverse symlinks")
        return path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
    fork_origin = fork_module.validate_origin(read_source, names)
    fork_ids = {fork_package["id"]}


def ref(package_id: str) -> str:
    package = packages[package_id]
    if package_id in fork_ids:
        return fork_module.identity_url(fork_origin, revision)
    return f"pkg:cargo/{package['name']}@{package['version']}"


def wanted(dependency) -> bool:
    """Keep a dependency edge unless it is only ever a dev-dependency."""
    if include_dev:
        return True
    kinds = dependency.get("dep_kinds") or [{"kind": None}]
    return any(kind.get("kind") in (None, "build") for kind in kinds)


# Reachability from the workspace members, over the edges we keep. A crate that
# is only reachable through a dev-dependency is not in the shipped artifact and
# listing it would overstate what the product links.
reachable: set[str] = set()
frontier = list(workspace)
while frontier:
    current = frontier.pop()
    if current in reachable:
        continue
    reachable.add(current)
    for dependency in nodes.get(current, {}).get("deps", []):
        if wanted(dependency):
            frontier.append(dependency["pkg"])


def licenses(package):
    expression = package.get("license")
    if expression:
        return [{"expression": expression}]
    if package.get("license_file"):
        return [{"license": {"name": f"file: {package['license_file']}"}}]
    return []


components = []
for package_id in sorted(reachable, key=ref):
    package = packages[package_id]
    if package_id in workspace:
        continue  # the workspace itself is metadata.component, not a dependency
    if package.get("source") is None and package_id not in fork_ids:
        raise ValueError("Unadmitted non-workspace path dependency in Core SBOM")
    component = {
        "type": "library",
        "bom-ref": ref(package_id),
        "name": package["name"],
        "version": package["version"],
        "purl": ref(package_id),
        "scope": "required",
    }
    if package_id in fork_ids:
        component["properties"] = fork_module.component_properties(fork_origin, revision)
    if package.get("description"):
        component["description"] = package["description"]
    entries = licenses(package)
    if entries:
        component["licenses"] = entries
    external = []
    if package.get("repository"):
        external.append({"type": "vcs", "url": package["repository"]})
    if package.get("source"):
        external.append({"type": "distribution", "url": package["source"]})
    if external:
        component["externalReferences"] = external
    components.append(component)

dependencies = []
for package_id in sorted(reachable, key=ref):
    edges = sorted(
        {
            ref(dependency["pkg"])
            for dependency in nodes.get(package_id, {}).get("deps", [])
            if wanted(dependency) and dependency["pkg"] in reachable
        }
    )
    dependencies.append({"ref": ref(package_id), "dependsOn": edges})

root_members = sorted(workspace, key=ref)
document = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "bom-ref": "foxcore-workspace",
            "name": "foxcore",
            "version": packages[root_members[0]]["version"] if root_members else "0.0.0",
            "description": "FoxCore native VPN core",
        },
        "properties": [
            {"name": "foxcore:target", "value": target},
            {"name": "foxcore:dev_dependencies", "value": str(include_dev).lower()},
            {"name": "foxcore:source", "value": "cargo metadata --locked"},
            {"name": "foxcore:workspace_members", "value": str(len(root_members))},
        ],
    },
    "components": components,
    "dependencies": dependencies,
}

if fork_origin is not None:
    document["metadata"]["properties"] += [{"name": "foxhole:native:vendored-fork-components", "value": "1"},
                                            {"name": "foxcore:source-revision", "value": revision}]
json.dump(document, sys.stdout, indent=2, sort_keys=False)
sys.stdout.write("\n")
print(
    f"{len(components)} third-party components, {len(dependencies)} graph nodes",
    file=sys.stderr,
)
PYTHON
status=$?
[ "$status" = "0" ] || exit "$status"

if [ "$CHECK" = "1" ]; then
    if [ ! -f "$OUT" ]; then
        echo "$OUT does not exist; run scripts/sbom.sh to create it" >&2
        exit 1
    fi
    if diff -u "$OUT" "$WORK/sbom.json"; then
        echo "sbom: $(basename "$OUT") is up to date"
    else
        echo "sbom: $(basename "$OUT") is stale — the dependency graph changed" >&2
        echo "   Regenerate with scripts/sbom.sh and review the diff." >&2
        exit 1
    fi
else
    cp "$WORK/sbom.json" "$OUT"
    echo "sbom: $OUT"
fi
