#!/usr/bin/env bash
# CycloneDX SBOM of what actually ships, from cargo's own resolution.
#
# Generated from `cargo metadata --locked`, so the document describes the
# lockfile in the tree rather than whatever crates.io resolves to today. Two
# runs on the same lockfile produce byte-identical output: there is no timestamp
# and no serial number in it, deliberately, because an SBOM that changes every
# time it is generated cannot be reviewed as a diff — and a diff is the only way
# anyone notices a dependency appearing.
#
# No new tool in the supply chain. cargo-cyclonedx and cargo-sbom would each add
# a build-time dependency tree to a repository whose supply chain is part of its
# threat model, to produce a document cargo already has all the inputs for.
#
# What is in the shipped SBOM (`--target`, default aarch64-linux-android):
#   * only crates that survive platform filtering for that target;
#   * only normal and build dependencies — dev-dependencies are excluded,
#     because a test harness is not in the .so;
#   * the resolved dependency graph, not just a flat list.
# `--all` writes the unfiltered workspace graph instead, dev-dependencies and
# every platform included: that is the graph `cargo deny` reasons about.
#
# Usage:
#   scripts/sbom.sh                       # sbom/foxcore-aarch64-linux-android.cdx.json
#   scripts/sbom.sh --target armv7-linux-androideabi
#   scripts/sbom.sh --all                 # sbom/workspace-all-targets.cdx.json
#   scripts/sbom.sh --check               # regenerate and fail if it differs
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
    python3 - >"$WORK/sbom.json" <<'PYTHON'
import json
import os
import sys

metadata = json.load(open(os.environ["FOXCORE_METADATA"], encoding="utf-8"))
target = os.environ["FOXCORE_TARGET"]
include_dev = os.environ["FOXCORE_ALL"] == "1"

packages = {package["id"]: package for package in metadata["packages"]}
workspace = set(metadata["workspace_members"])
resolve = metadata["resolve"]
nodes = {node["id"]: node for node in resolve["nodes"]}


def ref(package_id: str) -> str:
    package = packages[package_id]
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
    component = {
        "type": "library",
        "bom-ref": ref(package_id),
        "name": package["name"],
        "version": package["version"],
        "purl": ref(package_id),
        "scope": "required",
    }
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
