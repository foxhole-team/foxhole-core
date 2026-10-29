#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("metadata", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
metadata = json.loads(args.metadata.read_text())
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
roots = set(metadata["workspace_members"])
reachable = set()
queue = list(roots)
while queue:
    key = queue.pop()
    if key in reachable:
        continue
    reachable.add(key)
    for edge in nodes[key]["deps"]:
        if any(k["kind"] in (None, "build") for k in edge["dep_kinds"]):
            queue.append(edge["pkg"])
def ref(key):
    p = packages[key]
    return f"pkg:cargo/{p['name']}@{p['version']}"
components = []
for key in sorted(reachable - roots, key=ref):
    p = packages[key]
    item = {"type": "library", "bom-ref": ref(key), "name": p["name"], "version": p["version"], "purl": ref(key), "scope": "required"}
    if p.get("license"):
        item["licenses"] = [{"expression": p["license"]}]
    components.append(item)
root = packages[next(iter(roots))]
dependencies = []
for key in sorted(reachable, key=ref):
    children = set()
    for edge in nodes[key]["deps"]:
        if edge["pkg"] in reachable and any(k["kind"] in (None, "build") for k in edge["dep_kinds"]):
            children.add(ref(edge["pkg"]))
    dependencies.append({"ref": ref(key), "dependsOn": sorted(children)})
result = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"type": "library", "bom-ref": ref(root["id"]), "name": root["name"], "version": root["version"]}},
    "components": components,
    "dependencies": dependencies,
}
content = json.dumps(result, indent=2, sort_keys=True) + "\n"
if args.check:
    if args.output.read_text() != content:
        raise SystemExit("Sentinel SBOM is stale")
else:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content)
