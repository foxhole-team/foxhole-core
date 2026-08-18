#!/usr/bin/env python3
"""Is `new` still readable by an app written against `old`?

Used by scripts/abi-gate.sh on the capabilities document, and by
scripts/rollback-artifact.sh on parts of a release manifest.

The rule the whole file implements is the frozen ABI-v1 contract: fields may be
*added*, never removed, renamed, retyped or downgraded. So this is
deliberately not a diff — a diff would flag every addition, and additions are the
normal case. It reports only the changes that break a caller:

  * a key present in the reference and missing in the candidate;
  * a key whose JSON type changed;
  * one of the three version numbers changing (that is an ABI v2, not a patch);
  * a boolean that was true becoming false — `compiled: false` is how the core
    tells the app a protocol is not in this build, so flipping one is a silent
    feature removal for an app that already offers it;
  * an entry disappearing from a list of objects, matched by `id`;
  * a string disappearing from a positive list of strings (transport lists work
    this way).

`unsupported` is deliberately the inverse: removing an item means the new core
implemented something and is therefore additive. Treating that list like
`transports` made the ABI gate reject a capability gain while accepting a
capability loss.

Exit code 0 when compatible, 1 when not.
"""

import json
import sys

PINNED = {"capabilities_schema_version", "abi_version", "config_schema_version"}

problems: list[str] = []
notes: list[str] = []


def kind(value) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return "null"


def walk(path: str, old, new) -> None:
    if kind(old) != kind(new):
        problems.append(f"{path}: type changed {kind(old)} -> {kind(new)}")
        return

    if isinstance(old, dict):
        for key, value in old.items():
            where = f"{path}.{key}" if path else key
            if key not in new:
                problems.append(f"{where}: removed")
                continue
            walk(where, value, new[key])
        for key in new:
            if key not in old:
                notes.append(f"{path}.{key}" if path else key)
        return

    if isinstance(old, list):
        # Objects keyed by `id`: the capabilities document uses this shape for
        # protocols, features and journal capabilities.
        if old and all(isinstance(item, dict) and "id" in item for item in old):
            index = {item["id"]: item for item in new if isinstance(item, dict) and "id" in item}
            for item in old:
                identifier = item["id"]
                if identifier not in index:
                    problems.append(f"{path}[id={identifier}]: removed")
                    continue
                walk(f"{path}[id={identifier}]", item, index[identifier])
            for identifier in index:
                if not any(item["id"] == identifier for item in old):
                    notes.append(f"{path}[id={identifier}]")
            return
        # Plain strings normally name positive capabilities: a transport or
        # feature that disappeared is something the old app may already offer.
        #
        # `unsupported` is a negative contract. Removing an entry means the
        # candidate implemented it, so it is an additive capability gain. New
        # entries only clarify names that were never in a positive capability
        # list; a fail-closed app already refused them.
        if all(isinstance(item, str) for item in old):
            if path == "unsupported" or path.endswith(".unsupported"):
                for item in old:
                    if item not in new:
                        notes.append(f"{path}[-{item!r}]")
                for item in new:
                    if item not in old:
                        notes.append(f"{path}[{item!r}]")
                return
            missing = [item for item in old if item not in new]
            for item in missing:
                problems.append(f"{path}: value {item!r} removed")
            for item in new:
                if item not in old:
                    notes.append(f"{path}[{item!r}]")
            return
        if len(new) < len(old):
            problems.append(f"{path}: list shrank {len(old)} -> {len(new)}")
            return
        for position, item in enumerate(old):
            walk(f"{path}[{position}]", item, new[position])
        return

    # Scalars.
    leaf = path.rsplit(".", 1)[-1]
    if leaf in PINNED and old != new:
        problems.append(
            f"{path}: pinned version changed {old} -> {new}; "
            "this is an ABI v2 and needs parallel v1 support, not a fixture update"
        )
        return
    if isinstance(old, bool) and old and not new:
        problems.append(f"{path}: was true, now false — a capability was removed")


def check_self_consistency(path: str, node) -> None:
    """Flag a name declared both supported and unsupported in the same entry.

    This is a property of one document, not of a diff, so it is checked here rather than in
    `walk`: an entry that contradicts itself is wrong on its first publication, and the diff
    rules cannot see it — an addition to `unsupported` is deliberately only a note, on the
    reasoning that it clarifies a name no positive list claimed. That reasoning is sound and
    is exactly what let `amneziawg` ship `h1_h4_ranges` as unsupported while the parser,
    the config model and the importer all implemented it. A capability document that lies to
    the app is worse than one that omits, because the app fails closed on what it is told.
    """
    if isinstance(node, dict):
        denied = node.get("unsupported")
        if isinstance(denied, list):
            claimed = {
                item
                for key, value in node.items()
                if key != "unsupported" and isinstance(value, list)
                for item in value
                if isinstance(item, str)
            }
            for item in denied:
                if isinstance(item, str) and item in claimed:
                    problems.append(
                        f"{path}: {item!r} is listed as unsupported and also claimed as a capability"
                    )
        for key, value in node.items():
            check_self_consistency(f"{path}.{key}" if path else key, value)
        return
    if isinstance(node, list):
        for item in node:
            identifier = item.get("id") if isinstance(item, dict) else None
            child = f"{path}[id={identifier}]" if identifier else path
            check_self_consistency(child, item)


def compare(old, new) -> tuple[list[str], list[str]]:
    problems.clear()
    notes.clear()
    walk("", old, new)
    check_self_consistency("", new)
    return list(problems), list(notes)


def self_test() -> int:
    cases = [
        (
            "positive capability removal fails",
            {"transports": ["tcp", "udp"]},
            {"transports": ["tcp"]},
            True,
        ),
        (
            "negative capability removal is a gain",
            {"unsupported": ["itime", "link_import"]},
            {"unsupported": []},
            False,
        ),
        (
            "negative capability additions are descriptive",
            {"unsupported": []},
            {"unsupported": ["server_role"]},
            False,
        ),
        (
            "pinned versions never drift inside one schema",
            {"capabilities_schema_version": 1},
            {"capabilities_schema_version": 2},
            True,
        ),
    ]
    for name, old, new, should_fail in cases:
        found, _ = compare(old, new)
        if bool(found) != should_fail:
            print(f"self-test failed: {name}", file=sys.stderr)
            return 1
    print("abi-compare-json: self-test PASS")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 3:
        print(
            "usage: abi-compare-json.py <reference.json> <candidate.json> | --self-test",
            file=sys.stderr,
        )
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        old = json.load(handle)
    with open(sys.argv[2], encoding="utf-8") as handle:
        new = json.load(handle)

    found_problems, found_notes = compare(old, new)

    for note in found_notes:
        print(f"   + {note} (additive, allowed)")
    for problem in found_problems:
        print(f"!! {problem}", file=sys.stderr)
    if found_problems:
        print(
            f"{len(found_problems)} incompatible change(s) against {sys.argv[1]}",
            file=sys.stderr,
        )
        return 1
    print(f"compatible with {sys.argv[1]} ({len(found_notes)} additive change(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
