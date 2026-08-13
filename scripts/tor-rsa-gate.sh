#!/usr/bin/env bash
# RUSTSEC-2023-0071 (rsa, Marvin Attack) — reachability gate for the Tor build.
#
# The Marvin Attack is a timing side channel on *private-key* RSA operations:
# decryption and signing. Verifying somebody else's signature with a public key
# involves no secret and is not affected. A pinned-source audit established
# that the Arti graph we build never performs a private-key RSA
# operation on the client path — the only callers are relay and directory-
# authority code that is either behind features we do not enable, in crates that
# are not in the lockfile at all, or under `#[cfg(test)]`.
#
# That audit is a statement about pinned sources. This script re-derives it, so
# an Arti bump, a feature change or a new dependency that reopens the path turns
# the gate red instead of passing quietly.
#
# What it asserts:
#
#   1. `rsa` is still the version the audit was written against. A bump changes
#      the audited source and has to be re-read, not assumed.
#   2. The crates that depend on `rsa` directly are exactly the three that were
#      audited. A fourth one is a new question, not a variation on an old one.
#   3. The relay/dirauth crates that *do* sign with RSA are absent from the
#      resolved graph (`tor-relay-crypto`, `tor-cert-x509`), and the features
#      that would pull them in are off (`tor-proto/relay`, `tor-cert/x509`).
#   4. Every mention of the RSA private-key API anywhere in the resolved graph
#      — ours and third-party — matches the reviewed set in
#      fixtures/tor-rsa/rsa-private-key-api.txt. A new file, or a new kind of
#      mention in a file that already had one, fails.
#
# Check 4 is syntactic: it greps pinned sources for the names by which the
# private-key API can be reached (there is no way to call `RsaPrivateKey::sign`
# without naming `RsaPrivateKey`, `rsa::KeyPair`, or a `pkcs1v15::SigningKey`,
# and no way to name them through a macro whose own name is not in the graph
# either). It is not a compiler-verified call graph — it cannot be without a
# call-graph tool in the build. What it does give is that the audit cannot
# silently go stale.
#
# The graph inspected is `--all-features`, i.e. the widest Tor build we can
# produce. Both `tor` and `onion-service` are default features of
# foxcore-android, so the shipped build is not a subset that omits the onion
# path — it contains it, and a clean result here is a statement about exactly
# what ships.
#
# That is also why this script is no longer a supply-chain extra. It runs in the
# main path of scripts/gate.sh and in the `gate` job of the CI workflow: the
# crate carrying RUSTSEC-2023-0071 is in every shipped .so, so a green run here
# is a condition on the commit a release is built from.
#
# Usage:
#   scripts/tor-rsa-gate.sh              # check
#   scripts/tor-rsa-gate.sh --record     # rewrite the fixture after re-auditing
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

TARGET="aarch64-linux-android"
RECORD=0
while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            shift
            TARGET="${1:-}"
            ;;
        --record) RECORD=1 ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
    shift
done

FIXTURE="fixtures/tor-rsa/rsa-private-key-api.txt"

# A full template is portable across BSD/macOS and GNU/Linux. `mktemp -t name` works on macOS
# but GNU mktemp rejects it before the security gate can inspect anything.
META="$(mktemp "${TMPDIR:-/tmp}/foxcore-tor-rsa.XXXXXX")"
trap 'rm -f "$META"' EXIT

if ! cargo metadata --locked --all-features --filter-platform "$TARGET" \
    --format-version 1 >"$META" 2>/dev/null; then
    echo "tor-rsa-gate: cargo metadata --locked --all-features failed" >&2
    exit 1
fi

RECORD="$RECORD" FIXTURE="$FIXTURE" TARGET="$TARGET" python3 - "$META" <<'PY'
import json
import os
import re
import sys

meta = json.load(open(sys.argv[1]))
record = os.environ["RECORD"] == "1"
fixture = os.environ["FIXTURE"]
target = os.environ["TARGET"]

failures = []


def check(ok, msg):
    if ok:
        print(f"  ok    {msg}")
    else:
        print(f"  FAIL  {msg}")
        failures.append(msg)


# The pinned-source state that was audited. Changing any of these means the
# relevant source has to be re-read before this list moves.
AUDITED_RSA = "0.9.10"
AUDITED_DIRECT_DEPENDENTS = {
    ("ssh-key-fork-arti", "0.6.7"),
    ("tor-key-forge", "0.44.0"),
    ("tor-llcrypto", "0.44.0"),
}
# Crates whose *production* code signs with an RSA private key. Neither is a
# dependency of a Tor client; both arrive only with relay or directory-authority
# support, which is what makes the whole argument work.
ABSENT_CRATES = ["tor-relay-crypto", "tor-cert-x509"]
FORBIDDEN_FEATURES = [("tor-proto", "relay"), ("tor-cert", "x509")]

packages = {p["id"]: p for p in meta["packages"]}
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
workspace = set(meta["workspace_members"])

by_name = {}
for p in meta["packages"]:
    by_name.setdefault(p["name"], []).append(p)

print(f"tor-rsa-gate: RUSTSEC-2023-0071 reachability, --all-features, {target}")
print()

# 1. The version the audit was written against.
rsa_pkgs = by_name.get("rsa", [])
check(
    len(rsa_pkgs) == 1 and rsa_pkgs[0]["version"] == AUDITED_RSA,
    f"rsa is {AUDITED_RSA} (audited); found "
    + (", ".join(f"{p['version']}" for p in rsa_pkgs) or "none"),
)

# 2. Who pulls it in.
direct = set()
for node in meta["resolve"]["nodes"]:
    for dep in node["deps"]:
        if packages[dep["pkg"]]["name"] == "rsa":
            p = packages[node["id"]]
            direct.add((p["name"], p["version"]))
check(
    direct == AUDITED_DIRECT_DEPENDENTS,
    "rsa is reached only from the three audited crates"
    + ("" if direct == AUDITED_DIRECT_DEPENDENTS else f"; found {sorted(direct)}"),
)

# 3. The relay/dirauth side is not in the graph.
for name in ABSENT_CRATES:
    check(name not in by_name, f"{name} is absent from the resolved graph")
for name, feature in FORBIDDEN_FEATURES:
    enabled = set()
    for p in by_name.get(name, []):
        enabled |= set(nodes[p["id"]]["features"])
    check(feature not in enabled, f"{name} is built without feature `{feature}`")

# 4. Every mention of the private-key API in the graph.
#
# Each pattern is a name that has to appear in the source of any crate that
# reaches an RSA private-key operation:
#   RsaPrivateKey      the `rsa` crate's private key itself
#   rsa::KeyPair       tor-llcrypto's wrapper around it (its `sign` is the one
#                      Tor's relay and dirauth code calls)
#   rsa_decrypt*       the hazmat entry points to the vulnerable modexp
#   Pkcs1v15Encrypt / Oaep / DecryptingKey / decrypt_blinded
#                      RSA *decryption*, which is the classic Marvin oracle
#   pkcs1v15::SigningKey, pss::SigningKey, pss::BlindedSigningKey
#                      the RustCrypto signing wrappers
#   sign_with_rng      blinded signing on RsaPrivateKey
#   define_rsa_keypair tor-key-forge's macro, which generates a `sign` method
PATTERNS = {
    "RsaPrivateKey": re.compile(r"\bRsaPrivateKey\b"),
    "rsa::KeyPair": re.compile(r"\brsa::KeyPair\b"),
    "rsa_decrypt": re.compile(r"\brsa_decrypt\w*\s*\("),
    "encrypt-decrypt": re.compile(r"\bPkcs1v15Encrypt\b|\bOaep\b|\boaep::"),
    "DecryptingKey": re.compile(r"\bDecryptingKey\b"),
    "SigningKey": re.compile(r"\b(?:pkcs1v15|pss)::(?:Blinded)?SigningKey\b"),
    "decrypt_blinded": re.compile(r"\bdecrypt_blinded\b"),
    "sign_with_rng": re.compile(r"\bsign_with_rng\b"),
    "define_rsa_keypair": re.compile(r"\bdefine_rsa_keypair\b"),
}

hits = {}
for p in meta["packages"]:
    # The `rsa` crate is where the vulnerable code lives; scanning it would
    # record its own implementation, which is not the question.
    if p["name"] == "rsa":
        continue
    root = os.path.dirname(p["manifest_path"])
    if not os.path.isdir(root):
        continue
    # Workspace crates are labelled without a version: ours move every release
    # and the fixture should not churn for that.
    label = (
        f"workspace/{p['name']}"
        if p["id"] in workspace
        else f"{p['name']}-{p['version']}"
    )
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            found = sorted(n for n, rx in PATTERNS.items() if rx.search(text))
            if found:
                rel = os.path.relpath(path, root)
                key = f"{label}/{rel}"
                hits.setdefault(key, set()).update(found)

current = "".join(f"{k}\t{','.join(sorted(v))}\n" for k, v in sorted(hits.items()))

if record:
    os.makedirs(os.path.dirname(fixture), exist_ok=True)
    with open(fixture, "w", encoding="utf-8") as fh:
        fh.write(current)
    print(f"  recorded {len(hits)} files into {fixture}")
else:
    try:
        expected = open(fixture, encoding="utf-8").read()
    except OSError:
        expected = None
    if expected is None:
        check(False, f"{fixture} is missing; run scripts/tor-rsa-gate.sh --record")
    else:
        same = expected == current
        check(
            same,
            f"RSA private-key API mentions match {fixture} ({len(hits)} files)",
        )
        if not same:
            exp = set(expected.splitlines())
            cur = set(current.splitlines())
            for line in sorted(cur - exp):
                print(f"        + {line}")
            for line in sorted(exp - cur):
                print(f"        - {line}")
            print()
            print("        Every added line is a new place where an RSA private")
            print("        key could be used. Read it, decide it, record the")
            print("        verdict beside the fixture, then re-record.")

print()
if failures:
    print("tor-rsa-gate: FAIL")
    sys.exit(1)
print("tor-rsa-gate: PASS")
PY
