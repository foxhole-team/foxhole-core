#!/usr/bin/env bash
# RUSTSEC-2023-0071 (rsa, Marvin) — the *dynamic* half of the answer.
#
# scripts/tor-rsa-gate.sh is syntactic: it re-derives the call-graph argument
# from pinned sources and freezes the set of
# places the private-key API is named. What it cannot do is watch the code run.
# While Tor was an optional feature that gap was academic. It is a default
# feature now, so `rsa` is in every shipped .so, and "no caller exists in the
# sources" deserves to be checked against "no call happened".
#
# This checks it by execution:
#
#   1. A throwaway git worktree at HEAD — nothing here touches the real tree,
#      and in particular the shipped Cargo.lock never sees the patch below.
#   2. rsa <AUDITED> is copied out of the cargo registry and instrumented:
#      `::std::process::abort()` at the top of `rsa_decrypt` and
#      `rsa_decrypt_and_check`. Every private-key operation in that crate goes
#      through them — decryption via OAEP and PKCS#1 v1.5, and signing too,
#      because an RSA signature *is* a private-key exponentiation of a padded
#      digest. Public-key work (verification, encryption) runs `rsa_encrypt`
#      and is untouched, which matters because the client verifies relay
#      signatures constantly; a build that trapped those would abort
#      on correct behaviour and prove nothing.
#   3. `[patch.crates-io]` puts that copy under the entire graph.
#   4. `crates/proto-tor/examples/rsa_dynamic_probe.rs` runs a real Tor
#      session through the core's own TorOutbound: bootstrap, a clearnet
#      stream, an .onion stream.
#
# Abort rather than panic on purpose. A panic can be swallowed by a
# `catch_unwind` in a task pool and come back as an ordinary error, which would
# make a positive result look like a negative one.
#
# What a green run is worth, stated exactly: no private-key RSA operation was
# executed by anything this session did. It is not a proof about sessions this
# one did not have — a bridge, a pluggable transport, a published onion service
# — and it is not a proof that code such as a dead `KeyPair::sign` is absent
# from the artifact.
#
# NOT part of scripts/gate.sh. It needs the real Tor network, it takes minutes,
# and a gate that fails because a third-party onion is down is a gate people
# learn to ignore. Run it and retain the output whenever the Arti version moves.
#
# Usage:
#   scripts/tor-rsa-dynamic-probe.sh            # build, run, clean up
#   scripts/tor-rsa-dynamic-probe.sh --keep     # leave the worktree for poking
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

# The version the pinned-source audit covered. Deliberately duplicated from
# scripts/tor-rsa-gate.sh rather than sourced: if a bump makes these disagree,
# both scripts should be re-read, and a shared constant would hide that.
AUDITED_RSA="0.9.10"

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# A Tor bootstrap plus two streams is slow but not unbounded, so the build gets
# a ceiling past which something is wrong rather than merely slow. macOS ships
# no `timeout`; without coreutils the build simply runs uncapped rather than
# failing on a missing binary, which is what the first run of this script did.
BUILD_TIMEOUT_MIN=60
TIMEOUT=()
for candidate in timeout gtimeout; do
    if command -v "$candidate" >/dev/null 2>&1; then
        TIMEOUT=("$candidate" "${BUILD_TIMEOUT_MIN}m")
        break
    fi
done

say() { printf '\n== %s ==\n' "$1"; }
die() {
    printf '!! %s\n' "$1" >&2
    exit 1
}

# ------------------------------------------------------------------ headroom
# An Arti build is several hundred megabytes of artifacts and this box has been
# close to full. Checking is cheaper than a half-written target directory.
avail_gib="$(df -g "$ROOT" | awk 'NR==2 { print $4 }')"
say "disk"
echo "${avail_gib} GiB available"
[ "${avail_gib:-0}" -ge 3 ] || die "under 3 GiB free; refusing to build Arti here"

WORK="$(mktemp -d)"
cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo "worktree kept at $WORK/tree"
        return
    fi
    git -C "$ROOT" worktree remove --force "$WORK/tree" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------- the worktree
say "isolated worktree"
git worktree add --detach "$WORK/tree" HEAD >/dev/null 2>&1 ||
    die "could not create a worktree at HEAD"
TREE="$WORK/tree"
echo "$TREE at $(git -C "$ROOT" rev-parse --short HEAD)"
# Worth saying out loud: this probes HEAD, not the working tree. An
# uncommitted change to proto-tor or to the probe is not in what runs below.
git -C "$ROOT" diff --quiet HEAD -- crates/proto-tor ||
    echo "note: crates/proto-tor has uncommitted changes; they are NOT in this run"

# ------------------------------------------------------------ instrumented rsa
say "instrumenting rsa $AUDITED_RSA"
SOURCE=""
for candidate in "$HOME"/.cargo/registry/src/*/rsa-"$AUDITED_RSA"; do
    [ -d "$candidate" ] && SOURCE="$candidate" && break
done
[ -n "$SOURCE" ] || die "rsa-$AUDITED_RSA is not unpacked in the registry; run a build first"
mkdir -p "$TREE/vendor"
cp -R "$SOURCE" "$TREE/vendor/rsa"
chmod -R u+w "$TREE/vendor/rsa"
rm -f "$TREE/vendor/rsa/.cargo-ok"

python3 - "$TREE" <<'PY' || die "instrumenting rsa failed"
import pathlib, sys

tree = pathlib.Path(sys.argv[1])

# `rsa` is `#![no_std]` whatever its `std` feature says — that feature only
# forwards to dependencies — and it declares `extern crate std` only when the
# feature is on. The trap needs std regardless of what the consumer selected,
# so the declaration is made unconditional. It has to stay exactly where it is:
# an `extern crate` moved up next to the `#![...]` inner attributes is a syntax
# error, and the resulting couple of hundred cascading errors do not mention it.
lib = tree / "vendor/rsa/src/lib.rs"
source = lib.read_text()
gated = '#[cfg(feature = "std")]\nextern crate std;'
assert gated in source, "rsa/src/lib.rs no longer declares std the way this expects"
lib.write_text(source.replace(
    gated,
    "// FoxCore probe instrumentation, not upstream.\nextern crate std;",
    1,
))

trap = '''
/// FoxCore probe instrumentation, not upstream. See
/// scripts/tor-rsa-dynamic-probe.sh.
#[inline(never)]
fn foxcore_private_rsa_reached(entry: &str) -> ! {
    use ::std::io::Write as _;
    let mut err = ::std::io::stderr();
    let _ = writeln!(
        err,
        "\\nFOXCORE-RSA-PRIVATE-OP-REACHED: {entry}\\n{:?}",
        ::std::backtrace::Backtrace::force_capture()
    );
    let _ = err.flush();
    ::std::process::abort()
}
'''

path = tree / "vendor/rsa/src/algorithms/rsa.rs"
source = path.read_text()

# The abort makes every parameter of both functions unused, which is thirty
# lines of warnings about code that is deliberately mutilated. Silenced at the
# module so the probe's own output is the only thing in the transcript.
head = "//! Generic RSA implementation\n"
assert source.startswith(head), "algorithms/rsa.rs no longer starts with its module doc"
source = source.replace(head, head + "#![allow(unused_variables, unused_mut)]\n", 1)

anchor = "/// ⚠️ Performs raw RSA decryption with no padding or error checking."
assert anchor in source, "the rsa_decrypt doc comment moved"
source = source.replace(anchor, trap.strip() + "\n\n" + anchor, 1)

for name, signature in (
    ("rsa_decrypt", ") -> Result<BigUint> {\n    if c >= priv_key.n() {"),
    ("rsa_decrypt_and_check", ") -> Result<BigUint> {\n    let m = rsa_decrypt(rng, priv_key, c)?;"),
):
    assert signature in source, f"{name} no longer looks the way this expects"
    head, _, rest = signature.partition("\n")
    source = source.replace(
        signature,
        f'{head}\n    foxcore_private_rsa_reached("rsa::algorithms::rsa::{name}");\n'
        f"    #[allow(unreachable_code)]\n{rest}",
        1,
    )

path.write_text(source)
print("armed: rsa_decrypt, rsa_decrypt_and_check")
PY

cat >>"$TREE/Cargo.toml" <<'EOF'

# Probe worktree only.
[patch.crates-io]
rsa = { path = "vendor/rsa" }

# Optimised enough that a real bootstrap finishes in minutes, with line tables
# so a tripped trap still names its caller, and without the full debug info
# that would cost several GiB.
[profile.dev]
opt-level = 2
debug = "line-tables-only"
incremental = false
EOF

# ---------------------------------------------------------------- build & run
say "building the probe"
# The `+` form because macOS ships bash 3.2, where expanding an empty array
# under `set -u` is an unbound-variable error rather than nothing at all.
(cd "$TREE" && ${TIMEOUT[@]+"${TIMEOUT[@]}"} cargo build -p proto-tor --features arti \
    --example rsa_dynamic_probe 2>&1 | tail -5) || die "the probe did not build"

# ------------------------------------------------------------------ link time
# Asked before the session, because it is the stronger of the two answers and
# it is free. The trap is a plain non-generic function: it is compiled into the
# rlib unconditionally, and the only thing that references it is the body of a
# private-key operation. If it is not in the linked executable, the object
# carrying those operations was never pulled in — nothing that got linked can
# reach them, whatever any session does.
#
# Reported rather than enforced. A future rustc or linker could keep the symbol
# for reasons of its own without any call existing, and a check that turned red
# on that would be a check about codegen, not about Tor.
say "link-time reachability"
PROBE_BIN="$(find "$TREE/target/debug/examples" -name 'rsa_dynamic_probe' -perm -u+x -type f | head -1)"
RSA_RLIB="$(find "$TREE/target/debug/deps" -name 'librsa-*.rlib' | head -1)"
if [ -n "$PROBE_BIN" ] && [ -n "$RSA_RLIB" ]; then
    # Defined text symbols only, and the rsa crate identified by the
    # disambiguator rustc's v0 mangling gave it in *this* build. Grepping for
    # the bare string "rsa" would also count `ring::rsa` and
    # `tor_netdoc::types::misc::rsa`, which are different code entirely and
    # would turn the positive control into a number that is always large.
    defined() { nm "$1" 2>/dev/null | awk '$2 == "T" || $2 == "t" { print $3 }'; }
    crate="$(nm "$RSA_RLIB" 2>/dev/null | grep -oE 'Cs[A-Za-z0-9]+_3rsa' | head -1)"
    in_rlib="$(defined "$RSA_RLIB" | grep -cE 'rsa_decrypt|foxcore_private_rsa_reached')"
    in_bin="$(defined "$PROBE_BIN" | grep -cE 'rsa_decrypt|foxcore_private_rsa_reached')"
    rsa_in_rlib="$(defined "$RSA_RLIB" | grep -c "$crate")"
    rsa_in_bin="$(defined "$PROBE_BIN" | grep -c "$crate")"
    echo "private-key primitives: $in_rlib symbol(s) in the rsa rlib, $in_bin in the linked probe"
    echo "the rsa crate itself is linked: $rsa_in_bin of its $rsa_in_rlib symbols reached the probe"
    if [ "$in_bin" = "0" ]; then
        echo "=> the object carrying the private-key operations was not linked at all"
    else
        echo "=> the private-key operations ARE linked; the session below decides whether"
        echo "   anything calls them"
    fi
fi

say "running a real Tor session with the trap armed"
(cd "$TREE" && RUST_BACKTRACE=1 cargo run -q -p proto-tor --features arti \
    --example rsa_dynamic_probe)
status=$?

printf '\n'
case "$status" in
0) echo "tor-rsa-dynamic-probe: PASS — no private-key RSA operation executed" ;;
2) echo "tor-rsa-dynamic-probe: INCONCLUSIVE — the session did not complete, so
   nothing was observed. This is not a red result; see the output above." ;;
*) echo "tor-rsa-dynamic-probe: FAIL — the process died with status $status.
   If the output contains FOXCORE-RSA-PRIVATE-OP-REACHED, the pinned-source
   reachability argument is wrong and the backtrace names the caller." ;;
esac
exit "$status"
