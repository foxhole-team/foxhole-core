#!/usr/bin/env bash
# The gate every change has to pass before it is called done.
#
# Runs the same checks CI runs, in the same order, so a green run here means a
# green run there. Kept as a script rather than only a workflow file so the
# release gate remains reproducible outside GitHub Actions.
#
# Usage:
#   scripts/gate.sh          # stray test binaries, fmt, clippy, tests, android check, tor-rsa-gate
#   scripts/gate.sh --supply # also lockfile, cargo-deny on both graphs, both SBOMs, abi-gate
#                            # (needs `cargo install cargo-deny`)
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

# rustup's shims are not on PATH on the development machine.
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

# Wall-clock-sensitive tests (loopback sockets, short timeouts) flake when the
# whole suite runs at full width on a loaded desktop. Bounded on purpose.
TEST_THREADS="${FOXCORE_TEST_THREADS:-4}"

status=0
step() {
    printf '\n== %s ==\n' "$1"
}
fail() {
    printf '!! %s\n' "$1"
    status=1
}

# A killed `cargo test` leaves its test binaries alive, holding loopback ports.
# The next run then fails in the network tests and looks exactly like a
# regression — this cost real debugging time more than once, so the gate checks
# for it instead of letting the failure be mysterious.
step "stray test binaries"
strays="$(pgrep -f 'target/debug/deps/' 2>/dev/null | wc -l | tr -d ' ')"
if [ "$strays" != "0" ]; then
    fail "$strays test binaries from an earlier run are still alive."
    echo "   They hold loopback sockets and will fail the network tests."
    echo "   Clear them with: pkill -f 'target/debug/deps/'"
    exit 1
fi
echo "none"

step "cargo fmt --check"
cargo fmt --all -- --check || fail "formatting"

step "cargo clippy -D warnings"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy"

step "cargo test --workspace (--test-threads=$TEST_THREADS)"
cargo test --workspace -- --test-threads="$TEST_THREADS" || fail "tests"

# Everything above builds for the host, so nothing above compiles a line behind
# `cfg(target_os = "android")` — which is most of what actually ships. A split of
# foxcore-runtime left a private static reachable only from Android code, and
# fmt, clippy and the whole test suite stayed green while the .so would not link.
step "cargo ndk check (shipping Android ABIs)"
# A plain `cargo check --target` cannot do this: aws-lc-sys and ring run build
# scripts that need the NDK toolchain, which cargo-ndk is what supplies.
if [ "$(cargo ndk --version 2>/dev/null || true)" = "cargo-ndk 4.1.2" ]; then
    cargo ndk -t arm64-v8a -t armeabi-v7a check --workspace --all-features ||
        fail "android cross-check"
else
    printf '!! cargo-ndk 4.1.2 is required; install it with: cargo install cargo-ndk --version 4.1.2 --locked\n'
    status=1
fi

# RUSTSEC-2023-0071 (rsa, Marvin Attack) is accepted on the strength of an
# argument — the Arti graph performs no private-key RSA operation — and this
# re-derives that argument from the resolved graph.
#
# It used to live under --supply, next to cargo-deny, on the reasoning that Tor
# was an optional feature and its advisories were about code the release did not
# contain. `tor` is now in foxcore-android's default features, so the crate
# carrying that advisory is in every shipped .so, and a check that only runs when
# somebody remembers to type --supply is not a gate on it. Here it runs on every
# gate, and a release commit cannot be green without it.
step "Tor: RSA private-key reachability"
"$HERE/scripts/tor-rsa-gate.sh" || fail "tor-rsa-gate"

if [ "${1:-}" = "--supply" ]; then
    step "the lockfile is the build"
    cargo metadata --locked --format-version 1 >/dev/null || fail "cargo metadata --locked"
    git diff --quiet -- Cargo.lock || fail "Cargo.lock changed; commit it or explain why"

    step "cargo deny"
    if command -v cargo-deny >/dev/null 2>&1; then
        # Two graphs. The shipped one contains Arti client and onion-service,
        # so all of their findings are decided in deny.toml. The second graph
        # remains the widest-feature guard for future optional additions.
        cargo deny check || fail "cargo-deny: shipped graph"
        cargo deny --all-features --config deny-all-features.toml check ||
            fail "cargo-deny: widest feature graph"
    else
        fail "cargo-deny is not installed: cargo install cargo-deny --locked"
    fi

    step "SBOM"
    "$HERE/scripts/sbom.sh" --check || fail "SBOM is stale: scripts/sbom.sh"
    "$HERE/scripts/sbom.sh" --all --check || fail "SBOM is stale: scripts/sbom.sh --all"

    step "ABI v1 fixtures"
    "$HERE/scripts/abi-gate.sh" || fail "abi-gate"
fi

printf '\n'
if [ "$status" = "0" ]; then
    echo "gate: PASS"
else
    echo "gate: FAIL"
fi
exit "$status"
