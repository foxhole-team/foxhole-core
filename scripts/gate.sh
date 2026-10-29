#!/usr/bin/env bash
# Match local and CI gates; --supply also checks advisories, SBOMs and frozen ABI fixtures.
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

# Abandoned test processes retain loopback sockets and invalidate the next run.
step "stray test binaries"
strays="$(pgrep -f 'target/debug/deps/' 2>/dev/null | wc -l | tr -d ' ')"
if [ "$strays" != "0" ]; then
    fail "$strays test binaries from an earlier run are still alive."
    echo "   They hold loopback sockets and will fail the network tests."
    echo "   Clear them with: pkill -f 'target/debug/deps/'"
    exit 1
fi
echo "none"

step "Android Docker wrapper environment"
python3 scripts/tests/test_docker_android_env.py || fail "android-docker-wrapper-env"

step "cargo fmt --check"
cargo fmt --all -- --check || fail "formatting"

step "cargo clippy -D warnings"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy"

step "cargo test --workspace (--test-threads=$TEST_THREADS)"
cargo test --workspace -- --test-threads="$TEST_THREADS" || fail "tests"

# Host gates do not compile cfg(target_os = "android") or its NDK dependencies.
step "cargo ndk check (shipping Android ABIs)"
if [ "$(cargo ndk --version 2>/dev/null || true)" = "cargo-ndk 4.1.2" ]; then
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 --platform 26 check --locked --workspace --all-features ||
        fail "android cross-check"
else
    printf '!! cargo-ndk 4.1.2 is required; install it with: cargo install cargo-ndk --version 4.1.2 --locked\n'
    status=1
fi

# Re-derive the accepted rsa advisory exception: shipped Arti must have no private-key RSA path.
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
