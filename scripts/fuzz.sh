#!/usr/bin/env bash
# Stable runs are blind smoke tests; nightly plus cargo-fuzz enables coverage guidance.
#
# Usage:
#   scripts/fuzz.sh                       # same as `check`
#   scripts/fuzz.sh check                 # lint, exercise and build every target
#   scripts/fuzz.sh seed                  # rewrite fuzz/corpus/<target>
#   scripts/fuzz.sh list                  # target names, most exposed first
#   scripts/fuzz.sh run <target> [secs]   # default 60 seconds
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

HARNESS="$HERE/fuzz/harness/Cargo.toml"
FUZZ="$HERE/fuzz/Cargo.toml"
NIGHTLY="${FOXCORE_NIGHTLY:-nightly}"

TARGETS=(
    netstack_packet
    flow_key_from_packet
    dns_message
    wireguard_message
    socks_codec
    http_codec
    reality_records
    share_link
    shadowtls_server_stream
)

max_len_for() {
    case "$1" in
    # Cover fragmented records beyond libFuzzer's 4 KiB default.
    reality_records) echo 20000 ;;
    # Keep mutations within realistic link sizes.
    share_link) echo 1024 ;;
    # Input encodes a sequence of TLS socket reads, not one message.
    shadowtls_server_stream) echo 2048 ;;
    *) echo 4096 ;;
    esac
}

is_target() {
    for known in "${TARGETS[@]}"; do
        [ "$known" = "$1" ] && return 0
    done
    return 1
}

have_cargo_fuzz() {
    rustup run "$NIGHTLY" rustc --version >/dev/null 2>&1 &&
        cargo +"$NIGHTLY" fuzz --version >/dev/null 2>&1
}

case "${1:-check}" in
list)
    printf '%s\n' "${TARGETS[@]}"
    ;;

seed)
    cargo run --quiet --manifest-path "$HARNESS" --bin seed-corpus
    ;;

check)
    # These sans-io targets bind no ports, so concurrent test binaries are harmless.
    strays="$(pgrep -f 'target/debug/deps/' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$strays" != "0" ]; then
        printf '.. %s test binaries are running; harmless here, no ports are used.\n' "$strays"
    fi

    printf '\n== fuzz harness: fmt ==\n'
    cargo fmt --manifest-path "$HARNESS" -p foxcore-fuzz-harness -- --check || exit 1

    printf '\n== fuzz harness: clippy ==\n'
    cargo clippy --manifest-path "$HARNESS" -p foxcore-fuzz-harness --all-targets \
        -- -D warnings || exit 1

    printf '\n== fuzz harness: seeds and mutations ==\n'
    cargo test --manifest-path "$HARNESS" || exit 1

    printf '\n== fuzz targets: link against libFuzzer ==\n'
    cargo build --manifest-path "$FUZZ" || exit 1

    printf '\n== corpus ==\n'
    for target in "${TARGETS[@]}"; do
        count="$(find "fuzz/corpus/$target" -type f 2>/dev/null | wc -l | tr -d ' ')"
        printf '%-24s %s seeds\n' "$target" "$count"
        if [ "$count" = "0" ]; then
            printf '!! %s has no corpus; run %s\n' \
                "$target" "\`scripts/fuzz.sh seed\`"
            exit 1
        fi
    done
    ;;

run)
    target="${2:-}"
    seconds="${3:-60}"
    if ! is_target "$target"; then
        printf '!! usage: scripts/fuzz.sh run <target> [seconds]\n' >&2
        printf '%s\n' "${TARGETS[@]}" >&2
        exit 1
    fi
    max_len="$(max_len_for "$target")"

    if have_cargo_fuzz; then
        cargo +"$NIGHTLY" fuzz run --fuzz-dir "$HERE/fuzz" "$target" -- \
            "-max_total_time=$seconds" "-max_len=$max_len"
        exit $?
    fi

    cat <<EOF
!! No nightly toolchain with cargo-fuzz, so this run has no coverage feedback:
!!   libFuzzer will mutate at random and keep nothing it discovers.
!! For a real campaign:
!!   rustup toolchain install "$NIGHTLY"
!!   cargo +"$NIGHTLY" install cargo-fuzz --version 0.13.2 --locked
EOF
    cargo build --manifest-path "$FUZZ" --bin "$target" || exit 1
    mkdir -p "fuzz/artifacts/$target"
    "fuzz/target/debug/$target" \
        "-max_total_time=$seconds" "-max_len=$max_len" \
        "-artifact_prefix=fuzz/artifacts/$target/" \
        "fuzz/corpus/$target"
    ;;

*)
    sed -n '2,16p' "$0"
    exit 1
    ;;
esac
