#!/usr/bin/env bash
# The one entry point for the fuzz targets in `fuzz/`.
#
# The targets link and run on the pinned stable toolchain, so `run` works with
# nothing installed — but *blindly*: without nightly's `-Zsanitizer` there is no
# coverage feedback, libFuzzer keeps no corpus, and mutation is uniform random.
# That finds shallow crashes and nothing deeper. Install nightly and cargo-fuzz
# and this script switches to the coverage-guided path on its own.
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

# rustup's shims are not on PATH on the development machine.
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

HARNESS="$HERE/fuzz/harness/Cargo.toml"
FUZZ="$HERE/fuzz/Cargo.toml"
# CI sets a dated channel. Developers keep the conventional rolling alias
# unless they deliberately ask to reproduce that exact campaign.
NIGHTLY="${FOXCORE_NIGHTLY:-nightly}"

TARGETS=(
    flow_key_from_packet
    dns_message
    wireguard_message
    socks_codec
    http_codec
    reality_records
    share_link
    shadowtls_server_stream
)

# `reality_records` encrypts its input, so libFuzzer's 4 KiB default would keep
# the record fragmentation path — which the corpus seeds — permanently out of
# reach.
max_len_for() {
    case "$1" in
    reality_records) echo 20000 ;;
    # A share link is a URL and a subscription body is a handful of them. The
    # 4 KiB default spends the budget on kilobyte blobs that no provider ever
    # sends, and fills the committed corpus with them.
    share_link) echo 1024 ;;
    # The input is a whole sequence of socket reads, not one message: two bytes
    # of every segment are its length prefix, and a response worth exploring is
    # a handful of TLS records. 4 KiB would be spent on segment counts no
    # server produces.
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
    # `gate.sh` fails hard on live test binaries because a killed `cargo test`
    # leaves them holding loopback ports. Nothing here binds a socket — every
    # parser under test is sans-io and the SOCKS decoders read from a `&[u8]` —
    # so a live binary is only worth mentioning, and failing on it would mean
    # this script could not run while anyone else was running the suite.
    strays="$(pgrep -f 'target/debug/deps/' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$strays" != "0" ]; then
        printf '.. %s test binaries are running; harmless here, no ports are used.\n' "$strays"
    fi

    # `-p`, never `--all`: a sibling crate may be mid-edit in another session.
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
