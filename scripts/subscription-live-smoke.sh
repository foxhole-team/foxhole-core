#!/usr/bin/env bash
# Import the owner's live subscription and report what survived.
#
# FOXCORE_EXPECT_PROTOCOLS pins the imported protocol list as a regression guard.
# It is unset by default: a real subscription changes servers, and a probe that
# fails on that trains people to ignore it.
#
# FOXCORE_SUBSCRIPTION_INSPECT=1 asks for protocol shapes instead of an import,
# which is the only mode that also names lines the import drops.
set -euo pipefail

: "${FOXCORE_SUBSCRIPTION_URL:?set FOXCORE_SUBSCRIPTION_URL to an HTTPS subscription URL}"

case "$FOXCORE_SUBSCRIPTION_URL" in
  https://*) ;;
  *)
    echo "FOXCORE_SUBSCRIPTION_URL must use HTTPS" >&2
    exit 2
    ;;
esac

case "$FOXCORE_SUBSCRIPTION_URL" in
  *$'\n'*|*$'\r'*|*'"'*|*'\'*)
    echo "FOXCORE_SUBSCRIPTION_URL contains unsupported characters" >&2
    exit 2
    ;;
esac

CARGO_BIN="${CARGO:-cargo}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

probe_args=()
if [ -n "${FOXCORE_SUBSCRIPTION_INSPECT:-}" ]; then
  probe_args+=("--inspect")
elif [ -n "${FOXCORE_EXPECT_PROTOCOLS:-}" ]; then
  probe_args+=("$FOXCORE_EXPECT_PROTOCOLS")
fi

# Feed the private URL through curl's stdin config so it is not exposed in the
# process command line. The parser prints protocol kinds and drop counters only,
# never endpoints, credentials or the rejected line itself.
fetch_subscription() {
  printf 'url = "%s"\n' "$FOXCORE_SUBSCRIPTION_URL" |
    env -u FOXCORE_SUBSCRIPTION_URL curl \
      --config - \
      --fail \
      --silent \
      --show-error \
      --location \
      --proto '=https' \
      --tlsv1.2 \
      --max-filesize 1048576 \
      --retry 3 \
      --retry-all-errors \
      --max-time 60
}

# Same reason as in outbound-live-smoke.sh: down a pipe, a failed fetch reads on
# stdout as a failed import, and the fetch is the part that fails on a slow link.
body="$(fetch_subscription)" || {
  echo "subscription fetch failed; nothing was imported" >&2
  exit 3
}
if [ -z "$body" ]; then
  echo "subscription fetch returned an empty body; nothing was imported" >&2
  exit 3
fi
printf '%s\n' "$body" |
  env -u FOXCORE_SUBSCRIPTION_URL "$CARGO_BIN" run \
    --manifest-path "$ROOT/Cargo.toml" \
    --locked \
    --quiet \
    -p foxcore-testkit \
    --bin foxcore-subscription-probe \
    -- ${probe_args[@]+"${probe_args[@]}"}
