#!/usr/bin/env bash
# Drive foxcore-outbound-probe against live servers.
#
# Two profile sources, never both in one run:
#
#   FOXCORE_SUBSCRIPTION_URL       an HTTPS subscription; its body is piped
#                                  straight into the probe and never stored.
#   FOXCORE_PROBE_CONFIG_FILE      a JSON file mapping selector -> outbound
#                                  config, for locally hosted servers (tuic,
#                                  shadowtls, anytls, socks, http) that no
#                                  subscription hands out.
#
# Neither the URL nor the config ever reaches argv, and the probe prints closed
# stage labels and byte counters only.
set -euo pipefail

CARGO_BIN="${CARGO:-cargo}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

read -r -a protocols <<< "${FOXCORE_PROBE_PROTOCOLS:-vless hysteria2 vmess trojan shadowsocks}"
if ((${#protocols[@]} == 0)); then
  echo "FOXCORE_PROBE_PROTOCOLS must contain at least one protocol" >&2
  exit 2
fi
for protocol in "${protocols[@]}"; do
  case "$protocol" in
    # Carried by share links, so reachable from a subscription body.
    vless|vmess|hysteria2|trojan|shadowsocks|naive|wireguard|socks|http|anytls) ;;
    # No share-link scheme exists for these; they need the JSON source.
    tuic|shadowtls) ;;
    *)
      echo "FOXCORE_PROBE_PROTOCOLS contains an unsupported selector" >&2
      exit 2
      ;;
  esac
done

probe() {
  env -u FOXCORE_SUBSCRIPTION_URL "$CARGO_BIN" run \
    --manifest-path "$ROOT/Cargo.toml" \
    --locked \
    --quiet \
    -p foxcore-testkit \
    --bin foxcore-outbound-probe \
    -- "${protocols[@]}"
}

if [ -n "${FOXCORE_PROBE_CONFIG_FILE:-}" ]; then
  if [ -n "${FOXCORE_SUBSCRIPTION_URL:-}" ]; then
    echo "set exactly one of FOXCORE_SUBSCRIPTION_URL and FOXCORE_PROBE_CONFIG_FILE" >&2
    exit 2
  fi
  [ -r "$FOXCORE_PROBE_CONFIG_FILE" ] || {
    echo "FOXCORE_PROBE_CONFIG_FILE is not readable" >&2
    exit 2
  }
  probe < "$FOXCORE_PROBE_CONFIG_FILE"
  exit
fi

: "${FOXCORE_SUBSCRIPTION_URL:?set FOXCORE_SUBSCRIPTION_URL or FOXCORE_PROBE_CONFIG_FILE}"

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

# The private URL is fed through curl stdin config and removed from child
# environments. Subscription bytes are never written to disk.
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

# The body goes through a variable instead of straight down the pipe, and the
# reason is a diagnosis this pass paid for twice. Piped into the probe, a failed
# fetch puts curl's message on stderr while stdout says "selected profile could
# not be imported" — so the one line anyone reads and pastes blames the importer
# for a network fault. On a slow or contended link that is the common case, not
# the rare one. A shell variable keeps the body off disk and out of argv, which
# is all the pipe was protecting.
body="$(fetch_subscription)" || {
  echo "subscription fetch failed; no profile was probed" >&2
  exit 3
}
if [ -z "$body" ]; then
  echo "subscription fetch returned an empty body; no profile was probed" >&2
  exit 3
fi
printf '%s\n' "$body" | probe
