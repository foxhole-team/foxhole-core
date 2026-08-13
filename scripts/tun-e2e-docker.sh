#!/usr/bin/env bash
# Isolated TUN end-to-end test for FoxCore's in-process data plane.
#
# Runs entirely inside a throwaway Docker container with its OWN network namespace and NAT
# internet, so the host network is never touched and no root/sudo is needed (docker group).
# Proves the exact packet path the Android runtime uses; only the fd source differs.
#
# Usage: scripts/tun-e2e-docker.sh <engine-config.json>
#   The config may select VLESS, Hysteria2, Trojan, or Shadowsocks.
set -euo pipefail
CONFIG="${1:?usage: tun-e2e-docker.sh <engine-config.json>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

echo "== building release foxcore-tun (host glibc) =="
( cd "$HERE" && cargo build --release -p foxcore-testkit --bin foxcore-tun )

RUN="$(mktemp -d)"; trap 'rm -rf "$RUN"' EXIT
cp "$HERE/target/release/foxcore-tun" "$RUN/foxcore-tun"
cp "$CONFIG" "$RUN/config.json"

cat > "$RUN/entrypoint.sh" <<'INNER'
#!/bin/sh
set -e
apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y iproute2 curl dnsutils >/dev/null 2>&1
echo "[c] direct egress IP:"; curl -s --max-time 15 https://api.ipify.org; echo
ip tuntap add dev fox0 mode tun
ip addr add 10.99.0.1/24 dev fox0
ip link set fox0 mtu 1400 up
/w/foxcore-tun /w/config.json fox0 & TUN_PID=$!
sleep 1
# UDP path: route a resolver through the tunnel and query it.
ip route add 1.1.1.1/32 dev fox0
echo -n "[c] DNS-over-tunnel dig @1.1.1.1 example.com: "; dig +time=8 +tries=1 +short @1.1.1.1 example.com A | tr '\n' ' '; echo
# TCP path: resolve via the tunneled DNS, pin the IP, fetch the exit IP.
TIP=$(dig +time=8 +tries=1 +short @1.1.1.1 api.ipify.org A | grep -E '^[0-9]' | head -1)
ip route add "$TIP/32" dev fox0
echo "[c] exit IP THROUGH TUN->FoxCore outbound (TCP):"
curl -s --max-time 25 --resolve "api.ipify.org:443:$TIP" https://api.ipify.org; echo
kill $TUN_PID 2>/dev/null || true
INNER
chmod +x "$RUN/entrypoint.sh"

# Image must have glibc >= host (ubuntu:devel matches). Swap for a musl static build to use alpine.
docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun -v "$RUN":/w:ro \
  ubuntu:devel sh /w/entrypoint.sh
