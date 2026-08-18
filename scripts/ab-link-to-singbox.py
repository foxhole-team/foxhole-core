#!/usr/bin/env python3
"""Translate one subscription into a node manifest plus per-node sing-box configs.

This exists so the two arms of the FoxCore/sing-box comparison are pointed at
*the same server*. FoxCore consumes the provider's share link directly through
`foxcore-link`; sing-box has no share-link parser, so its arm needs the same
node re-expressed as JSON. Doing that by hand is how an A/B turns into two
different experiments, so it is done here, once, from one source line.

Credential hygiene is the reason this is a separate file rather than a few
lines of shell:

  * the subscription is read from a file path or stdin, never from a command
    line, because an argv string is visible in `ps` and in shell history;
  * stdout carries only node ids, protocol shapes and counters - never a
    server address, uuid, password, reality key or the source line itself;
  * the generated sing-box configs do carry credentials, because sing-box
    cannot connect without them. They are written with mode 0600 into a
    directory the caller names, and that directory belongs outside the repo.
    The caller is responsible for putting it in a scratch path; this script
    refuses to write inside a git work tree it can detect.

Usage:
    ab-link-to-singbox.py --sub-file <path> --out-dir <dir> [--socks-port N]
    ab-link-to-singbox.py --out-dir <dir> < subscription-body

Output on stdout: one JSON object per line, the sanitised manifest.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
from urllib.parse import parse_qs, unquote, urlparse

MAX_BODY_BYTES = 1024 * 1024
MAX_PROFILES = 256


def die(message):
    print(f"ab-link-to-singbox: {message}", file=sys.stderr)
    sys.exit(2)


def b64_any(text):
    """Decode base64 in whichever of the four alphabets the provider used."""
    text = text.strip()
    for altchars in (None, b"-_"):
        for pad in ("", "=", "==", "==="):
            try:
                raw = base64.b64decode(
                    (text + pad).encode(), altchars=altchars, validate=False
                )
                return raw.decode("utf-8")
            except Exception:
                continue
    raise ValueError("not base64")


def load_body(path):
    if path == "-":
        raw = sys.stdin.buffer.read(MAX_BODY_BYTES + 1)
    else:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        die("subscription body exceeds 1 MiB")
    text = raw.decode("utf-8", "replace").strip()
    if "://" not in text:
        try:
            text = b64_any(text)
        except ValueError:
            die("body is neither a URI list nor base64")
    return text


def links(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "://" not in line or line.startswith("#"):
            continue
        out.append(line)
        if len(out) > MAX_PROFILES:
            die(f"profile count exceeds {MAX_PROFILES}")
    return out


def qs_get(query, *names):
    for name in names:
        value = query.get(name)
        if value and value[0]:
            return unquote(value[0])
    return ""


def tls_block(query, default_sni, host):
    """The TLS half, shared by every stream protocol here.

    `server_name` falls back to the host on purpose: a REALITY node without an
    explicit `sni` is a node whose SNI is its host, and silently sending no SNI
    would make the sing-box arm fail a handshake the FoxCore arm completes.
    """
    security = qs_get(query, "security")
    sni = qs_get(query, "sni", "peer") or default_sni or host
    fingerprint = qs_get(query, "fp")
    alpn = qs_get(query, "alpn")
    block = {"enabled": True, "server_name": sni}
    if alpn:
        block["alpn"] = [part for part in alpn.split(",") if part]
    if qs_get(query, "allowInsecure") in ("1", "true"):
        block["insecure"] = True
    if fingerprint:
        block["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        reality = {"enabled": True, "public_key": qs_get(query, "pbk")}
        short_id = qs_get(query, "sid")
        if short_id:
            reality["short_id"] = short_id
        block["reality"] = reality
        block.pop("insecure", None)
    return block


def transport_block(query):
    kind = qs_get(query, "type", "headerType") or "tcp"
    if kind in ("tcp", "raw", "none", ""):
        return None, "tcp"
    if kind == "grpc":
        return {
            "type": "grpc",
            "service_name": qs_get(query, "serviceName", "path"),
        }, "grpc"
    if kind == "ws":
        block = {"type": "ws", "path": qs_get(query, "path") or "/"}
        host = qs_get(query, "host")
        if host:
            block["headers"] = {"Host": host}
        return block, "ws"
    if kind in ("http", "h2"):
        block = {"type": "http", "path": qs_get(query, "path") or "/"}
        host = qs_get(query, "host")
        if host:
            block["host"] = [host]
        return block, "http"
    return None, kind


def translate(link, tag):
    """One share link to one sing-box outbound. Returns (outbound, shape, note)."""
    url = urlparse(link)
    scheme = url.scheme.lower()
    query = parse_qs(url.query, keep_blank_values=True)
    host = url.hostname or ""
    port = url.port
    note = ""

    if scheme == "vless":
        transport, kind = transport_block(query)
        flow = qs_get(query, "flow")
        outbound = {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": port,
            "uuid": unquote(url.username or ""),
        }
        if flow:
            outbound["flow"] = flow
        security = qs_get(query, "security")
        if security in ("tls", "reality", "xtls"):
            outbound["tls"] = tls_block(query, "", host)
        if transport:
            outbound["transport"] = transport
        shape = f"vless-{security or 'none'}-{kind}" + (f"-{flow}" if flow else "")
        fingerprint = qs_get(query, "fp")
        if fingerprint and fingerprint not in (
            "chrome", "firefox", "edge", "safari", "ios", "android",
            "random", "randomized", "360", "qq",
        ):
            note = f"unrecognised uTLS fingerprint {fingerprint!r}"
        return outbound, shape, note

    if scheme in ("hysteria2", "hy2"):
        outbound = {
            "type": "hysteria2",
            "tag": tag,
            "server": host,
            "server_port": port,
            "password": unquote(url.username or "") or qs_get(query, "password"),
            "tls": tls_block(query, qs_get(query, "sni"), host),
        }
        obfs_password = qs_get(query, "obfs-password")
        if qs_get(query, "obfs") == "salamander" and obfs_password:
            outbound["obfs"] = {"type": "salamander", "password": obfs_password}
        return outbound, "hysteria2", note

    if scheme == "trojan":
        transport, kind = transport_block(query)
        outbound = {
            "type": "trojan",
            "tag": tag,
            "server": host,
            "server_port": port,
            "password": unquote(url.username or ""),
            "tls": tls_block(query, "", host),
        }
        if transport:
            outbound["transport"] = transport
        return outbound, f"trojan-{kind}", note

    if scheme == "vmess":
        try:
            blob = json.loads(b64_any(link[len("vmess://"):]))
        except Exception:
            return None, "vmess", "vmess payload is not v2rayN base64 JSON"
        net = str(blob.get("net", "tcp"))
        outbound = {
            "type": "vmess",
            "tag": tag,
            "server": str(blob.get("add", "")),
            "server_port": int(blob.get("port", 0) or 0),
            "uuid": str(blob.get("id", "")),
            "security": str(blob.get("scy") or "auto"),
            "alter_id": int(blob.get("aid", 0) or 0),
        }
        if str(blob.get("tls", "")) in ("tls", "reality"):
            tls = {"enabled": True, "server_name": str(blob.get("sni") or blob.get("host") or blob.get("add"))}
            if blob.get("alpn"):
                tls["alpn"] = [p for p in str(blob["alpn"]).split(",") if p]
            outbound["tls"] = tls
        if net == "ws":
            block = {"type": "ws", "path": str(blob.get("path") or "/")}
            if blob.get("host"):
                block["headers"] = {"Host": str(blob["host"])}
            outbound["transport"] = block
        elif net == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": str(blob.get("path") or "")}
        return outbound, f"vmess-{net}", note

    if scheme == "ss":
        # Two encodings in the wild: base64("method:password")@host:port and
        userinfo = url.username or ""
        method = password = ""
        if userinfo and not url.password:
            try:
                decoded = b64_any(unquote(userinfo))
                method, _, password = decoded.partition(":")
            except ValueError:
                method, password = "", ""
        if not method:
            method = unquote(userinfo)
            password = unquote(url.password or "")
        if not method or not password:
            return None, "shadowsocks", "unrecognised shadowsocks userinfo encoding"
        return (
            {
                "type": "shadowsocks",
                "tag": tag,
                "server": host,
                "server_port": port,
                "method": method,
                "password": password,
            },
            "shadowsocks",
            note,
        )

    if scheme in ("naive+https", "naive+quic"):
        return (
            {
                "type": "http",
                "tag": tag,
                "server": host,
                "server_port": port,
                "username": unquote(url.username or ""),
                "password": unquote(url.password or ""),
                "tls": {"enabled": True, "server_name": qs_get(query, "sni") or host},
            },
            "naive",
            "sing-box has no naive outbound; approximated with http-over-TLS",
        )

    if scheme == "wireguard":
        return None, "wireguard", "sing-box 1.12+ moves wireguard to `endpoints`; not driven by this harness"
    if scheme == "tg":
        return None, "tg", "support link, not a proxy node"
    return None, scheme, "no sing-box translation"


def resolve_one(host):
    """One A/AAAA record for the node host, chosen once on the host machine.

    Why this exists: sing-box on Android has no `/etc/resolv.conf` and its
    default `local` DNS server falls back to `[::1]:53`, which nothing is
    listening on - so the sing-box arm could not resolve the *node's own*
    hostname and failed every request in 2ms while the FoxCore arm, which
    resolves through bionic, connected fine. That is not a core difference,
    it is a CLI-on-Android packaging difference, and letting it stand would
    have handed FoxCore a win it did not earn.

    Giving sing-box a DNS block instead would put a resolver in one arm and
    not the other. Pinning both arms to one address removes name resolution
    from the measurement entirely and proves both arms dialled the same host.
    SNI and the REALITY server_name are untouched, so the handshake is
    unchanged.
    """
    import socket
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0]
    return None


def inside_git_worktree(path):
    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--sub-file", default="-", help="subscription body path, or - for stdin")
    parser.add_argument("--out-dir", required=True, help="scratch dir for generated configs (must be outside any git work tree)")
    parser.add_argument("--socks-port", type=int, default=1081, help="sing-box arm SOCKS listen port")
    parser.add_argument("--log-path", default="/data/local/tmp/ab/ab-sb.log")
    parser.add_argument(
        "--pin-server-ip", action="store_true",
        help="resolve each node host once here and pin BOTH arms to that address",
    )
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    if inside_git_worktree(out_dir):
        die(f"refusing to write node configs inside a git work tree: {out_dir}")
    os.chmod(out_dir, 0o700)

    body = load_body(args.sub_file)
    seen = {}
    manifest = []

    for index, link in enumerate(links(body)):
        outbound, shape, note = translate(link, "proxy")
        seen[shape] = seen.get(shape, 0) + 1
        node_id = f"{shape}-{seen[shape]}"
        scheme = urlparse(link).scheme.lower()
        record = {
            "node_id": node_id,
            "line": index + 1,
            "scheme": scheme,
            "shape": shape,
            "foxcore_selector": {
                "vless": "vless", "vmess": "vmess", "hysteria2": "hysteria2",
                "hy2": "hysteria2", "trojan": "trojan", "ss": "shadowsocks",
                "naive+https": "naive", "naive+quic": "naive", "anytls": "anytls",
            }.get(scheme),
            "singbox_translatable": outbound is not None,
            "note": note,
        }

        emit_link = link
        if args.pin_server_ip and outbound is not None and scheme == "vmess":
            try:
                blob = json.loads(b64_any(link[len("vmess://"):]))
                host = str(blob.get("add", ""))
                address = resolve_one(host) if host and not host.replace(".", "").isdigit() else None
                if address:
                    blob["server_ip"] = address
                    outbound["server"] = address
                    emit_link = "vmess://" + base64.b64encode(
                        json.dumps(blob).encode()).decode()
                    record["server_pinned"] = True
                else:
                    record["note"] = (record["note"] + "; " if record["note"] else "") + \
                        "vmess host did not resolve; cell must stay empty rather than " \
                        "count sing-box's DNS failure as a FoxCore win"
            except Exception:
                record["note"] = (record["note"] + "; " if record["note"] else "") + \
                    "vmess blob could not be re-encoded for pinning"
        elif args.pin_server_ip and outbound is not None:
            host = urlparse(link).hostname or ""
            if host and not host.replace(".", "").isdigit():
                address = resolve_one(host)
                if address:
                    outbound["server"] = address
                    joiner = "&" if urlparse(link).query else "?"
                    fragment = ""
                    if "#" in emit_link:
                        emit_link, _, fragment = emit_link.partition("#")
                        fragment = "#" + fragment
                    emit_link = f"{emit_link}{joiner}server_ip={address}{fragment}"
                    record["server_pinned"] = True
                else:
                    record["note"] = (record["note"] + "; " if record["note"] else "") + \
                        "host did not resolve here; both arms left on the hostname"

        link_path = os.path.join(out_dir, f"{node_id}.link")
        with open(os.open(link_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
            handle.write(emit_link + "\n")

        if outbound is not None:
            config = {
                "log": {"level": "error", "timestamp": True, "output": args.log_path},
                "inbounds": [{
                    "type": "socks",
                    "tag": "in",
                    "listen": "127.0.0.1",
                    "listen_port": args.socks_port,
                }],
                "outbounds": [outbound],
                "route": {"final": "proxy"},
            }
            config_path = os.path.join(out_dir, f"{node_id}.sb.json")
            with open(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
                json.dump(config, handle, indent=2)
        manifest.append(record)

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
        json.dump(manifest, handle, indent=2)

    for record in manifest:
        print(json.dumps(record))
    print(
        f"# nodes={len(manifest)} translatable={sum(1 for r in manifest if r['singbox_translatable'])}"
        f" out_dir={out_dir}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
