#!/usr/bin/env python3
"""Check `fingerprints/*.json` against uTLS' parrot tables.

The ClientHello this core sends is a parrot of a browser, and for most of the
profiles the reference for what that browser sends is
`refraction-networking/utls` -- not because uTLS is a better description of the
browser than a capture would be, but because uTLS is the code Xray and sing-box
actually run. Diverging from uTLS means diverging from the deployed population,
which is the thing a parrot cannot afford.

So the chain is:

    u_parrots.go  ->  fingerprints/<name>.json  ->  hello_profile.rs

This script checks the first arrow. The second is checked by
`proto-reality`'s `fingerprint_vector.rs`, which runs under `cargo test`.

Two profiles have no first arrow at all. `chrome_151` and `firefox_153` are
transcribed from a first-party capture because uTLS has no table for either
build, and a parrot faithful to a stale uTLS table is a client that matches no
shipping browser -- which is louder than an unknown client, not quieter. Those
two are listed in CAPTURE_DERIVED and are **not** silently skipped:

* the script re-reads uTLS and refuses to pass if uTLS has meanwhile grown a
  table for the build, because at that moment the exemption stops being true
  and the profile should be re-derived from uTLS or the divergence justified;
* it refuses to pass if the `Hello*_Auto` alias has moved past the version the
  exemption was written against, for the same reason;
* it refuses to pass if the committed file claims uTLS provenance while
  claiming the exemption, so a file cannot be exempt and uTLS-derived at once;
* and it says out loud, on every run, which profiles were checked against uTLS
  and which were not.

Run it deliberately -- when a browser moves, or before a release -- never from
the build. The committed JSON is the source of truth for the build precisely so
that a network fetch cannot change what the binary sends, and so that a change
to the parrot arrives as a reviewable diff rather than as a silent update.

Usage:

    scripts/fingerprint-from-utls.py                 # fetch u_parrots.go
    scripts/fingerprint-from-utls.py --source PATH   # use a local copy
    scripts/fingerprint-from-utls.py --json          # emit the parsed spec

Exit codes: 0 agreement, 1 divergence, 2 could not parse or fetch.

No credentials, no configuration and no network destination other than the
public uTLS source are involved.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.request

UTLS_BASE = "https://raw.githubusercontent.com/refraction-networking/utls/master"
UTLS_RAW = f"{UTLS_BASE}/u_parrots.go"
# Files whose `const` blocks name the code points the parrot tables use. Read
# rather than transcribed: a hand-kept copy of 60 cipher ids is a copy that
# drifts, and getting one wrong is a silently wrong hello.
UTLS_CONSTANT_FILES = ("u_common.go", "common.go", "cipher_suites.go")

REPO = pathlib.Path(__file__).resolve().parent.parent

# uTLS spells code points as Go constants. Only the ones the Chrome specs use
# are listed; an unknown name is an error rather than a guess, because a silent
# fallback here would be a silently wrong parrot.
CIPHERS = {
    "GREASE_PLACEHOLDER": "GREASE",
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xC030,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": 0xCCA9,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": 0xCCA8,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xC013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xC014,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
    # Older suites the non-Chrome parrots carry. Every value verified against
    # uTLS `cipher_suites.go`; none of them is implemented here, so all of them
    # are decorative and a server selecting one is refused.
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xC009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xC00A,
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": 0xC012,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xC023,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 0xC027,
    # uTLS' `DISABLED_`/`OLD_` prefixes mean "uTLS will not negotiate this",
    # not "absent from the hello". They are on the wire and so they are here.
    "DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xC024,
    "DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 0xC028,
    "DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
    "OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCC13,
    "OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xCC14,
}

CURVES = {
    "GREASE_PLACEHOLDER": "GREASE",
    "X25519MLKEM768": 0x11EC,
    "X25519Kyber768Draft00": 0x6399,
    "X25519": 0x001D,
    "CurveP256": 0x0017,
    "CurveP384": 0x0018,
    "CurveP521": 0x0019,
    "FakeCurveFFDHE2048": 0x0100,
    "FakeCurveFFDHE3072": 0x0101,
}

CERT_COMPRESSION = {
    "CertCompressionZlib": 0x0001,
    "CertCompressionBrotli": 0x0002,
    "CertCompressionZstd": 0x0003,
}

SIGALGS = {
    "ECDSAWithP256AndSHA256": 0x0403,
    "PSSWithSHA256": 0x0804,
    "PKCS1WithSHA256": 0x0401,
    "ECDSAWithP384AndSHA384": 0x0503,
    "PSSWithSHA384": 0x0805,
    "PKCS1WithSHA384": 0x0501,
    "PSSWithSHA512": 0x0806,
    "PKCS1WithSHA512": 0x0601,
    "ECDSAWithSHA1": 0x0203,
    "PKCS1WithSHA1": 0x0201,
    "PSSWithSHA512": 0x0806,
}

# uTLS extension struct name -> the code point it writes.
EXTENSIONS = {
    "UtlsGREASEExtension": "GREASE",
    "SNIExtension": 0x0000,
    "StatusRequestExtension": 0x0005,
    "SupportedCurvesExtension": 0x000A,
    "SupportedPointsExtension": 0x000B,
    "SignatureAlgorithmsExtension": 0x000D,
    "ALPNExtension": 0x0010,
    "SCTExtension": 0x0012,
    "UtlsPaddingExtension": 0x0015,
    # uTLS' `Fake*` prefix means "uTLS does not implement the feature", not
    # "the extension is absent". Both are on the wire in a Firefox hello.
    # Verified against uTLS: `fakeRecordSizeLimit = 0x001c` and
    # `fakeExtensionDelegatedCredentials = 34` in `u_common.go`.
    "FakeRecordSizeLimitExtension": 0x001C,
    "FakeDelegatedCredentialsExtension": 0x0022,
    "ExtendedMasterSecretExtension": 0x0017,
    "UtlsCompressCertExtension": 0x001B,
    "SessionTicketExtension": 0x0023,
    "SupportedVersionsExtension": 0x002B,
    "PSKKeyExchangeModesExtension": 0x002D,
    "KeyShareExtension": 0x0033,
    "ApplicationSettingsExtension": 0x4469,
    "ApplicationSettingsExtensionNew": 0x44CD,
    "GREASEEncryptedClientHelloExtension": 0xFE0D,
    "BoringGREASEECH": 0xFE0D,
    "RenegotiationInfoExtension": 0xFF01,
}

# The eight named uTLS parrots this core can carry, and the uTLS symbol each
# resolves to. sing-box maps its `fp=` names to `Hello*_Auto` aliases; those
# aliases are resolved here to the concrete symbol so the table cannot drift
# when upstream repoints an alias.
#
#   chrome  -> HelloChrome_Auto  = HelloChrome_133
#   firefox -> HelloFirefox_Auto = HelloFirefox_148
#   edge    -> HelloEdge_Auto    = HelloEdge_85     (not _106; uTLS says _106 is broken)
#   safari  -> HelloSafari_Auto  = HelloSafari_26_3
#   ios     -> HelloIOS_Auto     = HelloIOS_14
#   qq      -> HelloQQ_Auto      = HelloQQ_11_1
#
# `360` and `android` are absent on purpose: see REFUSED below.
PROFILES = {
    "chrome_131": "HelloChrome_131",
    "chrome_133": "HelloChrome_133",
    "edge_85": "HelloEdge_85",
    "ios_14": "HelloIOS_14",
    "qq_11_1": "HelloQQ_11_1",
    "safari_26_3": "HelloSafari_26_3",
    "firefox_148": "HelloFirefox_148",
}

# Profiles uTLS carries no table for, transcribed from a first-party capture
# instead. Each entry records what the exemption is claiming, and `main` checks
# every part of that claim against the uTLS source on each run -- an exemption
# nobody re-checks is how a table quietly stops being justified.
#
#   absent_symbols: uTLS symbols whose *appearance* ends the exemption.
#   alias:          the uTLS alias this build's name has overtaken, and the
#                   symbol it resolved to when the exemption was written.
CAPTURE_DERIVED = {
    "chrome_151": {
        "browser": "Chromium 151 (captured from Brave 151.1.93.136)",
        "absent_symbols": ("HelloChrome_151",),
        "alias": ("HelloChrome_Auto", "HelloChrome_133"),
        "why": "Chromium 151 offers ML-DSA-44/65/87 (0x0904/0905/0906) ahead of "
               "its other signature algorithms; no uTLS table carries them, so "
               "HelloChrome_133 no longer reproduces a shipping Chrome.",
    },
    "firefox_153": {
        "browser": "Firefox 153.0.4",
        "absent_symbols": ("HelloFirefox_153",),
        "alias": ("HelloFirefox_Auto", "HelloFirefox_148"),
        "why": "Firefox 153 dropped cipher 0xc009 and added session_ticket and "
               "psk_key_exchange_modes; HelloFirefox_148 differs from it in "
               "JA4_a, the unhashed part a cheap detector reads first.",
    },
}

# Names sing-box exposes that cannot be a REALITY hello here, with the reason.
# Checked by `the_refused_parrots_really_cannot_carry_reality` in
# `proto-reality`, which re-reads these from the uTLS source.
REFUSED = {
    "360": (
        "Hello360_7_5",
        "TLS 1.2 only: no supported_versions and no key_share extension, so "
        "there is no x25519 share for a REALITY server to derive against",
    ),
    "android": (
        "HelloAndroid_11_OkHttp",
        "TLS 1.2 only: no supported_versions and no key_share extension, so "
        "there is no x25519 share for a REALITY server to derive against",
    ),
}


def fetch(source: str | None) -> str:
    if source:
        return pathlib.Path(source).read_text(encoding="utf-8")
    with urllib.request.urlopen(UTLS_RAW, timeout=60) as response:
        return response.read().decode("utf-8")


def fetch_companion(source: str | None, name: str) -> str:
    """One of the files next to `u_parrots.go`, or "" if it cannot be read."""
    try:
        if source:
            return (pathlib.Path(source).parent / name).read_text(encoding="utf-8")
        with urllib.request.urlopen(f"{UTLS_BASE}/{name}", timeout=60) as response:
            return response.read().decode("utf-8")
    except OSError:
        return ""


def check_capture_derived(text: str, common: str, failures: list) -> list[str]:
    """Re-check every claim the capture-derived exemptions make.

    Returns the lines to print. A claim that has stopped being true is a
    failure, not a note: the whole point of writing the exemption down is that
    it gets re-read against upstream rather than assumed forever.
    """
    lines = []
    for name, claim in CAPTURE_DERIVED.items():
        path = REPO / "fingerprints" / f"{name}.json"
        if not path.exists():
            failures.append(f"{name}: CAPTURE_DERIVED names a file that does not exist")
            continue
        committed = json.loads(path.read_text())
        method = committed.get("provenance", {}).get("method", "")
        if "capture" not in method:
            failures.append(
                f"{name}: exempt from the uTLS check, but its provenance says "
                f"{method!r}. A profile cannot be both uTLS-derived and exempt "
                "from the uTLS check -- fix whichever one is wrong."
            )

        for symbol in claim["absent_symbols"]:
            if re.search(rf"\b{re.escape(symbol)}\b", text) or re.search(
                rf"\b{re.escape(symbol)}\b", common
            ):
                failures.append(
                    f"{name}: uTLS now defines {symbol}. The exemption was "
                    "granted because upstream had no table for this build. It "
                    "does now -- re-derive the profile from uTLS, or record why "
                    "the capture is still the better source."
                )

        alias, expected = claim["alias"]
        match = re.search(rf"^\s*{re.escape(alias)}\s*=\s*(\w+)", common, re.M)
        if not match:
            failures.append(
                f"{name}: cannot find {alias} in uTLS; the exemption cannot be "
                "re-checked, so it is not being trusted"
            )
        elif match.group(1) != expected:
            failures.append(
                f"{name}: {alias} is now {match.group(1)}, not {expected}. "
                "Upstream moved its idea of the current browser; check whether "
                "this profile should follow it."
            )
        else:
            lines.append(
                f"  {name:<12} {claim['browser']}\n"
                f"               uTLS has no table ({alias} is still {expected})\n"
                f"               {claim['why']}"
            )
    return lines


def fetch_constants(source: str | None) -> dict[str, int]:
    """`NAME uint16 = 0x1234` / `NAME = uint16(0x1234)` / `NAME CurveID = 23`.

    Every code point this script resolves comes from here when uTLS declares
    it, so the hand-written tables below act as a cross-check rather than as
    the source of truth.
    """
    texts = []
    for name in UTLS_CONSTANT_FILES:
        try:
            if source:
                texts.append((pathlib.Path(source).parent / name).read_text(encoding="utf-8"))
            else:
                with urllib.request.urlopen(f"{UTLS_BASE}/{name}", timeout=60) as response:
                    texts.append(response.read().decode("utf-8"))
        except OSError:
            continue

    found: dict[str, int] = {}
    patterns = (
        re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(?:uint16|CurveID|SignatureScheme|CertCompressionAlgo)\s*=\s*(0x[0-9a-fA-F]+|\d+)", re.M),
        re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*uint16\((0x[0-9a-fA-F]+|\d+)\)", re.M),
        re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)\s*$", re.M),
    )
    for text in texts:
        for pattern in patterns:
            for name, value in pattern.findall(text):
                found.setdefault(name, int(value, 0))
    return found


UTLS_CONSTANTS: dict[str, int] = {}


def extract_case(text: str, symbol: str) -> str:
    """The body of `case <symbol>:` up to the next `case ` at the same level."""
    start = re.search(rf"^\tcase {re.escape(symbol)}:$", text, re.MULTILINE)
    if not start:
        raise SystemExit(f"uTLS source has no `case {symbol}:` -- has it been renamed?")
    rest = text[start.end():]
    end = re.search(r"^\tcase ", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest



def block(body: str, marker: str) -> str | None:
    """The brace-balanced text of the first `marker{...}` in `body`.

    uTLS writes the same extension four different ways -- positional or named
    field, one line or fifteen, sometimes wrapped in `append(...)`. A regex
    that terminates on a closing brace picks the wrong one as soon as the
    literal nests, and it does so *silently*, which is the failure mode this
    whole script exists to prevent. Counting braces cannot.
    """
    start = body.find(marker)
    if start < 0:
        return None
    opening = body.find("{", start + len(marker) - 1)
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(body)):
        if body[index] == "{":
            depth += 1
        elif body[index] == "}":
            depth -= 1
            if depth == 0:
                return body[opening + 1 : index]
    return None


def tokens(text: str) -> list[str]:
    """Identifiers and bare hex literals, in source order.

    `CurveID(X)` and `SignatureScheme(X)` wrappers are unwrapped; Go type
    names that are never code points are dropped.
    """
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"\b(?:CurveID|SignatureScheme|CertCompressionAlgo|uint16|uint8)\s*\(", "(", text)
    out = []
    for token in re.findall(r"0x[0-9a-fA-F]{4}\b|[A-Za-z_][A-Za-z0-9_]*", text):
        if token in {"Group", "Data", "byte", "KeyShare", "append", "KeyShares",
                     "CurveID", "SignatureScheme", "CertCompressionAlgo",
                     "uint16", "uint8", "GetPaddingLen", "BoringPaddingStyle",
                     "Curves", "SupportedPoints", "Modes", "AlpnProtocols",
                     "SupportedSignatureAlgorithms", "Versions", "Algorithms",
                     "ReuseHybridAndClassicalKeyShares", "string", "Renegotiation",
                     "Limit", "AlgorithmsSignature", "SupportedProtocols"}:
            continue
        out.append(token)
    return out

def parse_spec(body: str) -> dict:
    spec: dict = {}

    cipher_block = block(body, "CipherSuites:")
    if cipher_block is None:
        raise SystemExit("could not find CipherSuites in the uTLS case body")
    spec["cipher_suites"] = [
        resolve(CIPHERS, name, "cipher suite") for name in tokens(cipher_block)
    ]

    # Extension order: the struct name of each entry, in source order. Taken
    # from the `Extensions:` block only, so unrelated identifiers elsewhere in
    # the case body cannot be mistaken for extensions.
    ext_block = re.search(r"Extensions: (?:ShuffleChromeTLSExtensions\()?\[\]TLSExtension\{(.*)", body, re.S)
    if not ext_block:
        raise SystemExit("could not find the Extensions block in the uTLS case body")
    spec["permute_extensions"] = "ShuffleChromeTLSExtensions(" in body
    names = re.findall(r"^\t{4}(?:&)?([A-Za-z0-9_]+)[\{\(]", ext_block.group(1), re.M)
    spec["extensions"] = [resolve(EXTENSIONS, name, "extension") for name in names]

    curve_block = block(body, "SupportedCurvesExtension{")
    spec["supported_groups"] = (
        [resolve(CURVES, name, "curve") for name in tokens(curve_block)]
        if curve_block
        else []
    )

    share_block = block(body, "KeyShareExtension{")
    spec["key_shares"] = (
        [resolve(CURVES, name, "curve") for name in tokens(share_block)]
        if share_block
        else []
    )

    sig_block = block(body, "SignatureAlgorithmsExtension{")
    spec["signature_algorithms"] = (
        [resolve(SIGALGS, name, "signature algorithm") for name in tokens(sig_block)]
        if sig_block
        else []
    )

    version_names = {
        "GREASE_PLACEHOLDER": "GREASE",
        "VersionTLS13": 0x0304,
        "VersionTLS12": 0x0303,
        "VersionTLS11": 0x0302,
        "VersionTLS10": 0x0301,
    }
    version_block = block(body, "SupportedVersionsExtension{")
    spec["supported_versions"] = (
        [resolve(version_names, name, "version") for name in tokens(version_block)]
        if version_block
        else []
    )

    alpn_block = block(body, "ALPNExtension{")
    spec["alpn"] = re.findall(r'"([^"]+)"', alpn_block) if alpn_block else []

    compress_block = block(body, "UtlsCompressCertExtension{")
    spec["cert_compression"] = (
        [resolve(CERT_COMPRESSION, name, "compression algorithm") for name in tokens(compress_block)]
        if compress_block
        else []
    )

    return spec


def resolve(mapping: dict, name: str, kind: str):
    # uTLS sometimes writes a bare hex literal where it has no Go constant for
    # a suite. That *is* the code point, so it needs no lookup -- and reading
    # it is not the same as guessing one.
    if re.fullmatch(r"0x[0-9a-fA-F]{4}", name):
        return int(name, 16)
    if name == "GREASE_PLACEHOLDER":
        return "GREASE"

    expected = mapping.get(name)
    declared = UTLS_CONSTANTS.get(name)
    if expected is not None and declared is not None and expected != declared:
        raise SystemExit(
            f"uTLS declares {name} = 0x{declared:04x}, but this script's table "
            f"says 0x{expected:04x}. Upstream moved a code point; do not "
            "reconcile it by editing the table without checking why."
        )
    value = expected if expected is not None else declared
    if value is None:
        raise SystemExit(
            f"uTLS names a {kind} this script cannot resolve: {name}. "
            "It is not in this script's table and uTLS declares no constant "
            "for it -- do not guess a code point."
        )
    return value


def as_points(entries: list) -> list:
    """Committed-JSON entries -> the same shape parse_spec produces."""
    out = []
    for entry in entries:
        value = entry["value"] if isinstance(entry, dict) else entry[0]
        out.append("GREASE" if value == "GREASE" else int(value, 16))
    return out


def compare(name: str, symbol: str, spec: dict, failures: list) -> None:
    committed = json.loads((REPO / "fingerprints" / f"{name}.json").read_text())["fingerprint"]

    def check(what, ours, theirs):
        if ours != theirs:
            failures.append(
                f"{name}: {what}\n"
                f"    committed: {fmt(ours)}\n"
                f"    {symbol}: {fmt(theirs)}"
            )

    check("cipher_suites", as_points(committed["cipher_suites"]), spec["cipher_suites"])
    check("supported_groups", as_points(committed["supported_groups"]), spec["supported_groups"])
    check("key_shares", as_points(committed["key_shares"]), spec["key_shares"])
    check(
        "supported_versions",
        as_points(committed["supported_versions"]),
        spec["supported_versions"],
    )
    check(
        "signature_algorithms",
        as_points(committed["signature_algorithms"]),
        spec["signature_algorithms"],
    )
    check("alpn", committed["alpn"], spec["alpn"])

    ours = [
        "GREASE" if entry["type"] == "GREASE" else int(entry["type"], 16)
        for entry in committed["extension_order"]
    ]
    theirs = list(spec["extensions"])
    # uTLS dropped UtlsPaddingExtension from the Chrome 131/133 tables; this
    # core keeps a padding slot, but BoringSSL's rule emits nothing for a hello
    # carrying an ML-KEM key share, so the bytes agree either way. Tolerate the
    # slot only in that direction, and only in last position.
    if ours and ours[-1] == 0x0015 and (not theirs or theirs[-1] != 0x0015):
        ours = ours[:-1]
    check("extension_order", ours, theirs)

    if committed["permute_extensions"] != spec["permute_extensions"]:
        failures.append(f"{name}: permute_extensions differs")


def fmt(values: list) -> str:
    return "[" + ", ".join(v if isinstance(v, str) else f"0x{v:04x}" for v in values) + "]"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="local u_parrots.go instead of fetching")
    parser.add_argument("--json", action="store_true", help="print the parsed uTLS specs")
    args = parser.parse_args()

    try:
        text = fetch(args.source)
    except OSError as error:
        print(f"could not read uTLS source: {error}", file=sys.stderr)
        return 2

    global UTLS_CONSTANTS
    UTLS_CONSTANTS = fetch_constants(args.source)

    specs = {name: parse_spec(extract_case(text, symbol)) for name, symbol in PROFILES.items()}

    if args.json:
        print(json.dumps(specs, indent=2, default=str))
        return 0

    failures: list[str] = []
    for name, symbol in PROFILES.items():
        compare(name, symbol, specs[name], failures)

    exempt = check_capture_derived(text, fetch_companion(args.source, "u_common.go"), failures)

    # Every committed vector is either checked against uTLS or listed as
    # capture-derived. A file that is in neither group has no reference at all,
    # which is the state this script exists to make impossible.
    committed_files = {path.stem for path in (REPO / "fingerprints").glob("*.json")}
    unaccounted = committed_files - set(PROFILES) - set(CAPTURE_DERIVED)
    for name in sorted(unaccounted):
        failures.append(
            f"{name}: committed under fingerprints/ but named neither in "
            "PROFILES nor in CAPTURE_DERIVED, so nothing checks it against "
            "anything. Add it to one of them."
        )

    if failures:
        print("fingerprints/ disagrees with uTLS:\n")
        for failure in failures:
            print(f"  {failure}\n")
        print(
            "Decide deliberately: either uTLS tracked a browser change and the\n"
            "committed table should follow, or the divergence is intentional and\n"
            "belongs in the table's notes. Re-hash with the fingerprint digest\n"
            "convention after any edit; `cargo test -p proto-reality` enforces it."
        )
        return 1

    print(f"fingerprints/ agrees with uTLS for: {', '.join(PROFILES)}")
    if exempt:
        print("\nnot checked against uTLS -- transcribed from a first-party capture:")
        for line in exempt:
            print(line)
        print(
            "\nEach exemption above was re-checked against the uTLS source on this\n"
            "run: the symbol is still absent and the _Auto alias has not moved.\n"
            "These profiles are held instead by their committed vector, by\n"
            "`fingerprint_vector.rs`, and by the measured browser JA4 pinned in\n"
            "`the_captured_profiles_reproduce_the_browsers_measured_ja4`."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
