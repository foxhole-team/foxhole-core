# Third-party notices

FoxHole Core embeds code from the projects below. Each entry says what was taken,
what was changed, and under which licence it arrived.

## ipstack

- Project: `narrowlink/ipstack`
- Version: `1.0.0` (crates.io `d603c9807158f8054f56c3672c8670096580c3ec1d5bab6f27b2aca89be89117`)
- Copyright (c) Narrowlink
- Licence: Apache-2.0, reproduced in
  `crates/foxcore-tun/src/ipstack/LICENSE-APACHE-ipstack`
- Embedded at: `crates/foxcore-tun/src/ipstack/`

Vendored rather than depended on, because the change FoxHole Core needs is inside the
TCP receive path and is not reachable from outside the crate: upstream
acknowledges received data into an unbounded channel and computes its advertised
window from out-of-order bytes only, so the window cannot close and an
application can push into a flow whose outbound is not taking anything. Measured
on the bench, that is 375 MiB of RSS. The fork gives the window an honest
occupancy count, allows it to reach zero, reopens it with a window update,
drops out-of-window data instead of buffering it, and holds the SYN|ACK until
the core has decided the flow can be carried. `ahash` was replaced with the
standard hasher and the upstream rustdoc examples were dropped. The changes,
measurements and executable regression coverage are documented beside the fork
in `crates/foxcore-tun/src/ipstack/mod.rs` and its tests.

Apache-2.0 permits this redistribution under GPL-3.0-or-later; the notice above
and the licence file are the conditions it attaches.

## uTLS

- Project: `refraction-networking/utls`
- Copyright (c) 2009 The Go Authors; `u_parrots.go` additionally
  "Copyright 2017 Google Inc. All rights reserved."
- Licence: BSD-3-Clause (SPDX `BSD-3-Clause`), confirmed against the repository
  `LICENSE` file, which carries the Go Authors' BSD text verbatim
- Used at: `crates/proto-reality/src/reality/hello_profile.rs` and the seven
  uTLS-derived vectors in `fingerprints/` (`chrome_133`, `chrome_131`,
  `edge_85`, `safari_26_3`, `ios_14`, `qq_11_1`, `firefox_148`). The
  `chrome_151` and `firefox_153` vectors take nothing from uTLS: uTLS has no
  table for either build, and both are transcribed from a first-party capture
  of the shipping browser.

No uTLS code is embedded, linked or executed: FoxHole Core is Rust and does not
build Go. What is taken is the *data* in uTLS' maintained parrot tables — `HelloChrome_133`,
`HelloChrome_131`, `HelloEdge_85`, `HelloSafari_26_3`, `HelloIOS_14` and
`HelloQQ_11_1` in `u_parrots.go` — transcribed into FoxHole Core's own table
types: the cipher list and its order, the extension set and its order, GREASE
placement, supported groups, signature algorithms, key shares, ALPN and the
certificate-compression algorithm. Which uTLS symbol each `fp=` name resolves
to is taken from sing-box's `common/tls/utls_client.go` and uTLS'
`Hello*_Auto` aliases, so the mapping matches the deployed ecosystem rather
than being chosen here.

`scripts/fingerprint-from-utls.py` re-reads those tables from uTLS source and
diffs them against the committed vectors, and it resolves every code point from
uTLS' own `const` blocks rather than from a transcribed copy.

uTLS is the reference rather than a reading of Chrome because it is the code
Xray and sing-box actually run, so matching uTLS is matching the deployed
population rather than one interpretation of a capture. Two rules were taken
from uTLS' own upstream instead, and are cited in place: BoringSSL's
`tls_record_version` for the initial record's `legacy_record_version`, and
BoringSSL's `setup_ech_grease` for the GREASE ECH HPKE suite.

The BSD-3-Clause conditions are satisfied by the copyright notice above; the
third condition (no use of the names of Google Inc. or contributors to endorse
or promote) is observed — this notice is attribution of provenance, not
endorsement.

## Shoes

FoxHole Core contains independently adapted protocol algorithms from the following
MIT-licensed project. The adapted code has been split behind FoxHole Core's own
protocol and transport interfaces; no upstream TUN, routing, configuration, or
application code is embedded.


- Project: `cfal/shoes`
- Reference commit: `386b11532424b8665ee3e46340c6236fb3c47595`
- Copyright (c) 2021-2023 Alex Lau <github@alau.ca>
- Adapted areas: modern VMess AEAD KDF/framing and compatibility test vectors;
  client-only REALITY TLS 1.3 state machine and crypto test vectors. FoxHole Core
  removes upstream server/TUN/routing code, secret-bearing debug traces and the
  crawler fallback; it additionally verifies the TLS server Finished message.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
