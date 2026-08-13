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
