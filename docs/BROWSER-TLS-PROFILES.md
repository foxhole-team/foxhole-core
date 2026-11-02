# Browser TLS profiles

Core source/dev1.0.2 adds `chrome_156` for REALITY and ordinary TCP TLS.
It is derived from Chromium156.0.8078.47 source, not a live browser capture.
The profile supplies no Trust Anchor IDs. It does not claim default-platform
Chrome fidelity, trusted-intermediate elision or Trust Anchor retry support.

The new behavior is a fresh per-connection GREASE signature scheme before the
existing ML-DSA/ECDSA/RSA list. Cipher order, hybrid-first groups, TLS version
offer, session-ID length, null compression, ALPN policy, ALPS and record
versions retain the verified shape. Certificate verification and insecure
consent defaults are unchanged. Ordinary TLS retains its Brotli decoder;
REALITY retains its documented TLS1.3-only/full-handshake limitations.

Bare `chrome`, absent REALITY fingerprint and the current API default now
select156. Explicit versioned profile names and saved configurations remain
available. Recognized legacy importer fallback still selects151 with
its existing dropped-option reason; unknown values still fail closed.
Ordinary TLS without a fingerprint remains stock TLS. Runtime tables can
supply dynamic signature GREASE only for the compiled156 slot and cannot
supply Trust Anchor IDs for it. Old natives ignore the unknown156 table.

`firefox_153` remains the captured historical profile. Current Firefox159
prefs alone are insufficient evidence for a complete new ClientHello;
no159, Safari, iOS, Edge or QQ profile was fabricated or renamed.

Modern REALITY Chrome151/156 uses the reviewed wire compatibility floor
26.3.27, not the FoxCore product version or a claim to be an Xray binary.
The actual generated hybrid and classical shares, their order and sizes must
match the compiled shape. Runtime tables cannot strip or change that shape
or select a lower auth version. Legacy profiles and randomized hellos retain
their previous1.8.0 auth header. This does not make QQ compatible with servers
that require a hybrid share. A new import using the unversioned REALITY `qq`
preference selects156 and reports the substitution; explicit `qq_11_1`, raw
engine configs and saved profiles keep QQ. No stored configuration is migrated.
An import `random` already resolves to a concrete compiled profile; its wire
compatibility follows that selected profile.

Upstream admission policy and rationale:
- https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770
- https://github.com/XTLS/Xray-core/pull/6181#issuecomment-4567373533
- https://github.com/XTLS/REALITY/blob/83f621788ca8/tls.go#L203-L263

This is a protocol compatibility correction. A particular provider's server
version, policy and successful authentication remain unconfirmed until an
actual native/device proof. HMAC, certificate, Finished, PKI and cancellation
checks are unchanged; no DNS route, timeout or UDP framing is altered.

Primary references:
- https://raw.githubusercontent.com/chromium/chromium/156.0.8078.47/net/base/features.cc
- https://raw.githubusercontent.com/chromium/chromium/156.0.8078.47/net/socket/ssl_client_socket_impl.cc
- https://raw.githubusercontent.com/chromium/chromium/156.0.8078.47/DEPS

New production native/JNI/APK qualification is separate. These source changes
must not be attributed to the retained Core1.0.1 producer. Android consumers,
seeds and actual binary/legal bindings require coordinated updates after the
new producer exists. They are not patched by this Core source change.
