# Atomic policy integration

A kill-switch policy is published before the previous flow cancellation token is revoked. Entering and leaving the kill switch both create a new cancellation epoch. This prevents WireGuard packet decisions observed during the blocked period from remaining cached after traffic is enabled again. Ordinary non-blocking policy reloads keep their existing flow-continuation behavior.

Attributed DNS response-cache entries include client identity, resolver lane and network epoch. All identities share the original total capacity; the implementation does not allocate a separate unbounded cache per application. Legacy cache APIs and fake-IP promises remain supported.

A native policy gate covers only traffic captured by its TUN or proxy integration. It does not capture Android UIDs that the platform excludes from a VPN. Android also shares DNS caches and resolver sockets within network contexts, so native identity scoping alone cannot promise physical DNS for an excluded Direct application.

Clients that require complete OS Direct routing, including system and Private DNS, must retain Android application scopes. Protect scope changes with a separately owned full-capture blackhole tunnel before saving rules or closing the old tunnel. Establish the target scope only after the target routing and storage state are ready. A previous gate FD is not a fallback after a new interface is established; failure handling must preserve or reacquire protection before closing the target. Stop is an explicit cancellation and release boundary.
