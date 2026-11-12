# Atomic policy integration

A kill-switch policy is published before the previous flow cancellation token is revoked. Entering and leaving the kill switch both create a new cancellation epoch. This prevents WireGuard packet decisions observed during the blocked period from remaining cached after traffic is enabled again. Ordinary non-blocking policy reloads keep their existing flow-continuation behavior.

Attributed DNS response-cache entries include client identity, resolver lane and network epoch. All identities share the original total capacity; the implementation does not allocate a separate unbounded cache per application. Legacy cache APIs and fake-IP promises remain supported.

A native policy gate covers only traffic captured by its TUN or proxy integration. It does not capture Android UIDs that the platform excludes from a VPN. Android also shares DNS caches and resolver sockets within network contexts, so native identity scoping alone cannot promise physical DNS for an excluded Direct application.

Clients that require complete OS Direct routing, including system and Private DNS, must retain Android application scopes. Protect scope changes with a separately owned full-capture blackhole tunnel before saving rules or closing the old tunnel. Establish the target scope only after the target routing and storage state are ready. A previous gate FD is not a fallback after a new interface is established; failure handling must preserve or reacquire protection before closing the target. Stop is an explicit cancellation and release boundary.


## L3 observation and the capability discrepancy

An ordinary non-blocking reload retains the cancellation epoch, so an existing
L3 decision normally remains until idle. Kill switch transitions, network epochs
and targeted `nativeRevokeFlows` cancellation cause `PacketSplitter` to reject a
voided decision and obtain a new one on the next packet. Ingress also refuses a
new attribution result whose policy/flow token was revoked while it was pending.
Re-evaluation is distinct from transport closure or TCP reset; without a newly
blocking policy, a revoked flow can be admitted again.

The current `PACKET_TUNNEL_FLOWS` capability constant still advertises
`reevaluated_after_idle` for kill switch/network change and `revocable_by_call=false`.
Its schema vocabulary has only `preserved`, `revoked`, `reevaluated_after_idle`.
That contradicts the observed source path. Integrators must not turn this source
observation into a stronger guarantee for a differently pinned/shipping binary.
A separate coordinated code change must update `capabilities.rs`,
`capabilities.schema.json`, capability tests and any consumers together; choosing
`revoked` would incorrectly promise the stream-proxy TCP-reset behavior.
The current Guard/VPN source search found no Kotlin/Java consumer of these L3
existing-flow fields; external consumers are not exhaustively inventoried.

Emergency DNS-policy refusal when enabling kill switch can publish Block and a
new revision before returning Invalid. See the [ABI recovery contract](abi.md#policy-reload).
