# Authoritative remote-cursor CAS admission

This crate is the fail-closed composition boundary in front of an authoritative
remote-cursor compare-and-swap adapter. `execute_authoritative_cas` invokes the
adapter only after it has checked one exact validated request, its exact
threshold-verified caller authorization with a durably consumed one-time
challenge, and a fresh threshold-verified writer lease against explicitly
configured audiences and an opaque external epoch-floor capability.
The replay-protected caller capability is consumed by the function and cannot
be reused for a second callback.

The callback receives a non-constructible `AuthorizedCasOperation`. Its
`operation_sha256` binds the request digest, caller-authorization digest,
writer-fencing certificate, writer identity and epoch, external floor evidence,
state identity, remote-cursor policy, CAS service and CAS policy. The adapter
should persist that digest in its audit record and call `ensure_freshness`
immediately at its atomic commit boundary.

The floor capability proves what one crash-safe single-host store returned
while holding its local lock. It does not prove WORM retention,
snapshot-rollback resistance, or currentness after the lock is released.
Production must close the non-atomic window between loading or advancing the
floor and performing the CAS using independent rollback-resistant storage and a
qualified service composition. This crate performs no I/O or mutation, does
not issue leases or challenges, and does not establish consensus, leader
election, linearizability, durability, authority independence or a production
CAS service. Those remain deployment requirements.
