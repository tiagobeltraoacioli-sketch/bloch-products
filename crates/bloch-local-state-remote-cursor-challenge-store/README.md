# Remote cursor CAS challenge store

Unix reference primitive for issuing and durably consuming single-use CSPRNG
challenges used by the remote-cursor CAS caller-authorization flow.

The store is explicitly provisioned. Its directory must be owner-controlled
`0700`; its lock and state files must be owner-controlled regular `0600` files
with one link. Opens use `O_NOFOLLOW`, advisory lock acquisition is bounded,
and mutations use `fsync(temp) -> rename -> fsync(directory)` with canonical,
bounded state. Outstanding challenges and consumed history are bounded.

Each challenge is permanently bound to the caller policy pin, remote cursor
policy pin, and state identity. Consumption takes ownership of the exact issued
nonce's opaque, non-cloneable, non-serializable in-process lease. The consumed
capability is non-cloneable too. Freshness is checked exclusively
against `Instant`, including immediately before durable replacement; no
operator-provided wall clock participates. A process restart therefore makes
all prior leases unusable. Operators must call the explicit invalidation API
before issuing replacements after restart. A failed consumption attempt also
drops its linear lease, so the retained outstanding entry must be explicitly
invalidated instead of retried.

Consumption is committed durably before the consumed capability is returned.
An I/O error after `rename` is necessarily ambiguous: the challenge may already
be consumed. Keep the caller offline, reload/reconcile the store, and never
retry authorization with that nonce. Issuance has the analogous conservative
failure mode: an error can leave a stranded outstanding challenge, which must
be invalidated rather than guessed usable.

This crate does not implement networking, authentication, signatures, private
key custody, trusted wall time, distributed consensus, replication, or HA.
`flock` and atomic rename are single-host coordination primitives. Filesystem,
volume, mount, VM, or host snapshot rollback can resurrect consumed state; a
production deployment needs an independent anti-rollback root and must not
claim replay safety across snapshot restoration from this crate alone.
