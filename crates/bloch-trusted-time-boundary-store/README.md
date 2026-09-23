# Bloch trusted-time boundary store

Unix reference implementation for persisting a monotonic
`TrustedTimeBoundary`. Provisioning is explicit and permanently binds the
store to a trusted-time policy pin, state identity, and remote-cursor policy
pin. Reads and updates fail closed when the store, lock, or state disappears.

The store uses owner-only objects, rejects symbolic and hard links, rechecks
the named lock after acquiring a bounded `flock`, and publishes updates with
file `fsync`, atomic rename, directory `fsync`, and readback. Equal boundaries
are idempotent; lower boundaries are refused.

An I/O or verification error after atomic rename may mean the higher floor was
already published. Callers must treat the outcome as possibly advanced, keep
the dependent service offline, and reload the store; they must never retry
using an older floor merely because the update returned an error.

This is a single-host filesystem reference primitive. It does **not** detect
or prevent rollback of a filesystem, volume, mount, VM, or host snapshot.
Production deployments still require an independent anti-rollback root.
