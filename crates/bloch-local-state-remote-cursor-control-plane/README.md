# Bloch remote cursor control-plane core

Unix-only reference storage for serialized application of validated remote
cursor CAS requests by cooperating processes on one qualified local
filesystem. A bounded advisory `flock` serializes operations.
State and request-ID decisions are persisted together using owner-only files,
`O_NOFOLLOW`, single-link checks, temporary-file `fsync`, atomic rename,
directory `fsync` and readback.

Provisioning is an explicit, one-time operation through
`provision_control_plane_store` and binds the state identity, remote policy pin
and signature domain to that store. Normal `apply_request` and read paths never
create a directory, lock, or state file. A typo or deletion during ordinary
operation thus fails closed and cannot silently become a new empty epoch
eligible for another bootstrap. Retrying provisioning over any existing path
also fails; partial provisioning requires deliberate operator recovery.

The core supports exact compare-and-swap and explicit create-once bootstrap.
Every request ID is durable: replaying the same ID and request digest returns
the recorded decision without another mutation, while reusing an ID for a
different request fails closed. CAS mismatch and already-initialized bootstrap
produce stable refusal decisions and do not change the current cursor.

The request history is deliberately bounded. Once full, new IDs fail rather
than evicting old idempotency records. Operators must provision a new qualified
epoch/store rather than silently losing replay protection.

This crate performs no networking, workload authentication, signing, private
key handling, replication, quorum consensus or high availability. Its returned
decision is unsigned material for independent authorities; it never fabricates
a signed receipt and does not prove authority independence. The single-host
filesystem implementation is a reference core, not a claim of remote durable
monotonicity under host rollback, mount substitution, shadow directories,
snapshot restoration or storage loss. Production operations require an
independently retained store epoch/filesystem identity and rollback detection.
