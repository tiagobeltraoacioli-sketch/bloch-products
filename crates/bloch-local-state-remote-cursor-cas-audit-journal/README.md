# CAS audit journal

This crate keeps a bounded, canonical, hash-chained audit journal for verified
remote-cursor CAS sessions. Its append API accepts the verifier-created opaque
`VerifiedRemoteCursorCasSession` capability, never receipt or transport JSON
supplied by an operator. That upstream capability already binds the inner CAS
request and signed receipt to the distinct wire request/response authenticated
by the transport session; this crate does not confuse those digest namespaces.

The journal policy pins the state identity, remote-cursor policy, current CAS
policy (the remote-cursor policy also governs CAS receipts today), CAS
signature domain, and authenticated-transport policy. An append checks the
session's CAS request/receipt pins and its authenticated transport provenance.

Persistence is a crash-safe logical append: the complete bounded state is
rewritten to a create-exclusive temporary file, fsynced, renamed, the directory
is fsynced, and the published file is read back. Unix paths are owner-only and
opened with `O_NOFOLLOW`; regular files must have one link and writers use a
bounded `flock`. Stale temporary files are removed while holding that lock.

This is one mutable host copy. Hash chaining detects corruption and reordering
inside the copy that is read, but does **not** provide WORM retention, snapshot
rollback resistance, consensus, replication, fencing, host authenticity, or
proof that transport attestors are independent. Those remain operational
requirements outside this crate.
