# Remote cursor quorum report store

This crate durably records an opaque `VerifiedReplicaQuorum` on one Unix host.
The store is pinned to an independently reviewed canonical store policy and
accepts only exact replay or a strictly newer cursor generation. It rejects
cross-audience reports, rollback, same-generation replacement, symlinks,
hardlinks, unsafe ownership/modes, and contended locks. Publication uses a
same-directory temporary file, file `fsync`, atomic rename, directory `fsync`,
and canonical readback.

This is an audit/rollback-detection component, **not** a consensus certificate.
It does not establish replica independence, linearizability, quorum honesty, or
remote durability. A privileged operator, VM/disk snapshot restore, storage
rollback, or loss of the single host can restore/delete both state and history.
Production needs independently retained monotonic state or replicated,
fenced storage. This crate performs no networking, signing, key custody,
replication, repair, or leader election.
