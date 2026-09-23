# Writer epoch floor store

Unix reference store for the highest locally accepted writer-fencing epoch. It
is explicitly provisioned once, binds the state to the writer-fencing, remote
cursor, CAS and state audiences, and only advances from a fresh
`VerifiedWriterLease` whose epoch is strictly greater than the persisted floor.
Each explicit provisioning generates and persists a random 256-bit `storeId`.
Loaded floor capabilities are non-cloneable and retain the complete audience,
the canonical durable-state SHA-256, and a separate canonical evidence SHA-256
that binds the store ID, audience, epoch, writer and lease certificate.

The implementation uses a same-UID `0700` directory, `0600` regular files,
`O_NOFOLLOW`, inode/link checks, a bounded `flock`, bounded canonical JSON,
temporary-file `fsync`, atomic rename, directory `fsync`, and readback.
Ordinary load and advance operations never create or repair missing objects.

This is a **single-host filesystem primitive**. It is not WORM storage, a
linearizable lease issuer, consensus, leader election, or proof against volume,
filesystem, VM, mount, backup, or host snapshot rollback. Production must keep
an independently controlled anti-rollback floor and enforce leases at the
authoritative CAS/write boundary. A loaded capability proves what was read
under the local lock; it does not prove that the store remained current after
that lock was released.
