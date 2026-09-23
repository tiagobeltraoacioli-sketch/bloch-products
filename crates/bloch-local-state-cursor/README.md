# Bloch local state cursor

Fail-closed, monotonic admission for fully verified local-state checkpoints.
The cursor accepts generation zero once, an exact replay of the current
checkpoint, or the immediately following generation whose state-root
predecessor is the digest of the current canonical root. Rollbacks, forks and
generation gaps are rejected.

Each cursor pins the authenticated checkpoint, checkpoint policy, canonical
state root, state bytes and semantic-manifest digests. Safely identifiable
stale `.cursor.json.tmp-<32 lowercase hex>` regular files left by interrupted
writes are removed under the writer lock. Similar-looking names, links and
unrelated files are never removed; unsafe matching objects fail closed.

The caller must retain the expected cursor through an independent,
authenticated path and pass it to every admission. This crate protects a
single Unix-host copy; it does not provide networking, encryption, backup,
WORM retention, replication or high availability. Restoring the cursor and
its expectation from the same host cannot prove that rollback did not occur.
