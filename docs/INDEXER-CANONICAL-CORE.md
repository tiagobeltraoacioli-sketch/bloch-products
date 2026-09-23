# Canonical indexer core

`bloch-indexer-core` is the first implementation slice of Bloch Data/Dev Cloud.
It is a deterministic state machine for applying decoded EVM blocks and logs
after a reviewed immutable anchor. The canonical state, permanent collision
history and pending outbox can be persisted and recovered as one unit.

Implemented invariants:

- exact network, chain ID and genesis binding;
- immutable anchor boundary;
- contiguous parent-hash extension;
- idempotent replay of identical blocks;
- bounded canonical reorganization;
- reverse-order list of removed block hashes;
- permanent detection of content changes under a previously seen block hash;
- canonical event ordering and unique transaction/log identities;
- strict lowercase fixed-width hashes and addresses;
- bounded event count, topic count and log data size;
- atomic snapshot replacement with restart recovery;
- fail-closed linkage from anchor through every pending outbox transition to
  the recovered canonical tip;
- deterministic, idempotent block-applied and block-reverted records;
- symlink, hardlink, unsafe-permission, truncation and corruption rejection on
  supported Unix platforms.

`bloch-indexer-input` is the strict JSON boundary. It rejects empty or oversized
input, recursive duplicate keys, unknown fields, trailing data, excessive
nesting and semantically invalid blocks before they reach the state machine.
Its authenticated envelope verifies Ed25519 signatures from independently
pinned producer keys and binds the exact block bytes to the deployment domain,
network identity and immutable anchor. This authenticates the producer and
payload only; it does not prove ancestry or consensus finality.

`bloch-indexer-query` is a pure versioned read contract. Status, tip, block and
event responses are network-bound and always report finality as
`notEstablished`. Block and event pages are bounded. Their deterministic
cursors are tied to a query kind and canonical snapshot, remain stable across
append-only growth, and fail closed if a reorg replaces that snapshot. Cursor
SHA-256 detects corruption but is not authentication or authorization.

Snapshots are limited to 64 MiB and stored with mode `0600` in a private
directory. Their SHA-256 detects torn writes and accidental corruption; it is
not a signature or proof of authenticity. The directory must remain under the
exclusive control of the indexer operator.

The delivery state machine claims records in global order, persists bounded
leases before external work and supports idempotent retry/acknowledgement. It
performs no network operation: a future worker must use the stable record ID as
the receiver-side idempotency key. Delivery is at-least-once, so a crash after
the external operation and before acknowledgement can cause a replay. Fully
acknowledged batches remain retained; safe compaction is not implemented.

Snapshot schema v2 stores canonical state, outbox and delivery cursor together.
It intentionally does not load v1 snapshots; no production migration is
claimed in this pre-deployment repository.

The core does not connect to RPC, deliver webhooks, open an HTTP service or
authenticate finality. The anchor must come from a separately reviewed source
and must never be interpreted as proof that a block is finalized.

Run the state-machine tests:

```sh
cargo test --locked --offline -p bloch-indexer-core
cargo test --locked --offline -p bloch-indexer-input
cargo test --locked --offline -p bloch-indexer-query
```

The next indexer slices are transport adapters around these contracts,
receiver-side delivery integration, safe outbox compaction and an SDK.
Multi-process database coordination and high availability are not part of this
file-snapshot implementation.
