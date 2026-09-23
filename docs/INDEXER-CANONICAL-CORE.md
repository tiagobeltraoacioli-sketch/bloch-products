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
- bounded event count, topic count and log data size.
- atomic snapshot replacement with restart recovery;
- fail-closed linkage from anchor through every pending outbox transition to
  the recovered canonical tip;
- deterministic, idempotent block-applied and block-reverted records;
- symlink, hardlink, unsafe-permission, truncation and corruption rejection on
  supported Unix platforms.

`bloch-indexer-input` is the strict JSON boundary. It rejects empty or oversized
input, recursive duplicate keys, unknown fields, trailing data, excessive
nesting and semantically invalid blocks before they reach the state machine.

Snapshots are limited to 64 MiB and stored with mode `0600` in a private
directory. Their SHA-256 detects torn writes and accidental corruption; it is
not a signature or proof of authenticity. The directory must remain under the
exclusive control of the indexer operator.

The core does not connect to RPC, expose a read API, deliver webhooks, retry or
acknowledge outbox records, or authenticate finality. The outbox is currently a
durable delivery-neutral queue only. It grows until a separately implemented
delivery/acknowledgement protocol exists. The anchor must come from a separately
reviewed source and must never be interpreted as proof that a block is
finalized.

Run the state-machine tests:

```sh
cargo test --locked --offline -p bloch-indexer-core
cargo test --locked --offline -p bloch-indexer-input
```

The next indexer slices are authenticated ingestion, a durable delivery worker
with explicit acknowledgement/retry semantics, and then versioned read APIs and
an SDK. Multi-process database coordination and high availability are not part
of this file-snapshot implementation.
