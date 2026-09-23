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

Producer policies use a strict, versioned JSON schema capped at 64 KiB. Their
canonical representation sorts producers and produces the SHA-256 that an
operator must pin through an independent configuration path. A policy digest,
key or policy embedded in an incoming block envelope is never trusted.

`bloch-indexer-query` is a pure versioned read contract. Status, tip, block and
event responses are network-bound and always report finality as
`notEstablished`. Block and event pages are bounded. Their deterministic
cursors are tied to a query kind and canonical snapshot, remain stable across
append-only growth, and fail closed if a reorg replaces that snapshot. Cursor
SHA-256 detects corruption but is not authentication or authorization.

`bloch-indexer-protocol` supplies strict JSON request/response envelopes and
typed SDK encoding for those reads. Requests are capped at 16 KiB and responses
at 2 MiB. Public errors are stable and do not contain internal error text. The
crate performs no socket, filesystem or transport I/O and exposes no write
operation.

Snapshots are limited to 64 MiB and stored with mode `0600` in a private
directory. Their SHA-256 detects torn writes and accidental corruption; it is
not a signature or proof of authenticity. The directory must remain under the
exclusive control of the indexer operator.

The delivery state machine claims records in global order, persists bounded
leases before external work and supports idempotent retry/acknowledgement. It
performs no network operation: a future worker must use the stable record ID as
the receiver-side idempotency key. Delivery is at-least-once, so a crash after
the external operation and before acknowledgement can cause a replay.

Fully acknowledged batch prefixes can be compacted atomically. Queue schema v2
retains transition tombstones, batch commitments and a cumulative hash chain
from the immutable anchor to the compacted tip. Pending or partially delivered
batches and active claims are never removed. Each call is limited to 10,000
batches and the retained checkpoint to 50,000 links. The checkpoint hash
detects inconsistent content but, like the snapshot checksum, is not an
authenticity signature; external audit retention remains an operator concern.

Snapshot schema v3 stores canonical state, compacted/pending outbox and delivery
cursor together. It intentionally does not load v1 or v2 snapshots; no
production migration is claimed in this pre-deployment repository.

The core does not connect to RPC, deliver webhooks, open an HTTP service or
authenticate finality. The anchor must come from a separately reviewed source
and must never be interpreted as proof that a block is finalized.

Run the state-machine tests:

```sh
cargo test --locked --offline -p bloch-indexer-core
cargo test --locked --offline -p bloch-indexer-input
cargo test --locked --offline -p bloch-indexer-query
cargo test --locked --offline -p bloch-indexer-protocol
```

The next indexer slices are authenticated transport adapters around these
contracts, receiver-side delivery integration and externally retained audit
checkpoints. Multi-process database coordination and high availability are not
part of this file-snapshot implementation.
