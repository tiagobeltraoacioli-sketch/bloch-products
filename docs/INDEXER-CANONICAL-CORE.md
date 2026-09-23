# Canonical indexer core

`bloch-indexer-core` is the first implementation slice of Bloch Data/Dev Cloud.
It is a deterministic in-memory state machine for applying already-decoded EVM
blocks and logs after a reviewed immutable anchor.

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

The core does not connect to RPC, persist data, expose an API, emit webhooks or
authenticate finality. The anchor must come from a separately reviewed source.
Its existence must never be interpreted as proof that a block is finalized.

Run the state-machine tests:

```sh
cargo test --locked --offline -p bloch-indexer-core
```

The next indexer slices are durable storage with atomic canonical/orphan
transitions, restart recovery, an input adapter with strict duplicate-key
handling, and only then versioned read APIs and idempotent webhooks.
