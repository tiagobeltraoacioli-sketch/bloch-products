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
- create-once snapshot initialization that refuses to overwrite valid or
  corrupt existing state;
- bounded Unix single-writer coordination with reload-under-lock before every
  persisted transition;
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

`bloch-indexer-delivery-protocol` serializes strict, versioned delivery
envelopes and receiver acceptance receipts. Domain-separated Ed25519 signatures
bind the deployment domain, complete chain identity, exact record bytes and
digest, claim attempt and generation. Sender and receiver roles must use
distinct IDs and keys from a canonical policy pinned through an independent
path. Receipt verification can be bound to the caller's expected durable claim,
but deliberately does not mutate or acknowledge state. A receipt proves only
that a configured receiver signed that acceptance; it does not prove finality
or successful downstream processing.

`bloch-indexer-receipt-ack` is the explicit mutation boundary. It authenticates
the exact delivery and receipt against the pinned policy and claim before
calling the lock-and-reload acknowledgement. Snapshot schema v4 stores the
receiver ID plus canonical policy, delivery and receipt SHA-256 digests in the same
atomic snapshot replacement as the resolution. The claim binds record ID,
attempt and generation. Exact replay is idempotent; changed evidence,
stale/expired claims and persistence failure fail closed.
The lower-level core acknowledgement primitives do not authenticate receipts;
an operator requiring authenticated acceptance must expose only this coordinator
at its service boundary.

`bloch-indexer-delivery-transport` adds strict, canonical and bounded offline
request/response codecs around those authenticated payloads. It pins content
types, protocol version, deployment domain and request correlation, but opens
no socket and implements no HTTP or RPC client/server. Correlation IDs are not
signatures; delivery and receipt authentication remains the security boundary.

`bloch-indexer-delivery-worker` provides a private local spool and a globally
discoverable active-job intent. It recovers crashes around durable claim,
externally signed delivery staging, response import, receipt verification and
ACK/retry persistence. Job identity commits to the complete claim, canonical
record digest and trust-policy digest. It owns no signer and performs no network
I/O.

`bloch-indexer-receiver-core` persists one accepted record outcome and separate
delivery-attempt acceptances before exposing receipt-signing bytes. Exact replay
recovers the same bytes or response. A later attempt after response loss can
receive a new attempt-bound receipt without repeating the record outcome.
Policy rotation for an already admitted record conflicts fail-closed and needs
an explicit operator migration decision.

Fully acknowledged batch prefixes can be compacted atomically. Queue schema v2
retains transition tombstones, batch commitments and a cumulative hash chain
from the immutable anchor to the compacted tip. Pending or partially delivered
batches and active claims are never removed. Each call is limited to 10,000
batches and the retained checkpoint to 50,000 links. The checkpoint hash
detects inconsistent content but, like the snapshot checksum, is not an
authenticity signature. `bloch-indexer-audit` exports and strictly verifies a
bounded canonical artifact. Optional detached Ed25519 verification binds the
complete independently pinned audit policy digest, signer, domain, network,
anchor and checkpoint contents. Retention and signer operation remain external,
and neither the checksum nor signature proves chain finality.

`bloch-indexer-audit-retention` stores signed artifacts as private create-once
files in a locally hash-chained Unix directory. Full replay revalidates the
policy pin, artifacts and signatures. A count and head hash retained outside
the ledger detects tail truncation. This provides bounded local tamper evidence,
not WORM storage, remote replication, multi-host coordination or finality; an
operator must preserve the external expectation independently.

Retention checkpoints turn that external expectation into a canonical,
path-independent document signed by a checkpoint key from a separately pinned
policy. Verification binds checkpoint domain, stable ledger ID, audit-policy
digest, count and head, and can require ancestry from a previously verified
checkpoint. It still does not make the local ledger WORM or replicated.

Snapshot schema v4 stores canonical state, compacted/pending outbox, delivery
cursor and authenticated acknowledgement evidence together. It intentionally
does not load older snapshots; no
production migration is claimed in this pre-deployment repository.

On supported Unix systems, persisted mutations use a same-directory advisory
lock with mode `0600`, reject symlinks, hardlinks, foreign ownership and inode
replacement, and wait for at most five seconds by default (with a hard maximum
of 30 seconds). The latest snapshot is reloaded after acquiring the lock so
cooperating stale callers cannot overwrite each other's transitions. Mutation
fails closed on unsupported platforms. This is local process coordination, not
a distributed or multi-host HA lock.

The core does not connect to RPC, deliver webhooks, open an HTTP service or
authenticate finality. The anchor must come from a separately reviewed source
and must never be interpreted as proof that a block is finalized.

Run the state-machine tests:

```sh
cargo test --locked --offline -p bloch-indexer-core
cargo test --locked --offline -p bloch-indexer-input
cargo test --locked --offline -p bloch-indexer-query
cargo test --locked --offline -p bloch-indexer-protocol
cargo test --locked --offline -p bloch-indexer-delivery-protocol
cargo test --locked --offline -p bloch-indexer-delivery-transport
cargo test --locked --offline -p bloch-indexer-delivery-worker
cargo test --locked --offline -p bloch-indexer-receiver-core
cargo test --locked --offline -p bloch-indexer-receipt-ack
cargo test --locked --offline -p bloch-indexer-audit
cargo test --locked --offline -p bloch-indexer-audit-retention
```

The next indexer slices are authenticated caller-operated network adapters
around these offline contracts, external signer/HSM integration, independently
replicated/WORM audit retention and database-backed distributed coordination.
High availability is not part of this file-snapshot implementation.
