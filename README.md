# Bloch Products

Implementation workspace for the product portfolio described in
`Bloch_Inc_Products_Services_EN_v3.pdf`.

The first buildable product is **Bloch Verify**: deterministic, fail-closed
comparison of checkpoint observations from independent node operators. The
current MVP validates and compares evidence; it does not authenticate operator
identity, prove finality, activate a network, or authorize asset movement.

## Implemented now

- `bloch-verify-core`: strict evidence schema, canonical digest and assessment.
- External operator trust policies pinned by an independently retained SHA-256.
- Domain-separated Ed25519 verification for exact node observations.
- Create-once detached-signature requests and signed-bundle assembly.
- Strict offline conversion of retained EVM JSON-RPC finalized captures.
- `bloch-verify`: offline CLI with bounded, read-only input handling.
- Descriptor-bound input/output handling and recursive duplicate-key rejection.
- `bloch-indexer-core`: anchored canonical-chain state machine with bounded
  reorgs, atomic restart snapshots, deterministic outbox and durable offline
  delivery leases.
- `bloch-indexer-input`: bounded strict-JSON validation before canonical state
  transitions, plus Ed25519 producer authentication against independently
  pinned, canonical policy digests.
- `bloch-indexer-query`: versioned, bounded, snapshot-bound read contracts for
  status, blocks and events.
- `bloch-indexer-protocol`: strict, transport-neutral JSON dispatch and typed
  SDK messages for the v1 read contract.
- `bloch-indexer-delivery-protocol`: versioned, domain-separated Ed25519
  delivery envelopes and receiver acceptance receipts bound to exact durable
  claims and independently pinned sender/receiver trust roles.
- `bloch-indexer-receipt-ack`: verifies the exact authenticated delivery and
  receipt before a lock-and-reload acknowledgement, retaining receiver and
  policy/delivery/receipt digests in the same durable snapshot transition.
- `bloch-indexer-delivery-transport`: bounded canonical request/response codecs
  that authenticate embedded deliveries and receipts while leaving sockets and
  HTTP/RPC operation to the caller.
- `bloch-indexer-delivery-worker`: crash-recoverable local spool joining durable
  claims, externally signed deliveries, transport artifacts, authenticated
  receipts and durable ACK/retry transitions.
- `bloch-indexer-receiver-core`: durable receiver-side idempotency, exact bytes
  for external receipt signing and recoverable canonical responses without
  owning a private key.
- `bloch-indexer-audit`: bounded canonical checkpoint artifacts and detached
  Ed25519 verification against an independently pinned audit policy.
- `bloch-indexer-audit-retention`: private create-once local ledger for signed
  audit artifacts, with hash chaining and independently retained count/head
  expectations for truncation detection.
- Signed, path-independent retention checkpoints bind ledger identity, audit
  policy, entry count and head to a separately pinned checkpoint policy.
- Multi-replica audit verification replays complete ledgers, compares every
  shared prefix and requires an exact current-state quorum without claiming
  physical or operator independence.
- `bloch-indexer-service-admission`: canonical fail-closed admission binds the
  chain anchor, five pinned policies, durable storage identities and distinct
  evidence for TLS, external signing, replica/WORM retention, HA and governance
  enforcement.
- `bloch-data-governance`: canonical, independently pinned institution/tenant,
  purpose, field-classification, jurisdiction, region, retention and release
  policy. Protected values remain off-chain; v1 can authorize only a bounded
  externally constructed hiding commitment for publication.
- The Bloch Data JSON ingestion boundary derives the top-level field inventory
  from bounded bytes, rejects duplicate keys recursively and emits canonical
  record bytes with a bound digest instead of trusting caller-declared fields.
  An independently pinned canonical dataset schema now validates required and
  optional scalar fields before the governance decision.
- Bloch Data lifecycle evidence binds each admitted record to signed legal-hold,
  disposal-order and external-evidence transitions without claiming physical
  deletion. Restart recovery replays every retained signature against
  independently pinned state roots. A salted-record commitment supports offline
  equality checks but remains unqualified as a production hiding commitment.
- `bloch-pay-reconciliation`: pinned payment routes and observation sources,
  canonical invoices, deterministic exact/partial/excess/late matching and
  exact canonical observations authenticated by domain-separated Ed25519
  signatures and explicit non-settlement reports that can never authorize
  credit or funds.
- Pinned Ed25519 invoice-issuer policies authorize exact invoice bytes before
  the protected reconciliation path. Threshold finality attestations bind
  authorities to the observed block without claiming native consensus proof.
- `bloch-pay-allocation-store`: Unix-only durable, idempotent allocation of
  authenticated observations, bound to the exact report, reconciliation policy,
  observer and observer-policy digests. Its stricter path also requires pinned
  invoice authorization, and signed checkpoints bind complete local snapshots
  to independently retained generation/digest expectations. None of these
  qualify settlement, credit, replication or HA.
- `bloch-pay-adjustments`: authenticated, replay-safe observations of
  cancellation, dispute and refund lifecycles bound to the exact payment. It
  observes events only and never sends refunds or moves funds. Canonical state
  recovery requires independent digest, generation, policy and payment roots.
- `bloch-local-state-store`: common Unix-only, bounded persistence for exact
  Bloch Data and Bloch Pay state bytes, with owner-only files, bounded locking,
  compare-and-swap generations, atomic `fsync` replacement and a two-phase
  prepare/promote path for externally authorized updates. It provides neither
  encryption nor HA, and the product crates still perform semantic and
  signature validation after load.
- `bloch-local-state-checkpoint`: domain-separated threshold Ed25519
  authentication for exact local-state roots and their product-specific
  semantic-manifest digest. Signing remains external, and multiple keys do not
  prove operator independence.
- `bloch-local-state-cursor`: canonical single-host cursor with exact replay,
  immediate-successor and predecessor checks. The independently authenticated
  current cursor must still come from an off-host monotonic control plane; a
  local cursor alone cannot defeat same-host rollback or provide HA.
- `bloch-local-state-admission`: read-only startup composition for Data and Pay
  that binds a retained threshold checkpoint, independently supplied exact
  cursor, product-specific semantic manifest and exact local state before
  replaying the product restore logic. Production writers still require a
  shared outer coordinator across the cursor and state stores.
- `bloch-local-state-coordination`: bounded Unix exclusion shared by startup
  admission and cooperating state/cursor writers. It detects unsafe local lock
  objects but does not provide cross-host fencing or distributed consensus.
- `bloch-local-state-remote-cursor`: canonical nonce-bound threshold Ed25519
  observations of the exact cursor held by an external control plane, with a
  secure offline verification CLI. Networking, remote storage and operational
  independence remain external gates.
- `bloch-local-state-remote-session`: transport-neutral one-shot fetch session
  with an in-memory CSPRNG nonce, monotonic deadline, current-time freshness and
  bounded incremental ingress plus an opaque verified cursor result. It
  supplies no network transport itself.
- `bloch-trusted-time`: canonical nonce-bound threshold Ed25519 time intervals,
  independently pinned and audience-bound to one state identity and remote
  cursor policy, returned as an opaque monotonic capability. Fetching,
  rollback-resistant boundary storage and host suspend qualification remain
  external gates.
- `bloch-local-state-runtime`: in-process Data/Pay startup composition joining
  the one-shot remote session to coordinated checkpoint, cursor, store and
  semantic admission without materializing a raw cursor or nonce file.
- `bloch-local-state-remote-cursor-control-plane`: Unix reference core for
  explicitly provisioned, durable, idempotent and serialized cursor CAS. It
  returns unsigned decision material and is not a replicated production
  service or signing authority.
- `bloch-local-state-transition`: coordinated writer and recovery composition
  across prepared state, external checkpoint/CAS callbacks, freshly observed
  successor, local cursor advancement, promotion and semantic postcheck.
- `bloch-local-state-rebootstrap`: offline, create-only v1-to-v2 re-bootstrap
  for the narrow legacy case that already committed to a complete state-root
  v2 and is re-signed by checkpoint authorities. It refuses root-v1 lineage,
  policy rotation and any state/root divergence.
- `bloch-indexer-signing-ceremony`: create-once offline delivery and receipt
  signing requests, with operational receipt import routed through the durable
  receiver core. Private keys remain external.
- Unix snapshot mutations use a bounded local single-writer lock, reload the
  latest durable state while locked and reject unsafe lock files. Snapshot
  initialization is create-once and cannot overwrite existing state.
- Machine-readable portfolio and delivery gates in `products/portfolio.json`.
- Positive and adversarial tests.

## Run

```sh
cargo test --workspace --locked
cargo run --locked -p bloch-verify -- \
  assess --bundle fixtures/valid-checkpoint.json --at 1790121600
```

Require the comparison layer to pass:

```sh
cargo run --locked -p bloch-verify -- \
  assess --bundle fixtures/valid-checkpoint.json --at 1790121600 \
  --require-comparison
```

Signed bundles use `assess-signed`, an external policy file and
`--expected-trust-policy-sha256`. `--require-authenticated-comparison` requires
every observation to match a pinned operator key and valid Ed25519 signature.

The detached signing workflow is documented in
[`docs/SIGNED-OBSERVATION-WORKFLOW.md`](docs/SIGNED-OBSERVATION-WORKFLOW.md).
`bloch-verify-ceremony` prepares exact bytes for an external Ed25519 signer,
imports its raw 64-byte signature and assembles responses. It never receives a
private key and does not implement signing.

The EVM input boundary is documented in
[`docs/EVM-RPC-CAPTURE.md`](docs/EVM-RPC-CAPTURE.md). The adapter does not make
network requests and never treats a node's `finalized` response as independent
consensus proof.
[`docs/EVM-RPC-BATCH-CAPTURE.md`](docs/EVM-RPC-BATCH-CAPTURE.md) describes the
deterministic four-call request and retained-response importer.
[`docs/EVM-ANCESTRY-EVIDENCE.md`](docs/EVM-ANCESTRY-EVIDENCE.md) documents the
bounded structural header-linkage verifier; it deliberately does not claim
consensus finality.
[`docs/PRODUCTION-QUALIFICATION-GATES.md`](docs/PRODUCTION-QUALIFICATION-GATES.md)
defines the chain- and genesis-bound production profile and records unavailable
verifiers without accepting caller-provided success claims. The
`bloch-verify-qualify` CLI pins the reviewed network identity by an externally
retained canonical SHA-256.

`--require-production-qualified` intentionally exits nonzero in this version.
Real-world organizational independence and authenticated consensus
finality/ancestry are not implemented yet.

The indexer snapshot, pending outbox, compacted checkpoint and delivery cursor
are recovered together. The libraries define producer, delivery, receipt,
audit, claim/retry/acknowledgement and read contracts, but perform no RPC
ingestion, webhook delivery, HTTP serving or database-backed HA operation. A
verified receipt can reach durable acknowledgement only through the explicit
receipt-ACK coordinator; protocol verification alone never mutates state.
Producer, receiver and audit authentication are
not consensus finality. The indexer remains a local fail-closed core rather
than a production service.

The complete offline delivery lifecycle and crash boundaries are documented in
[`docs/INDEXER-DELIVERY-OPERATIONS.md`](docs/INDEXER-DELIVERY-OPERATIONS.md).
Exact external-signing commands and recovery boundaries are in
[`docs/INDEXER-SIGNING-CEREMONY.md`](docs/INDEXER-SIGNING-CEREMONY.md).
The service admission contract and its deliberately limited evidence semantics
are documented in
[`docs/INDEXER-SERVICE-ADMISSION.md`](docs/INDEXER-SERVICE-ADMISSION.md).
The regulated-data boundary, hybrid local/off-chain design and threat model are
documented in
[`docs/BLOCH-DATA-REGULATED-DATA.md`](docs/BLOCH-DATA-REGULATED-DATA.md),
[`docs/BLOCH-DATA-HYBRID-ARCHITECTURE.md`](docs/BLOCH-DATA-HYBRID-ARCHITECTURE.md)
and [`docs/BLOCH-DATA-THREAT-MODEL.md`](docs/BLOCH-DATA-THREAT-MODEL.md).
The non-custodial Bloch Pay reconciliation boundary is documented in
[`docs/BLOCH-PAY-RECONCILIATION.md`](docs/BLOCH-PAY-RECONCILIATION.md), with the
authenticated allocation flow in
[`docs/BLOCH-PAY-AUTHENTICATED-ALLOCATION.md`](docs/BLOCH-PAY-AUTHENTICATED-ALLOCATION.md).
The adjustment state-machine boundary is documented in
[`crates/bloch-pay-adjustments/README.md`](crates/bloch-pay-adjustments/README.md).

## Product boundaries

The repository contains no wallet signing, private keys, custody, transaction
broadcast, bridge execution, DEX liquidity, payment credit, Pix integration,
asset issuance, DvP/PvP settlement or regulatory connectivity.

No license is granted yet. Copyright © Bloch Inc.
