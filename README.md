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

## Product boundaries

The repository contains no wallet signing, private keys, custody, transaction
broadcast, bridge execution, DEX liquidity, payment credit, Pix integration,
asset issuance, DvP/PvP settlement or regulatory connectivity.

No license is granted yet. Copyright © Bloch Inc.
