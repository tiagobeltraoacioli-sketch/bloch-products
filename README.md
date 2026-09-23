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
- `bloch-verify`: offline CLI with bounded, read-only input handling.
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

`--require-production-qualified` intentionally exits nonzero in this version.
Real-world organizational independence and authenticated consensus
finality/ancestry are not implemented yet.

## Product boundaries

The repository contains no wallet signing, private keys, custody, transaction
broadcast, bridge execution, DEX liquidity, payment credit, Pix integration,
asset issuance, DvP/PvP settlement or regulatory connectivity.

No license is granted yet. Copyright © Bloch Inc.
