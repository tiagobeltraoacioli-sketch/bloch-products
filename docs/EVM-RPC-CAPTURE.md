# EVM RPC capture adapter

`bloch-verify-evm-adapter` converts a retained EVM JSON-RPC capture into the
strict observation consumed by the detached-signature workflow. It performs no
network access and cannot silently select a different endpoint during review.

The capture schema is `bloch.verify.evm-rpc-capture.v1`. It contains the
observer and organization identifiers, an endpoint SHA-256 commitment, capture
time, network label, release revision, and complete request/response pairs for:

- `web3_clientVersion` with `[]`;
- `eth_chainId` with `[]`;
- `eth_getBlockByNumber` with `["0x0", false]`;
- `eth_getBlockByNumber` with `["finalized", false]`.

Every pair must use JSON-RPC 2.0, matching request/response IDs and a unique
numeric ID. Quantities must use canonical lowercase Ethereum hex notation. A
null `finalized` result is refused. See
[`fixtures/valid-evm-rpc-capture.json`](../fixtures/valid-evm-rpc-capture.json)
for the exact envelope.

Convert a reviewed capture with create-only output semantics:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-evm-adapter -- \
  convert \
  --capture path/to/evm-rpc-capture.json \
  --observation-out path/to/new-observation.json
```

The resulting observation sets its checkpoint to the header returned for the
`finalized` tag. This authenticates what the operator later signs; it does not
independently establish that the node follows the intended consensus or that
the block is finalized. Independent operators, signed observations, ancestry
evidence and consensus-specific verification remain separate gates.
