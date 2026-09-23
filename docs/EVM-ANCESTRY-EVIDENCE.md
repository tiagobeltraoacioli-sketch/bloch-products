# EVM ancestry evidence

`bloch-verify-evm-ancestry` validates an offline sequence of EVM headers from
an assessed checkpoint through a later block that an upstream source labeled
finalized. The verifier requires exact endpoint matches, consecutive heights,
unique block hashes and an unbroken `parentHash` chain. Evidence is bounded to
4,096 headers.

Verify evidence and create a machine-readable report:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-evm-ancestry -- \
  verify \
  --evidence path/to/evm-ancestry-evidence.json \
  --report-out path/to/new-ancestry-report.json
```

The format is illustrated by
[`fixtures/valid-evm-ancestry.json`](../fixtures/valid-evm-ancestry.json).

A successful report proves only that the supplied headers are internally
linked. It does not authenticate the source of those headers, establish a path
from a reviewed trust anchor, verify a validator set or prove protocol
finality. Consequently `consensusFinalityAuthenticated` and
`productionQualified` remain false.
