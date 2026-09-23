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

`bloch-verify-core::checkpoint_ancestry` can additionally authenticate this
same bounded parent chain. Its separately pinned canonical policy fixes the
reviewed network, the later terminal anchor, trusted-time audience and a
threshold of distinct Ed25519 authority organizations/control domains. The
signed envelope fixes the exact bundle, checkpoint and ancestry-evidence
digest. Verification requires a matching `VerifiedTrustedTime`; freshness is
then retained with a monotonic deadline.

That capability is suitable only for the `CheckpointAncestry` qualification
gate. It deliberately reports `consensus_finality_authenticated() == false`:
authority signatures attest exact parent linkage and do not substitute for a
protocol validator-set/finality proof.
