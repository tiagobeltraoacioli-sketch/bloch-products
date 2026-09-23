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

## Offline authenticated-ancestry ceremony

The offline ceremony command does not handle private keys. First validate that
the reviewed policy is already in its exact canonical encoding and print its
digest:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-ancestry-ceremony -- \
  digest-policy \
  --policy ceremony/checkpoint-ancestry-policy.json
```

Retain that digest through an independent review channel. Publish one
create-once binary message containing the exact policy pin, ancestry chain,
bundle, network, checkpoint, terminal anchor and validity interval:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-ancestry-ceremony -- \
  prepare-message \
  --policy ceremony/checkpoint-ancestry-policy.json \
  --expected-policy-sha256 0xINDEPENDENTLY_RETAINED_POLICY_SHA256 \
  --ancestry ceremony/evm-ancestry-evidence.json \
  --expected-bundle-sha256 0xEXACT_SIGNED_BUNDLE_SHA256 \
  --expected-network ceremony/reviewed-network.json \
  --expected-network-sha256 0xINDEPENDENTLY_RETAINED_NETWORK_SHA256 \
  --attested-at REVIEWED_UNIX_SECONDS \
  --valid-until REVIEWED_EXPIRY_UNIX_SECONDS \
  --message-out ceremony/checkpoint-ancestry-message.bin
```

Each authority signs those exact binary bytes in its own isolated signer or
HSM. The command prints the message SHA-256 for independent comparison. It does
not invoke a signer and never accepts a private-key option.

Collect signatures in authority-ID order as compact canonical JSON without a
trailing newline:

```json
[{"authorityId":"authority-1","signature":"0xED25519_SIGNATURE"},{"authorityId":"authority-2","signature":"0xED25519_SIGNATURE"}]
```

Then assemble the canonical, create-once evidence. Every option that determined
the signing message must be repeated exactly:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-ancestry-ceremony -- \
  assemble-evidence \
  --policy ceremony/checkpoint-ancestry-policy.json \
  --expected-policy-sha256 0xINDEPENDENTLY_RETAINED_POLICY_SHA256 \
  --ancestry ceremony/evm-ancestry-evidence.json \
  --expected-bundle-sha256 0xEXACT_SIGNED_BUNDLE_SHA256 \
  --expected-network ceremony/reviewed-network.json \
  --expected-network-sha256 0xINDEPENDENTLY_RETAINED_NETWORK_SHA256 \
  --attested-at REVIEWED_UNIX_SECONDS \
  --valid-until REVIEWED_EXPIRY_UNIX_SECONDS \
  --signatures ceremony/checkpoint-ancestry-signatures.json \
  --evidence-out ceremony/authenticated-checkpoint-ancestry.json
```

All inputs are bounded regular single-link files opened without following
symlinks. Output files are private and create-once. Assembly verifies the
canonical policy and signatures file, exact audience and chain, ordered known
authorities, Ed25519 signatures and threshold before publishing evidence.

This workflow intentionally stops before production admission. A reviewed
timestamp passed on the command line is not authenticated time. The ceremony
does not manufacture `VerifiedTrustedTime`, produce the opaque verified
ancestry capability, compose the qualification gate or prove consensus
finality. Production verification must separately acquire matching trusted
time and remain fail-closed when that capability is unavailable.
