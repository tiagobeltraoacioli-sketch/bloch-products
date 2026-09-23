# Bloch local state checkpoint

Threshold-authenticated anti-rollback roots for `bloch-local-state-store`.
The crate builds domain-separated bytes for external Ed25519 authorities,
assembles only signatures that meet an independently pinned policy threshold,
and verifies canonical checkpoints against exact identity, generation, state
digest and freshness expectations.

Checkpoint artifact v2 also signs a required `semanticManifestSha256`. This
binds the opaque persisted state to the independently reviewed Bloch Data or
Bloch Pay policy/context manifest expected by admission. The semantic manifest
itself stays outside the checkpoint and must never be derived from the state.

Private keys never enter this crate. Authority independence is an operational
qualification and is never inferred from multiple public keys. The signed
checkpoint must be retained outside the state-store host, and the expected
generation must also come from that independent control plane; otherwise an
old but valid checkpoint can be replayed.

This authenticates a local state root. It does not validate Bloch Data or Bloch
Pay semantics, encrypt state, prove consensus finality, provide backup/HA, or
authorize settlement, custody, credit, deletion or release of data.

## Offline CLI

The `bloch-local-state-checkpoint` binary implements a file-only ceremony. It
never accepts private keys and writes nothing to standard output. Every input
must be a bounded, single-link, owner-operated regular file with no group or
world permissions. Output directories must be owner-only; outputs are created
with mode `0600` and are never overwritten.

Generate the exact domain-separated message and a human/tool-readable request:

```sh
bloch-local-state-checkpoint request \
  --root independent-root.json \
  --policy checkpoint-policy.json \
  --policy-sha256 0xREVIEWED_POLICY_SHA256 \
  --semantic-manifest-sha256 0xREVIEWED_SEMANTIC_MANIFEST_SHA256 \
  --created-at 1789948800 \
  --request-out ceremony/signing-request.json \
  --message-out ceremony/signing-message.bin
```

Each independent authority signs `signing-message.bin` as raw Ed25519 bytes,
outside this program. Collect signatures as canonical compact JSON, sorted by
authority ID:

```json
{"schema":"bloch.products.local-state-checkpoint-signatures.v1","signatures":[{"authorityId":"authority-1","signature":"0x..."},{"authorityId":"authority-2","signature":"0x..."}]}
```

Assemble only after the pinned policy threshold is available:

```sh
bloch-local-state-checkpoint assemble \
  --root independent-root.json \
  --policy checkpoint-policy.json \
  --policy-sha256 0xREVIEWED_POLICY_SHA256 \
  --semantic-manifest-sha256 0xREVIEWED_SEMANTIC_MANIFEST_SHA256 \
  --created-at 1789948800 \
  --signatures ceremony/signatures.json \
  --artifact-out ceremony/checkpoint.json
```

Admission requires the complete expected root from an independent control
plane, not a root rediscovered from the state-store host:

```sh
bloch-local-state-checkpoint verify \
  --artifact ceremony/checkpoint.json \
  --policy checkpoint-policy.json \
  --policy-sha256 0xREVIEWED_POLICY_SHA256 \
  --expected-semantic-manifest-sha256 0xINDEPENDENT_SEMANTIC_MANIFEST_SHA256 \
  --expected-root independently-retained-root.json \
  --evaluated-at 1789948860 \
  --receipt-out ceremony/verification-receipt.json
```

The receipt records that the exact root expectation matched, but deliberately
keeps `authorityIndependenceProven` and `highAvailabilityProven` false. Those
are operational qualifications, not properties inferable from signatures.

Library integrations that already have an independently durable monotonic
cursor may call `authenticate_root_checkpoint` first and submit the returned
root and signed semantic-manifest digest to that admission pipeline.
Authentication alone proves neither anti-rollback admission nor semantic
correctness; the product layer must independently match and validate the
referenced manifest. Other callers should use `verify_root_checkpoint_exact`
with both the complete expected root and expected semantic digest.

On restart, an artifact that was already admitted may be older than the
policy's maximum checkpoint age. Only in that case, integrations may call
`authenticate_retained_root_checkpoint` and must immediately match its exact
checkpoint digest and complete root against an independently authenticated
cursor. The retained API still verifies canonical encoding, policy/domain,
issuance inside the policy validity window, and the signature threshold. It
must never be used for initial admission or cursor advancement and does not
prove expectation provenance, authority independence, current freshness,
replication or high availability.
