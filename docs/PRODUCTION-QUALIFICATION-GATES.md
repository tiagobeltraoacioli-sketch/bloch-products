# Production qualification gates

`bloch-verify-core::qualification` exposes the production policy and its
evaluation result as strict, machine-readable JSON structures. The active
profile is `bloch-l2-700771-production.v1` and requires every gate below.

| Gate | Evidence contract | Current verifier |
| --- | --- | --- |
| Network identity | `bloch.verify.network-identity.v1` | Implemented |
| Authenticated comparison | `bloch.verify.signed-checkpoint-bundle.v1` | Implemented |
| Organization independence | `bloch.verify.organization-independence-evidence.v1` | Not implemented |
| Checkpoint ancestry | `bloch.verify.checkpoint-ancestry-proof.v1` | Not implemented |
| Consensus finality | `bloch.verify.consensus-finality-proof.v1` | Not implemented |

An evidence schema name is a future interoperability contract, not proof that
the verifier supports it. An unsupported gate is emitted as
`verifierUnavailable`, never as passed. Opaque references and caller-provided
booleans cannot upgrade a gate.

The caller must provide the reviewed production `NetworkIdentity`; the profile
accepts only chain ID `700771` and pins the supplied genesis hash without
inventing a default. The report retains both expected and assessed identities,
and a mismatch in network name, chain ID or genesis hash fails an explicit
gate.

The qualification evaluator also refuses to elevate the underlying assessment:
its result can be true only if the source assessment is already production
qualified and every required gate passes. With the current implementation,
`productionQualified` is therefore always false.

## Offline qualification command

Create a strict network identity JSON containing the reviewed network name,
chain ID `700771` and reviewed genesis hash. Calculate its canonical digest:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-qualify -- \
  digest-network --network path/to/reviewed-network.json
```

Retain the printed digest through an independent review channel. Then assess a
signed bundle and create a report without overwriting an existing artifact:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-qualify -- \
  assess-signed \
  --bundle path/to/signed-bundle.json \
  --trust-policy path/to/operator-trust-policy.json \
  --expected-trust-policy-sha256 0xREVIEWED_POLICY_SHA256 \
  --expected-network path/to/reviewed-network.json \
  --expected-network-sha256 0xINDEPENDENTLY_RETAINED_NETWORK_SHA256 \
  --at REVIEWED_UNIX_SECONDS \
  --report-out path/to/new-qualification-report.json
```

The report retains both assessed and expected network identities plus the
expected network digest. A digest mismatch is refused before report creation.
The assessment command exits `0` only for a production-qualified report, `1`
when the report is created but a required gate remains closed, and `2` for an
invalid or unsafe input.
