# Production qualification gates

`bloch-verify-core::qualification` exposes the production policy and its
evaluation result as strict, machine-readable JSON structures. The active
profile is `bloch-l2-700771-production.v1` and requires every gate below.

| Gate | Evidence contract | Current verifier |
| --- | --- | --- |
| Network identity | `bloch.verify.network-identity.v1` | Implemented |
| Authenticated comparison | `bloch.verify.signed-checkpoint-bundle.v1` | Implemented |
| Organization independence | `bloch.verify.organization-independence-evidence.v1` | Implemented library and offline CLI verifier |
| Checkpoint ancestry | `bloch.verify.authenticated-checkpoint-ancestry.v1` | Implemented library capability and offline ceremony tooling; no CLI production composition yet |
| Consensus finality | `bloch.verify.consensus-finality-proof.v1` | Gate unavailable; pinned-set certificate primitive implemented |

An unsupported gate is emitted as `verifierUnavailable`, never as passed.
Implemented gates without their opaque verified capability and independent
policy pin are emitted as `failed`. Opaque references and caller-provided
booleans cannot upgrade a gate.

The checkpoint-ancestry verifier reuses the bounded `EvmAncestryEvidence`
parent chain and binds it to an exact assessed bundle, reviewed network,
checkpoint and later independently pinned terminal anchor. A threshold of
distinct Ed25519 authorities signs the canonical envelope. Evaluation time
comes from a matching `VerifiedTrustedTime` policy and state identity; an
operator-supplied timestamp cannot create the capability. The trusted-time
policy digest also commits to that policy's complete audience. The resulting
non-cloneable capability expires against a process monotonic clock.

This proves authenticated parent linkage from the assessed checkpoint through
the pinned later anchor only. The terminal field inherited from the EVM format
is named `finalized`, but neither that label nor the ancestry-authority
signatures prove consensus finality. The independent consensus-finality gate
therefore remains unavailable and production qualification remains closed.

`bloch-evm-consensus-finality` now verifies weighted Ed25519 signatures with a
strict greater-than-two-thirds quorum over an exact network, genesis,
generation and checkpoint. Its v1 policy accepts only an independently pinned
generation-1 validator set and authenticated trusted time; it has no transition
path. This proves that the configured keys signed the checkpoint statement. It
does not prove that a deployed node runs the corresponding consensus rules,
that the validators are operationally independent, or that any validator-set
transition is valid. For those reasons this primitive is not yet accepted by
the `ConsensusFinality` qualification gate.

The organizational-independence verifier accepts only canonical evidence signed
by the threshold in a separately pinned reviewer policy. The policy requires at
least three assessed organizations, distinct organization control domains and
reviewers whose organizations, control domains and keys are mutually distinct
and disjoint from the assessed organizations. The capability is bound to the
exact signed-bundle digest and reviewed-network digest. This authenticates the
reviewers' claims; it cannot inspect a company registry, beneficial ownership,
infrastructure tenancy or HSM custody. Those facts and the reviewer-policy pin
must be established and retained outside the assessed hosts.

The default evaluator and the CLI's existing argument path still fail this gate
when the verified capability and its independent policy pin are absent. The CLI
can compose the capability only when all three optional inputs are present: the
canonical evidence, canonical policy and independently retained policy digest.
Partial input is refused rather than silently ignored.

The separate `bloch-verify-ancestry-ceremony` command validates and digests a
canonical ancestry policy, publishes the exact binary signing message and
assembles canonical evidence from detached Ed25519 signatures. It never reads
a private key. Assembly checks the chain, audience, validity interval,
authority order, signature validity and threshold before using private,
create-once output. This is ceremony preparation and structural authentication,
not production verification: the command neither creates nor accepts a
`VerifiedTrustedTime`, does not return a `VerifiedCheckpointAncestry` capability
and is deliberately not connected to `assess-signed`.

The caller must provide the reviewed production `NetworkIdentity`; the profile
accepts only chain ID `700771` and pins the supplied genesis hash without
inventing a default. The report retains both expected and assessed identities,
and a mismatch in network name, chain ID or genesis hash fails an explicit
gate.

The qualification evaluator also refuses to elevate the underlying assessment:
its result can be true only if the source assessment is already production
qualified and every required gate passes. Ancestry now requires its separate
opaque capability, while consensus finality remains unavailable; therefore
`productionQualified` is still always false.

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

Canonicalize the reviewed organizational-independence policy outside the
assessed hosts. The following command validates that the file already has the
exact canonical representation and prints its digest; it does not rewrite the
policy:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-qualify -- \
  digest-independence-policy \
  --policy path/to/canonical-independence-policy.json
```

Retain that digest through an independent configuration/review channel. An
offline reviewer can verify the exact evidence audience before composing a
qualification report:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-qualify -- \
  verify-independence \
  --evidence path/to/canonical-independence-evidence.json \
  --policy path/to/canonical-independence-policy.json \
  --expected-policy-sha256 0xINDEPENDENTLY_RETAINED_POLICY_SHA256 \
  --expected-bundle-sha256 0xEXACT_SIGNED_BUNDLE_SHA256 \
  --expected-network path/to/reviewed-network.json \
  --expected-network-sha256 0xINDEPENDENTLY_RETAINED_NETWORK_SHA256 \
  --at REVIEWED_UNIX_SECONDS
```

On success this prints the verified evidence digest. To compose the same
capability into `assess-signed`, append all of these options to that command:

```text
--independence-evidence path/to/canonical-independence-evidence.json
--independence-policy path/to/canonical-independence-policy.json
--expected-independence-policy-sha256 0xINDEPENDENTLY_RETAINED_POLICY_SHA256
```

All file inputs use bounded, no-symlink, single-link reads. Reports are private,
create-once files and an existing path is never overwritten.

`--at` is reviewer-supplied ceremony/audit time. It is checked for canonical
Unix-seconds spelling and against the evidence and policy windows, but it is not
trusted-time acquisition. Therefore these offline commands do not by themselves
satisfy a production trusted-time gate or qualify reviewer independence.

The report retains both assessed and expected network identities plus the
expected network digest. A digest mismatch is refused before report creation.
The assessment command exits `0` only for a production-qualified report, `1`
when the report is created but a required gate remains closed, and `2` for an
invalid or unsafe input. Accepted independence evidence cannot satisfy any
other gate: checkpoint ancestry remains closed without its separate verified
capability, consensus finality remains unavailable, and production
qualification therefore remains closed.
