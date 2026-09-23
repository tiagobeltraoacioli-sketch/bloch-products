# Authenticated finality attestations

This module establishes a deliberately narrow fact: a configured threshold of
pinned Ed25519 authorities signed the same statement about the exact block in
an already authenticated payment observation.

It does **not** prove native chain consensus, canonical ancestry, settlement,
credit eligibility, ownership of funds, or authorization to release anything.
`network_finality_qualified()`, `settlement_qualified()`,
`credit_authorized()` and `funds_released()` therefore remain false even after
the authority threshold is met.

## Trust policy

`FinalityTrustPolicy` is strict canonical JSON and must be loaded with an
independently provisioned SHA-256 pin. It binds:

- the exact reconciliation-policy digest;
- a deployment-specific signature domain;
- an effective and expiry time;
- each network's signature threshold and maximum evidence age;
- each authority ID and Ed25519 public key to one network.

Networks and authorities must be canonically ordered. Authority IDs and keys
are unique, weak Ed25519 keys fail validation, and a policy cannot specify a
threshold greater than the number of configured authorities.

## Signed statement

`finality_signing_bytes` length-frames and domain-separates every component. A
signature is bound to both policy digests, authority, network, canonical
observation digest, transaction ID, event index, observed block height/hash,
and checkpoint time. The checkpoint height and hash must exactly equal the
observation's own block. This avoids pretending that a later checkpoint proves
ancestry when this offline module has no header chain.

The signature envelope is bounded, exact canonical JSON. Duplicate, unknown,
trailing and noncanonical fields fail closed. Verification returns an opaque
`AuthenticatedFinalityEvidence`; callers cannot construct one or inject a
finality boolean.

## Threshold evaluation

`evaluate_finality_attestation_threshold` accepts only opaque authenticated
observations and opaque authenticated evidence. It revalidates both independent
policy pins, validity windows, freshness, observation digest, network,
authority membership and exact checkpoint. It rejects duplicate authorities
and conflicting checkpoint times or hashes.

On success it returns an opaque `ThresholdFinalityAttestation`. The result says
only `attestation_threshold_met() == true`; it intentionally says
`network_finality_qualified() == false`.

## Production boundary

Before using an observation as a qualified finality receipt, an integration
must independently implement and review network-native consensus and ancestry
verification, reorganization handling, authority operations and key rotation,
durable replay protection, incident response and evidence retention. Those
controls are outside this crate, so the `qualified-finality-receipts` gate must
remain open.
