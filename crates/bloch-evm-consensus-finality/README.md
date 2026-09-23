# Bloch EVM consensus finality

Strict, transport-neutral verification of weighted Ed25519 validator signatures
over one EVM/L2 checkpoint. A successful verification returns a non-cloneable
capability bound to the exact policy digest, network, chain ID, genesis hash,
validator-set generation and checkpoint.

The checkpoint-certificate V1 format deliberately continues to support only
`pinnedV1`: its independently distributed, content-addressed policy must have
generation `1`. The checkpoint verifier does not accept a transitioned set,
so adding the transition protocol did not silently widen or weaken that API.

## Validator-set transition protocol

The separate `dualQuorumV1` transition format authenticates exact canonical
old-set and new-set digests. Every envelope also binds the root finality policy
digest, previous transition-certificate digest, signature domain, network,
chain ID, genesis hash, contiguous generations, activation time, authorization
deadline and transition ID. Old-set and new-set validators sign role-separated
messages, and each side must independently meet its strict weighted `>2/3`
quorum. New-set signatures establish proof of possession and acceptance; old
signatures alone cannot install attacker-selected or unusable keys.

The first link must start at an exact `pinnedV1` policy pin. Later links must
start from a live, non-cloneable `VerifiedValidatorSetTransition`, binding the
parent certificate and preventing replay onto a sibling branch. Generations
increase by exactly one. Manifests and certificates deny unknown JSON fields
and require canonical byte round trips; SHA-256 pins cover the complete
validated representation. The trusted-time audience is immutable across the
chain, and each capability is bounded by the certificate, new set,
predecessor and trusted-time deadlines.

## Checkpoints after a validator-set transition

The separate `transitionedValidatorSetV1` checkpoint format accepts only a
live `VerifiedValidatorSetTransition`. Its signed envelope binds the root
finality-policy digest, exact transition-certificate and predecessor-authority
digests, canonical validator-set manifest digest and generation, signature
domain, network, chain ID, genesis hash, exact checkpoint and exact verified
trusted-time token and audience. A certificate cannot therefore be replayed
onto a sibling transition, another generation, another network or a refreshed
time token. Signatures are checked against the transitioned manifest's strict
weighted quorum.

This is a new, role-separated envelope, certificate schema, signing prefix and
protocol identifier. It does not reinterpret or widen `pinnedV1`, and the
production qualification gate does not consume this capability. It proves a
certificate relationship only: it does not prove that production nodes
installed the transition, executed consensus with the set, selected a unique
fork, or made the checkpoint safe for settlement.

There is no implicit fallback, recovery key, quorum override, generation skip
or time-audience migration. Those require a separately reviewed protocol
version.

Verification requires `VerifiedTrustedTime`, with its policy and audience
pinned by the finality policy. This prevents production callers from selecting
their own wall-clock timestamp. The returned capability expires according to
the earliest of the finality policy and trusted-time token deadlines.

This crate does not fetch RPC data, prove checkpoint ancestry, implement EVM
or rollup consensus, establish validator organizational independence, persist
an anti-rollback checkpoint floor, or qualify a checkpoint for settlement.
Operators must establish those properties separately. In particular, a pinned
set and valid quorum signatures prove only that the configured keys signed the
exact checkpoint statement.

Likewise, a valid transition proves only that both configured key sets signed
one exact change-control statement. It does not prove that a node installed
the set, that the chain used it for consensus, that validators are independent
organizations, or that a unique transition was selected globally. A durable
external fork/rollback floor and deployed-consensus evidence remain mandatory
before operational qualification.
