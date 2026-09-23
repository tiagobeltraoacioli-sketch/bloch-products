# Bloch EVM consensus finality

Strict, transport-neutral verification of weighted Ed25519 validator signatures
over one EVM/L2 checkpoint. A successful verification returns a non-cloneable
capability bound to the exact policy digest, network, chain ID, genesis hash,
validator-set generation and checkpoint.

Version 1 deliberately supports only `pinnedV1`: the validator set is an
independently distributed, content-addressed policy and its generation must be
`1`. It does **not** accept validator-set transitions. A future transition
protocol must authenticate both the old and new sets and use a new schema; it
must not silently weaken this format.

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
