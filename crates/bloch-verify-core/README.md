# Bloch Verify core

Strict, transport-neutral verification primitives for Bloch Verify.

The `checkpoint_ancestry` module turns one bounded, internally valid
`EvmAncestryEvidence` chain into a non-cloneable capability only after a
canonical independently pinned policy, exact bundle/network/checkpoint/terminal
anchor, threshold Ed25519 signatures and matching `VerifiedTrustedTime` have
all been verified. Authority organizations, control domains and non-weak keys
must be distinct.

The qualification API accepts it through `ProductionGateCapabilities`.
Omission or any pin/audience/freshness mismatch fails `CheckpointAncestry`.
The older organizational-independence wrapper remains available.

An ancestry capability authenticates parent linkage from the assessed
checkpoint to a later pinned anchor. It never authenticates validator-set
transitions, quorum weight or protocol consensus finality; that separate gate
remains unavailable.
