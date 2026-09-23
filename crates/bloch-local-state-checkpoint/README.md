# Bloch local state checkpoint

Threshold-authenticated anti-rollback roots for `bloch-local-state-store`.
The crate builds domain-separated bytes for external Ed25519 authorities,
assembles only signatures that meet an independently pinned policy threshold,
and verifies canonical checkpoints against exact identity, generation, state
digest and freshness expectations.

Private keys never enter this crate. Authority independence is an operational
qualification and is never inferred from multiple public keys. The signed
checkpoint must be retained outside the state-store host, and the expected
generation must also come from that independent control plane; otherwise an
old but valid checkpoint can be replayed.

This authenticates a local state root. It does not validate Bloch Data or Bloch
Pay semantics, encrypt state, prove consensus finality, provide backup/HA, or
authorize settlement, custody, credit, deletion or release of data.
