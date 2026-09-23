# Authenticated receipt acknowledgement

This crate is the narrow mutation boundary between independently authenticated
delivery receipts and the durable indexer outbox. It verifies the canonical
delivery and receipt against a pinned sender/receiver policy and the exact
`DeliveryClaim`, then calls the core's lock-and-reload acknowledgement.

The snapshot transition stores the receiver ID and SHA-256 digests of the exact
trust policy, delivery and receipt alongside the acknowledged claim. It is one atomic
snapshot replacement, not an atomicity claim across separate files or systems.
The crate performs no network access, owns no private keys, and provides no
chain-finality or downstream-processing proof.
