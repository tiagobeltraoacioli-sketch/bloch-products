# Bloch indexer delivery protocol

Offline, versioned Ed25519 protocol for authenticating one outbox-record delivery and the receiver's acceptance receipt. The crate performs no network, file, key-generation, or durable-state operations.

A receipt proves only that a policy-pinned receiver signed acceptance of the exact canonical delivery envelope. It is not L2 finality, bridge finality, canonical-chain evidence, or an automatic acknowledgement of `DurableState`.
