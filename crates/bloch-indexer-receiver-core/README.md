# Bloch indexer receiver core

Durable, transport-neutral receiver-side processing for authenticated indexer
deliveries. It verifies a pinned delivery policy, persists one accepted outcome
per canonical record, persists each delivery-attempt acceptance before exposing
the exact receipt-signing bytes, and imports an external Ed25519 signature into
a recoverable canonical response.

Exact replay returns the same signing message or completed response. If a
response is lost, a new attempt can receive a new attempt-bound receipt without
repeating the record outcome. Changing the policy or canonical record for an
already admitted record fails closed and requires an explicit operator
migration decision.

The store must be a private Unix directory. State is create-once and protected
against symlinks, hardlinks, permissive ownership/modes and descriptor/path
replacement. The local advisory lock has a bounded wait.

This crate opens no socket, owns no private key, performs no sender ACK or
business side effect, and proves neither chain finality nor downstream
settlement. Network service, HSM/KMS signing, HA and replication remain outside
its boundary.
