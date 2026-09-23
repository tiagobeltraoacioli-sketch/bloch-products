# Bloch indexer audit retention

This crate retains authenticated outbox audit artifacts in a local directory.
Each canonical, private `00000000000000000001.json` entry is created once and
commits to the preceding entry's SHA-256. Every replay requires the audit trust
policy and its independently provisioned SHA-256 pin, then verifies both the
artifact and its detached Ed25519 signature.
Callers that need to detect truncation or a privileged rewrite must retain the
entry count and head digest independently and pass a `RetentionExpectation` on
replay. The unkeyed hash chain alone cannot authenticate its own latest head.

The checkpoint API turns that external boundary into a bounded canonical
document. It binds the audit-policy digest, a stable operator-assigned ledger
ID, entry count, and head digest to a separate checkpoint-policy digest. An
external Ed25519 signer signs domain-separated bytes; verification requires the
checkpoint policy and its independently provisioned pin, never policy material
from the checkpoint itself. The ledger ID is path-independent, so moving a
verified directory does not change its identity.

`verify_retention_checkpoint_against_ledger` replays the complete ledger and
requires its count and head to match the signed checkpoint. If a previously
verified checkpoint is supplied, that boundary must remain an ancestor at the
same entry number. This detects tail rollback and history replacement. The
previous checkpoint and both policy pins still need independent retention.

The directory must already exist, be owned by the effective user, and have mode
`0700` or stricter. Entry files are opened relative to its verified descriptor,
use `O_NOFOLLOW`, are create-only with `O_EXCL`, and have mode `0600`. A crash
during the direct create may leave an invalid final entry; replay then fails
closed and an operator must preserve and investigate the directory.

This is bounded local tamper evidence. It is not immutable/WORM storage,
multi-host writer coordination, high availability, remote replication, custody,
network transport, private-key custody, or evidence of L2 finality. An attacker
who can replace the whole directory, authenticated checkpoint and external
policy pins is outside this crate's trust boundary.
