# Bloch indexer audit retention

This crate retains authenticated outbox audit artifacts in a local directory.
Each canonical, private `00000000000000000001.json` entry is created once and
commits to the preceding entry's SHA-256. Every replay requires the audit trust
policy and its independently provisioned SHA-256 pin, then verifies both the
artifact and its detached Ed25519 signature.
Callers that need to detect truncation or a privileged rewrite must retain the
entry count and head digest independently and pass a `RetentionExpectation` on
replay. The unkeyed hash chain alone cannot authenticate its own latest head.

The directory must already exist, be owned by the effective user, and have mode
`0700` or stricter. Entry files are opened relative to its verified descriptor,
use `O_NOFOLLOW`, are create-only with `O_EXCL`, and have mode `0600`. A crash
during the direct create may leave an invalid final entry; replay then fails
closed and an operator must preserve and investigate the directory.

This is bounded local tamper evidence. It is not immutable/WORM storage,
multi-host writer coordination, high availability, remote replication, custody,
or evidence of L2 finality. An attacker who can replace the whole directory and
the external policy pin is outside this crate's trust boundary.
