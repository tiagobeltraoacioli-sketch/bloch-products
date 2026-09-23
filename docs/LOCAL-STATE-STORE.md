# Secure local product-state store

`bloch-local-state-store` supplies the common single-host persistence boundary
for Bloch Data lifecycle state and Bloch Pay adjustment state. It stores their
exact canonical bytes without interpreting them.

## Safety contract

- one state identity per store directory;
- generation zero is create-once;
- every mutation names the exact independently retained predecessor and
  advances one generation;
- an exact retry after a crash is idempotent and is bound to its predecessor;
- load requires the exact independently retained current root;
- the envelope and state are bounded, canonical and SHA-256 bound;
- directories must be owned by the effective user and mode `0700` or stricter;
- lock and state files must be regular, single-link, owner-only files;
- symlinks, hardlinks, path replacement, corruption, stale roots, skipped
  generations and a lock held beyond the bounded wait fail closed; and
- replacement writes sync the temporary file, rename atomically and sync the
  directory.

The caller obtains `StateRoot::canonical_bytes()` after a successful write and
must send them to a separate authenticated root-retention system. A root read
from the same disk is not independent and cannot establish anti-rollback.
Root schema v2 also binds the preceding canonical root digest, so an
authenticated current root commits to its immediate CAS lineage. Version-1
roots and envelopes are intentionally rejected; there is no automatic in-place
migration of an existing store.

`bloch-local-state-checkpoint` can authenticate a root and semantic-manifest
digest with a threshold of externally held Ed25519 keys. Its policy binds the
environment domain and exact state identity, rejects duplicate authority IDs
and duplicate public keys, and checks checkpoint freshness.

`bloch-local-state-cursor` persists the exact authenticated checkpoint, root,
policy and semantic-manifest digests and permits only exact replay or an
immediate successor linked to the prior canonical root. Its expected current
cursor must come from an independently authenticated monotonic control plane.
Taking expectations from the checkpoint itself would permit replay of an old,
validly signed checkpoint. The local cursor is defense in depth only: it does
not prevent a privileged same-host rollback and supplies neither WORM retention
nor multi-host HA.

## Product composition

For Bloch Data, persist the exact result of `lifecycle_state_bytes`; after a
restart, call `load_state` with the independent root and then
`restore_lifecycle_state` with its independently pinned policy and lifecycle
expectation. For Bloch Pay, persist `AdjustmentState::canonical_bytes`; after a
restart, load against the independent root and call `restore_adjustment_state`
with its product-level expectation. The generic store never substitutes for
those signature, policy, context and transition-chain checks.

`bloch-local-state-admission` implements that read-only startup composition. It
requires the exact checkpoint artifact already fixed by the independently
authenticated cursor, verifies the signed product-specific semantic-manifest
digest, loads the complete root and then performs the Data or Pay restore. It
accepts retained checkpoints after their short issuance-freshness window only
because the exact artifact digest must already be present in that cursor; this
path cannot create or advance a cursor. Cursor and state locks are separate, so
all production writers and startup admission still need one shared outer
coordinator.

Use different directories and state identities for tenants and products. Do
not put private signing keys in a state directory.

## 8 GB node boundary

This component is small enough for an 8 GB Unix node. Capacity does not make
the node production-ready. Before deployment, inventory the candidate Genesis
3 or AuxPoW host, preserve the legacy service, pin the release artifact, create
a dedicated unprivileged account and separate filesystem paths, enable host
monitoring and backups, and establish independent root retention and restore
drills.

This store does not encrypt protected data, implement KMS/HSM, provide a
database, coordinate multiple hosts, prove physical erasure, qualify chain
finality, settle payments or move funds. Those remain separate production
gates.

Interrupted replacement may leave a private temporary file. The next writer,
while holding the bounded store lock, validates and removes only files matching
the store's random temporary-file namespace before proceeding. Until approved
encryption at rest exists, use synthetic pilot data only.

## Two-phase mutation

The direct `write_state`/CLI `update` path is administrative and must not be
used as a production writer coordinated with an external checkpoint service.
The coordinated order is:

1. authenticate current root/cursor and validate the product transition;
2. call `prepare_state`, which writes `pending.json` but leaves `state.json`
   unchanged;
3. obtain the threshold checkpoint and complete the external monotonic CAS;
4. re-fetch and verify the accepted external cursor;
5. call `promote_prepared_state` with the exact old and accepted roots; and
6. load and semantically restore the promoted Data or Pay state before ready.

Retries of the exact prepare and completed promotion are idempotent. A pending
candidate blocks direct writes, forks and a different prepare. An abandoned
candidate can be removed only with `discard_prepared_state` against both the
exact current and prepared roots, and only after the external CAS is known not
to have accepted it. If the candidate is already absent, discard fails closed
instead of claiming it observed an exact match. A cursor that advanced without
the matching pending bytes fails closed and requires authenticated recovery;
it must never synthesize a replacement from local state.

The local lock assumes cooperating writers. Run each store under a dedicated
UID with no unrelated code: another process already holding that UID can race
directory entries or cause denial of service, and Unix permissions cannot make
it an independent trust domain.
