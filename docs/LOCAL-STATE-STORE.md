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

## Product composition

For Bloch Data, persist the exact result of `lifecycle_state_bytes`; after a
restart, call `load_state` with the independent root and then
`restore_lifecycle_state` with its independently pinned policy and lifecycle
expectation. For Bloch Pay, persist `AdjustmentState::canonical_bytes`; after a
restart, load against the independent root and call `restore_adjustment_state`
with its product-level expectation. The generic store never substitutes for
those signature, policy, context and transition-chain checks.

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
