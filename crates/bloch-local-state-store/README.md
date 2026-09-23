# Bloch local state store

Unix-only, bounded, crash-safe persistence for exact canonical product-state
bytes. The store uses a private directory, a bounded `flock`, compare-and-swap
generation checks, SHA-256 binding, atomic rename and file/directory `fsync`.
Version-2 roots bind the predecessor-root digest. Interrupted temporary files
use unpredictable names and are validated and removed under the next writer
lock; completed replacements are read back exactly before success is returned.

`write_state` returns canonical `StateRoot` bytes. Retain those bytes through an
independent authenticated channel; storing the only root beside `state.json`
would not detect rollback. `load_state` always requires that independent root.
After loading, the product crate must still perform semantic and signature
validation of the returned bytes.

The `bloch-local-state-store` binary exposes offline `init`, `update`, `load`
and `verify` operations. Inputs must be bounded owner-only regular files. The
sole exception is the exact `CREDENTIALS_DIRECTORY/state-root` path supplied by
systemd, which must have systemd's root-owned mode-0440 credential metadata.
Outputs are create-only mode-0600 files, and state is never written to stdout.
This is a low-level administrative interface: callers must validate Bloch Data
or Bloch Pay semantics before writing and after loading.

Production-oriented writers must use the library's two-phase path instead of
the direct `update` command: `prepare_state` durably stages `pending.json`
without replacing the current state; an external checkpoint/cursor authority
then accepts the exact candidate; only `promote_prepared_state` may atomically
replace current state. A pending candidate blocks direct writes and conflicting
prepares. `discard_prepared_state` removes only an exact candidate/current CAS
after the external authority has conclusively rejected or abandoned it. A
retry after the candidate is already absent fails closed as missing rather
than claiming that an unobserved candidate matched.

The bounded `flock` coordinates cooperating store processes; it is not a
sandbox against other code already running as the store owner. Each store must
use a dedicated UID that runs no unreviewed process, otherwise same-UID code
can race path entries or deny service even though symlink, hardlink and inode
checks fail closed when observed.

The store does not provide encryption, key management, authentication, backup,
replication, high availability, physical deletion, settlement or custody. It is
appropriate for a carefully administered single Unix host, including the
planned 8 GB Bloch Data/Bloch Pay node, only after host inventory and hardening.
The current deployment bundle is limited to synthetic state admission and does
not yet integrate authenticated checkpoints or a remote monotonic cursor.
