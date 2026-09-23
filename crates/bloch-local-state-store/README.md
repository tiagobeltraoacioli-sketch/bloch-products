# Bloch local state store

Unix-only, bounded, crash-safe persistence for exact canonical product-state
bytes. The store uses a private directory, a bounded `flock`, compare-and-swap
generation checks, SHA-256 binding, atomic rename and file/directory `fsync`.

`write_state` returns canonical `StateRoot` bytes. Retain those bytes through an
independent authenticated channel; storing the only root beside `state.json`
would not detect rollback. `load_state` always requires that independent root.
After loading, the product crate must still perform semantic and signature
validation of the returned bytes.

The store does not provide encryption, key management, authentication, backup,
replication, high availability, physical deletion, settlement or custody. It is
appropriate for a carefully administered single Unix host, including the
planned 8 GB Bloch Data/Bloch Pay node, only after host inventory and hardening.
