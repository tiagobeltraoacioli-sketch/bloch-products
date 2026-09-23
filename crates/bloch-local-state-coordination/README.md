# Bloch local state coordination

This crate supplies one bounded, owner-only Unix `flock` that callers hold
around a complete local state/checkpoint/cursor transition or read-only
startup-admission closure. The closure receives an unforgeable scoped
capability so coordination is explicit at composition boundaries.

All local writers and admission readers for a state identity must use the same
coordination directory. Operations that bypass this crate are not serialized.
The lock protects only cooperating processes on one Unix host using a
qualified local filesystem with reliable `flock` semantics. It does not
provide distributed locking, cross-host atomicity,
remote fencing, consensus, replication, durability or high availability.

The directory must be owned by the effective user and have no group/world
permissions. The lock must be a single-link, owner-only regular file. Symlinks,
hardlinks, path replacement, unsafe permissions and lock contention fail
closed. Acquisition is bounded rather than waiting indefinitely.
Operational acquisition never creates a missing directory or lock file.
Provision each fixed pair explicitly with
`provision_local_state_coordination_directory` before starting the service.

```rust,no_run
use bloch_local_state_coordination::{
    provision_local_state_coordination_directory,
    with_coordinated_startup_admission,
};
use std::path::Path;

let directory = Path::new("/run/bloch/product-a");
provision_local_state_coordination_directory(directory)?;
let result = with_coordinated_startup_admission(directory, |scope| {
    assert!(scope.local_exclusion_held());
    // Load/verify both state and cursor, or perform the complete transition.
    Ok::<_, std::io::Error>(())
});
assert!(result.is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `with_coordinated_state_transition` for the writer sequence. Both named
entry points intentionally share the same underlying lock and capability.
