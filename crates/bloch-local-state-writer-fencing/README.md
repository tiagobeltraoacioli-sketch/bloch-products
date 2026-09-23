# Bloch local-state writer fencing

This crate verifies canonical threshold-Ed25519 writer lease certificates. A
verified capability is bound to one exact state identity, remote-cursor policy,
CAS service and CAS policy, and to a matching `VerifiedTrustedTime` capability.
It is intentionally non-cloneable and remains usable only until the earlier of
the signed lease expiry and the trusted-time capability expiry.

Success proves only that the pinned threshold signed the exact lease and that
its epoch is strictly greater than an independently supplied floor. A lease or
its signatures do **not** elect a leader, establish consensus, prove authority
independence, or durably store the fencing floor. Production requires an
independent, linearizable issuer and rollback-resistant floor storage; every
write must also be rejected by the authoritative CAS service when its epoch is
not the current epoch.

This crate performs no network, disk, leader-election, consensus, key-custody,
or private-key operations.
