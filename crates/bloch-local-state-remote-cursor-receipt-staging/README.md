# Remote cursor receipt staging

This crate is a Unix, single-host, fail-closed staging primitive between an
already-made CAS decision and external receipt signing. `prepare` creates one
immutable operation, durably retaining the exact canonical request, decision,
policy pin/domain, decision time, and exact signing message. `import` verifies
the externally signed receipt with the existing remote-cursor verifier before
durably publishing its canonical bytes and digest.

The preferred API starts from the public `ControlPlaneDecision` and a
`VerifiedTrustedTime`. It independently checks that the control-plane request
digest and ID bind the parsed canonical request, checks the trusted-time state
identity and remote-policy audience, and obtains both decision and evaluation
time from those opaque capabilities. The raw decision/time APIs remain only
for compatibility and tightly controlled offline ceremonies; production code
must not treat operator-supplied wall time as trusted.
Trusted-time freshness is checked again after temporary-file fsync and
immediately before publication (and before returning an idempotent replay).

The store is explicitly create-once. Exact prepare/import replays are
idempotent; request, decision, policy, time, signing-message, or receipt
substitution is refused. Files are owner-only, opened without following
symlinks, rejected when hard-linked, bounded, serialized by a bounded lock,
and updated by fsync/rename/directory-fsync/readback.

This crate has no private keys and performs no networking. It is not an HSM,
signer, challenge service, replicated CAS system, independent authority, or
high-availability service. A host/filesystem/VM snapshot can roll this
single-host state back; deployments still need independent replication and
anti-rollback evidence. An I/O error after rename is ambiguous: keep the
operation offline and reload it before retrying.
