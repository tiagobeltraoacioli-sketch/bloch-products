# Remote cursor replica quorum verifier

This crate compares between 2 and 16 already authenticated remote-cursor
observations. Its canonical, independently pinned policy fixes the state
identity, remote cursor policy digest, quorum, replica IDs, declared provenance
IDs, trusted-time policy digest, absolute observation-age bound and a disjoint
exact signer-authority set for each replica.

Verification rejects duplicate replica IDs or observation digests, duplicate
declared provenance, signer mismatch, cross-state or cross-policy evidence,
different complete cursors at one generation, rollback against an independently
retained prior cursor, and a freshest cursor without a sufficiently co-temporal
quorum. The opaque result retains a canonical report and the complete cursor;
it never represents a partial-field or generation-only vote.

Every invocation requires an unexpired `VerifiedTrustedTime` whose state,
remote-policy and trusted-time-policy audience exactly matches the quorum
policy. Every supplied observation must be at or before that authenticated time
and have exclusive age below `maxObservationAgeSeconds`; equality is stale.
`maxObservationSkewSeconds` additionally limits timestamp spread within the
counted vote. Callers must still freshly collect each `VerifiedRemoteCursor`
with a unique nonce and qualified session.

No network or file I/O, key handling, endpoint authentication, replica
collection, persistence, consensus, leader election, fencing, replication or
HA is implemented here. Signer sets authenticate artifacts, while endpoint and
failure-domain independence remain operational facts that this crate cannot
prove. In particular, a valid report deliberately returns `false` for
consensus, linearizability and independence claims. A quorum comparison must
not be presented as proof that a write was linearized by a distributed system.
