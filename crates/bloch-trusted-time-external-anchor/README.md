# Bloch trusted-time external anchor

Transport-neutral verification for an anti-rollback anchor authenticated by an
independently pinned threshold of Ed25519 authorities. An anchor binds one
monotonic external generation to the exact canonical `TrustedTimeBoundary`, a
fresh challenge and the Data/Pay state audience. Freshness is evaluated only
with an already verified `VerifiedTrustedTime` capability.

The crate performs no I/O, networking or signing and never handles private
keys. It does **not** make local files, processes, virtual machines or hosts
independent or rollback-resistant. TPM monotonic counters, WORM storage, a
remote counter service, challenge issuance/retention, authority independence,
transport authentication and production availability remain external
operational responsibilities.

Callers must canonically encode the returned `ExternalAnchorExpectation`, retain
those bytes in the independent system and parse them against independently
configured policy and audience pins after restart. Equal generation is an
idempotent replay only when the exact boundary is unchanged; a greater
generation may only advance the boundary. Verification also requires the
trusted-time attestation to have reached the externally anchored boundary, so
an authentic but older time token cannot reopen state. The encoding is
canonical, bounded and audience-bound, but is not self-authenticating: storage integrity,
authenticated transport, availability, and detection of omission or rollback
of the retained bytes remain responsibilities of the independent system.
