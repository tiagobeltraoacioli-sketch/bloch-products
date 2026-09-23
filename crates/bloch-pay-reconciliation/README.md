# Bloch Pay reconciliation core

This crate performs deterministic, offline matching of canonical invoices to
payment observations under an independently pinned route/source policy. It
uses integer minor units, prevents observation reuse, rejects route
substitution and reports exact, partial, excess, late and unmatched evidence.

The optional offline authentication layer verifies an exact canonical
observation with Ed25519. Its independently pinned observer policy binds each
public key to one observer, source and network, and is itself bound to the
pinned reconciliation policy, tenant and merchant. Signing bytes use explicit
domain separation and length framing. The detached JSON signature envelope is
strictly bounded and canonical; duplicate, unknown and trailing fields fail
closed. Private keys never enter this crate.

An authenticated observation is still not settlement or finality proof. The
authenticated result keeps `finalityQualified`, `settlementQualified` and
`creditAuthorized` false. This crate connects to no chain, bank or Pix system,
broadcasts nothing and cannot release goods, credit an account or move funds.

Typical offline flow:

1. Parse the reconciliation and observer policies against digests provisioned
   independently.
2. Parse the observation as exact canonical JSON.
3. Export `observation_signing_bytes` to the external key holder.
4. Import its raw 64-byte signature with
   `encode_observation_signature_envelope`.
5. Verify the envelope and detached observation with
   `verify_authenticated_observation` before reconciliation.
6. Pass only those opaque verified values to `reconcile_authenticated`; its
   report exposes read-only evidence references for every observation.

The legacy `reconcile` path remains available for offline matching of raw
observations, but its report always sets `observationsAuthenticated` to false
and emits unauthenticated evidence references without cryptographic digests.

The wire contract and security boundary are detailed in
[`AUTHENTICATED-OBSERVATIONS.md`](AUTHENTICATED-OBSERVATIONS.md).

Production still requires qualified and operationally independent observers,
network-specific finality evidence, durable allocation/idempotency, regulated
payment partners, privacy governance and an independently approved credit
policy. A valid public-key signature establishes only origin and integrity in
the pinned context; it makes no statement about the truth of the observed
event or current health of the source.
