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

Invoice issuance has a separate offline authorization boundary. An
independently pinned canonical policy binds each Ed25519 issuer key to an
explicit set of route IDs and to the reconciliation-policy digest, tenant and
merchant. The domain-separated signature covers that complete context, the
authorization time and the exact canonical invoice bytes. Successful
verification returns an opaque `AuthorizedInvoice`; the protected
`reconcile_authorized_invoices` API accepts no raw `Invoice` values.

An authenticated observation is still not settlement or finality proof. The
authenticated result keeps `finalityQualified`, `settlementQualified` and
`creditAuthorized` false. This crate connects to no chain, bank or Pix system,
broadcasts nothing and cannot release goods, credit an account or move funds.

The optional finality-attestation layer accepts only an opaque authenticated
observation. Its independently pinned canonical policy binds Ed25519 authority
keys and a signature threshold to each network. Every signature covers the
exact canonical observation digest, transaction/event identity, observed block
and an exact same-block checkpoint. Policy validity and evidence freshness are
bounded, duplicate authorities cannot count twice, shared keys are rejected,
and disagreeing checkpoints never combine.

Meeting that signature threshold produces only an opaque
`ThresholdFinalityAttestation`. It reports `attestationThresholdMet` while
keeping `network_finality_qualified()`, settlement, credit and funds release
false. The only positive getter is `attestation_threshold_met()`.
Authority attestations are not native consensus or ancestry proofs; production
still needs a separately qualified finality receipt sourced from the network.

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

For protected invoice issuance, parse the authorization policy against its
independently provisioned SHA-256 pin, export
`invoice_authorization_signing_bytes` to the external key holder, verify the
detached result with `verify_authorized_invoice`, then pass only opaque
authorized invoices to `reconcile_authorized_invoices`.

The legacy `reconcile` path remains available for offline matching of raw
observations, but its report always sets `observationsAuthenticated` to false
and emits unauthenticated evidence references without cryptographic digests.
It is not the protected invoice-authorization path.

The wire contract and security boundary are detailed in
[`AUTHENTICATED-OBSERVATIONS.md`](AUTHENTICATED-OBSERVATIONS.md) and
[`INVOICE-AUTHORIZATION.md`](INVOICE-AUTHORIZATION.md).
The finality-attestation boundary is detailed in
[`FINALITY-ATTESTATIONS.md`](FINALITY-ATTESTATIONS.md).

Production still requires qualified and operationally independent observers,
network-specific finality evidence, durable allocation/idempotency, regulated
payment partners, privacy governance and an independently approved credit
policy. A valid public-key signature establishes only origin and integrity in
the pinned context; it makes no statement about the truth of the observed
event or current health of the source.
