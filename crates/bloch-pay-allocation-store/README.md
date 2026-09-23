# Bloch Pay allocation store

This Unix-only crate durably records how a reconciliation report allocated a
payment observation. It binds every entry to the canonical reconciliation
policy and report digests and prevents reuse of either an observation ID or a
`(network, transaction ID, event index)` tuple.

Allocation accepts only an `AuthenticatedPaymentObservation`. The associated
report must itself carry authenticated evidence for the exact observation
digest, observer ID, observer-policy digest, and reconciliation-policy digest.
A report produced from raw observations is rejected. Receipts durably retain
those authentication identities and pins.

`allocate_with_authorized_invoices` is the stricter issuance path. It also
requires every invoice in the report to carry authorization evidence under one
independently supplied authorization-policy pin. The receipt's report digest
therefore binds that issuer and invoice evidence. The lower-level `allocate`
API proves observation authentication only and must not be presented as an
invoice-authorization decision.

The store is local and deliberately narrow. It creates its directory with mode
`0700`, state and lock files with mode `0600`, rejects symlinks and hard links,
uses a bounded single-writer lock, and atomically replaces a canonical bounded
state snapshot after `fsync`. A byte-identical retry returns the original
receipt without rewriting state. A conflicting retry fails closed.

It can also export a canonical, self-contained checkpoint artifact. An
externally supplied Ed25519 signature binds the independently pinned checkpoint
policy, store identity, generation, canonical state digest, and creation time.
Verification additionally requires an independently obtained expected
generation and state digest, so a still-valid older signed snapshot cannot be
replayed as the current copy. The crate has no private-key or network API.

This component does **not** establish network finality, qualify settlement,
authorize credit, custody assets, or move/release funds. Those properties
remain `false` in every receipt. Authentication establishes only that the
pinned observer signed the exact canonical observation. A verified checkpoint
proves neither replication nor availability, quorum, consensus, leader
election, distributed consistency, nor disaster-recovery readiness.
