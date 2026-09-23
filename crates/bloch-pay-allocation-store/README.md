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

The store is local and deliberately narrow. It creates its directory with mode
`0700`, state and lock files with mode `0600`, rejects symlinks and hard links,
uses a bounded single-writer lock, and atomically replaces a canonical bounded
state snapshot after `fsync`. A byte-identical retry returns the original
receipt without rewriting state. A conflicting retry fails closed.

This component does **not** establish network finality, qualify settlement,
authorize credit, custody assets, or move/release funds. Those properties
remain `false` in every receipt. Authentication establishes only that the
pinned observer signed the exact canonical observation.
