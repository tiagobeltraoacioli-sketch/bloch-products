# Bloch indexer service admission

This crate evaluates an offline, fail-closed admission manifest. The canonical
manifest is independently pinned and binds the full network identity and block
anchor, the producer, delivery, audit, checkpoint and data-governance policies,
and absolute normalized storage paths with stable snapshot, spool, receiver and
ledger identities.

Each policy is reparsed by its owning crate. TLS, external signing,
replica/WORM retention, HA and data-governance enforcement must each provide a
distinct bounded evidence ID and SHA-256 digest, or explicitly remain
unavailable. All ten checks must pass; there is no caller-provided admission
boolean. Pinning a governance policy does not prove that a deployment enforces
it, which is why enforcement has a separate evidence gate.

An evidence digest proves only that the exact reviewed bytes were supplied. It
does not prove that a claim in those bytes is true, current or operational. This
crate performs no filesystem or network probe, deploys nothing, owns no private
key and proves neither consensus finality nor authorization for custody, bridge,
DEX or other asset movement.
