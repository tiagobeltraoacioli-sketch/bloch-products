# Indexer service admission

The admission manifest is a reviewed deployment contract, not a
self-attestation. Its canonical SHA-256 must be provisioned through an
independent configuration path before evaluation.

It binds:

- the complete chain identity and exact block anchor;
- producer, delivery, audit, retention-checkpoint and data-governance policies,
  their canonical digests and deployment contexts;
- absolute normalized snapshot, spool, receiver-state and audit-ledger paths;
- explicit snapshot, spool, receiver and ledger identities; and
- separate evidence records for TLS, external signing, replica/WORM retention,
  distributed HA and actual data-governance enforcement.

The evaluator reparses every policy with the original policy implementation and
checks exact contexts, domains, receiver identity, ledger identity and service
workload binding. Each external capability is either unavailable with a bounded
reason code, or has a distinct bounded evidence ID and the digest of exact
reviewed evidence bytes.
Admission is derived from ten checks; all must pass. A valid governance-policy
pin and enforcement evidence are separate gates: neither substitutes for the
other.

The evidence digest authenticates byte identity only. It does not establish
that the evidence is truthful, fresh, independently operated or currently
healthy. The evaluator performs no filesystem, network, TLS, HSM, WORM or HA
probe. Production admission must therefore remain false until operators have
independently reviewed current evidence and pinned both that evidence and the
manifest.

Service admission does not establish L2 consensus finality and does not
authorize bridge execution, DEX liquidity, custody or any asset movement.
