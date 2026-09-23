# Bloch Data governance gate

`bloch-data-governance` is an offline, fail-closed policy engine for regulated
data. It verifies canonical policy bytes against an independently provisioned
SHA-256 pin and evaluates tenant, institution, dataset/schema, purpose,
operation, jurisdiction, processing/storage region, workload, encryption-key
domain, recipient, field-minimization, approval and retention constraints.

Every field value remains off-chain in v1. A field is either
`off_chain_only`, or `off_chain_commitment_source`, which permits the value to
be used only as a hidden input to an allowlisted commitment construction. The
only public artifact produced by this crate is a nonzero 32-byte commitment
envelope. It contains no tenant, person, account, order, trade, balance,
position, custody, dataset, policy digest, field value, or arbitrary metadata.
The envelope's `authorizationContextSha256` is domain-separated over the pinned
policy digest, artifact rule, construction ID, domain and the commitment
itself. It binds that exact commitment to its off-chain authorization context
without publishing the policy digest or protected identifiers. Because the
commitment participates in this digest, correctly randomized commitments do
not create a stable cross-artifact identifier. Reuse of the same commitment is
still visibly linkable and must be rejected by the transaction layer.

The opaque `AuthorizedDecision` can only be produced after every governance
check passes. `authorize_onchain_commitment` additionally requires the exact
artifact rule, construction ID, domain and complete hidden-source inventory.
Unknown fields, extra recipients, cross-tenant requests, expired approvals,
unapproved regions and legal-hold deletion all fail closed.

`authorize_json_ingestion` closes the caller-declared field-inventory gap for a
bounded JSON record. Before policy authorization it parses a canonical
`bloch.data.dataset-schema.v1` document and verifies its SHA-256 against an
independently provisioned pin. The schema ID must equal both the policy and
runtime context. Schema documents reject unknown/duplicate/trailing content and
must declare a sorted, unique field inventory.

The v1 record model is deliberately narrow: top-level fields may be boolean,
signed 64-bit integer, byte-bounded UTF-8 string, or a bounded homogeneous
array of one of those scalar types. Fields are explicitly required or optional.
Objects, nulls, floating-point numbers, unknown fields, duplicate keys at any
depth, invalid bounds and trailing JSON all fail closed. The function emits
deterministic canonical JSON, a record SHA-256, and the exact admitted schema
digest. Equivalent object-key ordering therefore cannot create a second record
identity.

This validation proves only that bytes conform to the exact pinned structural
contract. It does not establish that values are true, current, authentic,
lawful, correctly classified, or compliant with LGPD, GDPR or sector rules.
Those decisions and authenticated provenance remain separate admission gates.

The policy's `constructionId` is an allowlist binding, not cryptographic proof.
The operator must separately qualify and enforce a randomized, hiding
commitment implementation; a plain deterministic hash of PII or financial data
is not acceptable. Runtime facts such as time, region, workload identity and
the observed schema must come from authenticated platform controls. This crate
does not give legal advice, claim regulatory compliance, inspect arbitrary
payload bytes, manage keys, execute deletion, or publish transactions.
