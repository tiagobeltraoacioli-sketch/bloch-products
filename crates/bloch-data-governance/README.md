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

## Offline lifecycle evidence

The `lifecycle` module adds a deterministic local state machine for records
already admitted by `authorize_json_ingestion`. Initialization binds the exact
record digest, dataset-schema digest and governance-policy digest. A separate,
canonical lifecycle authority policy is verified against an independently
provisioned SHA-256 pin and must repeat the governance retention deadline,
disposition and initial legal hold exactly.

Legal-hold placement/release, disposal ordering and evidence recording require
distinct authorized Ed25519 roles. A public key cannot be reused across those
actors. Every transition is signed externally over a domain-separated,
length-framed message containing the policy pin, exact record, prior state
digest, monotonic sequence and timestamp. The crate contains no private-key or
network API. Requests from the future, outside policy validity, against stale
state, before the retention deadline, under an active hold, or with the wrong
actor/disposition fail closed. The canonical state retains the signed audit
chain and a digest reference to externally held evidence.

`EvidenceRecorded` means only that an authorized actor signed a reference to
some external evidence. It does not validate that evidence's contents or prove
physical deletion, irreversible anonymization, backup/media purge, external
execution, legal sufficiency, or LGPD/GDPR/sector compliance. The corresponding
capability methods deliberately remain `false`. Durable storage, anti-rollback,
multi-writer serialization, key custody and execution by storage systems remain
deployment responsibilities.

The policy's `constructionId` is an allowlist binding, not cryptographic proof.
The operator must separately qualify and enforce a randomized, hiding
commitment implementation; a plain deterministic hash of PII or financial data
is not acceptable. Runtime facts such as time, region, workload identity and
the observed schema must come from authenticated platform controls. This crate
does not give legal advice, claim regulatory compliance, inspect arbitrary
payload bytes, manage keys, execute deletion, or publish transactions.

## Offline salted-record commitment

The crate includes the deliberately limited
`sha256-salted-authorized-record-v1` construction for offline equality checks.
It requires both an opaque authorized JSON ingestion and a separate opaque
`PublishCommitment` authorization under the same pinned policy. It commits only
to the exact, sorted `hiddenSourceFields` projection, and length-prefixes a
fixed preimage domain, policy digest, artifact rule, construction ID, policy
domain, independently pinned dataset-schema digest, field names and canonical
values, followed by an external nonce. The result can be passed through the
existing `authorize_onchain_commitment` gate. The nonce and opening never enter
the on-chain envelope.

The caller must generate a fresh, secret and unpredictable nonce for every
commitment using an approved CSPRNG. The API accepts 32 through 64 bytes and
rejects constant-byte values, but byte inspection cannot prove entropy,
freshness, uniqueness or secrecy. Nonce generation and reuse tracking are
therefore external operational controls. Reuse makes equal openings linkable;
loss of nonce secrecy permits offline guesses.

This salted SHA-256 construction is **not** a qualified hiding commitment.
Low-entropy identifiers, balances and other structured financial values remain
vulnerable to dictionary attacks when a nonce is weak, reused, disclosed or
compromised. It provides no zero-knowledge property, proof of knowledge,
binding beyond SHA-256 collision resistance, authenticated provenance,
consensus finality or regulatory compliance. Keep all source values, field
names, policy/schema digests and nonce material off-chain. A separately
reviewed commitment scheme and operational design are still required before
setting any `qualified_hiding_commitment` capability to true.
