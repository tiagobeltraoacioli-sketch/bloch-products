# Bloch Data threat model

## Scope and security posture

Bloch Data is intended to combine public-chain indexing with private,
institutional data supplied by exchanges, banks, brokers and other operators.
This hybrid architecture creates a confidentiality boundary that does not exist
in a public-chain indexer alone.

This document is a technical threat model, not a legal determination,
certification or claim of compliance. Legal and compliance owners must decide
whether data may be collected, processed, retained, transferred or deleted.
Bloch Data must enforce a reviewed, versioned and independently pinned policy;
it must not infer lawful basis, regulatory authorization or data-controller
roles.

The repository currently implements an offline, fail-closed canonical indexer,
authenticated producer and delivery protocols, durable receipt handling,
tamper-evident audit artifacts and service-admission contracts. It does not yet
implement the institutional privacy plane described below: tenant isolation,
field-level authorization, KMS-backed encryption, privacy-aware deletion,
regional enforcement or authenticated production networking remain deployment
gates.

Security objectives, in priority order, are:

1. prevent one tenant, workload or operator from reading or changing another
   tenant's data;
2. prevent private institutional data, identifiers and secrets from entering
   public-chain records, logs, proofs or immutable retention unintentionally;
3. preserve the integrity, provenance and replay resistance of accepted data;
4. make every sensitive read, export, policy change and deletion attributable;
5. fail closed when identity, policy, key, region, audit or durable-state
   evidence is absent, stale, conflicting or unverifiable; and
6. preserve availability without weakening confidentiality or authorization.

## Assets

The protected assets are:

- private institutional records, including positions, reconciliations,
  account-linked events and customer-supplied metadata;
- identifiers and linkage data capable of associating public addresses or
  transactions with persons, accounts or institutions;
- tenant, dataset, classification, purpose, jurisdiction and retention-policy
  metadata;
- canonical public-chain state, anchors, outbox records and delivery claims;
- derived indexes, materialized views, caches, query cursors and exports;
- encryption keys, signing keys, workload credentials and policy pins;
- producer, delivery, receiver, audit and retention trust policies;
- immutable audit commitments, retention checkpoints and independently stored
  evidence;
- deletion, legal-hold, export and break-glass decisions; and
- availability and recovery state, including backups and replicas.

Private keys, seed phrases, signing mnemonics and unrestricted third-party
credentials are prohibited input assets. Their appearance at an ingestion
boundary is a security event and must be rejected rather than stored.

## Trust boundaries

Bloch Data treats the following as distinct trust boundaries:

1. **Public-chain sources.** RPC nodes and producers may be faulty, stale,
   equivocating or malicious. Producer authentication does not establish
   consensus finality.
2. **Institutional ingestion.** Customer-controlled systems cross into a
   tenant-scoped processing plane. Authenticated origin does not make content
   correctly classified, minimized or safe.
3. **Tenant boundary.** Every tenant has an independent authorization and
   cryptographic context. Tenant identity supplied only inside an untrusted
   payload is not authoritative.
4. **Control plane.** Administrators configure schemas, classifications,
   purposes, regions, keys and retention. Control-plane authority is separate
   from data-plane read/write authority.
5. **Processing and storage.** Workers, databases, indexes, caches and backups
   may have different exposure and deletion characteristics. No implicit trust
   is inherited from network location.
6. **Query and export.** Interactive reads, webhooks and bulk exports cross
   from protected storage to caller-controlled destinations.
7. **Audit and evidence.** Audit ledgers and admission evidence must remain
   independently verifiable, but must not become repositories of sensitive
   payloads.
8. **Key and signer custody.** KMS/HSM and external signers are separate from
   application processes. A digest or signature proves byte identity and key
   use, not the truth, legality or freshness of the signed statement.
9. **Region and deployment boundary.** Scheduler labels, DNS names, request
   headers and cloud metadata are assertions, not sufficient proof of physical
   or legal processing location.

## Threats and required controls

### Cross-tenant access and confused-deputy operations

An attacker may replace a tenant identifier, reuse another tenant's cursor,
select a foreign encryption key, poison a shared cache, exploit an unscoped
administrative job or cause a privileged service to export data on its behalf.

Required controls:

- bind tenant, dataset, classification, purpose and policy version to the
  authenticated workload identity and to canonical ingestion, query, cursor,
  delivery, cache and export commitments;
- derive tenant context from independently authenticated configuration, never
  solely from payload fields or caller-selected headers;
- enforce deny-by-default RBAC and ABAC at every service and storage boundary,
  including background jobs and support tooling;
- use tenant-scoped namespaces and tenant/dataset encryption keys; require
  explicit, audited elevation for cross-tenant operations;
- include negative cross-tenant tests for every API, cursor, cache, export,
  backup restore and administrative workflow; and
- refuse requests when tenant identity, authorization context or policy pin is
  missing, ambiguous, expired or inconsistent.

### Insider misuse and privileged control-plane compromise

An authorized employee, contractor or compromised administrator may perform
unnecessary searches, broaden a schema, weaken retention, approve their own
export, rotate trust to an attacker key or use break-glass access as a normal
path.

Required controls:

- individual short-lived identities; no shared administrative accounts;
- separation of data-plane, policy, key, audit and infrastructure roles;
- dual authorization for bulk export, trust-policy change, tenant-key
  operation, legal hold, break-glass and destructive lifecycle changes;
- purpose-bound, time-limited elevation with immutable decision metadata and
  independent review;
- canonical policy diffs, signed releases and rollback-resistant policy
  versions; and
- alerts for unusual query breadth, cross-tenant attempts, mass export,
  repeated denials and emergency access.

No technical control eliminates coercion, collusion or compromise of enough
independent authorities.

### Sensitive data in logs, metrics, traces and errors

Payloads, addresses linked to customer identity, query filters, tokens,
signatures, URLs and error details may leak through observability systems,
which often have wider access and longer retention than source databases.

Required controls:

- structured logging with an allowlist of non-sensitive fields; payloads,
  authorization headers, credentials and raw customer identifiers are denied;
- opaque correlation IDs generated independently of personal or account data;
- stable public error codes without parser, storage, policy or cryptographic
  internals;
- redaction tests for success, rejection, retry, panic and debug paths;
- tenant-scoped access and bounded retention for observability data; and
- logging failure must not cause fallback to unredacted output. Security audit
  unavailability must block sensitive writes and exports where required by the
  reviewed policy.

### Hash dictionary and commitment attacks

A plain hash of a low-entropy identifier, account number, email address,
categorical value or small document does not anonymize it. An attacker can
enumerate candidates and compare their hashes. Stable hashes also permit
linkage across tenants, datasets and time.

Required controls:

- never place direct hashes of low-entropy sensitive values in public or
  broadly accessible proofs;
- commit to already minimized canonical records using tenant- and
  purpose-specific keyed commitments or suitably blinded constructions;
- keep commitment keys separate from application and audit storage, with
  rotation and revocation procedures;
- domain-separate every commitment by tenant, dataset, schema, purpose and
  version; and
- review proof metadata and cardinality for inference before publication.

SHA-256 checksums and the hash chains already implemented by the indexer detect
specific integrity failures; they are not confidentiality or anonymization
mechanisms.

### Correlation and re-identification

Even when direct identifiers are removed, timestamps, amounts, addresses,
transaction sequences, rare attributes, pagination behavior and repeated
exports may allow public-chain activity to be associated with a customer.

Required controls:

- field-level minimization and purpose-specific views rather than a universal
  institutional record;
- independent pseudonyms across tenants and purposes;
- query breadth, time-range, rate and result-size limits; aggregation or
  suppression where the intended use permits it;
- no globally stable customer-derived cursor, cache key, trace ID or export
  identifier; and
- explicit re-identification review for new joins, derived features and proof
  formats.

Pseudonymization reduces exposure but does not make linkable data anonymous.

### Malicious, stale or over-broad policy

A policy can be correctly signed and still be unsafe, obsolete, legally
inapplicable or malicious. An attacker may replay an old policy, embed a policy
inside input, substitute a permissive schema or exploit an undocumented
default.

Required controls:

- strict versioned schemas, canonical encoding, bounded size and independently
  retained policy digests;
- effective and expiry bounds, monotonic policy generation and explicit
  predecessor linkage;
- separate approval for classification, authorization, region and lifecycle
  changes;
- no payload-supplied policy, key or success assertion is authoritative;
- unknown fields, unknown classifications, missing purposes and unsupported
  versions fail closed; and
- policy evaluation produces bounded reason codes and auditable evidence, not
  a claim that the policy is legally sufficient.

### Region spoofing and unauthorized transfer

A workload may claim an allowed region while running elsewhere, use a remote
backup or logging endpoint, or export through an approved service to an
unapproved destination.

Required controls:

- deployment admission tied to attested workload identity, approved cluster,
  storage location, KMS key location and egress policy;
- region-scoped keys that cannot be used by workloads outside the admitted
  boundary;
- default-deny network egress and allowlisted replication, backup, telemetry
  and export destinations;
- signed inventory and continuous reconciliation of replicas and backups; and
- stop affected ingestion, replication and export when location evidence is
  absent, stale or conflicting.

These controls provide evidence about configured and observed infrastructure;
they do not by themselves establish legal data residency.

### Deletion, legal hold and immutable/WORM conflict

Raw sensitive data placed in an immutable audit ledger, signed proof or WORM
replica may become technically impossible to delete without destroying the
integrity history. Backups, caches and derived indexes may silently retain
deleted data.

Required controls:

- immutable ledgers contain only non-reversible, domain-separated commitments
  and minimal operational metadata, never raw institutional payloads or direct
  low-entropy hashes;
- mutable sensitive data is encrypted with dataset-scoped keys so approved
  crypto-erasure can make residual ciphertext inaccessible;
- retention, deletion and legal hold are explicit, versioned policies with
  separate authorization; a hold cannot be inferred by the application;
- deletion propagates to primary data, indexes, caches, exports, replicas and
  backup-expiry schedules, producing a bounded completion record;
- new ingestion is refused when no applicable retention policy exists; and
- conflicts between a verified deletion instruction and an active hold are
  surfaced for authorized resolution, never silently resolved by precedence.

Commitment retention may still reveal timing, volume or linkage and therefore
requires its own reviewed lifecycle.

### Replay, rollback and duplicate processing

An attacker may replay an authenticated block, institutional event, delivery,
receipt, export approval, deletion order or old service-admission evidence.
Crashes may repeat externally visible actions.

Required controls:

- domain-separated signatures bind tenant, dataset, network, schema, purpose,
  policy generation, stable record ID, attempt and generation;
- durable idempotency state is persisted before external side effects;
- bounded validity windows and monotonic sequence/generation checks for
  institutional commands;
- independently retained checkpoints detect audit or policy rollback; and
- exact replay may recover the prior result, while changed content under an
  existing identity or stale generation is rejected.

The existing delivery state machine and receiver core provide these properties
for indexer outbox deliveries. They do not automatically extend to future
institutional ingestion, deletion or export protocols.

### Proof and audit metadata leakage

Signed proofs may disclose customer presence, tenant names, volume, event
counts, topology, signer identities, processing times or business activity even
when payloads are omitted. Public verification can amplify this leakage.

Required controls:

- use opaque, random tenant and dataset references in externally shared
  evidence;
- minimize counts, timestamps, paths, hostnames and signer/operator details;
- separate internal audit artifacts from externally shareable attestations;
- authorize proof generation and destination as a sensitive export;
- document the disclosure surface of every proof schema and reject unexpected
  metadata; and
- prefer selective or aggregated evidence when exact values are unnecessary.

A valid signature authenticates the disclosed metadata; it does not make that
disclosure safe.

### Key, signer and evidence compromise

Compromised application credentials, KMS keys, signers or admission evidence
can authenticate malicious actions or expose stored data.

Required controls:

- keys are non-exportable where supported, separated by role, tenant, dataset
  and environment, and unavailable directly to general application code;
- signing remains external to offline verification and ceremony components;
- rotation and revocation are generation-bound and do not silently reinterpret
  historical records;
- service admission requires distinct evidence for transport protection,
  signer custody, retention and high availability; and
- key or evidence unavailability fails closed for new sensitive operations,
  while bounded read-only recovery follows an explicitly admitted policy.

## Control-plane admission

A production Bloch Data deployment handling institutional data must remain
unadmitted unless all of the following have current, independently reviewed
evidence and exact pinned configuration:

- tenant isolation and authorization-matrix tests;
- approved data classification and field-minimization schema;
- workload identity, transport authentication and default-deny egress;
- tenant/dataset encryption and KMS/HSM custody;
- region, replica, backup and recovery inventory;
- log and trace redaction tests;
- retention, deletion, legal-hold and crypto-erasure procedures;
- tamper-evident, payload-free audit retention;
- external-signing and trust-policy custody; and
- incident isolation, key revocation and restore exercises.

Evidence digests establish the identity of reviewed evidence only. Admission
must state unavailable when a verifier cannot establish a required property;
caller-provided booleans or self-attested success are insufficient.

## Residual risks

The following risks remain even when the required controls operate correctly:

- public-chain data can be re-identified through external datasets;
- authorized users can misuse data visible for their legitimate role;
- colluding or sufficiently compromised independent authorities can approve a
  malicious policy, export or proof;
- hardware, cloud control planes, KMS/HSM implementations and cryptographic
  algorithms may contain unknown vulnerabilities;
- traffic shape, timing, proof size and availability can reveal activity;
- deletion cannot retract data previously exported to or recorded by an
  external party, nor erase public-chain source data;
- legal requirements and institutional agreements can conflict or change
  faster than software policies; and
- high availability, disaster recovery and confidentiality can conflict during
  emergency operation.

These risks must be recorded for each deployment and accepted by accountable
business, security, privacy and legal owners. Technical admission is necessary
but is not proof of compliance or authorization to serve a regulated entity.
