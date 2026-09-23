# Bloch Data regulated-data boundary

Bloch Data must treat datasets received from exchanges, banks, brokers, DTVMs
and other regulated institutions as confidential by default. No dataset may be
admitted merely because transport or a signature is valid.

This document is an engineering control baseline, not a legal opinion or a
claim of regulatory compliance. Before each production integration, the
controller, operator and any subprocessor roles, lawful basis, contractual
purpose, permitted fields, jurisdictions, retention period and incident duties
must be approved by the responsible legal/privacy officers and the institution
that provides the data.

## Terminology

“Sensitive” is used here in the broader information-security and financial
market sense. A client identifier, order, trade, balance or custody position is
confidential and regulated even when it does not fall within the narrower legal
category of *dado pessoal sensível* in article 5 of the LGPD. Classification
must preserve both dimensions instead of assuming that all financial data has
the same statutory category.

## Fail-closed admission

Every dataset and derived output must carry a canonical, independently pinned
governance policy. Admission remains denied unless all of these fields are
present and consistent:

- institution and isolated tenant identity;
- dataset/schema identifier and allowed field classifications;
- documented purpose and approved processing operations;
- applicable jurisdictions and approved processing/storage regions;
- controller, operator, subprocessor and privacy-contact identifiers;
- legal/contractual authorization evidence digest and approval expiry;
- minimum necessary fields and explicitly forbidden fields;
- retention deadline, legal-hold state and deletion disposition;
- encryption-key domain and approved service/workload identities;
- permitted recipients, exports and derived-data classifications;
- audit, data-subject request and incident-response bindings; and
- versioned policy digest supplied separately from the data plane.

Unknown classification, purpose, tenant, region, recipient, expired approval,
missing policy, digest mismatch or unavailable control must reject ingestion,
query and export. A caller-provided `compliant: true` flag is never evidence.

## Required technical controls

1. Keep raw personal, account, order, trade, balance and custody data off public
   blockchains and public logs. Where a proof is necessary, retain only a
   domain-separated, properly blinded commitment that cannot be used as a lookup
   key for a person. A plain hash of predictable personal or financial data is
   not anonymization and is not safe to publish.
2. Enforce tenant and institution isolation in storage, keys, queues, caches,
   indexes, backups and audit views. Cross-tenant joins and exports default to
   denied.
3. Encrypt in transit and at rest using independently managed keys. Production
   decryption must require authenticated workload identity and least privilege;
   secrets and plaintext must not enter source control or operational logs.
4. Apply field-level classification and minimization before durable ingestion.
   Tokenization or pseudonymization reduces exposure but does not automatically
   make data anonymous or remove legal obligations.
5. Record append-only access and administrative events without copying protected
   payloads into the audit trail. Audit access is itself restricted and retained
   under an approved schedule.
6. Make retention and deletion executable: stop new processing at expiry,
   respect approved legal holds, delete or irreversibly anonymize eligible data,
   and track replicas, backups and derived datasets.
7. Provide controlled workflows for access, correction, portability, objection,
   restriction and deletion requests where applicable, with identity validation
   and an auditable decision rather than automatic destructive action.
8. Maintain incident detection, containment, evidence preservation and
   notification workflows with regulator- and contract-specific decisions made
   by authorized people.
9. Test restoration, key rotation, revocation, regional failover and emergency
   access. Availability must not bypass purpose, tenant or recipient checks.
10. Prevent production admission until privacy/security review, data-protection
    impact assessment when required, supplier review and institution acceptance
    are current and independently evidenced.

## Regulatory baseline to map per integration

- Brazil: the official [LGPD text](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709compilado.htm)
  and current [ANPD materials](https://www.gov.br/anpd/pt-br/centrais-de-conteudo).
- European Economic Area where applicable: the official
  [GDPR text](https://eur-lex.europa.eu/eli/reg/2016/679/oj), including purpose
  limitation, minimization, privacy by design/default and security controls.
- Brazilian regulated intermediaries where applicable: the current consolidated
  [CVM Resolution 35](https://conteudo.cvm.gov.br/legislacao/resolucoes/resol035.html),
  especially classification, confidentiality, access segregation, incident and
  third-party controls.
- Institutions in scope of Banco Central rules: the current cybersecurity and
  cloud/data-processing requirements published in the
  [BCB regulations portal](https://www.bcb.gov.br/estabilidadefinanceira/regulacao).
- Institution-specific exchange rules, market-data licences, secrecy duties,
  security schedules, data-processing agreements and audit rights. A contract
  with B3, A5X or another institution must be reviewed on its own terms; this
  repository does not infer authorization from the institution name.

Rules change and applicability depends on the actual data and roles. The legal
and DPO review must pin the exact versions and interpretation used for each
deployment; the software can enforce that reviewed decision but cannot make it.

## Current repository boundary

The repository now contains the canonical governance policy and a bounded JSON
ingestion adapter that derives its top-level field inventory, canonicalizes the
record and binds its digest to an opaque authorization. Before that governance
decision, an independently pinned canonical dataset schema validates required
and optional top-level booleans, bounded integers, byte-bounded strings and
bounded homogeneous scalar arrays. This v1 structural gate does not validate
nested or institution-specific business semantics, authenticity, truth or
legal authority. Signed lifecycle transitions can record legal holds, disposal
orders and references to external disposal evidence for an admitted record;
they never claim physical deletion, backup purge or regulatory compliance. A
salted SHA-256 record commitment is also available for offline equality checks,
but it is not a qualified hiding commitment and does not close the on-chain
privacy gate. Until deeper schemas, key management, tenant-isolated storage,
actual retention execution and incident/data-subject workflows are
implemented and independently qualified, Bloch Data is not admitted to ingest
production datasets from an exchange or regulated financial institution.

Lifecycle restart recovery requires independently retained state and context
roots, then replays every signed transition. This detects altered or rolled-back
local bytes when the independent roots are current; it is not a substitute for
durable protected storage of those roots.

The intended local/off-chain execution and minimized on-chain verification
boundary is specified in
[`BLOCH-DATA-HYBRID-ARCHITECTURE.md`](BLOCH-DATA-HYBRID-ARCHITECTURE.md).
