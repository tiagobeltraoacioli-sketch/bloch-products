# Bloch Data hybrid off-chain/on-chain architecture

Bloch Data should execute confidential workloads locally or in an isolated
institutional environment. A chain may verify narrowly scoped public results,
but must not become the database, message bus or audit log for protected data.

## Processing boundary

```text
institution source
       |
       v
authenticated encrypted intake
       |
       v
local/off-chain policy enforcement --> tenant-isolated encrypted storage
       |                                      |
       |                                      v
       |                              private audit/access log
       v
canonical minimized statement
       |
       v
proof/commitment builder with fresh blinding
       |
       v
on-chain verifier/registry (proof + public commitment + policy/version IDs)
```

The off-chain result is not publishable by default. A separately pinned release
policy must classify the exact output and authorize its destination. The
publisher recomputes the canonical bytes, verifies policy and proof context,
then rejects any field not on the on-chain allowlist.

## Placement rules

| Material | Default placement | Reason |
| --- | --- | --- |
| PII, KYC documents, account identifiers | Off-chain only | Identifies or links a person/account |
| Orders, trades, balances, positions and custody records | Off-chain only | Confidential client/market information |
| Institution raw feeds and licensed market data | Off-chain only | Contractual and redistribution restrictions may apply |
| Encryption keys, salts, blinders and credentials | Off-chain HSM/KMS only | Publishing destroys confidentiality |
| Tenant mapping, access policy and legal basis | Off-chain only | Security metadata can itself be sensitive |
| Detailed audit events | Off-chain restricted ledger | Actor/resource linkage can reveal protected activity |
| Public chain/network identifiers and verifier version | On-chain eligible | Needed to interpret verification |
| Domain-separated blinded commitment/Merkle root | Conditionally on-chain | Safe only after correlation and dictionary-attack review |
| Zero-knowledge proof and public inputs | Conditionally on-chain | Public inputs and proof metadata require the same review |
| Aggregate/statistical output | Conditionally on-chain | Requires re-identification and contractual disclosure review |
| Already public, redistributable source data | Conditionally on-chain | Licence, provenance and integrity still must be verified |

“Conditionally on-chain” means explicit approval by policy; it never means an
automatic fallback. On-chain bytes are assumed globally visible, copyable and
effectively irreversible.

## Commitment and proof safety

A direct hash of a CPF, account, order, balance or other predictable value can
be guessed offline and therefore must not be treated as private. Commitments
must use a reviewed construction, domain separation and high-entropy fresh
blinding retained off-chain. The commitment binds at least:

- protocol and statement schema versions;
- institution/tenant-scoped opaque context, not a public client identifier;
- source snapshot/version and canonical statement digest;
- purpose and release-policy digest;
- chain ID and verifying-contract identity; and
- expiry or epoch where replay must be bounded.

Zero-knowledge systems require a separate cryptographic review, trusted-setup
decision where relevant, deterministic circuit/version management, constrained
public inputs and adversarial tests. “ZK” does not make unsafe public inputs,
side channels or contract events private.

## Local deployment profiles

- **Institution managed:** packaged worker and verifier run inside the bank,
  exchange, broker or DTVM boundary; the institution owns storage and keys.
- **Dedicated managed tenant:** isolated compute, network, database, keys and
  backups per institution, with contractually approved regions and operators.
- **Offline batch:** signed/encrypted input package enters an isolated job; the
  output is a signed result/proof package with no persistent raw-data copy unless
  the retention policy explicitly permits it.

For the current development profile, a formally released 8 GB Unix node formerly
running Genesis 3 or AuxPoW can host the bounded lifecycle-state service. Each
record uses a distinct `bloch-local-state-store` directory. The service writes
canonical lifecycle bytes with the lifecycle sequence as its compare-and-swap
generation, while an authenticated control plane retains the returned root
outside the node. Restart admission first checks the local envelope against that
independent root and then replays the lifecycle state against independently
pinned policy, schema and record context. The node must not retain the only copy
of either class of root.

This profile is single-host and fail-closed. It is not a confidential execution
runtime, encrypted database, replica, backup, HSM/KMS, HA service or compliance
certification. Discovery and safe retirement of the previous workload precede
installation; unknown legacy processes or ownership make admission fail closed.

Shared multi-tenant processing remains denied until isolation, authorization,
key separation, query controls, deletion and backup behavior pass independent
qualification. A local deployment is not automatically compliant: software,
operators, updates, telemetry and support access remain part of the assessment.

## Cryptographic integration envelope

The interface between the private processor and an on-chain publisher should
contain canonical versioned bytes with:

- statement type, verifier/circuit version and domain;
- chain ID and verifying-contract address;
- public inputs and proof or blinded commitment;
- source-policy and release-policy digests;
- freshness/expiry and replay identifier;
- authorized external signer identity and signature; and
- no arbitrary metadata or extensible user-provided fields.

The on-chain contract must fail closed on unknown versions, wrong chain/domain,
expired or replayed statements, unapproved signer/verifier, malformed proof or
policy revocation. Contract events must emit only the approved public subset.

## Current status

This repository now contains an offline salted-record commitment for authorized
record projections and a signed retention/legal-hold evidence state machine.
The former cannot prove nonce entropy or hiding strength; the latter records an
external evidence reference but cannot execute or prove physical deletion.
Canonical lifecycle bytes can also be placed in a crash-safe, single-host Unix
store with local compare-and-swap and checked against an independently retained
root before semantic replay. This closes neither encryption nor protected root
custody, replication, backup recovery or HA.
The repository still does not contain the confidential execution runtime,
tenant-isolated encrypted store, KMS/HSM integration, privacy release policy,
qualified commitment/proof circuit or on-chain verifier described above. They
remain production gates.
