# Bloch Pay observation reconciliation

The first Bloch Pay implementation is deliberately non-custodial. It matches
canonical invoices to payment observations offline and reports what was
observed; it does not decide that payment settled and cannot authorize credit,
release, transfer or any other value-moving action.

## Pinned policy

The canonical reconciliation policy is independently pinned by SHA-256 and
binds:

- tenant and merchant identities;
- policy validity and maximum invoice lifetime;
- sorted, bounded observation source IDs; and
- sorted payment routes with network, asset, minor-unit exponent and exact
  destination.

A source ID by itself remains only an allowlist selector. The authenticated
path additionally verifies an exact canonical observation with a
domain-separated Ed25519 signature and an independently pinned observer trust
policy. That policy binds the observer key to the tenant, merchant, source,
network and reconciliation-policy digest. Cryptographic authentication does not
prove the observer is independent or operationally qualified.

## Deterministic matching

Invoices contain an opaque, unique reference, route, integer amount in minor
units and bounded validity period. Observations contain the actual network,
asset, destination, transaction/event identity, block reference, amount and
observation time.

The reconciler:

- refuses cross-tenant or cross-merchant invoices;
- refuses an observation whose route differs from the invoice route;
- prevents reuse of an observation ID or network transaction/event identity;
- rejects observations from the future or before invoice issuance;
- excludes observations at or after invoice expiry as late;
- reports unknown references as unmatched;
- checks amount addition for overflow; and
- sorts invoices and evidence deterministically.

The result can be `no_observation`, `partial_observed`, `exact_observed` or
`excess_observed`. These are comparison states, not payment states. Every report
and every invoice result encodes both `settlementQualified: false` and
`creditAuthorized: false`; callers cannot provide or deserialize a success
claim into the report.

`reconcile_authenticated` accepts only opaque values produced by successful
signature verification. Its report retains the observation, observer-policy
and reconciliation-policy digests. The raw reconciliation function is
explicitly marked unauthenticated and its report cannot enter the durable
allocation store.

The Unix-only allocation store persists an authenticated allocation under a
bounded single-writer lock. It rejects conflicting allocation IDs, observation
IDs and network transaction/event identities; exact retries return the same
receipt. This is local crash-safe idempotency, not distributed consistency.
The stricter allocation API additionally refuses reports without exact,
independently pinned invoice-authorization evidence.

Invoice issuance can now be authenticated offline against a pinned Ed25519
issuer policy bound to tenant, merchant, routes and the reconciliation policy.
The protected reconciliation path accepts only opaque authorized invoices and
retains their issuer/policy/digest evidence in the report. Operational key
custody, revocation and approval governance remain external gates.

A separate threshold-attestation path verifies that configured authorities
signed the exact observed block under a pinned per-network policy. It
deliberately keeps `networkFinalityQualified` false because signatures from
configured authorities are not a native consensus or ancestry proof.

The `bloch-pay-adjustments` state machine accepts externally signed,
policy-pinned observations of cancellation, dispute resolution and refund
events. Every event is bound to the exact authenticated payment digest,
sequence, authority, source and network. Exact replay is idempotent; conflicting
identities, invalid transitions and an observed refund above the original
payment amount fail closed. `refund_observed` is evidence from a configured
source, not proof that funds settled or authority to credit an account.
Adjustment state can be rehydrated only when its canonical digest, generation,
policy roots and exact payment roots match independently retained expectations.
`bloch-local-state-store` now supplies an optional crash-safe, single-host
filesystem layer for those canonical bytes. It does not make the root
independent and does not provide HA.

## Adjustment-state persistence and recovery

For each accepted adjustment generation, the Pay worker persists the exact
`AdjustmentState::canonical_bytes()` with `write_state`. Generation zero is the
only permitted initial write; subsequent writes use the independently retained
previous `StateRoot` and advance exactly once. A byte-identical replay is
idempotent, while a stale root, skipped generation or conflicting byte string
fails closed.

The returned root is small, but it is security-critical. Its canonical bytes
must leave the state-store failure domain through an authenticated channel, for
example a separately administered signed checkpoint service. It must not be
read from an adjacent file in the same directory and then treated as an
independent expectation.

Startup recovery follows this order:

1. obtain and canonically parse the independently retained `StateRoot`;
2. call `load_state`, which checks the local envelope, identity, generation and
   SHA-256 digest against that root;
3. call `restore_adjustment_state` over the returned bytes with the expected
   adjustment and reconciliation policy digests, adjustment/payment identities,
   payment digest and amount, generation and state digest; and
4. expose no recovered state unless both layers succeed.

The filesystem layer creates a mode `0700` directory and mode `0600` files,
rejects symlinks and hard links, serializes local writers under a bounded lock,
and uses atomic replacement plus `fsync`. It is limited to 8 MiB per state and
does not encrypt data, authenticate the host, retain roots independently,
replicate state or manage backups.

A dedicated or otherwise qualified Unix node with 8 GB RAM is sufficient for
this bounded pilot workload; RAM is not the production gate. Before reusing a
node that ran Genesis 3 or AuxPoW, operators must inventory and stop the old
service, preserve any required evidence, use a separate restricted service
account and state path, confirm disk capacity and encryption policy, and verify
that no old process can access the Pay directory. Co-location does not add HA:
backup restore, monitoring and a separately administered root/checkpoint path
remain required before production qualification.

## Remaining production gates

- operational qualification and independence of the configured observers;
- network-native canonical ancestry and consensus-finality evidence (threshold
  authority attestations are implemented but do not close this gate);
- distributed allocation consistency and high availability across hosts and
  databases (both current durable stores are single-host);
- hardened external policy-wallet/HSM operation, issuer revocation and key
  lifecycle controls;
- privacy-governed storage and controlled customer/merchant APIs;
- operational execution and qualification of cancellations/refunds,
  currency/asset metadata governance and accounting exports;
- approved credit/release policy and human/organizational authorities; and
- authorized bank, payment institution, acquirer, Pix or settlement partners.

Until those gates pass, Bloch Pay remains an offline authentication,
reconciliation and local allocation component only. It opens no network
connection, owns no private key, signs no transaction and moves no funds.
