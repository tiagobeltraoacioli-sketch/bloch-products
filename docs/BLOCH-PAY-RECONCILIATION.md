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

## Remaining production gates

- operational qualification and independence of the configured observers;
- network-specific canonical ancestry and settlement/finality evidence;
- distributed allocation consistency and high availability across hosts and
  databases (the current durable store is single-host);
- invoice issuance authorization and policy-wallet/HSM integration;
- privacy-governed storage and controlled customer/merchant APIs;
- refunds, disputes, cancellations, currency/asset metadata governance and
  accounting exports;
- approved credit/release policy and human/organizational authorities; and
- authorized bank, payment institution, acquirer, Pix or settlement partners.

Until those gates pass, Bloch Pay remains an offline authentication,
reconciliation and local allocation component only. It opens no network
connection, owns no private key, signs no transaction and moves no funds.
