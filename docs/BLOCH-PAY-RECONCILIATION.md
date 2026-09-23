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

A source ID is an allowlist selector, not source authentication. Production
must add an authenticated observation envelope from a qualified indexer and
independently pinned trust policy.

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

## Remaining production gates

- authenticated, independently pinned payment observations;
- network-specific canonical ancestry and settlement/finality evidence;
- durable allocation so an accepted chain event cannot be credited twice
  across processes, restarts or databases;
- invoice issuance authorization and policy-wallet/HSM integration;
- privacy-governed storage and controlled customer/merchant APIs;
- refunds, disputes, cancellations, currency/asset metadata governance and
  accounting exports;
- approved credit/release policy and human/organizational authorities; and
- authorized bank, payment institution, acquirer, Pix or settlement partners.

Until those gates pass, Bloch Pay is an offline reconciliation component only.
It opens no network connection, owns no key, signs no transaction and moves no
funds.
