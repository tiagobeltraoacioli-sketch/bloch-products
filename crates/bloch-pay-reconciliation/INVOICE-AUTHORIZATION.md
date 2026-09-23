# Offline invoice authorization

This module authenticates who authorized one exact invoice in a pinned
merchant context. It does not establish that a payment occurred and never
qualifies settlement, credit, custody, delivery or movement of funds.

## Trust inputs

Two SHA-256 pins must be provisioned independently of the signed envelope:

- the canonical reconciliation policy, which defines tenant, merchant and
  payment routes; and
- the canonical invoice-authorization policy, which binds each Ed25519 public
  key to an issuer identity and an explicit sorted set of route IDs.

The authorization policy is also bound to the reconciliation-policy digest,
tenant and merchant. Policy JSON is size bounded, rejects unknown and
duplicate fields, and must equal its canonical serialization byte for byte.
Weak Ed25519 public keys, duplicate keys, duplicate issuers, unsorted routes
and routes absent from the reconciliation policy fail closed.

## Signed bytes

`invoice_authorization_signing_bytes` length-frames, in order:

1. the fixed protocol domain `bloch.pay.invoice.authorization.v1`;
2. the deployment-specific signature domain;
3. both independently supplied policy digests;
4. tenant and merchant IDs;
5. route and issuer IDs;
6. the authorization timestamp; and
7. the complete canonical invoice bytes.

The external holder signs those bytes with Ed25519. Private keys are never
accepted, generated, persisted or transmitted by this crate. Encoding an
envelope verifies the detached raw 64-byte signature before returning bytes.

## Protected flow

1. Parse both policies using independently provisioned digests.
2. Parse or construct an invoice admitted by the reconciliation policy.
3. Export the signing bytes to the external key holder.
4. Import the signature and create the canonical detached envelope.
5. Call `verify_authorized_invoice` with the envelope, detached invoice and
   both pinned policies.
6. Pass only the returned opaque `AuthorizedInvoice` values to
   `reconcile_authorized_invoices`.

The protected reconciliation API accepts no raw `Invoice`. It rechecks the
reconciliation-policy pin, an explicit authorization-policy pin, each exact
invoice digest and every opaque value's policy bindings. Its report exposes
read-only evidence for each invoice. Raw reconciliation paths set
`invoicesAuthorized` to false and expose `null` cryptographic/issuer fields.

## Deliberate non-claims

A valid authorization proves integrity and origin only inside the pinned
context. It does not prove signer independence, invoice legality, customer
consent, source truth, network finality, payment receipt, availability of
funds or regulatory approval. Production still requires secure external key
custody, issuer lifecycle and revocation operations, audited policy
distribution, authorized payment partners and an approved credit/settlement
policy.
