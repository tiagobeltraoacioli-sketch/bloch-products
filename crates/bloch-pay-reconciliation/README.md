# Bloch Pay reconciliation core

This crate performs deterministic, offline matching of canonical invoices to
payment observations under an independently pinned route/source policy. It
uses integer minor units, prevents observation reuse, rejects route
substitution and reports exact, partial, excess, late and unmatched evidence.

An observation is not settlement proof. Source IDs are policy allowlists, not
authentication, and the report always keeps `settlementQualified` and
`creditAuthorized` false. This crate owns no wallet or private key, connects to
no chain, bank or Pix system, broadcasts nothing and cannot release goods,
credit an account or move funds.

Production requires authenticated observations from qualified indexers,
network-specific finality evidence, durable allocation/idempotency, regulated
payment partners, privacy governance and an independently approved credit
policy.
