# Bloch route risk

Deterministic read-only comparison for policy-pinned swap and bridge routes.
The library uses integer amounts and basis points, rejects unknown or unordered
inputs, applies age, fee, risk, amount and settlement limits, and ranks eligible
quotes by risk-adjusted minimum output. A policy can compare only one exact
network/asset pair, and every quote must use the same input amount, so unlike
units or trade sizes cannot be ranked together.

`compare_routes` treats quote data as unauthenticated caller input. The optional
offline provenance protocol pins a canonical authority policy, uses a
domain-separated Ed25519 threshold, and binds the exact canonical quote set,
route-risk policy, audience and validity window. Its non-cloneable capability
can be passed to `compare_authenticated_routes`, which reports
`quoteInputAuthenticated: true` only for those exact bytes at the exact audit
instant used for verification.

Source authentication is not evidence that a quote is economically accurate,
executable, finalized or settled. Both comparison paths always emit
`executionAuthorized: false`; a result is never permission to sign, submit or
settle a transaction, move bridge assets, or enable DEX liquidity. The offline
verification timestamp is caller-supplied ceremony/audit time, not authenticated
production time and cannot create a reusable freshness capability. Production
use additionally requires trusted time, consensus/finality, custody policy,
transaction simulation and an independent execution authorization boundary.
