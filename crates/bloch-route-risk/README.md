# Bloch route risk

Deterministic read-only comparison for policy-pinned swap and bridge routes.
The library uses integer amounts and basis points, rejects unknown or unordered
inputs, applies age, fee, risk, amount and settlement limits, and ranks eligible
quotes by risk-adjusted minimum output. A policy can compare only one exact
network/asset pair, and every quote must use the same input amount, so unlike
units or trade sizes cannot be ranked together.

Quote data remains unauthenticated caller input. Every report therefore emits
`quoteInputAuthenticated: false` and `executionAuthorized: false`. A result is
not permission to sign, submit or settle a transaction, move bridge assets, or
enable DEX liquidity. Production use still requires authenticated quote
provenance, consensus/finality, custody policy, transaction simulation and an
independent execution authorization boundary.
