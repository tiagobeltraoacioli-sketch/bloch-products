# Bloch authenticated fetch adapter contract

This crate narrows a network adapter to one fail-closed, non-cacheable,
exact-byte fetch. The caller pins an authenticated transport policy, purpose,
external mTLS key handle and timeout. The adapter receives only the handle (not
private-key bytes), endpoint and TLS constraints. It can release bytes only by
reporting the handshake it actually verified and by passing the response and
threshold evidence through the bounded authenticated-transport collector.

The contract rejects endpoint, TLS version, ALPN, cipher suite, server/client
SPKI, purpose or key-handle substitution. It also rejects responses reported as
coming from a cache, any cache read/write attempt, missing peer verification,
missing client-certificate use, unbounded input, stale trusted time and
deadline violations. Exact request, nonce and response binding is then checked
by `bloch-authenticated-transport-session`.

This is **not a live TLS implementation**. It does not perform DNS, routing,
socket I/O, TLS/mTLS, certificate-chain or revocation validation, hostname
verification, HSM/KMS operations, cache isolation, attestation, or egress
filtering. A separately qualified adapter and key provider must truthfully
produce the observations, honor the absolute monotonic deadline, ensure the
handle cannot export key material, and provide independently signed transport
evidence from the real exchange. An in-process adapter can lie; this contract
makes the required evidence explicit and testable, not physically
unforgeable.
