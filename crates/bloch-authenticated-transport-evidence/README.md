# Authenticated transport evidence

This crate verifies canonical threshold-Ed25519 evidence for one exact TLS
exchange. The independently pinned policy fixes the service and state audience,
purpose, DNS endpoint and port, TLS 1.3, ALPN, allowed cipher suites, server
SPKI pins, client SPKI identity, response limit, round-trip limit and attestor
threshold. Evidence binds the exact request nonce plus request/response digests
and is evaluated with `VerifiedTrustedTime`, never an operator wall clock.
The preferred exchange APIs accept the exact request and response byte slices
and derive both digests and the response length internally, so an adapter
cannot accidentally authenticate hashes assembled from different payloads.

The returned capability is opaque, non-cloneable and expires on a monotonic
deadline bounded by the evidence age, policy expiry and trusted-time expiry.

This is not a TLS implementation and does not inspect a live socket. It proves
only that the configured attestor keys signed the canonical claims. Production
still requires a qualified TLS 1.3/mTLS adapter which derives every field from
the actual handshake and exact transported bytes, protects attestor keys,
prevents nonce reuse, and demonstrates organizational independence and target
host behavior. DNS security, certificate issuance/revocation, network routing,
availability and server operation remain external gates.

## Offline audit CLI

`bloch-authenticated-transport-audit verify-exchange` re-verifies owner-only
canonical policy, trusted-time token, request, response and evidence files and
prints only authenticated digests and authority IDs. The trusted-time nonce and
transport request nonce are separate required inputs. This command is
diagnostic: it does not generate either nonce, retain an anti-rollback boundary,
open a live socket or prove that the inspected files came from one fresh
connection. Its JSON therefore always reports `productionQualified: false`.
