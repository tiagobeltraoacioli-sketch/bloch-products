# Bloch local state startup runtime

In-process startup composition for Bloch Data and Bloch Pay. Each entry point:

1. acquires the preprovisioned local coordination lock;
2. creates a one-shot remote fetch session with a memory-only nonce;
3. authenticates a fresh remote cursor against independently supplied policy
   bytes, policy pin and expected state identity;
4. authenticates the retained checkpoint, exact cursor and local state, then
   performs the product-specific semantic restore;
5. returns only the admitted product state and immutable evidence.

`start_data_with_trusted_time` and `start_pay_with_trusted_time` are the
trusted-time entry points. They consume an opaque threshold-authenticated time
capability and do not accept an operator time value or read wall-clock time for
remote freshness. They require an independently supplied trusted-time policy
pin and reject capabilities issued for another state identity or remote-cursor
policy. `start_data` and `start_pay` remain compatibility-only, non-qualified
paths because their fetch session uses the host wall clock.

`start_data_with_fresh_trusted_time` and
`start_pay_with_fresh_trusted_time` additionally generate a fresh in-memory
time challenge, acquire the bounded token, verify it against the retained
rollback floor, durably advance that floor, and only then fetch the remote
cursor and admit local state. The complete sequence holds the product's local
coordination lock. Every cooperating updater for that boundary store must use
the same coordination domain. The conservative floor is the token's signed
exclusive terminal instant, closing a crash window at the cost of requiring a
later token to reach that instant. The reference filesystem store still cannot
detect host, mount, volume or VM snapshot rollback.

`start_data_with_fresh_trusted_time_and_external_anchor` and
`start_pay_with_fresh_trusted_time_and_external_anchor` add an independently
pinned external anti-rollback gate. Under the same coordination lock they load
the local boundary, acquire fresh trusted time, generate a fresh anchor nonce,
receive the signed anchor document and the prior expectation over a
caller-authenticated external channel, verify the exact policy and Data/Pay
audience, require the token to have reached the external floor, and only then
advance the local boundary, fetch the remote cursor and admit state. Anchor
transport, verification, deadline, trusted-time, boundary, cursor and admission
failures have distinct error variants.

`start_data_with_authenticated_transport` and
`start_pay_with_authenticated_transport` are the preferred evidence-gated
composition. Before acquiring time or mutating a rollback boundary, they
validate independently pinned, purpose-specific transport policies for both
the external anchor and remote cursor against the exact state identity,
trusted-time policy and remote-cursor policy. The ordered critical section is:
local coordination lock, fresh trusted time, authenticated anchor exchange and
anchor verification, durable boundary advance, authenticated remote-cursor
exchange and cursor verification, then product admission. Response bytes stay
inside an opaque transport-session result until threshold evidence binds the
fresh session nonce, exact request bytes, exact response bytes, endpoint TLS
profile and audience. Request/response substitution and transport-policy
cross-use therefore fail closed.

The anchor transport response uses
`encode_authenticated_external_anchor_payload`, a versioned, length-delimited
body that places both the anchor document and retained expectation under the
same exact-exchange evidence. The runtime decodes that body only after evidence
verification. Remote-cursor transport requests similarly bind the inner fresh
cursor nonce and state identity; only the authenticated body is passed to the
remote-cursor verifier. A malformed authenticated anchor body is rejected and
never interpreted as an anchor or retained expectation.

The runtime never writes the external expectation to the local boundary store
and does not treat local persistence as independent evidence. The callback is
contractually responsible for authenticating the source of
`authenticated_expectation_bytes`; those canonical bytes are bounded and
parsed again against independently configured pins. The callback must also
honor the supplied monotonic deadline. This crate provides no network client,
TPM/WORM/remote-counter implementation, authenticated channel, independent
retention, or anchor authority operations. The authenticated-transport entry
points verify evidence but still do not open a socket, perform a TLS handshake,
derive handshake claims, operate attestors, or establish that configured
attestors are independent. Those remain adapter and deployment obligations.

The opaque verified remote cursor never leaves this composition. The crate has
no CLI, filesystem input loader, network client, cache, nonce persistence or
private-key API. The caller-provided transport must enforce the monotonic
deadline supplied by the fetch request. All cooperating local writers must use
the same coordination directory. This proves neither remote monotonicity nor
cross-host atomicity, authority independence, regulatory compliance or HA.
