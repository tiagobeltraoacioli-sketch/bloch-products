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

The opaque verified remote cursor never leaves this composition. The crate has
no CLI, filesystem input loader, network client, cache, nonce persistence or
private-key API. The caller-provided transport must enforce the monotonic
deadline supplied by the fetch request. All cooperating local writers must use
the same coordination directory. This proves neither remote monotonicity nor
cross-host atomicity, authority independence, regulatory compliance or HA.
