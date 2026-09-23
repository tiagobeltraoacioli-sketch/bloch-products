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

The opaque verified remote cursor never leaves this composition. The crate has
no CLI, filesystem input loader, network client, cache, nonce persistence or
private-key API. The caller-provided transport must enforce the monotonic
deadline supplied by the fetch request. All cooperating local writers must use
the same coordination directory. This proves neither remote monotonicity nor
cross-host atomicity, authority independence, regulatory compliance or HA.
