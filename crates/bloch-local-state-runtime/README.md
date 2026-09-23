# Bloch local state startup runtime

In-process startup composition for Bloch Data and Bloch Pay. Each entry point:

1. acquires the preprovisioned local coordination lock;
2. creates a one-shot remote fetch session with a memory-only nonce;
3. authenticates a fresh remote cursor against independently supplied policy
   bytes, policy pin and expected state identity;
4. authenticates the retained checkpoint, exact cursor and local state, then
   performs the product-specific semantic restore;
5. returns only the admitted product state and immutable evidence.

The opaque verified remote cursor never leaves this composition. The crate has
no CLI, filesystem input loader, network client, cache, nonce persistence or
private-key API. The caller-provided transport must enforce the monotonic
deadline supplied by the fetch request. All cooperating local writers must use
the same coordination directory. This proves neither remote monotonicity nor
cross-host atomicity, authority independence, regulatory compliance or HA.
