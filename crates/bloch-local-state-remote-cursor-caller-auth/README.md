# Remote cursor CAS caller authorization

This crate defines the canonical, threshold-Ed25519 authorization protocol for
one exact remote cursor CAS request. The signed envelope binds:

- the independently pinned caller policy;
- the pinned remote cursor policy, signature domain, and state identity;
- both the SHA-256 digest and complete canonical bytes of the CAS request;
- a 256-bit challenge nonce and bounded issue/expiry times.

Verification returns an opaque capability. The reference control-plane store
requires that capability and its provisioned caller-policy pin before it can
mutate durable cursor state. The capability has an exclusive monotonic deadline
derived during verification; mutation accepts no operator wall-clock value and
fails closed once that deadline is reached. Request substitution,
policy/identity crossing, stale authorization, nonce replay in another
challenge, and insufficient or untrusted signatures fail closed.

The crate performs no network I/O, stores no nonce, and never receives private
keys. Fresh challenge issuance and uniqueness, the trusted wall-clock used at
verification, authority independence, replicated storage, and transport
authentication remain deployment responsibilities. There is no durable nonce
store: even an idempotent replay of the same CAS request requires a freshly
verified authorization. Suspend/resume behavior and monotonic-clock
qualification remain external deployment gates.
