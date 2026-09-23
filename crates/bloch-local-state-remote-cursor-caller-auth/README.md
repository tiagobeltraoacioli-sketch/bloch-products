# Remote cursor CAS caller authorization

This crate defines the canonical, threshold-Ed25519 authorization protocol for
one exact remote cursor CAS request. The signed envelope binds:

- the independently pinned caller policy;
- the pinned remote cursor policy, signature domain, and state identity;
- both the SHA-256 digest and complete canonical bytes of the CAS request;
- a 256-bit challenge nonce and bounded issue/expiry times.

Verification returns a non-cloneable opaque capability. It is not accepted by
the reference control plane until `bind_consumed_challenge` also consumes the
matching durable proof from `bloch-local-state-remote-cursor-challenge-store`.
The resulting replay-protected capability is consumed by value and checked
against the provisioned caller-policy pin before durable mutation. It has an
exclusive monotonic deadline
derived during verification; mutation accepts no operator wall-clock value and
fails closed once that deadline is reached. Request substitution,
policy/identity crossing, stale authorization, nonce replay in another
challenge, and insufficient or untrusted signatures fail closed.

The preferred verifier consumes an opaque `VerifiedTrustedTime` capability and
requires it to bind the same state identity and remote-cursor policy as the CAS
request. It therefore accepts no operator-supplied wall-clock value. The
compatibility verifier which accepts `evaluated_at_unix_seconds` is only for a
caller that separately qualifies that clock and is not the production
composition described here.

The crate performs no network I/O, stores no nonce itself, and never receives
private keys. The companion single-host store provides durable issuance and
one-time consumption; replicated challenge storage, trusted-time acquisition
and boundary retention, authority independence, and transport authentication
remain deployment responsibilities. Even an idempotent replay of the same CAS
request requires a fresh challenge and authorization. Suspend/resume behavior
and monotonic-clock qualification remain external deployment gates.
