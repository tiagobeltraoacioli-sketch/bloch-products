# Bloch remote monotonic cursor protocol

Canonical, bounded and domain-separated Ed25519 observations of a
`CheckpointCursor` held by an external control plane. A pinned policy identifies
the exact state identity, signature domain, validity window, authority public
keys and threshold.

A fetch caller generates a fresh unpredictable nonce of at least 32 characters.
The control plane signs an envelope containing that nonce, observation time,
the complete canonical cursor and its SHA-256 digest. Verification requires the
same independently retained policy pin and request nonce, a threshold of valid
signatures, exact domain and identity, and a response inside the configured
freshness window. The verified opaque result exposes a `&CheckpointCursor`
suitable as the independent expectation passed to local startup admission.

This crate performs no networking, nonce generation, private-key handling or
storage. It does not prove remote monotonicity, authority independence, WORM
retention, high availability, TLS identity or operational separation. Those
properties must be qualified and enforced by the external control plane and
transport. A client must never reuse a request nonce or derive its expected
policy from the response.

## Offline/debug CLI

The `bloch-local-state-remote-cursor` binary generates a fetch nonce and
verifies a separately returned observation without performing network access. It never
accepts private keys and writes nothing to standard output. Inputs must be
bounded, owner-operated, owner-only, single-link regular files. Output parents
must be owner-only. Outputs are create-only mode `0600` and are never
overwritten.

Generate 256 bits from the operating system CSPRNG:

```sh
bloch-local-state-remote-cursor nonce \
  --out fetch/request-nonce.txt
```

Send the exact nonce bytes to the independently operated control plane through
the qualified transport. After receiving its canonical signed observation:

```sh
bloch-local-state-remote-cursor verify \
  --observation fetch/remote-observation.json \
  --policy remote-cursor-policy.json \
  --policy-sha256 0xINDEPENDENT_POLICY_SHA256 \
  --nonce fetch/request-nonce.txt \
  --cursor-out fetch/verified-cursor.json
```

Only canonical `CheckpointCursor` bytes are written to `--cursor-out`. The
verifier always uses the host's current system time; callers cannot override
freshness evaluation. The nonce has no trailing newline and must be destroyed
or archived as used by the caller.

Because nonce generation and verification are separate invocations and this
CLI neither consumes the nonce nor performs the network round trip, it is an
offline ceremony/debug tool—not proof of fetch freshness. A production network
client must generate and retain the nonce only in memory, enforce a monotonic
round-trip deadline, verify against current wall-clock time, and consume the
nonce exactly once. This crate does not provide that network client.

## Authenticated compare-and-swap protocol

The library also creates canonical remote CAS requests and verifies signed
acceptance or refusal receipts. A normal request binds:

- the complete expected current cursor and its digest;
- the complete successor cursor and its digest;
- the canonical successor `StateRoot`;
- the pinned remote policy, signature domain and state identity;
- a caller-generated request ID, fresh nonce and request timestamp.

Before producing a request, the library requires the successor generation to
advance exactly once, requires its root digest and state digest to equal the
successor cursor, and requires the successor root's predecessor digest to equal
the current cursor's root digest. Initial creation is a distinct
`create_once_bootstrap` mode: it has no expected current cursor, requires
generation zero and requires a root with no predecessor.

`parse_remote_cursor_cas_request` returns an opaque validated request with
getters for a control-plane implementation, including the independently pinned
policy digest, signature domain, state identity, request ID and digest, exact
current and successor cursors, and the retained canonical request bytes. It
validates structure and lineage only: the request is not signed by a client and
conveys no client authorization. Authentication and authorization of the
requesting workload remain transport and control-plane responsibilities.

The receipt embeds the exact canonical request and its SHA-256 digest. Its
decision is a tagged `accepted` or `refused` value, signed by the policy
threshold. Verification requires byte-exact equality with the caller's retained
request and checks request-to-decision latency plus response freshness. The
verified Rust result is an enum; only the acceptance variant exposes the
successor cursor, so a signed refusal cannot be consumed as acceptance.
Compare-and-swap conflicts should therefore be returned as a signed `refused`
receipt with a stable reason code, never as an HTTP/status-only side channel.

Transition and crash-recovery code should use
`verify_remote_cursor_cas_exchange`, not retain a bare verified receipt. It
returns an opaque `VerifiedRemoteCursorCasExchange` only after binding the
receipt to the exact independently retained request, policy digest, domain,
state identity, request ID and digest, current cursor, and successor cursor.
The exchange retains byte-exact canonical request and receipt representations
through `request_bytes()` and `receipt_bytes()` for durable journaling and
exact replay verification. Its fields and those of the validated request and
verified receipt variants are private; public access is read-only. Persist both
byte strings and re-run exchange verification on recovery rather than treating
an acceptance object or cursor alone as authorization for another request.

This protocol authenticates what the external authorities signed. Even a valid
acceptance deliberately reports `remote_cas_execution_proven() == false`: this
crate has no server, durable database, compare-and-swap implementation,
networking or evidence that the remote mutation actually occurred. Operational
code must fetch a fresh authenticated cursor afterward and independently
confirm that it equals the accepted successor.
