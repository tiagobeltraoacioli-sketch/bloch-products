# Implementation order

This is a lightweight engineering index. Detailed product and API documentation
will follow working implementations and retained evidence.

1. Bloch Verify comparison core and offline CLI — implemented.
2. Signed observation envelopes, detached signing requests and independently
   pinned operator trust policy — implemented; external organizational
   verification remains open.
3. Strict offline EVM RPC capture adapter and bounded structural ancestry
   verifier — implemented; authenticated trust-anchor ancestry and consensus
   finality remain open.
4. Machine-readable production qualification gates — implemented fail-closed;
   organization-independence, ancestry and consensus-finality verifiers remain
   open.
5. Anchored canonical indexer state machine, strict JSON input, atomic durable
   snapshots, restart recovery, Ed25519 producer authentication, deterministic
   outbox, durable offline claim/retry/ack state and versioned bounded read
   contracts — implemented. Canonical producer-policy pinning, bounded safe
   outbox compaction and a strict transport-neutral read protocol/SDK are also
   implemented; authenticated network transports, receiver integration,
   external audit retention and database/HA operation remain open.
6. Non-custodial treasury policy evaluation and payment reconciliation.
7. Read-only route risk comparison.
8. Regulated or value-moving products only after their external gates pass.

Each phase must preserve the distinction between structural validation,
authenticated evidence and authorization to perform an operation.
