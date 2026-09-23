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
   outbox compaction, a strict transport-neutral read protocol/SDK, authenticated
   delivery/receipt envelopes, signed audit artifacts and bounded local
   single-writer coordination are also implemented. Authenticated receipts can
   authorize a durable ACK with their evidence retained atomically in snapshot
   v4. Strict offline delivery transport codecs and local hash-chained signed
   audit retention are implemented. A crash-recoverable sender spool, durable
   idempotent receiver core, offline external-signing ceremonies, externally
   signed retention checkpoints, multi-replica ledger comparison and canonical
   fail-closed service admission are also implemented. A canonical regulated-data
   policy now denies cross-tenant/purpose/region/retention violations and permits
   only bounded hiding commitments at the on-chain boundary. Authenticated
   network adapters, tenant-isolated encrypted storage, actual KMS/HSM,
   qualified commitment implementations, physical privacy-lifecycle execution,
   independently operated WORM replicas and distributed database/HA operation
   remain open. Offline signed retention/legal-hold evidence and a deliberately
   unqualified salted-record equality commitment are implemented.
6. Non-custodial payment reconciliation — deterministic invoice/observation
   matching with pinned routes and permanently false settlement/credit claims is
   implemented. Exact observations can be authenticated against pinned Ed25519
   observer policies; exact invoices can be authorized against pinned issuer
   policies. Both flow through a protected reconciliation path into a durable
   local idempotent allocation store, whose complete snapshots can be signed
   and checked against independent generation/digest expectations. Per-network
   authority thresholds can attest the exact observed block without claiming
   native consensus finality. Observer independence and qualification,
   consensus/ancestry proof, distributed allocation HA, hardened policy-wallet
   operation, bank/Pix integration and credit policy remain open. Authenticated
   cancellation/dispute/refund observations now feed a replay-safe local state
   machine, but no external adjustment is executed by the software.
7. Read-only route risk comparison.
8. Regulated or value-moving products only after their external gates pass.

Each phase must preserve the distinction between structural validation,
authenticated evidence and authorization to perform an operation.
