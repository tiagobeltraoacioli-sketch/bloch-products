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
   unqualified salted-record equality commitment are implemented. Canonical
   lifecycle bytes can now use a crash-safe single-host Unix store with bounded
   local locking and compare-and-swap against an independently retained root;
   lifecycle semantic replay remains mandatory, and encrypted storage,
   protected external-root custody, backup recovery and HA remain open.
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
   machine, but no external adjustment is executed by the software. Both the
   Data lifecycle and Pay adjustment states now have bounded canonical recovery
   against independent anti-rollback roots. A common Unix-only local store adds
   crash-safe two-phase CAS persistence for their exact bytes, threshold
   Ed25519 checkpoints authenticate roots and semantic-manifest digests without
   taking private keys, and a local cursor enforces exact lineage relative to
   an independently supplied current cursor. A nonce-bound threshold protocol
   now authenticates fresh remote cursor observations, and a shared local lock
   coordinates cooperating admission and writer processes. Transport-neutral
   in-process startup and writer/recovery compositions plus a single-host
   durable CAS reference core now exist. Threshold-authenticated,
   audience-bound trusted-time capabilities, fresh bounded acquisition, a
   single-host monotonic-boundary reference store, bounded cursor ingress and
   threshold caller authorization for exact CAS requests also exist. A durable
   single-host one-time challenge store now upgrades exact authorizations into
   linear replay-protected CAS capabilities. Crash-safe receipt signing/import
   staging, an offline owner-only signing-request/detached-signature CLI and an
   absolute-time-bounded replica comparison verifier also exist. A bounded
   collector now acquires every configured replica with a distinct nonce and
   returns only a verified quorum. A single-host crash-safe report store accepts
   only that opaque capability and rejects local rollback/equivocation. An
   exact authenticated CAS session now composes verified caller authorization,
   transport evidence and signed decision receipts, and a hash-chained
   single-host journal retains only that opaque result. Threshold-signed writer
   fencing certificates are also verified against trusted time and an
   independently supplied epoch floor. None of these supplies signer custody,
   consensus, snapshot resistance, a linearizable lease issuer or the durable
   independent floor. A crash-safe local floor store now produces an opaque
   audience-bound floor, and an authoritative-CAS admission boundary requires
   it together with the exact replay-protected caller authorization and fresh
   writer lease before invoking an adapter. The store remains single-host and
   the floor-to-CAS window is not atomic. A canonical
   external-anchor protocol is now composed into optional Data/Pay startup and
   can authenticate an independently retained monotonic generation and time
   boundary, but does not provide the TPM/WORM/remote counter itself. Canonical
   threshold transport evidence plus a one-shot bounded session can bind exact
   request/response bytes to a fresh nonce. The preferred runtime path now
   composes those sessions before parsing external-anchor and remote-cursor
   responses, and an offline CLI can re-audit retained artifacts, but a live
   qualified TLS adapter must still derive the handshake claims. A strict
   fetch-adapter contract now exposes the pinned handshake parameters, external
   mTLS key handle, deadline and bounded ingress while forbidding cache use; it
   does not implement or qualify DNS, sockets, TLS, HSM access or egress.
   Independent
   rollback-resistant retention, suspend/resume qualification, replicated
   remote deployment, operational trust roots, encryption and multi-host HA
   remain open.
7. Read-only route risk comparison — deterministic policy-pinned comparison is
   implemented with exact integer amounts, bounded quote freshness, fee/risk/
   settlement limits and permanently false authentication/execution claims.
   Authenticated quote provenance, live adapters, simulation and execution
   authorization remain open.
8. Regulated or value-moving products only after their external gates pass.

Each phase must preserve the distinction between structural validation,
authenticated evidence and authorization to perform an operation.
