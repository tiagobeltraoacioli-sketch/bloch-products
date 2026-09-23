# Implementation order

This is a lightweight engineering index. Detailed product and API documentation
will follow working implementations and retained evidence.

1. Bloch Verify comparison core and offline CLI.
2. Signed observation envelopes and independently pinned operator trust roots.
3. Node adapters and checkpoint collection without implicit trust in RPC.
4. Indexer, versioned read API, idempotent webhooks and SDK.
5. Non-custodial treasury policy evaluation and payment reconciliation.
6. Read-only route risk comparison.
7. Regulated or value-moving products only after their external gates pass.

Each phase must preserve the distinction between structural validation,
authenticated evidence and authorization to perform an operation.

