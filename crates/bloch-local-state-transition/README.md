# Bloch local state transition

This crate composes host-local coordination, the two-phase state store,
authenticated checkpoints, the monotonic local cursor and verified remote CAS
receipts into one fail-closed transition. It performs no network access, holds
no private key and signs nothing.

`execute_transition` holds one `LocalStateCoordination` capability across:

1. fresh externally verified current-cursor admission;
2. exact current checkpoint/state loading and semantic pre-validation;
3. durable preparation of the immediate successor;
4. external checkpoint creation and verification for that exact root;
5. durable owner-only journaling of the exact canonical CAS request before
   external submission;
6. external remote CAS and durable retention of its exact verified receipt;
7. fresh verification of the accepted successor; and
8. local cursor advancement, pending-state promotion and semantic postcheck.

The callback implementation is responsible for bounded transport, trusted
time, nonce freshness, policy pins and verifying a CAS receipt against the
exact request formed from the callback arguments. The crate rechecks every
root/cursor/checkpoint relationship before local mutation.

A signed refusal is distinct from a transport/unknown outcome. Only an exact
signed refusal permits the prepared candidate to be discarded. Unknown and
post-acceptance failures retain the journal and, until promotion, the pending
candidate. Call
`reconcile_transition` after restart with the retained verified checkpoints.
It freshly observes the remote cursor: the predecessor triggers replay of the
exact journaled request, the successor completes locally, and every other
cursor fails closed. Recovery safely handles either side of the local cursor
advance and state-promotion crash boundaries.

A postcheck error after promotion is reported separately as
`CommittedButPostcheck`: durable state and cursor have already advanced, so it
must never be described or handled as an uncommitted transition.

The coordination, state, cursor and journal directories must be fixed,
pre-provisioned owner-only directories for one dedicated UID. Journal request
and receipt bytes are bounded, canonical and written with fsync plus atomic
rename. A pending journal blocks a new transition until reconciliation.

This crate does not provide remote linearizability, authority independence,
trusted time, remote fencing, semantic rules, replication, durability or high
availability. Those are deployment gates supplied and qualified externally.
