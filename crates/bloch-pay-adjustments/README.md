# Bloch Pay adjustments

This crate tracks a deterministic, non-custodial lifecycle for externally
observed cancellation, dispute, and refund events. Every event is canonical,
signed by an Ed25519 authority allowed by an independently pinned policy, and
bound to the originating authenticated payment observation.
Initialization recomputes an independently supplied reconciliation-policy pin
and binds tenant, merchant, validity bounds, allowed sources, and route networks
before accepting the adjustment policy.

The state machine accepts only the next sequence number. Exact replay is
idempotent; reuse of an event ID, external reference, or network event with
different content fails closed. Invalid transitions, stale events, policy
substitution, signature substitution, and state truncation are rejected.

`refund_observed` means only that a configured observer signed an observation.
This crate does not send cancellations or refunds, connect to a payment rail,
hold assets, handle private keys, establish finality or settlement, authorize
credit, or authorize movement/release of funds. All such output flags are
always `false`.

Adjustment state v2 supports bounded, exact-canonical recovery. Restoration
requires an independently retained state digest, generation, both policy
digests and the exact payment identity/digest/amount. It also revalidates the
complete status-transition chain and duplicate identities. Because compact
state retains event digests rather than detached signatures, recovery proves
agreement with the independent state root; it does not reauthenticate the
original event signatures.

## Local persistence

`bloch-local-state-store` can provide the single-host filesystem layer for this
state. Persist the exact result of `AdjustmentState::canonical_bytes()` under a
stable identity (normally the adjustment ID), using `AdjustmentState::generation()`
as the store generation. Keep the returned `StateRoot::canonical_bytes()` in a
separate authenticated control plane; saving that root beside `state.json` does
not provide rollback protection.

Recovery is deliberately two-stage:

1. parse the independently retained root with `parse_state_root`, then call
   `load_state` with that root;
2. pass the loaded bytes to `restore_adjustment_state` with an
   `AdjustmentStateExpectation` containing the same root digest and generation,
   plus the independently retained adjustment-policy, reconciliation-policy and
   payment roots.

Only a state returned by the second step may re-enter the adjustment state
machine. The local store verifies the filesystem envelope and compare-and-swap
lineage; `restore_adjustment_state` verifies the Bloch Pay meaning of its
contents. Neither check substitutes for the other.

The store accepts an initial generation of zero and then exactly one generation
per successful update. Publish the new root to the independent control plane
before considering the update recoverable, and never derive the expected root
from the same local directory during startup. A missing, stale or mismatched
root must stop recovery rather than select the newest-looking local file.

This is bounded local durability, not a database or secret store. It permits at
most 8 MiB of state, is Unix-only, uses one bounded writer lock and provides no
encryption, backup, replication, high availability, key custody or host
attestation. Those responsibilities remain external.
