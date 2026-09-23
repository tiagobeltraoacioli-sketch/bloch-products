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
