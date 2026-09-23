# Remote cursor operational boundary

`bloch-local-state-remote-cursor` authenticates a fresh observation of the
complete v2 checkpoint cursor held by an external control plane. It is the
source of startup expectations for `bloch-local-state-admission`; it is not the
control plane itself.

## Trust material

Provision the canonical remote-cursor policy and its SHA-256 pin through two
reviewed, authenticated paths. The policy fixes one state identity, signature
domain, validity interval, freshness limit, threshold and sorted distinct
Ed25519 public keys. Never accept a policy or policy pin returned alongside an
observation. Authority separation, HSM operation, WORM retention, TLS identity
and service availability require independent operational qualification.

Policy rotation is an explicit ceremony. The current trust root must authorize
the successor policy and effective interval outside this protocol before any
client configuration changes. A next-generation checkpoint signed under a new
checkpoint policy is likewise accepted only when the independently provisioned
remote cursor already fixes its exact policy and artifact digests.

## Read/startup sequence

1. Generate a new unpredictable request nonce. Never persist it for reuse.
2. Fetch an observation over the separately authenticated transport.
3. Verify canonical encoding, the independent policy pin, requested nonce,
   trusted signature threshold, state identity and freshness against a trusted
   clock.
4. Materialize the verified canonical cursor only in an owner-private
   short-lived runtime directory such as `/run`; never use a persistent stale
   cache as a fallback.
5. Acquire the shared local coordination lock used by every state/cursor
   writer and startup admission.
6. Authenticate the exact retained checkpoint, require equality with both the
   verified remote cursor and local cursor, load the complete state root and
   run the Data or Pay semantic restore.
7. Remove the ephemeral cursor after the admission process has consumed it.

Failure to fetch, authenticate or freshly observe the cursor rejects startup.
Local absence must never be interpreted as permission to bootstrap generation
zero. Initial bootstrap requires an external create-once record.

## Write/recovery sequence

Under the same shared local coordination lock:

1. fetch and authenticate the current external cursor;
2. verify the local cursor and state against it and validate the semantic
   product transition;
3. write the exact next state through `prepare_state`;
4. obtain the threshold checkpoint binding its semantic manifest;
5. perform an authenticated remote compare-and-swap from the exact current
   cursor to the exact successor;
6. fetch and authenticate a fresh observation of the accepted successor;
7. advance the local cursor with that exact observation;
8. promote only the exact prepared root; and
9. reload and semantically restore before reporting readiness.

A crash after remote CAS but before local promotion is recoverable only from the
still-present exact `pending.json`, accepted successor cursor and checkpoint.
Missing or conflicting pending bytes fail closed; they must not be synthesized
from local state. `discard_prepared_state` is permitted only after authenticated
evidence proves the remote CAS did not accept the candidate.

The repository now defines authenticated cursor observation, canonical signed
CAS requests and receipts, and an explicitly provisioned durable single-host
reference CAS core. The reference core returns unsigned decision material; it
is not a network service, signing authority, replicated linearizable service or
caller-authorization boundary. Therefore this sequence remains an
implementation contract, not deployment evidence, and production activation
is blocked. Even a valid signed acceptance receipt must be followed by a fresh
authenticated cursor observation matching the exact successor.

## Migration

Checkpoint artifact and cursor schemas v1 are intentionally rejected by v2
parsers. Migration requires maintenance mode, the independently retained legacy
root/evidence, a newly signed v2 checkpoint and an externally created v2 cursor.
Deleting a local cursor and calling generation-zero bootstrap is not migration
and is forbidden.
