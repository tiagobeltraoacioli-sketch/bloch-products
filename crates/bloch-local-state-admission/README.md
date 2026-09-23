# Bloch local state admission

Read-only startup admission for persisted Bloch Data lifecycle state and Bloch
Pay adjustment state. The library composes four independent checks:

1. authenticate a canonical retained threshold checkpoint v2 and its semantic digest;
2. require the checkpoint to equal an independently retained admitted cursor;
3. load the local state only through the checkpoint's complete state root;
4. restore the product state against a canonical, independently pinned
   semantic manifest.

Data admission additionally parses the exact lifecycle authority policy pinned
by its semantic manifest and replays every retained lifecycle transition.
Pay admission uses the complete adjustment/payment expectation carried by its
semantic manifest. Neither path derives expectations from local state or from
unsigned checkpoint fields.

Because startup may occur after the checkpoint's short issuance-freshness
window, retained authentication verifies canonical encoding, signatures,
policy/domain/identity and that issuance occurred inside the policy validity
window, but does not apply `maxCheckpointAgeSeconds`. This is safe here only
because the very next step requires the artifact and complete root to equal an
independently retained exact cursor. This API must not be used to create or
advance that cursor.

The two product manifests have distinct schemas and reject unknown fields,
non-canonical JSON, invalid identifiers, invalid digests, empty input and input
over 64 KiB. Successful output is opaque and exposes the restored product state
and immutable admission evidence. It does not claim regulatory compliance,
settlement, authority independence, high availability or exclusion of a
concurrent writer.

This is startup/read-only admission. Cursor and state stores have separate
locks, so a production deployment must serialize this function with all cursor
and state writers through an outer service lock or equivalent coordinator. The
library rechecks both stores before returning to catch ordinary staged-update
races, but that recheck is not a substitute for writer coordination.
