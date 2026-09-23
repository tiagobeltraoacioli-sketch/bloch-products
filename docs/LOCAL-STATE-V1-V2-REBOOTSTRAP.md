# Local-state checkpoint/cursor v1 to v2 re-bootstrap

There is no signature-preserving conversion from checkpoint v1 to v2.
Checkpoint v2 adds a signed semantic-manifest digest and uses a new
domain-separated signing message. Existing v1 signatures cannot be replayed as
v2 authorization.

The supported offline path is deliberately narrow:

1. stop and lock out every writer;
2. obtain the retained v1 checkpoint, policy and cursor plus the cursor's digest
   from the independent monotonic control plane;
3. have the threshold authorities review the semantic manifest and sign a new
   v2 checkpoint over the exact same canonical root;
4. obtain the proposed v2 cursor and its digest independently;
5. run `bloch-local-state-rebootstrap` from reviewed media into a new empty,
   owner-only output directory;
6. independently compare the output digest, install through a reviewed
   create-only procedure, and run checkpoint/cursor/store/product admission;
7. restart writers only after the complete evidence bundle is retained.

The tool does not consult local `state.json`, `pending.json` or `cursor.json` to
form expectations. Its two cursor SHA-256 arguments are trust inputs, not values
to calculate on the host being recovered.

Only legacy checkpoint/cursor v1 evidence that already pins a complete
state-root v2 is reconstructible. If the legacy checkpoint contains state-root
v1, if the policy changes, or if any root field differs, automated migration is
impossible and fails closed. Preserve the evidence and conduct a separately
authorized re-genesis/recovery ceremony; do not synthesize predecessor lineage
or semantic expectations from local artifacts.
