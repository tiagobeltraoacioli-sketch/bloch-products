# Bloch local state re-bootstrap

Offline, create-only re-bootstrap of the narrow legacy format that used
checkpoint artifact v1 and cursor v1 **but already embedded canonical state-root
v2**. The tool never signs anything, accepts no private keys and never reads a
local state store to discover what should be current.

This is not a format converter. Checkpoint v1 did not sign
`semanticManifestSha256`, so the original signatures cannot authorize a v2
artifact. Before running the tool, the checkpoint authorities must independently
review the semantic manifest and issue a new checkpoint v2 over the exact same
root. The monotonic control plane must independently supply authenticated
SHA-256 pins for both the retained cursor v1 and proposed cursor v2.

The tool authenticates the legacy signature threshold, checks that cursor v1
pins that exact artifact/root, authenticates the new v2 threshold, checks that
cursor v2 pins the exact new artifact/root/semantic manifest, and requires
identity, generation, complete root and state digest continuity. It then writes
only the already supplied canonical cursor v2 to a create-only owner-only file.
It does not modify either cursor store.

Run with all services that can mutate the state, checkpoint or cursor stopped:

```sh
umask 077
bloch-local-state-rebootstrap rebootstrap \
  --legacy-artifact evidence/checkpoint-v1.json \
  --legacy-policy evidence/checkpoint-policy.json \
  --legacy-policy-sha256 0xINDEPENDENT_POLICY_PIN \
  --legacy-cursor evidence/cursor-v1.json \
  --expected-legacy-cursor-sha256 0xINDEPENDENT_LEGACY_CURSOR_PIN \
  --new-artifact ceremony/checkpoint-v2.json \
  --new-policy ceremony/checkpoint-policy.json \
  --new-policy-sha256 0xINDEPENDENT_POLICY_PIN \
  --expected-semantic-manifest-sha256 0xINDEPENDENT_SEMANTIC_PIN \
  --new-cursor ceremony/cursor-v2.json \
  --expected-new-cursor-sha256 0xINDEPENDENT_NEW_CURSOR_PIN \
  --cursor-out publish/cursor-v2.json
```

Every input must be a bounded, single-link, owner-only regular file. The output
parent must be owner-only and the output must not already exist. Success is
silent. After success, compare the output digest again through the independent
control plane, install it using a separately reviewed create-only procedure,
and run full checkpoint, cursor, store and product-semantic admission before
restarting any writer.

## Mandatory refusal cases

Automated re-bootstrap is refused when:

- the legacy artifact embeds state-root v1 or omits the v2 predecessor field;
- either independently supplied cursor digest is absent or mismatched;
- v1 or v2 bytes are non-canonical, unbounded or fail signature verification;
- checkpoint policy changes between versions;
- state identity, generation, complete canonical root or state digest changes;
- artifact, cursor, policy or semantic-manifest pins do not match exactly; or
- the new cursor/checkpoint was derived only from the local host.

Root-v1 evidence lacks authenticated v2 lineage and cannot be reconstructed by
this tool. Freeze the writer, preserve all evidence, and perform a new authority
ceremony plus an independently authorized genesis/recovery decision. Never copy
the local state digest into a new expectation merely to make admission pass.

The tool does not prove authority independence, currentness, finality, semantic
correctness, backup, replication or high availability.
