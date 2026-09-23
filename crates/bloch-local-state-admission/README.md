# Bloch local state admission

Read-only startup admission for persisted Bloch Data lifecycle state and Bloch
Pay adjustment state. The library composes four independent checks:

1. authenticate a canonical retained threshold checkpoint v2 and its semantic digest;
2. consume a freshly verified remote cursor observation and require the
   checkpoint to equal that exact independently observed cursor;
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
settlement, authority independence or high availability. The uncoordinated
entry points do not claim exclusion of a concurrent writer.

This is startup/read-only admission. Cursor and state stores have separate
locks. Production uses `admit_data_lifecycle_coordinated` or
`admit_pay_adjustment_coordinated` and requires every cooperating cursor/state
writer to use the same coordination directory. The base APIs remain useful for
tests, but their final recheck is not a substitute for writer coordination.

## Startup CLI

`bloch-local-state-admission data` and `bloch-local-state-admission pay` expose
the same read-only checks to a service manager while holding the shared
`bloch-local-state-coordination` lock. They are silent on success and
never emit state bytes. Policy and semantic pins are taken from the exact
remotely authenticated cursor, not from command-line values or local state.
The CLI verifies the remote observation, fresh request nonce and independently
pinned remote policy in-process using current system time.

Production commands accept only `--coordination-directory`, `--cursor-store`
and `--state-store`. Every trust input has one fixed systemd credential name:
`remote-observation`, `remote-policy`, `remote-policy-pin`, `request-nonce`,
`checkpoint-artifact`, `checkpoint-policy`, `semantic-manifest`, and
`expected-state-identity`, plus `lifecycle-policy` for Data. Files are opened
with `O_NOFOLLOW`, bounded and
checked before/after reading. Credentials must be exact root-owned mode `0440`
single-link files directly inside an absolute, root-owned, non-writable
`$CREDENTIALS_DIRECTORY`.

`manual-data` and `manual-pay` are deliberately separate operator/test modes.
They require explicit paths for every trust input and accept only single-link,
owner-private files. They still verify the remote observation with current
system time and never accept a raw expected cursor.
