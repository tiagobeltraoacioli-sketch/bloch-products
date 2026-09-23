# Remote cursor receipt staging

This crate is a Unix, single-host, fail-closed staging primitive between an
already-made CAS decision and external receipt signing. `prepare` creates one
immutable operation, durably retaining the exact canonical request, decision,
policy pin/domain, decision time, and exact signing message. `import` verifies
the externally signed receipt with the existing remote-cursor verifier before
durably publishing its canonical bytes and digest.

The preferred API starts from the public `ControlPlaneDecision` and a
`VerifiedTrustedTime`. It independently checks that the control-plane request
digest and ID bind the parsed canonical request, checks the trusted-time state
identity and remote-policy audience, and obtains both decision and evaluation
time from those opaque capabilities. The raw decision/time APIs remain only
for compatibility and tightly controlled offline ceremonies; production code
must not treat operator-supplied wall time as trusted.
Trusted-time freshness is checked again after temporary-file fsync and
immediately before publication (and before returning an idempotent replay).

The store is explicitly create-once. Exact prepare/import replays are
idempotent; request, decision, policy, time, signing-message, or receipt
substitution is refused. Files are owner-only, opened without following
symlinks, rejected when hard-linked, bounded, serialized by a bounded lock,
and updated by fsync/rename/directory-fsync/readback.

This crate has no private keys and performs no networking. It is not an HSM,
signer, challenge service, replicated CAS system, independent authority, or
high-availability service. A host/filesystem/VM snapshot can roll this
single-host state back; deployments still need independent replication and
anti-rollback evidence. An I/O error after rename is ambiguous: keep the
operation offline and reload it before retrying.

## Offline CLI

`bloch-receipt-staging` is an offline operator tool. It never receives a
private key and performs no network I/O. `inspect` prints only non-secret
metadata: it omits the canonical request, signing message, receipt bytes, and
signatures. Signing material is only written to an explicitly selected,
create-once owner-only file:

```console
bloch-receipt-staging inspect --store /secure/receipt-operation
bloch-receipt-staging export-signing-request \
  --store /secure/receipt-operation \
  --out /secure/transfer/receipt-signing-request.json

bloch-receipt-staging assemble-receipt \
  --store /secure/receipt-operation \
  --policy /secure/pins/remote-cursor-policy.json \
  --policy-sha256 0xREVIEWED_SHA256 \
  --signature-bundle /secure/transfer/receipt-signature-bundle.json \
  --out /secure/transfer/signed-receipt.json
```

The export is canonical JSON and is bound to the staged request, decision,
decision time, policy pin/domain, and state identity. Existing output files,
symlinks, unsafe staging stores, and non-owner-only input files fail closed.
The output directory itself must be a real, operator-owned `0700` directory;
the CLI validates it before creation and again after file and directory fsync.

The signature bundle uses schema
`bloch.products.remote-cursor-receipt-signature-bundle.v1` and repeats the
state identity, policy pin, signature domain, request digest, and signing
message digest from the signing request. Its signatures must be strictly
ordered by authority ID. Assembly rejects non-canonical JSON, duplicate or
unknown authority IDs, an insufficient threshold, invalid signatures, and any
audience or message substitution before writing a canonical receipt. The
receipt decision time always comes from immutable staging; assembly accepts no
wall-clock argument and performs no network access.

`assemble-receipt` only creates a verified ceremony artifact. It deliberately
does not import the receipt into staging and is not a production admission
gate. Production import remains dependent on `ControlPlaneDecision` and
`VerifiedTrustedTime` through the preferred in-process APIs.

The CLI intentionally cannot reconstruct the opaque `ControlPlaneDecision` or
`VerifiedTrustedTime` required by the preferred production API. Consequently,
its only import command is conspicuously ceremony-only and requires an
operator-supplied evaluation time plus an explicit acknowledgement:

```console
bloch-receipt-staging ceremony-import-receipt \
  --store /secure/receipt-operation \
  --policy /secure/pins/remote-cursor-policy.json \
  --policy-sha256 0xREVIEWED_SHA256 \
  --receipt /secure/transfer/signed-receipt.json \
  --evaluated-at-unix-seconds REVIEWED_UNIX_TIME \
  --acknowledge-operator-time-is-not-production
```

That path verifies the canonical policy and receipt and binds them to the
immutable operation already staged. It is not a production admission path:
operator wall-clock input is not trusted time. Production callers must use
`import_remote_cursor_cas_receipt_with_trusted_time` or
`import_remote_cursor_cas_signatures_with_trusted_time` in-process with the
opaque capabilities obtained from the control plane and trusted-time verifier.
