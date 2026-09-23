# Bloch trusted-time session

Transport-neutral, one-shot acquisition of `VerifiedTrustedTime`.

The caller supplies canonical policy bytes, an independently provisioned
policy digest, the expected state/remote-policy audience, an optional
rollback-resistant boundary, and a bounded timeout. A transport callback gets
a process-local CSPRNG nonce and monotonic deadline and returns an incremental
reader. The crate never performs network or filesystem I/O, stores a nonce, or
handles signing keys.

The transport remains responsible for authenticated endpoint delivery and for
making every potentially blocking operation respect the supplied deadline.
Persisting and advancing the returned rollback boundary remains an operational
responsibility.
