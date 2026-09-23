# Bloch remote cursor fetch session

Transport-neutral, one-shot acquisition of a freshly authenticated remote
cursor. Each call parses an independently pinned canonical policy, checks its
exact expected state identity, generates a 256-bit nonce only in memory, and
passes a request plus monotonic deadline to a caller-provided transport. The
response is accepted only before that deadline. Only `VerifiedRemoteCursor`
is returned.

`fetch_verified_remote_cursor_with_trusted_time` verifies freshness with an
opaque threshold-authenticated `VerifiedTrustedTime` capability whose clock
advances monotonically. It neither accepts an operator time argument nor reads
the wall clock. The caller supplies the independently pinned trusted-time
policy digest, and the capability must target the exact state identity and
remote-cursor policy digest of the fetch. The compatibility entry point still
reads local system time; deployments requiring the trusted-time gate must use
the capability entry point and persist its rollback boundary in
rollback-resistant storage.

Transport adapters should use `RemoteCursorFetchRequest::read_bounded_response`
with a `MonotonicDeadlineRead`. It incrementally reads at most 4 KiB per
operation, never grows the result past the protocol limit, passes the same
absolute monotonic deadline to every read, and performs a one-byte overflow
probe when the limit is reached. The adapter must still configure its
underlying I/O so each operation returns by the supplied deadline; synchronous
Rust code cannot preempt an implementation which ignores it.

The legacy callback result remains a `Vec<u8>` for compatibility. A transport
which constructs that vector itself can allocate before this crate checks its
size, so production adapters must use the bounded response reader rather than
an unbounded read-to-end operation.

This crate performs no network I/O, caching, filesystem access or private-key
handling. It never writes a nonce to disk and provides no nonce-file API. A
transport may copy the nonce as necessary to send the request, but must not
persist or reuse it. Freshness does not prove remote monotonicity, authority
independence, TLS identity, cross-host atomicity, WORM retention or high
availability.
