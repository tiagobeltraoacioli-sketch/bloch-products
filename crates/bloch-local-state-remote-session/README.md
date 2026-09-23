# Bloch remote cursor fetch session

Transport-neutral, one-shot acquisition of a freshly authenticated remote
cursor. Each call parses an independently pinned canonical policy, checks its
exact expected state identity, generates a 256-bit nonce only in memory, and
passes a request plus monotonic deadline to a caller-provided transport. The
response is accepted only before that deadline and is verified against current
system time. Only `VerifiedRemoteCursor` is returned.

The callback must enforce its supplied deadline and response limit while
performing I/O. This crate checks the deadline after the callback and again
after cryptographic authentication, but cannot preempt a blocking synchronous
transport. Use an I/O implementation with connect/read timeouts no later than
`request.deadline()` and a bounded reader no larger than
`request.maximum_response_bytes()`. The crate rejects an oversized returned
buffer, but cannot undo memory already allocated by a transport adapter.

This crate performs no network I/O, caching, filesystem access or private-key
handling. It never writes a nonce to disk and provides no nonce-file API. A
transport may copy the nonce as necessary to send the request, but must not
persist or reuse it. Freshness does not prove remote monotonicity, authority
independence, TLS identity, cross-host atomicity, WORM retention or high
availability.
