# Bloch indexer protocol v1

`bloch-indexer-protocol` is the offline, transport-neutral JSON boundary for
the read-only indexer API. It does not open sockets, read files, deliver
messages, mutate canonical state, or assert L2 finality.

The v1 request envelope supports only `status`, `tip`, `block`, `blocks`, and
`events`. Requests are limited to 16 KiB and reject duplicate keys at every
depth, unknown fields, trailing values, invalid schemas, and unsafe request
identifiers. Successful responses retain the versioned query schemas and are
limited to 2 MiB. Failure responses expose fixed codes and messages rather
than parser, storage, or implementation details.

The crate also provides typed request encoding and strict response decoding
for SDK consumers. Cursor strings remain opaque. They are integrity checked
by `bloch-indexer-query`, bound to a network, query kind, and observed
canonical snapshot, but are not authentication or authorization tokens.

Typical embedding:

```rust,no_run
use bloch_indexer_core::CanonicalIndexer;
use bloch_indexer_protocol::dispatch;

fn handle_locally(indexer: &CanonicalIndexer, bounded_request: &[u8]) -> Vec<u8> {
    dispatch(indexer, bounded_request)
}
```

Any HTTP, RPC, queue, or local IPC adapter remains outside this crate and must
add its own authentication, authorization, rate limiting, and transport byte
limits.
