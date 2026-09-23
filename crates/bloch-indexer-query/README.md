# Bloch indexer query

`bloch-indexer-query` is the offline, read-only v1 query contract for
`bloch-indexer-core`. It opens no socket and performs no filesystem or network
I/O.

The API exposes:

- network-bound status and observed canonical tip;
- a bounded block-metadata lookup;
- block pages capped at 100 records;
- event pages capped at 100 records and 1 MiB of serialized event-record
  payload;
- deterministic cursors bound to query kind, chain identity, genesis and the
  observed canonical tip.

A cursor remains usable when newer blocks are appended: subsequent pages stop
at the original snapshot. It fails closed if a reorganization removes or
replaces that snapshot, if it is used with another network or query kind, or if
its canonical encoding/checksum is changed. The SHA-256 checksum detects
accidental corruption; it is not authentication and cursors must not be used as
authorization tokens.

Every response reports finality as `notEstablished`. “Canonical at the observed
snapshot” is not evidence of consensus finality. The block endpoint returns
metadata only; potentially large logs are retrieved through the bounded event
page.

This library is transport-neutral. Any future HTTP/RPC adapter must preserve
the request limits and strict response schemas defined here and add its own
authentication, rate limiting and response-size accounting.
