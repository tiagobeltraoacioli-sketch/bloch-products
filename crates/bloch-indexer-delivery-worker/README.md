# Bloch indexer delivery worker

Local, crash-recoverable orchestration for one exact durable outbox claim:

1. persist a globally discoverable active intent;
2. acquire the durable claim;
3. accept an externally signed delivery and encode its transport request;
4. import and authenticate caller-transported response bytes;
5. persist the receiver receipt and durably ACK the exact claim; or
6. schedule an explicit bounded retry before a response is accepted.

The worker opens no socket and owns no private key. Job, request, response,
receipt, retry intent, and completion files are private, bounded, canonical,
create-once artifacts. Their deterministic job identity commits to claim,
record digest, and trust-policy digest. A local advisory lock serializes each
job and the active-job pointer.

This crate intentionally does not provide network transport, signing, chain
finality, distributed locking, HA failover, or WORM retention. Those remain
caller-owned operational boundaries.
