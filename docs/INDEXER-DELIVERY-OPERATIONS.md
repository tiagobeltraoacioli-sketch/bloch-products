# Indexer delivery operations

This is the implemented offline lifecycle. Files move between operator-owned
components; no crate in this flow opens a network connection or owns a private
key.

1. The worker writes an active intent and durably claims the next outbox record.
2. An external sender signs the exact domain-separated delivery message.
3. The worker verifies that delivery against the claim and pinned policy, then
   stores a canonical transport request.
4. The receiver verifies the request and persists the record outcome plus the
   exact delivery-attempt acceptance before returning bytes to sign.
5. An external receiver signer signs those bytes. The receiver verifies and
   durably stores the receipt before returning a canonical response.
6. The worker stores and re-verifies the response and receipt, then atomically
   persists the ACK and its receiver/policy/delivery/receipt evidence in the
   indexer snapshot.
7. Without an authenticated response, the worker can explicitly persist a
   bounded retry instead. A stored authenticated response cannot be discarded
   through the retry path.

The active job is globally discoverable in the local spool. Exact replay closes
crashes between claim and job creation, receiver intent and signing, receipt and
response return, or durable ACK and terminal marker creation. A response lost
after receiver acceptance can be retried with a new attempt-bound receipt while
the receiver reuses the original record outcome.

The operator must provision sender, receiver, audit and retention-checkpoint
policy digests through independent configuration paths. Signing occurs outside
these crates. Low-level core ACK functions do not authenticate receipts and
must not be exposed by a deployment that requires receiver-authenticated ACKs.

Still open for production:

- authenticated TLS/mTLS or equivalent network adapters;
- HSM/KMS-backed external signing and key rotation ceremonies;
- monitoring, quotas, backup and disaster-recovery procedures;
- replicated or WORM audit retention;
- distributed database coordination and HA failover;
- independently established L2 consensus finality.

None of the delivery, receipt, audit or retention signatures proves chain
finality or authorizes bridge, DEX, custody or asset movement.
