# Indexer external-signing ceremony

`bloch-indexer-signing-ceremony` keeps sender and receiver private keys outside
the indexer processes. It only emits the exact domain-separated bytes to sign
and imports a raw 64-byte Ed25519 signature. It never accepts a private-key
path, seed, mnemonic, KMS credential, or network endpoint.

Build it offline from the locked workspace:

```sh
cargo build --release --locked --offline --bin bloch-indexer-signing-ceremony
CEREMONY=target/release/bloch-indexer-signing-ceremony
```

All inputs must be non-empty regular files no larger than 1 MiB, must not be
symlinks or hardlinks, and must not be group/world writable. Output parent
directories must be real, non-group/world-writable directories. Outputs are
create-once mode `0600`. Repeating a command succeeds only when the existing
output is byte-for-byte identical, which supports recovery without allowing
replacement. Use a private directory (`0700`) and transfer `message.bin` to
the isolated signer by an authenticated process.

## Sender delivery

```sh
"$CEREMONY" prepare-delivery \
  --record record.json \
  --trust-policy delivery-policy.json \
  --expected-trust-policy-sha256 0xPIN_REVIEWED_INDEPENDENTLY \
  --sender-id sender-1 \
  --attempt 1 \
  --generation 1 \
  --request-out delivery-signing-request.json \
  --message-out delivery-message.bin

# On the isolated signer, sign delivery-message.bin and return exactly 64 raw bytes.

"$CEREMONY" import-delivery \
  --request delivery-signing-request.json \
  --signature delivery-signature.bin \
  --trust-policy delivery-policy.json \
  --expected-trust-policy-sha256 0xPIN_REVIEWED_INDEPENDENTLY \
  --delivery-out delivery.json
```

The canonical request includes the complete delivery context, canonical record,
independent policy pin, exact message, and message digest. Import recomputes all
of them and verifies the final delivery before publishing it.

## Operational receiver

Production-like receiver processing must use the durable receiver commands.
The store records the accepted record outcome and acceptance intent before a
message is released for signing, then records the verified receipt before the
transport response is returned.

```sh
mkdir receiver-store
chmod 700 receiver-store

"$CEREMONY" receiver-prepare \
  --transport-request transport-request.json \
  --store receiver-store \
  --trust-policy delivery-policy.json \
  --expected-trust-policy-sha256 0xPIN_REVIEWED_INDEPENDENTLY \
  --receiver-id receiver-1 \
  --message-out receipt-message.bin \
  --response-out transport-response.json

# If receipt-message.bin was produced, sign it externally and import it.
"$CEREMONY" receiver-import \
  --transport-request transport-request.json \
  --store receiver-store \
  --signature receipt-signature.bin \
  --trust-policy delivery-policy.json \
  --expected-trust-policy-sha256 0xPIN_REVIEWED_INDEPENDENTLY \
  --receiver-id receiver-1 \
  --response-out transport-response.json
```

If the acceptance is already complete, `receiver-prepare` recovers the exact
stored transport response at `--response-out` and does not require another
signature. A conflicting request or outcome is refused.

`prepare-receipt` and `import-receipt` also exist for protocol fixtures and
offline interoperability tests. They produce a cryptographically valid receipt
but do not persist the receiver outcome. They are not the operational receiver
workflow.

These signatures authenticate delivery and receiver acceptance only. They do
not establish L2 finality, bridge finality, custody authorization, automatic
sender ACK, WORM retention, or multi-host coordination.
