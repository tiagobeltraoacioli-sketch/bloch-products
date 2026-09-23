# Bloch indexer delivery transport boundary

Strict, offline request/response codecs for moving authenticated delivery
envelopes and their receiver-signed acceptance receipts across a caller-owned
transport. The crate opens no sockets and implements no HTTP or RPC client or
server.

Decoding authenticates the embedded payload using an independently supplied
`bloch-indexer-delivery-protocol` trust policy. Transport correlation IDs are
not signed. An accepted receipt proves receiver acceptance of one exact
delivery; it is not chain finality and does not acknowledge durable state.

