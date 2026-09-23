# Deterministic EVM RPC batch capture

`bloch-verify-evm-capture` creates the exact four-call JSON-RPC batch expected by
the offline adapter and imports the retained response without making any
network connection itself.

Create a new request file:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-evm-capture -- \
  request --out path/to/new-request.json
```

Send that file to the reviewed endpoint using the operator's separately
controlled transport. Retain the unmodified response and independently record
the endpoint commitment, capture time and deployed release revision. The
transport is intentionally outside this tool so endpoint authentication and
network policy remain explicit operator responsibilities.

Import an unordered four-entry batch response:

```sh
cargo run --release --locked --offline \
  --bin bloch-verify-evm-capture -- \
  import \
  --response path/to/retained-response.json \
  --observer-id REVIEWED_OBSERVER_ID \
  --organization-id REVIEWED_ORGANIZATION_ID \
  --endpoint-sha256 0xREVIEWED_ENDPOINT_SHA256 \
  --observed-at REVIEWED_UNIX_SECONDS \
  --network bloch-l2 \
  --release-revision 0xREVIEWED_40_HEX_GIT_REVISION \
  --capture-out path/to/new-capture.json
```

The importer correlates response IDs with the generated requests, refuses
duplicates, missing or unknown IDs, validates the complete capture through the
strict EVM adapter, and creates the output only if it does not already exist.
The resulting capture still represents one node operator's claims and must go
through conversion, detached signing and independent comparison.
