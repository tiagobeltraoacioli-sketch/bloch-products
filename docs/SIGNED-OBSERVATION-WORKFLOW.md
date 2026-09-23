# Signed observation workflow

This workflow authenticates the exact bytes of node observations without
placing operator private keys in this repository or its CLI. It does not prove
checkpoint ancestry, consensus finality or real-world organizational
independence, and therefore cannot produce a production-qualified report.

## Preconditions

- Review the operator trust policy through a separate governance process.
- Retain its expected SHA-256 through an independent channel.
- Keep each Ed25519 private key in its operator's external signer.
- Use a new output directory and new output filenames for every run.

Build the offline tools:

```sh
cargo build --release --locked --offline \
  --bin bloch-verify-ceremony --bin bloch-verify
```

Set paths and the independently reviewed policy digest:

```sh
CEREMONY=target/operator-observation-ceremony-20260923
POLICY=path/to/operator-trust-policy.json
OBSERVATION=path/to/operator-observation.json
EXPECTED_POLICY_SHA256=0xREPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS
```

Prepare the exact message and its reviewable request:

```sh
target/release/bloch-verify-ceremony prepare \
  --observation "$OBSERVATION" \
  --trust-policy "$POLICY" \
  --expected-trust-policy-sha256 "$EXPECTED_POLICY_SHA256" \
  --out-dir "$CEREMONY"
```

The command creates `message.bin` and `request.json` in a new private
directory. Transfer `message.bin` to the operator's reviewed Ed25519 signer.
The signer must sign those bytes exactly and return a raw 64-byte Ed25519
signature. Signer-specific commands are deliberately outside this tool because
key custody and hardware differ between operators.

Import and cryptographically verify the returned signature:

```sh
target/release/bloch-verify-ceremony import \
  --request "$CEREMONY/request.json" \
  --signature path/to/operator-signature.bin \
  --response-out "$CEREMONY/response.json"
```

Repeat preparation and import independently for every observer. Assemble the
responses only with the same externally reviewed trust policy:

```sh
target/release/bloch-verify-ceremony assemble \
  --trust-policy "$POLICY" \
  --expected-trust-policy-sha256 "$EXPECTED_POLICY_SHA256" \
  --response path/to/operator-a-response.json \
  --response path/to/operator-b-response.json \
  --bundle-out target/signed-checkpoint-bundle.json
```

Assess at an explicitly reviewed Unix timestamp:

```sh
target/release/bloch-verify assess-signed \
  --bundle target/signed-checkpoint-bundle.json \
  --trust-policy "$POLICY" \
  --expected-trust-policy-sha256 "$EXPECTED_POLICY_SHA256" \
  --at REVIEWED_UNIX_TIMESTAMP \
  --require-authenticated-comparison
```

All inputs are size-bounded and must be regular, single-link files that are not
group- or world-writable. Outputs use create-only semantics; an existing path
is refused. Any digest, identity, key, network, checkpoint or signature
mismatch is rejected. Partial output directories must be retained for audit or
abandoned; retry with a new directory rather than editing generated artifacts.
