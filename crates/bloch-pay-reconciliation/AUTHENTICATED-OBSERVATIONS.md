# Authenticated payment observations

## Trust boundary

Authentication proves that the private-key holder named by an independently
pinned observer policy signed one exact canonical observation in one exact
context. It does not prove that the event happened, that its block is final,
that money settled, or that credit or fulfillment is authorized.

The observer policy is canonical JSON and binds:

- its policy ID and signature domain;
- the SHA-256 pin of the reconciliation policy;
- tenant and merchant IDs;
- validity times; and
- each Ed25519 public key to an observer ID, source ID and network.

Every authorized source and network must also exist in the pinned
reconciliation policy. Observer IDs and public keys are unique. Multiple
independent observers may be authorized for the same source/network pair.

## Signing contract

`observation_signing_bytes` produces a binary, length-framed message containing
the fixed protocol domain, deployment signature domain, both policy digests,
tenant, merchant, network, source, observer ID and the complete canonical JSON
bytes of the observation. A signature therefore cannot be replayed across any
of those boundaries.

The external signer returns a raw 64-byte Ed25519 signature. The crate verifies
it before producing a detached canonical JSON envelope. The envelope repeats
the public context, observation digest and signature, but does not contain the
observation. Verification requires both artifacts and both independent policy
pins.

`reconcile_authenticated` accepts only the opaque values returned by successful
verification, checks the reconciliation-policy pin again, recomputes every
canonical observation digest and attaches read-only evidence references to the
report. Each reference contains the observation ID and digest, observer ID,
observer-policy digest and reconciliation-policy digest. The raw `reconcile`
API explicitly marks its report and evidence references unauthenticated.

## Parser and resource limits

- observer policy and signature envelope: at most 64 KiB each;
- canonical observation: at most 16 KiB;
- observer count: 1 through 256;
- unknown or duplicate JSON fields: rejected;
- trailing whitespace or other non-canonical encoding: rejected;
- malformed, uppercase, wrong-length or weak Ed25519 keys: rejected; and
- malformed or wrong-length signatures: rejected.

The implementation has no private-key API, filesystem or network access, and
does not persist allocation state. Durable idempotency and network-specific
finality evidence remain separate production gates.
