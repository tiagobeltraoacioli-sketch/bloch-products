# Authenticated remote-cursor CAS session

This crate composes one canonical remote-cursor CAS request, mandatory verified
caller authorization, fresh trusted time, an authenticated transport session,
and a threshold-signed CAS receipt. Response bytes are not released as a CAS
result until both the exact transport exchange and the receipt have verified.

The transport callback receives exact canonical request bytes, a fresh
transport nonce, an absolute monotonic deadline, and bounded readers. The
caller authorization's canonical bytes and digest must match an
opaque authorization capability already bound to the exact CAS request. A
detached or substituted authorization cannot be attached to another request.

The successful value is a non-clone opaque capability. It exposes the verified
accepted/refused decision and provenance digests, but not unauthenticated raw
response bytes.

This crate performs no DNS, socket, TLS, storage, replication, consensus,
leader election, fencing, mutation, challenge consumption, or private-key
operation. Transport attestor independence, caller challenge replay protection,
authority independence, linearizability, durability and high availability
remain properties of the deployed adapters and control plane; this verifier
does not claim them.
