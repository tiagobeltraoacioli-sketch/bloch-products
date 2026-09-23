# Remote cursor quorum collection session

This crate performs one bounded, fail-closed collection from every replica in
an independently pinned replica-quorum policy. It generates a fresh 256-bit
operating-system nonce for each replica by invoking the existing remote-cursor
fetch session, authenticates every observation against `VerifiedTrustedTime`,
binds the response to the requested replica's exact signer set, and only then
passes the in-memory observations to the replica-quorum verifier. The only
successful output is the opaque `VerifiedReplicaQuorum` report.

The caller supplies a transport-neutral callback. Every callback receives the
requested replica ID, expected state identity, unique request nonce, maximum
response size, and an absolute monotonic deadline. The transport must enforce
that deadline on all blocking I/O; `read_bounded_response` is available for
incremental bounded ingress. The collector also enforces a global collection
deadline and a per-replica deadline.

Nonces and raw responses are never returned or persisted by this crate. A
duplicate nonce, duplicate replica, replay under another nonce, signer/replica
substitution, authentication failure, timeout, or incomplete collection aborts
the whole operation without returning partial evidence or a raw fallback.

This crate implements no network protocol, TLS, endpoint discovery, storage,
replication, consensus, leader election, fencing, or HA. Exact signer-set
binding authenticates a configured replica identity; it does not prove that
replicas or their declared failure domains are operationally independent. A
successful quorum comparison is not proof of consensus or linearizability.
