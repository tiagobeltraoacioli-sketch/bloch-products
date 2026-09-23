# Bloch authenticated transport session

Transport-neutral, one-shot composition of authenticated transport evidence and
`VerifiedTrustedTime`. Each session generates a fresh 256-bit CSPRNG nonce in
memory, binds that nonce and the exact request and response bytes to the pinned
transport policy, and releases the response only after threshold evidence has
been verified.

The callback receives borrowed request bytes, the nonce, and one absolute
monotonic deadline. Its bounded collector reads response and evidence streams
incrementally, requests at most 4 KiB per read, passes the same deadline to
every potentially blocking read, and probes for overflow without growing past
the configured limits. An adapter must ensure that its reads actually return
by the supplied deadline; synchronous Rust cannot preempt an implementation
that ignores it.

This crate does **not** open a socket, perform DNS, TLS or mTLS, inspect a live
handshake, manage certificates or private keys, create attestor signatures, or
prove that attestors are independent. The callback and attestors remain
responsible for deriving truthful TLS fields and evidence from the real
exchange. Successful verification proves only that the configured threshold
signed the exact exchange described by the independently pinned policy.
