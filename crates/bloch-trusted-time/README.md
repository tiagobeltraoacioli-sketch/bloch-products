# Bloch trusted time

This crate verifies canonical, nonce-bound time intervals signed by an
Ed25519 threshold under a separately pinned policy. Verification returns an
opaque capability whose time advances from the attested instant using only
the process monotonic clock until an exclusive deadline. Every policy, signed
token and returned capability is bound to one state identity and one exact
remote-cursor policy pin. Consumers therefore do not accept an
operator-supplied wall-clock value or a time proof issued for another state.

The capability can produce a canonical rollback boundary. Production callers
must durably store that boundary in storage that an attacker cannot roll back,
and supply it when verifying the next token. A missing or rollbackable boundary
cannot provide cross-restart rollback protection.

This crate deliberately does not fetch tokens, persist boundaries, manage
keys, synchronize authority clocks, or establish that authorities are
independent. Threshold signatures prove agreement by configured keys, not
clock accuracy, organizational independence, high availability, or regulatory
qualification. Those remain deployment and ceremony gates.

Whether a platform's monotonic clock advances across suspend is platform
specific. Production operation must either prohibit suspend or re-acquire a
fresh token and boundary after resume; this crate does not qualify that host
behavior.
