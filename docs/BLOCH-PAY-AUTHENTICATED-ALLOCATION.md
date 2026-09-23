# Bloch Pay authenticated allocation

The implemented offline path is deliberately narrow:

1. Canonicalize the reconciliation policy and retain its independently reviewed
   SHA-256 pin.
2. Canonicalize and independently pin an observer trust policy binding each
   Ed25519 public key to one observer, source and network.
3. Verify the detached, domain-separated signature over the exact canonical
   observation and both policy digests.
4. Reconcile only the resulting opaque authenticated observations.
5. Persist an allocation only when the report contains matching authenticated
   evidence for the same observation, observer and policies.

The authenticated value and report evidence have private fields, so downstream
callers cannot construct a success claim directly. The allocation receipt binds
the allocation ID, exact report and observation digests, reconciliation-policy
digest, observer identity and observer-policy digest. Reusing an allocation,
observation, or network transaction/event identity with different evidence
fails closed.

## Trust boundary

Authentication proves that the configured private-key holder signed the exact
bytes. It does not prove that the observer is independent, that its upstream
data is correct, or that the referenced network event is final. The software
does not hold private keys, contact a network, qualify settlement, authorize
credit, custody assets or release funds. Every report and receipt keeps those
claims false.

The current allocation store is crash-safe and single-host on Unix. Production
still requires qualified independent observers, chain-specific finality
evidence, protected external signing, distributed consistency/HA, privacy and
retention controls, authorized partners and approved operational authorities.
