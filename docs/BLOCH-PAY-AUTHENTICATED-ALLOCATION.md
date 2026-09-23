# Bloch Pay authenticated allocation

The implemented offline path is deliberately narrow:

1. Canonicalize the reconciliation policy and retain its independently reviewed
   SHA-256 pin.
2. Canonicalize and independently pin an observer trust policy binding each
   Ed25519 public key to one observer, source and network.
3. Verify each exact invoice against an independently pinned issuer policy.
4. Verify the detached, domain-separated signature over the exact canonical
   observation and both observation-policy digests.
5. Reconcile only opaque authorized invoices and authenticated observations.
6. Persist through the stricter allocation API only when the report contains
   matching invoice and observation evidence under the expected policy pins.

The authenticated value and report evidence have private fields, so downstream
callers cannot construct a success claim directly. The allocation receipt binds
the allocation ID, exact report and observation digests, reconciliation-policy
digest, observer identity and observer-policy digest. Reusing an allocation,
observation, or network transaction/event identity with different evidence
fails closed.

A signed checkpoint can carry the complete canonical local allocation state.
Verification requires both the expected generation and state digest from an
independent channel, preventing a still-valid older checkpoint from satisfying
the current-state check. This is portable integrity evidence, not replication.

## Trust boundary

Authentication proves that the configured private-key holder signed the exact
bytes. It does not prove that the observer is independent, that its upstream
data is correct, or that the referenced network event is final. The software
does not hold private keys, contact a network, qualify settlement, authorize
credit, custody assets or release funds. Every report and receipt keeps those
claims false.

The current allocation store is crash-safe and single-host on Unix. Threshold
authority attestations for the exact observed block are available, but they do
not prove network-native consensus or ancestry. Production
still requires qualified independent observers, chain-specific finality
evidence, protected external signing, distributed consistency/HA, privacy and
retention controls, authorized partners and approved operational authorities.
