use bloch_pay_reconciliation::*;
use ed25519_dalek::{Signer, SigningKey};

fn reconciliation_policy() -> ReconciliationPolicy {
    ReconciliationPolicy {
        schema: POLICY_SCHEMA.into(),
        policy_id: "merchant-a-reconciliation-v1".into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        max_invoice_lifetime_seconds: 1_000,
        allowed_source_ids: vec!["source-a".into()],
        routes: vec![PaymentRoute {
            route_id: "blch-l2".into(),
            network: "bloch-l2".into(),
            asset_id: "blch".into(),
            minor_unit_exponent: 18,
            destination: "0x1111111111111111111111111111111111111111".into(),
        }],
    }
}

fn observer_policy(key: &SigningKey, reconciliation_sha256: &str) -> ObserverTrustPolicy {
    ObserverTrustPolicy {
        schema: OBSERVER_POLICY_SCHEMA.into(),
        policy_id: "merchant-a-observers-v1".into(),
        signature_domain: "bloch-pay-prod-observations".into(),
        reconciliation_policy_sha256: reconciliation_sha256.into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        effective_at_unix_seconds: 150,
        expires_at_unix_seconds: 9_000,
        observers: vec![TrustedObserver {
            observer_id: "observer-a".into(),
            source_id: "source-a".into(),
            network: "bloch-l2".into(),
            ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().to_bytes())),
        }],
    }
}

fn observation() -> PaymentObservation {
    PaymentObservation {
        schema: OBSERVATION_SCHEMA.into(),
        observation_id: "observation-a".into(),
        source_id: "source-a".into(),
        network: "bloch-l2".into(),
        transaction_id: format!("0x{}", "11".repeat(32)),
        event_index: 3,
        asset_id: "blch".into(),
        destination: "0x1111111111111111111111111111111111111111".into(),
        reference: "reference-aaaaaaaa".into(),
        amount_minor: 25,
        observed_at_unix_seconds: 300,
        block_height: 900,
        block_hash: format!("0x{}", "22".repeat(32)),
    }
}

fn invoice(amount_minor: u64) -> Invoice {
    Invoice {
        schema: INVOICE_SCHEMA.into(),
        invoice_id: "invoice-a".into(),
        tenant_id: "tenant-a".into(),
        merchant_id: "merchant-a".into(),
        route_id: "blch-l2".into(),
        reference: "reference-aaaaaaaa".into(),
        amount_minor,
        issued_at_unix_seconds: 200,
        expires_at_unix_seconds: 800,
    }
}

struct Fixture {
    key: SigningKey,
    reconciliation: ReconciliationPolicy,
    reconciliation_sha256: String,
    observers: ObserverTrustPolicy,
    observers_sha256: String,
}

impl Fixture {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[17; 32]);
        let reconciliation = reconciliation_policy();
        let reconciliation_sha256 = policy_sha256(&reconciliation).unwrap();
        let observers = observer_policy(&key, &reconciliation_sha256);
        let observers_sha256 = observer_policy_sha256(&observers).unwrap();
        Self {
            key,
            reconciliation,
            reconciliation_sha256,
            observers,
            observers_sha256,
        }
    }

    fn envelope(&self, observation: &PaymentObservation) -> Vec<u8> {
        let message = observation_signing_bytes(
            &self.reconciliation,
            &self.reconciliation_sha256,
            &self.observers,
            &self.observers_sha256,
            "observer-a",
            observation,
            500,
        )
        .unwrap();
        encode_observation_signature_envelope(
            &self.reconciliation,
            &self.reconciliation_sha256,
            &self.observers,
            &self.observers_sha256,
            "observer-a",
            observation,
            500,
            &self.key.sign(&message).to_bytes(),
        )
        .unwrap()
    }
}

#[test]
fn authenticates_exact_observation_without_claiming_finality_or_settlement() {
    let fixture = Fixture::new();
    let observation = observation();
    let envelope = fixture.envelope(&observation);
    let authenticated = verify_authenticated_observation(
        &envelope,
        &fixture.reconciliation,
        &fixture.reconciliation_sha256,
        &fixture.observers,
        &fixture.observers_sha256,
        &observation,
        500,
    )
    .unwrap();

    assert_eq!(authenticated.observation(), &observation);
    assert_eq!(authenticated.observer_id(), "observer-a");
    assert_eq!(
        authenticated.observer_policy_sha256(),
        fixture.observers_sha256
    );
    assert!(!authenticated.finality_qualified());
    assert!(!authenticated.settlement_qualified());
    assert!(!authenticated.credit_authorized());
}

#[test]
fn authenticated_reconciliation_links_every_read_only_evidence_digest() {
    let fixture = Fixture::new();
    let first = observation();
    let mut second = observation();
    second.observation_id = "observation-b".into();
    second.transaction_id = format!("0x{}", "33".repeat(32));
    second.event_index = 4;
    second.block_height = 901;
    second.block_hash = format!("0x{}", "44".repeat(32));

    let authenticate = |observation: &PaymentObservation| {
        verify_authenticated_observation(
            &fixture.envelope(observation),
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            observation,
            500,
        )
        .unwrap()
    };
    let authenticated = vec![authenticate(&second), authenticate(&first)];
    let report = reconcile_authenticated(
        &fixture.reconciliation,
        &fixture.reconciliation_sha256,
        &[invoice(50)],
        &authenticated,
        500,
    )
    .unwrap();

    assert!(report.observations_authenticated());
    assert_eq!(report.observation_evidence().len(), 2);
    for evidence in report.observation_evidence() {
        let source = authenticated
            .iter()
            .find(|item| item.observation().observation_id == evidence.observation_id())
            .unwrap();
        assert!(evidence.authenticated());
        assert_eq!(
            evidence.canonical_observation_sha256(),
            Some(source.canonical_observation_sha256())
        );
        assert_eq!(evidence.observer_id(), Some(source.observer_id()));
        assert_eq!(
            evidence.observer_policy_sha256(),
            Some(fixture.observers_sha256.as_str())
        );
        assert_eq!(
            evidence.reconciliation_policy_sha256(),
            Some(fixture.reconciliation_sha256.as_str())
        );
    }
    assert!(!report.settlement_qualified());
    assert!(!report.credit_authorized());

    assert_eq!(
        reconcile_authenticated(
            &fixture.reconciliation,
            &format!("0x{}", "ab".repeat(32)),
            &[invoice(50)],
            &authenticated,
            500,
        ),
        Err(ReconciliationError::PolicyDigestMismatch)
    );
}

#[test]
fn raw_reconciliation_is_explicitly_unauthenticated() {
    let fixture = Fixture::new();
    let observation = observation();
    let report = reconcile(&fixture.reconciliation, &[invoice(25)], &[observation], 500).unwrap();

    assert!(!report.observations_authenticated());
    let evidence = &report.observation_evidence()[0];
    assert!(!evidence.authenticated());
    assert_eq!(evidence.canonical_observation_sha256(), None);
    assert_eq!(evidence.observer_id(), None);
    assert_eq!(evidence.observer_policy_sha256(), None);
    assert_eq!(evidence.reconciliation_policy_sha256(), None);
}

#[test]
fn policies_and_observations_require_exact_canonical_bounded_json() {
    let fixture = Fixture::new();
    let policy_bytes = canonical_observer_policy_bytes(&fixture.observers).unwrap();
    assert_eq!(
        parse_observer_policy(&policy_bytes, &fixture.observers_sha256).unwrap(),
        fixture.observers
    );

    let mut trailing = policy_bytes.clone();
    trailing.push(b'\n');
    assert_eq!(
        parse_observer_policy(&trailing, &fixture.observers_sha256),
        Err(ObservationAuthenticationError::NonCanonicalJson)
    );
    let text = String::from_utf8(policy_bytes).unwrap();
    let duplicate = text.replacen(
        "\"policyId\":",
        "\"policyId\":\"attacker\",\"policyId\":",
        1,
    );
    assert!(matches!(
        parse_observer_policy(duplicate.as_bytes(), &fixture.observers_sha256),
        Err(ObservationAuthenticationError::InvalidJson { .. })
    ));
    let unknown = text.replacen('{', "{\"trusted\":true,", 1);
    assert!(matches!(
        parse_observer_policy(unknown.as_bytes(), &fixture.observers_sha256),
        Err(ObservationAuthenticationError::InvalidJson { .. })
    ));
    assert!(matches!(
        parse_observer_policy(
            &vec![b' '; MAX_OBSERVER_POLICY_BYTES + 1],
            &fixture.observers_sha256
        ),
        Err(ObservationAuthenticationError::TooLarge { .. })
    ));

    let observation = observation();
    let observation_bytes =
        canonical_observation_bytes(&fixture.reconciliation, &observation, 500).unwrap();
    assert_eq!(
        parse_payment_observation(&observation_bytes, &fixture.reconciliation, 500).unwrap(),
        observation
    );
    let mut observation_trailing = observation_bytes.clone();
    observation_trailing.push(b' ');
    assert_eq!(
        parse_payment_observation(&observation_trailing, &fixture.reconciliation, 500),
        Err(ObservationAuthenticationError::NonCanonicalJson)
    );
}

#[test]
fn signature_cannot_replay_across_observation_network_source_or_domain() {
    let fixture = Fixture::new();
    let observation = observation();
    let envelope = fixture.envelope(&observation);

    let mut changed_amount = observation.clone();
    changed_amount.amount_minor += 1;
    assert!(matches!(
        verify_authenticated_observation(
            &envelope,
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            &changed_amount,
            500,
        ),
        Err(ObservationAuthenticationError::ObservationDigestMismatch)
    ));

    let mut changed_network = observation.clone();
    changed_network.network = "other-l2".into();
    assert!(matches!(
        verify_authenticated_observation(
            &envelope,
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            &changed_network,
            500,
        ),
        Err(ObservationAuthenticationError::UntrustedObserver)
    ));

    let mut other_domain = fixture.observers.clone();
    other_domain.signature_domain = "bloch-pay-staging-observations".into();
    let other_domain_sha = observer_policy_sha256(&other_domain).unwrap();
    assert!(
        verify_authenticated_observation(
            &envelope,
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &other_domain,
            &other_domain_sha,
            &observation,
            500,
        )
        .is_err()
    );
}

#[test]
fn reconciliation_tenant_merchant_and_policy_pins_are_mandatory() {
    let fixture = Fixture::new();
    let observation = observation();
    let envelope = fixture.envelope(&observation);
    let wrong_digest = format!("0x{}", "ab".repeat(32));
    assert_eq!(
        verify_authenticated_observation(
            &envelope,
            &fixture.reconciliation,
            &wrong_digest,
            &fixture.observers,
            &fixture.observers_sha256,
            &observation,
            500,
        ),
        Err(ObservationAuthenticationError::ReconciliationPolicyDigestMismatch)
    );

    let mut other_tenant = fixture.reconciliation.clone();
    other_tenant.tenant_id = "tenant-b".into();
    let other_tenant_sha = policy_sha256(&other_tenant).unwrap();
    assert_eq!(
        observation_signing_bytes(
            &other_tenant,
            &other_tenant_sha,
            &fixture.observers,
            &fixture.observers_sha256,
            "observer-a",
            &observation,
            500,
        ),
        Err(ObservationAuthenticationError::TrustContextMismatch)
    );
}

#[test]
fn envelope_is_strict_and_invalid_signatures_never_encode() {
    let fixture = Fixture::new();
    let observation = observation();
    assert_eq!(
        encode_observation_signature_envelope(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            "observer-a",
            &observation,
            500,
            &[0; 64],
        ),
        Err(ObservationAuthenticationError::InvalidSignature)
    );

    let envelope = fixture.envelope(&observation);
    let text = String::from_utf8(envelope.clone()).unwrap();
    let unknown = text.replacen('{', "{\"settled\":true,", 1);
    assert!(matches!(
        verify_authenticated_observation(
            unknown.as_bytes(),
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            &observation,
            500,
        ),
        Err(ObservationAuthenticationError::InvalidJson { .. })
    ));
    let duplicate = text.replacen(
        "\"observerId\":",
        "\"observerId\":\"attacker\",\"observerId\":",
        1,
    );
    assert!(matches!(
        verify_authenticated_observation(
            duplicate.as_bytes(),
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            &observation,
            500,
        ),
        Err(ObservationAuthenticationError::InvalidJson { .. })
    ));
    let mut trailing = envelope;
    trailing.push(b'\n');
    assert_eq!(
        verify_authenticated_observation(
            &trailing,
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.observers,
            &fixture.observers_sha256,
            &observation,
            500,
        ),
        Err(ObservationAuthenticationError::NonCanonicalJson)
    );
}
