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

fn payment_observation(id: &str, transaction_byte: &str) -> PaymentObservation {
    PaymentObservation {
        schema: OBSERVATION_SCHEMA.into(),
        observation_id: id.into(),
        source_id: "source-a".into(),
        network: "bloch-l2".into(),
        transaction_id: format!("0x{}", transaction_byte.repeat(32)),
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

struct Fixture {
    reconciliation: ReconciliationPolicy,
    reconciliation_sha256: String,
    observation: AuthenticatedPaymentObservation,
    second_observation: AuthenticatedPaymentObservation,
    finality: FinalityTrustPolicy,
    finality_sha256: String,
    finality_keys: [SigningKey; 2],
}

impl Fixture {
    fn new() -> Self {
        let reconciliation = reconciliation_policy();
        let reconciliation_sha256 = policy_sha256(&reconciliation).unwrap();
        let observer_key = SigningKey::from_bytes(&[17; 32]);
        let observer_policy = ObserverTrustPolicy {
            schema: OBSERVER_POLICY_SCHEMA.into(),
            policy_id: "observers-v1".into(),
            signature_domain: "bloch-pay-observations".into(),
            reconciliation_policy_sha256: reconciliation_sha256.clone(),
            tenant_id: "tenant-a".into(),
            merchant_id: "merchant-a".into(),
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 9_000,
            observers: vec![TrustedObserver {
                observer_id: "observer-a".into(),
                source_id: "source-a".into(),
                network: "bloch-l2".into(),
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(observer_key.verifying_key().to_bytes())
                ),
            }],
        };
        let observer_sha256 = observer_policy_sha256(&observer_policy).unwrap();
        let authenticate = |raw: PaymentObservation| {
            let message = observation_signing_bytes(
                &reconciliation,
                &reconciliation_sha256,
                &observer_policy,
                &observer_sha256,
                "observer-a",
                &raw,
                500,
            )
            .unwrap();
            let envelope = encode_observation_signature_envelope(
                &reconciliation,
                &reconciliation_sha256,
                &observer_policy,
                &observer_sha256,
                "observer-a",
                &raw,
                500,
                &observer_key.sign(&message).to_bytes(),
            )
            .unwrap();
            verify_authenticated_observation(
                &envelope,
                &reconciliation,
                &reconciliation_sha256,
                &observer_policy,
                &observer_sha256,
                &raw,
                500,
            )
            .unwrap()
        };
        let observation = authenticate(payment_observation("observation-a", "11"));
        let second_observation = authenticate(payment_observation("observation-b", "33"));
        let finality_keys = [
            SigningKey::from_bytes(&[31; 32]),
            SigningKey::from_bytes(&[32; 32]),
        ];
        let finality = FinalityTrustPolicy {
            schema: FINALITY_POLICY_SCHEMA.into(),
            policy_id: "bloch-l2-finality-v1".into(),
            signature_domain: "bloch-pay-prod-finality".into(),
            reconciliation_policy_sha256: reconciliation_sha256.clone(),
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 9_000,
            networks: vec![FinalityNetworkRule {
                network: "bloch-l2".into(),
                minimum_signatures: 2,
                max_evidence_age_seconds: 300,
            }],
            authorities: finality_keys
                .iter()
                .enumerate()
                .map(|(index, key)| FinalityAuthority {
                    authority_id: format!("finality-{}", index + 1),
                    network: "bloch-l2".into(),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().to_bytes())
                    ),
                })
                .collect(),
        };
        let finality_sha256 = finality_policy_sha256(&finality).unwrap();
        Self {
            reconciliation,
            reconciliation_sha256,
            observation,
            second_observation,
            finality,
            finality_sha256,
            finality_keys,
        }
    }

    fn checkpoint(&self, finalized_at: u64) -> FinalityCheckpoint {
        FinalityCheckpoint {
            finalized_block_height: self.observation.observation().block_height,
            finalized_block_hash: self.observation.observation().block_hash.clone(),
            finalized_at_unix_seconds: finalized_at,
        }
    }

    fn evidence_at(
        &self,
        authority_index: usize,
        observation: &AuthenticatedPaymentObservation,
        checkpoint: &FinalityCheckpoint,
    ) -> AuthenticatedFinalityEvidence {
        let authority_id = format!("finality-{}", authority_index + 1);
        let message = finality_signing_bytes(
            &self.reconciliation,
            &self.reconciliation_sha256,
            &self.finality,
            &self.finality_sha256,
            &authority_id,
            observation,
            checkpoint,
            500,
        )
        .unwrap();
        let envelope = encode_finality_signature_envelope(
            &self.reconciliation,
            &self.reconciliation_sha256,
            &self.finality,
            &self.finality_sha256,
            &authority_id,
            observation,
            checkpoint,
            500,
            &self.finality_keys[authority_index]
                .sign(&message)
                .to_bytes(),
        )
        .unwrap();
        verify_authenticated_finality_evidence(
            &envelope,
            &self.reconciliation,
            &self.reconciliation_sha256,
            &self.finality,
            &self.finality_sha256,
            observation,
            500,
        )
        .unwrap()
    }
}

#[test]
fn threshold_qualifies_only_observation_finality() {
    let fixture = Fixture::new();
    let checkpoint = fixture.checkpoint(450);
    let evidence = [
        fixture.evidence_at(1, &fixture.observation, &checkpoint),
        fixture.evidence_at(0, &fixture.observation, &checkpoint),
    ];
    let qualified = evaluate_finality_attestation_threshold(
        &fixture.reconciliation,
        &fixture.reconciliation_sha256,
        &fixture.finality,
        &fixture.finality_sha256,
        &fixture.observation,
        &evidence,
        500,
    )
    .unwrap();

    assert!(qualified.attestation_threshold_met());
    assert!(!qualified.network_finality_qualified());
    assert_eq!(qualified.authority_ids(), ["finality-1", "finality-2"]);
    assert_eq!(
        qualified.observation_sha256(),
        fixture.observation.canonical_observation_sha256()
    );
    assert!(!qualified.settlement_qualified());
    assert!(!qualified.credit_authorized());
    assert!(!qualified.funds_released());
    assert!(!evidence[0].settlement_qualified());
}

#[test]
fn threshold_and_authority_uniqueness_fail_closed() {
    let fixture = Fixture::new();
    let checkpoint = fixture.checkpoint(450);
    let one = fixture.evidence_at(0, &fixture.observation, &checkpoint);
    assert_eq!(
        evaluate_finality_attestation_threshold(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            &fixture.observation,
            std::slice::from_ref(&one),
            500
        ),
        Err(FinalityError::ThresholdNotMet)
    );
    assert_eq!(
        evaluate_finality_attestation_threshold(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            &fixture.observation,
            &[one.clone(), one],
            500
        ),
        Err(FinalityError::DuplicateAuthority)
    );
}

#[test]
fn observation_substitution_and_signature_tampering_are_rejected() {
    let fixture = Fixture::new();
    let checkpoint = fixture.checkpoint(450);
    let message = finality_signing_bytes(
        &fixture.reconciliation,
        &fixture.reconciliation_sha256,
        &fixture.finality,
        &fixture.finality_sha256,
        "finality-1",
        &fixture.observation,
        &checkpoint,
        500,
    )
    .unwrap();
    let envelope = encode_finality_signature_envelope(
        &fixture.reconciliation,
        &fixture.reconciliation_sha256,
        &fixture.finality,
        &fixture.finality_sha256,
        "finality-1",
        &fixture.observation,
        &checkpoint,
        500,
        &fixture.finality_keys[0].sign(&message).to_bytes(),
    )
    .unwrap();
    assert_eq!(
        verify_authenticated_finality_evidence(
            &envelope,
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            &fixture.second_observation,
            500
        ),
        Err(FinalityError::EvidenceMismatch)
    );

    let mut tampered = envelope;
    let marker = b"\"signature\":\"0x";
    let offset = tampered
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    tampered[offset] = if tampered[offset] == b'a' { b'b' } else { b'a' };
    assert_eq!(
        verify_authenticated_finality_evidence(
            &tampered,
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            &fixture.observation,
            500
        ),
        Err(FinalityError::InvalidSignature)
    );
}

#[test]
fn policy_requires_exact_canonical_json_and_independent_pin() {
    let fixture = Fixture::new();
    let bytes = canonical_finality_policy_bytes(&fixture.finality).unwrap();
    assert_eq!(
        parse_finality_policy(&bytes, &fixture.finality_sha256).unwrap(),
        fixture.finality
    );
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    assert_eq!(
        parse_finality_policy(&trailing, &fixture.finality_sha256),
        Err(FinalityError::NonCanonicalJson)
    );
    assert_eq!(
        parse_finality_policy(&bytes, &format!("0x{}", "ab".repeat(32))),
        Err(FinalityError::FinalityPolicyDigestMismatch)
    );
}

#[test]
fn policy_rejects_shared_keys_and_impossible_thresholds() {
    let fixture = Fixture::new();
    let mut shared = fixture.finality.clone();
    shared.authorities[1].ed25519_public_key = shared.authorities[0].ed25519_public_key.clone();
    assert_eq!(
        canonical_finality_policy_bytes(&shared),
        Err(FinalityError::InvalidField("authority"))
    );
    let mut impossible = fixture.finality.clone();
    impossible.networks[0].minimum_signatures = 3;
    assert_eq!(
        canonical_finality_policy_bytes(&impossible),
        Err(FinalityError::InvalidField("minimumSignatures"))
    );
}

#[test]
fn exact_observed_block_and_freshness_are_mandatory() {
    let fixture = Fixture::new();
    let mut wrong_block = fixture.checkpoint(450);
    wrong_block.finalized_block_height += 1;
    assert_eq!(
        finality_signing_bytes(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            "finality-1",
            &fixture.observation,
            &wrong_block,
            500
        ),
        Err(FinalityError::EvidenceMismatch)
    );
    let stale = fixture.checkpoint(199);
    assert_eq!(
        finality_signing_bytes(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            "finality-1",
            &fixture.observation,
            &stale,
            500
        ),
        Err(FinalityError::EvidenceMismatch)
    );
    assert_eq!(
        finality_signing_bytes(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            "finality-1",
            &fixture.observation,
            &fixture.checkpoint(450),
            1_000
        ),
        Err(FinalityError::EvidenceMismatch)
    );
}

#[test]
fn conflicting_authenticated_checkpoints_do_not_combine() {
    let fixture = Fixture::new();
    let first = fixture.evidence_at(0, &fixture.observation, &fixture.checkpoint(450));
    let second = fixture.evidence_at(1, &fixture.observation, &fixture.checkpoint(451));
    assert_eq!(
        evaluate_finality_attestation_threshold(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &fixture.finality_sha256,
            &fixture.observation,
            &[first, second],
            500
        ),
        Err(FinalityError::ConflictingCheckpoint)
    );
}

#[test]
fn all_policy_pins_are_revalidated() {
    let fixture = Fixture::new();
    let checkpoint = fixture.checkpoint(450);
    let evidence = [
        fixture.evidence_at(0, &fixture.observation, &checkpoint),
        fixture.evidence_at(1, &fixture.observation, &checkpoint),
    ];
    assert_eq!(
        evaluate_finality_attestation_threshold(
            &fixture.reconciliation,
            &fixture.reconciliation_sha256,
            &fixture.finality,
            &format!("0x{}", "ab".repeat(32)),
            &fixture.observation,
            &evidence,
            500
        ),
        Err(FinalityError::FinalityPolicyDigestMismatch)
    );
}
