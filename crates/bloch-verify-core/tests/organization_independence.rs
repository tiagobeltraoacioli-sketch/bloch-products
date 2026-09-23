use bloch_verify_core::organization_independence::{
    IndependenceReviewer, IndependenceSignature, ORGANIZATION_INDEPENDENCE_POLICY_SCHEMA,
    OrganizationControlProfile, OrganizationIndependenceError, OrganizationIndependencePolicy,
    create_organization_independence_evidence, organization_independence_policy_bytes,
    organization_independence_policy_sha256, organization_independence_signature_message,
    parse_organization_independence_policy, verify_organization_independence_evidence,
};
use bloch_verify_core::qualification::{
    GateDisposition, QualificationGateId, evaluate_production_gates_with_organization_independence,
};
use bloch_verify_core::{
    AssessmentReport, AuthenticationBoundary, Checks, NetworkIdentity, VerifyError,
    network_identity_sha256,
};
use ed25519_dalek::{Signer, SigningKey};

struct Fixture {
    policy: OrganizationIndependencePolicy,
    pin: String,
    keys: Vec<SigningKey>,
    bundle: String,
    network: String,
}

impl Fixture {
    fn new() -> Self {
        let digest = |byte: char| format!("0x{}", byte.to_string().repeat(64));
        let organizations = (0..3)
            .map(|index| OrganizationControlProfile {
                organization_id: format!("organization-{index}"),
                legal_identity_evidence_sha256: digest(char::from(b'a' + index)),
                beneficial_control_evidence_sha256: digest(char::from(b'd' + index)),
                administrative_control_domain: format!("admin-{index}"),
                infrastructure_control_domain: format!("infra-{index}"),
                signing_key_control_domain: format!("keys-{index}"),
            })
            .collect();
        let keys = vec![
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[9; 32]),
            SigningKey::from_bytes(&[11; 32]),
        ];
        let reviewers = keys
            .iter()
            .enumerate()
            .map(|(index, key)| IndependenceReviewer {
                reviewer_id: format!("reviewer-{index}"),
                organization_id: format!("review-firm-{index}"),
                control_domain: format!("review-control-{index}"),
                ed25519_public_key: format!("0x{}", hex::encode(key.verifying_key().as_bytes())),
            })
            .collect();
        let network = digest('1');
        let policy = OrganizationIndependencePolicy {
            schema: ORGANIZATION_INDEPENDENCE_POLICY_SCHEMA.into(),
            policy_id: "production-independence".into(),
            signature_domain: "bloch-production-review".into(),
            expected_network_sha256: network.clone(),
            minimum_organizations: 3,
            reviewer_threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            maximum_evidence_age_seconds: 100,
            organizations,
            reviewers,
        };
        let pin = organization_independence_policy_sha256(&policy).unwrap();
        Self {
            policy,
            pin,
            keys,
            bundle: digest('2'),
            network,
        }
    }

    fn evidence(&self) -> Vec<u8> {
        let message = organization_independence_signature_message(
            &self.policy,
            &self.pin,
            &self.bundle,
            200,
            260,
        )
        .unwrap();
        let signatures = self
            .keys
            .iter()
            .take(2)
            .enumerate()
            .map(|(index, key)| IndependenceSignature {
                reviewer_id: format!("reviewer-{index}"),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect();
        create_organization_independence_evidence(
            &self.policy,
            &self.pin,
            &self.bundle,
            200,
            260,
            signatures,
        )
        .unwrap()
    }
}

#[test]
fn verifies_exact_threshold_attestation_and_canonical_policy() {
    let fixture = Fixture::new();
    let policy_bytes = organization_independence_policy_bytes(&fixture.policy).unwrap();
    assert_eq!(
        parse_organization_independence_policy(&policy_bytes, &fixture.pin).unwrap(),
        fixture.policy
    );
    let verified = verify_organization_independence_evidence(
        &fixture.evidence(),
        &fixture.policy,
        &fixture.pin,
        &fixture.bundle,
        &fixture.network,
        220,
    )
    .unwrap();
    assert_eq!(verified.organization_ids().len(), 3);
    assert_eq!(verified.reviewer_ids(), &["reviewer-0", "reviewer-1"]);
    assert!(!verified.external_legal_facts_proven());
    verified.ensure_monotonic_freshness().unwrap();
}

#[test]
fn rejects_bundle_network_policy_and_time_substitution() {
    let fixture = Fixture::new();
    let evidence = fixture.evidence();
    let changed = format!("0x{}", "3".repeat(64));
    for result in [
        verify_organization_independence_evidence(
            &evidence,
            &fixture.policy,
            &fixture.pin,
            &changed,
            &fixture.network,
            220,
        ),
        verify_organization_independence_evidence(
            &evidence,
            &fixture.policy,
            &fixture.pin,
            &fixture.bundle,
            &changed,
            220,
        ),
    ] {
        assert!(matches!(
            result,
            Err(OrganizationIndependenceError::AudienceMismatch)
        ));
    }
    assert!(matches!(
        verify_organization_independence_evidence(
            &evidence,
            &fixture.policy,
            &fixture.pin,
            &fixture.bundle,
            &fixture.network,
            260,
        ),
        Err(OrganizationIndependenceError::InvalidTime)
    ));
}

#[test]
fn rejects_insufficient_or_invalid_signatures() {
    let fixture = Fixture::new();
    let message = organization_independence_signature_message(
        &fixture.policy,
        &fixture.pin,
        &fixture.bundle,
        200,
        260,
    )
    .unwrap();
    let one = vec![IndependenceSignature {
        reviewer_id: "reviewer-0".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.keys[0].sign(&message).to_bytes())
        ),
    }];
    assert_eq!(
        create_organization_independence_evidence(
            &fixture.policy,
            &fixture.pin,
            &fixture.bundle,
            200,
            260,
            one,
        )
        .unwrap_err(),
        OrganizationIndependenceError::ThresholdNotMet
    );
    let invalid = (0..2)
        .map(|index| IndependenceSignature {
            reviewer_id: format!("reviewer-{index}"),
            signature: format!("0x{}", "00".repeat(64)),
        })
        .collect();
    assert_eq!(
        create_organization_independence_evidence(
            &fixture.policy,
            &fixture.pin,
            &fixture.bundle,
            200,
            260,
            invalid,
        )
        .unwrap_err(),
        OrganizationIndependenceError::InvalidSignature
    );
}

#[test]
fn rejects_shared_controls_and_non_independent_reviewer() {
    let fixture = Fixture::new();
    let mut shared_control = fixture.policy.clone();
    shared_control.organizations[1].administrative_control_domain = shared_control.organizations[0]
        .infrastructure_control_domain
        .clone();
    assert_eq!(
        organization_independence_policy_bytes(&shared_control).unwrap_err(),
        OrganizationIndependenceError::InvalidPolicy
    );

    let mut captive_reviewer = fixture.policy;
    captive_reviewer.reviewers[0].organization_id =
        captive_reviewer.organizations[0].organization_id.clone();
    assert_eq!(
        organization_independence_policy_bytes(&captive_reviewer).unwrap_err(),
        OrganizationIndependenceError::InvalidPolicy
    );
}

#[test]
fn qualification_requires_exact_independence_policy_pin_and_bundle() {
    let mut fixture = Fixture::new();
    let network = NetworkIdentity {
        network: "bloch-l2".into(),
        chain_id: 700_771,
        genesis_hash: format!("0x{}", "a".repeat(64)),
    };
    fixture.network = network_identity_sha256(&network).unwrap();
    fixture.policy.expected_network_sha256 = fixture.network.clone();
    fixture.pin = organization_independence_policy_sha256(&fixture.policy).unwrap();
    let capability = verify_organization_independence_evidence(
        &fixture.evidence(),
        &fixture.policy,
        &fixture.pin,
        &fixture.bundle,
        &fixture.network,
        220,
    )
    .unwrap();
    let assessment = AssessmentReport {
        schema: "bloch.verify.assessment-report.v1",
        bundle_sha256: fixture.bundle.clone(),
        evaluated_at_unix_seconds: 220,
        observation_count: 3,
        distinct_organization_count: 3,
        checks: Checks {
            unique_observers: true,
            threshold_satisfied: true,
            observations_fresh: true,
            network_consistent: true,
            checkpoint_consistent: true,
            claimed_finality_covers_checkpoint: true,
        },
        comparison_passed: true,
        authenticated_comparison_passed: true,
        authentication: AuthenticationBoundary {
            observations_signed: true,
            trust_policy_digest_matched: true,
            operator_keys_pinned: true,
            organizations_externally_verified: false,
            checkpoint_ancestry_verified: false,
            finality_authenticated: false,
        },
        production_qualified: true,
        reasons: Vec::new(),
    };
    let report = evaluate_production_gates_with_organization_independence(
        &assessment,
        &network,
        &network,
        &fixture.pin,
        &capability,
    )
    .unwrap();
    let gate = report
        .gates
        .iter()
        .find(|gate| gate.gate_id == QualificationGateId::OrganizationIndependence)
        .unwrap();
    assert_eq!(gate.disposition, GateDisposition::Passed);
    assert!(gate.passed);
    assert!(!report.production_qualified);

    assert_eq!(
        evaluate_production_gates_with_organization_independence(
            &assessment,
            &network,
            &network,
            &format!("0x{}", "f".repeat(64)),
            &capability,
        )
        .unwrap_err(),
        VerifyError::TrustPolicyDigestMismatch
    );
}
