use bloch_trusted_time::{
    TRUSTED_TIME_POLICY_SCHEMA, TrustedTimeAuthority, TrustedTimePolicy, TrustedTimeSignature,
    create_trusted_time_token, trusted_time_policy_sha256, trusted_time_signature_message,
    verify_trusted_time_token,
};
use bloch_verify_core::checkpoint_ancestry::{
    AncestryAuthority, AncestrySignature, CHECKPOINT_ANCESTRY_POLICY_SCHEMA,
    CheckpointAncestryAudience, CheckpointAncestryError, CheckpointAncestryPolicy,
    checkpoint_ancestry_policy_bytes, checkpoint_ancestry_policy_sha256,
    checkpoint_ancestry_signature_message, create_checkpoint_ancestry_evidence,
    verify_checkpoint_ancestry_evidence,
};
use bloch_verify_core::qualification::{
    GateDisposition, ProductionGateCapabilities, QualificationGateId,
    evaluate_current_production_gates, evaluate_production_gates_with_capabilities,
};
use bloch_verify_core::{
    AssessmentReport, AuthenticationBoundary, Checks, EvmAncestryEvidence, NetworkIdentity,
    network_identity_sha256, parse_evm_ancestry_evidence,
};
use ed25519_dalek::{Signer, SigningKey};

const NONCE: &str = "ancestry_time_nonce_0123456789abcdef0123456789abcdef";

struct Fixture {
    ancestry: EvmAncestryEvidence,
    ancestry_policy: CheckpointAncestryPolicy,
    ancestry_pin: String,
    ancestry_keys: Vec<SigningKey>,
    bundle: String,
    network_sha256: String,
    time_policy: TrustedTimePolicy,
    time_pin: String,
    time_keys: Vec<SigningKey>,
}

impl Fixture {
    fn new() -> Self {
        let ancestry = parse_evm_ancestry_evidence(include_bytes!(
            "../../../fixtures/valid-evm-ancestry.json"
        ))
        .unwrap();
        let network_sha256 = network_identity_sha256(&ancestry.network).unwrap();
        let time_keys = vec![
            SigningKey::from_bytes(&[31; 32]),
            SigningKey::from_bytes(&[32; 32]),
        ];
        let time_policy = TrustedTimePolicy {
            schema: TRUSTED_TIME_POLICY_SCHEMA.into(),
            policy_id: "ancestry-time".into(),
            signature_domain: "bloch-ancestry-time".into(),
            state_identity: "verify:ancestry:700771".into(),
            remote_cursor_policy_sha256: format!("0x{}", "9".repeat(64)),
            threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 10_000,
            max_token_lifetime_seconds: 200,
            authorities: time_keys
                .iter()
                .enumerate()
                .map(|(index, key)| TrustedTimeAuthority {
                    authority_id: format!("time-{index}"),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let time_pin = trusted_time_policy_sha256(&time_policy).unwrap();
        let ancestry_keys = vec![
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
        ];
        let ancestry_policy = CheckpointAncestryPolicy {
            schema: CHECKPOINT_ANCESTRY_POLICY_SCHEMA.into(),
            policy_id: "bloch-l2-ancestry".into(),
            signature_domain: "bloch-checkpoint-ancestry".into(),
            expected_network_sha256: network_sha256.clone(),
            trusted_anchor_height: ancestry.finalized.height,
            trusted_anchor_block_hash: ancestry.finalized.block_hash.clone(),
            trusted_anchor_state_root: ancestry.finalized.state_root.clone(),
            trusted_time_policy_sha256: time_pin.clone(),
            trusted_time_state_identity: time_policy.state_identity.clone(),
            authority_threshold: 2,
            effective_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 10_000,
            maximum_evidence_age_seconds: 100,
            authorities: ancestry_keys
                .iter()
                .enumerate()
                .map(|(index, key)| AncestryAuthority {
                    authority_id: format!("ancestry-{index}"),
                    organization_id: format!("organization-{index}"),
                    control_domain: format!("control-{index}"),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let ancestry_pin = checkpoint_ancestry_policy_sha256(&ancestry_policy).unwrap();
        Self {
            ancestry,
            ancestry_policy,
            ancestry_pin,
            ancestry_keys,
            bundle: format!("0x{}", "8".repeat(64)),
            network_sha256,
            time_policy,
            time_pin,
            time_keys,
        }
    }

    fn audience(&self) -> CheckpointAncestryAudience<'_> {
        CheckpointAncestryAudience {
            assessed_bundle_sha256: &self.bundle,
            expected_network_sha256: &self.network_sha256,
            expected_checkpoint: &self.ancestry.checkpoint,
        }
    }

    fn evidence(&self) -> Vec<u8> {
        let message = checkpoint_ancestry_signature_message(
            &self.ancestry_policy,
            &self.ancestry_pin,
            &self.ancestry,
            &self.audience(),
            2_000,
            2_100,
        )
        .unwrap();
        let signatures = self
            .ancestry_keys
            .iter()
            .enumerate()
            .map(|(index, key)| AncestrySignature {
                authority_id: format!("ancestry-{index}"),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect();
        create_checkpoint_ancestry_evidence(
            &self.ancestry_policy,
            &self.ancestry_pin,
            &self.ancestry,
            &self.audience(),
            2_000,
            2_100,
            signatures,
        )
        .unwrap()
    }

    fn trusted_time(&self) -> bloch_trusted_time::VerifiedTrustedTime {
        let message =
            trusted_time_signature_message(&self.time_policy, &self.time_pin, NONCE, 2_020, 2_150)
                .unwrap();
        let signatures = self
            .time_keys
            .iter()
            .enumerate()
            .map(|(index, key)| TrustedTimeSignature {
                authority_id: format!("time-{index}"),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let token = create_trusted_time_token(
            &self.time_policy,
            &self.time_pin,
            NONCE,
            2_020,
            2_150,
            &signatures,
        )
        .unwrap();
        verify_trusted_time_token(&token, &self.time_policy, &self.time_pin, NONCE, None).unwrap()
    }

    fn capability(&self) -> bloch_verify_core::checkpoint_ancestry::VerifiedCheckpointAncestry {
        verify_checkpoint_ancestry_evidence(
            &self.evidence(),
            &self.ancestry_policy,
            &self.ancestry_pin,
            &self.ancestry,
            &self.audience(),
            &self.trusted_time(),
        )
        .unwrap()
    }
}

#[test]
fn verifies_exact_threshold_parent_linkage_without_claiming_finality() {
    let fixture = Fixture::new();
    assert_eq!(
        checkpoint_ancestry_policy_bytes(&fixture.ancestry_policy).unwrap(),
        serde_json::to_vec(&fixture.ancestry_policy).unwrap()
    );
    let capability = fixture.capability();
    assert_eq!(capability.policy_sha256(), fixture.ancestry_pin);
    assert_eq!(capability.assessed_bundle_sha256(), fixture.bundle);
    assert_eq!(capability.authority_ids(), &["ancestry-0", "ancestry-1"]);
    assert_eq!(capability.deadline_unix_seconds(), 2_100);
    assert!(!capability.consensus_finality_authenticated());
    capability.ensure_monotonic_freshness().unwrap();
}

#[test]
fn rejects_bundle_network_checkpoint_anchor_and_time_substitution() {
    let fixture = Fixture::new();
    let evidence = fixture.evidence();
    let time = fixture.trusted_time();
    let changed = format!("0x{}", "7".repeat(64));
    let wrong_bundle = CheckpointAncestryAudience {
        assessed_bundle_sha256: &changed,
        ..fixture.audience()
    };
    assert_eq!(
        verify_checkpoint_ancestry_evidence(
            &evidence,
            &fixture.ancestry_policy,
            &fixture.ancestry_pin,
            &fixture.ancestry,
            &wrong_bundle,
            &time,
        )
        .unwrap_err(),
        CheckpointAncestryError::AudienceMismatch
    );
    let wrong_network = CheckpointAncestryAudience {
        expected_network_sha256: &changed,
        ..fixture.audience()
    };
    assert_eq!(
        verify_checkpoint_ancestry_evidence(
            &evidence,
            &fixture.ancestry_policy,
            &fixture.ancestry_pin,
            &fixture.ancestry,
            &wrong_network,
            &time,
        )
        .unwrap_err(),
        CheckpointAncestryError::AudienceMismatch
    );
    let mut checkpoint = fixture.ancestry.checkpoint.clone();
    checkpoint.block_hash = format!("0x{}", "e".repeat(64));
    let wrong_checkpoint = CheckpointAncestryAudience {
        expected_checkpoint: &checkpoint,
        ..fixture.audience()
    };
    assert_eq!(
        verify_checkpoint_ancestry_evidence(
            &evidence,
            &fixture.ancestry_policy,
            &fixture.ancestry_pin,
            &fixture.ancestry,
            &wrong_checkpoint,
            &time,
        )
        .unwrap_err(),
        CheckpointAncestryError::AudienceMismatch
    );
    let mut wrong_anchor = fixture.ancestry_policy.clone();
    wrong_anchor.trusted_anchor_block_hash = format!("0x{}", "f".repeat(64));
    let wrong_pin = checkpoint_ancestry_policy_sha256(&wrong_anchor).unwrap();
    assert_eq!(
        verify_checkpoint_ancestry_evidence(
            &evidence,
            &wrong_anchor,
            &wrong_pin,
            &fixture.ancestry,
            &fixture.audience(),
            &time,
        )
        .unwrap_err(),
        CheckpointAncestryError::AudienceMismatch
    );
    let mut wrong_time_policy = fixture.ancestry_policy.clone();
    wrong_time_policy.trusted_time_state_identity = "different:state".into();
    let wrong_time_pin = checkpoint_ancestry_policy_sha256(&wrong_time_policy).unwrap();
    let message = checkpoint_ancestry_signature_message(
        &wrong_time_policy,
        &wrong_time_pin,
        &fixture.ancestry,
        &fixture.audience(),
        2_000,
        2_100,
    )
    .unwrap();
    let signatures = fixture
        .ancestry_keys
        .iter()
        .enumerate()
        .map(|(index, key)| AncestrySignature {
            authority_id: format!("ancestry-{index}"),
            signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
        })
        .collect();
    let wrong_evidence = create_checkpoint_ancestry_evidence(
        &wrong_time_policy,
        &wrong_time_pin,
        &fixture.ancestry,
        &fixture.audience(),
        2_000,
        2_100,
        signatures,
    )
    .unwrap();
    assert_eq!(
        verify_checkpoint_ancestry_evidence(
            &wrong_evidence,
            &wrong_time_policy,
            &wrong_time_pin,
            &fixture.ancestry,
            &fixture.audience(),
            &time,
        )
        .unwrap_err(),
        CheckpointAncestryError::TrustedTimeMismatch
    );
}

#[test]
fn rejects_insufficient_invalid_duplicate_and_weak_authorities() {
    let fixture = Fixture::new();
    let message = checkpoint_ancestry_signature_message(
        &fixture.ancestry_policy,
        &fixture.ancestry_pin,
        &fixture.ancestry,
        &fixture.audience(),
        2_000,
        2_100,
    )
    .unwrap();
    let one = vec![AncestrySignature {
        authority_id: "ancestry-0".into(),
        signature: format!(
            "0x{}",
            hex::encode(fixture.ancestry_keys[0].sign(&message).to_bytes())
        ),
    }];
    assert_eq!(
        create_checkpoint_ancestry_evidence(
            &fixture.ancestry_policy,
            &fixture.ancestry_pin,
            &fixture.ancestry,
            &fixture.audience(),
            2_000,
            2_100,
            one,
        )
        .unwrap_err(),
        CheckpointAncestryError::ThresholdNotMet
    );
    let mut weak = fixture.ancestry_policy;
    weak.authorities[0].ed25519_public_key = format!("0x{}", "00".repeat(32));
    assert_eq!(
        checkpoint_ancestry_policy_bytes(&weak).unwrap_err(),
        CheckpointAncestryError::InvalidPolicy
    );
}

fn assessment(bundle: String) -> AssessmentReport {
    AssessmentReport {
        schema: "bloch.verify.assessment-report.v1",
        bundle_sha256: bundle,
        evaluated_at_unix_seconds: 2_020,
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
    }
}

#[test]
fn qualification_is_fail_closed_and_keeps_finality_separate() {
    let fixture = Fixture::new();
    let capability = fixture.capability();
    let assessment = assessment(fixture.bundle.clone());
    let default = evaluate_current_production_gates(
        &assessment,
        &fixture.ancestry.network,
        &fixture.ancestry.network,
    )
    .unwrap();
    let default_gate = default
        .gates
        .iter()
        .find(|gate| gate.gate_id == QualificationGateId::CheckpointAncestry)
        .unwrap();
    assert_eq!(default_gate.disposition, GateDisposition::Failed);

    let report = evaluate_production_gates_with_capabilities(
        &assessment,
        &fixture.ancestry.network,
        &fixture.ancestry.network,
        ProductionGateCapabilities {
            organization_independence: None,
            checkpoint_ancestry: Some((&fixture.ancestry_pin, &capability)),
        },
    )
    .unwrap();
    let ancestry_gate = report
        .gates
        .iter()
        .find(|gate| gate.gate_id == QualificationGateId::CheckpointAncestry)
        .unwrap();
    let finality_gate = report
        .gates
        .iter()
        .find(|gate| gate.gate_id == QualificationGateId::ConsensusFinality)
        .unwrap();
    assert!(ancestry_gate.passed);
    assert!(!finality_gate.passed);
    assert_eq!(
        finality_gate.disposition,
        GateDisposition::VerifierUnavailable
    );
    assert!(!report.production_qualified);
}

#[test]
fn production_fixture_has_expected_network_identity() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.ancestry.network,
        NetworkIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: format!("0x{}", "3".repeat(64)),
        }
    );
}
