//! Machine-readable production qualification gates.
//!
//! This module deliberately models evidence that the current verifier cannot
//! authenticate yet. A supplied claim is not a passed gate: only a named,
//! implemented verifier may produce a passing outcome.

use crate::{
    AssessmentReport, NetworkIdentity, VerifyError, network_identity_sha256,
    validate_network_identity,
};
use serde::{Deserialize, Serialize};

pub const QUALIFICATION_POLICY_SCHEMA: &str = "bloch.verify.production-qualification-policy.v1";
pub const QUALIFICATION_REPORT_SCHEMA: &str = "bloch.verify.production-qualification-report.v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProductionQualificationPolicy {
    pub schema: String,
    pub profile_id: String,
    pub expected_network: NetworkIdentity,
    pub all_gates_required: bool,
    pub gates: Vec<QualificationGateDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QualificationGateDefinition {
    pub gate_id: QualificationGateId,
    pub evidence_schema: String,
    pub verifier_id: String,
    pub verifier_status: VerifierStatus,
    pub requirements: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum QualificationGateId {
    NetworkIdentity,
    AuthenticatedComparison,
    OrganizationIndependence,
    CheckpointAncestry,
    ConsensusFinality,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VerifierStatus {
    Implemented,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GateDisposition {
    Passed,
    Failed,
    VerifierUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProductionQualificationReport {
    pub schema: String,
    pub profile_id: String,
    pub expected_network: NetworkIdentity,
    pub expected_network_sha256: String,
    pub assessed_network: NetworkIdentity,
    pub source_assessment_schema: String,
    pub gates: Vec<QualificationGateOutcome>,
    pub production_qualified: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QualificationGateOutcome {
    pub gate_id: QualificationGateId,
    pub evidence_schema: String,
    pub verifier_id: String,
    pub disposition: GateDisposition,
    pub passed: bool,
    pub reason: String,
}

/// The currently approved production profile for Bloch L2.
///
/// Evidence schema identifiers are contracts for future implementations, not
/// an assertion that evidence using those identifiers is already supported.
pub fn bloch_l2_700771_policy(
    expected_network: &NetworkIdentity,
) -> Result<ProductionQualificationPolicy, VerifyError> {
    validate_network_identity(expected_network, "expectedNetwork")?;
    if expected_network.chain_id != 700_771 {
        return Err(VerifyError::InvalidField("expectedNetwork.chainId"));
    }
    Ok(ProductionQualificationPolicy {
        schema: QUALIFICATION_POLICY_SCHEMA.into(),
        profile_id: "bloch-l2-700771-production.v1".into(),
        expected_network: expected_network.clone(),
        all_gates_required: true,
        gates: vec![
            QualificationGateDefinition {
                gate_id: QualificationGateId::NetworkIdentity,
                evidence_schema: "bloch.verify.network-identity.v1".into(),
                verifier_id: "bloch-verify-core.network-identity.v1".into(),
                verifier_status: VerifierStatus::Implemented,
                requirements: vec![
                    "network name matches the reviewed production profile".into(),
                    "chain ID is exactly 700771".into(),
                    "genesis hash matches an independently reviewed pinned value".into(),
                ],
            },
            QualificationGateDefinition {
                gate_id: QualificationGateId::AuthenticatedComparison,
                evidence_schema: "bloch.verify.signed-checkpoint-bundle.v1".into(),
                verifier_id: "bloch-verify-core.assess-signed.v1".into(),
                verifier_status: VerifierStatus::Implemented,
                requirements: vec![
                    "every observation has a valid signature from a pinned operator key".into(),
                    "the independently retained trust-policy digest matches".into(),
                    "observer, freshness, network and checkpoint thresholds pass".into(),
                ],
            },
            QualificationGateDefinition {
                gate_id: QualificationGateId::OrganizationIndependence,
                evidence_schema: "bloch.verify.organization-independence-evidence.v1".into(),
                verifier_id: "bloch-verify-org-independence.unavailable".into(),
                verifier_status: VerifierStatus::NotImplemented,
                requirements: vec![
                    "legal identities and beneficial control are externally verified".into(),
                    "organizations have disjoint administrative control".into(),
                    "infrastructure and signing-key control are independently evidenced".into(),
                    "the reviewer is independent of every observed organization".into(),
                ],
            },
            QualificationGateDefinition {
                gate_id: QualificationGateId::CheckpointAncestry,
                evidence_schema: "bloch.verify.checkpoint-ancestry-proof.v1".into(),
                verifier_id: "bloch-verify-checkpoint-ancestry.unavailable".into(),
                verifier_status: VerifierStatus::NotImplemented,
                requirements: vec![
                    "the proof begins at an independently pinned genesis or trusted anchor".into(),
                    "every parent link through the assessed checkpoint is authenticated".into(),
                    "height, block hash and state root are bound to the proof".into(),
                ],
            },
            QualificationGateDefinition {
                gate_id: QualificationGateId::ConsensusFinality,
                evidence_schema: "bloch.verify.consensus-finality-proof.v1".into(),
                verifier_id: "bloch-verify-consensus-finality.unavailable".into(),
                verifier_status: VerifierStatus::NotImplemented,
                requirements: vec![
                    "a protocol-specific finality proof binds the assessed checkpoint".into(),
                    "the validator set is authenticated from an independent trust root".into(),
                    "quorum weight and every required validator signature are verified".into(),
                    "validator-set transitions from the trust root are authenticated".into(),
                ],
            },
        ],
    })
}

/// Evaluates only capabilities implemented by this binary.
///
/// In particular, this function cannot be convinced by caller-provided
/// booleans or opaque evidence references. Unsupported evidence gates remain
/// `verifierUnavailable`, and the result remains fail-closed.
pub fn evaluate_current_production_gates(
    assessment: &AssessmentReport,
    assessed_network: &NetworkIdentity,
    expected_network: &NetworkIdentity,
) -> Result<ProductionQualificationReport, VerifyError> {
    validate_network_identity(assessed_network, "assessedNetwork")?;
    let policy = bloch_l2_700771_policy(expected_network)?;
    let mut reasons = Vec::new();
    let gates = policy
        .gates
        .iter()
        .map(|definition| {
            let (disposition, passed, reason): (GateDisposition, bool, String) =
                match definition.gate_id {
                    QualificationGateId::NetworkIdentity => {
                        if assessed_network.network == policy.expected_network.network
                            && assessed_network.chain_id == policy.expected_network.chain_id
                            && assessed_network.genesis_hash
                                == policy.expected_network.genesis_hash
                        {
                            (
                                GateDisposition::Passed,
                                true,
                                "assessed network identity matches the reviewed profile".into(),
                            )
                        } else {
                            (
                                GateDisposition::Failed,
                                false,
                                "assessed network name, chain ID or genesis hash does not match the reviewed profile".into(),
                            )
                        }
                    }
                    QualificationGateId::AuthenticatedComparison => {
                        if assessment.authenticated_comparison_passed {
                            (
                                GateDisposition::Passed,
                                true,
                                "authenticated signed-observation comparison passed".into(),
                            )
                        } else {
                            (
                                GateDisposition::Failed,
                                false,
                                "authenticated signed-observation comparison did not pass".into(),
                            )
                        }
                    }
                    QualificationGateId::OrganizationIndependence => (
                        GateDisposition::VerifierUnavailable,
                        false,
                        "no implemented verifier authenticates organizational independence".into(),
                    ),
                    QualificationGateId::CheckpointAncestry => (
                        GateDisposition::VerifierUnavailable,
                        false,
                        "no implemented verifier authenticates checkpoint ancestry".into(),
                    ),
                    QualificationGateId::ConsensusFinality => (
                        GateDisposition::VerifierUnavailable,
                        false,
                        "no implemented verifier authenticates protocol consensus finality".into(),
                    ),
                };
            if !passed {
                reasons.push(reason.clone());
            }
            QualificationGateOutcome {
                gate_id: definition.gate_id,
                evidence_schema: definition.evidence_schema.clone(),
                verifier_id: definition.verifier_id.clone(),
                disposition,
                passed,
                reason,
            }
        })
        .collect::<Vec<_>>();

    // Never upgrade an assessment produced by the underlying verifier. This
    // additional conjunction is intentional defense in depth.
    let production_qualified = assessment.production_qualified
        && policy.all_gates_required
        && gates.iter().all(|gate| gate.passed);

    Ok(ProductionQualificationReport {
        schema: QUALIFICATION_REPORT_SCHEMA.into(),
        profile_id: policy.profile_id,
        expected_network: policy.expected_network,
        expected_network_sha256: network_identity_sha256(expected_network)?,
        assessed_network: assessed_network.clone(),
        source_assessment_schema: assessment.schema.into(),
        gates,
        production_qualified,
        reasons,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OperatorTrustPolicy, SignedEvidenceBundle, SignedNodeObservation, TrustedOperator, assess,
        assess_signed, parse_bundle, signed_observation_message, trust_policy_sha256,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const FIXTURE: &[u8] = include_bytes!("../../../fixtures/valid-checkpoint.json");

    fn production_network() -> NetworkIdentity {
        NetworkIdentity {
            network: "bloch-l2".into(),
            chain_id: 700_771,
            genesis_hash: format!("0x{}", "a".repeat(64)),
        }
    }

    #[test]
    fn policy_names_all_required_evidence_contracts() {
        let expected = production_network();
        let policy = bloch_l2_700771_policy(&expected).unwrap();
        assert_eq!(policy.expected_network.network, expected.network);
        assert_eq!(policy.expected_network.chain_id, expected.chain_id);
        assert_eq!(policy.expected_network.genesis_hash, expected.genesis_hash);
        assert!(policy.all_gates_required);
        assert_eq!(policy.gates.len(), 5);
        assert_eq!(
            policy
                .gates
                .iter()
                .filter(|gate| gate.verifier_status == VerifierStatus::NotImplemented)
                .count(),
            3
        );
        let encoded = serde_json::to_vec(&policy).unwrap();
        let decoded: ProductionQualificationPolicy = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(policy).unwrap()
        );
    }

    #[test]
    fn passing_unsigned_comparison_cannot_pass_any_authentication_gate() {
        let bundle = parse_bundle(FIXTURE).unwrap();
        let assessment = assess(&bundle, 1_790_121_600).unwrap();
        let qualification =
            evaluate_current_production_gates(&assessment, &bundle.network, &production_network())
                .unwrap();
        assert!(qualification.gates.iter().all(|gate| !gate.passed));
        assert!(!qualification.production_qualified);
        assert_eq!(qualification.assessed_network.chain_id, 4);
        assert_eq!(qualification.expected_network.chain_id, 700_771);
        assert_eq!(
            qualification.expected_network_sha256,
            network_identity_sha256(&production_network()).unwrap()
        );
    }

    #[test]
    fn authenticated_comparison_does_not_imply_independence_ancestry_or_finality() {
        let mut unsigned = parse_bundle(FIXTURE).unwrap();
        let network = production_network();
        unsigned.network = network.clone();
        for observation in &mut unsigned.observations {
            observation.network = network.network.clone();
            observation.chain_id = network.chain_id;
            observation.genesis_hash = network.genesis_hash.clone();
        }
        let keys = [
            SigningKey::from_bytes(&[7; 32]),
            SigningKey::from_bytes(&[9; 32]),
        ];
        let policy = OperatorTrustPolicy {
            schema: "bloch.verify.operator-trust-policy.v1".into(),
            policy_id: "qualification-test".into(),
            valid_from_unix_seconds: 1_790_000_000,
            valid_until_unix_seconds: 1_790_200_000,
            comparison: unsigned.policy.clone(),
            operators: unsigned
                .observations
                .iter()
                .zip(&keys)
                .map(|(observation, key)| TrustedOperator {
                    observer_id: observation.observer_id.clone(),
                    organization_id: observation.organization_id.clone(),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().to_bytes())
                    ),
                })
                .collect(),
        };
        let digest = trust_policy_sha256(&policy).unwrap();
        let signed_observations = unsigned
            .observations
            .iter()
            .zip(&keys)
            .map(|(observation, key)| SignedNodeObservation {
                observation: observation.clone(),
                signature: format!(
                    "0x{}",
                    hex::encode(
                        key.sign(&signed_observation_message(&digest, observation).unwrap())
                            .to_bytes()
                    )
                ),
            })
            .collect();
        let signed = SignedEvidenceBundle {
            schema: "bloch.verify.signed-checkpoint-bundle.v1".into(),
            network: unsigned.network,
            checkpoint: unsigned.checkpoint,
            trust_policy_sha256: digest.clone(),
            signed_observations,
        };
        let assessment = assess_signed(&signed, &policy, &digest, 1_790_121_600).unwrap();
        let qualification =
            evaluate_current_production_gates(&assessment, &signed.network, &network).unwrap();

        assert!(qualification.gates[0].passed);
        assert!(qualification.gates[1].passed);
        assert!(qualification.gates[2..].iter().all(|gate| {
            !gate.passed && gate.disposition == GateDisposition::VerifierUnavailable
        }));
        assert!(!qualification.production_qualified);
        assert_eq!(qualification.reasons.len(), 3);
    }

    #[test]
    fn profile_requires_reviewed_chain_and_genesis_and_records_mismatch() {
        let bundle = parse_bundle(FIXTURE).unwrap();
        let assessment = assess(&bundle, 1_790_121_600).unwrap();
        let expected = production_network();
        let qualification =
            evaluate_current_production_gates(&assessment, &bundle.network, &expected).unwrap();
        let identity_gate = &qualification.gates[0];
        assert_eq!(identity_gate.gate_id, QualificationGateId::NetworkIdentity);
        assert_eq!(identity_gate.disposition, GateDisposition::Failed);
        assert!(!identity_gate.passed);
        assert_ne!(
            qualification.assessed_network.genesis_hash,
            qualification.expected_network.genesis_hash
        );

        let mut invalid_expected = expected;
        invalid_expected.chain_id = 4;
        assert_eq!(
            evaluate_current_production_gates(&assessment, &bundle.network, &invalid_expected)
                .unwrap_err(),
            VerifyError::InvalidField("expectedNetwork.chainId")
        );
    }
}
