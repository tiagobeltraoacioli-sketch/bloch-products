use bloch_data_governance::{
    DataClassification, DataOperation, FieldPlacement, FieldRule, GovernanceError,
    GovernancePolicy, OnChainCommitmentRule, RetentionDisposition, RetentionRule, SemanticCategory,
    canonical_governance_policy_bytes, governance_policy_sha256, parse_governance_policy,
};
use bloch_indexer_audit::{
    AuditSigner, AuditTrustPolicy, audit_trust_policy_sha256, canonical_audit_trust_policy_bytes,
};
use bloch_indexer_audit_retention::{
    RetentionCheckpointPolicy, RetentionCheckpointSigner,
    canonical_retention_checkpoint_policy_bytes, retention_checkpoint_policy_sha256,
};
use bloch_indexer_core::{BlockAnchor, ChainIdentity};
use bloch_indexer_delivery_protocol::{
    TrustPolicy, TrustedSigner, canonical_trust_policy_bytes, trust_policy_sha256,
};
use bloch_indexer_input::authenticated::{
    AuthenticationPolicy, TrustedProducer, authentication_policy_sha256,
    canonical_authentication_policy_bytes,
};
use bloch_indexer_service_admission::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

struct Fixture {
    manifest: OperationalManifest,
    producer: Vec<u8>,
    delivery: Vec<u8>,
    audit: Vec<u8>,
    checkpoint: Vec<u8>,
    data_governance: Vec<u8>,
    evidence: Vec<(String, Vec<u8>)>,
}

impl Fixture {
    fn new() -> Self {
        let network = ChainIdentity {
            network: "bloch-l2-mainnet".into(),
            chain_id: 700_771,
            genesis_hash: hash(b"genesis"),
        };
        let anchor = BlockAnchor {
            height: 100,
            block_hash: hash(b"anchor"),
            state_root: hash(b"state"),
        };
        let producer = AuthenticationPolicy {
            deployment_domain: "indexer-producer-prod".into(),
            network: network.clone(),
            anchor: anchor.clone(),
            producers: vec![TrustedProducer {
                producer_id: "producer-1".into(),
                ed25519_public_key: key(1),
            }],
        };
        let delivery = TrustPolicy {
            destination_domain: "indexer-delivery-prod".into(),
            network: network.clone(),
            senders: vec![TrustedSigner {
                signer_id: "sender-1".into(),
                ed25519_public_key: key(2),
            }],
            receivers: vec![TrustedSigner {
                signer_id: "receiver-1".into(),
                ed25519_public_key: key(3),
            }],
        };
        let audit = AuditTrustPolicy {
            audit_domain: "indexer-audit-prod".into(),
            network: network.clone(),
            anchor_tip_hash: anchor.block_hash.clone(),
            signers: vec![AuditSigner {
                signer_id: "audit-1".into(),
                ed25519_public_key: key(4),
            }],
        };
        let checkpoint = RetentionCheckpointPolicy {
            checkpoint_domain: "indexer-checkpoint-prod".into(),
            ledger_id: "ledger-1".into(),
            signers: vec![RetentionCheckpointSigner {
                signer_id: "checkpoint-1".into(),
                ed25519_public_key: key(5),
            }],
        };
        let data_governance = GovernancePolicy {
            schema: bloch_data_governance::GOVERNANCE_POLICY_SCHEMA.into(),
            policy_id: "data-governance-1".into(),
            version: 1,
            institution_id: "postern".into(),
            tenant_id: "bloch".into(),
            dataset_id: "indexer-events".into(),
            dataset_schema_id: "indexer-events-v1".into(),
            purpose_id: "delivery".into(),
            effective_at_unix_seconds: 100,
            approval_expires_at_unix_seconds: 1_000,
            allowed_operations: vec![DataOperation::Ingest, DataOperation::PublishCommitment],
            applicable_jurisdictions: vec!["BR".into()],
            processing_regions: vec!["br-south".into()],
            storage_regions: vec!["br-south".into()],
            controller_id: "postern".into(),
            operator_id: "bloch-ops".into(),
            privacy_contact_id: "privacy-office".into(),
            authorization_evidence_sha256: hash(b"governance-authorization"),
            key_domain: "bloch-data".into(),
            allowed_workload_ids: vec!["delivery-service-1".into()],
            permitted_recipient_ids: vec![],
            forbidden_field_ids: vec![],
            retention: RetentionRule {
                dispose_after_unix_seconds: 900,
                legal_hold_id: None,
                disposition: RetentionDisposition::Delete,
            },
            fields: vec![FieldRule {
                field_id: "account-id".into(),
                classification: DataClassification::Confidential,
                semantic_category: SemanticCategory::CorrelatableIdentifier,
                placement: FieldPlacement::OffChainCommitmentSource,
                required_for: vec![DataOperation::Ingest, DataOperation::PublishCommitment],
            }],
            onchain_commitments: vec![OnChainCommitmentRule {
                artifact_rule_id: "indexer-root".into(),
                construction_id: "randomized-commitment-v1".into(),
                domain: "bloch-indexer-root".into(),
                hidden_source_fields: vec!["account-id".into()],
            }],
        };
        let evidence: Vec<(String, Vec<u8>)> = [
            ("tls-evidence", b"verified TLS deployment artifact".to_vec()),
            (
                "signer-evidence",
                b"verified external signer artifact".to_vec(),
            ),
            (
                "worm-evidence",
                b"verified replicated WORM artifact".to_vec(),
            ),
            ("ha-evidence", b"verified HA exercise artifact".to_vec()),
            (
                "governance-evidence",
                b"reviewed runtime governance enforcement artifact".to_vec(),
            ),
        ]
        .into_iter()
        .map(|(id, bytes)| (id.into(), bytes))
        .collect::<Vec<_>>();
        let capability = |position: usize| Capability::Evidence {
            evidence_id: evidence[position].0.clone(),
            sha256: hash(&evidence[position].1),
        };
        let manifest = OperationalManifest {
            schema: OPERATIONAL_MANIFEST_SCHEMA.into(),
            service_id: "delivery-service-1".into(),
            network,
            anchor,
            domains: ServiceDomains {
                producer: producer.deployment_domain.clone(),
                delivery: delivery.destination_domain.clone(),
                audit: audit.audit_domain.clone(),
                checkpoint: checkpoint.checkpoint_domain.clone(),
            },
            policy_sha256: PolicyDigests {
                producer: authentication_policy_sha256(&producer).unwrap(),
                delivery: trust_policy_sha256(&delivery).unwrap(),
                audit: audit_trust_policy_sha256(&audit).unwrap(),
                checkpoint: retention_checkpoint_policy_sha256(&checkpoint).unwrap(),
                data_governance: governance_policy_sha256(&data_governance).unwrap(),
            },
            storage: StorageBindings {
                snapshot_path: "/srv/bloch/indexer/snapshot.json".into(),
                snapshot_id: "snapshot-1".into(),
                spool_path: "/srv/bloch/indexer/spool".into(),
                spool_id: "spool-1".into(),
                receiver_state_path: "/srv/bloch/indexer/receiver.json".into(),
                audit_ledger_path: "/srv/bloch/indexer/audit-ledger".into(),
                receiver_id: "receiver-1".into(),
                ledger_id: checkpoint.ledger_id.clone(),
            },
            capabilities: ExternalCapabilities {
                network_tls: capability(0),
                external_signer: capability(1),
                replica_worm: capability(2),
                high_availability: capability(3),
                data_governance_enforcement: capability(4),
            },
        };
        Self {
            manifest,
            producer: canonical_authentication_policy_bytes(&producer).unwrap(),
            delivery: canonical_trust_policy_bytes(&delivery).unwrap(),
            audit: canonical_audit_trust_policy_bytes(&audit).unwrap(),
            checkpoint: canonical_retention_checkpoint_policy_bytes(&checkpoint).unwrap(),
            data_governance: canonical_governance_policy_bytes(&data_governance).unwrap(),
            evidence,
        }
    }

    fn evaluate(&self) -> AdmissionReport {
        self.evaluate_with(&self.manifest, &self.evidence)
    }

    fn evaluate_with(
        &self,
        manifest: &OperationalManifest,
        evidence: &[(String, Vec<u8>)],
    ) -> AdmissionReport {
        let manifest_bytes = canonical_manifest_bytes(manifest).unwrap();
        let manifest_digest = operational_manifest_sha256(manifest).unwrap();
        let evidence = evidence
            .iter()
            .map(|(id, bytes)| EvidenceMaterial {
                evidence_id: id,
                bytes,
            })
            .collect::<Vec<_>>();
        evaluate_operational_admission(
            &manifest_bytes,
            &manifest_digest,
            AdmissionMaterials {
                policies: PolicyMaterials {
                    producer: Some(&self.producer),
                    delivery: Some(&self.delivery),
                    audit: Some(&self.audit),
                    checkpoint: Some(&self.checkpoint),
                    data_governance: Some(&self.data_governance),
                },
                evidence: &evidence,
            },
        )
        .unwrap()
    }
}

#[test]
fn admits_only_when_all_policies_and_external_evidence_verify() {
    let fixture = Fixture::new();
    let report = fixture.evaluate();
    assert!(report.admitted());
    assert_eq!(report.checks().len(), 10);
    assert!(
        report
            .checks()
            .iter()
            .all(|check| check.outcome() == CheckOutcome::Passed)
    );
    let bytes = admission_report_bytes(&report).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["admitted"], true);
    assert_eq!(decoded["checks"].as_array().unwrap().len(), 10);
}

#[test]
fn unavailable_capability_is_an_explicit_denial() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest.clone();
    manifest.capabilities.high_availability = Capability::Unavailable {
        reason_code: "not-provisioned".into(),
    };
    let report = fixture.evaluate_with(&manifest, &fixture.evidence);
    assert!(!report.admitted());
    assert_failed(
        &report,
        "capability.high_availability",
        "capability_unavailable",
    );
}

#[test]
fn governance_enforcement_evidence_is_independent_from_the_policy_pin() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest.clone();
    manifest.capabilities.data_governance_enforcement = Capability::Unavailable {
        reason_code: "enforcement-not-attested".into(),
    };
    let report = fixture.evaluate_with(&manifest, &fixture.evidence);
    assert!(!report.admitted());
    assert_failed(
        &report,
        "capability.data_governance_enforcement",
        "capability_unavailable",
    );
    assert!(report.checks().iter().any(|check| {
        check.check_id() == "policy.data_governance" && check.outcome() == CheckOutcome::Passed
    }));
}

#[test]
fn missing_mismatched_and_duplicate_evidence_fail_closed() {
    let fixture = Fixture::new();
    let report = fixture.evaluate_with(&fixture.manifest, &fixture.evidence[..3]);
    assert!(!report.admitted());
    assert_failed(&report, "capability.high_availability", "evidence_missing");
    assert_failed(
        &report,
        "capability.data_governance_enforcement",
        "evidence_missing",
    );

    let mut tampered = fixture.evidence.clone();
    tampered[0].1.push(0);
    let report = fixture.evaluate_with(&fixture.manifest, &tampered);
    assert_failed(
        &report,
        "capability.network_tls",
        "evidence_digest_mismatch",
    );

    let mut duplicate = fixture.evidence.clone();
    duplicate.push(fixture.evidence[0].clone());
    let report = fixture.evaluate_with(&fixture.manifest, &duplicate);
    assert_failed(&report, "capability.network_tls", "evidence_duplicate");
}

#[test]
fn missing_or_wrong_policy_never_admits() {
    let fixture = Fixture::new();
    let bytes = canonical_manifest_bytes(&fixture.manifest).unwrap();
    let digest = operational_manifest_sha256(&fixture.manifest).unwrap();
    let evidence = fixture
        .evidence
        .iter()
        .map(|(id, bytes)| EvidenceMaterial {
            evidence_id: id,
            bytes,
        })
        .collect::<Vec<_>>();
    let report = evaluate_operational_admission(
        &bytes,
        &digest,
        AdmissionMaterials {
            policies: PolicyMaterials {
                producer: None,
                delivery: Some(b"{}"),
                audit: Some(&fixture.audit),
                checkpoint: Some(&fixture.checkpoint),
                data_governance: None,
            },
            evidence: &evidence,
        },
    )
    .unwrap();
    assert!(!report.admitted());
    assert_failed(&report, "policy.producer", "policy_missing");
    assert_failed(&report, "policy.delivery", "policy_invalid");
    assert_failed(&report, "policy.data_governance", "policy_missing");
}

#[test]
fn governance_policy_distinguishes_local_execution_from_on_chain_publication() {
    let fixture = Fixture::new();
    let digest = fixture.manifest.policy_sha256.data_governance.clone();
    let parsed = parse_governance_policy(&fixture.data_governance, &digest).unwrap();
    assert_eq!(
        parsed.fields[0].placement,
        FieldPlacement::OffChainCommitmentSource
    );
    assert!(
        parsed
            .allowed_operations
            .contains(&DataOperation::PublishCommitment)
    );
    assert_eq!(parsed.onchain_commitments.len(), 1);
}

#[test]
fn confidential_or_correlatable_material_cannot_be_placed_on_chain() {
    let fixture = Fixture::new();
    let digest = fixture.manifest.policy_sha256.data_governance.clone();
    let parsed = parse_governance_policy(&fixture.data_governance, &digest).unwrap();
    assert_eq!(
        parsed.fields[0].classification,
        DataClassification::Confidential
    );
    assert_eq!(
        parsed.fields[0].semantic_category,
        SemanticCategory::CorrelatableIdentifier
    );
    let source = String::from_utf8(fixture.data_governance.clone()).unwrap();
    let bytes = source
        .replace("off_chain_commitment_source", "on_chain")
        .into_bytes();
    assert!(matches!(
        parse_governance_policy(&bytes, &hash(&bytes)),
        Err(GovernanceError::InvalidJson(_))
    ));
}

#[test]
fn governance_policy_pin_and_canonical_encoding_are_fail_closed() {
    let fixture = Fixture::new();
    assert_eq!(
        parse_governance_policy(&fixture.data_governance, &hash(b"wrong")).unwrap_err(),
        GovernanceError::PolicyDigestMismatch
    );
    let mut noncanonical = fixture.data_governance;
    noncanonical.push(b'\n');
    assert_eq!(
        parse_governance_policy(&noncanonical, &hash(&noncanonical)).unwrap_err(),
        GovernanceError::NonCanonicalPolicy
    );
}

#[test]
fn policy_context_mismatch_is_reported_even_for_valid_pinned_policy() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest.clone();
    manifest.storage.receiver_id = "receiver-2".into();
    let report = fixture.evaluate_with(&manifest, &fixture.evidence);
    assert!(!report.admitted());
    assert_failed(&report, "policy.delivery", "context_mismatch");
}

#[test]
fn manifest_requires_canonical_bytes_and_independent_digest() {
    let fixture = Fixture::new();
    let canonical = canonical_manifest_bytes(&fixture.manifest).unwrap();
    let digest = operational_manifest_sha256(&fixture.manifest).unwrap();
    let mut padded = canonical.clone();
    padded.push(b'\n');
    assert_eq!(
        parse_operational_manifest(&padded, &hash(&padded)).unwrap_err(),
        AdmissionError::NonCanonicalManifest
    );
    assert_eq!(
        parse_operational_manifest(&canonical, &hash(b"different")).unwrap_err(),
        AdmissionError::ManifestDigestMismatch
    );
    assert_eq!(
        parse_operational_manifest(&canonical, &digest).unwrap(),
        fixture.manifest
    );
}

#[test]
fn unknown_or_duplicate_manifest_fields_are_rejected() {
    let fixture = Fixture::new();
    let bytes = canonical_manifest_bytes(&fixture.manifest).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["callerSaysReady"] = serde_json::Value::Bool(true);
    let unknown = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        parse_operational_manifest(&unknown, &hash(&unknown)),
        Err(AdmissionError::InvalidJson(_))
    ));

    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen(
        "\"serviceId\":\"delivery-service-1\"",
        "\"serviceId\":\"delivery-service-1\",\"serviceId\":\"delivery-service-1\"",
        1,
    );
    assert!(matches!(
        parse_operational_manifest(duplicate.as_bytes(), &hash(duplicate.as_bytes())),
        Err(AdmissionError::NonCanonicalManifest) | Err(AdmissionError::InvalidJson(_))
    ));
}

#[test]
fn unsafe_or_ambiguous_bindings_are_not_canonicalizable() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest.clone();
    manifest.storage.spool_path = "../spool".into();
    assert_eq!(
        canonical_manifest_bytes(&manifest).unwrap_err(),
        AdmissionError::InvalidManifest("storagePaths")
    );

    let mut manifest = fixture.manifest;
    let duplicate = manifest.capabilities.network_tls.clone();
    manifest.capabilities.external_signer = duplicate;
    assert_eq!(
        canonical_manifest_bytes(&manifest).unwrap_err(),
        AdmissionError::InvalidManifest("capabilityEvidence")
    );
}

fn assert_failed(report: &AdmissionReport, id: &str, code: &str) {
    assert!(report.checks().iter().any(|check| {
        check.check_id() == id && check.code() == code && check.outcome() == CheckOutcome::Failed
    }));
}

fn key(seed: u8) -> String {
    format!(
        "0x{}",
        hex::encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes()
        )
    )
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
