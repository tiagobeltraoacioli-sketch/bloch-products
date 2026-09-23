use bloch_data_governance::*;

fn hash(byte: char) -> String {
    format!("0x{}", byte.to_string().repeat(64))
}

fn field(
    id: &str,
    classification: DataClassification,
    category: SemanticCategory,
    placement: FieldPlacement,
    required_for: Vec<DataOperation>,
) -> FieldRule {
    FieldRule {
        field_id: id.into(),
        classification,
        semantic_category: category,
        placement,
        required_for,
    }
}

fn policy() -> GovernancePolicy {
    GovernancePolicy {
        schema: GOVERNANCE_POLICY_SCHEMA.into(),
        policy_id: "bank-a-positions-v1".into(),
        version: 1,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "positions".into(),
        dataset_schema_id: "positions-v1".into(),
        purpose_id: "daily-reconciliation".into(),
        effective_at_unix_seconds: 100,
        approval_expires_at_unix_seconds: 900,
        allowed_operations: vec![
            DataOperation::Ingest,
            DataOperation::Read,
            DataOperation::Derive,
            DataOperation::Export,
            DataOperation::PublishCommitment,
            DataOperation::Delete,
        ],
        applicable_jurisdictions: vec!["BR".into()],
        processing_regions: vec!["br-sao-paulo-1".into()],
        storage_regions: vec!["br-sao-paulo-1".into()],
        controller_id: "bank-a".into(),
        operator_id: "bloch-data".into(),
        privacy_contact_id: "privacy-bank-a".into(),
        authorization_evidence_sha256: hash('a'),
        key_domain: "tenant-a-regulated".into(),
        allowed_workload_ids: vec!["indexer-prod-1".into()],
        permitted_recipient_ids: vec!["bank-a-reconciliation".into()],
        forbidden_field_ids: vec!["secret_note".into()],
        retention: RetentionRule {
            dispose_after_unix_seconds: 1_000,
            legal_hold_id: None,
            disposition: RetentionDisposition::Delete,
        },
        fields: vec![
            field(
                "account_id",
                DataClassification::Personal,
                SemanticCategory::AccountIdentifier,
                FieldPlacement::OffChainCommitmentSource,
                vec![DataOperation::Ingest, DataOperation::PublishCommitment],
            ),
            field(
                "balance",
                DataClassification::FinancialConfidential,
                SemanticCategory::Balance,
                FieldPlacement::OffChainCommitmentSource,
                vec![DataOperation::Ingest, DataOperation::PublishCommitment],
            ),
            field(
                "market_code",
                DataClassification::Internal,
                SemanticCategory::Operational,
                FieldPlacement::OffChainOnly,
                vec![DataOperation::Ingest],
            ),
        ],
        onchain_commitments: vec![OnChainCommitmentRule {
            artifact_rule_id: "positions-root-v1".into(),
            construction_id: "randomized-hiding-commitment-v1".into(),
            domain: "bloch-positions-root-v1".into(),
            hidden_source_fields: vec!["account_id".into(), "balance".into()],
        }],
    }
}

fn context(operation: DataOperation) -> DecisionContext {
    let observed_field_ids = match operation {
        DataOperation::Ingest => vec!["account_id".into(), "balance".into(), "market_code".into()],
        DataOperation::PublishCommitment => vec!["account_id".into(), "balance".into()],
        _ => Vec::new(),
    };
    DecisionContext {
        now_unix_seconds: 500,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "positions".into(),
        dataset_schema_id: "positions-v1".into(),
        purpose_id: "daily-reconciliation".into(),
        operation,
        processing_region: "br-sao-paulo-1".into(),
        storage_region: "br-sao-paulo-1".into(),
        jurisdictions: vec!["BR".into()],
        workload_id: "indexer-prod-1".into(),
        key_domain: "tenant-a-regulated".into(),
        recipient_id: None,
        observed_field_ids,
    }
}

#[test]
fn canonical_policy_requires_an_independent_pin() {
    let policy = policy();
    let bytes = canonical_governance_policy_bytes(&policy).unwrap();
    let digest = governance_policy_sha256(&policy).unwrap();
    assert_eq!(parse_governance_policy(&bytes, &digest).unwrap(), policy);
    assert_eq!(
        parse_governance_policy(&bytes, &hash('b')),
        Err(GovernanceError::PolicyDigestMismatch)
    );
    assert!(matches!(
        parse_governance_policy(&bytes, &hash('0')),
        Err(GovernanceError::InvalidPolicy("expectedSha256"))
    ));
}

#[test]
fn strict_policy_rejects_unknown_duplicate_trailing_and_oversize_input() {
    let policy = policy();
    let bytes = canonical_governance_policy_bytes(&policy).unwrap();
    let digest = governance_policy_sha256(&policy).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let unknown = text.replacen('{', "{\"allow\":true,", 1);
    assert!(matches!(
        parse_governance_policy(unknown.as_bytes(), &digest),
        Err(GovernanceError::InvalidJson(_))
    ));
    let duplicate = text.replacen(
        "\"policyId\":",
        "\"policyId\":\"attacker\",\"policyId\":",
        1,
    );
    assert!(matches!(
        parse_governance_policy(duplicate.as_bytes(), &digest),
        Err(GovernanceError::InvalidJson(_))
    ));
    let mut trailing = bytes;
    trailing.push(b'\n');
    assert_eq!(
        parse_governance_policy(&trailing, &digest),
        Err(GovernanceError::NonCanonicalPolicy)
    );
    let oversized = vec![b' '; MAX_POLICY_BYTES + 1];
    assert!(matches!(
        parse_governance_policy(&oversized, &digest),
        Err(GovernanceError::TooLarge { .. })
    ));
}

#[test]
fn valid_ingestion_admits_and_creates_opaque_authorization() {
    let policy = policy();
    let context = context(DataOperation::Ingest);
    let report = evaluate_governance_gate(&policy, &context).unwrap();
    assert!(report.admitted());
    assert!(
        report
            .checks()
            .iter()
            .all(|check| check.outcome() == CheckOutcome::Passed)
    );
    let authorization = authorize_governance_gate(&policy, &context).unwrap();
    assert_eq!(authorization.operation(), DataOperation::Ingest);
}

#[test]
fn identity_purpose_region_jurisdiction_workload_key_and_recipient_fail_closed() {
    let policy = policy();
    for mutate in 0..8 {
        let mut request = context(DataOperation::Ingest);
        match mutate {
            0 => request.tenant_id = "tenant-b".into(),
            1 => request.purpose_id = "marketing".into(),
            2 => request.processing_region = "us-east-1".into(),
            3 => request.storage_region = "us-east-1".into(),
            4 => request.jurisdictions = vec!["US".into()],
            5 => request.workload_id = "unknown".into(),
            6 => request.key_domain = "tenant-b-regulated".into(),
            7 => request.recipient_id = Some("unexpected".into()),
            _ => unreachable!(),
        }
        assert!(
            !evaluate_governance_gate(&policy, &request)
                .unwrap()
                .admitted()
        );
        assert!(matches!(
            authorize_governance_gate(&policy, &request),
            Err(GovernanceError::Denied)
        ));
    }
    let mut export = context(DataOperation::Export);
    assert!(
        !evaluate_governance_gate(&policy, &export)
            .unwrap()
            .admitted()
    );
    export.recipient_id = Some("bank-a-reconciliation".into());
    assert!(
        evaluate_governance_gate(&policy, &export)
            .unwrap()
            .admitted()
    );
}

#[test]
fn fields_must_be_known_minimal_sorted_unique_and_complete() {
    let policy = policy();
    let mut request = context(DataOperation::Ingest);
    request.observed_field_ids.push("secret_note".into());
    assert!(
        !evaluate_governance_gate(&policy, &request)
            .unwrap()
            .admitted()
    );
    request = context(DataOperation::Ingest);
    request.observed_field_ids.push("unknown".into());
    assert!(
        !evaluate_governance_gate(&policy, &request)
            .unwrap()
            .admitted()
    );
    request = context(DataOperation::Ingest);
    request.observed_field_ids.pop();
    assert!(
        !evaluate_governance_gate(&policy, &request)
            .unwrap()
            .admitted()
    );
    request = context(DataOperation::Ingest);
    request.observed_field_ids.push("balance".into());
    assert!(
        !evaluate_governance_gate(&policy, &request)
            .unwrap()
            .admitted()
    );
}

#[test]
fn approval_retention_and_legal_hold_are_enforced() {
    let policy = policy();
    let mut request = context(DataOperation::Read);
    request.now_unix_seconds = 99;
    assert!(
        !evaluate_governance_gate(&policy, &request)
            .unwrap()
            .admitted()
    );
    request.now_unix_seconds = 900;
    assert!(
        !evaluate_governance_gate(&policy, &request)
            .unwrap()
            .admitted()
    );
    let mut deletion = context(DataOperation::Delete);
    deletion.now_unix_seconds = 999;
    assert!(
        !evaluate_governance_gate(&policy, &deletion)
            .unwrap()
            .admitted()
    );
    deletion.now_unix_seconds = 1_000;
    assert!(
        evaluate_governance_gate(&policy, &deletion)
            .unwrap()
            .admitted()
    );
    let mut held = policy.clone();
    held.retention.legal_hold_id = Some("court-hold-1".into());
    assert!(
        !evaluate_governance_gate(&held, &deletion)
            .unwrap()
            .admitted()
    );
}

#[test]
fn only_an_exact_nonzero_commitment_can_be_authorized() {
    let policy = policy();
    let authorization =
        authorize_governance_gate(&policy, &context(DataOperation::PublishCommitment)).unwrap();
    let mut input = OnChainCommitmentInput {
        artifact_rule_id: "positions-root-v1".into(),
        construction_id: "randomized-hiding-commitment-v1".into(),
        domain: "bloch-positions-root-v1".into(),
        commitment: [7; 32],
    };
    let envelope = authorize_onchain_commitment(&authorization, &input).unwrap();
    assert_eq!(envelope.commitment(), format!("0x{}", "07".repeat(32)));
    let bytes = onchain_commitment_envelope_bytes(&envelope).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in [
        "tenant-a",
        "bank-a",
        "positions-v1",
        "account_id",
        "balance",
        "policySha256",
    ] {
        assert!(!text.contains(forbidden));
    }
    assert_eq!(envelope.authorization_context_sha256().len(), 66);
    assert!(text.contains("authorizationContextSha256"));
    let first_context_digest = envelope.authorization_context_sha256().to_owned();
    let mut other_commitment = input.clone();
    other_commitment.commitment = [9; 32];
    let other = authorize_onchain_commitment(&authorization, &other_commitment).unwrap();
    assert_ne!(first_context_digest, other.authorization_context_sha256());
    let mut revised_policy = policy.clone();
    revised_policy.version = 2;
    let revised_authorization =
        authorize_governance_gate(&revised_policy, &context(DataOperation::PublishCommitment))
            .unwrap();
    let revised = authorize_onchain_commitment(&revised_authorization, &input).unwrap();
    assert_ne!(first_context_digest, revised.authorization_context_sha256());
    input.commitment = [0; 32];
    assert_eq!(
        authorize_onchain_commitment(&authorization, &input),
        Err(GovernanceError::InvalidCommitment("commitment"))
    );
}

#[test]
fn commitment_rejects_wrong_rule_construction_domain_operation_and_missing_source() {
    let policy = policy();
    let valid = OnChainCommitmentInput {
        artifact_rule_id: "positions-root-v1".into(),
        construction_id: "randomized-hiding-commitment-v1".into(),
        domain: "bloch-positions-root-v1".into(),
        commitment: [8; 32],
    };
    let ingest = authorize_governance_gate(&policy, &context(DataOperation::Ingest)).unwrap();
    assert!(authorize_onchain_commitment(&ingest, &valid).is_err());
    let authorization =
        authorize_governance_gate(&policy, &context(DataOperation::PublishCommitment)).unwrap();
    for mutate in 0..3 {
        let mut input = valid.clone();
        match mutate {
            0 => input.artifact_rule_id = "unknown".into(),
            1 => input.construction_id = "sha256-raw".into(),
            2 => input.domain = "other-domain".into(),
            _ => unreachable!(),
        }
        assert!(authorize_onchain_commitment(&authorization, &input).is_err());
    }
    let mut incomplete = context(DataOperation::PublishCommitment);
    incomplete.observed_field_ids.pop();
    assert!(matches!(
        authorize_governance_gate(&policy, &incomplete),
        Err(GovernanceError::Denied)
    ));
}

#[test]
fn policy_rejects_commitment_sources_not_explicitly_placed_offchain() {
    let mut invalid_policy = policy();
    invalid_policy.fields[0].placement = FieldPlacement::OffChainOnly;
    assert_eq!(
        canonical_governance_policy_bytes(&invalid_policy),
        Err(GovernanceError::InvalidPolicy("commitmentSourcePlacement"))
    );
    let mut invalid_policy = policy();
    invalid_policy.onchain_commitments[0]
        .hidden_source_fields
        .push("secret_note".into());
    assert!(canonical_governance_policy_bytes(&invalid_policy).is_err());
}

#[test]
fn malformed_or_downgraded_placement_enum_is_not_accepted() {
    let policy = policy();
    let bytes = canonical_governance_policy_bytes(&policy).unwrap();
    let digest = governance_policy_sha256(&policy).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let downgraded = text.replace("off_chain_commitment_source", "on_chain_raw");
    assert!(matches!(
        parse_governance_policy(downgraded.as_bytes(), &digest),
        Err(GovernanceError::InvalidJson(_))
    ));
}
