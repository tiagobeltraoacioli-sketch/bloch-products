use bloch_data_governance::*;

fn hash(byte: char) -> String {
    format!("0x{}", byte.to_string().repeat(64))
}

fn policy() -> GovernancePolicy {
    GovernancePolicy {
        schema: GOVERNANCE_POLICY_SCHEMA.into(),
        policy_id: "bank-a-position-commitment-v1".into(),
        version: 1,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "positions".into(),
        dataset_schema_id: "positions-v1".into(),
        purpose_id: "reconciliation".into(),
        effective_at_unix_seconds: 100,
        approval_expires_at_unix_seconds: 1_000,
        allowed_operations: vec![DataOperation::Ingest, DataOperation::PublishCommitment],
        applicable_jurisdictions: vec!["BR".into()],
        processing_regions: vec!["br-sao-paulo-1".into()],
        storage_regions: vec!["br-sao-paulo-1".into()],
        controller_id: "bank-a".into(),
        operator_id: "bloch-data".into(),
        privacy_contact_id: "privacy-bank-a".into(),
        authorization_evidence_sha256: hash('a'),
        key_domain: "tenant-a-key".into(),
        allowed_workload_ids: vec!["worker-1".into()],
        permitted_recipient_ids: vec![],
        forbidden_field_ids: vec![],
        retention: RetentionRule {
            dispose_after_unix_seconds: 2_000,
            legal_hold_id: None,
            disposition: RetentionDisposition::Delete,
        },
        fields: vec![
            FieldRule {
                field_id: "account_id".into(),
                classification: DataClassification::Personal,
                semantic_category: SemanticCategory::AccountIdentifier,
                placement: FieldPlacement::OffChainCommitmentSource,
                required_for: vec![DataOperation::Ingest, DataOperation::PublishCommitment],
            },
            FieldRule {
                field_id: "balance".into(),
                classification: DataClassification::FinancialConfidential,
                semantic_category: SemanticCategory::Balance,
                placement: FieldPlacement::OffChainCommitmentSource,
                required_for: vec![DataOperation::Ingest, DataOperation::PublishCommitment],
            },
            FieldRule {
                field_id: "market_code".into(),
                classification: DataClassification::Internal,
                semantic_category: SemanticCategory::Operational,
                placement: FieldPlacement::OffChainOnly,
                required_for: vec![],
            },
        ],
        onchain_commitments: vec![OnChainCommitmentRule {
            artifact_rule_id: "position-record-v1".into(),
            construction_id: SALTED_RECORD_COMMITMENT_CONSTRUCTION_ID.into(),
            domain: "bank-a-position-record-v1".into(),
            hidden_source_fields: vec!["account_id".into(), "balance".into()],
        }],
    }
}

fn schema() -> DatasetSchema {
    DatasetSchema {
        schema: DATASET_SCHEMA_SCHEMA.into(),
        schema_id: "positions-v1".into(),
        version: 1,
        fields: vec![
            DatasetFieldSchema {
                field_id: "account_id".into(),
                required: true,
                value: DatasetValueSchema::String {
                    min_bytes: 1,
                    max_bytes: 64,
                },
            },
            DatasetFieldSchema {
                field_id: "balance".into(),
                required: true,
                value: DatasetValueSchema::Integer {
                    minimum: 0,
                    maximum: 1_000_000,
                },
            },
            DatasetFieldSchema {
                field_id: "market_code".into(),
                required: false,
                value: DatasetValueSchema::String {
                    min_bytes: 1,
                    max_bytes: 16,
                },
            },
        ],
    }
}

fn ingestion_context() -> JsonIngestionContext {
    JsonIngestionContext {
        now_unix_seconds: 500,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "positions".into(),
        dataset_schema_id: "positions-v1".into(),
        purpose_id: "reconciliation".into(),
        processing_region: "br-sao-paulo-1".into(),
        storage_region: "br-sao-paulo-1".into(),
        jurisdictions: vec!["BR".into()],
        workload_id: "worker-1".into(),
        key_domain: "tenant-a-key".into(),
    }
}

fn publish_context(fields: Vec<&str>) -> DecisionContext {
    DecisionContext {
        now_unix_seconds: 500,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "positions".into(),
        dataset_schema_id: "positions-v1".into(),
        purpose_id: "reconciliation".into(),
        operation: DataOperation::PublishCommitment,
        processing_region: "br-sao-paulo-1".into(),
        storage_region: "br-sao-paulo-1".into(),
        jurisdictions: vec!["BR".into()],
        workload_id: "worker-1".into(),
        key_domain: "tenant-a-key".into(),
        recipient_id: None,
        observed_field_ids: fields.into_iter().map(String::from).collect(),
    }
}

fn authorize_record(policy: &GovernancePolicy, record: &[u8]) -> AuthorizedJsonIngestion {
    let schema = schema();
    let schema_bytes = canonical_dataset_schema_bytes(&schema).unwrap();
    let schema_digest = dataset_schema_sha256(&schema).unwrap();
    authorize_json_ingestion(
        policy,
        &ingestion_context(),
        &schema_bytes,
        &schema_digest,
        record,
    )
    .unwrap()
}

fn nonce(seed: u8) -> [u8; 32] {
    std::array::from_fn(|index| seed.wrapping_add(index as u8))
}

#[test]
fn authorized_opening_verifies_offline_and_enters_existing_publication_gate() {
    let policy = policy();
    let ingestion = authorize_record(
        &policy,
        br#"{"account_id":"opaque-7","balance":42,"market_code":"b3"}"#,
    );
    let publication =
        authorize_governance_gate(&policy, &publish_context(vec!["account_id", "balance"]))
            .unwrap();
    let nonce = nonce(7);
    let request = SaltedRecordCommitmentRequest {
        artifact_rule_id: "position-record-v1",
        external_nonce: &nonce,
    };
    let commitment = commit_authorized_json_record(&ingestion, &publication, request).unwrap();
    verify_authorized_json_record_commitment(&ingestion, &publication, request, &commitment)
        .unwrap();

    let envelope =
        authorize_onchain_commitment(&publication, &commitment.as_onchain_input()).unwrap();
    let serialized =
        String::from_utf8(onchain_commitment_envelope_bytes(&envelope).unwrap()).unwrap();
    for protected in [
        "opaque-7",
        "tenant-a",
        "positions-v1",
        "account_id",
        "balance",
        &hex::encode(nonce),
    ] {
        assert!(!serialized.contains(protected));
    }
}

#[test]
fn nonce_is_external_bounded_and_changes_the_commitment() {
    let policy = policy();
    let ingestion = authorize_record(&policy, br#"{"account_id":"a","balance":1}"#);
    let publication =
        authorize_governance_gate(&policy, &publish_context(vec!["account_id", "balance"]))
            .unwrap();
    let first_nonce = nonce(1);
    let second_nonce = nonce(2);
    let commit = |external_nonce| {
        commit_authorized_json_record(
            &ingestion,
            &publication,
            SaltedRecordCommitmentRequest {
                artifact_rule_id: "position-record-v1",
                external_nonce,
            },
        )
    };
    assert_ne!(
        commit(&first_nonce).unwrap().commitment(),
        commit(&second_nonce).unwrap().commitment()
    );
    assert!(matches!(
        commit(&[1; MIN_EXTERNAL_NONCE_BYTES - 1]),
        Err(OfflineCommitmentError::NonceLength { .. })
    ));
    assert!(matches!(
        commit(&[1; MAX_EXTERNAL_NONCE_BYTES + 1]),
        Err(OfflineCommitmentError::NonceLength { .. })
    ));
    assert_eq!(
        commit(&[0; MIN_EXTERNAL_NONCE_BYTES]),
        Err(OfflineCommitmentError::DegenerateNonce)
    );
    assert_eq!(
        commit(&[9; MIN_EXTERNAL_NONCE_BYTES]),
        Err(OfflineCommitmentError::DegenerateNonce)
    );
}

#[test]
fn record_nonce_policy_and_domain_are_bound() {
    let policy = policy();
    let first = authorize_record(&policy, br#"{"account_id":"a","balance":1}"#);
    let changed = authorize_record(&policy, br#"{"account_id":"a","balance":2}"#);
    let publication =
        authorize_governance_gate(&policy, &publish_context(vec!["account_id", "balance"]))
            .unwrap();
    let first_nonce = nonce(3);
    let other_nonce = nonce(4);
    let request = SaltedRecordCommitmentRequest {
        artifact_rule_id: "position-record-v1",
        external_nonce: &first_nonce,
    };
    let commitment = commit_authorized_json_record(&first, &publication, request).unwrap();
    assert_eq!(
        verify_authorized_json_record_commitment(&changed, &publication, request, &commitment),
        Err(OfflineCommitmentError::CommitmentMismatch)
    );
    assert_eq!(
        verify_authorized_json_record_commitment(
            &first,
            &publication,
            SaltedRecordCommitmentRequest {
                artifact_rule_id: "position-record-v1",
                external_nonce: &other_nonce,
            },
            &commitment,
        ),
        Err(OfflineCommitmentError::CommitmentMismatch)
    );

    let mut revised_policy = policy.clone();
    revised_policy.version = 2;
    let revised_publication = authorize_governance_gate(
        &revised_policy,
        &publish_context(vec!["account_id", "balance"]),
    )
    .unwrap();
    assert_eq!(
        commit_authorized_json_record(&first, &revised_publication, request),
        Err(OfflineCommitmentError::Authorization("policySha256"))
    );

    let mut other_domain_policy = policy;
    other_domain_policy.onchain_commitments[0].domain = "bank-a-position-record-v2".into();
    let other_ingestion =
        authorize_record(&other_domain_policy, br#"{"account_id":"a","balance":1}"#);
    let other_publication = authorize_governance_gate(
        &other_domain_policy,
        &publish_context(vec!["account_id", "balance"]),
    )
    .unwrap();
    assert_ne!(
        commitment.commitment(),
        commit_authorized_json_record(&other_ingestion, &other_publication, request)
            .unwrap()
            .commitment()
    );
}

#[test]
fn only_exact_hidden_source_inventory_is_committed() {
    let policy = policy();
    let first = authorize_record(
        &policy,
        br#"{"account_id":"a","balance":1,"market_code":"b3"}"#,
    );
    let second = authorize_record(
        &policy,
        br#"{"account_id":"a","balance":1,"market_code":"a5x"}"#,
    );
    let publication =
        authorize_governance_gate(&policy, &publish_context(vec!["account_id", "balance"]))
            .unwrap();
    let nonce = nonce(5);
    let request = SaltedRecordCommitmentRequest {
        artifact_rule_id: "position-record-v1",
        external_nonce: &nonce,
    };
    assert_eq!(
        commit_authorized_json_record(&first, &publication, request)
            .unwrap()
            .commitment(),
        commit_authorized_json_record(&second, &publication, request)
            .unwrap()
            .commitment()
    );

    let excessive_publication = authorize_governance_gate(
        &policy,
        &publish_context(vec!["account_id", "balance", "market_code"]),
    )
    .unwrap();
    assert_eq!(
        commit_authorized_json_record(&first, &excessive_publication, request),
        Err(OfflineCommitmentError::Authorization("hiddenSourceFields"))
    );
}

#[test]
fn wrong_operation_rule_or_construction_fails_closed() {
    let policy = policy();
    let ingestion = authorize_record(&policy, br#"{"account_id":"a","balance":1}"#);
    let request_nonce = nonce(6);
    let request = SaltedRecordCommitmentRequest {
        artifact_rule_id: "position-record-v1",
        external_nonce: &request_nonce,
    };
    assert_eq!(
        commit_authorized_json_record(&ingestion, ingestion.authorization(), request),
        Err(OfflineCommitmentError::Authorization("operation"))
    );
    let publication =
        authorize_governance_gate(&policy, &publish_context(vec!["account_id", "balance"]))
            .unwrap();
    assert_eq!(
        commit_authorized_json_record(
            &ingestion,
            &publication,
            SaltedRecordCommitmentRequest {
                artifact_rule_id: "unknown",
                external_nonce: &request_nonce,
            },
        ),
        Err(OfflineCommitmentError::Rule("artifactRuleId"))
    );

    let mut wrong_construction = policy;
    wrong_construction.onchain_commitments[0].construction_id = "pedersen-v1".into();
    let wrong_ingestion =
        authorize_record(&wrong_construction, br#"{"account_id":"a","balance":1}"#);
    let wrong_publication = authorize_governance_gate(
        &wrong_construction,
        &publish_context(vec!["account_id", "balance"]),
    )
    .unwrap();
    assert_eq!(
        commit_authorized_json_record(&wrong_ingestion, &wrong_publication, request),
        Err(OfflineCommitmentError::Rule("constructionId"))
    );
}
