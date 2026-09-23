use bloch_data_governance::*;

fn hash(byte: char) -> String {
    format!("0x{}", byte.to_string().repeat(64))
}

fn policy() -> GovernancePolicy {
    GovernancePolicy {
        schema: GOVERNANCE_POLICY_SCHEMA.into(),
        policy_id: "institution-record-v1".into(),
        version: 1,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "positions".into(),
        dataset_schema_id: "positions-v1".into(),
        purpose_id: "reconciliation".into(),
        effective_at_unix_seconds: 100,
        approval_expires_at_unix_seconds: 1_000,
        allowed_operations: vec![DataOperation::Ingest],
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
        forbidden_field_ids: vec!["credential".into()],
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
                placement: FieldPlacement::OffChainOnly,
                required_for: vec![DataOperation::Ingest],
            },
            FieldRule {
                field_id: "balance".into(),
                classification: DataClassification::FinancialConfidential,
                semantic_category: SemanticCategory::Balance,
                placement: FieldPlacement::OffChainOnly,
                required_for: vec![DataOperation::Ingest],
            },
        ],
        onchain_commitments: vec![],
    }
}

fn context() -> JsonIngestionContext {
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

#[test]
fn derives_fields_from_exact_payload_and_binds_digest() {
    let bytes = br#"{"account_id":"opaque-1","balance":42}"#;
    let authorization = authorize_json_ingestion(&policy(), &context(), bytes).unwrap();
    assert_eq!(
        authorization.authorization().operation(),
        DataOperation::Ingest
    );
    assert_eq!(
        authorization.observed_field_ids(),
        &["account_id".to_string(), "balance".to_string()]
    );
    assert_eq!(authorization.record_sha256().len(), 66);

    let reordered = br#"{"balance":42,"account_id":"opaque-1"}"#;
    let second = authorize_json_ingestion(&policy(), &context(), reordered).unwrap();
    assert_eq!(
        second.observed_field_ids(),
        authorization.observed_field_ids()
    );
    assert_eq!(second.record_sha256(), authorization.record_sha256());
    assert_eq!(
        second.canonical_record_bytes(),
        authorization.canonical_record_bytes()
    );
    assert_eq!(
        authorization.canonical_record_bytes(),
        br#"{"account_id":"opaque-1","balance":42}"#
    );
}

#[test]
fn unknown_missing_forbidden_and_invalid_fields_fail_closed() {
    for bytes in [
        br#"{"account_id":"x"}"#.as_slice(),
        br#"{"account_id":"x","balance":1,"unknown":true}"#.as_slice(),
        br#"{"account_id":"x","balance":1,"credential":"secret"}"#.as_slice(),
        br#"{"account_id":"x","balance":1,"Bad Field":true}"#.as_slice(),
    ] {
        assert!(authorize_json_ingestion(&policy(), &context(), bytes).is_err());
    }
}

#[test]
fn duplicate_nested_keys_trailing_values_arrays_and_oversize_fail_closed() {
    let duplicate = br#"{"account_id":"x","balance":1,"nested":{"x":1,"x":2}}"#;
    assert!(authorize_json_ingestion(&policy(), &context(), duplicate).is_err());
    let trailing = br#"{"account_id":"x","balance":1}{}"#;
    assert!(authorize_json_ingestion(&policy(), &context(), trailing).is_err());
    assert!(matches!(
        authorize_json_ingestion(&policy(), &context(), br#"[1,2]"#),
        Err(JsonIngestionError::NotObject)
    ));
    let oversized = vec![b' '; MAX_JSON_RECORD_BYTES + 1];
    assert!(matches!(
        authorize_json_ingestion(&policy(), &context(), &oversized),
        Err(JsonIngestionError::TooLarge { .. })
    ));
}

#[test]
fn runtime_context_cannot_cross_tenant_or_key_domain() {
    let bytes = br#"{"account_id":"x","balance":1}"#;
    let mut wrong_tenant = context();
    wrong_tenant.tenant_id = "tenant-b".into();
    assert!(authorize_json_ingestion(&policy(), &wrong_tenant, bytes).is_err());
    let mut wrong_key = context();
    wrong_key.key_domain = "tenant-b-key".into();
    assert!(authorize_json_ingestion(&policy(), &wrong_key, bytes).is_err());
}
