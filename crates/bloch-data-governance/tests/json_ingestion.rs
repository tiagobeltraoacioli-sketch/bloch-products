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
            FieldRule {
                field_id: "flags".into(),
                classification: DataClassification::Internal,
                semantic_category: SemanticCategory::Operational,
                placement: FieldPlacement::OffChainOnly,
                required_for: vec![],
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
                field_id: "flags".into(),
                required: false,
                value: DatasetValueSchema::Array {
                    items: ScalarType::String,
                    min_items: 1,
                    max_items: 2,
                },
            },
        ],
    }
}

fn authorize(bytes: &[u8]) -> Result<AuthorizedJsonIngestion, JsonIngestionError> {
    let schema = schema();
    let schema_bytes = canonical_dataset_schema_bytes(&schema).unwrap();
    let digest = dataset_schema_sha256(&schema).unwrap();
    authorize_json_ingestion(&policy(), &context(), &schema_bytes, &digest, bytes)
}

#[test]
fn derives_fields_from_exact_payload_and_binds_digest() {
    let bytes = br#"{"account_id":"opaque-1","balance":42}"#;
    let authorization = authorize(bytes).unwrap();
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
    let second = authorize(reordered).unwrap();
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
        assert!(authorize(bytes).is_err());
    }
}

#[test]
fn duplicate_nested_keys_trailing_values_arrays_and_oversize_fail_closed() {
    let duplicate = br#"{"account_id":"x","balance":1,"nested":{"x":1,"x":2}}"#;
    assert!(authorize(duplicate).is_err());
    let trailing = br#"{"account_id":"x","balance":1}{}"#;
    assert!(authorize(trailing).is_err());
    assert!(matches!(
        authorize(br#"[1,2]"#),
        Err(JsonIngestionError::NotObject)
    ));
    let oversized = vec![b' '; MAX_JSON_RECORD_BYTES + 1];
    assert!(matches!(
        authorize(&oversized),
        Err(JsonIngestionError::TooLarge { .. })
    ));
}

#[test]
fn runtime_context_cannot_cross_tenant_or_key_domain() {
    let bytes = br#"{"account_id":"x","balance":1}"#;
    let mut wrong_tenant = context();
    wrong_tenant.tenant_id = "tenant-b".into();
    let schema = schema();
    let schema_bytes = canonical_dataset_schema_bytes(&schema).unwrap();
    let digest = dataset_schema_sha256(&schema).unwrap();
    assert!(
        authorize_json_ingestion(&policy(), &wrong_tenant, &schema_bytes, &digest, bytes).is_err()
    );
    let mut wrong_key = context();
    wrong_key.key_domain = "tenant-b-key".into();
    assert!(
        authorize_json_ingestion(&policy(), &wrong_key, &schema_bytes, &digest, bytes).is_err()
    );
}

#[test]
fn independently_pinned_schema_enforces_types_bounds_and_canonical_output() {
    let schema = schema();
    let schema_bytes = canonical_dataset_schema_bytes(&schema).unwrap();
    let digest = dataset_schema_sha256(&schema).unwrap();
    let authorized = authorize_json_ingestion(
        &policy(),
        &context(),
        &schema_bytes,
        &digest,
        br#"{"balance":7,"account_id":"conta"}"#,
    )
    .unwrap();
    assert_eq!(authorized.dataset_schema_sha256(), digest);
    assert_eq!(
        authorized.canonical_record_bytes(),
        br#"{"account_id":"conta","balance":7}"#
    );

    for record in [
        br#"{"account_id":1,"balance":7}"#.as_slice(),
        br#"{"account_id":"","balance":7}"#.as_slice(),
        br#"{"account_id":"conta","balance":-1}"#.as_slice(),
        br#"{"account_id":"conta","balance":7.0}"#.as_slice(),
        br#"{"account_id":"conta","balance":7,"nested":{}}"#.as_slice(),
        br#"{"account_id":null,"balance":7}"#.as_slice(),
        br#"{"account_id":"conta","balance":7,"flags":[]}"#.as_slice(),
        br#"{"account_id":"conta","balance":7,"flags":["a",1]}"#.as_slice(),
        br#"{"account_id":"conta","balance":7,"flags":["a","b","c"]}"#.as_slice(),
    ] {
        assert!(
            authorize_json_ingestion(&policy(), &context(), &schema_bytes, &digest, record)
                .is_err()
        );
    }
    assert!(
        authorize_json_ingestion(
            &policy(),
            &context(),
            &schema_bytes,
            &digest,
            br#"{"account_id":"conta","balance":7,"flags":["audited"]}"#,
        )
        .is_ok()
    );
}

#[test]
fn schema_parser_rejects_wrong_pin_noncanonical_duplicate_unknown_and_invalid_bounds() {
    let valid_schema = schema();
    let bytes = canonical_dataset_schema_bytes(&valid_schema).unwrap();
    let digest = dataset_schema_sha256(&valid_schema).unwrap();
    assert_eq!(parse_dataset_schema(&bytes, &digest).unwrap(), valid_schema);
    assert_eq!(
        parse_dataset_schema(&bytes, &hash('b')),
        Err(DatasetSchemaError::SchemaDigestMismatch)
    );
    let mut noncanonical = bytes.clone();
    noncanonical.push(b'\n');
    assert_eq!(
        parse_dataset_schema(&noncanonical, &digest),
        Err(DatasetSchemaError::NonCanonicalSchema)
    );
    let text = String::from_utf8(bytes).unwrap();
    for malformed in [
        text.replacen("\"schemaId\":", "\"schemaId\":\"evil\",\"schemaId\":", 1),
        text.replacen("{", "{\"unknown\":true,", 1),
    ] {
        assert!(matches!(
            parse_dataset_schema(malformed.as_bytes(), &digest),
            Err(DatasetSchemaError::InvalidJson(_))
        ));
    }

    let mut invalid = schema();
    invalid.fields[1].value = DatasetValueSchema::Integer {
        minimum: 10,
        maximum: 9,
    };
    assert_eq!(
        canonical_dataset_schema_bytes(&invalid),
        Err(DatasetSchemaError::InvalidSchema("integerBounds"))
    );

    let oversized = vec![b' '; MAX_DATASET_SCHEMA_BYTES + 1];
    assert!(matches!(
        parse_dataset_schema(&oversized, &digest),
        Err(DatasetSchemaError::TooLarge { .. })
    ));

    let mut wrong_identity = schema();
    wrong_identity.schema_id = "positions-v2".into();
    let wrong_bytes = canonical_dataset_schema_bytes(&wrong_identity).unwrap();
    let wrong_digest = dataset_schema_sha256(&wrong_identity).unwrap();
    assert!(
        authorize_json_ingestion(
            &policy(),
            &context(),
            &wrong_bytes,
            &wrong_digest,
            br#"{"account_id":"conta","balance":7}"#,
        )
        .is_err()
    );
}
