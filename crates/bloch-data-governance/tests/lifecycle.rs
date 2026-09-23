use bloch_data_governance::*;
use ed25519_dalek::{Signer, SigningKey};

fn fixed_hash(byte: char) -> String {
    format!("0x{}", byte.to_string().repeat(64))
}
fn keys() -> [SigningKey; 3] {
    [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ]
}
fn governance() -> GovernancePolicy {
    GovernancePolicy {
        schema: GOVERNANCE_POLICY_SCHEMA.into(),
        policy_id: "record-v1".into(),
        version: 1,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "records".into(),
        dataset_schema_id: "records-v1".into(),
        purpose_id: "reconciliation".into(),
        effective_at_unix_seconds: 100,
        approval_expires_at_unix_seconds: 1_000,
        allowed_operations: vec![DataOperation::Ingest],
        applicable_jurisdictions: vec!["BR".into()],
        processing_regions: vec!["br-1".into()],
        storage_regions: vec!["br-1".into()],
        controller_id: "bank-a".into(),
        operator_id: "bloch-data".into(),
        privacy_contact_id: "privacy".into(),
        authorization_evidence_sha256: fixed_hash('a'),
        key_domain: "tenant-key".into(),
        allowed_workload_ids: vec!["worker-1".into()],
        permitted_recipient_ids: vec![],
        forbidden_field_ids: vec![],
        retention: RetentionRule {
            dispose_after_unix_seconds: 2_000,
            legal_hold_id: None,
            disposition: RetentionDisposition::Delete,
        },
        fields: vec![FieldRule {
            field_id: "account".into(),
            classification: DataClassification::Personal,
            semantic_category: SemanticCategory::AccountIdentifier,
            placement: FieldPlacement::OffChainOnly,
            required_for: vec![DataOperation::Ingest],
        }],
        onchain_commitments: vec![],
    }
}
fn admitted() -> (GovernancePolicy, AuthorizedJsonIngestion, String) {
    let governance = governance();
    let schema = DatasetSchema {
        schema: DATASET_SCHEMA_SCHEMA.into(),
        schema_id: "records-v1".into(),
        version: 1,
        fields: vec![DatasetFieldSchema {
            field_id: "account".into(),
            required: true,
            value: DatasetValueSchema::String {
                min_bytes: 1,
                max_bytes: 32,
            },
        }],
    };
    let schema_bytes = canonical_dataset_schema_bytes(&schema).unwrap();
    let schema_sha = dataset_schema_sha256(&schema).unwrap();
    let context = JsonIngestionContext {
        now_unix_seconds: 500,
        institution_id: "bank-a".into(),
        tenant_id: "tenant-a".into(),
        dataset_id: "records".into(),
        dataset_schema_id: "records-v1".into(),
        purpose_id: "reconciliation".into(),
        processing_region: "br-1".into(),
        storage_region: "br-1".into(),
        jurisdictions: vec!["BR".into()],
        workload_id: "worker-1".into(),
        key_domain: "tenant-key".into(),
    };
    let ingestion = authorize_json_ingestion(
        &governance,
        &context,
        &schema_bytes,
        &schema_sha,
        br#"{"account":"opaque"}"#,
    )
    .unwrap();
    (governance, ingestion, schema_sha)
}
fn policy(governance: &GovernancePolicy, schema_sha: &str) -> LifecyclePolicy {
    let keys = keys();
    LifecyclePolicy {
        schema: LIFECYCLE_POLICY_SCHEMA.into(),
        policy_id: "lifecycle-v1".into(),
        signature_domain: "production-a".into(),
        governance_policy_sha256: governance_policy_sha256(governance).unwrap(),
        dataset_schema_sha256: schema_sha.into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 4_000,
        dispose_after_unix_seconds: 2_000,
        disposition: RetentionDisposition::Delete,
        initial_legal_hold_id: None,
        actors: vec![
            LifecycleActor {
                actor_id: "disposer".into(),
                role: LifecycleActorRole::DisposalAuthority,
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(keys[0].verifying_key().to_bytes())
                ),
            },
            LifecycleActor {
                actor_id: "evidence".into(),
                role: LifecycleActorRole::EvidenceRecorder,
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(keys[1].verifying_key().to_bytes())
                ),
            },
            LifecycleActor {
                actor_id: "hold".into(),
                role: LifecycleActorRole::LegalHoldAuthority,
                ed25519_public_key: format!(
                    "0x{}",
                    hex::encode(keys[2].verifying_key().to_bytes())
                ),
            },
        ],
    }
}
fn request(
    state: &LifecycleState,
    pin: &str,
    at: u64,
    actor: &str,
    action: LifecycleAction,
) -> LifecycleTransitionRequest {
    LifecycleTransitionRequest {
        schema: LIFECYCLE_TRANSITION_SCHEMA.into(),
        lifecycle_policy_sha256: pin.into(),
        record_sha256: state.record_sha256().into(),
        prior_state_sha256: state.state_sha256().unwrap(),
        sequence: state.sequence() + 1,
        occurred_at_unix_seconds: at,
        actor_id: actor.into(),
        action,
    }
}
fn authorize(
    state: &LifecycleState,
    policy: &LifecyclePolicy,
    pin: &str,
    request: &LifecycleTransitionRequest,
    key: &SigningKey,
    evaluated: u64,
) -> Result<AuthorizedLifecycleTransition, LifecycleError> {
    let signing = lifecycle_transition_signing_bytes(state, policy, pin, request, evaluated)?;
    let signature = key.sign(&signing).to_bytes();
    authorize_lifecycle_transition(
        state,
        policy,
        pin,
        &serde_json::to_vec(request).unwrap(),
        &signature,
        evaluated,
    )
}

#[test]
fn signed_hold_order_and_evidence_form_a_deterministic_audit_chain() {
    let (governance, ingestion, schema_sha) = admitted();
    let policy = policy(&governance, &schema_sha);
    let pin = lifecycle_policy_sha256(&policy).unwrap();
    let mut state =
        initialize_lifecycle_state(&ingestion, &governance, &policy, &pin, 500).unwrap();
    let keys = keys();

    let place = request(
        &state,
        &pin,
        600,
        "hold",
        LifecycleAction::PlaceLegalHold {
            hold_id: "case-7".into(),
        },
    );
    let transition = authorize(&state, &policy, &pin, &place, &keys[2], 600).unwrap();
    apply_authorized_lifecycle_transition(&mut state, transition).unwrap();
    let blocked = request(
        &state,
        &pin,
        2_100,
        "disposer",
        LifecycleAction::OrderDisposal {
            order_id: "order-1".into(),
            disposition: RetentionDisposition::Delete,
        },
    );
    let transition = authorize(&state, &policy, &pin, &blocked, &keys[0], 2_100).unwrap();
    assert_eq!(
        apply_authorized_lifecycle_transition(&mut state, transition),
        Err(LifecycleError::TransitionDenied)
    );

    let release = request(
        &state,
        &pin,
        2_101,
        "hold",
        LifecycleAction::ReleaseLegalHold {
            hold_id: "case-7".into(),
        },
    );
    let transition = authorize(&state, &policy, &pin, &release, &keys[2], 2_101).unwrap();
    apply_authorized_lifecycle_transition(&mut state, transition).unwrap();
    let order = request(
        &state,
        &pin,
        2_102,
        "disposer",
        LifecycleAction::OrderDisposal {
            order_id: "order-1".into(),
            disposition: RetentionDisposition::Delete,
        },
    );
    let transition = authorize(&state, &policy, &pin, &order, &keys[0], 2_102).unwrap();
    apply_authorized_lifecycle_transition(&mut state, transition).unwrap();
    let evidence = request(
        &state,
        &pin,
        2_103,
        "evidence",
        LifecycleAction::ConfirmDisposalEvidence {
            order_id: "order-1".into(),
            evidence_id: "receipt-1".into(),
            evidence_sha256: fixed_hash('e'),
        },
    );
    let transition = authorize(&state, &policy, &pin, &evidence, &keys[1], 2_103).unwrap();
    apply_authorized_lifecycle_transition(&mut state, transition).unwrap();

    assert_eq!(state.phase(), LifecyclePhase::EvidenceRecorded);
    assert_eq!(state.sequence(), 4);
    assert_eq!(state.evidence_id(), Some("receipt-1"));
    assert!(!state.physical_deletion_proven());
    assert!(!state.backup_purge_proven());
    assert!(!state.irreversible_anonymization_proven());
    assert!(!state.regulatory_compliance_proven());
    assert!(!state.external_execution_succeeded());
    assert_eq!(
        lifecycle_state_bytes(&state).unwrap(),
        lifecycle_state_bytes(&state).unwrap()
    );
}

#[test]
fn wrong_role_signature_future_replay_and_early_disposal_fail_closed() {
    let (governance, ingestion, schema_sha) = admitted();
    let policy = policy(&governance, &schema_sha);
    let pin = lifecycle_policy_sha256(&policy).unwrap();
    let keys = keys();
    let mut state =
        initialize_lifecycle_state(&ingestion, &governance, &policy, &pin, 500).unwrap();
    let early = request(
        &state,
        &pin,
        900,
        "disposer",
        LifecycleAction::OrderDisposal {
            order_id: "order-1".into(),
            disposition: RetentionDisposition::Delete,
        },
    );
    let transition = authorize(&state, &policy, &pin, &early, &keys[0], 900).unwrap();
    assert_eq!(
        apply_authorized_lifecycle_transition(&mut state, transition),
        Err(LifecycleError::TransitionDenied)
    );

    let wrong_role = request(
        &state,
        &pin,
        600,
        "disposer",
        LifecycleAction::PlaceLegalHold {
            hold_id: "case-1".into(),
        },
    );
    assert_eq!(
        lifecycle_transition_signing_bytes(&state, &policy, &pin, &wrong_role, 600),
        Err(LifecycleError::UnauthorizedActor)
    );
    let valid = request(
        &state,
        &pin,
        601,
        "hold",
        LifecycleAction::PlaceLegalHold {
            hold_id: "case-1".into(),
        },
    );
    let bytes = serde_json::to_vec(&valid).unwrap();
    assert!(matches!(
        authorize_lifecycle_transition(&state, &policy, &pin, &bytes, &[0; 64], 601),
        Err(LifecycleError::InvalidSignature)
    ));
    let transition = authorize(&state, &policy, &pin, &valid, &keys[2], 601).unwrap();
    let replay = transition.clone();
    apply_authorized_lifecycle_transition(&mut state, transition).unwrap();
    assert_eq!(
        apply_authorized_lifecycle_transition(&mut state, replay),
        Err(LifecycleError::StateMismatch)
    );

    let future = request(
        &state,
        &pin,
        800,
        "hold",
        LifecycleAction::ReleaseLegalHold {
            hold_id: "case-1".into(),
        },
    );
    assert_eq!(
        lifecycle_transition_signing_bytes(&state, &policy, &pin, &future, 700),
        Err(LifecycleError::OutsideValidityWindow)
    );
}

#[test]
fn pin_and_admission_substitution_are_rejected() {
    let (governance, ingestion, schema_sha) = admitted();
    let mut policy = policy(&governance, &schema_sha);
    let pin = lifecycle_policy_sha256(&policy).unwrap();
    assert_eq!(
        parse_lifecycle_policy(
            &canonical_lifecycle_policy_bytes(&policy).unwrap(),
            &fixed_hash('f')
        ),
        Err(LifecycleError::PolicyDigestMismatch)
    );
    policy.dataset_schema_sha256 = fixed_hash('d');
    let substituted_pin = lifecycle_policy_sha256(&policy).unwrap();
    assert_eq!(
        initialize_lifecycle_state(&ingestion, &governance, &policy, &substituted_pin, 500),
        Err(LifecycleError::AdmissionMismatch)
    );
    assert_eq!(
        initialize_lifecycle_state(&ingestion, &governance, &policy, &pin, 500),
        Err(LifecycleError::PolicyDigestMismatch)
    );
}

#[test]
fn impossible_timeline_expired_evaluation_and_reused_keys_are_rejected() {
    let (governance, ingestion, schema_sha) = admitted();
    let mut invalid = policy(&governance, &schema_sha);
    invalid.dispose_after_unix_seconds = invalid.expires_at_unix_seconds;
    assert_eq!(
        canonical_lifecycle_policy_bytes(&invalid),
        Err(LifecycleError::InvalidField("policy"))
    );

    let mut reused = policy(&governance, &schema_sha);
    reused.actors[1].ed25519_public_key = reused.actors[0].ed25519_public_key.clone();
    assert_eq!(
        canonical_lifecycle_policy_bytes(&reused),
        Err(LifecycleError::InvalidField("ed25519PublicKeyReuse"))
    );

    let policy = policy(&governance, &schema_sha);
    let pin = lifecycle_policy_sha256(&policy).unwrap();
    let state = initialize_lifecycle_state(&ingestion, &governance, &policy, &pin, 500).unwrap();
    let request = request(
        &state,
        &pin,
        3_999,
        "hold",
        LifecycleAction::PlaceLegalHold {
            hold_id: "case-1".into(),
        },
    );
    assert_eq!(
        lifecycle_transition_signing_bytes(&state, &policy, &pin, &request, 4_000),
        Err(LifecycleError::OutsideValidityWindow)
    );
}
