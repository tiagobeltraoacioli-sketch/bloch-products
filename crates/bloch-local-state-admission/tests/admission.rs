#![cfg(unix)]

use bloch_data_governance::{
    LIFECYCLE_POLICY_SCHEMA, LIFECYCLE_STATE_SCHEMA, LifecycleActor, LifecycleActorRole,
    LifecyclePhase, LifecyclePolicy, RetentionDisposition, canonical_lifecycle_policy_bytes,
    lifecycle_policy_sha256,
};
use bloch_local_state_admission::*;
use bloch_local_state_checkpoint::{
    CheckpointAuthority, CheckpointPolicy, DetachedCheckpointSignature, POLICY_SCHEMA,
    authenticate_root_checkpoint, checkpoint_policy_bytes, checkpoint_policy_sha256,
    checkpoint_signature_message, create_root_checkpoint,
};
use bloch_local_state_coordination::{
    CoordinatedError, CoordinationError, provision_local_state_coordination_directory,
    with_coordinated_state_transition,
};
use bloch_local_state_cursor::admit_checkpoint;
use bloch_local_state_remote_cursor::{
    REMOTE_CURSOR_POLICY_SCHEMA, RemoteCursorAuthority, RemoteCursorPolicy, RemoteCursorSignature,
    VerifiedRemoteCursor, create_remote_cursor_observation, remote_cursor_policy_sha256,
    remote_cursor_signature_message, verify_remote_cursor_observation,
};
use bloch_local_state_store::{StateRoot, write_state};
use bloch_pay_adjustments::{ADJUSTMENT_STATE_SCHEMA, AdjustmentStatus};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "bloch-admission-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    state_store: Temp,
    cursor_store: Temp,
    artifact: Vec<u8>,
    checkpoint_policy: Vec<u8>,
    semantic: Vec<u8>,
    semantic_pin: String,
    remote_cursor: VerifiedRemoteCursor,
    root: StateRoot,
}

impl Fixture {
    fn new(identity: &str, state: &[u8], semantic: Vec<u8>, semantic_pin: String) -> Self {
        let state_store = Temp::new("state");
        let cursor_store = Temp::new("cursor");
        let root = write_state(&state_store.0, identity, 0, state, None).unwrap();
        let keys = [
            SigningKey::from_bytes(&[31; 32]),
            SigningKey::from_bytes(&[32; 32]),
        ];
        let policy = CheckpointPolicy {
            schema: POLICY_SCHEMA.into(),
            policy_id: "startup-admission-policy".into(),
            checkpoint_domain: "bloch-products-test".into(),
            state_identity: identity.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_checkpoint_age_seconds: 200,
            authorities: keys
                .iter()
                .enumerate()
                .map(|(index, key)| CheckpointAuthority {
                    authority_id: format!("authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let checkpoint_pin = checkpoint_policy_sha256(&policy).unwrap();
        let message =
            checkpoint_signature_message(&root, &policy, &checkpoint_pin, &semantic_pin, 200)
                .unwrap();
        let signatures = keys
            .iter()
            .enumerate()
            .map(|(index, key)| DetachedCheckpointSignature {
                authority_id: format!("authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let artifact = create_root_checkpoint(
            &root,
            &policy,
            &checkpoint_pin,
            &semantic_pin,
            200,
            &signatures,
        )
        .unwrap();
        let verified =
            authenticate_root_checkpoint(&artifact, &policy, &checkpoint_pin, 250).unwrap();
        let cursor = admit_checkpoint(&cursor_store.0, &verified, None).unwrap();
        let remote_keys = [
            SigningKey::from_bytes(&[33; 32]),
            SigningKey::from_bytes(&[34; 32]),
        ];
        let remote_policy = RemoteCursorPolicy {
            schema: REMOTE_CURSOR_POLICY_SCHEMA.into(),
            policy_id: "remote-startup-policy".into(),
            signature_domain: "bloch-products-remote-test".into(),
            state_identity: identity.into(),
            threshold: 2,
            effective_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            max_observation_age_seconds: 100,
            authorities: remote_keys
                .iter()
                .enumerate()
                .map(|(index, key)| RemoteCursorAuthority {
                    authority_id: format!("remote-authority-{}", index + 1),
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                })
                .collect(),
        };
        let remote_pin = remote_cursor_policy_sha256(&remote_policy).unwrap();
        let nonce = "fixture-nonce-0123456789abcdef0123456789abcdef";
        let remote_message =
            remote_cursor_signature_message(&cursor, &remote_policy, &remote_pin, nonce, 240)
                .unwrap();
        let remote_signatures = remote_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RemoteCursorSignature {
                authority_id: format!("remote-authority-{}", index + 1),
                signature: format!("0x{}", hex::encode(key.sign(&remote_message).to_bytes())),
            })
            .collect::<Vec<_>>();
        let remote_observation = create_remote_cursor_observation(
            &cursor,
            &remote_policy,
            &remote_pin,
            nonce,
            240,
            &remote_signatures,
        )
        .unwrap();
        let remote_cursor = verify_remote_cursor_observation(
            &remote_observation,
            &remote_policy,
            &remote_pin,
            nonce,
            250,
        )
        .unwrap();
        Self {
            state_store,
            cursor_store,
            artifact,
            checkpoint_policy: checkpoint_policy_bytes(&policy).unwrap(),
            semantic,
            semantic_pin,
            remote_cursor,
            root,
        }
    }

    fn startup(&self) -> StartupAdmission<'_> {
        StartupAdmission {
            artifact_bytes: &self.artifact,
            checkpoint_policy_bytes: &self.checkpoint_policy,
            semantic_manifest_bytes: &self.semantic,
            verified_remote_cursor: &self.remote_cursor,
            cursor_store: &self.cursor_store.0,
            state_store: &self.state_store.0,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitialLifecycleState<'a> {
    schema: &'static str,
    lifecycle_policy_sha256: &'a str,
    governance_policy_sha256: &'a str,
    dataset_schema_sha256: &'a str,
    record_sha256: &'a str,
    dispose_after_unix_seconds: u64,
    disposition: RetentionDisposition,
    sequence: u64,
    phase: LifecyclePhase,
    active_legal_hold_id: Option<&'a str>,
    disposal_order_id: Option<&'a str>,
    evidence_id: Option<&'a str>,
    evidence_sha256: Option<&'a str>,
    events: Vec<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitialAdjustmentState<'a> {
    schema: &'static str,
    adjustment_policy_sha256: &'a str,
    reconciliation_policy_sha256: &'a str,
    adjustment_id: &'a str,
    payment_observation_id: &'a str,
    payment_observation_sha256: &'a str,
    payment_amount_minor: u64,
    generation: u64,
    status: AdjustmentStatus,
    applied_events: Vec<serde_json::Value>,
    settlement_qualified: bool,
    credit_authorized: bool,
    funds_moved: bool,
}

#[test]
fn admits_data_only_after_checkpoint_cursor_store_and_semantic_restore() {
    let governance = digest(b"governance");
    let dataset = digest(b"dataset");
    let record = digest(b"record");
    let lifecycle_policy = lifecycle_policy(&governance, &dataset);
    let lifecycle_pin = lifecycle_policy_sha256(&lifecycle_policy).unwrap();
    let state = serde_json::to_vec(&InitialLifecycleState {
        schema: LIFECYCLE_STATE_SCHEMA,
        lifecycle_policy_sha256: &lifecycle_pin,
        governance_policy_sha256: &governance,
        dataset_schema_sha256: &dataset,
        record_sha256: &record,
        dispose_after_unix_seconds: 800,
        disposition: RetentionDisposition::Delete,
        sequence: 0,
        phase: LifecyclePhase::Retained,
        active_legal_hold_id: None,
        disposal_order_id: None,
        evidence_id: None,
        evidence_sha256: None,
        events: vec![],
    })
    .unwrap();
    let manifest = DataLifecycleSemanticManifest {
        schema: DATA_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: "data:tenant-a:lifecycle".into(),
        lifecycle_policy_sha256: lifecycle_pin,
        governance_policy_sha256: governance,
        dataset_schema_sha256: dataset,
        record_sha256: record,
        sequence: 0,
    };
    let semantic = data_semantic_manifest_bytes(&manifest).unwrap();
    let semantic_pin = data_semantic_manifest_sha256(&manifest).unwrap();
    let fixture = Fixture::new(&manifest.state_identity, &state, semantic, semantic_pin);
    let admitted = admit_data_lifecycle(DataLifecycleAdmission {
        startup: fixture.startup(),
        lifecycle_policy_bytes: &canonical_lifecycle_policy_bytes(&lifecycle_policy).unwrap(),
    })
    .unwrap();
    assert_eq!(admitted.state().sequence(), 0);
    assert_eq!(admitted.evidence().generation(), 0);
    assert_eq!(
        admitted.evidence().semantic_manifest_sha256(),
        fixture.semantic_pin
    );
    assert_eq!(
        admitted.evidence().remote_cursor_observation_sha256(),
        fixture.remote_cursor.observation_sha256()
    );
    assert!(!admitted.evidence().concurrent_writer_excluded());
    assert!(!admitted.evidence().regulatory_compliance_proven());
}

#[test]
fn admits_pay_and_rejects_wrong_semantic_pin_or_changed_store() {
    let adjustment_policy = digest(b"adjustment-policy");
    let reconciliation_policy = digest(b"reconciliation-policy");
    let observation = digest(b"payment-observation");
    let state = serde_json::to_vec(&InitialAdjustmentState {
        schema: ADJUSTMENT_STATE_SCHEMA,
        adjustment_policy_sha256: &adjustment_policy,
        reconciliation_policy_sha256: &reconciliation_policy,
        adjustment_id: "adjustment-1",
        payment_observation_id: "observation-1",
        payment_observation_sha256: &observation,
        payment_amount_minor: 125,
        generation: 0,
        status: AdjustmentStatus::Active,
        applied_events: vec![],
        settlement_qualified: false,
        credit_authorized: false,
        funds_moved: false,
    })
    .unwrap();
    let manifest = PayAdjustmentSemanticManifest {
        schema: PAY_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: "pay:merchant-a:adjustment-1".into(),
        adjustment_policy_sha256: adjustment_policy,
        reconciliation_policy_sha256: reconciliation_policy,
        adjustment_id: "adjustment-1".into(),
        payment_observation_id: "observation-1".into(),
        payment_observation_sha256: observation,
        payment_amount_minor: 125,
        generation: 0,
    };
    let semantic = pay_semantic_manifest_bytes(&manifest).unwrap();
    let semantic_pin = pay_semantic_manifest_sha256(&manifest).unwrap();
    let fixture = Fixture::new(&manifest.state_identity, &state, semantic, semantic_pin);
    let admitted = admit_pay_adjustment(PayAdjustmentAdmission {
        startup: fixture.startup(),
    })
    .unwrap();
    assert_eq!(admitted.state().adjustment_id(), "adjustment-1");
    assert!(!admitted.state().settlement_qualified());

    let wrong = b"{}";
    let mut startup = fixture.startup();
    startup.semantic_manifest_bytes = wrong;
    assert!(matches!(
        admit_pay_adjustment(PayAdjustmentAdmission { startup }),
        Err(AdmissionError::SemanticManifestPinMismatch)
    ));

    let other = Fixture::new(
        &manifest.state_identity,
        b"different-state",
        fixture.semantic.clone(),
        fixture.semantic_pin.clone(),
    );
    let mut startup = fixture.startup();
    startup.verified_remote_cursor = &other.remote_cursor;
    assert!(matches!(
        admit_pay_adjustment(PayAdjustmentAdmission { startup }),
        Err(AdmissionError::Cursor(_))
    ));

    write_state(
        &fixture.state_store.0,
        &manifest.state_identity,
        1,
        b"unauthorized-next-state",
        Some(&fixture.root),
    )
    .unwrap();
    assert!(matches!(
        admit_pay_adjustment(PayAdjustmentAdmission {
            startup: fixture.startup()
        }),
        Err(AdmissionError::Store(_))
    ));
}

#[test]
fn semantic_manifests_reject_noncanonical_cross_product_and_unknown_fields() {
    let manifest = PayAdjustmentSemanticManifest {
        schema: PAY_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: "pay:merchant-a:adjustment-1".into(),
        adjustment_policy_sha256: digest(b"adjustment"),
        reconciliation_policy_sha256: digest(b"reconciliation"),
        adjustment_id: "adjustment-1".into(),
        payment_observation_id: "observation-1".into(),
        payment_observation_sha256: digest(b"observation"),
        payment_amount_minor: 1,
        generation: 0,
    };
    let bytes = pay_semantic_manifest_bytes(&manifest).unwrap();
    let pin = pay_semantic_manifest_sha256(&manifest).unwrap();
    assert_eq!(parse_pay_semantic_manifest(&bytes, &pin).unwrap(), manifest);
    let mut trailing = bytes.clone();
    trailing.push(b'\n');
    assert!(matches!(
        parse_pay_semantic_manifest(&trailing, &digest(&trailing)),
        Err(AdmissionError::InvalidSemanticManifest)
    ));
    assert!(matches!(
        parse_data_semantic_manifest(&bytes, &pin),
        Err(AdmissionError::InvalidSemanticManifest)
    ));
    let unknown = String::from_utf8(bytes)
        .unwrap()
        .replacen('{', "{\"unknown\":true,", 1)
        .into_bytes();
    assert!(matches!(
        parse_pay_semantic_manifest(&unknown, &digest(&unknown)),
        Err(AdmissionError::InvalidSemanticManifest)
    ));
}

#[test]
fn coordinated_convenience_api_holds_shared_lock_and_fails_bounded() {
    let fixture = valid_pay_fixture();
    let coordination = Temp::new("coordination");
    provision_local_state_coordination_directory(&coordination.0).unwrap();
    let worker_path = coordination.0.clone();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        with_coordinated_state_transition(&worker_path, |_scope| {
            held_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            Ok::<_, std::io::Error>(())
        })
        .unwrap();
    });
    held_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let started = std::time::Instant::now();
    let result = admit_pay_adjustment_coordinated(
        &coordination.0,
        PayAdjustmentAdmission {
            startup: fixture.startup(),
        },
    );
    assert!(matches!(
        result,
        Err(CoordinatedError::Coordination(CoordinationError::Busy))
    ));
    assert!(started.elapsed() >= Duration::from_millis(400));
    assert!(started.elapsed() < Duration::from_secs(2));

    release_tx.send(()).unwrap();
    worker.join().unwrap();
    admit_pay_adjustment_coordinated(
        &coordination.0,
        PayAdjustmentAdmission {
            startup: fixture.startup(),
        },
    )
    .unwrap();
}

fn valid_pay_fixture() -> Fixture {
    let adjustment_policy = digest(b"adjustment-policy");
    let reconciliation_policy = digest(b"reconciliation-policy");
    let observation = digest(b"payment-observation");
    let state = serde_json::to_vec(&InitialAdjustmentState {
        schema: ADJUSTMENT_STATE_SCHEMA,
        adjustment_policy_sha256: &adjustment_policy,
        reconciliation_policy_sha256: &reconciliation_policy,
        adjustment_id: "adjustment-1",
        payment_observation_id: "observation-1",
        payment_observation_sha256: &observation,
        payment_amount_minor: 125,
        generation: 0,
        status: AdjustmentStatus::Active,
        applied_events: vec![],
        settlement_qualified: false,
        credit_authorized: false,
        funds_moved: false,
    })
    .unwrap();
    let manifest = PayAdjustmentSemanticManifest {
        schema: PAY_SEMANTIC_MANIFEST_SCHEMA.into(),
        state_identity: "pay:merchant-a:adjustment-1".into(),
        adjustment_policy_sha256: adjustment_policy,
        reconciliation_policy_sha256: reconciliation_policy,
        adjustment_id: "adjustment-1".into(),
        payment_observation_id: "observation-1".into(),
        payment_observation_sha256: observation,
        payment_amount_minor: 125,
        generation: 0,
    };
    let semantic = pay_semantic_manifest_bytes(&manifest).unwrap();
    let semantic_pin = pay_semantic_manifest_sha256(&manifest).unwrap();
    Fixture::new(&manifest.state_identity, &state, semantic, semantic_pin)
}

fn lifecycle_policy(governance: &str, dataset: &str) -> LifecyclePolicy {
    let roles = [
        LifecycleActorRole::LegalHoldAuthority,
        LifecycleActorRole::DisposalAuthority,
        LifecycleActorRole::EvidenceRecorder,
    ];
    LifecyclePolicy {
        schema: LIFECYCLE_POLICY_SCHEMA.into(),
        policy_id: "lifecycle-policy".into(),
        signature_domain: "bloch-data-test".into(),
        governance_policy_sha256: governance.into(),
        dataset_schema_sha256: dataset.into(),
        effective_at_unix_seconds: 100,
        expires_at_unix_seconds: 1_000,
        dispose_after_unix_seconds: 800,
        disposition: RetentionDisposition::Delete,
        initial_legal_hold_id: None,
        actors: roles
            .iter()
            .enumerate()
            .map(|(index, role)| {
                let key = SigningKey::from_bytes(&[(index + 41) as u8; 32]);
                LifecycleActor {
                    actor_id: format!("actor-{}", index + 1),
                    role: *role,
                    ed25519_public_key: format!(
                        "0x{}",
                        hex::encode(key.verifying_key().as_bytes())
                    ),
                }
            })
            .collect(),
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}
